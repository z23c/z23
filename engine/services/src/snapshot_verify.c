/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * snapshot_verify.c — FlyClient + SHA3 snapshot verification.
 *
 * Owns the FlyClient challenge/response wire format, the FlyClient
 * proof verification gate, and the SHA3-256 finalization over staging UTXOs.
 * On SHA3 pass it hands off to snapshot_apply via
 * snapsync_stage_promote_active_internal. Runtime activation is currently
 * contained there until the unified canonical installer exists. */

#include "net/snapshot_sync_contract.h"
#include "services/chain_evidence_authority_service.h"
#include "models/database.h"
#include "models/mmb_leaf_store.h"
#include "chain/mmb.h"
#include "chain/mmr.h"                  /* MMR_COMMITMENT_INTERVAL boundary */
#include "chain/checkpoints.h"          /* g_sha3_checkpoint anchor-root bind */
#include "storage/coins_kv.h"           /* boundary utxo_root read */
#include "storage/progress_store.h"     /* progress_store_db() handle */
#include "chain/pow.h"
#include "chain/chainparams.h"
#include "chain/chain.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "net/flyclient.h"
#include "net/fast_sync.h"
#include "core/serialize.h"
#include "event/event.h"
#include "sync/sync_state.h"
#include "encoding/utilstrencodings.h"
#include "util/log_macros.h"
#include "validation/main_state.h"
#include "validation/sync_evidence_policy.h"
#include "rpc/legacy_chain_oracle.h"

#include "snapshot_sync_internal.h"

#include <string.h>
#include <stdio.h>

/* ── Failure helpers ─────────────────────────────────────── */

void snapsync_mark_failed_internal(struct snapshot_sync_service *svc,
                                   const char *state_reason)
{
    if (!svc)
        return;
    snapsync_service_lock_internal();
    svc->state = SNAPSYNC_FAILED;
    snapsync_set_state(SNAPSYNC_FAILED,
                       state_reason ? state_reason : "snapshot failed");
    snapsync_service_unlock_internal();
}

struct zcl_result snapsync_finalize_fail_internal(struct snapsync_finalize_ctx *finalize,
                                     struct node_db *ndb,
                                     struct snapshot_sync_service *svc,
                                     uint32_t peer_id,
                                     const char *reason,
                                     const char *state_reason)
{
    const char *r = reason ? reason : "unknown";

    if (ndb && ndb->open) {
        bool discarded =
            snapsync_discard_staging_txn_internal(ndb, "snapsync.finalize_fail", r).ok;
        event_emitf(EV_SNAPSYNC_VERIFIED, peer_id,
                    "snapshot=FAILED reason=%s staging_discarded=%s",
                    r, discarded ? "true" : "false");
    } else {
        event_emitf(EV_SNAPSYNC_VERIFIED, peer_id,
                    "snapshot=FAILED reason=%s staging_discarded=false",
                    r);
    }
    snapsync_mark_failed_internal(svc, state_reason);
    if (finalize)
        finalize->ok = false;
    return ZCL_ERR(-1, "snapshot finalize failed: %s", r);
}

/* ── Finalize (SHA3 verification + atomic activate) ──────── */

static bool snapsync_finalize_write(struct node_db *ndb, void *ctx)
{
    struct snapsync_finalize_ctx *finalize = ctx;
    struct snapshot_sync_service *svc;
    uint8_t local_root[32];
    uint64_t local_count = 0;
    uint32_t serving_peer_id;
    struct node_db_status db_status = {0};
    bool fc_verified;
    bool sha3_ok;
    double elapsed_s;

    if (!finalize || !finalize->svc || !ndb || !ndb->open)
        LOG_FAIL("snapshot_sync", "finalize_write: null args finalize=%p ndb=%p", (void*)finalize, (void*)ndb);
    svc = finalize->svc;

    node_db_get_status(ndb, &db_status);
    if (db_status.tx_open && !node_db_commit(ndb))
        LOG_FAIL("snapshot_sync", "finalize_write: failed to commit open transaction");

    snapsync_service_lock_internal();
    svc->state = SNAPSYNC_VERIFYING;
    snapsync_set_state(SNAPSYNC_VERIFYING, "all chunks received");
    serving_peer_id = svc->serving_peer_id;
    fc_verified = svc->fc_verified;
    snapsync_service_unlock_internal();

    if (!fc_verified)
        return snapsync_finalize_fail_internal(finalize, ndb, svc, serving_peer_id,
                                               "proof_missing",
                                               "snapshot proof missing").ok;

    if (svc->offered_count == 0 ||
        svc->received_utxos != svc->offered_count) {
        event_emitf(EV_SNAPSYNC_VERIFIED, serving_peer_id,
                    "snapshot=FAILED reason=count_mismatch received=%llu offered=%llu",
                    (unsigned long long)svc->received_utxos,
                    (unsigned long long)svc->offered_count);
        return snapsync_finalize_fail_internal(finalize, ndb, svc, serving_peer_id,
                                               "count_mismatch",
                                               "snapshot count mismatch").ok;
    }

    elapsed_s = (double)(snapsync_now_us_internal() - svc->start_time_us) / 1000000.0;
    event_emitf(EV_SNAPSYNC_PROGRESS, serving_peer_id,
                "phase=snapshot_verify received=%llu/%llu rate=%.0f/s",
                (unsigned long long)svc->received_utxos,
                (unsigned long long)svc->offered_count,
                elapsed_s > 0 ? (double)svc->received_utxos / elapsed_s : 0);

    if (!snapsync_set_staging_phase_internal(ndb, SNAPSYNC_PHASE_SNAPSHOT_VERIFY).ok)
        LOG_FAIL("snapshot_sync", "finalize_write: failed to set verify phase");
    snapsync_hash_staging_internal(ndb, local_root, &local_count);

    /* Self-consistency: the offered set we staged must hash to the root the
     * peer offered (kept exactly as before — never weakened). */
    sha3_ok = (memcmp(local_root, svc->offered_utxo_root, 32) == 0);
    if (local_count != svc->offered_count)
        sha3_ok = false;

    /* Anchor bind (only-tightening): at the in-binary checkpoint height we do
     * not trust the peer's offered root at all — we require our OWN locally
     * computed commitment over the staged set to equal the compiled SHA3
     * checkpoint root. local_root is the SHA3-256 over the staged UTXOs in the
     * same canonical (txid,vout) order that derived g_sha3_checkpoint.sha3_hash
     * (checkpoints.c). The genuine anchor set hashes to the compiled root by
     * construction; a fabricated set that is merely self-consistent with the
     * peer's offered root cannot match it. When NOT at the anchor height this
     * branch is skipped, so the offered-root self-consistency check above is
     * the sole gate, exactly as it has always been. The bind only ANDs in an
     * extra requirement: sha3_ok can flip true->false here, never false->true. */
    {
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        bool at_anchor = (cp && svc->offered_height == cp->height);
        if (at_anchor) {
            bool root_ok  = (memcmp(local_root, cp->sha3_hash, 32) == 0);
            bool count_ok = (cp->utxo_count == 0 ||
                             local_count == cp->utxo_count);
            if (!root_ok || !count_ok) {
                char want[65], have[65];
                HexStr(cp->sha3_hash, 32, false, want, sizeof(want));
                HexStr(local_root, 32, false, have, sizeof(have));
                /* Plain fprintf (not LOG_ERR/LOG_FAIL — those return, and we
                 * must route through snapsync_finalize_fail_internal below so
                 * staging is discarded and the FAILED event is emitted). */
                fprintf(stderr,  // obs-ok:paired-with-checkpoint-fail-event-and-result
                        "[snapshot_sync] %s:%d %s(): anchor_root_mismatch height=%d "
                        "compiled_root=%s local_root=%s compiled_count=%llu "
                        "local_count=%llu root_ok=%d count_ok=%d\n",
                        __FILE__, __LINE__, __func__, cp->height, want, have,
                        (unsigned long long)cp->utxo_count,
                        (unsigned long long)local_count, root_ok, count_ok);
                sha3_ok = false;
                if (!snapsync_exit_turbo_mode_internal(svc).ok)
                    event_emitf(EV_SNAPSYNC_VERIFIED, serving_peer_id,
                                "snapshot=FAILED reason=turbo_exit_failed");
                event_emitf(EV_UTXO_CHECKPOINT_FAIL, 0,
                            "snapshot anchor-root MISMATCH height=%d compiled=%s local=%s",
                            cp->height, want, have);
                return snapsync_finalize_fail_internal(finalize, ndb, svc,
                                                       serving_peer_id,
                                                       "anchor_root_mismatch",
                                                       "snapshot anchor root mismatch").ok;
            }
        }
    }

    if (sha3_ok) {
        const struct chain_evidence_record snapshot_verified = {
            .utxo_sha3_verified = sha3_ok,
            .mmb_flyclient_proof_verified = fc_verified,
        };

        /* The activation service owns the complete canonical transaction.
         * Today it returns the containment result before its first mutation;
         * keeping this handoff outside a node.db-only transaction prevents a
         * future installer from being falsely wrapped in partial atomicity. */
        finalize->activation_attempted = true;
        finalize->activation_result =
            snapsync_stage_promote_active_internal(ndb, svc, local_root,
                                                   local_count,
                                                   &snapshot_verified);
        if (finalize->activation_result.ok)
            finalize->activation_result = ZCL_ERR(
                SNAPSYNC_ACTIVATION_CONTAINED_ERROR_CODE,
                "peer snapshot activation cannot publish COMPLETE until "
                "consensus_state_snapshot_install is available");

        /* Independent verifier-side containment: changing the apply service's
         * return value alone can never publish COMPLETE. Removing this branch
         * is part of the future unified-installer activation transaction. */
        snapsync_mark_failed_internal(
            svc, "peer snapshot activation contained: unified installer required");
        event_emitf(EV_SNAPSYNC_VERIFIED, serving_peer_id,
                    "snapshot=VERIFIED activation=CONTAINED blocker=%s "
                    "staging_preserved=true",
                    SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID);
        return false;
    } else {
        char exp[65], got[65];
        HexStr(svc->offered_utxo_root, 32, false, exp, sizeof(exp));
        HexStr(local_root, 32, false, got, sizeof(got));
        if (!snapsync_exit_turbo_mode_internal(svc).ok)
            event_emitf(EV_SNAPSYNC_VERIFIED, serving_peer_id,
                        "snapshot=FAILED reason=turbo_exit_failed");
        event_emitf(EV_UTXO_CHECKPOINT_FAIL, 0,
                    "snapshot SHA3 FAILED expected=%s got=%s count=%llu offered=%llu",
                    exp, got,
                    (unsigned long long)local_count,
                    (unsigned long long)svc->offered_count);
        return snapsync_finalize_fail_internal(finalize, ndb, svc, serving_peer_id,
                                               "sha3_failed",
                                               "SHA3 verification failed").ok;
    }
}

struct zcl_result snapsync_finalize(struct snapshot_sync_service *svc)
{
    struct snapsync_finalize_ctx ctx;
    bool finalize_allowed = false;
    bool turbo_active = false;
    bool keep_failed_state = false;

    if (!svc)
        return ZCL_ERR(-1, "finalize: svc is NULL");
    snapsync_service_lock_internal();
    finalize_allowed = (svc->state == SNAPSYNC_RECEIVING &&
                       svc->ndb && svc->ndb->open);
    if (finalize_allowed)
        turbo_active = svc->turbo_active;
    snapsync_service_unlock_internal();

    if (!finalize_allowed) {
        return ZCL_ERR(-2, "finalize: not allowed (state != RECEIVING or ndb not open)");
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.svc = svc;

    if (!snapsync_run_write_internal(svc, snapsync_finalize_write, &ctx)) {
        snapsync_service_lock_internal();
        keep_failed_state = (svc->state == SNAPSYNC_FAILED);
        if (!keep_failed_state)
            svc->state = SNAPSYNC_FAILED;
        snapsync_service_unlock_internal();

        if (!keep_failed_state) {
            snapsync_set_state(SNAPSYNC_FAILED, "finalize write path failed");
            if (!snapsync_exit_turbo_mode_internal(svc).ok)
                event_emitf(EV_SNAPSYNC_VERIFIED, 0,
                            "snapshot=FAILED reason=turbo_exit_failed path=finalize");
        } else if (turbo_active) {
            if (!snapsync_exit_turbo_mode_internal(svc).ok)
                event_emitf(EV_SNAPSYNC_VERIFIED, 0,
                            "snapshot=FAILED reason=turbo_exit_failed path=finalize_failed_state");
        }
        if (ctx.activation_attempted && !ctx.activation_result.ok)
            return ctx.activation_result;
        return ZCL_ERR(-3, "finalize: write path failed");
    }
    snapsync_service_lock_internal();
    if (!ctx.ok) {
        snapsync_set_state(SNAPSYNC_FAILED,
                           "snapshot SHA3 verification failed");
        svc->state = SNAPSYNC_FAILED;
    }
    snapsync_service_unlock_internal();
    if (!ctx.ok)
        return ZCL_ERR(-4, "finalize: SHA3 verification failed");
    return ZCL_OK;
}

/* ── FlyClient wire format helpers ───────────────────────── */

struct zcl_result snapsync_parse_fc_response(struct fc_response *resp,
                                struct byte_stream *s)
{
    uint32_t num_samples = 0;

    if (!resp || !s)
        return ZCL_ERR(-1, "parse_fc_response: resp=%p stream=%p", (void*)resp, (void*)s);

    memset(resp, 0, sizeof(*resp));
    if (!stream_read_u32_le(s, &num_samples) ||
        num_samples == 0 || num_samples > FC_MAX_SAMPLES) {
        return ZCL_ERR(-2, "parse_fc_response: bad num_samples=%u (max=%d)",
                 num_samples, FC_MAX_SAMPLES);
    }

    resp->num_samples = num_samples;
    for (uint32_t i = 0; i < num_samples; i++) {
        struct fc_sample *sample = &resp->samples[i];
        if (!stream_read_bytes(s, sample->leaf.block_hash, 32) ||
            !stream_read_u32_le(s, &sample->leaf.height) ||
            !stream_read_u32_le(s, &sample->leaf.timestamp) ||
            !stream_read_u32_le(s, &sample->leaf.nBits) ||
            !stream_read_bytes(s, sample->leaf.sapling_root, 32) ||
            !stream_read_bytes(s, sample->leaf.chain_work, 32) ||
            !stream_read_u64_le(s, &sample->proof.leaf_index) ||
            !stream_read_bytes(s, sample->proof.leaf_hash, 32) ||
            !stream_read_u32_le(s, &sample->proof.num_siblings) ||
            sample->proof.num_siblings > MMB_MAX_MOUNTAINS) {
            return ZCL_ERR(-3, "parse_fc_response: truncated sample %u at pos %zu/%zu",
                     i, s->read_pos, s->size);
        }

        for (uint32_t j = 0; j < sample->proof.num_siblings; j++) {
            if (!stream_read_bytes(s, sample->proof.siblings[j], 32))
                return ZCL_ERR(-4, "parse_fc_response: truncated sibling %u/%u in sample %u",
                         j, sample->proof.num_siblings, i);
        }

        if (!stream_read_u32_le(s, &sample->proof.num_peaks) ||
            sample->proof.num_peaks > MMB_MAX_MOUNTAINS) {
            return ZCL_ERR(-5, "parse_fc_response: bad num_peaks=%u in sample %u",
                     sample->proof.num_peaks, i);
        }

        for (uint32_t j = 0; j < sample->proof.num_peaks; j++) {
            if (!stream_read_bytes(s, sample->proof.peaks[j], 32))
                return ZCL_ERR(-6, "parse_fc_response: truncated peak %u/%u in sample %u",
                         j, sample->proof.num_peaks, i);
        }

        if (!stream_read_u64_le(s, &sample->proof.mmb_size))
            return ZCL_ERR(-7, "parse_fc_response: truncated mmb_size in sample %u", i);
    }

    return ZCL_OK;
}

struct zcl_result snapsync_write_fc_challenge(const struct snapshot_sync_service *svc,
                                 struct byte_stream *s)
{
    if (!svc || !s)
        return ZCL_ERR(-1, "write_fc_challenge: svc=%p stream=%p", (void*)svc, (void*)s);

    stream_write_bytes(s, svc->fc_challenge.seed, 32);
    stream_write_u64_le(s, svc->fc_challenge.chain_length);
    stream_write_bytes(s, svc->fc_challenge.mmb_root, 32);
    return ZCL_OK;
}

struct zcl_result snapsync_build_fc_response(struct fc_response *resp,
                                const struct fc_challenge *challenge,
                                const struct active_chain *chain_active,
                                const struct mmb_leaf_store *leaf_store)
{
    const uint8_t (*all_hashes)[32];
    uint64_t indices[FC_MAX_SAMPLES];
    uint32_t count = 0;

    if (!resp || !challenge || !chain_active || !leaf_store ||
        !leaf_store->open || leaf_store->num_leaves == 0) {
        return ZCL_ERR(-1, "build_fc_response: invalid args resp=%p challenge=%p chain=%p leaves=%llu",
                 (void*)resp, (void*)challenge, (void*)chain_active,
                 leaf_store ? (unsigned long long)leaf_store->num_leaves : 0ULL);
    }

    all_hashes = mmb_leaf_store_all(leaf_store);
    if (!all_hashes)
        return ZCL_ERR(-2, "build_fc_response: mmb_leaf_store_all returned NULL");

    memset(resp, 0, sizeof(*resp));
    fc_generate_indices(challenge->seed, challenge->chain_length,
                        indices, &count);
    resp->num_samples = count;

    for (uint32_t i = 0; i < count; i++) {
        int h = (int)indices[i];
        uint64_t prove_len = challenge->chain_length;
        const struct block_index *bi = active_chain_at(chain_active, h);
        struct fc_sample *sample = &resp->samples[i];
        bool have_leaf = false;

        if (bi && bi->phashBlock) {
            /* Reproduce the boundary utxo_root so this prover-side leaf hashes
             * identically to the stored leaf hash mmb_prove returned (the leaf
             * store keeps only the hash, so the root must come from the
             * persisted boundary table). Missing → zero sentinel. */
            uint8_t utxo_root[32] = {0};
            if (bi->nHeight > 0 &&
                bi->nHeight % MMR_COMMITMENT_INTERVAL == 0) {
                sqlite3 *pdb = progress_store_db();
                bool found = false;
                if (pdb)
                    coins_kv_boundary_root_get(pdb, bi->nHeight, utxo_root,
                                               &found);
                if (!found) memset(utxo_root, 0, 32);
            }
            mmb_leaf_from_block(&sample->leaf,
                                bi->phashBlock->data,
                                bi->nHeight, bi->nTime, bi->nBits,
                                bi->hashFinalSaplingRoot.data,
                                (const uint8_t *)bi->nChainWork.pn,
                                utxo_root);
            have_leaf = true;
        }
        if (!have_leaf && legacy_chain_rpc_get_mmb_leaf(h, &sample->leaf))
            have_leaf = true;
        if (!have_leaf) {
            return ZCL_ERR(-3,
                     "build_fc_response: no block metadata at height %d for sample %u",
                     h, i);
        }

        if (prove_len > leaf_store->num_leaves)
            prove_len = leaf_store->num_leaves;
        if (!mmb_prove(all_hashes, prove_len, (uint64_t)h, &sample->proof))
            return ZCL_ERR(-4, "build_fc_response: mmb_prove failed for height %d sample %u", h, i);

        uint8_t sample_leaf_hash[32];
        mmb_hash_leaf(&sample->leaf, sample_leaf_hash);
        if (memcmp(sample_leaf_hash, sample->proof.leaf_hash, 32) != 0) {
            struct mmb_leaf oracle_leaf;
            uint8_t oracle_leaf_hash[32];

            if (legacy_chain_rpc_get_mmb_leaf(h, &oracle_leaf)) {
                mmb_hash_leaf(&oracle_leaf, oracle_leaf_hash);
                if (memcmp(oracle_leaf_hash, sample->proof.leaf_hash, 32) == 0) {
                    sample->leaf = oracle_leaf;
                } else {
                    return ZCL_ERR(-5,
                             "build_fc_response: leaf/proof hash mismatch at height %d sample %u",
                             h, i);
                }
            } else {
                return ZCL_ERR(-6,
                         "build_fc_response: cannot reconcile leaf/proof hash mismatch at height %d sample %u",
                         h, i);
            }
        }
    }

    for (uint32_t i = 0; i < count; i++) {
        if (!mmb_verify(&resp->samples[i].proof, challenge->mmb_root))
            return ZCL_ERR(-7, "build_fc_response: mmb_verify failed for sample %u", i);
    }

    return ZCL_OK;
}

struct zcl_result snapsync_write_fc_response(struct byte_stream *s,
                                const struct fc_response *resp)
{
    if (!s || !resp || resp->num_samples == 0 ||
        resp->num_samples > FC_MAX_SAMPLES) {
        return ZCL_ERR(-1, "write_fc_response: invalid args s=%p resp=%p samples=%u",
                 (void*)s, (void*)resp, resp ? resp->num_samples : 0);
    }

    stream_write_u32_le(s, resp->num_samples);
    for (uint32_t i = 0; i < resp->num_samples; i++) {
        const struct fc_sample *sample = &resp->samples[i];
        stream_write_bytes(s, sample->leaf.block_hash, 32);
        stream_write_u32_le(s, sample->leaf.height);
        stream_write_u32_le(s, sample->leaf.timestamp);
        stream_write_u32_le(s, sample->leaf.nBits);
        stream_write_bytes(s, sample->leaf.sapling_root, 32);
        stream_write_bytes(s, sample->leaf.chain_work, 32);
        stream_write_u64_le(s, sample->proof.leaf_index);
        stream_write_bytes(s, sample->proof.leaf_hash, 32);
        stream_write_u32_le(s, sample->proof.num_siblings);
        for (uint32_t j = 0; j < sample->proof.num_siblings; j++)
            stream_write_bytes(s, sample->proof.siblings[j], 32);
        stream_write_u32_le(s, sample->proof.num_peaks);
        for (uint32_t j = 0; j < sample->proof.num_peaks; j++)
            stream_write_bytes(s, sample->proof.peaks[j], 32);
        stream_write_u64_le(s, sample->proof.mmb_size);
    }

    return ZCL_OK;
}

/* -- FlyClient proof verification --------------------------------------- */

/* Action: verify FlyClient proofs before accepting snapshot UTXO staging.
 * Checks 20 random block samples with MMB inclusion proofs
 * and PoW target verification (block_hash < target(nBits)). */
struct zcl_result snapsync_verify_flyclient(struct snapshot_sync_service *svc,
                               const struct fc_response *resp)
{
    enum snapshot_sync_state state = SNAPSYNC_IDLE;
    uint32_t serving_peer_id = 0;
    struct fc_challenge challenge;

    if (!svc || !resp)
        return ZCL_ERR(-1, "verify_flyclient: svc=%p resp=%p", (void*)svc, (void*)resp);

    snapsync_service_lock_internal();
    state = svc->state;
    serving_peer_id = svc->serving_peer_id;
    memcpy(&challenge, &svc->fc_challenge, sizeof(challenge));
    snapsync_service_unlock_internal();
    if (state != SNAPSYNC_NEGOTIATING) {
        printf("[snapsync] FlyClient: wrong state %s\n",
               snapsync_state_name(state));
        return ZCL_ERR(-2, "verify_flyclient: wrong state %s",
                       snapsync_state_name(state));
    }

    /* Verify all samples against the challenge */
    if (!fc_verify_response(resp, &challenge)) {
        printf("[snapsync] FlyClient: MMB proof verification FAILED\n");
        event_emitf(EV_FC_CHAIN_VERIFIED, serving_peer_id,
                    "flyclient=FAILED samples=%u", resp->num_samples);
        return ZCL_ERR(-3, "verify_flyclient: MMB proof verification failed samples=%u",
                       resp->num_samples);
    }

    uint8_t offered_chain_work[32];
    snapsync_service_lock_internal();
    memcpy(offered_chain_work, svc->offered_chain_work, 32);
    snapsync_service_unlock_internal();
    if (zcl_chainwork_is_zero(offered_chain_work)) {
        printf("[snapsync] FlyClient: missing offered chainwork\n");
        event_emitf(EV_FC_CHAIN_VERIFIED, serving_peer_id,
                    "flyclient=FAILED chainwork=missing");
        return ZCL_ERR(-4, "verify_flyclient: missing offered chainwork");
    }

    /* Additional check: verify PoW targets for each sample.
     * The MMB leaf contains block_hash and nBits — verify that
     * block_hash actually meets the difficulty target. */
    const struct chain_params *cp = chain_params_get();
    const struct consensus_params *consensus = cp ? &cp->consensus : NULL;
    if (!consensus) {
        printf("[snapsync] FlyClient: no chain params for PoW check\n");
        return ZCL_ERR(-5, "verify_flyclient: no chain params for PoW check");
    }

    /* Minimum-chainwork FLOOR: serialize the consensus nMinimumChainWork to the
     * canonical little-endian byte layout (byte 0 = least significant), which is
     * exactly the layout of offered_chain_work / mmb_leaf.chain_work, and reject
     * any offered anchor whose accumulated work is below it. The floor sits far
     * below any genuine ~3M-height snapshot, so it never false-rejects a real
     * anchor, but it blocks a forged minimum-difficulty chain whose tiny work
     * could otherwise pass the relative leaf<=offered checks below. */
    uint8_t min_chainwork_le[32];
    {
        struct arith_uint256 floor_arith;
        struct uint256 floor_le;
        uint256_to_arith(&floor_arith, &consensus->nMinimumChainWork);
        arith_to_uint256(&floor_le, &floor_arith);
        memcpy(min_chainwork_le, floor_le.data, 32);
    }
    if (zcl_chainwork_below_floor(offered_chain_work, min_chainwork_le)) {
        char got[65], floor_hex[65];
        HexStr(offered_chain_work, 32, false, got, sizeof(got));
        HexStr(min_chainwork_le, 32, false, floor_hex, sizeof(floor_hex));
        printf("[snapsync] FlyClient: offered chainwork below floor "
               "(work=%s floor=%s)\n", got, floor_hex);
        event_emitf(EV_FC_CHAIN_VERIFIED, serving_peer_id,
                    "flyclient=FAILED chainwork=below_floor");
        return ZCL_ERR(-9, "verify_flyclient: offered chainwork %s below "
                       "minimum floor %s", got, floor_hex);
    }

    uint32_t pow_failures = 0;
    uint32_t work_failures = 0;
    for (uint32_t i = 0; i < resp->num_samples; i++) {
        const struct mmb_leaf *leaf = &resp->samples[i].leaf;
        struct uint256 hash;
        if (zcl_chainwork_is_zero(leaf->chain_work) ||
            zcl_chainwork_compare_le(leaf->chain_work,
                                     offered_chain_work) > 0) {
            printf("[snapsync] FlyClient: chainwork check FAILED for "
                   "sample %u (h=%u)\n", i, leaf->height);
            work_failures++;
        }
        memcpy(hash.data, leaf->block_hash, 32);
        if (!CheckProofOfWork(hash, leaf->nBits, consensus)) {
            printf("[snapsync] FlyClient: PoW check FAILED for sample %u "
                   "(h=%u)\n", i, leaf->height);
            pow_failures++;
        }
    }

    if (pow_failures > 0) {
        printf("[snapsync] FlyClient: %u/%u PoW checks FAILED\n",
               pow_failures, resp->num_samples);
        event_emitf(EV_FC_CHAIN_VERIFIED, serving_peer_id,
                    "flyclient=FAILED pow_failures=%u/%u",
                    pow_failures, resp->num_samples);
        return ZCL_ERR(-6, "verify_flyclient: %u/%u PoW checks failed",
                       pow_failures, resp->num_samples);
    }
    if (work_failures > 0) {
        printf("[snapsync] FlyClient: %u/%u chainwork checks FAILED\n",
               work_failures, resp->num_samples);
        event_emitf(EV_FC_CHAIN_VERIFIED, serving_peer_id,
                    "flyclient=FAILED work_failures=%u/%u",
                    work_failures, resp->num_samples);
        return ZCL_ERR(-7, "verify_flyclient: %u/%u chainwork checks failed",
                       work_failures, resp->num_samples);
    }

    snapsync_service_lock_internal();
    svc->fc_verified = false;
    snapsync_service_unlock_internal();
    {
        struct zcl_result br = snapsync_begin_receive(svc);
        if (!br.ok)
            return ZCL_ERR(-8, "verify_flyclient: begin_receive failed: %s",
                           br.message);
    }

    snapsync_service_lock_internal();
    svc->fc_verified = true;
    snapsync_service_unlock_internal();
    printf("*** FlyClient PASSED: %u samples, all PoW targets valid, "
           "MMB proofs verified ***\n", resp->num_samples);
    event_emitf(EV_FC_CHAIN_VERIFIED, serving_peer_id,
                "flyclient=PASSED samples=%u chain_length=%llu",
                resp->num_samples,
                (unsigned long long)challenge.chain_length);

    return ZCL_OK;
}
