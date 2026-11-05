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

static bool snapsync_finalize_count_mismatch(
    struct snapsync_finalize_ctx *finalize, struct node_db *ndb,
    struct snapshot_sync_service *svc, uint32_t serving_peer_id)
{
    event_emitf(EV_SNAPSYNC_VERIFIED, serving_peer_id,
                "snapshot=FAILED reason=count_mismatch received=%llu offered=%llu",
                (unsigned long long)svc->received_utxos,
                (unsigned long long)svc->offered_count);
    return snapsync_finalize_fail_internal(finalize, ndb, svc, serving_peer_id,
                                           "count_mismatch",
                                           "snapshot count mismatch").ok;
}

static void snapsync_finalize_emit_progress(
    const struct snapshot_sync_service *svc, uint32_t serving_peer_id)
{
    double elapsed_s =
        (double)(snapsync_now_us_internal() - svc->start_time_us) / 1000000.0;
    event_emitf(EV_SNAPSYNC_PROGRESS, serving_peer_id,
                "phase=snapshot_verify received=%llu/%llu rate=%.0f/s",
                (unsigned long long)svc->received_utxos,
                (unsigned long long)svc->offered_count,
                elapsed_s > 0 ? (double)svc->received_utxos / elapsed_s : 0);
}

/* Anchor-root mismatch tail: leave turbo mode, emit the checkpoint-fail
 * event, then discard staging through the common failure path (false). */
static bool snapsync_finalize_anchor_mismatch(
    struct snapsync_finalize_ctx *finalize, struct node_db *ndb,
    struct snapshot_sync_service *svc, uint32_t serving_peer_id,
    const struct sha3_utxo_checkpoint *cp, const char *want, const char *have)
{
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

/* SHA3 verified: hand off to activation, which is contained (false). */
static bool snapsync_finalize_contain_activation(
    struct snapsync_finalize_ctx *finalize, struct node_db *ndb,
    struct snapshot_sync_service *svc, uint32_t serving_peer_id,
    const uint8_t local_root[32], uint64_t local_count,
    const struct chain_evidence_record *snapshot_verified)
{
    /* The activation service owns the complete canonical transaction.
     * Today it returns the containment result before its first mutation;
     * keeping this handoff outside a node.db-only transaction prevents a
     * future installer from being falsely wrapped in partial atomicity. */
    finalize->activation_attempted = true;
    finalize->activation_result =
        snapsync_stage_promote_active_internal(ndb, svc, local_root,
                                               local_count,
                                               snapshot_verified);
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
}

/* SHA3 mismatch tail: report expected/got, leave turbo mode, discard staging. */
static bool snapsync_finalize_sha3_failed(
    struct snapsync_finalize_ctx *finalize, struct node_db *ndb,
    struct snapshot_sync_service *svc, uint32_t serving_peer_id,
    const uint8_t local_root[32], uint64_t local_count)
{
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

/* Received UTXO count equals a non-zero offered count. */
static bool snapsync_finalize_counts_match(const struct snapshot_sync_service *svc)
{
    return !(svc->offered_count == 0 ||
             svc->received_utxos != svc->offered_count);
}

/* Offered root and count both match the locally staged set. */
static bool snapsync_finalize_offer_matches(
    const struct snapshot_sync_service *svc, const uint8_t local_root[32],
    uint64_t local_count)
{
    bool ok = (memcmp(local_root, svc->offered_utxo_root, 32) == 0);
    if (local_count != svc->offered_count)
        ok = false;
    return ok;
}

static bool snapsync_finalize_at_anchor(const struct snapshot_sync_service *svc,
                                        const struct sha3_utxo_checkpoint *cp)
{
    return (cp && svc->offered_height == cp->height);
}

static bool snapsync_finalize_anchor_count_ok(
    const struct sha3_utxo_checkpoint *cp, uint64_t local_count)
{
    return (cp->utxo_count == 0 || local_count == cp->utxo_count);
}

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

    if (!snapsync_finalize_counts_match(svc)) {
        return snapsync_finalize_count_mismatch(finalize, ndb, svc,
                                                serving_peer_id);
    }

    snapsync_finalize_emit_progress(svc, serving_peer_id);

    if (!snapsync_set_staging_phase_internal(ndb, SNAPSYNC_PHASE_SNAPSHOT_VERIFY).ok)
        LOG_FAIL("snapshot_sync", "finalize_write: failed to set verify phase");
    snapsync_hash_staging_internal(ndb, local_root, &local_count);

    /* Self-consistency: the offered set we staged must hash to the root the
     * peer offered (kept exactly as before — never weakened). */
    sha3_ok = snapsync_finalize_offer_matches(svc, local_root, local_count);

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
        bool at_anchor = snapsync_finalize_at_anchor(svc, cp);
        if (at_anchor) {
            bool root_ok  = (memcmp(local_root, cp->sha3_hash, 32) == 0);
            bool count_ok = snapsync_finalize_anchor_count_ok(cp, local_count);
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
                return snapsync_finalize_anchor_mismatch(finalize, ndb, svc,
                                                         serving_peer_id, cp,
                                                         want, have);
            }
        }
    }

    if (sha3_ok) {
        const struct chain_evidence_record snapshot_verified = {
            .utxo_sha3_verified = sha3_ok,
            .mmb_flyclient_proof_verified = fc_verified,
        };

        return snapsync_finalize_contain_activation(finalize, ndb, svc,
                                                    serving_peer_id, local_root,
                                                    local_count,
                                                    &snapshot_verified);
    } else {
        return snapsync_finalize_sha3_failed(finalize, ndb, svc,
                                             serving_peer_id, local_root,
                                             local_count);
    }
}

/* The finalize write path failed: force FAILED state and leave turbo mode. */
static void snapsync_finalize_mark_write_failed(
    struct snapshot_sync_service *svc, bool turbo_active)
{
    bool keep_failed_state = false;

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
}

struct zcl_result snapsync_finalize(struct snapshot_sync_service *svc)
{
    struct snapsync_finalize_ctx ctx;
    bool finalize_allowed = false;
    bool turbo_active = false;

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
        snapsync_finalize_mark_write_failed(svc, turbo_active);
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

/* Read the fixed-size part of one sample (leaf + proof header); false on a
 * short read or an oversized sibling count. */
static bool snapsync_fc_read_sample_head(struct byte_stream *s,
                                         struct fc_sample *sample)
{
    return stream_read_bytes(s, sample->leaf.block_hash, 32) &&
           stream_read_u32_le(s, &sample->leaf.height) &&
           stream_read_u32_le(s, &sample->leaf.timestamp) &&
           stream_read_u32_le(s, &sample->leaf.nBits) &&
           stream_read_bytes(s, sample->leaf.sapling_root, 32) &&
           stream_read_bytes(s, sample->leaf.chain_work, 32) &&
           stream_read_u64_le(s, &sample->proof.leaf_index) &&
           stream_read_bytes(s, sample->proof.leaf_hash, 32) &&
           stream_read_u32_le(s, &sample->proof.num_siblings) &&
           !(sample->proof.num_siblings > MMB_MAX_MOUNTAINS);
}

/* Read count 32-byte hashes in order; on a short read *failed_at is the
 * index that failed. */
static bool snapsync_fc_read_hash_run(struct byte_stream *s, uint8_t (*out)[32],
                                      uint32_t count, uint32_t *failed_at)
{
    for (uint32_t j = 0; j < count; j++) {
        if (!stream_read_bytes(s, out[j], 32)) {
            *failed_at = j;
            return false;
        }
    }
    return true;
}

/* Read the optional section after the last sample: u32 root_count, then
 * root_count 32-byte utxo_roots in sample order. mmb_hash_leaf covers the root,
 * so without it the receiver cannot reproduce the prover's leaf hash at a
 * boundary height.
 *
 * What a root proves here: only that the peer's own leaf hash and MMB commit to
 * it. A root changed afterwards fails that leaf hash, but a peer can commit a
 * fabricated root in its own MMB and pass. No header commits a UTXO root and
 * local leaves can lack one, so the binding never compares it, and it says
 * nothing about the real UTXO set (see utxo_root in chain/mmb.h).
 *
 * Nothing left means an older prover: every root stays zero, which fails at a
 * boundary height exactly as it did before this section existed. Older
 * receivers stop reading after the last sample, so they ignore the section, and
 * this reader likewise ignores anything after it. */
static struct zcl_result snapsync_fc_read_utxo_roots(struct fc_response *resp,
                                                     struct byte_stream *s)
{
    uint32_t root_count = 0;

    if (stream_remaining(s) == 0)
        return ZCL_OK;
    if (!stream_read_u32_le(s, &root_count))
        return ZCL_ERR(-8, "parse_fc_response: truncated root_count");
    if (root_count != resp->num_samples)
        return ZCL_ERR(-9, "parse_fc_response: root_count=%u for %u samples",
                       root_count, resp->num_samples);
    for (uint32_t i = 0; i < root_count; i++) {
        if (!stream_read_bytes(s, resp->samples[i].leaf.utxo_root, 32))
            return ZCL_ERR(-10, "parse_fc_response: truncated root %u/%u",
                           i, root_count);
    }
    return ZCL_OK;
}

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
        if (!snapsync_fc_read_sample_head(s, sample)) {
            return ZCL_ERR(-3, "parse_fc_response: truncated sample %u at pos %zu/%zu",
                     i, s->read_pos, s->size);
        }

        uint32_t j = 0;
        if (!snapsync_fc_read_hash_run(s, sample->proof.siblings,
                                       sample->proof.num_siblings, &j))
            return ZCL_ERR(-4, "parse_fc_response: truncated sibling %u/%u in sample %u",
                     j, sample->proof.num_siblings, i);

        if (!stream_read_u32_le(s, &sample->proof.num_peaks) ||
            sample->proof.num_peaks > MMB_MAX_MOUNTAINS) {
            return ZCL_ERR(-5, "parse_fc_response: bad num_peaks=%u in sample %u",
                     sample->proof.num_peaks, i);
        }

        if (!snapsync_fc_read_hash_run(s, sample->proof.peaks,
                                       sample->proof.num_peaks, &j))
            return ZCL_ERR(-6, "parse_fc_response: truncated peak %u/%u in sample %u",
                     j, sample->proof.num_peaks, i);

        if (!stream_read_u64_le(s, &sample->proof.mmb_size))
            return ZCL_ERR(-7, "parse_fc_response: truncated mmb_size in sample %u", i);
    }

    return snapsync_fc_read_utxo_roots(resp, s);
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

/* Fill sample->leaf from the active-chain block index; false when the index
 * has no block hash (the caller then tries the legacy oracle). */
static bool snapsync_fc_leaf_from_block_index(const struct block_index *bi,
                                              struct fc_sample *sample)
{
    if (!(bi && bi->phashBlock))
        return false;
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
    return true;
}

/* Leaf/proof hash mismatch: adopt the oracle leaf when it hashes to the
 * proof's leaf hash, else report why it cannot be reconciled. */
static struct zcl_result snapsync_fc_reconcile_leaf(struct fc_sample *sample,
                                                    int h, uint32_t i)
{
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
    return ZCL_OK;
}

/* Leaf for height h: the active-chain block index first, then the legacy
 * oracle; false when neither has block metadata. */
static bool snapsync_fc_fill_leaf(const struct active_chain *chain_active,
                                  int h, struct fc_sample *sample)
{
    const struct block_index *bi = active_chain_at(chain_active, h);
    bool have_leaf = snapsync_fc_leaf_from_block_index(bi, sample);

    if (!have_leaf && legacy_chain_rpc_get_mmb_leaf(h, &sample->leaf))
        have_leaf = true;
    return have_leaf;
}

/* MMB inclusion proof for height h over the first min(chain_length,
 * num_leaves) leaves. */
static bool snapsync_fc_prove_sample(const uint8_t (*all_hashes)[32],
                                     uint64_t chain_length, uint64_t num_leaves,
                                     int h, struct fc_sample *sample)
{
    uint64_t prove_len = chain_length;

    if (prove_len > num_leaves)
        prove_len = num_leaves;
    return mmb_prove(all_hashes, prove_len, (uint64_t)h, &sample->proof);
}

/* Verify every sample proof against the challenge root; *bad is the first
 * failing sample index. */
static bool snapsync_fc_verify_proofs(const struct fc_response *resp,
                                      uint32_t count, const uint8_t mmb_root[32],
                                      uint32_t *bad)
{
    for (uint32_t i = 0; i < count; i++) {
        if (!mmb_verify(&resp->samples[i].proof, mmb_root)) {
            *bad = i;
            return false;
        }
    }
    return true;
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
        struct fc_sample *sample = &resp->samples[i];

        if (!snapsync_fc_fill_leaf(chain_active, h, sample)) {
            return ZCL_ERR(-3,
                     "build_fc_response: no block metadata at height %d for sample %u",
                     h, i);
        }

        if (!snapsync_fc_prove_sample(all_hashes, challenge->chain_length,
                                      leaf_store->num_leaves, h, sample))
            return ZCL_ERR(-4, "build_fc_response: mmb_prove failed for height %d sample %u", h, i);

        uint8_t sample_leaf_hash[32];
        mmb_hash_leaf(&sample->leaf, sample_leaf_hash);
        if (memcmp(sample_leaf_hash, sample->proof.leaf_hash, 32) != 0) {
            struct zcl_result rec = snapsync_fc_reconcile_leaf(sample, h, i);
            if (!rec.ok)
                return rec;
        }
    }

    uint32_t bad = 0;
    if (!snapsync_fc_verify_proofs(resp, count, challenge->mmb_root, &bad))
        return ZCL_ERR(-7, "build_fc_response: mmb_verify failed for sample %u", bad);

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

    /* The section snapsync_fc_read_utxo_roots reads. */
    stream_write_u32_le(s, resp->num_samples);
    for (uint32_t i = 0; i < resp->num_samples; i++)
        stream_write_bytes(s, resp->samples[i].leaf.utxo_root, 32);

    return ZCL_OK;
}

/* -- FlyClient proof verification --------------------------------------- */

/* Low bits of mmb_proof.mmb_size hold the leaf count, in both forms mmb_prove
 * writes (the high bits are its left/right path, the only part mmb_verify
 * reads). */
#define SNAPSYNC_FC_MMB_LEAF_COUNT_MASK 0xFFFFFFFFFFULL

/* How a peer's proof stands against the headers this node validated. */
enum snapsync_fc_binding_verdict {
    SNAPSYNC_FC_BOUND,        /* every compared field equals our header */
    SNAPSYNC_FC_UNCHECKABLE,  /* no fault shown: we cannot compare, or only
                               * the uncommitted chain_work differs */
    SNAPSYNC_FC_FORGED,       /* contradicts a field the block hash commits */
};

struct snapsync_fc_binding {
    enum snapsync_fc_binding_verdict verdict;
    const char *reason;
    uint32_t forged_sample;
    uint8_t anchor_work[32];
};

/* The offer fields the binding compares, copied out of the service so the
 * service lock and cs_main are never held together. */
struct snapsync_fc_offer {
    int32_t height;
    uint8_t block_hash[32];
    uint8_t chain_work[32];
};

static struct zcl_result snapsync_fc_check_chainwork_floor(
    const struct consensus_params *consensus,
    const uint8_t anchor_work[32], uint32_t serving_peer_id)
{
    /* Minimum-chainwork FLOOR: serialize the consensus nMinimumChainWork to the
     * canonical little-endian byte layout (byte 0 = least significant), which is
     * exactly the layout of nChainWork.pn / mmb_leaf.chain_work, and reject an
     * anchor whose accumulated work is below it. anchor_work is OUR header's
     * value, never the peer's claim. The floor sits far below any genuine
     * ~3M-height snapshot, so it never false-rejects a real anchor. */
    uint8_t min_chainwork_le[32];
    {
        struct arith_uint256 floor_arith;
        struct uint256 floor_le;
        uint256_to_arith(&floor_arith, &consensus->nMinimumChainWork);
        arith_to_uint256(&floor_le, &floor_arith);
        memcpy(min_chainwork_le, floor_le.data, 32);
    }
    if (zcl_chainwork_below_floor(anchor_work, min_chainwork_le)) {
        char got[65], floor_hex[65];
        HexStr(anchor_work, 32, false, got, sizeof(got));
        HexStr(min_chainwork_le, 32, false, floor_hex, sizeof(floor_hex));
        printf("[snapsync] FlyClient: anchor chainwork below floor "
               "(work=%s floor=%s)\n", got, floor_hex);
        event_emitf(EV_FC_CHAIN_VERIFIED, serving_peer_id,
                    "flyclient=FAILED chainwork=below_floor");
        return ZCL_ERR(-9, "verify_flyclient: anchor chainwork %s below "
                       "minimum floor %s", got, floor_hex);
    }
    return ZCL_OK;
}

/* Index of the first sample whose claimed leaf count is not chain_length, or
 * num_samples when all match. Nothing else ties a proof to the length: the
 * count is not hashed into the root. */
static uint32_t snapsync_fc_first_size_mismatch(const struct fc_response *resp,
                                                uint64_t chain_length)
{
    for (uint32_t i = 0; i < resp->num_samples; i++) {
        if ((resp->samples[i].proof.mmb_size &
             SNAPSYNC_FC_MMB_LEAF_COUNT_MASK) != chain_length)
            return i;
    }
    return resp->num_samples;
}

/* True when the leaf disagrees with our header on a field the block hash
 * commits. The leaf layout is snapsync_fc_leaf_from_block_index's. utxo_root
 * stays peer-asserted (chain/mmb.h), so it is not compared. */
static bool snapsync_fc_leaf_contradicts_header(const struct mmb_leaf *leaf,
                                                const struct block_index *local)
{
    return memcmp(leaf->block_hash, local->phashBlock->data, 32) != 0 ||
           leaf->timestamp != local->nTime ||
           leaf->nBits != local->nBits ||
           memcmp(leaf->sapling_root, local->hashFinalSaplingRoot.data, 32) != 0;
}

/* Compare every sample with our header at its height. A forgery anywhere wins
 * over a difference that shows no fault, so the scan does not stop early for
 * one of those. Caller holds cs_main. */
static void snapsync_fc_bind_samples_locked(struct block_index *anchor,
                                            const struct fc_response *resp,
                                            struct snapsync_fc_binding *out)
{
    for (uint32_t i = 0; i < resp->num_samples; i++) {
        const struct mmb_leaf *leaf = &resp->samples[i].leaf;
        const struct block_index *local =
            block_index_get_ancestor(anchor, (int)leaf->height);

        if (!local || !local->phashBlock) {
            /* A snapshot-seeded anchor has no parents to compare with. */
            out->verdict = SNAPSYNC_FC_UNCHECKABLE;
            out->reason = "sample_header_missing";
        } else if (snapsync_fc_leaf_contradicts_header(leaf, local)) {
            out->verdict = SNAPSYNC_FC_FORGED;
            out->reason = "sample_contradicts_header";
            out->forged_sample = i;
            return;
        } else if (memcmp(leaf->chain_work, local->nChainWork.pn, 32) != 0) {
            /* Not committed by the hash, and an import can leave our own
             * value wrong: this fails the check but shows no fault. */
            out->verdict = SNAPSYNC_FC_UNCHECKABLE;
            out->reason = "sample_chain_work_differs";
        }
    }
}

/* Bind the offer and the samples to our best-header chain, whose headers
 * passed check_block_header (PoW and Equihash) when they were accepted.
 * Takes cs_main, the lock pindex_best_header and the block index are written
 * under, as hsr_target_authoritative does for the same walk. */
static void snapsync_fc_bind_to_headers(struct main_state *ms,
                                        const struct snapsync_fc_offer *offer,
                                        const struct fc_response *resp,
                                        struct snapsync_fc_binding *out)
{
    memset(out, 0, sizeof(*out));
    out->verdict = SNAPSYNC_FC_UNCHECKABLE;
    zcl_mutex_lock(&ms->cs_main);
    struct block_index *best = ms->pindex_best_header;
    struct block_index *anchor =
        best ? block_index_get_ancestor(best, offer->height) : NULL;
    if (!anchor || !anchor->phashBlock) {
        out->reason = "best_header_behind_offer";
    } else if (memcmp(anchor->phashBlock->data, offer->block_hash, 32) != 0) {
        out->reason = "anchor_hash_differs";
    } else {
        out->verdict = SNAPSYNC_FC_BOUND;
        memcpy(out->anchor_work, anchor->nChainWork.pn, 32);
        if (memcmp(out->anchor_work, offer->chain_work, 32) != 0) {
            out->verdict = SNAPSYNC_FC_UNCHECKABLE;
            out->reason = "anchor_chain_work_differs";
        }
        snapsync_fc_bind_samples_locked(anchor, resp, out);
    }
    zcl_mutex_unlock(&ms->cs_main);
}

/* The proof shows no fault but cannot be checked here: return to idle so a
 * later offer is heard, and let header sync carry on. snapsync_reset clears the
 * anchor slot, but that locator hint belongs to boot or chain restore, not to
 * this attempt, so it is put back. No offence is recorded, and the peer goes on
 * a short cooldown so it cannot loop offer, proofs and stand-down.
 *
 * A reset that could not finish leaves the service FAILED, not idle, until the
 * failed-reset condition recovers it. That is our fault, not the peer's, so the
 * code stays the no-offence one. */
static struct zcl_result snapsync_fc_stand_down(struct snapshot_sync_service *svc,
                                                uint32_t serving_peer_id,
                                                const char *reason)
{
    struct block_index *anchor_hint = snapsync_get_anchor();
    bool idle;

    event_emitf(EV_FC_CHAIN_VERIFIED, serving_peer_id,
                "flyclient=UNCHECKABLE reason=%s", reason);
    snapsync_reset(svc);
    snapsync_set_anchor(anchor_hint);
    snapsync_service_lock_internal();
    idle = svc->state == SNAPSYNC_IDLE;
    snapsync_cool_down_peer_internal(svc, serving_peer_id);
    snapsync_service_unlock_internal();
    if (idle && sync_get_state() == SYNC_SNAPSHOT_RECEIVE)
        sync_set_state(SYNC_HEADERS_DOWNLOAD, "snapshot offer not checkable");
    return ZCL_ERR(SNAPSYNC_FLYCLIENT_UNVERIFIABLE_ERROR_CODE,
                   "verify_flyclient: cannot check offer against local "
                   "headers: %s", reason);
}

/* The checks that need no local header: the proofs must hold together under
 * the offered root and length, and an offer must name its work. */
static struct zcl_result snapsync_fc_check_self_consistent(
    const struct fc_response *resp, const struct fc_challenge *challenge,
    const uint8_t offered_chain_work[32], uint32_t serving_peer_id)
{
    if (!fc_verify_response(resp, challenge)) {
        printf("[snapsync] FlyClient: MMB proof verification FAILED\n");
        event_emitf(EV_FC_CHAIN_VERIFIED, serving_peer_id,
                    "flyclient=FAILED samples=%u", resp->num_samples);
        return ZCL_ERR(-3, "verify_flyclient: MMB proof verification failed samples=%u",
                       resp->num_samples);
    }
    uint32_t bad = snapsync_fc_first_size_mismatch(resp, challenge->chain_length);
    if (bad < resp->num_samples) {
        event_emitf(EV_FC_CHAIN_VERIFIED, serving_peer_id,
                    "flyclient=FAILED mmb_size_mismatch sample=%u", bad);
        return ZCL_ERR(-6, "verify_flyclient: sample %u mmb_size does not "
                       "match chain_length %llu", bad,
                       (unsigned long long)challenge->chain_length);
    }
    if (zcl_chainwork_is_zero(offered_chain_work)) {
        printf("[snapsync] FlyClient: missing offered chainwork\n");
        event_emitf(EV_FC_CHAIN_VERIFIED, serving_peer_id,
                    "flyclient=FAILED chainwork=missing");
        return ZCL_ERR(-4, "verify_flyclient: missing offered chainwork");
    }
    return ZCL_OK;
}

/* Action: verify a peer's FlyClient proof before staging its UTXO snapshot.
 *
 * What this proves: the offered anchor and every sampled leaf (FC_NUM_SAMPLES,
 * drawn from our seed) equal headers this node already validated, so the
 * length and the work come from our own chain, not the offer.
 * What it does not prove: anything about the UTXO payload. Headers commit no
 * UTXO or MMB root, so utxo_root and the rest of the belt stay peer-asserted.
 *
 * Failures that show no fault of the peer stand the service down and return
 * SNAPSYNC_FLYCLIENT_UNVERIFIABLE_ERROR_CODE; every other failure is an
 * offence for the route to score, and leaves the service negotiating, except
 * the wrong state, which the route does not score. */
struct zcl_result snapsync_verify_flyclient(struct snapshot_sync_service *svc,
                               struct main_state *ms,
                               const struct fc_response *resp)
{
    enum snapshot_sync_state state = SNAPSYNC_IDLE;
    uint32_t serving_peer_id = 0;
    struct fc_challenge challenge;
    struct snapsync_fc_offer offer;
    struct snapsync_fc_binding binding;

    if (!svc || !ms || !resp)
        return ZCL_ERR(-1, "verify_flyclient: svc=%p ms=%p resp=%p",
                       (void*)svc, (void*)ms, (const void*)resp);

    snapsync_service_lock_internal();
    state = svc->state;
    serving_peer_id = svc->serving_peer_id;
    memcpy(&challenge, &svc->fc_challenge, sizeof(challenge));
    offer.height = svc->offered_height;
    memcpy(offer.block_hash, svc->offered_block_hash, 32);
    memcpy(offer.chain_work, svc->offered_chain_work, 32);
    snapsync_service_unlock_internal();
    if (state != SNAPSYNC_NEGOTIATING) {
        printf("[snapsync] FlyClient: wrong state %s\n",
               snapsync_state_name(state));
        return ZCL_ERR(-2, "verify_flyclient: wrong state %s",
                       snapsync_state_name(state));
    }

    struct zcl_result consistent = snapsync_fc_check_self_consistent(
        resp, &challenge, offer.chain_work, serving_peer_id);
    if (!consistent.ok)
        return consistent;

    const struct chain_params *cp = chain_params_get();
    const struct consensus_params *consensus = cp ? &cp->consensus : NULL;
    if (!consensus) {
        printf("[snapsync] FlyClient: no chain params for work floor\n");
        return ZCL_ERR(-5, "verify_flyclient: no chain params for work floor");
    }

    snapsync_fc_bind_to_headers(ms, &offer, resp, &binding);
    if (binding.verdict == SNAPSYNC_FC_FORGED) {
        event_emitf(EV_FC_CHAIN_VERIFIED, serving_peer_id,
                    "flyclient=FAILED forged_sample=%u h=%u",
                    binding.forged_sample,
                    resp->samples[binding.forged_sample].leaf.height);
        return ZCL_ERR(-7, "verify_flyclient: sample %u contradicts our header "
                       "at height %u", binding.forged_sample,
                       resp->samples[binding.forged_sample].leaf.height);
    }
    if (binding.verdict == SNAPSYNC_FC_UNCHECKABLE)
        return snapsync_fc_stand_down(svc, serving_peer_id, binding.reason);

    struct zcl_result floor_res = snapsync_fc_check_chainwork_floor(
        consensus, binding.anchor_work, serving_peer_id);
    if (!floor_res.ok)
        return floor_res;

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
    printf("*** FlyClient PASSED: %u samples match local headers, "
           "MMB proofs verified ***\n", resp->num_samples);
    event_emitf(EV_FC_CHAIN_VERIFIED, serving_peer_id,
                "flyclient=PASSED samples=%u chain_length=%llu",
                resp->num_samples,
                (unsigned long long)challenge.chain_length);

    return ZCL_OK;
}

struct zcl_result snapsync_awaiting_flyclient_from(
    const struct snapshot_sync_service *svc, uint32_t peer_id,
    bool *out_awaiting)
{
    if (!svc || !out_awaiting)
        return ZCL_ERR(-1, "flyclient wait: invalid arguments");

    snapsync_service_lock_internal();
    *out_awaiting = svc->state == SNAPSYNC_NEGOTIATING &&
                    svc->serving_peer_id == peer_id;
    snapsync_service_unlock_internal();
    return ZCL_OK;
}
