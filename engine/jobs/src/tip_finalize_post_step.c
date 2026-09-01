/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * tip_finalize_post_step — reducer post-finalize side effects.
 * See tip_finalize_post_step.h for the contract.
 *
 * tip_finalize_run_post_finalize owns the wallet_sync / Sapling trial-decrypt
 * / nullifier-spend / mempool-remove / MMR / MMB side effects, run after tip
 * publication. The connected block is READ BACK from disk via
 * stage_default_block_reader (the reducer does not receive it as a parameter),
 * and the wallet / node_db / mempool handles are fetched through the public
 * app_runtime_* accessors.
 */

#include "tip_finalize_post_step.h"
#include "jobs/catchup_cadence.h"      /* live catch-up boundary-fold defer */
#include "jobs/stage_helpers.h"
#include "utxo_root_ladder_tripwire.h"   /* OBSERVE-ONLY golden ladder caller */

#include "chain/chain.h"
#include "chain/chainparams.h"           /* fMineBlocksOnDemand regtest gate */
#include "chain/mmb.h"
#include "chain/sha3_windows.h"          /* golden-window corroboration table */
#include "config/runtime.h"
#include "crypto/sha3.h"                /* incremental raw-window digest */
#include "event/event.h"                 /* EV_BLOCK_INDEX_CORRUPT telemetry */
#include "util/blocker.h"                /* typed evidence blocker */
#include "controllers/blockchain_controller.h"
#include "controllers/sync_controller.h"
#include "core/uint256.h"
#include "models/database.h"            /* struct node_db */
#include "chain/mmr.h"                  /* MMR_COMMITMENT_INTERVAL boundary */
#include "coins/coins_view.h"           /* live coins_kv cache publication */
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "storage/coins_kv.h"           /* coins_kv_commitment + boundary root */
#include "storage/blocks_mmap_reader.h" /* zero-copy canonical block payload */
#include "storage/progress_store.h"     /* progress_store_db() handle */
#include "services/block_source_policy.h" /* projection-deferred diagnostic */
#include "services/chain_evidence_authority_service.h" /* live evidence follow */
#include "util/util.h"                  /* GetDataDir */
#include "validation/check_block.h"     /* coinbase-height label check */
#include "validation/chain_linkage_check.h" /* fail-loud HOLD latch */
#include "validation/process_block.h"   /* g_body_pull_active */
#include "validation/txmempool.h"
#include "wallet/wallet.h"
#include "models/zmsg.h"                /* on-chain ZMSG memo ingest */

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Byte ceiling for one golden window. The mmap reader is zero-copy, but this
 * still bounds work on corrupt/pathological block-index metadata. */
#define SHA3_WINDOW_TRIPWIRE_MAX_BYTES (128u * 1024u * 1024u)

enum sha3_window_tripwire_result
sha3_window_tripwire_report(int window_index, bool matched)
{
    if (window_index < 0 || (size_t)window_index >= g_sha3_windows_count)
        return SHA3_WINDOW_TRIPWIRE_SKIP;

    if (matched)
        return SHA3_WINDOW_TRIPWIRE_MATCH;   /* corroborated — silent, cheap */

    /* MISMATCH. OBSERVE-ONLY: the golden table is an immutable commitment over
     * frozen history, so a divergence is never transient — re-running cannot
     * clear it. It means a peer served a bad body or the local body is
     * corrupt, and only an operator repair (re-fetch / rebuild) resolves it.
     * That is exactly BLOCKER_PERMANENT ("malformed block / consensus reject —
     * never auto-retry; only operator clears"). We give it NO escape action and
     * NO deadline: it is pure evidence surfaced by native blocker diagnostics
     * as a pipeline HOLD. The fold continues; the tip is untouched. */
    int start = window_index * SHA3_WINDOW_SIZE;
    int end   = start + SHA3_WINDOW_SIZE - 1;
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "sha3 golden-window mismatch wi=%d h=%d..%d: recomputed digest != "
             "locked commitment (bad body from a peer or local corruption)",
             window_index, start, end);

    struct blocker_record r;
    if (!blocker_init(&r, "sha3_window_mismatch", "sha3_window_tripwire",
                      BLOCKER_PERMANENT, reason))
        return SHA3_WINDOW_TRIPWIRE_MISMATCH;  /* blocker_init logged the why */
    r.escape_deadline_secs = 0;   /* evidence only — never auto-escaped */
    r.escape_action[0] = '\0';
    if (blocker_set(&r) == 0)
        event_emitf(EV_BLOCK_INDEX_CORRUPT, 0,
                    "verdict=sha3_window_mismatch wi=%d h=%d..%d observe_only=1",
                    window_index, start, end);

    return SHA3_WINDOW_TRIPWIRE_MISMATCH;
}

enum sha3_window_tripwire_result
sha3_window_tripwire_eval(int window_index, const uint8_t *concat, size_t len)
{
    if (window_index < 0 || (size_t)window_index >= g_sha3_windows_count)
        return SHA3_WINDOW_TRIPWIRE_SKIP;

    bool matched = sha3_windows_verify_window(window_index, concat, len);
    return sha3_window_tripwire_report(window_index, matched);
}

/* Run the corroboration tripwire iff `pindex_new` closes a golden-covered
 * 1000-block window. Called at the very END of the post-finalize step (tip
 * already published), so it is structurally observe-only. Cost is bounded to
 * once per 1000 blocks and only for covered heights (< ~3.11M) — in daily
 * snapshot-boot operation the tip is above the table so this never runs; it is
 * armed for the genesis replay / refold path where a bad body would appear. */
static void sha3_window_tripwire_at_boundary(const struct block_index *pindex_new,
                                             const char *datadir)
{
    /* Operator kill-switch (self-contained; no config surface). Checked only
     * at the once-per-1000-blocks boundary, so its cost is nil. */
    if (getenv("ZCL_DISABLE_SHA3_WINDOW_TRIPWIRE"))
        return;

    int h = pindex_new->nHeight;
    if (h < 0)
        return;
    /* Only the block that CLOSES a window (last height of the 1000-run). */
    if ((h % SHA3_WINDOW_SIZE) != (SHA3_WINDOW_SIZE - 1))
        return;
    int wi = h / SHA3_WINDOW_SIZE;
    if (wi < 0 || (size_t)wi >= g_sha3_windows_count)
        return;   /* window not covered by the golden table */

    int start = wi * SHA3_WINDOW_SIZE;   /* == h - (SHA3_WINDOW_SIZE - 1) */

    /* Collect the window's block_index list by walking pprev from the tip.
     * Any gap / mislabel aborts (observe-only: skip, never false-fire). */
    const struct block_index *chain[SHA3_WINDOW_SIZE];
    const struct block_index *bi = pindex_new;
    for (int i = SHA3_WINDOW_SIZE - 1; i >= 0; i--) {
        if (!bi || bi->nHeight != start + i)
            return;
        chain[i] = bi;
        bi = bi->pprev;
    }

    /* Hash the canonical on-disk payload bytes directly. The golden table was
     * generated from raw `getblock <hash> 0` payloads, and nDataPos points at
     * those exact bytes after the blk*.dat framing header. The former path
     * parsed and reserialized all 1000 blocks, then allocated their full
     * concatenation; that verdict-equivalent detour cost ~8 seconds inside a
     * tip-finalize batch. The existing mmap reader validates magic, payload
     * length, and file bounds before returning bytes. Incremental SHA3 is
     * byte-identical to hashing the concatenation and uses constant memory. */
    char blocks_dir[2304];
    int pn = snprintf(blocks_dir, sizeof(blocks_dir), "%s/blocks", datadir);
    if (pn < 0 || (size_t)pn >= sizeof(blocks_dir))
        return;
    struct blocks_mmap *mmap = NULL;
    if (!bmr_open(blocks_dir, &mmap))
        return;
    struct sha3_256_ctx sha3;
    sha3_256_init(&sha3);
    size_t total = 0;
    for (int i = 0; i < SHA3_WINDOW_SIZE; i++) {
        size_t len = 0;
        const uint8_t *payload = bmr_get_payload(
            mmap, chain[i]->nFile, chain[i]->nDataPos, &len);
        if (!payload || len > SHA3_WINDOW_TRIPWIRE_MAX_BYTES - total) {
            bmr_close(mmap);
            return;   /* missing/corrupt body or over cap: no false evidence */
        }
        sha3_256_write(&sha3, payload, len);
        total += len;
    }
    uint8_t digest[32];
    sha3_256_finalize(&sha3, digest);
    bmr_close(mmap);
    (void)sha3_window_tripwire_report(
        wi, memcmp(digest, g_sha3_windows[wi].hash, sizeof(digest)) == 0);
}

/* Publish the reducer-authored coins generation and remove transactions that
 * the connected block confirmed. Both operations are idempotent, and both
 * must run even when another authority path published this exact tip before
 * tip_finalize reached its durable row. Keep them under cs_main as one seam:
 * accept_to_mempool_detailed uses the same lock through validation and insert,
 * so a transaction cannot be admitted between the cache invalidation and the
 * confirmed-transaction removal pass. */
static void tip_finalize_reconcile_block(struct block_index *pindex_new,
                                         const struct block *blk)
{
    struct main_state *main_state = app_runtime_main_state();
    struct coins_view_cache *coins_tip = app_runtime_coins_tip();
    struct tx_mempool *mempool = app_runtime_mempool();
    if (main_state)
        zcl_mutex_lock(&main_state->cs_main);
    if (coins_tip) {
        for (size_t i = 0; i < blk->num_vtx; i++) {
            const struct transaction *tx = &blk->vtx[i];
            (void)coins_view_cache_invalidate(coins_tip, &tx->hash);
            if (!transaction_is_coinbase(tx)) {
                for (size_t j = 0; j < tx->num_vin; j++)
                    (void)coins_view_cache_invalidate(
                        coins_tip, &tx->vin[j].prevout.hash);
            }
        }
    }
    if (mempool)
        tx_mempool_remove_for_block(mempool,
            blk->vtx, blk->num_vtx,
            (unsigned int)pindex_new->nHeight);
    if (main_state)
        zcl_mutex_unlock(&main_state->cs_main);
}

bool tip_finalize_run_mempool_reconcile(struct block_index *pindex_new)
{
    if (!pindex_new) {
        LOG_WARN("tip_finalize", "mempool reconcile refused NULL block index");
        return false;
    }

    char datadir[2048];
    GetDataDir(true, datadir, sizeof(datadir));

    struct block owned;
    struct block_parse_handle handle;
    const struct block *blk = NULL;
    bool borrowed = false;
    if (!stage_acquire_block_view(&owned, &handle, &blk, &borrowed,
                                  pindex_new, pindex_new->nHeight, datadir,
                                  NULL, NULL)) {
        LOG_WARN("tip_finalize",
                 "mempool reconcile skipped h=%d have_data=%d: "
                 "body unreadable; confirmed transactions remain deferred",
                 pindex_new->nHeight,
                 (pindex_new->nStatus & BLOCK_HAVE_DATA) ? 1 : 0);
        block_free(&owned);
        return false;
    }

    tip_finalize_reconcile_block(pindex_new, blk);
    stage_release_block_view(&owned, &handle, borrowed);
    return true;
}

/* Idempotent wallet subset of post-finalize publication. A body can become
 * visible after another authority already published this height; in that
 * case MMR/MMB must not append twice, but wallet confirmation, Sapling note,
 * nullifier, and derived wallet rows still have to observe the exact body. */
static void tip_finalize_reconcile_wallet_body(
    struct block_index *pindex_new, const struct block *blk)
{
    if (!pindex_new || !blk ||
        atomic_load_explicit(&g_body_pull_active, memory_order_relaxed))
        return;

    struct wallet *wallet = app_runtime_wallet();
    struct node_db *ndb = app_runtime_node_db();
    const struct chain_params *cp_regtest = chain_params_get();
    const bool regtest_on_demand =
        cp_regtest && cp_regtest->fMineBlocksOnDemand;
    if (!wallet)
        return;

    if (regtest_on_demand)
        (void)wallet_advance_confirmations(wallet, pindex_new->nHeight);

    for (size_t i = 0; i < blk->num_vtx; i++) {
        const struct transaction *tx = &blk->vtx[i];
        bool wallet_involved = wallet_sync_transaction(wallet, tx, pindex_new);
        if (!regtest_on_demand && wallet_involved && ndb &&
            !node_db_sync_wallet_tx_confirmed_async(
                ndb, tx, wallet, pindex_new->nHeight,
                pindex_new->phashBlock->data, pindex_new->nTime)) {
            LOG_WARN("tip_finalize",
                     "wallet confirmation projection enqueue failed "
                     "at height %d tx %zu",
                     pindex_new->nHeight, i);
        }
        if (tx->num_shielded_output > 0 &&
            wallet->sapling_keys.num_keys > 0) {
            struct uint256 txid;
            if (!transaction_hash_serialized(tx, &txid))
                continue;
            zcl_mutex_lock(&wallet->cs);
            size_t notes_before = wallet->num_sapling_notes;
            zcl_mutex_unlock(&wallet->cs);
            wallet_try_sapling_decrypt(wallet, tx, &txid);
            if (ndb) {
                size_t n_notes = 0;
                struct sapling_received_note *snap =
                    wallet_copy_sapling_notes(wallet, &n_notes);
                for (size_t ni = notes_before; ni < n_notes; ni++) {
                    struct sapling_received_note *note = &snap[ni];
                    node_db_sync_sapling_note(ndb,
                        note->txid.data, note->output_index,
                        (int64_t)note->value, note->rcm,
                        note->memo, 512, note->ivk,
                        note->diversifier, note->pk_d,
                        note->cm, note->nf, pindex_new->nHeight);
                    zmsg_ingest_onchain_note(ndb, note->memo,
                                             note->txid.data);
                }
                free(snap);
            }
        }
        if (tx->num_shielded_spend > 0)
            wallet_mark_sapling_nullifiers_spent(wallet, tx);
    }
    zcl_mutex_lock(&wallet->cs);
    wallet->best_block_height = pindex_new->nHeight;
    zcl_mutex_unlock(&wallet->cs);

    if (ndb && regtest_on_demand &&
        !node_db_sync_connect_block_async_with_wallet(
            ndb, blk, pindex_new, wallet)) {
        LOG_WARN("tip_finalize",
                 "regtest projection: async connect_block enqueue failed "
                 "at height %d", pindex_new->nHeight);
    }
}

bool tip_finalize_run_wallet_reconcile(struct block_index *pindex_new)
{
    if (!pindex_new)
        return false;
    char datadir[2048];
    GetDataDir(true, datadir, sizeof(datadir));
    struct block owned;
    struct block_parse_handle handle;
    const struct block *blk = NULL;
    bool borrowed = false;
    if (!stage_acquire_block_view(&owned, &handle, &blk, &borrowed,
                                  pindex_new, pindex_new->nHeight, datadir,
                                  NULL, NULL)) {
        LOG_WARN("tip_finalize",
                 "wallet reconcile skipped h=%d have_data=%d: body unreadable",
                 pindex_new->nHeight,
                 (pindex_new->nStatus & BLOCK_HAVE_DATA) ? 1 : 0);
        block_free(&owned);
        return false;
    }
    tip_finalize_reconcile_wallet_body(pindex_new, blk);
    stage_release_block_view(&owned, &handle, borrowed);
    return true;
}

void tip_finalize_run_post_finalize(struct block_index *pindex_new)
{
    if (!pindex_new)
        return;

    /* Note the published tip for the chain-evidence follow. The drive MUST
     * NOT run the evidence machinery itself: it holds the coins_kv authority
     * mutex, and the evidence path takes csr->lock then coins_kv — calling it
     * from here is the inverted ABBA edge that would deadlock via inverted
     * lock order. This stamps one leaf-mutex slot and returns;
     * node_health_collect drains it with the correct lock order before every
     * health snapshot, so the mismatch this follow exists to clear is never
     * observed. */
    chain_evidence_note_finalized_tip(pindex_new);

    char datadir[2048];
    GetDataDir(true, datadir, sizeof(datadir));

    struct block owned;
    struct block_parse_handle handle;
    const struct block *blk = NULL;
    bool borrowed = false;
    if (!stage_acquire_block_view(&owned, &handle, &blk, &borrowed,
                                  pindex_new, pindex_new->nHeight, datadir,
                                  NULL, NULL)) {
        /* No on-disk body (HAVE_DATA absent / read failed). The body is read
         * back from disk, so a missing body is a benign skip — the tip still
         * advanced, only the derived side effects are deferred. The skip must
         * be DIAGNOSED, never silent: all six side effects (wallet sync, note
         * decrypt, nullifier spend, mempool remove, MMR, MMB) are dropped for
         * this height. */
        LOG_WARN("tip_finalize",
                 "post-finalize side effects skipped h=%d have_data=%d: "
                 "body unreadable; wallet/mempool/MMR/MMB deferred",
                 pindex_new->nHeight,
                 (pindex_new->nStatus & BLOCK_HAVE_DATA) ? 1 : 0);
        /* A partial injected-reader deserialize can have allocated owned.vtx before the
         * read failed — the success path frees it at the bottom; this
         * early return must too. */
        block_free(&owned);
        return;
    }

    /* Fail-loud validation pack, check 2: the BIP34-style height embedded
     * in the coinbase scriptSig must equal OUR label for the block just
     * finalized. The body was already read back from disk above, so this
     * costs one header hash + a few byte compares — no extra I/O. A
     * mismatch is a label/height shift (a mis-spliced chain): HOLD the
     * pipeline (refuse h+1 onward) + PAGE. E13-neutral: the block stays
     * valid; only OUR pipeline holds. Crash-only: no FATAL, side effects
     * still run so the published tip stays coherent.
     *
     * HASH-BOUND: the check fires only when the read body IS the indexed
     * block (header hash == phashBlock). A body that hashes differently
     * is a mis-positioned/corrupt body — a different defect class, owned
     * by the have_data_unreadable machinery, and comparing ITS coinbase
     * against OUR label would be a false splice signal. */
    if (pindex_new->nHeight >= 1 && pindex_new->phashBlock &&
        blk->num_vtx > 0) {
        struct uint256 body_hash;
        block_get_hash(blk, &body_hash);
        if (uint256_eq(&body_hash, pindex_new->phashBlock) &&
            !check_block_coinbase_height_matches(&blk->vtx[0],
                                                 pindex_new->nHeight)) {
            char reason[160];
            snprintf(reason, sizeof(reason),
                     "coinbase-embedded height != our label h=%d (label "
                     "shift detected at finalize; held before h=%d)",
                     pindex_new->nHeight, pindex_new->nHeight + 1);
            LOG_WARN("tip_finalize", "[validation_pack] %s", reason);
            chain_linkage_hold_raise("coinbase_label",
                                     "chain.coinbase_label_mismatch",
                                     pindex_new->nHeight + 1, reason);
        }
    }

    /* Wallet publication is idempotent and is also reused when this body
     * becomes visible after served-tip authority already reached the height. */
    tip_finalize_reconcile_wallet_body(pindex_new, blk);

    /* Publish the committed coins_kv generation to the long-lived read cache
     * before any later relay or block-template selection can consult it. The
     * reducer authors coins_kv directly (not through coins_tip.batch_write),
     * so cache entries loaded while this block was in the mempool otherwise
     * retain the pre-connect generation forever: spent parents still look
     * live and newly-created txids can remain absent. Invalidate exactly the
     * keys this finalized block changed; the next read resolves through the
     * canonical coins_kv path. */
    tip_finalize_reconcile_block(pindex_new, blk);

    /* Projection-deferred DIAGNOSTIC.
     * The reducer consensus path does NOT write the derived block/tx SQLite
     * projection inline — the active chain, block index, and coins view are
     * authoritative and the projection is repairable from verified block
     * bytes. Record that the per-block projection write was deferred as a
     * DIAGNOSTIC counter. This is NOT a block reject: the tip already
     * advanced. Explicit import/catchup paths backfill the projection under
     * the DB service's write ownership. */
    {
        struct node_db *ndb = app_runtime_node_db();
        if (ndb)
            block_source_policy_note_projection_deferred(
                pindex_new->nHeight, "consensus_path");
    }

    /* Append block hash to Merkle Mountain Range */
    if (pindex_new->phashBlock)
        rpc_blockchain_mmr_append(pindex_new->phashBlock->data);

    /* Append rich leaf to Merkle Mountain Belt (O(1) per block).
     *
     * Keystone: at a 100-block boundary, the leaf carries the SHA3 root of the
     * full UTXO set as it stands AFTER this block (coins_kv_commitment — the
     * one canonical encoder). This is the only path that observes the live
     * coins set at the exact moment it equals height H, so it computes the
     * boundary root ONCE here and records it under the per-height key; catch-up
     * and leaf-store rebuild read that recorded value so every leaf hash is
     * byte-identical regardless of which path built it. The O(N) SHA3 fold runs
     * only once per 100 blocks and only at the live tip — never on a
     * latency-critical path.
     *
     * The fold is gated OFF in two catch-up postures; in both, the boundary
     * root is left ABSENT — the leaf carries the zero sentinel, the same
     * pre-keystone hash the catch-up pass (rpc_blockchain_mmb_catchup) and
     * leaf-store rebuild reproduce from a missing table entry (the keystone
     * binding for that boundary is simply absent, never forged):
     *   1. deferred-proof-validation IBD (h <=
     *      g_deferred_proof_validation_below_height — the same guard the MMR
     *      commit uses): re-folding the full set every 100 blocks while
     *      replaying millions of blocks is wasteful.
     *   2. live catch-up (catchup_cadence_active(): peers connected AND gap
     *      >= ZCL_CATCHUP_GAP_THRESHOLD, default 500 — the same predicate the
     *      staged-sync supervisor already uses for this class of decision):
     *      a snapshot/bundle-seeded node folds ABOVE the checkpoint, where
     *      guard 1 no longer applies, but the full-table scan every 100
     *      blocks still sits inline on the fold critical path.
     * Skipped roots are NOT recomputed later: no path can observe the
     * historical coins set at H once the tip has moved past it, and every
     * consumer (mmb catch-up, leaf-store rebuild, FlyClient prover, legacy
     * oracle, ladder verify) maps a missing entry back to the zero sentinel,
     * so this node's leaf hashes stay internally byte-consistent. At tip both
     * gates are false and the fold runs exactly as before. */
    if (pindex_new->phashBlock) {
        uint8_t utxo_root[32] = {0};
        if (pindex_new->nHeight > 0 &&
            pindex_new->nHeight % MMR_COMMITMENT_INTERVAL == 0) {
            extern _Atomic int g_deferred_proof_validation_below_height;
            int defer_below = atomic_load(&g_deferred_proof_validation_below_height);
            bool ibd_defer = (defer_below >= 0 &&
                              pindex_new->nHeight <= defer_below);
            /* Live catch-up: skip the O(N) boundary scan exactly like the
             * IBD-defer posture (zero-sentinel leaf). Cheap: evaluated only
             * at boundary heights; catchup_cadence_active() is two lock-free
             * reads and touches no reducer-drive lock. */
            bool catchup_defer = !ibd_defer && catchup_cadence_active();
            if (!ibd_defer && !catchup_defer) {
                sqlite3 *pdb = progress_store_db();
                if (pdb && coins_kv_commitment(pdb, utxo_root) == 0) {
                    /* Persist before the leaf so a crash between append and
                     * save still lets the next catch-up reproduce this hash.
                     * MUST be the in-tx variant: this runs inside the stage's
                     * batch BEGIN IMMEDIATE + per-step SAVEPOINT, so the
                     * own-BEGIN _set fails 100% ("cannot start a transaction
                     * within a transaction") and never persists the root.
                     * In-tx commits the root atomically with this height's
                     * finalize log row.
                     *
                     * Streak-throttled diagnostic: post_finalize runs on the
                     * serial reducer drive under progress_store_tx_lock, so the
                     * statics are race-free. Log the FIRST failure of a streak
                     * (loud, named) and suppress the rest; the next success
                     * emits one recovery line with the suppressed count — never
                     * a per-boundary WARN spam. */
                    static int s_boundary_fail_streak = 0;
                    if (!coins_kv_boundary_root_set_in_tx(
                            pdb, pindex_new->nHeight, utxo_root)) {
                        if (s_boundary_fail_streak++ == 0)
                            LOG_WARN("tip_finalize",
                                     "boundary utxo_root persist failed h=%d "
                                     "(leaf still carries the computed root; "
                                     "suppressing repeats until it recovers)",
                                     pindex_new->nHeight);
                    } else if (s_boundary_fail_streak > 0) {
                        LOG_INFO("tip_finalize",
                                 "boundary utxo_root persist recovered h=%d "
                                 "after %d suppressed failure(s)",
                                 pindex_new->nHeight, s_boundary_fail_streak);
                        s_boundary_fail_streak = 0;
                    }
                } else {
                    memset(utxo_root, 0, 32);
                    LOG_WARN("tip_finalize",
                             "coins_kv_commitment failed h=%d; leaf carries "
                             "zero utxo_root sentinel", pindex_new->nHeight);
                }
            }
        }

        struct mmb_leaf leaf;
        mmb_leaf_from_block(&leaf,
            pindex_new->phashBlock->data,
            pindex_new->nHeight, pindex_new->nTime, pindex_new->nBits,
            pindex_new->hashFinalSaplingRoot.data,
            (const uint8_t *)pindex_new->nChainWork.pn,
            utxo_root);
        rpc_blockchain_mmb_append(&leaf);
    }

    /* OBSERVE-ONLY SHA3 golden-window corroboration tripwire. Runs at most once
     * per 1000-block window, only for windows covered by the locked golden
     * table, and only HERE — after the tip is already published above. It emits
     * evidence (a typed blocker + EV_BLOCK_INDEX_CORRUPT) on a digest mismatch
     * and NEVER rejects a block, raises a HOLD, or changes the tip. Consensus
     * parity with zclassicd is bit-identical whether or not it fires. */
    sha3_window_tripwire_at_boundary(pindex_new, datadir);

    /* OBSERVE-ONLY golden UTXO-root ladder corroboration tripwire (same
     * posture as the SHA3 tripwire directly above). See
     * utxo_root_ladder_tripwire.h for the full contract. */
    utxo_root_ladder_tripwire_at_boundary(pindex_new->nHeight);

    stage_release_block_view(&owned, &handle, borrowed);
}
