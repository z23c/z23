// one-result-type-ok:sapling-checkpoint-hook-best-effort-semantics
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sapling_checkpoint_hook — implementation. See services/sapling_checkpoint_hook.h.
 *
 * Return type is bare void (NOT struct zcl_result), same as anchor_selfmint
 * and seal_service: this is OBSERVE-ONLY and BEST-EFFORT — a write/lookup
 * failure here MUST NOT fail the block, so there is nothing for a caller to
 * branch on. Failures are logged by the functions this calls
 * (sapling_tree_flat_checkpoint_note) and dropped. */

#include "services/sapling_checkpoint_hook.h"

#include "platform/time_compat.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/anchor_kv.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "validation/process_block.h"

#include <sqlite3.h>
#include <stdatomic.h>

/* Named so both the raise and the self-clear below agree on identity. */
#define SAPLING_CKPT_ANCHOR_READ_ERROR_BLOCKER_ID \
    "sapling_checkpoint_hook.anchor_read_error"

/* Own interval counter, independent of the shared one inside
 * sapling_tree_flat_checkpoint_note (which node_db_catchup_service.c's
 * calls also pace against). Keeping this separate means this hook's own
 * cadence (tied to REDUCER-applied blocks) is never stolen by the catchup
 * lane's calls, and vice versa — each call site owns its own "when", while
 * sapling_tree_flat_checkpoint_note's reducer-cursor BOUND (not pacing) is
 * the single, shared correctness guard both funnel through. */
static _Atomic int64_t g_blocks_since_reducer_ckpt_attempt = 0;

void sapling_checkpoint_hook_in_tx(struct sqlite3 *db, int64_t height,
                                   const uint8_t block_hash[32])
{
    if (!db || !block_hash || !sapling_checkpoint_path())
        return;

    /* Cheap self-pacing FIRST, before any DB read: this hook runs on EVERY
     * successfully-applied reducer block (called from utxo_apply_stage.c's
     * step_apply), so the expensive path (anchor tree SELECT +
     * deserialize) must not run on the hot per-block path during fast IBD
     * replay. On all but one call in SAPLING_CHECKPOINT_BLOCK_INTERVAL this
     * is a single atomic increment and nothing else. */
    int64_t since = atomic_fetch_add(&g_blocks_since_reducer_ckpt_attempt, 1) + 1;
    if (since < SAPLING_CHECKPOINT_BLOCK_INTERVAL)
        return;
    atomic_store(&g_blocks_since_reducer_ckpt_attempt, 0);

    /* Fetch the CURRENT reducer-applied Sapling frontier (the same anchor_kv
     * table utxo_apply_anchors.c's fold_sapling reads/writes) — never the
     * catchup lane's own private tree. No-op when no frontier exists yet:
     * pre-activation, or the exact birth-defect empty-table window the
     * empty-frontier healer exists to cure — there is nothing correct to
     * checkpoint in either case, and fold_sapling would refuse identically. */
    struct incremental_merkle_tree tree;
    enum anchor_kv_lookup_result lr =
        anchor_kv_latest_tree(db, ANCHOR_POOL_SAPLING, &tree, NULL, NULL);
    if (lr == ANCHOR_KV_ERROR) {
        /* A store-level failure reading sapling_anchors (prepare/step/decode
         * error inside anchor_kv_latest_tree) is distinct from the benign
         * "no frontier yet" case (ANCHOR_KV_HISTORY_INCOMPLETE /
         * ANCHOR_KV_MISSING, handled by the `lr != ANCHOR_KV_FOUND` fallthrough
         * below). Best-effort/non-fatal for THIS hook — the checkpoint cache is
         * a pure optimization, never fold_sapling's source of truth — but a
         * bare LOG_WARN that scrolls off is invisible to dumpstate/automation.
         * Raise a named, self-clearing TRANSIENT blocker so a persistent
         * sapling_anchors read failure is a first-class, throttled signal
         * instead of a silently-dropped log line. */
        static struct log_throttle ckpt_anchor_err_throttle = LOG_THROTTLE_INIT;
        int64_t now = platform_time_wall_unix();
        uint64_t reps = 0;
        if (log_throttle_should_emit(&ckpt_anchor_err_throttle, 1, now, 300,
                                     &reps))
            LOG_WARN("sapling_checkpoint_hook",
                     "anchor_kv_latest_tree store error at h=%lld — skipping "
                     "this checkpoint attempt (best-effort, not fatal) "
                     "repeated=%llu",
                     (long long)height, (unsigned long long)reps);
        struct blocker_record rec;
        if (blocker_init(&rec, SAPLING_CKPT_ANCHOR_READ_ERROR_BLOCKER_ID,
                         "sapling_checkpoint_hook", BLOCKER_TRANSIENT,
                         "anchor_kv_latest_tree failed reading sapling_anchors "
                         "during a periodic checkpoint attempt — the flat "
                         "checkpoint cache is best-effort so boot/sync are "
                         "unaffected, but a persisted read error on that "
                         "table warrants operator attention"))
            blocker_set(&rec);
        return;
    }
    if (lr != ANCHOR_KV_FOUND)
        return;
    /* A clean read clears any earlier read-error episode — self-terminating,
     * same discipline as every other typed blocker in this codebase. */
    blocker_clear(SAPLING_CKPT_ANCHOR_READ_ERROR_BLOCKER_ID);

    /* force=true: this hook already self-paced above, so it does not need
     * the shared inner interval gate inside sapling_tree_flat_checkpoint_note
     * to also throttle it. That function's own reducer-cursor BOUND still
     * applies regardless of force — defense in depth: `height` is provably
     * == the reducer's own coins_applied_height-1 in this same transaction,
     * but the guard is never bypassed on the strength of that assumption
     * alone. */
    sapling_tree_flat_checkpoint_note(&tree, height, block_hash, true);
}

#ifdef ZCL_TESTING
void sapling_checkpoint_hook_test_force_next(void)
{
    atomic_store(&g_blocks_since_reducer_ckpt_attempt,
                (int64_t)SAPLING_CHECKPOINT_BLOCK_INTERVAL);
}
#endif
