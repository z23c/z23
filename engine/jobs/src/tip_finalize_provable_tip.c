/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * tip_finalize provable-tip (H*) cache — implementation.
 * See tip_finalize_provable_tip.h for the contract. */

#include "tip_finalize_provable_tip.h"

#include "platform/time_compat.h"
#include "jobs/reducer_frontier.h"
#include "storage/progress_store.h"
#include "util/boot_scan.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"

#include <sqlite3.h>
#include <stdint.h>

/* Recompute H* (the deepest provably-consistent height) from the durable
 * progress.kv state and publish it into the external provable-tip cache.
 *
 * Called at the finalize ADVANCE (once per finalized block, but only on the
 * full-fold fallback below — the common case is the O(1) watermark bump), the
 * reorg REWIND (once per detected reorg), and the one-time boot warm. All
 * callers hold progress_store_tx_lock(). reducer_frontier_compute_hstar is PURE
 * SELECT-only and REQUIRES the caller hold that lock, so this must never run
 * without it. On a read error it leaves the cache unchanged (logs, does not
 * crash) — a stale-but-bounded H* is strictly better than serving -1 or a wrong
 * tip.
 *
 * CALLER MUST hold progress_store_tx_lock(). */
void tf_refresh_provable_tip(sqlite3 *db)
{
    if (!db)
        return;
    int32_t hs = 0, sf = 0;
    if (!reducer_frontier_compute_hstar(db, &hs, &sf)) {
        LOG_WARN("tip_finalize",
                 "[tip_finalize] provable-tip refresh: compute_hstar failed "
                 "(cache holds prior H*)");
        return;
    }
    reducer_frontier_provable_tip_set(hs);
}

void tf_warm_provable_tip_once(sqlite3 *db, const char *reason)
{
    if (!db || reducer_frontier_provable_tip_is_published())
        return;
    progress_store_tx_lock();
    if (!reducer_frontier_provable_tip_is_published()) {
        tf_refresh_provable_tip(db);
        if (reducer_frontier_provable_tip_is_published()) {
            LOG_INFO("tip_finalize",
                     "[tip_finalize] provable-tip cache warmed h=%d reason=%s",
                     reducer_frontier_provable_tip_cached(),
                     reason ? reason : "");
        }
    }
    progress_store_tx_unlock();
}

/* Advance the H* provable-tip cache after finalizing `next_h`. H* is DEFINED by
 * the pure SELECT-only fold (reducer_frontier_compute_hstar); this cache is a
 * re-derivable VIEW of it, never a second writable ledger. Common case — the
 * just-finalized block extends the published, adjacent frontier — is O(1): bump
 * the watermark by one row (the exact hash-bound receipts checked upstream prove
 * this one-height extension without re-reading the already-proven prefix). ANY
 * doubt — cache unpublished, or not exactly one below next_h (a gap, a fresh
 * cache, an anchor transition, a prior non-finalize row, or a reorg that took
 * the full rewind path) — falls back to the complete fold, which REPAIRS the
 * cache from durable state, with a named (throttled) log line. The boot warm
 * (tf_warm_provable_tip_once) already seeds the cache from the full fold, so the
 * first steady advance builds on a fold-verified base; the cache is volatile
 * (never persisted), re-derived at every boot and on every doubt, so it cannot
 * silently drift — there is no durable second copy to cross-check, and a crash
 * simply drops it. CALLER holds progress_store_tx_lock(). */
void tf_advance_provable_tip(sqlite3 *db, int next_h)
{
    /* Resolve the counter once PER FINALIZE (not per row, and not cached across
     * a boot_scan_reset_for_testing() — that clears the registration table, so
     * a cached pointer would bump an orphaned slot the by-name reader can't
     * find; one find() over <=48 slots per finalize is negligible). */
    if (reducer_frontier_provable_tip_is_published()) {
        int32_t cached = reducer_frontier_provable_tip_cached();
        if (cached == next_h - 1) {
            reducer_frontier_provable_tip_set(next_h);
            boot_scan_bump(boot_scan_counter("reducer_frontier.hstar_fastpath"));
            return;
        }
        /* Already current: another path in THIS finalize cycle published H*
         * at exactly the height we just finalized (the on-demand authority
         * anchor republishes H* on every ingested tip block before the
         * stage's own advance runs, and a mint/refold re-warm does the same).
         * Publishing next_h again would be a no-op, so take the O(1) exit
         * instead of re-folding the whole frontier per block — measured at
         * ~2.1 ms/block of pure compute_hstar work on a regtest fold, all of
         * it confirming a value the cache already held. Anything else
         * (cached < next_h - 1 or cached > next_h) is still "any doubt"
         * and takes the full fold below. */
        if (cached == next_h) {
            boot_scan_bump(boot_scan_counter("reducer_frontier.hstar_fastpath"));
            return;
        }
    }

    /* Named, throttled: the full-fold fallback / self-heal (normal on the first
     * advance each boot). Observability only — no blocker reason carries this. */
    static struct log_throttle fallback_throttle = LOG_THROTTLE_INIT;
    uint64_t reps = 0;
    if (log_throttle_should_emit(&fallback_throttle, 1,
                                 platform_time_wall_unix(), 300, &reps))
        LOG_INFO("tip_finalize",
                 "[tip_finalize] H* cache full-fold fallback (non-adjacent "
                 "frontier next_h=%d cached=%d) repeated=%llu",
                 next_h, reducer_frontier_provable_tip_cached(),
                 (unsigned long long)reps);
    tf_refresh_provable_tip(db);
}
