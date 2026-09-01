/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * tip_finalize provable-tip (H*) cache management — a separable concern from
 * the finalize step, so it owns its own translation unit.
 * H* is DEFINED by the pure SELECT-only fold (reducer_frontier_compute_hstar);
 * the functions here maintain a re-derivable VIEW of it, never a second
 * writable ledger. All are pure functions of the durable progress DB. */

#ifndef ZCL_JOBS_TIP_FINALIZE_PROVABLE_TIP_H
#define ZCL_JOBS_TIP_FINALIZE_PROVABLE_TIP_H

struct sqlite3;

/* Recompute H* from durable progress.kv and publish it into the provable-tip
 * cache; leaves the cache unchanged (logs) on a read error. CALLER holds
 * progress_store_tx_lock(). */
void tf_refresh_provable_tip(struct sqlite3 *db);

/* One-time boot warm: publish H* from the full fold if the cache is still the
 * unpublished sentinel. Takes progress_store_tx_lock() itself. */
void tf_warm_provable_tip_once(struct sqlite3 *db, const char *reason);

/* O(1) watermark advance after finalizing next_h: bump the cache by one row
 * when it extends the published, adjacent frontier; fall back to the full fold
 * (which repairs the cache) on any doubt, with a named throttled log. CALLER
 * holds progress_store_tx_lock(). */
void tf_advance_provable_tip(struct sqlite3 *db, int next_h);

#endif /* ZCL_JOBS_TIP_FINALIZE_PROVABLE_TIP_H */
