/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * disk_low_pause — self-heal condition for the index-fold "*.disk_low"
 * blockers.
 *
 * SYMPTOM: a secondary-index backfill (address_index or txindex projection)
 *   is holding a NAMED "<index_id>.disk_low" BLOCKER_RESOURCE blocker,
 *   raised by index_fold_guard.c's index_fold_disk_ok() when free space on
 *   the datadir fs drops below the fold's conservative headroom floor (or
 *   the global disk_monitor is already CRITICAL). Keep this enumeration in
 *   sync with index_fold_disk_ok()'s callers — currently exactly two:
 *   address_index_service.c and txindex_projection_service.c.
 * REMEDY: this condition does not raise or clear the "<index_id>.disk_low"
 *   blockers itself (index_fold_disk_ok owns that lifecycle) — it reclaims
 *   DERIVED/temp bytes (the same storage_reclaim_derived() reclaim
 *   disk_full_pause uses: WAL checkpoint+truncate, stale *.tmp sweep) and
 *   forces a fresh disk_monitor poll, so the NEXT index_fold_disk_ok() call
 *   (driven by the fold's own tip-follow cadence) sees the freed headroom
 *   and clears its own blocker. AUTO-TERMINATING: transient-resource class,
 *   same cooldown shape as disk_full_pause — re-arms UNBOUNDED, NEVER
 *   latches operator_needed.
 * WITNESSED: neither "<index_id>.disk_low" blocker is present anymore (the
 *   fold's own next pass cleared it after space returned).
 * COND_CRITICAL; poll_secs=15. */

#ifndef ZCL_CONDITIONS_DISK_LOW_PAUSE_H
#define ZCL_CONDITIONS_DISK_LOW_PAUSE_H

void register_disk_low_pause(void);

#ifdef ZCL_TESTING
void disk_low_pause_test_reset(void);
int  disk_low_pause_test_remedy_calls(void);
#endif

#endif /* ZCL_CONDITIONS_DISK_LOW_PAUSE_H */
