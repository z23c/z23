/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONDITIONS_DISK_FULL_PAUSE_H
#define ZCL_CONDITIONS_DISK_FULL_PAUSE_H

/* SYMPTOM: the disk_monitor free-space watchdog reports CRITICAL
 *   (disk_monitor_is_critical() == true) — free bytes below the refuse
 *   threshold (default 1 GB), the same flag the block processor / mempool
 *   already consult before committing new bytes (so this also covers the
 *   SQLITE_FULL / ENOSPC surface). A full disk is otherwise a SILENT refuse.
 * REMEDY: raise a NAMED BLOCKER_RESOURCE blocker ("disk-full", owner
 *   "storage") so the stall is named not silent; force disk_monitor_poll_now()
 *   and reclaim DERIVED/temp bytes (WAL checkpoint+truncate of the sqlite DBs,
 *   *.tmp scratch under the datadir). Drains were never hard-stopped — the
 *   disk_monitor_is_critical() gate the write paths honor IS the pause; this
 *   condition adds the named blocker + the always-terminating reclaim + the
 *   resume witness. AUTO-TERMINATING: transient-resource class — re-arms on a
 *   long cooldown UNBOUNDED, NEVER latches operator_needed.
 * WITNESSED: a fresh poll shows !disk_monitor_is_critical() (space returned;
 *   the write-path gate self-clears and drains resume).
 * COND_CRITICAL; poll_secs=15. */
void register_disk_full_pause(void);

#ifdef ZCL_TESTING
void disk_full_pause_test_reset(void);
int  disk_full_pause_test_remedy_calls(void);
#endif

#endif /* ZCL_CONDITIONS_DISK_FULL_PAUSE_H */
