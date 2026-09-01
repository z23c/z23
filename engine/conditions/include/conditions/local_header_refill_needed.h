/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONDITIONS_LOCAL_HEADER_REFILL_NEEDED_H
#define ZCL_CONDITIONS_LOCAL_HEADER_REFILL_NEEDED_H

/* SYMPTOM: peer_max >= tip+1 but the active tip has no next-child header at
 *   tip+1 (sync_monitor_active_next_child_exists() false) — the local header
 *   chain needs the missing header to extend.
 * REMEDY: sync_monitor_local_header_refill(next_h); if block_source_policy
 *   decision=proceed, force SYNC_HEADERS_DOWNLOAD + kick_local_sync.
 * WITNESSED: the missing header child at g_missing_height now exists, OR
 *   peers retreated below that height (the gap closed from the other end).
 * COND_WARN; poll_secs=5 (backoff 300s, max_attempts 3). */
void register_local_header_refill_needed(void);

#ifdef ZCL_TESTING
void local_header_refill_needed_test_reset(void);
int local_header_refill_needed_test_remedy_calls(void);
#endif

#endif /* ZCL_CONDITIONS_LOCAL_HEADER_REFILL_NEEDED_H */
