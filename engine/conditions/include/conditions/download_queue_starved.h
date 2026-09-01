/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONDITIONS_DOWNLOAD_QUEUE_STARVED_H
#define ZCL_CONDITIONS_DOWNLOAD_QUEUE_STARVED_H

/* SYMPTOM: in SYNC_BLOCKS_DOWNLOAD with peers and pending download work
 *   (queued, in-flight, or unsettled requests), in_flight stays below
 *   DL_MAX_IN_FLIGHT_TOTAL_IBD/QUEUE_STARVED_RATIO_DEN for >= 120s.
 * REMEDY: action=kick_refill — sync_monitor_kick_local_sync().
 * WITNESSED: the cumulative request counter advanced past the value captured
 *   at detect (new blocks requested), or the pending work drained/settled.
 * COND_WARN; poll_secs=5 (backoff 120s, max_attempts 5 -> operator_needed). */
void register_download_queue_starved(void);

#ifdef ZCL_TESTING
void download_queue_starved_test_reset(void);
int download_queue_starved_test_remedy_calls(void);
#endif

#endif /* ZCL_CONDITIONS_DOWNLOAD_QUEUE_STARVED_H */
