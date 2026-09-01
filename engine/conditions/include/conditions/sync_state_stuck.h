/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONDITIONS_SYNC_STATE_STUCK_H
#define ZCL_CONDITIONS_SYNC_STATE_STUCK_H

/* SYMPTOM: the SYNC FSM has been parked >= 600s in a non-healthy state (not
 *   AT_TIP/HEADERS_DOWNLOAD/BLOCKS_DOWNLOAD) with no active long_op.
 * REMEDY: action=kick_fsm — emit EV_TIP_STALE, force SYNC_HEADERS_DOWNLOAD,
 *   sync_monitor_kick_local_sync().
 * WITNESSED: now in a healthy state (at tip or downloading) AND the tip
 *   height advanced since detect — both required (FSM-changed alone is a lie).
 * COND_WARN; poll_secs=5 (backoff 600s, max_attempts 3). */
void register_sync_state_stuck(void);

#ifdef ZCL_TESTING
void sync_state_stuck_test_reset(void);
int sync_state_stuck_test_remedy_calls(void);
#endif

#endif /* ZCL_CONDITIONS_SYNC_STATE_STUCK_H */
