/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONDITIONS_SYNC_VIOLATION_LAG_H
#define ZCL_CONDITIONS_SYNC_VIOLATION_LAG_H

/* SYMPTOM: the gap (peer_max - local) stays above SYNC_VIOLATION_GAP (100)
 *   for >= SYNC_VIOLATION_SECS (600) with no local height movement — we are
 *   lagging the network's tip and not making observable progress.
 * REMEDY: action=outbound_rotation — connman_force_outbound_rotation(),
 *   record WATCHDOG_SYNC_VIOLATION, set SYNC_IDLE then kick_local_sync;
 *   rate-limited by SYNC_VIOLATION_COOLDOWN_SECS (3600).
 * WITNESSED: the gap closed — peer_max - local <= SYNC_VIOLATION_GAP.
 * COND_CRITICAL; poll_secs=5 (backoff 60s, max_attempts 1). Continue-with-
 * cooldown: re-arms every 600s, unbounded, past max_attempts instead of
 * latching permanently (external-resource/peer-dependent condition). */
void register_sync_violation_lag(void);

#ifdef ZCL_TESTING
void sync_violation_lag_test_reset(void);
int sync_violation_lag_test_remedy_calls(void);
#endif

#endif /* ZCL_CONDITIONS_SYNC_VIOLATION_LAG_H */
