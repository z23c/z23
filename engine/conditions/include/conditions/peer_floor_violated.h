/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONDITIONS_PEER_FLOOR_VIOLATED_H
#define ZCL_CONDITIONS_PEER_FLOOR_VIOLATED_H

/* SYMPTOM: outbound healthy peer count stays below PEER_FLOOR_MIN_HEALTHY (3)
 *   for >= PEER_FLOOR_TRIGGER_SECS (60) (unless ZCL_PEERLESS_OK=1).
 * REMEDY: if block_source_policy decision=recover — drop stalled outbound +
 *   excess inbound peers, reset addnode backoff, connman_kick_seed_discovery,
 *   kick_local_sync, record WATCHDOG_PEER_FLOOR recovery.
 * WITNESSED: healthy peers back above the floor AND the chain actually moved
 *   (local height advanced past detect, OR we are already at/above peer_max —
 *   peers were the only deficit); peers-alone is the old false-ok bug.
 * COND_WARN; poll_secs=5 (backoff 60s, max_attempts 5 -> operator_needed). */
void register_peer_floor_violated(void);

#ifdef ZCL_TESTING
void peer_floor_violated_test_reset(void);
int peer_floor_violated_test_remedy_calls(void);
#endif

#endif /* ZCL_CONDITIONS_PEER_FLOOR_VIOLATED_H */
