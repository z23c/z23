/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONDITIONS_REPLAY_CANARY_FAILED_H
#define ZCL_CONDITIONS_REPLAY_CANARY_FAILED_H

/* SYMPTOM: a replay-canary sentinel (replay_canary_<kind>.json in the
 *   verdict dir) reports verdict=="FAIL" — the standing replay harness
 *   proved this binary cannot honestly re-derive the chain (or cross-node
 *   parity broke). The canary_sentinel_watch service latches the verdict;
 *   this Condition reads its latch.
 * REMEDY: action=operator_escalation — log every FAIL kind's reason+ts and
 *   return COND_REMEDY_FAILED so the engine pages. There is no safe
 *   auto-remedy: a replay FAIL is consensus-grade evidence and only a
 *   subsequent PASS run (or operator action) may clear it.
 * WITNESSED: the watch latch reads clear again — which only a later canary
 *   run writing a PASS sentinel for every previously-FAIL kind can do (the
 *   remedy never touches the latch; sentinel ABSENCE never clears it).
 * COND_CRITICAL; poll_secs=60 (backoff 300s, max_attempts 1). */
void register_replay_canary_failed(void);

#ifdef ZCL_TESTING
void replay_canary_failed_test_reset(void);
int replay_canary_failed_test_remedy_calls(void);
#endif

#endif /* ZCL_CONDITIONS_REPLAY_CANARY_FAILED_H */
