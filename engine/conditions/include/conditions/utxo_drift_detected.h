/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONDITIONS_UTXO_DRIFT_DETECTED_H
#define ZCL_CONDITIONS_UTXO_DRIFT_DETECTED_H

/* SYMPTOM: the persisted utxo_drift_detected state flag is set (the local
 *   UTXO sha3 diverged from the audited remote sha3 at utxo_audit_last_height).
 * REMEDY: action=operator_escalation — log local/remote sha3, emit
 *   EV_UTXO_DRIFT_DETECTED, and return COND_REMEDY_FAILED so the engine pages
 *   rather than auto-running a destructive wipe/reimport (consensus-critical).
 * WITNESSED: the drift flag is clear again — which only an external repair or
 *   operator can do (the remedy never clears it).
 * COND_CRITICAL; poll_secs=60 (backoff 300s, max_attempts 1). */
void register_utxo_drift_detected(void);

#ifdef ZCL_TESTING
struct node_db;
void utxo_drift_detected_test_reset(void);
void utxo_drift_detected_test_set_node_db(struct node_db *ndb);
int utxo_drift_detected_test_remedy_calls(void);
#endif

#endif /* ZCL_CONDITIONS_UTXO_DRIFT_DETECTED_H */
