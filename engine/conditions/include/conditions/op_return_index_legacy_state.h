/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * op_return_index_legacy_state — public registration + test hooks for the
 * self-heal condition that names a REFUSED legacy_v1/unknown op_return_index
 * persisted cursor state (engine/models/src/op_return_index.c) as a typed,
 * rearm-forever blocker. Mirrors the state_auditor_mismatch / catalog_lag_
 * exceeded template. */

#ifndef ZCL_CONDITIONS_OP_RETURN_INDEX_LEGACY_STATE_H
#define ZCL_CONDITIONS_OP_RETURN_INDEX_LEGACY_STATE_H

#include <stdbool.h>

/* SYMPTOM: op_return_index_state_is_legacy_refused() classifies the
 *   persisted op_return_index cursor state as LEGACY_V1 (a pre-range record
 *   left by an older binary) or UNKNOWN (a future/corrupt record) — either
 *   way, op_return_index_get_cursor() REFUSES rather than reinterpret it.
 * REMEDY (non-destructive): log the classification and raise/refresh the
 *   typed named blocker "op_return_index.legacy_state" (BLOCKER_DEPENDENCY
 *   — there is no safe auto-repair for a foreign record shape; an operator
 *   rebuild is the real cure). Never truncates or rewrites any store —
 *   `z23 app oprindex rebuild` (op_return_index_truncate) is the named
 *   escape, run by a human, not by this remedy.
 * WITNESSED: op_return_index_state_is_legacy_refused() reads false again
 *   (EMPTY or V2) — a real external fix landed (the operator ran the
 *   rebuild), not a coincidental clean read elsewhere.
 * COND_WARN; poll_secs=5; rearm-forever cooldown (peer_floor's / state_
 *   auditor_mismatch's posture) so a persisting legacy record keeps nudging
 *   without permanently latching. */
void register_op_return_index_legacy_state(void);

#ifdef ZCL_TESTING
struct node_db;
void op_return_index_legacy_state_test_reset(void);
void op_return_index_legacy_state_test_set_node_db(struct node_db *ndb);
int op_return_index_legacy_state_test_remedy(void);
bool op_return_index_legacy_state_test_detect(void);
bool op_return_index_legacy_state_test_witness(void);
int op_return_index_legacy_state_test_remedy_calls(void);
#endif

#endif /* ZCL_CONDITIONS_OP_RETURN_INDEX_LEGACY_STATE_H */
