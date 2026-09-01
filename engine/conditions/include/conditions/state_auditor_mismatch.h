/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * state_auditor_mismatch — public registration + test hooks for the
 * self-heal condition that names a CONFIRMED state_auditor integrity
 * mismatch (see services/state_auditor.h) as a typed, rearm-forever blocker.
 * Mirrors the catalog_lag_exceeded / peer_floor_violated template. */

#ifndef ZCL_CONDITIONS_STATE_AUDITOR_MISMATCH_H
#define ZCL_CONDITIONS_STATE_AUDITOR_MISMATCH_H

#include <stdbool.h>

/* SYMPTOM: state_auditor has CONFIRMED (STATE_AUDITOR_CONFIRM_STREAK
 *   consecutive samples of the SAME pinned window/range) a stored-vs-
 *   recomputed integrity mismatch on some leg (op_return_index catalog
 *   digest, or the coins_kv-authority-vs-utxos-projection XOR commitment
 *   over a keyspace window).
 * REMEDY (non-destructive): log which leg + range + detail, and
 *   raise/refresh the typed named blocker "state_auditor.<leg>.mismatch"
 *   (BLOCKER_DEPENDENCY — there is no safe auto-repair for a corrupted
 *   stored commitment; an operator/backfill rebuild is the real cure).
 *   Never truncates or rewrites any store.
 * WITNESSED: state_auditor's OWN re-check of that exact pinned window came
 *   back clean (a real external fix landed — e.g. a truncate + backfill
 *   re-derive of op_return_index, or a checkpoint resync) — NOT a
 *   coincidental clean sample somewhere else in the keyspace/height space,
 *   because state_auditor keeps re-checking the SAME pinned window while a
 *   mismatch is latched (services/state_auditor.h "investigating" state).
 * COND_WARN; poll_secs=5; rearm-forever cooldown (peer_floor's posture) so a
 *   persisting mismatch keeps nudging without permanently latching. */
void register_state_auditor_mismatch(void);

#ifdef ZCL_TESTING
int state_auditor_mismatch_test_remedy(void);
bool state_auditor_mismatch_test_detect(void);
bool state_auditor_mismatch_test_witness(void);
void state_auditor_mismatch_test_reset(void);
#endif

#endif /* ZCL_CONDITIONS_STATE_AUDITOR_MISMATCH_H */
