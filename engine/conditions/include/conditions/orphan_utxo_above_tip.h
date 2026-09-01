/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONDITIONS_ORPHAN_UTXO_ABOVE_TIP_H
#define ZCL_CONDITIONS_ORPHAN_UTXO_ABOVE_TIP_H

/* SYMPTOM: UTXO rows sit ABOVE the active chain tip — orphans left by a
 *   rewind/reorg where the coins set ended up ahead of the connected tip
 *   (any_utxo_above(tip_h), tip_h > 0).
 * REMEDY: action=clean_above_tip — utxo_recovery_clean_above_tip(), the
 *   bounded helper that only auto-deletes a single-block overshoot of
 *   <= UTXO_BOOT_REWIND_MAX_ROWS (32); a larger overshoot is refused and
 *   surfaced as COND_REMEDY_FAILED so the engine backs off / pages a human.
 * WITNESSED: no UTXO row remains above the current tip (!any_utxo_above).
 * COND_WARN; poll_secs=60 (backoff 300s, max_attempts 3). */
void register_orphan_utxo_above_tip(void);

#ifdef ZCL_TESTING
struct node_db;
void orphan_utxo_above_tip_test_reset(void);
void orphan_utxo_above_tip_test_set_node_db(struct node_db *ndb);
int orphan_utxo_above_tip_test_remedy_calls(void);
#endif

#endif /* ZCL_CONDITIONS_ORPHAN_UTXO_ABOVE_TIP_H */
