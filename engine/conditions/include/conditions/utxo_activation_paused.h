/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONDITIONS_UTXO_ACTIVATION_PAUSED_H
#define ZCL_CONDITIONS_UTXO_ACTIVATION_PAUSED_H

#include <stdbool.h>

/* SYMPTOM: process_block_get_utxo_activation_paused_height() reports a paused
 *   height for >= 300s (UTXO activation wedged at that block).
 * REMEDY: action=resume (or =repair when reason contains utxo_audit_drift) —
 *   process_block_clear_utxo_activation_pause_range() then kick activation
 *   (gap_fill_kick + activation_request_connect).
 * WITNESSED: the pause flag is clear AND the active tip advanced (reached the
 *   previously-paused height or past the tip recorded at detect) — real
 *   forward progress, not just the flag clearing.
 * COND_CRITICAL; poll_secs=5 (backoff 30s, max_attempts 2). */
void register_utxo_activation_paused(void);

#ifdef ZCL_TESTING
void utxo_activation_paused_test_reset(void);
void utxo_activation_paused_test_set_reason(const char *reason);
void utxo_activation_paused_test_set_remedy_clear_enabled(bool enabled);
int utxo_activation_paused_test_resume_calls(void);
int utxo_activation_paused_test_repair_calls(void);
#endif

#endif /* ZCL_CONDITIONS_UTXO_ACTIVATION_PAUSED_H */
