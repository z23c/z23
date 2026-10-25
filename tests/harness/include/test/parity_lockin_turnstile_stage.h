/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Stage-level ZIP-209 turnstile cases (drive the real utxo_apply stage),
 * run from the parity_lockin_turnstile group. */

#ifndef TEST_PARITY_LOCKIN_TURNSTILE_STAGE_H
#define TEST_PARITY_LOCKIN_TURNSTILE_STAGE_H

/* Returns the number of failed checks. */
int parity_lockin_turnstile_stage_cases(void);

#endif
