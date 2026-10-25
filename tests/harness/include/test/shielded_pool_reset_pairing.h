/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Source-pairing guard: nullifier_kv_reset_* implies shielded_pool_kv_reset_in_tx. */

#ifndef TEST_SHIELDED_POOL_RESET_PAIRING_H
#define TEST_SHIELDED_POOL_RESET_PAIRING_H

/* Returns the number of failed checks. */
int shielded_pool_reset_pairing_cases(void);

#endif
