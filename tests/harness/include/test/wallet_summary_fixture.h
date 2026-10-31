/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Node.db fixture writers shared by the wallet summary and history tests. */

#ifndef ZCL_TEST_WALLET_SUMMARY_FIXTURE_H
#define ZCL_TEST_WALLET_SUMMARY_FIXTURE_H

#include "models/database.h"

#include <stdint.h>

/* A block row at `height` so the chain tip reads `height`. */
bool wsh_put_block(struct node_db *ndb, int height);
/* A Sapling note of `ivk`; its nullifier is derived from (tx, idx). */
bool wsh_put_note(struct node_db *ndb, uint8_t tx, uint32_t idx,
                  const uint8_t ivk[32], int64_t value, int height,
                  const char *memo_text);
/* Mark note (tx, idx) as spent by the transaction named `spender`. */
bool wsh_spend_note(struct node_db *ndb, uint8_t tx, uint32_t idx,
                    uint8_t spender);
/* The nullifier wsh_put_note gave note (tx, idx). */
void wsh_note_nullifier(uint8_t tx, uint32_t idx, uint8_t out[32]);

#endif
