/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Owner-controlled file-market seller signing key, encrypted at rest under
 * the same passphrase-wrapped metadata DEK that protects purchase plans. */

#ifndef ZCL_DB_MODEL_MARKET_SELLER_KEY_H
#define ZCL_DB_MODEL_MARKET_SELLER_KEY_H

#include <stdbool.h>
#include <stdint.h>

struct node_db;

/* Load the persistent seller ed25519 seed, minting and durably encrypting it
 * exactly once. The 32-byte seed never touches the database in the clear:
 * the stored envelope is wallet_metadata_encrypt() output bound to the
 * derived public key as AAD. Callers must memory_cleanse seed_out after
 * sealing. Fails closed when the wallet metadata DEK is unavailable (wallet
 * locked or not encrypted at rest). */
bool db_market_seller_key_ensure(struct node_db *ndb, uint8_t seed_out[32],
                                 uint8_t pubkey_out[32], int64_t now_unix);

#endif
