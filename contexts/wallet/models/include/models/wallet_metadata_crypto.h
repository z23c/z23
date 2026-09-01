/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Authenticated per-row metadata encryption under a passphrase-wrapped DEK. */

#ifndef ZCL_MODELS_WALLET_METADATA_CRYPTO_H
#define ZCL_MODELS_WALLET_METADATA_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_db;

#define WALLET_METADATA_PLAINTEXT_MAX 16384
#define WALLET_METADATA_OVERHEAD 32

bool wallet_metadata_encrypt(struct node_db *ndb,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *plaintext, size_t plaintext_len,
                             uint8_t *out, size_t out_cap, size_t *out_len);

bool wallet_metadata_decrypt(struct node_db *ndb,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *envelope, size_t envelope_len,
                             uint8_t *out, size_t out_cap, size_t *out_len);

#endif
