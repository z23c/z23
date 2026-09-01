/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fast authenticated envelopes for transparent wallet-key rows. */

#ifndef ZCL_WALLET_SQLITE_KEY_CRYPTO_H
#define ZCL_WALLET_SQLITE_KEY_CRYPTO_H

#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WSQL_KEY_ENVELOPE_MAGIC "WKD1"
#define WSQL_KEY_ENVELOPE_MAGIC_LEN 4
#define WSQL_KEY_ENVELOPE_OVERHEAD 36

static inline size_t wallet_sqlite_key_envelope_size(size_t plaintext_len)
{
    return WSQL_KEY_ENVELOPE_OVERHEAD + plaintext_len;
}

/* Ensure this database has one passphrase-wrapped data-encryption key.
 * PBKDF2 is paid once per unlocked database, not once per wallet-key row. */
bool wallet_sqlite_key_crypto_prepare(sqlite3 *db);

bool wallet_sqlite_key_is_envelope(const void *blob, size_t blob_len);

/* Encrypt/decrypt one row with the pubkey hash as authenticated context. */
bool wallet_sqlite_key_encrypt(sqlite3 *db,
                               const uint8_t pubkey_hash[20],
                               const uint8_t *plaintext,
                               size_t plaintext_len,
                               uint8_t *out, size_t out_cap,
                               size_t *out_len);
bool wallet_sqlite_key_decrypt(sqlite3 *db,
                               const uint8_t pubkey_hash[20],
                               const uint8_t *envelope,
                               size_t envelope_len,
                               uint8_t *out, size_t out_cap,
                               size_t *out_len);

/* Lock/passphrase transitions and database close wipe the cached DEK. */
void wallet_sqlite_key_crypto_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_WALLET_SQLITE_KEY_CRYPTO_H */
