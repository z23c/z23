/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: protect wallet-owned application metadata with a wrapped DEK. */

#include "models/wallet_metadata_crypto.h"

#include "crypto/chacha20poly1305.h"
#include "models/activerecord.h"
#include "models/database.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include "wallet/wallet_keystore.h"
#include "wallet/wallet_lock.h"

#include <openssl/rand.h>
#include <string.h>

#define WMETA_MAGIC "MDE1"
#define WMETA_NONCE_LEN 12
#define WMETA_PASS_MAX 512

struct wallet_metadata_key_row {
    int64_t id;
    uint8_t wrapped[WKS_HEADER_LEN + WKS_KEY_LEN];
    size_t wrapped_len;
};

DEFINE_MODEL_CALLBACKS(wallet_metadata_key)

static bool wmeta_key_validate(const struct wallet_metadata_key_row *row,
                               struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_custom(errors, row && row->id == 1, "id", "must equal one");
    validates_custom(errors, row && row->wrapped_len == sizeof(row->wrapped),
                     "wrapped_dek", "has wrong envelope length");
    return !ar_errors_any(errors);
}

static bool wmeta_key_read(struct node_db *ndb,
                           struct wallet_metadata_key_row *row)
{
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT id,wrapped_dek FROM wallet_metadata_key WHERE id=1", ;,
        row->id = AR_COL_INT(s, 0);
        int n = AR_COL_BYTES(s, 1);
        if (n != (int)sizeof(row->wrapped)) {
            AR_FINALIZE(s);
            LOG_FAIL("wallet_metadata", "wrapped DEK length invalid: %d", n);
        }
        AR_READ_BLOB(s, 1, row->wrapped, sizeof(row->wrapped));
        row->wrapped_len = sizeof(row->wrapped));
}

static bool wmeta_key_save(struct node_db *ndb,
                           const struct wallet_metadata_key_row *row)
{
    sqlite3_stmt *s = NULL;
    AR_ADHOC_SAVE(ndb, s,
        "INSERT INTO wallet_metadata_key(id,wrapped_dek) VALUES(?,?)",
        db_wallet_metadata_key_callbacks(), "wallet_metadata_key", row,
        wmeta_key_validate,
        AR_BIND_INT(s, 1, row->id);
        AR_BIND_BLOB(s, 2, row->wrapped, row->wrapped_len));
}

static bool wmeta_load_dek(struct node_db *ndb, uint8_t dek[WKS_KEY_LEN])
{
    if (!ndb || !ndb->open || !wallet_lock_encrypted_at_rest())
        LOG_FAIL("wallet_metadata", "encrypted wallet database is required");
    char pass[WMETA_PASS_MAX + 1];
    if (!wallet_lock_copy_passphrase(pass, sizeof(pass)))
        LOG_FAIL("wallet_metadata", "wallet is locked");

    struct wallet_metadata_key_row row;
    memset(&row, 0, sizeof(row));
    bool exists = wmeta_key_read(ndb, &row);
    if (!exists) {
        row.id = 1;
        row.wrapped_len = sizeof(row.wrapped);
        if (RAND_bytes(dek, WKS_KEY_LEN) != 1 ||
            !wks_encrypt(dek, WKS_KEY_LEN, pass, wks_default_iterations(),
                         row.wrapped, sizeof(row.wrapped), &row.wrapped_len) ||
            !wmeta_key_save(ndb, &row)) {
            memory_cleanse(pass, sizeof(pass));
            memory_cleanse(dek, WKS_KEY_LEN);
            LOG_FAIL("wallet_metadata", "could not create metadata DEK");
        }
        memory_cleanse(pass, sizeof(pass));
        return true;
    }

    size_t dek_len = 0;
    bool ok = wks_decrypt(row.wrapped, row.wrapped_len, pass, dek,
                          WKS_KEY_LEN, &dek_len) && dek_len == WKS_KEY_LEN;
    memory_cleanse(pass, sizeof(pass));
    memory_cleanse(&row, sizeof(row));
    if (!ok) {
        memory_cleanse(dek, WKS_KEY_LEN);
        LOG_FAIL("wallet_metadata", "metadata DEK unwrap failed");
    }
    return true;
}

bool wallet_metadata_encrypt(struct node_db *ndb,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *plaintext, size_t plaintext_len,
                             uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!aad || aad_len == 0 || (!plaintext && plaintext_len) || !out ||
        !out_len || plaintext_len > WALLET_METADATA_PLAINTEXT_MAX ||
        out_cap < plaintext_len + WALLET_METADATA_OVERHEAD)
        LOG_FAIL("wallet_metadata", "encrypt: invalid bounds or argument");
    uint8_t dek[WKS_KEY_LEN], nonce[WMETA_NONCE_LEN];
    if (!wmeta_load_dek(ndb, dek) || RAND_bytes(nonce, sizeof(nonce)) != 1) {
        memory_cleanse(dek, sizeof(dek));
        LOG_FAIL("wallet_metadata", "encrypt: key or nonce unavailable");
    }
    memcpy(out, WMETA_MAGIC, 4);
    memcpy(out + 4, nonce, sizeof(nonce));
    bool ok = chacha20poly1305_encrypt(
        plaintext, plaintext_len, aad, aad_len, nonce, dek, out + 16);
    memory_cleanse(dek, sizeof(dek));
    memory_cleanse(nonce, sizeof(nonce));
    if (!ok)
        LOG_FAIL("wallet_metadata", "encrypt: AEAD failed");
    *out_len = plaintext_len + WALLET_METADATA_OVERHEAD;
    return true;
}

bool wallet_metadata_decrypt(struct node_db *ndb,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *envelope, size_t envelope_len,
                             uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!aad || aad_len == 0 || !envelope || envelope_len <
        WALLET_METADATA_OVERHEAD || envelope_len >
        WALLET_METADATA_PLAINTEXT_MAX + WALLET_METADATA_OVERHEAD || !out ||
        !out_len || out_cap < envelope_len - WALLET_METADATA_OVERHEAD ||
        memcmp(envelope, WMETA_MAGIC, 4) != 0)
        LOG_FAIL("wallet_metadata", "decrypt: invalid envelope or bounds");
    uint8_t dek[WKS_KEY_LEN];
    if (!wmeta_load_dek(ndb, dek))
        LOG_FAIL("wallet_metadata", "decrypt: DEK unavailable");
    size_t clen = envelope_len - 16;
    bool ok = chacha20poly1305_decrypt(
        envelope + 16, clen, aad, aad_len, envelope + 4, dek, out);
    memory_cleanse(dek, sizeof(dek));
    if (!ok)
        LOG_FAIL("wallet_metadata", "decrypt: authentication failed");
    *out_len = envelope_len - WALLET_METADATA_OVERHEAD;
    return true;
}
