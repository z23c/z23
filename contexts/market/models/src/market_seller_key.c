/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * ActiveRecord model: MarketSellerKey (singleton owner signing identity).
 *
 * One row (id=1) holds the wallet-metadata-encrypted ed25519 seed whose
 * public key signs every local paid file-market offer. Mint uses the same
 * key source and derivation as the buyer credential path
 * (file_market_purchase_service.c): a 32-byte CSPRNG seed expanded by
 * ed25519_keypair. Custody also matches: the seed rests only inside a
 * wallet_metadata_encrypt envelope under the passphrase-wrapped DEK. */

#include "models/market_seller_key.h"

#include "crypto/ed25519.h"
#include "models/activerecord.h"
#include "models/database.h"
#include "models/wallet_metadata_crypto.h"
#include "support/cleanse.h"
#include "util/log_macros.h"

#include <openssl/rand.h>
#include <sqlite3.h>
#include <string.h>

#define MSK_SEED_LEN 32
#define MSK_ENCRYPTED_LEN (MSK_SEED_LEN + WALLET_METADATA_OVERHEAD)

struct market_seller_key_row {
    int64_t id;
    uint8_t encrypted_seed[MSK_ENCRYPTED_LEN];
    size_t encrypted_seed_len;
    uint8_t seller_pubkey[32];
    int64_t created_at;
};

DEFINE_MODEL_CALLBACKS(market_seller_key)

static bool msk_validate(const struct market_seller_key_row *row,
                         struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!row) {
        ar_errors_add(errors, "row", "is NULL");
        return false;
    }
    validates_custom(errors, row->id == 1, "id", "must equal one");
    validates_custom(errors,
        row->encrypted_seed_len == MSK_ENCRYPTED_LEN,
        "encrypted_seed", "has wrong envelope length");
    static const uint8_t zero32[32] = {0};
    validates_custom(errors,
        memcmp(row->seller_pubkey, zero32, 32) != 0,
        "seller_pubkey", "can't be all zero");
    validates_positive(errors, row, created_at);
    return !ar_errors_any(errors);
}

static bool msk_read(struct node_db *ndb, struct market_seller_key_row *row)
{
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT id,encrypted_seed,seller_pubkey,created_at"
        " FROM market_seller_key WHERE id=1", ;,
        row->id = AR_COL_INT(s, 0);
        int n = AR_COL_BYTES(s, 1);
        if (n != (int)MSK_ENCRYPTED_LEN) {
            AR_FINALIZE(s);
            LOG_FAIL("market", "market_seller_key envelope length invalid: %d",
                     n);
        }
        AR_READ_BLOB(s, 1, row->encrypted_seed, MSK_ENCRYPTED_LEN);
        row->encrypted_seed_len = MSK_ENCRYPTED_LEN;
        AR_READ_BLOB(s, 2, row->seller_pubkey, 32);
        row->created_at = AR_COL_INT(s, 3));
}

static bool msk_save(struct node_db *ndb,
                     const struct market_seller_key_row *row)
{
    sqlite3_stmt *s = NULL;
    AR_ADHOC_SAVE(ndb, s,
        "INSERT INTO market_seller_key"
        "(id,encrypted_seed,seller_pubkey,created_at) VALUES(?,?,?,?)",
        db_market_seller_key_callbacks(), "market_seller_key", row,
        msk_validate,
        AR_BIND_INT(s, 1, row->id);
        AR_BIND_BLOB(s, 2, row->encrypted_seed, row->encrypted_seed_len);
        AR_BIND_BLOB(s, 3, row->seller_pubkey, 32);
        AR_BIND_INT(s, 4, row->created_at));
}

/* Decrypt and authenticate an existing row into the caller's outputs. The
 * stored public key is the envelope AAD, and the decrypted seed must
 * re-derive it exactly — any drift is a hard failure, never a re-mint. */
static bool msk_unlock(struct node_db *ndb,
                       const struct market_seller_key_row *row,
                       uint8_t seed_out[32], uint8_t pubkey_out[32])
{
    size_t seed_len = 0;
    uint8_t derived[32], secret_copy[32];
    bool ok = wallet_metadata_decrypt(ndb, row->seller_pubkey, 32,
        row->encrypted_seed, row->encrypted_seed_len,
        seed_out, MSK_SEED_LEN, &seed_len) && seed_len == MSK_SEED_LEN;
    if (ok) {
        ed25519_keypair(derived, secret_copy, seed_out);
        memory_cleanse(secret_copy, sizeof(secret_copy));
        ok = memcmp(derived, row->seller_pubkey, 32) == 0;
    }
    if (!ok) {
        memory_cleanse(seed_out, MSK_SEED_LEN);
        LOG_FAIL("market", "seller key envelope authentication failed");
    }
    memcpy(pubkey_out, row->seller_pubkey, 32);
    return true;
}

bool db_market_seller_key_ensure(struct node_db *ndb, uint8_t seed_out[32],
                                 uint8_t pubkey_out[32], int64_t now_unix)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("market", "db_market_seller_key_ensure: db not open");
    if (!seed_out || !pubkey_out || now_unix <= 0)
        LOG_FAIL("market", "db_market_seller_key_ensure: outputs and time required");

    struct market_seller_key_row row;
    memset(&row, 0, sizeof(row));
    if (msk_read(ndb, &row))
        return msk_unlock(ndb, &row, seed_out, pubkey_out);

    uint8_t seed[MSK_SEED_LEN], secret_copy[32];
    if (RAND_bytes(seed, sizeof(seed)) != 1)
        LOG_FAIL("market", "seller key CSPRNG failed");
    ed25519_keypair(row.seller_pubkey, secret_copy, seed);
    memory_cleanse(secret_copy, sizeof(secret_copy));
    row.id = 1;
    row.created_at = now_unix;
    bool minted = wallet_metadata_encrypt(ndb, row.seller_pubkey, 32,
        seed, sizeof(seed), row.encrypted_seed,
        sizeof(row.encrypted_seed), &row.encrypted_seed_len) &&
        row.encrypted_seed_len == MSK_ENCRYPTED_LEN;
    if (minted && !msk_save(ndb, &row)) {
        /* A concurrent mint won the singleton race; load and unlock the
         * persisted row rather than overwriting another owner's key. */
        memory_cleanse(seed, sizeof(seed));
        memset(&row, 0, sizeof(row));
        if (msk_read(ndb, &row))
            return msk_unlock(ndb, &row, seed_out, pubkey_out);
        LOG_FAIL("market", "seller key lost the mint race and cannot reload");
    }
    if (!minted) {
        memory_cleanse(seed, sizeof(seed));
        LOG_FAIL("market", "seller key mint or durable encryption failed");
    }
    memcpy(seed_out, seed, MSK_SEED_LEN);
    memcpy(pubkey_out, row.seller_pubkey, 32);
    memory_cleanse(seed, sizeof(seed));
    return true;
}
