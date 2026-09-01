/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * One expensive passphrase wrap per wallet, fast AEAD per key row. */

#include "wallet/wallet_sqlite_key_crypto.h"

#include "base/serialize_le.h"
#include "support/cleanse.h"
#include "util/ar_step_readonly.h"
#include "util/result.h"
#include "util/safe_alloc.h"
#include "wallet/wallet_keystore.h"
#include "wallet/wallet_lock.h"
#include "wallet/wallet_sqlite.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WKEY_DEK_LEN 32
#define WKEY_NONCE_LEN 12
#define WKEY_TAG_LEN 16
#define WKEY_VERSION 1U
#define WKEY_PASS_MAX 512

static pthread_mutex_t g_key_crypto_mu = PTHREAD_MUTEX_INITIALIZER;
static sqlite3 *g_key_crypto_db;
static uint8_t g_key_crypto_dek[WKEY_DEK_LEN];
static bool g_key_crypto_ready;
static bool g_key_crypto_failed;

void wallet_sqlite_key_crypto_reset(void)
{
    pthread_mutex_lock(&g_key_crypto_mu);
    memory_cleanse(g_key_crypto_dek, sizeof(g_key_crypto_dek));
    g_key_crypto_db = NULL;
    g_key_crypto_ready = false;
    g_key_crypto_failed = false;
    pthread_mutex_unlock(&g_key_crypto_mu);
}

bool wallet_sqlite_key_is_envelope(const void *blob, size_t blob_len)
{
    bool wrapped = blob && blob_len >= WSQL_KEY_ENVELOPE_OVERHEAD &&
        memcmp(blob, WSQL_KEY_ENVELOPE_MAGIC,
               WSQL_KEY_ENVELOPE_MAGIC_LEN) == 0 &&
        zcl_read_u32_be((const uint8_t *)blob + 4) == WKEY_VERSION;
    if (wrapped)
        wallet_lock_note_encrypted_at_rest();
    return wrapped;
}

static bool read_wrapped_dek(sqlite3 *db, uint8_t *out, size_t out_cap,
                             size_t *out_len, bool *found)
{
    *found = false;
    *out_len = 0;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT wrapped_dek FROM wallet_key_encryption WHERE id=1", -1,
            &stmt, NULL) != SQLITE_OK || !stmt) {
        if (stmt) sqlite3_finalize(stmt);
        return false;
    }
    int rc = AR_STEP_ROW_READONLY(stmt);
    if (rc == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(stmt, 0);
        int blob_len = sqlite3_column_bytes(stmt, 0);
        if (!blob || blob_len <= 0 || (size_t)blob_len > out_cap) {
            sqlite3_finalize(stmt);
            return false;
        }
        memcpy(out, blob, (size_t)blob_len);
        *out_len = (size_t)blob_len;
        *found = true;
    } else if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_finalize(stmt);
    return true;
}

static bool insert_wrapped_dek(sqlite3 *db, const uint8_t *wrapped,
                               size_t wrapped_len)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR IGNORE INTO wallet_key_encryption(id,wrapped_dek) "
            "VALUES(1,?1)",
            -1, &stmt, NULL) != SQLITE_OK || !stmt) {
        if (stmt) sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_bind_blob(stmt, 1, wrapped, (int)wrapped_len,
                      SQLITE_TRANSIENT);
    int rc = AR_STEP_WRITE(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool wallet_sqlite_key_crypto_prepare(sqlite3 *db)
{
    if (!db)
        return false;
    char pass[WKEY_PASS_MAX + 1];
    if (!wallet_lock_copy_passphrase(pass, sizeof(pass)))
        return false;

    pthread_mutex_lock(&g_key_crypto_mu);
    if (g_key_crypto_db == db && g_key_crypto_ready) {
        pthread_mutex_unlock(&g_key_crypto_mu);
        memory_cleanse(pass, sizeof(pass));
        return true;
    }
    if (g_key_crypto_db == db && g_key_crypto_failed) {
        pthread_mutex_unlock(&g_key_crypto_mu);
        memory_cleanse(pass, sizeof(pass));
        return false;
    }
    memory_cleanse(g_key_crypto_dek, sizeof(g_key_crypto_dek));
    g_key_crypto_db = db;
    g_key_crypto_ready = false;
    g_key_crypto_failed = false;

    uint8_t wrapped[WKS_HEADER_LEN + WKEY_DEK_LEN];
    size_t wrapped_len = 0;
    bool found = false;
    bool ok = read_wrapped_dek(db, wrapped, sizeof(wrapped),
                               &wrapped_len, &found);
    uint8_t dek[WKEY_DEK_LEN];
    memset(dek, 0, sizeof(dek));

    if (ok && found) {
        size_t dek_len = 0;
        ok = wks_decrypt(wrapped, wrapped_len, pass, dek, sizeof(dek),
                         &dek_len) && dek_len == sizeof(dek);
    } else if (ok) {
        /* Creating the wrapped DEK inside somebody else's transaction could
         * cache material whose row is later rolled back. Callers prepare
         * before BEGIN; fail closed if a new caller violates that contract. */
        ok = sqlite3_get_autocommit(db) != 0 &&
             RAND_bytes(dek, sizeof(dek)) == 1;
        size_t created_len = 0;
        if (ok)
            ok = wks_encrypt(dek, sizeof(dek), pass,
                             wks_default_iterations(), wrapped,
                             sizeof(wrapped), &created_len) &&
                 insert_wrapped_dek(db, wrapped, created_len);
        /* INSERT OR IGNORE is race-safe. If another writer won, use the
         * authoritative stored wrapper rather than our candidate. */
        if (ok && sqlite3_changes(db) == 0) {
            memory_cleanse(dek, sizeof(dek));
            wrapped_len = 0;
            found = false;
            ok = read_wrapped_dek(db, wrapped, sizeof(wrapped),
                                  &wrapped_len, &found) && found;
            size_t dek_len = 0;
            if (ok)
                ok = wks_decrypt(wrapped, wrapped_len, pass, dek,
                                 sizeof(dek), &dek_len) &&
                     dek_len == sizeof(dek);
        }
    }

    if (ok) {
        memcpy(g_key_crypto_dek, dek, sizeof(dek));
        g_key_crypto_ready = true;
    } else {
        g_key_crypto_failed = true;
    }
    memory_cleanse(dek, sizeof(dek));
    memory_cleanse(wrapped, sizeof(wrapped));
    pthread_mutex_unlock(&g_key_crypto_mu);
    memory_cleanse(pass, sizeof(pass));
    if (ok)
        wallet_lock_note_encrypted_at_rest();
    return ok;
}

static bool copy_dek(sqlite3 *db, uint8_t out[WKEY_DEK_LEN])
{
    if (!wallet_sqlite_key_crypto_prepare(db))
        return false;
    pthread_mutex_lock(&g_key_crypto_mu);
    bool ok = g_key_crypto_db == db && g_key_crypto_ready;
    if (ok)
        memcpy(out, g_key_crypto_dek, WKEY_DEK_LEN);
    pthread_mutex_unlock(&g_key_crypto_mu);
    return ok;
}

bool wallet_sqlite_key_encrypt(sqlite3 *db,
                               const uint8_t pubkey_hash[20],
                               const uint8_t *plaintext,
                               size_t plaintext_len,
                               uint8_t *out, size_t out_cap,
                               size_t *out_len)
{
    if (!db || !pubkey_hash || (!plaintext && plaintext_len) || !out ||
        !out_len || plaintext_len > (size_t)INT_MAX ||
        out_cap < wallet_sqlite_key_envelope_size(plaintext_len))
        return false;
    uint8_t dek[WKEY_DEK_LEN], nonce[WKEY_NONCE_LEN], tag[WKEY_TAG_LEN];
    if (!copy_dek(db, dek) || RAND_bytes(nonce, sizeof(nonce)) != 1) {
        memory_cleanse(dek, sizeof(dek));
        return false;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        memory_cleanse(dek, sizeof(dek));
        return false;
    }
    bool ok = false;
    int n = 0;
    memcpy(out, WSQL_KEY_ENVELOPE_MAGIC, WSQL_KEY_ENVELOPE_MAGIC_LEN);
    zcl_write_u32_be(out + 4, WKEY_VERSION);
    memcpy(out + 8, nonce, sizeof(nonce));
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            sizeof(nonce), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, dek, nonce) != 1 ||
        EVP_EncryptUpdate(ctx, NULL, &n, pubkey_hash, 20) != 1)
        goto done;
    if (plaintext_len &&
        (EVP_EncryptUpdate(ctx, out + WSQL_KEY_ENVELOPE_OVERHEAD, &n,
                           plaintext, (int)plaintext_len) != 1 ||
         (size_t)n != plaintext_len))
        goto done;
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, NULL, &final_len) != 1 || final_len != 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            sizeof(tag), tag) != 1)
        goto done;
    memcpy(out + 20, tag, sizeof(tag));
    *out_len = wallet_sqlite_key_envelope_size(plaintext_len);
    ok = true;
done:
    EVP_CIPHER_CTX_free(ctx);
    memory_cleanse(dek, sizeof(dek));
    memory_cleanse(tag, sizeof(tag));
    return ok;
}

bool wallet_sqlite_key_decrypt(sqlite3 *db,
                               const uint8_t pubkey_hash[20],
                               const uint8_t *envelope,
                               size_t envelope_len,
                               uint8_t *out, size_t out_cap,
                               size_t *out_len)
{
    if (!db || !pubkey_hash || !envelope || !out || !out_len ||
        !wallet_sqlite_key_is_envelope(envelope, envelope_len))
        return false;
    size_t ciphertext_len = envelope_len - WSQL_KEY_ENVELOPE_OVERHEAD;
    if (ciphertext_len > out_cap || ciphertext_len > (size_t)INT_MAX)
        return false;
    uint8_t dek[WKEY_DEK_LEN];
    if (!copy_dek(db, dek))
        return false;
    const uint8_t *nonce = envelope + 8;
    const uint8_t *tag = envelope + 20;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        memory_cleanse(dek, sizeof(dek));
        return false;
    }
    bool ok = false;
    int n = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            WKEY_NONCE_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, dek, nonce) != 1 ||
        EVP_DecryptUpdate(ctx, NULL, &n, pubkey_hash, 20) != 1)
        goto done;
    if (ciphertext_len &&
        (EVP_DecryptUpdate(ctx, out, &n,
                           envelope + WSQL_KEY_ENVELOPE_OVERHEAD,
                           (int)ciphertext_len) != 1 ||
         (size_t)n != ciphertext_len))
        goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            WKEY_TAG_LEN, (void *)(uintptr_t)tag) != 1)
        goto done;
    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, NULL, &final_len) != 1 || final_len != 0)
        goto done;
    *out_len = ciphertext_len;
    ok = true;
done:
    EVP_CIPHER_CTX_free(ctx);
    memory_cleanse(dek, sizeof(dek));
    if (!ok && ciphertext_len <= out_cap)
        memory_cleanse(out, ciphertext_len);
    return ok;
}

static bool wkey_is_wks1(const void *blob, size_t blob_len)
{
    bool wrapped = blob && blob_len >= WKS_HEADER_LEN &&
        memcmp(blob, WKS_MAGIC, WKS_MAGIC_LEN) == 0;
    if (wrapped)
        wallet_lock_note_encrypted_at_rest();
    return wrapped;
}

static bool wkey_legacy_encrypt(const uint8_t *plain, size_t plain_len,
                                uint8_t **out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0;
    char pass[WKEY_PASS_MAX + 1];
    if (!wallet_lock_copy_passphrase(pass, sizeof(pass)))
        return false;
    size_t cap = wks_envelope_size(plain_len);
    uint8_t *wrapped = zcl_malloc(cap, "wallet_legacy_envelope");
    bool ok = wrapped && wks_encrypt(plain, plain_len, pass,
        wks_default_iterations(), wrapped, cap, out_len);
    memory_cleanse(pass, sizeof(pass));
    if (!ok) {
        if (wrapped) { memory_cleanse(wrapped, cap); free(wrapped); }
        return false;
    }
    *out = wrapped;
    return true;
}

static bool wkey_legacy_decrypt(const uint8_t *wrapped, size_t wrapped_len,
                                uint8_t **out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0;
    char pass[WKEY_PASS_MAX + 1];
    if (!wallet_lock_copy_passphrase(pass, sizeof(pass)))
        return false;
    uint8_t *plain = zcl_malloc(wrapped_len, "wallet_legacy_plaintext");
    bool ok = plain && wks_decrypt(wrapped, wrapped_len, pass, plain,
                                   wrapped_len, out_len);
    memory_cleanse(pass, sizeof(pass));
    if (!ok) {
        if (plain) { memory_cleanse(plain, wrapped_len); free(plain); }
        return false;
    }
    *out = plain;
    return true;
}

static struct zcl_result wkey_scrub_fail(struct wallet_sqlite *ws,
                                         struct zcl_result result);

static bool wkey_transparent_migration_needed(sqlite3 *db)
{
    sqlite3_stmt *scan = NULL;
    if (sqlite3_prepare_v2(db, "SELECT privkey FROM wallet_keys",
                           -1, &scan, NULL) != SQLITE_OK || !scan) {
        if (scan) sqlite3_finalize(scan);
        return true;
    }
    bool needed = false;
    int rc;
    while ((rc = AR_STEP_ROW_READONLY(scan)) == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(scan, 0);
        int blob_len = sqlite3_column_bytes(scan, 0);
        if (!wallet_sqlite_key_is_envelope(blob,
                                            blob_len > 0 ? (size_t)blob_len : 0)) {
            needed = true;
            break;
        }
    }
    if (rc != SQLITE_ROW && rc != SQLITE_DONE)
        needed = true;
    sqlite3_finalize(scan);
    return needed;
}

struct zcl_result wallet_sqlite_migrate_transparent_keys_r(
    struct wallet_sqlite *ws, struct wallet *wallet)
{
    if (!ws || !wallet)
        return ZCL_ERR(WSQL_NULL_ARG, "key migration: NULL wallet argument");
    if (!ws->open)
        return wkey_scrub_fail(ws, ZCL_ERR(WSQL_DB_NOT_OPEN,
            "key migration: wallet_sqlite is not open"));
    if (!wallet_lock_effective_passphrase() ||
        !wkey_transparent_migration_needed(ws->db))
        return ZCL_OK;
    if (!wallet_sqlite_key_crypto_prepare(ws->db))
        return wkey_scrub_fail(ws, ZCL_ERR(WSQL_WRITE_FAIL,
            "key migration: wallet data-encryption key unavailable"));

    char *error = NULL;
    if (sqlite3_exec(ws->db, "BEGIN IMMEDIATE", NULL, NULL, &error)
            != SQLITE_OK) {
        struct zcl_result result = ZCL_ERR(WSQL_TXN_BEGIN_FAIL,
            "key migration: BEGIN IMMEDIATE failed: %s",
            error ? error : "(unknown)");
        if (error) sqlite3_free(error);
        return wkey_scrub_fail(ws, result);
    }

    struct zcl_result first_failure = ZCL_OK;
    zcl_mutex_lock(&wallet->keystore.cs);
    for (size_t i = 0; i < wallet->keystore.num_keys; i++) {
        if (!wallet->keystore.keys[i].used ||
            !wallet->keystore.keys[i].key.fValid)
            continue;
        struct pubkey pubkey;
        if (!privkey_get_pubkey(&wallet->keystore.keys[i].key, &pubkey)) {
            first_failure = ZCL_ERR(WSQL_INVARIANT_PRIVKEY,
                "key migration: loaded key %zu has no public key", i);
            break;
        }
        struct zcl_result written = wallet_sqlite_write_key_r(
            ws, &pubkey, &wallet->keystore.keys[i].key);
        if (!written.ok) {
            first_failure = written;
            break;
        }
    }
    zcl_mutex_unlock(&wallet->keystore.cs);
    if (!first_failure.ok) {
        sqlite3_exec(ws->db, "ROLLBACK", NULL, NULL, NULL);
        return wkey_scrub_fail(ws, first_failure);
    }

    error = NULL;
    if (sqlite3_exec(ws->db, "COMMIT", NULL, NULL, &error) != SQLITE_OK) {
        struct zcl_result result = ZCL_ERR(WSQL_TXN_COMMIT_FAIL,
            "key migration: COMMIT failed: %s",
            error ? error : "(unknown)");
        if (error) sqlite3_free(error);
        sqlite3_exec(ws->db, "ROLLBACK", NULL, NULL, NULL);
        return wkey_scrub_fail(ws, result);
    }
    return ZCL_OK;
}

/* Upgrade transparent rows to WKD1. Legacy WKS1 rows pay their PBKDF2
 * cost once; future boots unwrap one wallet DEK. */
static int wkey_scrub_transparent(struct wallet_sqlite *ws)
{
    sqlite3_stmt *scan = NULL;
    sqlite3_stmt *update = NULL;
    if (sqlite3_prepare_v2(ws->db,
            "SELECT rowid,pubkey_hash,privkey FROM wallet_keys",
            -1, &scan, NULL) != SQLITE_OK || !scan ||
        sqlite3_prepare_v2(ws->db,
            "UPDATE wallet_keys SET privkey=?1 WHERE rowid=?2",
            -1, &update, NULL) != SQLITE_OK || !update) {
        if (scan) sqlite3_finalize(scan);
        if (update) sqlite3_finalize(update);
        return -1;
    }
    int upgraded = 0;
    bool failed = false;
    int rc;
    while ((rc = AR_STEP_ROW_READONLY(scan)) == SQLITE_ROW) {
        const void *hash = sqlite3_column_blob(scan, 1);
        int hash_len = sqlite3_column_bytes(scan, 1);
        const void *blob = sqlite3_column_blob(scan, 2);
        int blob_len = sqlite3_column_bytes(scan, 2);
        if (!hash || hash_len != 20 || !blob || blob_len <= 0) {
            failed = true;
            break;
        }
        if (wallet_sqlite_key_is_envelope(blob, (size_t)blob_len))
            continue;

        uint8_t *legacy_plain = NULL;
        const uint8_t *plain = blob;
        size_t plain_len = (size_t)blob_len;
        if (wkey_is_wks1(blob, (size_t)blob_len)) {
            if (!wkey_legacy_decrypt(blob, (size_t)blob_len,
                                     &legacy_plain, &plain_len)) {
                failed = true;
                break;
            }
            plain = legacy_plain;
        }
        size_t cap = wallet_sqlite_key_envelope_size(plain_len);
        uint8_t *wrapped = zcl_malloc(cap, "wallet_key_wkd1_migration");
        size_t wrapped_len = 0;
        bool encrypted = wrapped && wallet_sqlite_key_encrypt(
            ws->db, hash, plain, plain_len, wrapped, cap, &wrapped_len);
        if (legacy_plain) {
            memory_cleanse(legacy_plain, plain_len);
            free(legacy_plain);
        }
        if (!encrypted) {
            if (wrapped) { memory_cleanse(wrapped, cap); free(wrapped); }
            failed = true;
            break;
        }
        sqlite3_reset(update);
        sqlite3_bind_blob(update, 1, wrapped, (int)wrapped_len,
                          SQLITE_TRANSIENT);
        sqlite3_bind_int64(update, 2, sqlite3_column_int64(scan, 0));
        int update_rc = AR_STEP_WRITE(update);
        memory_cleanse(wrapped, cap);
        free(wrapped);
        if (update_rc != SQLITE_DONE) {
            failed = true;
            break;
        }
        upgraded++;
    }
    sqlite3_finalize(update);
    sqlite3_finalize(scan);
    return failed || rc != SQLITE_DONE ? -1 : upgraded;
}

/* Sapling keys and the HD seed retain the legacy WKS1 row format. */
static int wkey_scrub_legacy_column(sqlite3 *db, const char *table,
                                    const char *column)
{
    char select_sql[160];
    char update_sql[160];
    snprintf(select_sql, sizeof(select_sql),
             "SELECT rowid,%s FROM %s", column, table);
    snprintf(update_sql, sizeof(update_sql),
             "UPDATE %s SET %s=?1 WHERE rowid=?2", table, column);
    sqlite3_stmt *scan = NULL;
    sqlite3_stmt *update = NULL;
    if (sqlite3_prepare_v2(db, select_sql, -1, &scan, NULL) != SQLITE_OK ||
        !scan || sqlite3_prepare_v2(db, update_sql, -1, &update, NULL)
            != SQLITE_OK || !update) {
        if (scan) sqlite3_finalize(scan);
        if (update) sqlite3_finalize(update);
        return -1;
    }
    int upgraded = 0;
    bool failed = false;
    int rc;
    while ((rc = AR_STEP_ROW_READONLY(scan)) == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(scan, 1);
        int blob_len = sqlite3_column_bytes(scan, 1);
        if (!blob || blob_len <= 0 ||
            wkey_is_wks1(blob, (size_t)blob_len))
            continue;
        uint8_t *wrapped = NULL;
        size_t wrapped_len = 0;
        if (!wkey_legacy_encrypt(blob, (size_t)blob_len,
                                 &wrapped, &wrapped_len)) {
            failed = true;
            break;
        }
        sqlite3_reset(update);
        sqlite3_bind_blob(update, 1, wrapped, (int)wrapped_len,
                          SQLITE_TRANSIENT);
        sqlite3_bind_int64(update, 2, sqlite3_column_int64(scan, 0));
        int update_rc = AR_STEP_WRITE(update);
        memory_cleanse(wrapped, wrapped_len);
        free(wrapped);
        if (update_rc != SQLITE_DONE) {
            failed = true;
            break;
        }
        upgraded++;
    }
    sqlite3_finalize(update);
    sqlite3_finalize(scan);
    return failed || rc != SQLITE_DONE ? -1 : upgraded;
}

static struct zcl_result wkey_scrub_fail(struct wallet_sqlite *ws,
                                         struct zcl_result result)
{
    if (ws) {
        snprintf(ws->last_error, sizeof(ws->last_error), "%s",
                 result.message);
    }
    return result;
}

struct zcl_result wallet_sqlite_scrub_plaintext_r(struct wallet_sqlite *ws)
{
    if (!ws)
        return ZCL_ERR(WSQL_NULL_ARG, "wallet_sqlite pointer is NULL");
    if (!ws->open)
        return wkey_scrub_fail(ws, ZCL_ERR(WSQL_DB_NOT_OPEN,
            "scrub: wallet_sqlite is not open"));
    if (!wallet_lock_effective_passphrase())
        return ZCL_OK;
    if (!wallet_sqlite_key_crypto_prepare(ws->db))
        return wkey_scrub_fail(ws, ZCL_ERR(WSQL_WRITE_FAIL,
            "scrub: wallet key data-encryption key unavailable"));

    char *error = NULL;
    if (sqlite3_exec(ws->db, "BEGIN IMMEDIATE", NULL, NULL, &error)
            != SQLITE_OK) {
        struct zcl_result result = ZCL_ERR(WSQL_TXN_BEGIN_FAIL,
            "scrub: BEGIN IMMEDIATE failed: %s",
            error ? error : "(unknown)");
        if (error) sqlite3_free(error);
        return wkey_scrub_fail(ws, result);
    }
    int transparent = wkey_scrub_transparent(ws);
    int sapling = transparent < 0 ? -1 : wkey_scrub_legacy_column(
        ws->db, "wallet_sapling_keys", "xsk");
    int seed = transparent < 0 || sapling < 0 ? -1 :
        wkey_scrub_legacy_column(ws->db, "wallet_seed", "seed");
    if (transparent < 0 || sapling < 0 || seed < 0) {
        sqlite3_exec(ws->db, "ROLLBACK", NULL, NULL, NULL);
        return wkey_scrub_fail(ws, ZCL_ERR(WSQL_WRITE_FAIL,
            "scrub: at-rest upgrade failed: %s", sqlite3_errmsg(ws->db)));
    }
    error = NULL;
    if (sqlite3_exec(ws->db, "COMMIT", NULL, NULL, &error) != SQLITE_OK) {
        struct zcl_result result = ZCL_ERR(WSQL_TXN_COMMIT_FAIL,
            "scrub: COMMIT failed: %s", error ? error : "(unknown)");
        if (error) sqlite3_free(error);
        sqlite3_exec(ws->db, "ROLLBACK", NULL, NULL, NULL);
        return wkey_scrub_fail(ws, result);
    }
    if (transparent + sapling + seed > 0)
        printf("wallet_sqlite: upgraded %d secret row(s) "
               "(transparent_wkd1=%d sapling_wks1=%d seed_wks1=%d)\n",
               transparent + sapling + seed,
               transparent, sapling, seed);
    return ZCL_OK;
}
