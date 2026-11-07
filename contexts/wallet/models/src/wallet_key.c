/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord model: WalletKey, SaplingKey, WalletSeed, WalletScript
 *
 * validates :pubkey_hash, presence: true
 * validates :pubkey, presence: true
 * validates :privkey, presence: true
 * validates :pubkey_len, custom: "must be 33 (compressed)"
 *
 * WalletSeed:
 * validates :seed, presence: true
 *
 * SaplingKey:
 * validates :ivk, presence: true
 * validates :xsk, :xfvk, :diversifier, :pk_d, presence: true
 * validates :address, string_present: true */

#include "base/serialize_le.h"
#include "util/log_macros.h"
#include "models/wallet_key.h"
#include "models/wallet_tx.h"
#include "support/cleanse.h"
#include "util/result.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include "util/safe_alloc.h"

/* ── Callbacks ─────────────────────────────────────────────────── *
 * The wallet_key/sapling_key before/after_save hooks are gone with the
 * model save functions: node.db's secret columns have a single writer —
 * the encryption-aware wallet_sqlite layer — which owns the
 * EV_WALLET_KEY_SAVED / EV_SAPLING_KEY_SAVED and wallet-projection
 * key-add emission (see contexts/wallet/modules/wallet/src/wallet_sqlite.c). The callback
 * registries stay: db_wallet_key_delete and db_wallet_script_save still
 * run the AR destroy/save lifecycle. */

DEFINE_MODEL_CALLBACKS(wallet_key)
DEFINE_MODEL_CALLBACKS(sapling_key)
DEFINE_MODEL_CALLBACKS(wallet_script)

/* ── Validation ────────────────────────────────────────────────── */

bool db_wallet_key_validate(const struct db_wallet_key *k,
                            struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_presence_of(errors, k, pubkey_hash);
    validates_presence_of(errors, k, pubkey);
    validates_presence_of(errors, k, privkey);
    validates_custom(errors, k->pubkey_len == 33,
                     "pubkey_len", "must be 33 (compressed)");
    validates_custom(errors, !(k->pubkey_len == 33 && !k->compressed),
                     "compressed", "must be true for 33-byte pubkey");
    validates_non_negative(errors, k, created_at);
    return !ar_errors_any(errors);
}

bool db_sapling_key_validate(const struct db_sapling_key *k,
                             struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_presence_of(errors, k, ivk);
    validates_presence_of(errors, k, xsk);
    validates_presence_of(errors, k, xfvk);
    validates_presence_of(errors, k, diversifier);
    validates_presence_of(errors, k, pk_d);
    validates_string_present(errors, k->address, "address");
    return !ar_errors_any(errors);
}

bool db_wallet_script_validate(const struct db_wallet_script *sc,
                               struct ar_errors *errors)
{
    static const uint8_t zero[20] = {0};
    ar_errors_clear(errors);
    validates_custom(errors,
        memcmp(sc->script_hash, zero, 20) != 0,
        "script_hash", "can't be blank");
    validates_custom(errors,
        sc->redeem_script != NULL,
        "redeem_script", "can't be null");
    validates_positive(errors, sc, script_len);
    validates_max(errors, sc, script_len, 10000);
    return !ar_errors_any(errors);
}

/* ── WalletKey CRUD ───────────────────────────────────────────── *
 * There is no db_wallet_key_save: the wallet_keys secret column has a
 * single writer, the encryption-aware wallet_sqlite layer. This model
 * keeps the read/destroy side for diagnostics and the vault. */
bool db_wallet_key_find(struct node_db *ndb, const uint8_t pubkey_hash[20],
                        struct db_wallet_key *out)
{
    if (!ndb->open) return false;
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT pubkey,privkey,compressed,created_at"
        " FROM wallet_keys WHERE pubkey_hash=?",
        AR_BIND_BLOB(s, 1, pubkey_hash, 20),
        memset(out, 0, sizeof(*out));
        memcpy(out->pubkey_hash, pubkey_hash, 20);
        int pk_len = AR_COL_BYTES(s, 0);
        const void *pk = sqlite3_column_blob(s, 0);
        if (pk && pk_len <= 33) {
            memcpy(out->pubkey, pk, (size_t)pk_len);
            out->pubkey_len = (size_t)pk_len;
        }
        AR_READ_BLOB(s, 1, out->privkey, 32);
        out->compressed = AR_COL_INT(s, 2) != 0;
        out->created_at = AR_COL_INT(s, 3));
}

bool db_wallet_key_delete(struct node_db *ndb, const uint8_t pubkey_hash[20])
{
    if (!ndb->open) return false;

    struct ar_callbacks *cbs = db_wallet_key_callbacks();
    struct db_wallet_key k;
    memset(&k, 0, sizeof(k));
    memcpy(k.pubkey_hash, pubkey_hash, 20);
    sqlite3_stmt *s = NULL;
    AR_ADHOC_DESTROY(ndb, s, "DELETE FROM wallet_keys WHERE pubkey_hash=?",
        cbs, &k, AR_BIND_BLOB(s, 1, pubkey_hash, 20));
}

bool db_wallet_key_exists(struct node_db *ndb, const uint8_t pubkey_hash[20])
{
    if (!ndb->open) return false;
    sqlite3_stmt *s = NULL;
    AR_QUERY_EXISTS(ndb, s,
        "SELECT 1 FROM wallet_keys WHERE pubkey_hash=?",
        AR_BIND_BLOB(s, 1, pubkey_hash, 20));
}

int db_wallet_key_count(struct node_db *ndb)
{
    if (!ndb->open) return 0;
    AR_QUERY_COUNT_SQL(ndb, "SELECT COUNT(*) FROM wallet_keys");
}

bool db_wallet_key_first_pubkey_hash(struct node_db *ndb, uint8_t out[20])
{
    if (!ndb || !ndb->open || !out)
        return false;
    sqlite3_stmt *s = NULL;
    AR_PREPARE_BOOL(ndb, s,
        "SELECT pubkey_hash FROM wallet_keys LIMIT 1");
    bool ok = false;
    if (AR_STEP_ROW(s)) {
        const void *pkh = sqlite3_column_blob(s, 0);
        if (pkh && AR_COL_BYTES(s, 0) == 20) {
            memcpy(out, pkh, 20);
            ok = true;
        }
    }
    AR_FINALIZE(s);
    return ok;
}

/* ── Row Deserialization ──────────────────────────────────────── */

static void row_to_wallet_key(sqlite3_stmt *s, struct db_wallet_key *k)
{
    memset(k, 0, sizeof(*k));
    AR_READ_BLOB(s, 0, k->pubkey_hash, 20);
    int pk_len = AR_COL_BYTES(s, 1);
    const void *pk = sqlite3_column_blob(s, 1);
    if (pk && pk_len <= 33) {
        memcpy(k->pubkey, pk, (size_t)pk_len);
        k->pubkey_len = (size_t)pk_len;
    }
    AR_READ_BLOB(s, 2, k->privkey, 32);
    k->compressed = AR_COL_INT(s, 3) != 0;
    k->created_at = AR_COL_INT(s, 4);
}

int db_wallet_key_each(struct node_db *ndb, wallet_key_cb cb, void *ctx)
{
    if (!ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    AR_PREPARE_RET(ndb, s,
        "SELECT pubkey_hash,pubkey,privkey,compressed,created_at"
        " FROM wallet_keys",
        0);
    int count = 0;
    while (AR_STEP_ROW(s)) {
        struct db_wallet_key k;
        row_to_wallet_key(s, &k);
        cb(&k, ctx);
        memory_cleanse(k.privkey, 32);
        count++;
    }
    AR_FINALIZE(s);
    return count;
}

/* ── SaplingKey CRUD ──────────────────────────────────────────── *
 * There is no db_sapling_key_save: the wallet_sapling_keys secret
 * column has a single writer, the encryption-aware wallet_sqlite
 * layer. This model keeps the read side for diagnostics. */

/* ── SaplingKey Row Deserialization ────────────────────────────── */

static void row_to_sapling_key(sqlite3_stmt *s, int col,
                                struct db_sapling_key *out)
{
    memset(out, 0, sizeof(*out));
    AR_READ_BLOB(s, col, out->ivk, 32);
    AR_READ_BLOB(s, col + 1, out->xsk, 169);
    AR_READ_BLOB(s, col + 2, out->xfvk, 169);
    AR_READ_BLOB(s, col + 3, out->diversifier, 11);
    AR_READ_BLOB(s, col + 4, out->pk_d, 32);
    out->child_index = (uint32_t)AR_COL_INT(s, col + 5);
    AR_READ_STR(s, col + 6, out->address, sizeof(out->address));
}

bool db_sapling_key_find_by_ivk(struct node_db *ndb, const uint8_t ivk[32],
                                struct db_sapling_key *out)
{
    if (!ndb->open) return false;
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT ivk,xsk,xfvk,diversifier,pk_d,child_index,address"
        " FROM wallet_sapling_keys WHERE ivk=?",
        AR_BIND_BLOB(s, 1, ivk, 32),
        if (out)
            row_to_sapling_key(s, 0, out));
}

int db_sapling_key_count(struct node_db *ndb)
{
    if (!ndb->open) return 0;
    AR_QUERY_COUNT_SQL(ndb, "SELECT COUNT(*) FROM wallet_sapling_keys");
}

#define WALLET_BIRTHDAY_STATE_KEY "wallet_birthday_height"
#define WALLET_BIRTHDAY_HASH_KEY "wallet_birthday_hash"

bool db_wallet_birthday_get(struct node_db *ndb, int64_t *height,
                            uint8_t hash[32])
{
    int64_t h = 0;
    size_t len = 0;
    if (!ndb || !ndb->open || !height || !hash ||
        !node_db_state_get_int(ndb, WALLET_BIRTHDAY_STATE_KEY, &h) || h < 0 ||
        !node_db_state_get(ndb, WALLET_BIRTHDAY_HASH_KEY, hash, 32, &len) ||
        len != 32)
        return false;
    *height = h;
    return true;
}

#define WALLET_BIRTHDAY_PROOF_KEY "wallet_birthday_scan_identity"

static bool birthday_write(struct node_db *ndb, int64_t height, const uint8_t hash[32],
                           const uint8_t *identity)
{
    if (!ndb || !ndb->open || !ndb->db || !hash || height < 0) return false;
    if (sqlite3_exec(ndb->db, "SAVEPOINT wallet_birthday", NULL, NULL, NULL) != SQLITE_OK) return false;
    bool ok = node_db_state_delete(ndb, WALLET_BIRTHDAY_PROOF_KEY) &&
        node_db_state_set(ndb, WALLET_BIRTHDAY_HASH_KEY, hash, 32) &&
        node_db_state_set_int(ndb, WALLET_BIRTHDAY_STATE_KEY, height) &&
        (!identity || node_db_state_set(ndb, WALLET_BIRTHDAY_PROOF_KEY, identity, 32));
    if (ok && sqlite3_exec(ndb->db, "RELEASE wallet_birthday", NULL, NULL, NULL) == SQLITE_OK) return true;
    int rollback = sqlite3_exec(ndb->db, "ROLLBACK TO wallet_birthday", NULL, NULL, NULL);
    int release = sqlite3_exec(ndb->db, "RELEASE wallet_birthday", NULL, NULL, NULL);
    if (rollback != SQLITE_OK || release != SQLITE_OK) {
        LOG_ERROR("wallet_key", "birthday savepoint cleanup failed rollback=%d release=%d", rollback, release);
        _Exit(EXIT_FAILURE);
    }
    return false;
}

/* A read error and any partial tuple both refuse a new birthday. */
static bool birthday_tuple_absent(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    bool ok = sqlite3_prepare_v2(db,
        "SELECT 1 FROM node_state WHERE key IN (?1,?2,?3) LIMIT 1",
        -1, &s, NULL) == SQLITE_OK && s &&
        sqlite3_bind_text(s, 1, WALLET_BIRTHDAY_STATE_KEY, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_text(s, 2, WALLET_BIRTHDAY_HASH_KEY, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_text(s, 3, WALLET_BIRTHDAY_PROOF_KEY, -1, SQLITE_STATIC) == SQLITE_OK;
    if (ok) ok = sqlite3_step(s) == SQLITE_DONE; // raw-sql-ok:wallet-birthday-absence
    if (s && sqlite3_finalize(s) != SQLITE_OK) ok = false;
    return ok;
}

/* Store an initial birthday only when no part of the old tuple exists. */
bool db_wallet_birthday_set_if_absent(struct node_db *ndb, int64_t height,
                                      const uint8_t hash[32])
{
    if (!ndb || !ndb->open || !ndb->db || !hash || height < 0) return false;
    sqlite3 *db = ndb->db;
    if (sqlite3_exec(db, "SAVEPOINT wallet_birthday_once", NULL, NULL, NULL) != SQLITE_OK)
        return false;
    bool ok = birthday_tuple_absent(db);
    if (ok) ok = birthday_write(ndb, height, hash, NULL);
    if (ok && sqlite3_exec(db, "RELEASE wallet_birthday_once", NULL, NULL, NULL) == SQLITE_OK)
        return true;
    int rollback = sqlite3_exec(db, "ROLLBACK TO wallet_birthday_once", NULL, NULL, NULL);
    int release = sqlite3_exec(db, "RELEASE wallet_birthday_once", NULL, NULL, NULL);
    if (rollback != SQLITE_OK || release != SQLITE_OK) {
        LOG_ERROR("wallet_key", "birthday absence savepoint cleanup failed rollback=%d release=%d", rollback, release);
        _Exit(EXIT_FAILURE);
    }
    return false;
}

bool db_wallet_birthday_set(struct node_db *ndb, int64_t height, const uint8_t hash[32])
{
    return birthday_write(ndb, height, hash, NULL);
}

bool db_wallet_birthday_set_created(struct node_db *ndb, int64_t height,
                                    const uint8_t hash[32], const uint8_t identity[32])
{
    return identity && birthday_write(ndb, height, hash, identity);
}

static bool birthday_proof_row(sqlite3_stmt *s, int64_t *height,
                               uint8_t hash[32], uint8_t identity[32])
{
    for (int i = 0; i < 3; i++) {
        int size = i == 1 ? 8 : 32;
        if (sqlite3_column_type(s, i) != SQLITE_BLOB || sqlite3_column_bytes(s, i) != size ||
            !sqlite3_column_blob(s, i)) return false;
    }
    memcpy(identity, sqlite3_column_blob(s, 0), 32);
    memcpy(height, sqlite3_column_blob(s, 1), 8);
    memcpy(hash, sqlite3_column_blob(s, 2), 32);
    return *height >= 0;
}


static bool birthday_proof_query_bind(sqlite3_stmt *s)
{
    return sqlite3_bind_text(s, 1, WALLET_BIRTHDAY_PROOF_KEY, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_text(s, 2, WALLET_BIRTHDAY_STATE_KEY, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_text(s, 3, WALLET_BIRTHDAY_HASH_KEY, -1, SQLITE_STATIC) == SQLITE_OK;
}

static bool birthday_proof_args(struct node_db *ndb, int64_t *height,
                                uint8_t hash[32], uint8_t identity[32])
{
    return ndb && ndb->open && ndb->db && height && hash && identity;
}


enum wallet_birthday_proof_status db_wallet_birthday_proof_get(struct node_db *ndb,
    int64_t *height, uint8_t hash[32], uint8_t identity[32])
{
    if (height) *height = 0;
    if (hash) memset(hash, 0, 32);
    if (identity) memset(identity, 0, 32);
    if (!birthday_proof_args(ndb, height, hash, identity)) return WALLET_BIRTHDAY_PROOF_ERROR;
    sqlite3_stmt *s = NULL;
    const char *sql = "SELECT value,(SELECT value FROM node_state WHERE key=?2),"
        "(SELECT value FROM node_state WHERE key=?3) FROM node_state WHERE key=?1";
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) != SQLITE_OK) return WALLET_BIRTHDAY_PROOF_ERROR;
    if (!birthday_proof_query_bind(s)) {
        sqlite3_finalize(s); return WALLET_BIRTHDAY_PROOF_ERROR;
    }
    int rc = sqlite3_step(s); // raw-sql-ok:read-only-introspection
    enum wallet_birthday_proof_status status = WALLET_BIRTHDAY_PROOF_ERROR;
    if (rc == SQLITE_DONE) status = WALLET_BIRTHDAY_PROOF_ABSENT;
    else if (rc == SQLITE_ROW) {
        status = birthday_proof_row(s, height, hash, identity)
            ? WALLET_BIRTHDAY_PROOF_FOUND : WALLET_BIRTHDAY_PROOF_MALFORMED;
        if (sqlite3_step(s) != SQLITE_DONE) status = WALLET_BIRTHDAY_PROOF_ERROR; // raw-sql-ok:read-only-introspection
    }
    if (sqlite3_finalize(s) != SQLITE_OK) status = WALLET_BIRTHDAY_PROOF_ERROR;
    if (status != WALLET_BIRTHDAY_PROOF_FOUND) { *height = 0; memset(hash, 0, 32); memset(identity, 0, 32); }
    return status;
}

/* Versioned single-row prepare record; contains only a nonce and public bindings. */
#define WALLET_CREATE_PENDING_KEY "wallet_create_pending_v1"
#define WALLET_CREATE_PENDING_BYTES 105u

static bool wallet_create_pending_encode(const struct wallet_create_pending *p,
                                         uint8_t out[WALLET_CREATE_PENDING_BYTES])
{
    if (!p || p->floor < 0) return false;
    out[0] = p->committed ? 2 : 1;
    memcpy(out + 1, p->nonce, 32); memcpy(out + 33, p->identity, 32);
    uint64_t floor = (uint64_t)p->floor;
    zcl_write_u64_le(out + 65, floor);
    memcpy(out + 73, p->floor_hash, 32);
    return true;
}

bool db_wallet_create_pending_insert(struct node_db *ndb, const struct wallet_create_pending *pending)
{
    uint8_t bytes[WALLET_CREATE_PENDING_BYTES];
    if (!ndb || !ndb->open || !ndb->db || !wallet_create_pending_encode(pending, bytes) || pending->committed) return false;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db, "INSERT INTO node_state(key,value) VALUES(?,?)", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_text(s, 1, WALLET_CREATE_PENDING_KEY, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_blob(s, 2, bytes, sizeof(bytes), SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_DONE; // raw-sql-ok:kv-state-primitive
    return sqlite3_finalize(s) == SQLITE_OK && ok;
}

static enum wallet_birthday_proof_status wallet_create_pending_decode(sqlite3_stmt *s, struct wallet_create_pending *out)
{
    const uint8_t *b = sqlite3_column_blob(s, 0);
    if (sqlite3_column_type(s, 0) != SQLITE_BLOB || sqlite3_column_bytes(s, 0) != WALLET_CREATE_PENDING_BYTES || !b || (b[0] != 1 && b[0] != 2))
        return WALLET_BIRTHDAY_PROOF_MALFORMED;
    uint64_t floor = zcl_read_u64_le(b + 65);
    if (floor > INT_MAX) return WALLET_BIRTHDAY_PROOF_MALFORMED;
    memcpy(out->nonce, b + 1, 32); memcpy(out->identity, b + 33, 32);
    out->floor = (int)floor; out->committed = b[0] == 2; memcpy(out->floor_hash, b + 73, 32);
    return WALLET_BIRTHDAY_PROOF_FOUND;
}

enum wallet_birthday_proof_status db_wallet_create_pending_get(struct node_db *ndb,
                                                               struct wallet_create_pending *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!ndb || !ndb->open || !ndb->db || !out) return WALLET_BIRTHDAY_PROOF_ERROR;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db, "SELECT value FROM node_state WHERE key=?", -1, &s, NULL) != SQLITE_OK)
        return WALLET_BIRTHDAY_PROOF_ERROR;
    if (sqlite3_bind_text(s, 1, WALLET_CREATE_PENDING_KEY, -1, SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(s); return WALLET_BIRTHDAY_PROOF_ERROR;
    }
    int rc = sqlite3_step(s); // raw-sql-ok:read-only-introspection
    enum wallet_birthday_proof_status result = WALLET_BIRTHDAY_PROOF_ERROR;
    if (rc == SQLITE_DONE) result = WALLET_BIRTHDAY_PROOF_ABSENT;
    else if (rc == SQLITE_ROW) {
        result = wallet_create_pending_decode(s, out);
        if (sqlite3_step(s) != SQLITE_DONE) result = WALLET_BIRTHDAY_PROOF_ERROR; // raw-sql-ok:read-only-introspection
    }
    if (sqlite3_finalize(s) != SQLITE_OK) result = WALLET_BIRTHDAY_PROOF_ERROR;
    if (result != WALLET_BIRTHDAY_PROOF_FOUND) memset(out, 0, sizeof(*out));
    return result;
}

static bool wallet_create_pending_replace(struct node_db *ndb, const uint8_t *old, const uint8_t *next)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db, "UPDATE node_state SET value=? WHERE key=? AND value=?", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_blob(s, 1, next, WALLET_CREATE_PENDING_BYTES, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_text(s, 2, WALLET_CREATE_PENDING_KEY, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_blob(s, 3, old, WALLET_CREATE_PENDING_BYTES, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_DONE && sqlite3_changes(ndb->db) == 1; // raw-sql-ok:kv-state-primitive
    return sqlite3_finalize(s) == SQLITE_OK && ok;
}

bool db_wallet_create_pending_commit(struct node_db *ndb, const struct wallet_create_pending *pending)
{
    uint8_t old[WALLET_CREATE_PENDING_BYTES], next[WALLET_CREATE_PENDING_BYTES];
    if (!ndb || !ndb->open || !ndb->db || !pending || pending->committed ||
        sqlite3_txn_state(ndb->db, "main") != SQLITE_TXN_WRITE ||
        pending->floor > INT_MAX - WALLET_BIRTHDAY_MARGIN || !wallet_create_pending_encode(pending, old)) return false;
    struct wallet_create_pending committed = *pending; committed.committed = true;
    if (!wallet_create_pending_encode(&committed, next)) return false;
    if (pending->floor > 0 && !db_wallet_birthday_set_created(ndb,
        (int64_t)pending->floor + WALLET_BIRTHDAY_MARGIN, pending->floor_hash, pending->identity)) return false;
    return wallet_create_pending_replace(ndb, old, next);
}

bool db_wallet_create_pending_cancel(struct node_db *ndb, const struct wallet_create_pending *pending)
{
    uint8_t bytes[WALLET_CREATE_PENDING_BYTES];
    if (!ndb || !ndb->open || !ndb->db || !pending || pending->committed ||
        !wallet_create_pending_encode(pending, bytes)) return false;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db, "DELETE FROM node_state WHERE key=? AND value=?", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_text(s, 1, WALLET_CREATE_PENDING_KEY, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_blob(s, 2, bytes, sizeof(bytes), SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_DONE && sqlite3_changes(ndb->db) == 1; // raw-sql-ok:kv-state-primitive
    return sqlite3_finalize(s) == SQLITE_OK && ok;
}


/* ── Wallet Seed ──────────────────────────────────────────────── *
 * There is no db_wallet_seed_save: wallet_seed has a single writer,
 * the encryption-aware wallet_sqlite layer. The read side stays. */

bool db_wallet_seed_load(struct node_db *ndb, uint8_t seed[32],
                         uint32_t *next_child)
{
    if (!ndb->open) return false;
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT seed,next_child FROM wallet_seed WHERE id=1",
        (void)0,
        AR_READ_BLOB(s, 0, seed, 32);
        *next_child = (uint32_t)AR_COL_INT(s, 1));
}

/* ── Redeem Scripts ───────────────────────────────────────────── */

bool db_wallet_script_save(struct node_db *ndb, const struct db_wallet_script *sc)
{
    if (!ndb->open) return false;
    struct ar_callbacks *cbs = db_wallet_script_callbacks();
    sqlite3_stmt *s = NULL;
    AR_ADHOC_SAVE(ndb, s,
        "INSERT OR REPLACE INTO wallet_scripts(script_hash,redeem_script)"
        " VALUES(?,?)",
        cbs, "wallet_script", sc, db_wallet_script_validate,
        AR_BIND_BLOB(s, 1, sc->script_hash, 20);
        AR_BIND_BLOB(s, 2, sc->redeem_script, (int)sc->script_len));
}

bool db_wallet_script_find(struct node_db *ndb, const uint8_t script_hash[20],
                           struct db_wallet_script *out)
{
    if (!ndb->open) return false;
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT redeem_script FROM wallet_scripts WHERE script_hash=?",
        AR_BIND_BLOB(s, 1, script_hash, 20),
        memset(out, 0, sizeof(*out));
        memcpy(out->script_hash, script_hash, 20);
        out->script_len = (size_t)AR_COL_BYTES(s, 0);
        const void *rs = sqlite3_column_blob(s, 0);
        if (rs && out->script_len > 0) {
            out->redeem_script = zcl_malloc(out->script_len, "wallet_key redeem_script find");
            if (out->redeem_script)
                memcpy(out->redeem_script, rs, out->script_len);
        });
}

/* ── Relationships ─────────────────────────────────────────────── */

/* WalletKey has_many :wallet_utxos */
int db_wallet_key_utxos(struct node_db *ndb, const uint8_t pubkey_hash[20],
                        struct db_wallet_utxo *out, size_t max)
{
    if (!ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "SELECT txid,vout,value,script,height,is_coinbase"
        " FROM wallet_utxos WHERE address_hash=?"
        " AND spent_txid IS NULL ORDER BY value DESC LIMIT ?",
        -1, &s, NULL);
    if (!s) LOG_RETURN(0, "wallet_key", "prepare failed: %s", sqlite3_errmsg(ndb->db));
    AR_BIND_BLOB(s, 1, pubkey_hash, 20);
    AR_BIND_INT(s, 2, (int)max);
    int count = 0;
    while (AR_STEP_ROW(s) && (size_t)count < max) {
        memset(&out[count], 0, sizeof(out[count]));
        AR_READ_BLOB(s, 0, out[count].txid, 32);
        out[count].vout = (uint32_t)AR_COL_INT(s, 1);
        out[count].value = AR_COL_INT(s, 2);
        memcpy(out[count].address_hash, pubkey_hash, 20);
        out[count].script_len = (size_t)AR_COL_BYTES(s, 3);
        out[count].script = NULL;
        out[count].height = (int)AR_COL_INT(s, 4);
        out[count].is_coinbase = AR_COL_INT(s, 5) != 0;
        count++;
    }
    AR_FINALIZE(s);
    return count;
}

/* SaplingKey has_many :sapling_notes */
int db_sapling_key_notes(struct node_db *ndb, const uint8_t ivk[32],
                         struct db_sapling_note *out, size_t max)
{
    if (!ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "SELECT txid,output_index,value,rcm,memo,diversifier,pk_d,"
        "cm,nullifier,block_height,source"
        " FROM wallet_sapling_notes WHERE ivk=?"
        " AND spent_txid IS NULL ORDER BY value DESC LIMIT ?",
        -1, &s, NULL);
    if (!s) LOG_RETURN(0, "wallet_key", "prepare failed: %s", sqlite3_errmsg(ndb->db));
    AR_BIND_BLOB(s, 1, ivk, 32);
    AR_BIND_INT(s, 2, (int)max);
    int count = 0;
    while (AR_STEP_ROW(s) && (size_t)count < max) {
        memset(&out[count], 0, sizeof(out[count]));
        AR_READ_BLOB(s, 0, out[count].txid, 32);
        out[count].output_index = (uint32_t)AR_COL_INT(s, 1);
        out[count].value = AR_COL_INT(s, 2);
        AR_READ_BLOB(s, 3, out[count].rcm, 32);
        int memo_len = AR_COL_BYTES(s, 4);
        const void *memo = sqlite3_column_blob(s, 4);
        if (memo && memo_len > 0) {
            size_t ml = (size_t)memo_len < 512 ? (size_t)memo_len : 512;
            memcpy(out[count].memo, memo, ml);
            out[count].memo_len = ml;
        }
        memcpy(out[count].ivk, ivk, 32);
        AR_READ_BLOB(s, 5, out[count].diversifier, 11);
        AR_READ_BLOB(s, 6, out[count].pk_d, 32);
        AR_READ_BLOB(s, 7, out[count].cm, 32);
        AR_READ_BLOB(s, 8, out[count].nullifier, 32);
        if (sqlite3_column_type(s, 9) != SQLITE_NULL)
            out[count].block_height = (int)AR_COL_INT(s, 9);
        AR_READ_STR(s, 10, out[count].source, sizeof(out[count].source));
        if (!out[count].source[0])
            snprintf(out[count].source, sizeof(out[count].source), "%s",
                     DB_SAPLING_NOTE_SOURCE_LOCAL);
        count++;
    }
    AR_FINALIZE(s);
    return count;
}
