/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord models: WalletTx, WalletUTXO, SaplingNote
 *
 * WalletTx:
 *   validates :txid, presence: true
 *   validates :time_received, positive: true
 *   has_many :wallet_utxos, :sapling_notes
 *   belongs_to :block
 *
 * WalletUTXO:
 *   validates :txid, presence: true
 *   validates :value, money_range: [0, MAX_MONEY]
 *   belongs_to :wallet_key
 *
 * SaplingNote:
 *   validates :txid, :ivk, :nullifier, :cm, :pk_d, :diversifier, :rcm, presence
 *   validates :value, money_range: [0, MAX_MONEY]
 *   belongs_to :sapling_key */

#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/ar_step_readonly.h"
#include "encoding/utilstrencodings.h"
#include "models/wallet_tx.h"
#include "models/ar_after_commit.h"
#include "models/wallet_tx_internal.h"
#include "models/block.h"
#include "models/wallet_key.h"
#include "wallet/sapling_keys.h"
#include "wallet/wallet.h"
#include "wallet/wallet_sqlite.h"
#include "script/standard.h"
#include "chain/chainparams.h"
#include "event/event.h"
#include "storage/wallet_projection.h"
#include "storage/event_log.h"
#include "util/safe_alloc.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>

static const uint8_t ZERO_HASH[32] = {0};

/* ── Callbacks ─────────────────────────────────────────────────── */

DEFINE_MODEL_CALLBACKS(wallet_tx)
DEFINE_MODEL_CALLBACKS(wallet_utxo)
/* sapling_note callbacks live in sapling_note.c */

/* before_save: validate wallet_tx txid is non-null */
static bool wallet_tx_before_save(void *record, void *ctx)
{
    (void)ctx;
    const struct db_wallet_tx *t = record;
    static const uint8_t zero[32] = {0};
    if (memcmp(t->txid, zero, 32) == 0) {
        LOG_FAIL("wallet_tx", "before_save REJECTED: null txid");
    }
    return true;
}

static void wallet_tx_after_save(void *record, void *ctx)
{
    (void)ctx;
    const struct db_wallet_tx *t = record;
    const char *category = t->from_me ? "send" : "receive";
    event_emitf(EV_WALLET_TX_SAVED, 0,
                "category=%s", category);
    if (!wallet_projection_emit_tx_seen(t->txid,
            t->has_block ? t->block_height : -1,
            t->fee, t->from_me ? 1u : 0u)) {
        LOG_WARN("wallet_projection", "[wallet_projection] tx seen projection emit failed");
    }
}

static void wallet_tx_init_hooks(void)
{
    static bool done = false;
    if (done) return;
    struct ar_callbacks *cbs = db_wallet_tx_callbacks();
    ar_register_before_save(cbs, wallet_tx_before_save);
    ar_register_after_save(cbs, wallet_tx_after_save);
    done = true;
}

/* before_save: validate txid not null, vout >= 0, value >= 0 */
static bool wallet_utxo_before_save(void *record, void *ctx)
{
    (void)ctx;
    const struct db_wallet_utxo *u = record;
    static const uint8_t zero[32] = {0};
    if (memcmp(u->txid, zero, 32) == 0) {
        LOG_FAIL("wallet_utxo", "before_save REJECTED: null txid");
    }
    if (u->value < 0 || u->value > 2100000000000000LL) {
        LOG_FAIL("wallet_utxo", "before_save REJECTED: value out of range");
    }
    return true;
}

/* after_save: emit model-specific event */
static void wallet_utxo_after_save(void *record, void *ctx)
{
    (void)ctx;
    const struct db_wallet_utxo *u = record;
    event_emitf(EV_WALLET_UTXO_SAVED, 0, "vout=%u", u->vout);
    if (!wallet_projection_emit_utxo_seen(u->txid, u->vout, u->value,
            u->address_hash, u->height, u->is_coinbase ? 1u : 0u)) {
        LOG_WARN("wallet_projection", "[wallet_projection] utxo seen projection emit failed");
    }
}

static void wallet_utxo_init_hooks(void)
{
    static bool done = false;
    if (done) return;
    struct ar_callbacks *cbs = db_wallet_utxo_callbacks();
    ar_register_before_save(cbs, wallet_utxo_before_save);
    ar_register_after_save(cbs, wallet_utxo_after_save);
    done = true;
}

/* Test-only: re-arm the wallet_tx and wallet_utxo model hooks after a group
 * cleared the shared callback structs via ar_callbacks_init() (test_activerecord).
 * Mirrors the init_hooks pair but bypasses their one-shot `done` guards. */
void wallet_tx_reset_hooks_for_testing(void)
{
    struct ar_callbacks *tx = db_wallet_tx_callbacks();
    ar_callbacks_init(tx);
    ar_register_before_save(tx, wallet_tx_before_save);
    ar_register_after_save(tx, wallet_tx_after_save);
    struct ar_callbacks *utxo = db_wallet_utxo_callbacks();
    ar_callbacks_init(utxo);
    ar_register_before_save(utxo, wallet_utxo_before_save);
    ar_register_after_save(utxo, wallet_utxo_after_save);
}

/* ── Validation ────────────────────────────────────────────────── */

bool db_wallet_tx_validate(const struct db_wallet_tx *t, struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_presence_of(errors, t, txid);
    validates_positive(errors, t, time_received);
    validates_custom(errors,
        !(t->raw_tx && t->raw_tx_len == 0),
        "raw_tx_len", "must be positive when raw_tx present");
    validates_custom(errors,
        t->raw_tx_len <= (size_t)INT32_MAX,
        "raw_tx_len", "exceeds max size");
    if (t->has_block) {
        validates_non_negative(errors, t, block_height);
        validates_presence_of(errors, t, block_hash);
    }
    validates_non_negative(errors, t, fee);
    return !ar_errors_any(errors);
}

bool db_wallet_utxo_validate(const struct db_wallet_utxo *u,
                              struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_presence_of(errors, u, txid);
    validates_money_range(errors, u, value, 2100000000000000LL);
    validates_non_negative(errors, u, height);
    validates_custom(errors,
        !(u->script && u->script_len == 0),
        "script_len", "must be positive when script present");
    validates_max(errors, u, script_len, 10000);
    validates_custom(errors,
        !(u->script_len > 0 && !u->script),
        "script", "null pointer with nonzero length");
    if (u->is_spent) {
        static const uint8_t z[32] = {0};
        if (memcmp(u->spent_txid, z, 32) == 0)
            ar_errors_add(errors, "spent_txid", "can't be blank when spent");
    }
    return !ar_errors_any(errors);
}

/* ── Row Deserialization ──────────────────────────────────────── */

static void db_wallet_tx_read_row(sqlite3_stmt *s, int col,
                                  struct db_wallet_tx *out)
{
    memset(out, 0, sizeof(*out));
    AR_READ_BLOB(s, col, out->txid, 32);                  col++;

    /* raw_tx: variable-length blob, needs malloc */
    out->raw_tx_len = (size_t)AR_COL_BYTES(s, col);
    const void *rt = sqlite3_column_blob(s, col++);
    if (rt && out->raw_tx_len > 0) {
        out->raw_tx = zcl_malloc(out->raw_tx_len, "wallet_tx raw_tx");
        if (!out->raw_tx) { out->raw_tx_len = 0; return; }
        memcpy(out->raw_tx, rt, out->raw_tx_len);
    }

    AR_READ_BLOB(s, col, out->block_hash, 32);
    out->has_block = memcmp(out->block_hash, ZERO_HASH, 32) != 0;
    col++;

    if (sqlite3_column_type(s, col) != SQLITE_NULL) {
        out->block_height = (int)AR_COL_INT(s, col);
        /* Historical/imported rows can carry the legacy unconfirmed sentinel
         * height 0.  It is not a block assignment: treating it as one turns
         * tip_height - 0 + 1 into millions of fictional confirmations and
         * exposes an all-zero block hash through gettransaction. */
        if (out->block_height > 0)
            out->has_block = true;
    }
    col++;

    out->time_received = AR_COL_INT(s, col++);
    out->from_me = AR_COL_INT(s, col++) != 0;
    out->fee = AR_COL_INT(s, col++);
}

static void db_wallet_tx_raw_view_read_row(sqlite3_stmt *s, int col,
                                           struct db_wallet_tx_raw_view *out)
{
    memset(out, 0, sizeof(*out));
    out->raw_tx_len = (size_t)AR_COL_BYTES(s, col);
    if (out->raw_tx_len > 0) {
        const void *raw = sqlite3_column_blob(s, col);
        if (raw) {
            out->raw_tx = zcl_malloc(out->raw_tx_len, "wallet_tx raw_view");
            if (out->raw_tx)
                memcpy(out->raw_tx, raw, out->raw_tx_len);
            else
                out->raw_tx_len = 0;
        }
    }
    col++;
    out->block_height = sqlite3_column_type(s, col) == SQLITE_NULL
        ? 0 : (int)AR_COL_INT(s, col);
}

static void db_wallet_utxo_read_row(sqlite3_stmt *s, int col,
                                     struct db_wallet_utxo *out)
{
    memset(out, 0, sizeof(*out));
    AR_READ_BLOB(s, col, out->txid, 32);                   col++;
    out->vout = (uint32_t)AR_COL_INT(s, col++);
    out->value = AR_COL_INT(s, col++);
    AR_READ_BLOB(s, col, out->address_hash, 20);           col++;
    /* script: variable-length, needs malloc */
    out->script_len = (size_t)AR_COL_BYTES(s, col);
    const void *sc = sqlite3_column_blob(s, col);
    if (sc && out->script_len > 0) {
        out->script = zcl_malloc(out->script_len, "wallet_tx utxo script");
        if (out->script)
            memcpy(out->script, sc, out->script_len);
    } else {
        out->script = NULL;
    }
    col++;
    out->height = (int)AR_COL_INT(s, col++);
    out->is_coinbase = AR_COL_INT(s, col++) != 0;
}

/* Read spent_txid/spent_vin from columns after standard UTXO columns */
static void read_utxo_spent(sqlite3_stmt *s, int col, struct db_wallet_utxo *u)
{
    const void *st = sqlite3_column_blob(s, col);
    if (st && sqlite3_column_bytes(s, col) >= 32) {
        memcpy(u->spent_txid, st, 32);
        u->is_spent = true;
    }
    if (sqlite3_column_type(s, col + 1) != SQLITE_NULL)
        u->spent_vin = (int)AR_COL_INT(s, col + 1);
}

/* ── WalletTx CRUD ────────────────────────────────────────────── */

bool db_wallet_tx_save(struct node_db *ndb, const struct db_wallet_tx *t)
{
    if (!ndb->open)
        return false; /* raw-return-ok:closed store cannot delete a UTXO */
    if (t->time_received == 0)
        ((struct db_wallet_tx *)t)->time_received = (int64_t)platform_time_wall_time_t();

    wallet_tx_init_hooks();
    struct ar_callbacks *cbs = db_wallet_tx_callbacks();
    sqlite3_stmt *s = NULL;
    AR_ADHOC_SAVE(ndb, s,
        "INSERT OR REPLACE INTO wallet_transactions"
        "(txid,raw_tx,block_hash,block_height,time_received,from_me,fee)"
        " VALUES(?,?,?,?,?,?,?)",
        cbs, "wallet_tx", t, db_wallet_tx_validate,
        AR_BIND_BLOB(s, 1, t->txid, 32);
        AR_BIND_BLOB(s, 2, t->raw_tx, (int)t->raw_tx_len);
        if (t->has_block)
            AR_BIND_BLOB(s, 3, t->block_hash, 32);
        else
            AR_BIND_NULL(s, 3);
        if (t->has_block)
            AR_BIND_INT(s, 4, t->block_height);
        else
            AR_BIND_NULL(s, 4);
        AR_BIND_INT(s, 5, t->time_received);
        AR_BIND_INT(s, 6, t->from_me ? 1 : 0);
        AR_BIND_INT(s, 7, t->fee));
}

enum db_wallet_tx_presence db_wallet_tx_presence_checked(struct node_db *ndb,
                                                       const uint8_t txid[32])
{
    if (!ndb || !ndb->open || !ndb->db || !txid) return DB_WALLET_TX_ERROR;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db, "SELECT 1 FROM wallet_transactions WHERE txid=?", -1, &s, NULL) != SQLITE_OK) {
        LOG_WARN("wallet_tx", "transaction presence prepare failed: %s", sqlite3_errmsg(ndb->db));
        return DB_WALLET_TX_ERROR;
    }
    enum db_wallet_tx_presence result = DB_WALLET_TX_ERROR;
    if (sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC) == SQLITE_OK) {
        int rc = AR_STEP_ROW_READONLY(s);
        if (rc == SQLITE_DONE) result = DB_WALLET_TX_ABSENT;
        else if (rc == SQLITE_ROW && AR_STEP_ROW_READONLY(s) == SQLITE_DONE)
            result = DB_WALLET_TX_PRESENT;
    }
    if (sqlite3_finalize(s) != SQLITE_OK) result = DB_WALLET_TX_ERROR;
    if (result == DB_WALLET_TX_ERROR)
        LOG_WARN("wallet_tx", "transaction presence query failed: %s", sqlite3_errmsg(ndb->db));
    return result;
}

bool db_wallet_tx_find(struct node_db *ndb, const uint8_t txid[32],
                       struct db_wallet_tx *out)
{
    if (!ndb->open) return false;
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT txid,raw_tx,block_hash,block_height,time_received,from_me,fee"
        " FROM wallet_transactions WHERE txid=?",
        AR_BIND_BLOB(s, 1, txid, 32),
        db_wallet_tx_read_row(s, 0, out));
}

bool db_wallet_tx_delete(struct node_db *ndb, const uint8_t txid[32])
{
    if (!ndb->open) return false;

    struct ar_callbacks *cbs = db_wallet_tx_callbacks();
    struct db_wallet_tx t;
    memset(&t, 0, sizeof(t));
    memcpy(t.txid, txid, 32);

    /* dependent: :destroy — delete child wallet_utxos */
    sqlite3_stmt *du = NULL;
    sqlite3_prepare_v2(ndb->db,
        "DELETE FROM wallet_utxos WHERE txid=?", -1, &du, NULL);
    if (du) {
        AR_BIND_BLOB(du, 1, txid, 32);
        (void)AR_STEP_DONE(du);
        AR_FINALIZE(du);
    }

    sqlite3_stmt *s = NULL;
    AR_ADHOC_DESTROY(ndb, s, "DELETE FROM wallet_transactions WHERE txid=?",
        cbs, &t, AR_BIND_BLOB(s, 1, txid, 32));
}

int db_wallet_tx_count(struct node_db *ndb)
{
    if (!ndb->open) return 0;
    AR_QUERY_COUNT_SQL(ndb, "SELECT COUNT(*) FROM wallet_transactions");
}

void db_wallet_utxo_free(struct db_wallet_utxo *u)
{
    if (!u) return;
    free(u->script);
    u->script = NULL;
    u->script_len = 0;
}

int db_wallet_tx_list(struct node_db *ndb, struct db_wallet_tx *out,
                      size_t max, size_t offset)
{
    if (!ndb->open || !out || max == 0) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT txid,raw_tx,block_hash,block_height,time_received,from_me,fee"
        " FROM wallet_transactions"
        " ORDER BY time_received DESC, txid DESC"
        " LIMIT ? OFFSET ?",
        out, max,
        AR_BIND_INT(s, 1, (int)max);
        AR_BIND_INT(s, 2, (int64_t)offset),
        db_wallet_tx_read_row(s, 0, &out[count]));
}

int db_wallet_tx_recent_raw(struct node_db *ndb,
                            struct db_wallet_tx_raw_view *out,
                            size_t max)
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open || !out || max == 0)
        return 0;
    AR_QUERY_LIST(ndb, s,
        "SELECT raw_tx, block_height "
        "FROM wallet_transactions "
        "WHERE raw_tx IS NOT NULL "
        "ORDER BY block_height DESC, time_received DESC "
        "LIMIT ?",
        out, max,
        AR_BIND_INT(s, 1, (int)max),
        db_wallet_tx_raw_view_read_row(s, 0, &out[count]));
}

void db_wallet_tx_raw_view_free(struct db_wallet_tx_raw_view *row)
{
    if (!row)
        return;
    free(row->raw_tx);
    row->raw_tx = NULL;
    row->raw_tx_len = 0;
}

int db_wallet_tx_list_unconfirmed(struct node_db *ndb,
                                  struct db_wallet_txid_ref *out,
                                  size_t max)
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open || !out || max == 0)
        return 0;
    AR_QUERY_LIST(ndb, s,
        "SELECT txid FROM wallet_transactions "
        "WHERE block_height IS NULL OR block_height = 0 "
        "ORDER BY time_received DESC, txid DESC "
        "LIMIT ?",
        out, max,
        AR_BIND_INT(s, 1, (int)max),
        AR_READ_BLOB(s, 0, out[count].txid, 32));
}

bool db_wallet_tx_update_block_height(struct node_db *ndb,
                                      const uint8_t txid[32],
                                      int block_height)
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open || !txid || block_height <= 0)
        return false;
    AR_EXEC_CHANGED_BOOL(ndb, s,
        "UPDATE wallet_transactions SET block_height=? WHERE txid=?",
        AR_BIND_INT(s, 1, block_height);
        AR_BIND_BLOB(s, 2, txid, 32));
}

/* ── WalletUTXO CRUD ─────────────────────────────────────────── */

static bool db_utxo_cutover_event_room(struct db_wallet_utxo_cutover_delivery *d)
{
    if (!d || d->committed || ar_after_commit_depth() <= 0) return false;
    if (d->count < d->capacity) return true;
    size_t next = d->capacity ? d->capacity * 2 : 16;
    if (next < d->capacity || next > SIZE_MAX / sizeof(*d->events)) return false;
    void *p = zcl_realloc(d->events, next * sizeof(*d->events), "cutover utxo events");
    if (!p) return false;
    d->events = p; d->capacity = next;
    return true;
}

static void db_utxo_cutover_committed(void *record, void *ctx)
{
    (void)record;
    struct db_wallet_utxo_cutover_delivery *delivery = ctx;
    delivery->committed = true;
}

static bool db_utxo_cutover_arm(struct db_wallet_utxo_cutover_delivery *delivery)
{
    if (delivery->armed) return true;
    uint8_t token = 1;
    if (!ar_after_commit_enqueue(db_utxo_cutover_committed, delivery, &token, sizeof(token))) return false;
    delivery->armed = true;
    return true;
}

static void db_utxo_cutover_event_add(struct db_wallet_utxo_cutover_delivery *d,
                                      const struct db_wallet_utxo *u)
{
    struct db_wallet_utxo_cutover_event *e = &d->events[d->count++];
    memcpy(e->txid, u->txid, 32); memcpy(e->address_hash, u->address_hash, 20);
    e->vout = u->vout; e->value = u->value; e->height = u->height; e->is_coinbase = u->is_coinbase;
}

static bool db_utxo_cutover_bind_output(sqlite3_stmt *s, const struct db_wallet_utxo *u)
{
    return sqlite3_bind_blob(s, 1, u->txid, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_int64(s, 2, u->vout) == SQLITE_OK && sqlite3_bind_int64(s, 3, u->value) == SQLITE_OK &&
        sqlite3_bind_blob(s, 4, u->address_hash, 20, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_blob(s, 5, u->script, (int)u->script_len, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_int(s, 6, u->height) == SQLITE_OK && sqlite3_bind_int(s, 7, u->is_coinbase) == SQLITE_OK;
}

static bool db_utxo_cutover_bind_spend(sqlite3_stmt *s, const uint8_t txid[32],
                                       uint32_t vout, const uint8_t spent_by[32], int vin)
{
    return sqlite3_bind_blob(s, 1, spent_by, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_int(s, 2, vin) == SQLITE_OK && sqlite3_bind_blob(s, 3, txid, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_int64(s, 4, vout) == SQLITE_OK && sqlite3_bind_blob(s, 5, spent_by, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_int(s, 6, vin) == SQLITE_OK;
}

enum db_wallet_utxo_cutover_result db_wallet_utxo_cutover_merge(
    struct node_db *ndb, const struct db_wallet_utxo *u,
    struct db_wallet_utxo_cutover_delivery *delivery)
{
    if (!ndb || !ndb->open || !ndb->db || !u ||
        sqlite3_txn_state(ndb->db, "main") != SQLITE_TXN_WRITE || u->is_spent ||
        !db_utxo_cutover_event_room(delivery))
        return DB_UTXO_CUTOVER_ERROR;
    struct ar_callbacks callbacks;
    ar_callbacks_init(&callbacks);
    if (!ar_register_before_save(&callbacks, wallet_utxo_before_save)) return DB_UTXO_CUTOVER_ERROR;
    AR_BEGIN_SAVE(&callbacks, "wallet_utxo", u, db_wallet_utxo_validate);
    sqlite3_stmt *s = NULL;
    const char *sql = "INSERT INTO wallet_utxos(txid,vout,value,address_hash,script,height,is_coinbase) "
        "VALUES(?,?,?,?,?,?,?) ON CONFLICT(txid,vout) DO UPDATE SET height=excluded.height "
        "WHERE wallet_utxos.value=excluded.value AND wallet_utxos.address_hash=excluded.address_hash "
        "AND wallet_utxos.script=excluded.script AND wallet_utxos.is_coinbase=excluded.is_coinbase";
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) != SQLITE_OK) return DB_UTXO_CUTOVER_ERROR;
    bool bound = db_utxo_cutover_bind_output(s, u);
    int rc = bound ? AR_STEP_WRITE(s) : SQLITE_ERROR;
    int changed = sqlite3_changes(ndb->db);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE) return DB_UTXO_CUTOVER_ERROR;
    if (changed != 1) return DB_UTXO_CUTOVER_CONFLICT;
    if (!db_utxo_cutover_arm(delivery)) return DB_UTXO_CUTOVER_ERROR;
    db_utxo_cutover_event_add(delivery, u);
    AR_FINISH_SAVE(&callbacks, u, true);
}

enum db_wallet_utxo_cutover_result db_wallet_utxo_cutover_spend(
    struct node_db *ndb, const uint8_t txid[32], uint32_t vout,
    const uint8_t spent_by[32], int vin)
{
    if (!ndb || !ndb->open || !ndb->db || !txid || !spent_by || vin < 0 ||
        !memcmp(spent_by, ZERO_HASH, 32) || sqlite3_txn_state(ndb->db, "main") != SQLITE_TXN_WRITE)
        return DB_UTXO_CUTOVER_ERROR;
    sqlite3_stmt *s = NULL;
    const char *sql = "UPDATE wallet_utxos SET spent_txid=?,spent_vin=? WHERE txid=? AND vout=? "
        "AND (spent_txid IS NULL OR (spent_txid=? AND spent_vin=?))";
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) != SQLITE_OK) return DB_UTXO_CUTOVER_ERROR;
    bool bound = db_utxo_cutover_bind_spend(s, txid, vout, spent_by, vin);
    int rc = bound ? AR_STEP_WRITE(s) : SQLITE_ERROR;
    int changed = sqlite3_changes(ndb->db);
    sqlite3_finalize(s);
    return rc != SQLITE_DONE ? DB_UTXO_CUTOVER_ERROR :
        (changed == 1 ? DB_UTXO_CUTOVER_OK : DB_UTXO_CUTOVER_CONFLICT);
}

/* Caller holds a stable event sink and keeps wallet writes quiescent. */
static bool db_utxo_reemit_types(sqlite3_stmt *s)
{
    for (int i = 0; i < 6; i++) {
        int expected = (i == 0 || i == 3) ? SQLITE_BLOB : SQLITE_INTEGER;
        if (sqlite3_column_type(s, i) != expected) return false;
    }
    return sqlite3_column_bytes(s, 0) == 32 && sqlite3_column_bytes(s, 3) == 20;
}

static bool db_utxo_reemit_ranges(sqlite3_int64 vout, sqlite3_int64 value,
    sqlite3_int64 height, sqlite3_int64 coinbase)
{
    return vout >= 0 && vout <= INT_MAX && value >= 0 && value <= 2100000000000000LL &&
        height >= 0 && height <= INT_MAX && (coinbase == 0 || coinbase == 1);
}

static bool db_utxo_reemit_row(sqlite3_stmt *s, event_log_t *log)
{
    if (!db_utxo_reemit_types(s)) return false;
    sqlite3_int64 vout = sqlite3_column_int64(s, 1), value = sqlite3_column_int64(s, 2);
    sqlite3_int64 height = sqlite3_column_int64(s, 4), coinbase = sqlite3_column_int64(s, 5);
    if (!db_utxo_reemit_ranges(vout, value, height, coinbase)) return false;
    const uint8_t *txid = sqlite3_column_blob(s, 0);
    const uint8_t *address = sqlite3_column_blob(s, 3);
    return txid && address && memcmp(txid, ZERO_HASH, 32) != 0 &&
        wallet_projection_event_log() == log &&
        wallet_projection_emit_utxo_seen(txid, (uint32_t)vout, value, address,
                                         (int32_t)height, (uint8_t)coinbase);
}

static bool db_utxo_reemit_scan(sqlite3 *db, event_log_t *log)
{
    sqlite3_stmt *s = NULL;
    bool ok = false;
    if (sqlite3_prepare_v2(db, "SELECT txid,vout,value,address_hash,height,is_coinbase "
            "FROM wallet_utxos ORDER BY txid,vout", -1, &s, NULL) != SQLITE_OK) goto done;
    int rc;
    while ((rc = AR_STEP_ROW_READONLY(s)) == SQLITE_ROW)
        if (!db_utxo_reemit_row(s, log)) goto done;
    ok = rc == SQLITE_DONE;
done:
    if (s && sqlite3_finalize(s) != SQLITE_OK) ok = false;
    return ok;
}

static bool db_utxo_reemit_finish(sqlite3 *db, bool ok)
{
    if (sqlite3_exec(db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK) return ok;
    if (!sqlite3_get_autocommit(db) && sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK &&
        !sqlite3_get_autocommit(db)) abort();
    return false;
}

bool db_wallet_utxo_reemit_all(struct node_db *ndb)
{
    event_log_t *log = wallet_projection_event_log();
    if (!ndb || !ndb->open || !ndb->db || !log) return false;
    sqlite3 *db = ndb->db;
    sqlite3_mutex *mu = sqlite3_db_mutex(db);
    if (!mu || sqlite3_mutex_try(mu) != SQLITE_OK) return false;
    bool ok = false;
    if (sqlite3_get_autocommit(db) && sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK)
        ok = db_utxo_reemit_finish(db, db_utxo_reemit_scan(db, log));
    sqlite3_mutex_leave(mu);
    return ok && wallet_projection_event_log() == log && event_log_flush(log);
}


bool db_wallet_utxo_cutover_delivery_flush(struct db_wallet_utxo_cutover_delivery *delivery)
{
    if (!delivery || !delivery->armed || !delivery->committed) return false;
    event_log_t *log = wallet_projection_event_log();
    if (!log) return false;
    for (size_t i = 0; i < delivery->count; i++) {
        const struct db_wallet_utxo_cutover_event *e = &delivery->events[i];
        if (wallet_projection_event_log() != log ||
            !wallet_projection_emit_utxo_seen(e->txid, e->vout, e->value, e->address_hash, e->height, e->is_coinbase))
            return false;
    }
    return wallet_projection_event_log() == log && event_log_flush(log);
}

void db_wallet_utxo_cutover_delivery_clear(struct db_wallet_utxo_cutover_delivery *delivery)
{
    if (!delivery) return;
    free(delivery->events); memset(delivery, 0, sizeof(*delivery));
}

static enum db_wallet_cutover_tx_class db_cutover_tx_class(
    const struct db_wallet_utxo_cutover_projection *projection,
    const struct wallet_cutover_v2_entry *entry)
{
    if (entry->new_depth > 0) return DB_CUTOVER_TX_ACTIVE;
    return projection->classify_unconfirmed(projection->classify_ctx, entry->txid);
}

static const struct wallet_tx *db_cutover_find_tx(struct wallet *w,
    const struct wallet_cutover_v2_plan *plan, const uint8_t id[32],
    const struct wallet_cutover_v2_entry **entry)
{
    *entry = wallet_cutover_v2_plan_find(plan, w, id);
    if (!*entry || (*entry)->slot >= MAX_WALLET_TX) return NULL;
    const struct wallet_tx *tx = &w->map_wallet[(*entry)->slot];
    return tx->used && !memcmp(tx->tx.hash.data, id, 32) ? tx : NULL;
}

static bool db_cutover_owned_output(struct wallet *w, const struct tx_out *out, uint8_t address[20])
{
    struct tx_destination dest;
    if (!wallet_is_mine(w, out) || wallet_is_watch_only(w, out) ||
        !script_extract_destination(&out->script_pub_key, &dest)) return false; // raw-return-ok:ownership-predicate
    if (dest.type == DEST_KEY_ID) memcpy(address, dest.id.key.id.data, 20);
    else if (dest.type == DEST_SCRIPT_ID) memcpy(address, dest.id.script.hash.data, 20);
    else return false;
    return true;
}

static bool db_cutover_entry_height(const struct wallet_cutover_v2_plan *plan,
                                     const struct wallet_cutover_v2_entry *entry, int *height)
{
    if (entry->new_depth < 0 || entry->new_depth > plan->reference_height + 1LL) return false;
    *height = entry->new_depth ? plan->reference_height - entry->new_depth + 1 : 0;
    return true;
}

static bool db_cutover_spender_matches(sqlite3_stmt *s, struct wallet *w,
    const struct wallet_cutover_v2_plan *plan, const struct db_wallet_utxo_cutover_projection *projection,
    const uint8_t source[32], uint32_t vout)
{
    int type = sqlite3_column_type(s, 7);
    if (type == SQLITE_NULL) return sqlite3_column_type(s, 8) == SQLITE_NULL;
    const uint8_t *id = sqlite3_column_blob(s, 7);
    if (type != SQLITE_BLOB || !id || sqlite3_column_bytes(s, 7) != 32 ||
        sqlite3_column_type(s, 8) != SQLITE_INTEGER) return false;
    sqlite3_int64 vin = sqlite3_column_int64(s, 8);
    const struct wallet_cutover_v2_entry *entry = NULL;
    const struct wallet_tx *spender = db_cutover_find_tx(w, plan, id, &entry);
    if (!spender || vin < 0 || (uint64_t)vin >= spender->tx.num_vin ||
        db_cutover_tx_class(projection, entry) != DB_CUTOVER_TX_ACTIVE) return false;
    const struct outpoint *prev = &spender->tx.vin[(size_t)vin].prevout;
    return prev->n == vout && !memcmp(prev->hash.data, source, 32);
}

static bool db_cutover_existing_fields(sqlite3_stmt *s, const struct wallet_tx *tx,
                                       const struct tx_out *out, const uint8_t address[20])
{
    const void *stored_address = sqlite3_column_blob(s, 3), *script = sqlite3_column_blob(s, 4);
    return sqlite3_column_type(s, 2) == SQLITE_INTEGER && sqlite3_column_int64(s, 2) == out->value &&
        sqlite3_column_type(s, 3) == SQLITE_BLOB && stored_address && sqlite3_column_bytes(s, 3) == 20 &&
        !memcmp(stored_address, address, 20) && sqlite3_column_type(s, 4) == SQLITE_BLOB && script &&
        sqlite3_column_bytes(s, 4) == (int)out->script_pub_key.size &&
        !memcmp(script, out->script_pub_key.data, out->script_pub_key.size) &&
        sqlite3_column_type(s, 6) == SQLITE_INTEGER &&
        sqlite3_column_int(s, 6) == (int)transaction_is_coinbase(&tx->tx);
}

static bool db_cutover_existing_row(sqlite3_stmt *s, struct wallet *w,
    const struct wallet_cutover_v2_plan *plan, const struct db_wallet_utxo_cutover_projection *projection)
{
    const uint8_t *id = sqlite3_column_blob(s, 0);
    sqlite3_int64 vout = sqlite3_column_int64(s, 1);
    if (sqlite3_column_type(s, 0) != SQLITE_BLOB || !id || sqlite3_column_bytes(s, 0) != 32 ||
        sqlite3_column_type(s, 1) != SQLITE_INTEGER || vout < 0 || vout > UINT32_MAX) return false;
    const struct wallet_cutover_v2_entry *entry = NULL;
    const struct wallet_tx *tx = db_cutover_find_tx(w, plan, id, &entry);
    if (!tx || (uint64_t)vout >= tx->tx.num_vout || db_cutover_tx_class(projection, entry) != DB_CUTOVER_TX_ACTIVE)
        return false;
    const struct tx_out *out = &tx->tx.vout[(size_t)vout];
    uint8_t address[20];
    if (!db_cutover_owned_output(w, out, address)) {
        LOG_WARN("wallet_cutover", "stored output is not spendable by the current wallet");
        return false;
    }
    if (!db_cutover_existing_fields(s, tx, out, address)) return false;
    return db_cutover_spender_matches(s, w, plan, projection, id, (uint32_t)vout);
}

static bool db_cutover_validate_existing(struct node_db *ndb, struct wallet *w,
    const struct wallet_cutover_v2_plan *plan, const struct db_wallet_utxo_cutover_projection *projection)
{
    sqlite3_stmt *s = NULL;
    const char *sql = "SELECT txid,vout,value,address_hash,script,height,is_coinbase,spent_txid,spent_vin FROM wallet_utxos";
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) != SQLITE_OK) return false;
    int rc; bool ok = true;
    while ((rc = AR_STEP_ROW_READONLY(s)) == SQLITE_ROW)
        if (!db_cutover_existing_row(s, w, plan, projection)) { ok = false; break; }
    if (rc != SQLITE_DONE) ok = false;
    sqlite3_finalize(s);
    return ok;
}

static bool db_cutover_add_output(struct node_db *ndb, struct wallet *w,
    const struct wallet_cutover_v2_plan *plan, const struct wallet_cutover_v2_entry *entry,
    const struct db_wallet_utxo_cutover_projection *projection, size_t vout)
{
    const struct wallet_tx *tx = &w->map_wallet[entry->slot];
    const struct tx_out *out = &tx->tx.vout[vout];
    uint8_t address[20];
    if (!db_cutover_owned_output(w, out, address)) return true;
    enum db_wallet_cutover_tx_class state = db_cutover_tx_class(projection, entry);
    if (state == DB_CUTOVER_TX_INACTIVE) return true;
    if (state != DB_CUTOVER_TX_ACTIVE || (transaction_is_coinbase(&tx->tx) && !entry->new_depth)) return false;
    int height;
    if (!db_cutover_entry_height(plan, entry, &height) || vout > UINT32_MAX) return false;
    struct db_wallet_utxo row = {.vout = (uint32_t)vout, .value = out->value, .height = height,
        .script = (uint8_t *)out->script_pub_key.data, .script_len = out->script_pub_key.size,
        .is_coinbase = transaction_is_coinbase(&tx->tx)};
    memcpy(row.txid, entry->txid, 32); memcpy(row.address_hash, address, 20);
    return db_wallet_utxo_cutover_merge(ndb, &row, projection->delivery) == DB_UTXO_CUTOVER_OK;
}

static bool db_cutover_add_outputs(struct node_db *ndb, struct wallet *w,
    const struct wallet_cutover_v2_plan *plan, const struct db_wallet_utxo_cutover_projection *projection)
{
    for (size_t i = 0; i < plan->count; i++) {
        const struct wallet_cutover_v2_entry *entry = &plan->entries[i];
        const struct wallet_tx *tx = &w->map_wallet[entry->slot];
        for (size_t j = 0; j < tx->tx.num_vout; j++)
            if (!db_cutover_add_output(ndb, w, plan, entry, projection, j)) return false;
    }
    return true;
}

static bool db_cutover_add_input(struct node_db *ndb, struct wallet *w,
    const struct wallet_cutover_v2_plan *plan, const struct db_wallet_utxo_cutover_projection *projection,
    const struct wallet_cutover_v2_entry *spender, size_t vin)
{
    const struct wallet_tx *tx = &w->map_wallet[spender->slot];
    const struct outpoint *prev = &tx->tx.vin[vin].prevout;
    const struct wallet_cutover_v2_entry *source_entry = NULL;
    const struct wallet_tx *source = db_cutover_find_tx(w, plan, prev->hash.data, &source_entry);
    if (!source) return true;
    if (prev->n >= source->tx.num_vout) return false;
    uint8_t address[20];
    if (!db_cutover_owned_output(w, &source->tx.vout[prev->n], address)) return true;
    enum db_wallet_cutover_tx_class state = db_cutover_tx_class(projection, spender);
    if (state == DB_CUTOVER_TX_INACTIVE) return true;
    if (state != DB_CUTOVER_TX_ACTIVE || db_cutover_tx_class(projection, source_entry) != DB_CUTOVER_TX_ACTIVE || vin > INT_MAX)
        return false;
    return db_wallet_utxo_cutover_spend(ndb, prev->hash.data, prev->n, spender->txid, (int)vin) == DB_UTXO_CUTOVER_OK;
}

static bool db_cutover_add_inputs(struct node_db *ndb, struct wallet *w,
    const struct wallet_cutover_v2_plan *plan, const struct db_wallet_utxo_cutover_projection *projection)
{
    for (size_t i = 0; i < plan->count; i++) {
        const struct wallet_cutover_v2_entry *entry = &plan->entries[i];
        const struct wallet_tx *tx = &w->map_wallet[entry->slot];
        for (size_t j = 0; j < tx->tx.num_vin; j++)
            if (!db_cutover_add_input(ndb, w, plan, projection, entry, j)) return false;
    }
    return true;
}

static bool db_cutover_collect_input(struct wallet *w, struct wallet_cutover_v2_plan *plan,
    const struct db_wallet_utxo_cutover_projection *projection,
    const struct wallet_cutover_v2_entry *spender, size_t vin)
{
    const struct wallet_tx *tx = &w->map_wallet[spender->slot];
    const struct outpoint *prev = &tx->tx.vin[vin].prevout;
    const struct wallet_cutover_v2_entry *source_entry = NULL;
    const struct wallet_tx *source = db_cutover_find_tx(w, plan, prev->hash.data, &source_entry);
    if (!source) return true;
    if (prev->n >= source->tx.num_vout) return false;
    if (!wallet_is_mine(w, &source->tx.vout[prev->n])) return true;
    enum db_wallet_cutover_tx_class state = db_cutover_tx_class(projection, spender);
    if (state == DB_CUTOVER_TX_INACTIVE) return true;
    if (state != DB_CUTOVER_TX_ACTIVE || db_cutover_tx_class(projection, source_entry) != DB_CUTOVER_TX_ACTIVE)
        return false;
    return wallet_cutover_v2_plan_mark_spent(plan, prev->hash.data, prev->n, spender->new_depth > 0);
}

static bool db_cutover_collect_spends(struct wallet *w, struct wallet_cutover_v2_plan *plan,
                                       const struct db_wallet_utxo_cutover_projection *projection)
{
    for (size_t i = 0; i < plan->count; i++) {
        const struct wallet_cutover_v2_entry *entry = &plan->entries[i];
        const struct wallet_tx *tx = &w->map_wallet[entry->slot];
        for (size_t j = 0; j < tx->tx.num_vin; j++)
            if (!db_cutover_collect_input(w, plan, projection, entry, j)) return false;
    }
    return true;
}

static enum db_cutover_coin_verdict db_cutover_coin_for_output(
    const struct db_wallet_utxo_cutover_projection *projection, const struct wallet_cutover_v2_plan *plan,
    const struct wallet_cutover_v2_entry *entry, const struct wallet_tx *tx, uint32_t vout)
{
    int height;
    if (!entry->new_depth || !db_cutover_entry_height(plan, entry, &height)) return DB_CUTOVER_COIN_UNKNOWN;
    return projection->reference_coin(projection->reference_coin_ctx, entry->txid, vout,
        &tx->tx.vout[vout], height, transaction_is_coinbase(&tx->tx));
}

static bool db_cutover_verify_reference(struct wallet *w, struct wallet_cutover_v2_plan *plan,
                                         const struct db_wallet_utxo_cutover_projection *projection)
{
    for (size_t i = 0; i < plan->count; i++) {
        const struct wallet_cutover_v2_entry *entry = &plan->entries[i];
        if (!entry->new_depth) continue;
        const struct wallet_tx *tx = &w->map_wallet[entry->slot];
        for (size_t j = 0; j < tx->tx.num_vout; j++) {
            if (!wallet_is_mine(w, &tx->tx.vout[j])) continue;
            if (j > UINT32_MAX) {
                LOG_WARN("wallet_cutover", "wallet output index exceeds the outpoint range");
                return false;
            }
            enum db_cutover_coin_verdict verdict = db_cutover_coin_for_output(projection, plan, entry, tx, (uint32_t)j);
            bool spent = wallet_cutover_v2_plan_has_spent(plan, entry->txid, (uint32_t)j, true);
            if ((verdict == DB_CUTOVER_COIN_UNSPENT && !spent) ||
                (verdict == DB_CUTOVER_COIN_SPENT && spent)) continue;
            return false;
        }
    }
    return true;
}

static bool db_cutover_validate_old_spends(struct wallet *w, struct wallet_cutover_v2_plan *plan,
                                          const struct db_wallet_utxo_cutover_projection *projection)
{
    for (size_t i = 0; i < SPENT_SET_BUCKETS; i++) {
        const struct spent_outpoint *old = &w->spent_set[i];
        if (!old->occupied || wallet_cutover_v2_plan_has_spent(plan, old->txid.data, old->vout, false)) continue;
        const struct wallet_cutover_v2_entry *entry = NULL;
        const struct wallet_tx *tx = db_cutover_find_tx(w, plan, old->txid.data, &entry);
        if (!tx || old->vout >= tx->tx.num_vout || !wallet_is_mine(w, &tx->tx.vout[old->vout]) ||
            db_cutover_coin_for_output(projection, plan, entry, tx, old->vout) != DB_CUTOVER_COIN_UNSPENT)
            return false;
    }
    return true;
}

static bool db_cutover_projection_valid(struct node_db *ndb, struct wallet *wallet,
    const struct wallet_cutover_v2_plan *plan, const struct db_wallet_utxo_cutover_projection *projection)
{
    return ndb && ndb->open && ndb->db && wallet && plan && projection &&
        projection->delivery && projection->classify_unconfirmed && projection->reference_coin &&
        sqlite3_txn_state(ndb->db, "main") == SQLITE_TXN_WRITE && ar_after_commit_depth() == 1;
}

bool db_wallet_utxo_cutover_project(void *ctx, struct node_db *ndb,
    struct wallet *wallet, struct wallet_cutover_v2_plan *plan)
{
    const struct db_wallet_utxo_cutover_projection *projection = ctx;
    if (!db_cutover_projection_valid(ndb, wallet, plan, projection)) return false;
    if (!db_cutover_collect_spends(wallet, plan, projection) ||
        !db_cutover_verify_reference(wallet, plan, projection) ||
        !db_cutover_validate_old_spends(wallet, plan, projection) ||
        !db_cutover_validate_existing(ndb, wallet, plan, projection) ||
        !db_cutover_add_outputs(ndb, wallet, plan, projection) ||
        !db_cutover_add_inputs(ndb, wallet, plan, projection)) return false;
    wallet_cutover_v2_plan_finish_spends(plan);
    return true;
}

bool db_wallet_utxo_save(struct node_db *ndb, const struct db_wallet_utxo *u)
{
    if (!ndb->open) return false;
    wallet_utxo_init_hooks();
    struct ar_callbacks *cbs = db_wallet_utxo_callbacks();
    AR_BEGIN_SAVE(cbs, "wallet_utxo", u, db_wallet_utxo_validate);

    sqlite3_stmt *s = ndb->stmt_wallet_utxo_insert;
    AR_RESET(s);
    AR_BIND_BLOB(s, 1, u->txid, 32);
    AR_BIND_INT(s, 2, (int)u->vout);
    AR_BIND_INT(s, 3, u->value);
    AR_BIND_BLOB(s, 4, u->address_hash, 20);
    AR_BIND_BLOB(s, 5, u->script, (int)u->script_len);
    AR_BIND_INT(s, 6, u->height);
    AR_BIND_INT(s, 7, u->is_coinbase ? 1 : 0);
    bool ok = AR_STEP_DONE(s);
    AR_FINISH_SAVE(cbs, u, ok);
}

bool db_wallet_utxo_mark_spent(struct node_db *ndb,
                               const uint8_t txid[32], uint32_t vout,
                               const uint8_t spent_by[32], int vin)
{
    if (!ndb->open) return false;
    sqlite3_stmt *s = ndb->stmt_wallet_utxo_spend;
    AR_RESET(s);
    AR_BIND_BLOB(s, 1, spent_by, 32);
    AR_BIND_INT(s, 2, vin);
    AR_BIND_BLOB(s, 3, txid, 32);
    AR_BIND_INT(s, 4, (int)vout);
    bool ok = AR_STEP_DONE(s);
    return ok && sqlite3_changes(ndb->db) > 0;
}

bool db_wallet_utxo_find(struct node_db *ndb,
                         const uint8_t txid[32], uint32_t vout,
                         struct db_wallet_utxo *out)
{
    if (!ndb->open) return false;
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT value,address_hash,script,height,spent_txid,spent_vin,is_coinbase"
        " FROM wallet_utxos WHERE txid=? AND vout=?",
        AR_BIND_BLOB(s, 1, txid, 32);
        AR_BIND_INT(s, 2, (int)vout),
        memset(out, 0, sizeof(*out));
        memcpy(out->txid, txid, 32);
        out->vout = vout;
        out->value = AR_COL_INT(s, 0);
        AR_READ_BLOB(s, 1, out->address_hash, 20);
        out->script_len = (size_t)AR_COL_BYTES(s, 2);
        const void *sc2 = sqlite3_column_blob(s, 2);
        if (sc2 && out->script_len > 0) {
            out->script = zcl_malloc(out->script_len, "wallet_tx utxo_find script");
            if (out->script)
                memcpy(out->script, sc2, out->script_len);
        } else {
            out->script = NULL;
        }
        out->height = (int)AR_COL_INT(s, 3);
        const void *st = sqlite3_column_blob(s, 4);
        if (st && sqlite3_column_bytes(s, 4) >= 32) {
            memcpy(out->spent_txid, st, 32);
            out->is_spent = true;
        }
        if (sqlite3_column_type(s, 5) != SQLITE_NULL)
            out->spent_vin = (int)AR_COL_INT(s, 5);
        out->is_coinbase = AR_COL_INT(s, 6) != 0);
}

int64_t db_wallet_utxo_balance(struct node_db *ndb)
{
    return db_wallet_utxo_balance_with_count(ndb, NULL);
}

int64_t db_wallet_utxo_balance_with_count(struct node_db *ndb, int *utxo_count)
{
    int64_t total = 0;
    int count = 0;

    (void)wallet_tx_query_total_and_count(ndb,
        "SELECT COALESCE(SUM(value),0), COUNT(*) "
        "FROM wallet_utxos WHERE spent_txid IS NULL",
        NULL, 0, &total, &count);
    if (utxo_count)
        *utxo_count = count;
    return total;
}

int64_t db_wallet_utxo_spendable_balance(struct node_db *ndb, int *utxo_count)
{
    sqlite3_stmt *s = NULL;
    int64_t total = 0;
    int count = 0;

    if (utxo_count)
        *utxo_count = 0;
    if (!ndb || !ndb->open)
        return 0;

    /* Coinbase outputs are spendable only once buried COINBASE_MATURITY=100
     * blocks deep. Exclude immature coinbase from the spendable total so the
     * reported balance matches what the coin-selector can actually spend (see
     * db_wallet_utxo_select_coins) and what rpc_listunspent shows. */
    int tip = db_wallet_chain_tip_height(ndb);

    sqlite3_prepare_v2(ndb->db,
        "SELECT COALESCE(SUM(value),0), COUNT(*) FROM wallet_utxos"
        " WHERE spent_txid IS NULL"
        "   AND (is_coinbase=0 OR height <= ?)",
        -1, &s, NULL);
    if (!s)
        LOG_RETURN(0, "wallet_tx", "prepare failed: %s", sqlite3_errmsg(ndb->db));
    AR_BIND_INT(s, 1, tip - 100);
    if (AR_STEP_ROW(s)) {
        total = AR_COL_INT(s, 0);
        count = (int)AR_COL_INT(s, 1);
    }
    AR_FINALIZE(s);
    if (utxo_count)
        *utxo_count = count;
    return total;
}

int db_wallet_utxo_list_unspent(struct node_db *ndb,
                                struct db_wallet_utxo *out, size_t max)
{
    if (!ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT txid,vout,value,address_hash,script,height,is_coinbase"
        " FROM wallet_utxos WHERE spent_txid IS NULL"
        " ORDER BY value DESC",
        out, max,
        (void)0,
        db_wallet_utxo_read_row(s, 0, &out[count]));
}

int db_wallet_utxo_list_all(struct node_db *ndb,
                            struct db_wallet_utxo *out, size_t max)
{
    if (!ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT txid,vout,value,address_hash,script,height,is_coinbase,"
        "spent_txid,spent_vin"
        " FROM wallet_utxos ORDER BY height ASC",
        out, max,
        (void)0,
        db_wallet_utxo_read_row(s, 0, &out[count]);
        read_utxo_spent(s, 7, &out[count]));
}

int db_wallet_utxo_select_coins(struct node_db *ndb, int64_t target,
                                int current_height,
                                struct db_wallet_utxo *out, size_t max)
{
    if (!ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "SELECT txid,vout,value,address_hash,script,height,is_coinbase"
        " FROM wallet_utxos"
        " WHERE spent_txid IS NULL"
        "   AND (is_coinbase=0 OR height <= ?)"
        " ORDER BY value DESC",
        -1, &s, NULL);
    if (!s) LOG_RETURN(0, "wallet_tx", "prepare failed: %s", sqlite3_errmsg(ndb->db));
    AR_BIND_INT(s, 1, current_height - 100);
    int count = 0;
    int64_t total = 0;
    while (AR_STEP_ROW(s) && (size_t)count < max) {
        db_wallet_utxo_read_row(s, 0, &out[count]);
        total += out[count].value;
        count++;
        if (total >= target) break;
    }
    AR_FINALIZE(s);
    return count;
}

int db_wallet_utxo_select_coins_for_address(struct node_db *ndb, int64_t target,
                                            int current_height,
                                            const uint8_t address_hash[20],
                                            struct db_wallet_utxo *out,
                                            size_t max)
{
    return db_wallet_utxo_select_coins_for_address_above(
        ndb, target, current_height, address_hash, -1, out, max);
}

int db_wallet_utxo_select_coins_for_address_above(
    struct node_db *ndb, int64_t target, int current_height,
    const uint8_t address_hash[20], int32_t floor_height,
    struct db_wallet_utxo *out, size_t max)
{
    if (!ndb->open || !address_hash) return 0;
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "SELECT txid,vout,value,address_hash,script,height,is_coinbase"
        " FROM wallet_utxos"
        " WHERE spent_txid IS NULL"
        "   AND address_hash = ?"
        "   AND (? < 0 OR height > ?)"
        "   AND (is_coinbase=0 OR height <= ?)"
        " ORDER BY value DESC",
        -1, &s, NULL);
    if (!s) LOG_RETURN(0, "wallet_tx", "prepare failed: %s", sqlite3_errmsg(ndb->db));
    AR_BIND_BLOB(s, 1, address_hash, 20);
    AR_BIND_INT(s, 2, floor_height);
    AR_BIND_INT(s, 3, floor_height);
    AR_BIND_INT(s, 4, current_height - 100);
    int count = 0;
    int64_t total = 0;
    while (AR_STEP_ROW(s) && (size_t)count < max) {
        db_wallet_utxo_read_row(s, 0, &out[count]);
        total += out[count].value;
        count++;
        if (total >= target) break;
    }
    AR_FINALIZE(s);
    return count;
}

/* Every mature coin of one address, value DESC then outpoint, so a capped
 * selection is the same on every run. Rows beyond `max` are counted, not read. */
int db_wallet_utxo_select_all_for_address(
    struct node_db *ndb, int current_height, const uint8_t address_hash[20],
    int32_t floor_height, struct db_wallet_utxo *out, size_t max,
    size_t *remaining)
{
    if (remaining)
        *remaining = 0;
    if (!ndb || !ndb->open || !address_hash || !out)
        return 0;
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "SELECT txid,vout,value,address_hash,script,height,is_coinbase"
        " FROM wallet_utxos"
        " WHERE spent_txid IS NULL"
        "   AND address_hash = ?"
        "   AND (? < 0 OR height > ?)"
        "   AND (is_coinbase=0 OR height <= ?)"
        " ORDER BY value DESC, txid, vout",
        -1, &s, NULL);
    if (!s) LOG_RETURN(-1, "wallet_tx", "prepare failed: %s", sqlite3_errmsg(ndb->db));
    AR_BIND_BLOB(s, 1, address_hash, 20);
    AR_BIND_INT(s, 2, floor_height);
    AR_BIND_INT(s, 3, floor_height);
    AR_BIND_INT(s, 4, current_height - 100);
    size_t count = 0, beyond = 0;
    bool failed = false;
    while (AR_STEP_ROW(s) && !failed) {
        if (count >= max) {
            beyond++;
            continue;
        }
        db_wallet_utxo_read_row(s, 0, &out[count]);
        failed = out[count].script_len > 0 && !out[count].script;
        if (failed)
            LOG_ERROR("wallet_tx", "select_all: script allocation failed");
        count++;
    }
    AR_FINALIZE(s);
    if (failed) {
        for (size_t i = 0; i < count; i++)
            db_wallet_utxo_free(&out[i]);
        return -1;
    }
    if (remaining)
        *remaining = beyond;
    return (int)count;
}

/* Coinbase value of one address that is not yet spendable. */
bool db_wallet_utxo_immature_for_address(struct node_db *ndb,
                                         int current_height,
                                         const uint8_t address_hash[20],
                                         int32_t floor_height, int64_t *value)
{
    if (value)
        *value = 0;
    if (!ndb || !ndb->open || !address_hash || !value)
        return false;
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "SELECT COALESCE(SUM(value),0) FROM wallet_utxos"
        " WHERE spent_txid IS NULL AND address_hash = ?"
        "   AND (? < 0 OR height > ?)"
        "   AND is_coinbase=1 AND height > ?",
        -1, &s, NULL);
    if (!s) LOG_RETURN(false, "wallet_tx", "prepare failed: %s", sqlite3_errmsg(ndb->db));
    AR_BIND_BLOB(s, 1, address_hash, 20);
    AR_BIND_INT(s, 2, floor_height);
    AR_BIND_INT(s, 3, floor_height);
    AR_BIND_INT(s, 4, current_height - 100);
    bool ok = AR_STEP_ROW(s);
    if (ok)
        *value = AR_COL_INT(s, 0);
    AR_FINALIZE(s);
    return ok;
}

/* The address with the largest mature total, ties by the lower hash. */
bool db_wallet_utxo_largest_address(struct node_db *ndb, int current_height,
                                    int32_t floor_height,
                                    uint8_t address_hash[20])
{
    if (!ndb || !ndb->open || !address_hash)
        return false;
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "SELECT address_hash FROM wallet_utxos"
        " WHERE spent_txid IS NULL"
        "   AND (? < 0 OR height > ?)"
        "   AND (is_coinbase=0 OR height <= ?)"
        " GROUP BY address_hash ORDER BY SUM(value) DESC, address_hash"
        " LIMIT 1",
        -1, &s, NULL);
    if (!s) LOG_RETURN(false, "wallet_tx", "prepare failed: %s", sqlite3_errmsg(ndb->db));
    AR_BIND_INT(s, 1, floor_height);
    AR_BIND_INT(s, 2, floor_height);
    AR_BIND_INT(s, 3, current_height - 100);
    bool found = AR_STEP_ROW(s) && sqlite3_column_bytes(s, 0) == 20;
    if (found)
        AR_READ_BLOB(s, 0, address_hash, 20);
    AR_FINALIZE(s);
    return found;
}

bool db_wallet_utxo_delete(struct node_db *ndb,
                            const uint8_t txid[32], uint32_t vout)
{
    if (!ndb->open) return false;

    struct ar_callbacks *cbs = db_wallet_utxo_callbacks();
    struct db_wallet_utxo u;
    memset(&u, 0, sizeof(u));
    memcpy(u.txid, txid, 32);
    u.vout = vout;
    AR_BEGIN_DESTROY(cbs, &u);

    sqlite3_stmt *s = NULL;
    AR_PREPARE_BOOL(ndb, s, "DELETE FROM wallet_utxos WHERE txid=? AND vout=?");
    AR_BIND_BLOB(s, 1, txid, 32);
    AR_BIND_INT(s, 2, (int)vout);
    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    ok = ok && sqlite3_changes(ndb->db) > 0;
    AR_FINISH_DESTROY(cbs, &u, ok);
}

bool db_wallet_utxo_release_spent_by(struct node_db *ndb,
                                     const uint8_t spent_by[32])
{
    if (!ndb || !ndb->open || !spent_by)
        return false;
    for (;;) {
        sqlite3_stmt *s = NULL;
        struct db_wallet_utxo row;
        AR_PREPARE_BOOL(ndb, s,
            "SELECT txid,vout,value,address_hash,script,height,is_coinbase,"
            "spent_txid,spent_vin FROM wallet_utxos"
            " WHERE spent_txid=? LIMIT 1");
        AR_BIND_BLOB(s, 1, spent_by, 32);
        if (!AR_STEP_ROW(s)) {
            AR_FINALIZE(s);
            return true;
        }
        db_wallet_utxo_read_row(s, 0, &row);
        read_utxo_spent(s, 7, &row);
        AR_FINALIZE(s);
        row.is_spent = false;
        memset(row.spent_txid, 0, sizeof(row.spent_txid));
        row.spent_vin = 0;
        bool ok = db_wallet_utxo_save(ndb, &row);
        db_wallet_utxo_free(&row);
        if (!ok)
            return false;
    }
}

int db_wallet_utxo_count_for_tx(struct node_db *ndb,
                                 const uint8_t txid[32])
{
    if (!ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_COUNT_BOUND(ndb, s,
        "SELECT COUNT(*) FROM wallet_utxos WHERE txid=?",
        AR_BIND_BLOB(s, 1, txid, 32));
}

bool db_wallet_utxo_delete_all(struct node_db *ndb)
{
    if (!ndb->open) return false;
    return node_db_exec(ndb, "DELETE FROM wallet_utxos");
}

bool db_wallet_utxo_replace_all(struct node_db *ndb,
                                const struct db_wallet_utxo *rows,
                                size_t count)
{
    size_t i = 0;
    bool ok = true;

    if (!ndb || !ndb->open)
        return false;
    if (count > 0 && !rows)
        return false;

    ok = node_db_begin(ndb);
    ok = ok && db_wallet_utxo_delete_all(ndb);
    for (i = 0; ok && i < count; i++)
        ok = db_wallet_utxo_save(ndb, &rows[i]);
    if (!ok) {
        node_db_rollback(ndb);
        return false;
    }
    return node_db_commit(ndb);
}

bool db_wallet_tx_delete_all(struct node_db *ndb)
{
    if (!ndb->open) return false;
    return node_db_exec(ndb, "DELETE FROM wallet_transactions");
}

/* SaplingNote CRUD lives in sapling_note.c */

/* ── Relationships ─────────────────────────────────────────────── */

/* WalletTx has_many :wallet_utxos */
int db_wallet_tx_utxos(struct node_db *ndb, const uint8_t txid[32],
                        struct db_wallet_utxo *out, size_t max)
{
    if (!ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "SELECT txid,vout,value,address_hash,script,height,is_coinbase,"
        "spent_txid,spent_vin"
        " FROM wallet_utxos WHERE txid=? ORDER BY vout",
        -1, &s, NULL);
    if (!s)
        LOG_RETURN(0, "wallet_tx", "prepare failed: %s", sqlite3_errmsg(ndb->db));
    AR_BIND_BLOB(s, 1, txid, 32);
    int count = 0;
    while (AR_STEP_ROW(s) && (size_t)count < max) {
        db_wallet_utxo_read_row(s, 0, &out[count]);
        read_utxo_spent(s, 7, &out[count]);
        count++;
    }
    AR_FINALIZE(s);
    return count;
}

/* WalletTx has_many :sapling_notes */
int db_wallet_tx_notes(struct node_db *ndb, const uint8_t txid[32],
                        struct db_sapling_note *out, size_t max)
{
    if (!ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "SELECT txid,output_index,value,rcm,memo,ivk,diversifier,pk_d,"
        "cm,nullifier,block_height,source,spent_txid"
        " FROM wallet_sapling_notes WHERE txid=? ORDER BY output_index",
        -1, &s, NULL);
    if (!s)
        LOG_RETURN(0, "wallet_tx", "prepare failed: %s", sqlite3_errmsg(ndb->db));
    AR_BIND_BLOB(s, 1, txid, 32);
    int count = 0;
    while (AR_STEP_ROW(s) && (size_t)count < max) {
        db_sapling_note_read_row(s, 0, &out[count]);
        wallet_tx_read_spent_txid(s, 12, &out[count]);
        count++;
    }
    AR_FINALIZE(s);
    return count;
}

/* WalletUTXO belongs_to :wallet_key */
bool db_wallet_utxo_key(struct node_db *ndb, const struct db_wallet_utxo *u,
                        struct db_wallet_key *out)
{
    return db_wallet_key_find(ndb, u->address_hash, out);
}

/* SaplingNote belongs_to :sapling_key — lives in sapling_note.c */
