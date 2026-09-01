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
#include "encoding/utilstrencodings.h"
#include "models/wallet_tx.h"
#include "models/wallet_tx_internal.h"
#include "models/block.h"
#include "models/wallet_key.h"
#include "wallet/sapling_keys.h"
#include "chain/chainparams.h"
#include "event/event.h"
#include "storage/wallet_projection.h"
#include "util/safe_alloc.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

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
    char txid_hex[65];
    HexStr(t->txid, 32, false, txid_hex, sizeof(txid_hex));
    const char *category = t->from_me ? "send" : "receive";
    event_emitf(EV_WALLET_TX_SAVED, 0,
                "txid=%s category=%s", txid_hex, category);
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
        LOG_FAIL("wallet_utxo", "before_save REJECTED: value %lld out of range",
                 (long long)u->value);
    }
    return true;
}

/* after_save: emit model-specific event */
static void wallet_utxo_after_save(void *record, void *ctx)
{
    (void)ctx;
    const struct db_wallet_utxo *u = record;
    event_emitf(EV_WALLET_UTXO_SAVED, 0, "vout=%u value=%lld",
                u->vout, (long long)u->value);
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
    if (!ndb->open || !address_hash) return 0;
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "SELECT txid,vout,value,address_hash,script,height,is_coinbase"
        " FROM wallet_utxos"
        " WHERE spent_txid IS NULL"
        "   AND address_hash = ?"
        "   AND (is_coinbase=0 OR height <= ?)"
        " ORDER BY value DESC",
        -1, &s, NULL);
    if (!s) LOG_RETURN(0, "wallet_tx", "prepare failed: %s", sqlite3_errmsg(ndb->db));
    AR_BIND_BLOB(s, 1, address_hash, 20);
    AR_BIND_INT(s, 2, current_height - 100);
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
