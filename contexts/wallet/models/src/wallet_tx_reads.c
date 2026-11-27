/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * WalletTx read-model helpers.
 *
 * Read-only aggregate and activity queries over wallet_transactions and
 * wallet_utxos. Row lifecycle and validation live in wallet_tx.c; these helpers
 * do not persist records.
 *
 * ar-validate-skip:read-only-wallet-aggregates
 */

#include "models/wallet_tx.h"
#include "models/wallet_tx_internal.h"
#include "util/log_macros.h"
#include "util/ar_step_readonly.h"
#include "util/safe_alloc.h"
#include "core/amount.h"
#include <limits.h>
#include <stdlib.h>

#include <string.h>

enum db_wallet_tx_presence wallet_tx_find_checked(struct node_db *ndb,
    const uint8_t txid[32], struct db_wallet_tx *out)
{
    if (!ndb || !ndb->open || !txid || !out) return DB_WALLET_TX_ERROR;
    sqlite3_stmt *s = NULL;
    const char *sql = "SELECT txid,raw_tx,block_hash,block_height,time_received,from_me,fee"
                      " FROM wallet_transactions WHERE txid=?";
    struct db_wallet_tx row = {0};
    enum db_wallet_tx_presence result = DB_WALLET_TX_ERROR;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) == SQLITE_OK &&
        sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC) == SQLITE_OK) {
        int rc = AR_STEP_ROW_READONLY(s);
        if (rc == SQLITE_DONE) result = DB_WALLET_TX_ABSENT;
        else if (rc == SQLITE_ROW && db_wallet_tx_read_row(s, 0, &row))
            result = DB_WALLET_TX_PRESENT;
    }
    if (sqlite3_finalize(s) != SQLITE_OK) result = DB_WALLET_TX_ERROR;
    if (result == DB_WALLET_TX_PRESENT) *out = row;
    else db_wallet_tx_free(&row);
    return result;
}

bool db_wallet_tx_find(struct node_db *ndb, const uint8_t txid[32],
                       struct db_wallet_tx *out)
{
    return wallet_tx_find_checked(ndb, txid, out) == DB_WALLET_TX_PRESENT;
}

static bool wallet_tx_read_balance(sqlite3_stmt *stmt, int64_t *total, int *count)
{
    if (ar_step_checked(stmt, "wallet balance", NULL) != ZCL_STEP_ROW ||
        sqlite3_column_type(stmt, 0) != SQLITE_INTEGER) return false;
    *total = sqlite3_column_int64(stmt, 0);
    if (count) {
        int64_t n = sqlite3_column_int64(stmt, 1);
        if (sqlite3_column_type(stmt, 1) != SQLITE_INTEGER || n < 0 || n > INT_MAX) return false;
        *count = (int)n;
    }
    return *total >= 0 && ar_step_checked(stmt, "wallet balance end", NULL) == ZCL_STEP_DONE;
}

/* Owns stmt and publishes only a complete nonnegative aggregate. */
bool wallet_tx_finish_balance(sqlite3_stmt *stmt, bool bound, int64_t *total_out, int *count_out)
{
    int64_t total = -1;
    int count = -1;
    bool ok = stmt && bound && wallet_tx_read_balance(stmt, &total, count_out ? &count : NULL);
    if (stmt && sqlite3_finalize(stmt) != SQLITE_OK) ok = false;
    if (total_out) *total_out = ok ? total : -1;
    if (count_out) *count_out = ok ? count : -1;
    return ok;
}

bool wallet_tx_query_total_and_count(struct node_db *ndb, const char *sql,
                                     const void *bind_blob, size_t bind_blob_len,
                                     int64_t *total_out, int *count_out)
{
    if (total_out) *total_out = -1;
    if (count_out) *count_out = -1;
    if (!ndb || !ndb->open || !ndb->db || !sql || bind_blob_len > INT_MAX ||
        (bind_blob_len > 0 && !bind_blob)) return false;
    sqlite3_stmt *s = NULL;
    bool ok = sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) == SQLITE_OK;
    if (ok && bind_blob && bind_blob_len > 0)
        ok = sqlite3_bind_blob(s, 1, bind_blob, (int)bind_blob_len, SQLITE_STATIC) == SQLITE_OK;
    return wallet_tx_finish_balance(s, ok, total_out, count_out);
}

static int db_wallet_query_max_height(struct node_db *ndb, const char *sql)
{
    if (!ndb || !ndb->open || !ndb->db || !sql) return -1;
    sqlite3_stmt *s = NULL;
    bool ok = sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) == SQLITE_OK;
    int height = 0;
    if (ok) ok = ar_step_checked(s, "wallet tip", NULL) == ZCL_STEP_ROW;
    if (ok && sqlite3_column_type(s, 0) != SQLITE_NULL) {
        int64_t h = sqlite3_column_int64(s, 0);
        ok = sqlite3_column_type(s, 0) == SQLITE_INTEGER && h >= 0 && h <= INT_MAX;
        if (ok) height = (int)h;
    }
    if (ok) ok = ar_step_checked(s, "wallet tip end", NULL) == ZCL_STEP_DONE;
    if (s && sqlite3_finalize(s) != SQLITE_OK) ok = false;
    return ok ? height : -1;
}

int64_t db_wallet_tx_total_fees(struct node_db *ndb, int *fee_paying_count)
{
    if (fee_paying_count) *fee_paying_count = 0;
    if (!ndb || !ndb->open)
        return 0;
    sqlite3_stmt *s = NULL;
    int64_t total = 0;
    int count = 0;
    AR_PREPARE_RET(ndb, s,
        "SELECT fee FROM wallet_transactions WHERE from_me = 1 AND fee > 0",
        0);
    while (AR_STEP_ROW(s)) {
        total += AR_COL_INT(s, 0);
        count++;
    }
    AR_FINALIZE(s);
    if (fee_paying_count) *fee_paying_count = count;
    return total;
}

int db_wallet_utxo_recent_activity(struct node_db *ndb,
                                   struct db_wallet_activity *out, size_t max)
{
    if (!ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT wu.value, wu.height, COALESCE(b.time,0)"
        " FROM wallet_utxos wu"
        " LEFT JOIN blocks b ON b.height=wu.height"
        " WHERE wu.spent_txid IS NULL"
        " ORDER BY wu.height DESC LIMIT ?",
        out, max,
        AR_BIND_INT(s, 1, (int)max),
        out[count].value = AR_COL_INT(s, 0);
        out[count].height = (int)AR_COL_INT(s, 1);
        out[count].time = AR_COL_INT(s, 2));
}

/* Chain-tip and wallet-summary readers for controllers/services. */
int db_wallet_chain_tip_height(struct node_db *ndb)
{
    return db_wallet_query_max_height(ndb, "SELECT MAX(height) FROM blocks");
}

static int wallet_effective_tip_from_chain(struct node_db *ndb, int chain_tip)
{
    if (chain_tip < 0) return -1;
    int utxo_tip = db_wallet_query_max_height(ndb,
        "SELECT MAX(height) FROM wallet_utxos WHERE spent_txid IS NULL");
    if (utxo_tip < 0) return -1;
    return utxo_tip > chain_tip ? utxo_tip : chain_tip;
}

int db_wallet_effective_tip_height(struct node_db *ndb)
{
    return wallet_effective_tip_from_chain(ndb, db_wallet_chain_tip_height(ndb));
}

static bool wallet_projection_summary_collect(struct node_db *ndb, void *ctx)
{
    struct db_wallet_projection_summary *value = ctx;
    value->chain_tip_height = db_wallet_chain_tip_height(ndb);
    value->effective_tip_height = wallet_effective_tip_from_chain(ndb, value->chain_tip_height);
    value->transparent_balance = db_wallet_utxo_balance_with_count(ndb, &value->utxo_count);
    value->shielded_balance = db_sapling_note_balance_with_count(ndb, &value->note_count);
    if (value->chain_tip_height < 0 || value->effective_tip_height < 0 ||
        value->transparent_balance < 0 || value->shielded_balance < 0) return false;
    value->speed_balance = value->transparent_balance;
    return true;
}

bool db_wallet_projection_summary(struct node_db *ndb,
                                  struct db_wallet_projection_summary *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    struct db_wallet_projection_summary value = {0};
    if (!wallet_db_read_snapshot(ndb, wallet_projection_summary_collect, &value)) return false;
    *out = value;
    return true;
}
struct wallet_utxo_snapshot_row {
    struct db_wallet_utxo row;
    struct wallet_utxo_snapshot_row *next;
};

struct wallet_utxo_snapshot {
    struct wallet_utxo_snapshot_row *head, *tail;
    size_t bytes, limit;
};

static bool wallet_utxo_valid_blobs(sqlite3_stmt *s)
{
    if (sqlite3_column_type(s, 0) != SQLITE_BLOB ||
        sqlite3_column_bytes(s, 0) != 32 || !sqlite3_column_blob(s, 0))
        return false;
    int type = sqlite3_column_type(s, 3);
    if (type != SQLITE_NULL &&
        (type != SQLITE_BLOB || sqlite3_column_bytes(s, 3) != 20 || !sqlite3_column_blob(s, 3)))
        return false;
    return sqlite3_column_type(s, 4) == SQLITE_BLOB;
}

static bool wallet_utxo_valid_numbers(sqlite3_stmt *s)
{
    if (sqlite3_column_type(s, 1) != SQLITE_INTEGER ||
        sqlite3_column_int64(s, 1) < 0 || sqlite3_column_int64(s, 1) > UINT32_MAX ||
        sqlite3_column_type(s, 2) != SQLITE_INTEGER || !MoneyRange(sqlite3_column_int64(s, 2)))
        return false;
    if (sqlite3_column_type(s, 5) != SQLITE_INTEGER ||
        sqlite3_column_int64(s, 5) < 0 || sqlite3_column_int64(s, 5) > INT_MAX ||
        sqlite3_column_type(s, 6) != SQLITE_INTEGER ||
        sqlite3_column_int64(s, 6) < 0 || sqlite3_column_int64(s, 6) > 1)
        return false;
    return true;
}

static void wallet_utxo_snapshot_free(struct wallet_utxo_snapshot *snapshot)
{
    struct wallet_utxo_snapshot_row *item = snapshot->head;
    while (item) {
        struct wallet_utxo_snapshot_row *next = item->next;
        db_wallet_utxo_free(&item->row);
        free(item);
        item = next;
    }
    snapshot->head = snapshot->tail = NULL;
}

static enum db_wallet_utxo_iter_result wallet_utxo_snapshot_add(
    struct wallet_utxo_snapshot *snapshot, sqlite3_stmt *s)
{
    if (!wallet_utxo_valid_blobs(s) || !wallet_utxo_valid_numbers(s) ||
        sqlite3_errcode(sqlite3_db_handle(s)) == SQLITE_NOMEM) {
        LOG_WARN("wallet_tx", "unspent iterator: invalid or unreadable row");
        return DB_WALLET_UTXO_ITER_READ_ERROR;
    }
    size_t script_len = (size_t)sqlite3_column_bytes(s, 4);
    if (sqlite3_errcode(sqlite3_db_handle(s)) == SQLITE_NOMEM)
        return DB_WALLET_UTXO_ITER_RESOURCE;
    if (snapshot->bytes > snapshot->limit || sizeof(struct wallet_utxo_snapshot_row) > snapshot->limit - snapshot->bytes ||
        script_len > snapshot->limit - snapshot->bytes - sizeof(struct wallet_utxo_snapshot_row))
        return DB_WALLET_UTXO_ITER_RESOURCE;
    struct wallet_utxo_snapshot_row *item = zcl_malloc(sizeof(*item), "wallet utxo snapshot row");
    if (!item) return DB_WALLET_UTXO_ITER_RESOURCE;
    db_wallet_utxo_read_row(s, 0, &item->row);
    item->next = NULL;
    if ((item->row.script_len && !item->row.script) || sqlite3_errcode(sqlite3_db_handle(s)) == SQLITE_NOMEM) {
        db_wallet_utxo_free(&item->row);
        free(item);
        return DB_WALLET_UTXO_ITER_RESOURCE;
    }
    if (snapshot->tail) snapshot->tail->next = item; else snapshot->head = item;
    snapshot->tail = item;
    snapshot->bytes += sizeof(*item) + script_len;
    return DB_WALLET_UTXO_ITER_OK;
}

static enum db_wallet_utxo_iter_result wallet_utxo_snapshot_read(
    sqlite3 *db, struct wallet_utxo_snapshot *snapshot)
{
    sqlite3_stmt *s = NULL;
    enum db_wallet_utxo_iter_result result = DB_WALLET_UTXO_ITER_READ_ERROR;
    if (sqlite3_prepare_v2(db,
            "SELECT txid,vout,value,address_hash,script,height,is_coinbase"
            " FROM wallet_utxos WHERE spent_txid IS NULL ORDER BY value DESC",
            -1, &s, NULL) != SQLITE_OK || !s) {
        LOG_WARN("wallet_tx", "unspent iterator: prepare failed: %s", sqlite3_errmsg(db));
        goto done;
    }
    for (;;) {
        enum zcl_step step = ar_step_checked(s, "wallet unspent iterator", NULL);
        if (step == ZCL_STEP_DONE) { result = DB_WALLET_UTXO_ITER_OK; break; }
        if (step == ZCL_STEP_ERROR) { result = DB_WALLET_UTXO_ITER_READ_ERROR; break; }
        result = wallet_utxo_snapshot_add(snapshot, s);
        if (result != DB_WALLET_UTXO_ITER_OK) break;
    }
done:
    if (s && sqlite3_finalize(s) != SQLITE_OK) {
        LOG_WARN("wallet_tx", "unspent iterator: finalize failed: %s", sqlite3_errmsg(db));
        result = DB_WALLET_UTXO_ITER_READ_ERROR;
    }
    return result;
}

enum db_wallet_utxo_iter_result db_wallet_utxo_each_unspent(
    struct node_db *ndb, size_t scratch_limit,
    bool (*visit)(struct db_wallet_utxo *, void *), void *ctx)
{
    if (!ndb || !ndb->open || !ndb->db || !visit) {
        LOG_WARN("wallet_tx", "unspent iterator: missing database or visitor");
        return DB_WALLET_UTXO_ITER_READ_ERROR;
    }
    sqlite3_mutex *mu = sqlite3_db_mutex(ndb->db);
    if (!mu) {
        LOG_WARN("wallet_tx", "unspent iterator: database mutex unavailable");
        return DB_WALLET_UTXO_ITER_READ_ERROR;
    }
    struct wallet_utxo_snapshot snapshot = {.limit = scratch_limit};
    sqlite3_mutex_enter(mu);
    enum db_wallet_utxo_iter_result result = DB_WALLET_UTXO_ITER_READ_ERROR;
    if (sqlite3_get_autocommit(ndb->db))
        result = wallet_utxo_snapshot_read(ndb->db, &snapshot);
    else
        LOG_WARN("wallet_tx", "unspent iterator: connection has an active transaction");
    sqlite3_mutex_leave(mu);
    for (struct wallet_utxo_snapshot_row *item = snapshot.head;
         result == DB_WALLET_UTXO_ITER_OK && item; item = item->next) {
        struct db_wallet_utxo row = item->row;
        if (!visit(&row, ctx)) result = DB_WALLET_UTXO_ITER_VISITOR_ERROR;
    }
    wallet_utxo_snapshot_free(&snapshot);
    return result;
}
