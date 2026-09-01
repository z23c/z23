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

#include <string.h>

/* Shared read-only aggregate primitive for wallet model siblings. */
bool wallet_tx_query_total_and_count(struct node_db *ndb,
                                     const char *sql,
                                     const void *bind_blob,
                                     size_t bind_blob_len,
                                     int64_t *total_out,
                                     int *count_out)
{
    sqlite3_stmt *s = NULL;
    int64_t total = 0;
    int count = 0;

    if (!ndb || !ndb->open || !sql)
        return false;
    sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL);
    if (!s)
        LOG_FAIL("wallet_tx", "prepare failed: %s", sqlite3_errmsg(ndb->db));
    if (bind_blob && bind_blob_len > 0)
        AR_BIND_BLOB(s, 1, bind_blob, (int)bind_blob_len);
    if (AR_STEP_ROW(s)) {
        total = AR_COL_INT(s, 0);
        count = (int)AR_COL_INT(s, 1);
    }
    AR_FINALIZE(s);
    if (total_out)
        *total_out = total;
    if (count_out)
        *count_out = count;
    return true;
}

static int db_wallet_query_max_height(struct node_db *ndb, const char *sql)
{
    sqlite3_stmt *s = NULL;
    int height = 0;

    if (!ndb || !ndb->open || !sql)
        return 0;
    sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL);
    if (!s)
        LOG_RETURN(0, "wallet_tx", "prepare failed: %s", sqlite3_errmsg(ndb->db));
    if (AR_STEP_ROW(s) && sqlite3_column_type(s, 0) != SQLITE_NULL)
        height = (int)AR_COL_INT(s, 0);
    AR_FINALIZE(s);
    return height;
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

int db_wallet_effective_tip_height(struct node_db *ndb)
{
    int chain_tip = db_wallet_chain_tip_height(ndb);
    int utxo_tip = db_wallet_query_max_height(ndb,
        "SELECT MAX(height) FROM wallet_utxos WHERE spent_txid IS NULL");
    return utxo_tip > chain_tip ? utxo_tip : chain_tip;
}

bool db_wallet_projection_summary(struct node_db *ndb,
                                  struct db_wallet_projection_summary *out)
{
    if (!ndb || !ndb->open || !out)
        return false;
    memset(out, 0, sizeof(*out));
    out->chain_tip_height = db_wallet_chain_tip_height(ndb);
    out->effective_tip_height = db_wallet_effective_tip_height(ndb);
    out->transparent_balance = db_wallet_utxo_balance_with_count(ndb,
        &out->utxo_count);
    out->shielded_balance = db_sapling_note_balance_with_count(ndb,
        &out->note_count);
    out->speed_balance = out->transparent_balance;
    return true;
}
