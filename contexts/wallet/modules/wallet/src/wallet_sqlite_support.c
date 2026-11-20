/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shared error capture and statement reset for wallet SQLite. */

#include "wallet_sqlite_internal.h"
#include "util/ar_step_readonly.h"
#include <string.h>

struct zcl_result wsql_fail(struct wallet_sqlite *ws, struct zcl_result r)
{
    if (ws && !r.ok) {
        size_t n = sizeof(ws->last_error) - 1;
        strncpy(ws->last_error, r.message, n);
        ws->last_error[n] = '\0';
    }
    return r;
}

static void wsql_reset_statement(sqlite3_stmt *stmt)
{
    if (stmt)
        sqlite3_reset(stmt);
}

void wallet_sqlite_reset_all_statements(struct wallet_sqlite *ws)
{
    if (!ws)
        return;
    wsql_reset_statement(ws->stmt_key_write);
    wsql_reset_statement(ws->stmt_key_read);
    wsql_reset_statement(ws->stmt_key_read_one);
    wsql_reset_statement(ws->stmt_key_delete);
    wsql_reset_statement(ws->stmt_keypool_write);
    wsql_reset_statement(ws->stmt_keypool_read);
    wsql_reset_statement(ws->stmt_keypool_clear);
    wsql_reset_statement(ws->stmt_tx_write);
    wsql_reset_statement(ws->stmt_tx_read);
    wsql_reset_statement(ws->stmt_seed_write);
    wsql_reset_statement(ws->stmt_seed_read);
    wsql_reset_statement(ws->stmt_zkey_write);
    wsql_reset_statement(ws->stmt_zkey_read);
    wsql_reset_statement(ws->stmt_script_write);
    wsql_reset_statement(ws->stmt_script_read);
    wsql_reset_statement(ws->stmt_watch_write);
    wsql_reset_statement(ws->stmt_watch_read);
    wsql_reset_statement(ws->stmt_best_block_write);
    wsql_reset_statement(ws->stmt_best_block_read);
    wsql_reset_statement(ws->stmt_scan_height_write);
    wsql_reset_statement(ws->stmt_scan_height_read);
}

struct zcl_result wallet_sqlite_key_count_r(struct wallet_sqlite *ws, int64_t *count)
{
    if (!ws || !count) return ZCL_ERR(WSQL_NULL_ARG, "wallet key count: missing argument");
    if (!ws->open || !ws->db) return wsql_fail(ws, ZCL_ERR(WSQL_DB_NOT_OPEN, "wallet key count: database not open"));
    sqlite3 *db = ws->db;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT count(*) FROM wallet_keys", -1, &stmt, NULL) != SQLITE_OK)
        return wsql_fail(ws, ZCL_ERR(WSQL_READ_FAIL, "wallet key count unavailable"));
    bool ok = ar_step_checked(stmt, "wallet key count", NULL) == ZCL_STEP_ROW &&
              sqlite3_column_type(stmt, 0) == SQLITE_INTEGER;
    int64_t n = ok ? sqlite3_column_int64(stmt, 0) : -1;
    if (ok) ok = n >= 0 && ar_step_checked(stmt, "wallet key count completion", NULL) == ZCL_STEP_DONE;
    if (sqlite3_finalize(stmt) != SQLITE_OK || !ok)
        return wsql_fail(ws, ZCL_ERR(WSQL_READ_FAIL, "wallet key count unavailable"));
    *count = n;
    return ZCL_OK;
}
