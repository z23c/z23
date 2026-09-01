/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shared error capture and statement reset for wallet SQLite. */

#include "wallet_sqlite_internal.h"
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

void wallet_sqlite_reset_all_statements(struct wallet_sqlite *ws)
{
    if (!ws)
        return;
    if (ws->stmt_key_write) sqlite3_reset(ws->stmt_key_write);
    if (ws->stmt_key_read) sqlite3_reset(ws->stmt_key_read);
    if (ws->stmt_key_read_one) sqlite3_reset(ws->stmt_key_read_one);
    if (ws->stmt_key_delete) sqlite3_reset(ws->stmt_key_delete);
    if (ws->stmt_keypool_write) sqlite3_reset(ws->stmt_keypool_write);
    if (ws->stmt_keypool_read) sqlite3_reset(ws->stmt_keypool_read);
    if (ws->stmt_keypool_clear) sqlite3_reset(ws->stmt_keypool_clear);
    if (ws->stmt_tx_write) sqlite3_reset(ws->stmt_tx_write);
    if (ws->stmt_tx_read) sqlite3_reset(ws->stmt_tx_read);
    if (ws->stmt_seed_write) sqlite3_reset(ws->stmt_seed_write);
    if (ws->stmt_seed_read) sqlite3_reset(ws->stmt_seed_read);
    if (ws->stmt_zkey_write) sqlite3_reset(ws->stmt_zkey_write);
    if (ws->stmt_zkey_read) sqlite3_reset(ws->stmt_zkey_read);
    if (ws->stmt_script_write) sqlite3_reset(ws->stmt_script_write);
    if (ws->stmt_script_read) sqlite3_reset(ws->stmt_script_read);
    if (ws->stmt_watch_write) sqlite3_reset(ws->stmt_watch_write);
    if (ws->stmt_watch_read) sqlite3_reset(ws->stmt_watch_read);
    if (ws->stmt_best_block_write) sqlite3_reset(ws->stmt_best_block_write);
    if (ws->stmt_best_block_read) sqlite3_reset(ws->stmt_best_block_read);
    if (ws->stmt_scan_height_write) sqlite3_reset(ws->stmt_scan_height_write);
    if (ws->stmt_scan_height_read) sqlite3_reset(ws->stmt_scan_height_read);
}
