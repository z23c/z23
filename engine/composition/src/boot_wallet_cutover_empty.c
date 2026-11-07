/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Checked shielded-empty proof for wallet cutover startup and publication. */
#include "boot_wallet_cutover_empty_internal.h"
#include "wallet/wallet.h"
#include "wallet/wallet_sqlite.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

static bool bce_no_shielded_rows(sqlite3 *db)
{
    static const char query[] =
        "SELECT EXISTS(SELECT 1 FROM wallet_sapling_keys),"
        "EXISTS(SELECT 1 FROM wallet_sapling_notes),"
        "EXISTS(SELECT 1 FROM wallet_seed)";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK || !stmt) {
        LOG_WARN("wallet", "shielded-empty proof query could not be prepared");
        if (stmt) sqlite3_finalize(stmt);
        return false;
    }
    enum zcl_step step = ar_step_checked(stmt, "shielded-empty proof", NULL);
    bool empty = step == ZCL_STEP_ROW;
    for (int i = 0; empty && i < 3; ++i)
        empty = sqlite3_column_type(stmt, i) == SQLITE_INTEGER && sqlite3_column_int(stmt, i) == 0;
    if (empty) empty = ar_step_checked(stmt, "shielded-empty proof completion", NULL) == ZCL_STEP_DONE;
    return sqlite3_finalize(stmt) == SQLITE_OK && empty;
}

bool boot_wallet_cutover_shielded_empty_locked(struct wallet_sqlite *ws,
    sqlite3 *db, const struct wallet *wallet, bool sapling_load_ok)
{
    if (!sapling_load_ok || !ws || !ws->open || !db || ws->db != db || !wallet)
        return false;
    const struct sapling_keystore *keys = &wallet->sapling_keys;
    if (keys->has_seed || keys->locked || keys->num_keys ||
        keys->num_damaged || keys->num_unscannable) return false;
    return bce_no_shielded_rows(db);
}
