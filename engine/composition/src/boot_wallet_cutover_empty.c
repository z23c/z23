/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Checked shielded-empty proof for wallet cutover startup and publication. */
#include "boot_wallet_cutover_empty_internal.h"
#include "wallet/wallet.h"
#include "wallet/wallet_sqlite.h"
#include "wallet/wallet_lock.h"
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

static bool boot_wallet_notes_empty_inputs(struct wallet_sqlite *ws,
    sqlite3 *db, const struct wallet *wallet, bool sapling_load_ok)
{
    return sapling_load_ok && ws && ws->open && db && ws->db == db && !sqlite3_get_autocommit(db) && wallet &&
        !wallet->num_sapling_notes && wallet->sapling_notes_cap <= MAX_SAPLING_NOTES &&
        (!wallet->sapling_notes_cap || wallet->sapling_notes);
}

bool boot_wallet_cutover_notes_empty_locked(struct wallet_sqlite *ws,
    sqlite3 *db, const struct wallet *wallet, bool sapling_load_ok)
{
    if (!boot_wallet_notes_empty_inputs(ws, db, wallet, sapling_load_ok)) return false;
    for (size_t i = 0; i < wallet->sapling_notes_cap; ++i)
        if (wallet->sapling_notes[i].used) return false;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT EXISTS(SELECT 1 FROM wallet_sapling_notes)", -1, &stmt, NULL) != SQLITE_OK || !stmt) {
        if (stmt) sqlite3_finalize(stmt);
        return false;
    }
    bool empty = ar_step_checked(stmt, "wallet notes empty proof", NULL) == ZCL_STEP_ROW &&
        sqlite3_column_type(stmt, 0) == SQLITE_INTEGER && sqlite3_column_int(stmt, 0) == 0 &&
        ar_step_checked(stmt, "wallet notes empty proof completion", NULL) == ZCL_STEP_DONE;
    return sqlite3_finalize(stmt) == SQLITE_OK && empty;
}

static bool bce_no_wallet_rows(sqlite3 *db)
{
    static const char query[] =
        "SELECT EXISTS(SELECT 1 FROM wallet_keys), EXISTS(SELECT 1 FROM wallet_keypool),"
        "EXISTS(SELECT 1 FROM wallet_key_encryption), EXISTS(SELECT 1 FROM wallet_scripts),"
        "EXISTS(SELECT 1 FROM wallet_watch_only), EXISTS(SELECT 1 FROM wallet_transactions),"
        "EXISTS(SELECT 1 FROM wallet_utxos), EXISTS(SELECT 1 FROM wallet_sapling_diversifier)";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK || !stmt) {
        if (stmt) sqlite3_finalize(stmt);
        return false;
    }
    bool empty = ar_step_checked(stmt, "wallet-empty proof", NULL) == ZCL_STEP_ROW;
    for (int i = 0; empty && i < 8; ++i)
        empty = sqlite3_column_type(stmt, i) == SQLITE_INTEGER && sqlite3_column_int(stmt, i) == 0;
    if (empty) empty = ar_step_checked(stmt, "wallet-empty proof completion", NULL) == ZCL_STEP_DONE;
    return sqlite3_finalize(stmt) == SQLITE_OK && empty;
}

static bool bce_transparent_slots_empty(const struct wallet *wallet)
{
    for (size_t i = 0; i < MAX_KEYSTORE_KEYS; ++i) if (wallet->keystore.keys[i].used) return false;
    for (size_t i = 0; i < MAX_KEYSTORE_WATCHING; ++i) if (wallet->keystore.watching[i].used) return false;
    for (size_t i = 0; i < MAX_KEYSTORE_SCRIPTS; ++i) if (wallet->keystore.scripts[i].used) return false;
    return true;
}

static bool bce_wallet_counts_empty(const struct wallet *wallet)
{
    return !wallet->has_master_key && !wallet->num_wallet_tx && !wallet->key_pool_size &&
        !wallet->num_spent && !wallet->num_sapling_notes && !wallet->keystore.num_keys &&
        !wallet->keystore.num_watching && !wallet->keystore.num_scripts &&
        wallet->sapling_notes_cap <= MAX_SAPLING_NOTES &&
        (!wallet->sapling_notes_cap || wallet->sapling_notes);
}

static bool bce_wallet_memory_empty(const struct wallet *wallet)
{
    if (!bce_wallet_counts_empty(wallet)) return false;
    for (size_t i = 0; i < MAX_WALLET_TX; ++i) if (wallet->map_wallet[i].used) return false;
    for (size_t i = 0; i < MAX_KEY_POOL; ++i) if (wallet->key_pool[i].persisted) return false;
    for (size_t i = 0; i < SPENT_SET_BUCKETS; ++i) if (wallet->spent_set[i].occupied) return false;
    if (!bce_transparent_slots_empty(wallet)) return false;
    for (size_t i = 0; i < MAX_SAPLING_KEYS; ++i) if (wallet->sapling_keys.keys[i].used) return false;
    for (size_t i = 0; i < wallet->sapling_notes_cap; ++i) if (wallet->sapling_notes[i].used) return false;
    return true;
}

bool boot_wallet_cutover_full_empty_locked(struct wallet_sqlite *ws,
    sqlite3 *db, const struct wallet *wallet, bool sapling_load_ok)
{
    return !wallet_lock_is_locked() &&
        boot_wallet_cutover_shielded_empty_locked(ws, db, wallet, sapling_load_ok) &&
        bce_wallet_memory_empty(wallet) && bce_no_wallet_rows(db);
}

static bool bce_no_transparent_rows(sqlite3 *db)
{
    static const char query[] =
        "SELECT EXISTS(SELECT 1 FROM wallet_keys), EXISTS(SELECT 1 FROM wallet_keypool),"
        "EXISTS(SELECT 1 FROM wallet_scripts), EXISTS(SELECT 1 FROM wallet_watch_only),"
        "EXISTS(SELECT 1 FROM wallet_transactions), EXISTS(SELECT 1 FROM wallet_utxos)";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK || !stmt) {
        if (stmt) sqlite3_finalize(stmt);
        return false;
    }
    bool empty = ar_step_checked(stmt, "transparent-empty proof", NULL) == ZCL_STEP_ROW;
    for (int i = 0; empty && i < 6; ++i)
        empty = sqlite3_column_type(stmt, i) == SQLITE_INTEGER && sqlite3_column_int(stmt, i) == 0;
    if (empty) empty = ar_step_checked(stmt, "transparent-empty proof completion", NULL) == ZCL_STEP_DONE;
    return sqlite3_finalize(stmt) == SQLITE_OK && empty;
}

static bool bce_transparent_memory_empty(const struct wallet *wallet)
{
    if (wallet->num_wallet_tx || wallet->key_pool_size ||
        wallet->num_spent || wallet->keystore.num_keys || wallet->keystore.num_watching ||
        wallet->keystore.num_scripts) return false;
    for (size_t i = 0; i < MAX_WALLET_TX; ++i) if (wallet->map_wallet[i].used) return false;
    for (size_t i = 0; i < MAX_KEY_POOL; ++i) if (wallet->key_pool[i].persisted) return false;
    for (size_t i = 0; i < SPENT_SET_BUCKETS; ++i) if (wallet->spent_set[i].occupied) return false;
    return bce_transparent_slots_empty(wallet);
}

bool boot_wallet_cutover_transparent_empty_locked(struct wallet_sqlite *ws,
    sqlite3 *db, const struct wallet *wallet)
{
    return ws && ws->open && db && ws->db == db && wallet && !wallet_lock_is_locked() &&
        bce_transparent_memory_empty(wallet) && bce_no_transparent_rows(db);
}
