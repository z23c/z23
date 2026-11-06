/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Boot-time rebuild of an empty wallet_utxos table.
 *
 * Part of the boot composition root (engine/composition/src/), extracted from
 * boot_services.c. The utxos table nominates the rows that belong to a wallet
 * key; the coins database decides which of them become wallet rows. A row is
 * inserted only when its coin exists and its amount and script match, and it
 * takes its height and coinbase flag from the coin. Any other row is skipped
 * and counted. With no coins view nothing is inserted. */

#include "config/boot_internal.h"
#include "controllers/wallet_row_coins.h"
#include "util/ar_step_readonly.h"
#include <sqlite3.h>
#include <stdio.h>

struct wallet_rebuild_tally {
    int inserted;
    int skipped;
    bool failed;
};

static void wallet_rebuild_insert_row(sqlite3_stmt *ins, sqlite3_stmt *sel,
                                      const struct wallet_row_coin *coin,
                                      struct wallet_rebuild_tally *t)
{
    sqlite3_reset(ins);
    sqlite3_bind_blob(ins, 1, sqlite3_column_blob(sel, 0), 32, SQLITE_STATIC);
    sqlite3_bind_int(ins, 2, sqlite3_column_int(sel, 1));
    sqlite3_bind_int64(ins, 3, sqlite3_column_int64(sel, 2));
    sqlite3_bind_blob(ins, 4, sqlite3_column_blob(sel, 3), 20, SQLITE_STATIC);
    sqlite3_bind_blob(ins, 5, sqlite3_column_blob(sel, 4),
                      sqlite3_column_bytes(sel, 4), SQLITE_STATIC);
    sqlite3_bind_int(ins, 6, coin->height);
    sqlite3_bind_int(ins, 7, coin->is_coinbase ? 1 : 0);
    if (AR_STEP_WRITE(ins) != SQLITE_DONE)
        t->failed = true;
    else
        t->inserted++;
}

static void wallet_rebuild_candidate(sqlite3_stmt *ins, sqlite3_stmt *sel,
                                     struct coins_view_cache *coins,
                                     struct wallet_rebuild_tally *t)
{
    const void *txid = sqlite3_column_blob(sel, 0);
    const void *script = sqlite3_column_blob(sel, 4);
    struct wallet_row_coin coin;
    if (!txid || sqlite3_column_bytes(sel, 0) != 32 ||
        sqlite3_column_bytes(sel, 3) != 20 ||
        wallet_row_check_coin(coins, txid,
                              (uint32_t)sqlite3_column_int(sel, 1),
                              sqlite3_column_int64(sel, 2), script,
                              (size_t)sqlite3_column_bytes(sel, 4),
                              &coin) != WALLET_ROW_AGREES)
        t->skipped++;
    else
        wallet_rebuild_insert_row(ins, sel, &coin, t);
}

static bool wallet_rebuild_run(sqlite3 *db, struct coins_view_cache *coins,
                               struct wallet_rebuild_tally *t)
{
    sqlite3_stmt *sel = NULL;
    sqlite3_stmt *ins = NULL;
    bool ok = sqlite3_prepare_v2(db,
        "SELECT u.txid, u.vout, u.value, u.address_hash, u.script "
        "FROM utxos u INNER JOIN wallet_keys wk "
        "ON u.address_hash = wk.pubkey_hash", -1, &sel, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(db,
        "INSERT OR IGNORE INTO wallet_utxos "
        "(txid, vout, value, address_hash, script, height, is_coinbase) "
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)", -1, &ins, NULL) == SQLITE_OK;
    while (ok && !t->failed && AR_STEP_ROW_READONLY(sel) == SQLITE_ROW)
        wallet_rebuild_candidate(ins, sel, coins, t);
    ok = ok && !t->failed;
    sqlite3_finalize(sel);
    sqlite3_finalize(ins);
    return ok;
}

int boot_wallet_rebuild_confirmed(struct node_db *ndb,
                                  struct coins_view_cache *coins,
                                  int *skipped)
{
    struct wallet_rebuild_tally t = {0};
    if (skipped)
        *skipped = 0;
    if (!ndb || !ndb->db)
        return -1;
    if (!coins) {
        fprintf(stderr, "wallet_utxos: rebuild withheld because the coins "
                "database is unavailable\n");
        return -1;
    }
    if (sqlite3_exec(ndb->db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) {
        fprintf(stderr, "wallet_utxos: BEGIN failed: %s\n",
                sqlite3_errmsg(ndb->db));
        return -1;
    }
    bool ok = wallet_rebuild_run(ndb->db, coins, &t);
    if (ok && sqlite3_exec(ndb->db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        fprintf(stderr, "wallet_utxos: COMMIT failed: %s\n",
                sqlite3_errmsg(ndb->db));
        ok = false;
    }
    if (!ok) {
        fprintf(stderr, "wallet_utxos: rebuild failed: %s\n",
                sqlite3_errmsg(ndb->db));
        if (sqlite3_exec(ndb->db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
            fprintf(stderr, "wallet_utxos: ROLLBACK failed: %s\n",
                    sqlite3_errmsg(ndb->db));
        return -1;
    }
    if (skipped)
        *skipped = t.skipped;
    return t.inserted;
}
