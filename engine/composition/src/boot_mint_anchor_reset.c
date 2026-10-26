/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Reset every derived store before a fresh offline anchor mint. */

#include "config/boot_internal.h"

#include "jobs/reducer_frontier.h"
#include "jobs/stage_repair_internal.h"
#include "jobs/utxo_apply_stage.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/shielded_pool_kv.h"
#include "storage/progress_store.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

/* Declared by the UTXO recovery service's private contract. */
bool utxo_recovery_clear_cold_import_seed_checked(struct node_db *ndb);

/* The node.db header_admit_log is a legacy mirror (see boot_refold_staged.c);
 * a fresh producer datadir never creates it, so a missing table is already
 * reset. An existing table that fails to clear still fails closed. */
static bool clear_legacy_header_admit_mirror(struct node_db *ndb)
{
    sqlite3_stmt *stmt = NULL;
    if (!node_db_prepare_readonly_query(ndb,
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='header_admit_log'", &stmt)) {
        LOG_WARN("boot",
            "-mint-anchor: legacy header_admit_log mirror probe failed");
        return false;
    }
    int rc = AR_STEP_ROW_READONLY(stmt);
    sqlite3_finalize(stmt);
    if (rc == SQLITE_DONE)
        return true;
    if (rc != SQLITE_ROW) {
        LOG_WARN("boot",
            "-mint-anchor: legacy header_admit_log mirror probe rc=%d", rc);
        return false;
    }
    return node_db_exec(ndb, "DELETE FROM header_admit_log");
}

/* Anchor, nullifier and pool-totals history reset to COMPLETE in the open
 * refold transaction; the three always move together. */
static bool mint_reset_shielded_history_in_tx(sqlite3 *db)
{
    return anchor_kv_reset_mark_complete_in_tx(db) &&
           nullifier_kv_reset_mark_complete_in_tx(db) &&
           shielded_pool_kv_reset_in_tx(db);
}

/* Phase 1 of the genesis reset: neutralize imported authority, then clear
 * every coins and anchor surface derived from it, in one short-circuit
 * chain so the first failure skips everything after it. */
static bool mint_reset_neutralize_imported_authority(struct node_db *ndb,
                                                     sqlite3 *rpdb)
{
    bool ok = utxo_recovery_clear_cold_import_seed_checked(ndb) &&
        node_db_state_set(ndb, "leveldb_utxo_migrated", NULL, 0);
    ok = ok && coins_kv_reset_for_reseed(rpdb) &&
        boot_index_clear_coins_state(ndb) &&
        clear_legacy_header_admit_mirror(ndb) &&
        node_db_state_set(ndb, "sapling_tree", NULL, 0) &&
        node_db_state_set(ndb, "sapling_tree_rescan_height", NULL, 0);
    return ok;
}

/* Delete every fold log inside the open refold transaction; a missing table
 * on a fresh datadir already counts as cleared, while any other failure
 * stops the sweep with *err_out left set for the caller to free. */
static bool refold_tx_clear_fold_logs(sqlite3 *rpdb, bool ok, char **err_out)
{
    static const char *const k_refold_tables[] = {
        "validate_headers_log", "body_fetch_log", "body_persist_log",
        "script_validate_log", "proof_validate_log", "utxo_apply_log",
        "tip_finalize_log", "utxo_apply_delta", "created_outputs",
    };
    for (size_t i = 0;
         ok && i < sizeof(k_refold_tables) / sizeof(k_refold_tables[0]);
         i++) {
        char dsql[96];
        snprintf(dsql, sizeof dsql, "DELETE FROM %s", k_refold_tables[i]);
        if (sqlite3_exec(rpdb, dsql, NULL, NULL, err_out) != SQLITE_OK) {
            if (*err_out && strstr(*err_out, "no such table")) {
                sqlite3_free(*err_out);
                *err_out = NULL;
            } else {
                ok = false;
            }
        }
    }
    return ok;
}

/* Park every staged-pipeline cursor at height 0 inside the open refold
 * transaction so the reducer re-folds forward from genesis. */
static bool refold_tx_force_stage_cursors(sqlite3 *rpdb, bool ok)
{
    static const char *const k_refold_stages[] = {
        "header_admit", "validate_headers", "body_fetch", "body_persist",
        "script_validate", "proof_validate", "utxo_apply", "tip_finalize",
    };
    for (size_t i = 0;
         ok && i < sizeof(k_refold_stages) / sizeof(k_refold_stages[0]);
         i++)
        ok = stage_repair_force_stage_cursor(rpdb, k_refold_stages[i], 0);
    return ok;
}

/* Frontier, shielded history and trusted-base metadata always reset together
 * inside the open refold transaction. */
static bool refold_tx_reset_derived_state(sqlite3 *rpdb)
{
    return utxo_apply_frontier_set_in_tx(rpdb, 0) &&
           mint_reset_shielded_history_in_tx(rpdb) &&
           progress_meta_delete_in_tx(rpdb, REDUCER_TRUSTED_BASE_HEIGHT_KEY) &&
           progress_meta_delete_in_tx(rpdb, REDUCER_TRUSTED_BASE_HASH_KEY);
}

/* Run the staged-reducer reset as one transaction: clear the fold logs and
 * stage cursors, reset the derived state, then commit or roll back. */
static bool refold_tx_reset_reducer_to_genesis(sqlite3 *rpdb)
{
    bool refold_ok = true;
    char *refold_err = NULL;
    progress_store_tx_lock();
    if (sqlite3_exec(rpdb, "BEGIN IMMEDIATE", NULL, NULL, &refold_err)
        != SQLITE_OK)
        refold_ok = false;
    refold_ok = refold_tx_clear_fold_logs(rpdb, refold_ok, &refold_err);
    refold_ok = refold_tx_force_stage_cursors(rpdb, refold_ok);
    refold_ok = refold_ok && refold_tx_reset_derived_state(rpdb);
    if (refold_ok && sqlite3_exec(rpdb, "COMMIT", NULL, NULL, &refold_err)
        != SQLITE_OK)
        refold_ok = false;
    if (!refold_ok)
        sqlite3_exec(rpdb, "ROLLBACK", NULL, NULL, NULL);
    if (refold_err)
        sqlite3_free(refold_err);
    progress_store_tx_unlock();
    return refold_ok;
}

bool boot_mint_anchor_genesis_reset(struct node_db *ndb)
{
    sqlite3 *rpdb = progress_store_db();
    if (!rpdb) {
        fprintf(stderr, "[boot] -refold-staged: progress store not open; skip\n");
        return false;
    }

    /* Neutralize imported authority before resetting every derived surface. */
    if (!mint_reset_neutralize_imported_authority(ndb, rpdb)) {
        LOG_WARN("boot", "-mint-anchor genesis reset phase 1 failed");
        return false;
    }

    bool refold_ok = refold_tx_reset_reducer_to_genesis(rpdb);

    fprintf(stderr,
            "[boot] -refold-staged: staged reducer reset to genesis %s; "
            "the staged pipeline re-folds forward over on-disk bodies "
            "(H* climbs as the logs fill)\n",
            refold_ok ? "OK" : "FAILED");
    return refold_ok;
}
