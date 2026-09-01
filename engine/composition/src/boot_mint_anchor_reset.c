/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Reset every derived store before a fresh offline anchor mint. */

#include "config/boot_internal.h"

#include "jobs/reducer_frontier.h"
#include "jobs/stage_repair_internal.h"
#include "jobs/utxo_apply_stage.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
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

bool boot_mint_anchor_genesis_reset(struct node_db *ndb)
{
    sqlite3 *rpdb = progress_store_db();
    if (!rpdb) {
        fprintf(stderr, "[boot] -refold-staged: progress store not open; skip\n");
        return false;
    }

    /* Neutralize imported authority before resetting every derived surface. */
    bool phase1_ok = utxo_recovery_clear_cold_import_seed_checked(ndb) &&
        node_db_state_set(ndb, "leveldb_utxo_migrated", NULL, 0);
    phase1_ok = phase1_ok && coins_kv_reset_for_reseed(rpdb) &&
        boot_index_clear_coins_state(ndb) &&
        clear_legacy_header_admit_mirror(ndb) &&
        node_db_state_set(ndb, "sapling_tree", NULL, 0) &&
        node_db_state_set(ndb, "sapling_tree_rescan_height", NULL, 0);
    if (!phase1_ok) {
        LOG_WARN("boot", "-mint-anchor genesis reset phase 1 failed");
        return false;
    }

    static const char *const k_refold_tables[] = {
        "validate_headers_log", "body_fetch_log", "body_persist_log",
        "script_validate_log", "proof_validate_log", "utxo_apply_log",
        "tip_finalize_log", "utxo_apply_delta", "created_outputs",
    };
    static const char *const k_refold_stages[] = {
        "header_admit", "validate_headers", "body_fetch", "body_persist",
        "script_validate", "proof_validate", "utxo_apply", "tip_finalize",
    };
    bool refold_ok = true;
    char *refold_err = NULL;
    progress_store_tx_lock();
    if (sqlite3_exec(rpdb, "BEGIN IMMEDIATE", NULL, NULL, &refold_err)
        != SQLITE_OK)
        refold_ok = false;
    for (size_t i = 0;
         refold_ok && i < sizeof(k_refold_tables) / sizeof(k_refold_tables[0]);
         i++) {
        char dsql[96];
        snprintf(dsql, sizeof dsql, "DELETE FROM %s", k_refold_tables[i]);
        if (sqlite3_exec(rpdb, dsql, NULL, NULL, &refold_err) != SQLITE_OK) {
            if (refold_err && strstr(refold_err, "no such table")) {
                sqlite3_free(refold_err);
                refold_err = NULL;
            } else {
                refold_ok = false;
            }
        }
    }
    for (size_t i = 0;
         refold_ok && i < sizeof(k_refold_stages) / sizeof(k_refold_stages[0]);
         i++)
        if (!stage_repair_force_stage_cursor(rpdb, k_refold_stages[i], 0))
            refold_ok = false;
    if (refold_ok && !utxo_apply_frontier_set_in_tx(rpdb, 0))
        refold_ok = false;
    if (refold_ok && (!anchor_kv_reset_mark_complete_in_tx(rpdb) ||
                      !nullifier_kv_reset_mark_complete_in_tx(rpdb)))
        refold_ok = false;
    if (refold_ok) {
        refold_ok = progress_meta_delete_in_tx(
                        rpdb, REDUCER_TRUSTED_BASE_HEIGHT_KEY) &&
                    progress_meta_delete_in_tx(
                        rpdb, REDUCER_TRUSTED_BASE_HASH_KEY);
    }
    if (refold_ok && sqlite3_exec(rpdb, "COMMIT", NULL, NULL, &refold_err)
        != SQLITE_OK)
        refold_ok = false;
    if (!refold_ok)
        sqlite3_exec(rpdb, "ROLLBACK", NULL, NULL, NULL);
    if (refold_err)
        sqlite3_free(refold_err);
    progress_store_tx_unlock();

    fprintf(stderr,
            "[boot] -refold-staged: staged reducer reset to genesis %s; "
            "the staged pipeline re-folds forward over on-disk bodies "
            "(H* climbs as the logs fill)\n",
            refold_ok ? "OK" : "FAILED");
    return refold_ok;
}
