/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * node.db UTXO lifecycle + performance modes: IBD turbo / normal mode,
 * index drop/rebuild, UTXO wiping, counting, and WAL checkpoint control.
 *
 * ar-validate-skip:connection-handle-not-a-row
 *   These functions operate on the struct node_db connection handle and
 *   the UTXO table at the bulk-lifecycle level (wipe/count, index
 *   drop/rebuild, PRAGMA modes) — not on row records. Row-level
 *   validation lives on the models that use this handle (same rationale
 *   as database.c). */

#include "util/log_macros.h"
#include "models/database.h"
#include "models/database_lifetime.h"
#include "models/database_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── UTXO Lifecycle ────────────────────────────────────────────── */

bool node_db_wipe_utxos(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return false;
    int64_t existing = node_db_utxo_count(ndb);
    const char *offline_repair = getenv("ZCL_OFFLINE_REPAIR");
    if (existing > 1000 &&
        (!offline_repair || strcmp(offline_repair, "1") != 0)) {
        LOG_INFO("db", "db: refused to wipe %lld UTXOs without " "ZCL_OFFLINE_REPAIR=1", (long long)existing);
        return false;
    }
    bool ok = true;
    ok &= node_db_exec(ndb, "DELETE FROM utxos");
    ok &= node_db_exec(ndb, "DELETE FROM node_state WHERE key='coins_best_block'");
    ok &= node_db_exec(ndb, "DELETE FROM node_state WHERE key='utxo_commitment'");
    if (ok)
        printf("db: wiped UTXO set + coins state\n");
    return ok;
}

int64_t node_db_utxo_count(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return 0;
    sqlite3_stmt *stmt = NULL;
    int64_t count = 0;
    if (sqlite3_prepare_v2(ndb->db, "SELECT count(*) FROM utxos",
                           -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW)  // raw-sql-ok:read-only-introspection
            count = sqlite3_column_int64(stmt, 0);
        sqlite3_finalize(stmt);
    }
    return count;
}

/* ── Performance Modes ─────────────────────────────────────────── */

/* Secondary indexes dropped during IBD for throughput, rebuilt after. */
static const char *const DB_DROP_INDEXES[] = {
    "DROP INDEX IF EXISTS idx_utxo_address",
    "DROP INDEX IF EXISTS idx_utxo_value",
    "DROP INDEX IF EXISTS idx_utxo_height",
    "DROP INDEX IF EXISTS idx_utxo_height_value",
    "DROP INDEX IF EXISTS idx_tx_block",
    "DROP INDEX IF EXISTS idx_tx_height",
    /* Explorer projection secondary indexes — deferred during the bulk
     * per-block reindex (PKs stay to enforce idempotent overwrite). */
    "DROP INDEX IF EXISTS idx_txo_addr",
    "DROP INDEX IF EXISTS idx_txo_height",
    "DROP INDEX IF EXISTS idx_txo_hodl_scan",
    "DROP INDEX IF EXISTS idx_txi_prev",
    "DROP INDEX IF EXISTS idx_txi_prev_height",
    "DROP INDEX IF EXISTS idx_txi_height",
    "DROP INDEX IF EXISTS idx_ss_nf",
    "DROP INDEX IF EXISTS idx_ss_height",
    "DROP INDEX IF EXISTS idx_so_height",
    "DROP INDEX IF EXISTS idx_js_height",
    "DROP INDEX IF EXISTS idx_spnf_height",
    "DROP INDEX IF EXISTS idx_opret_height",
    "DROP INDEX IF EXISTS idx_opret_slp",
};
static const char *const DB_CREATE_INDEXES[] = {
    "CREATE INDEX IF NOT EXISTS idx_utxo_address"
        " ON utxos(address_hash) WHERE address_hash IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS idx_utxo_value"
        " ON utxos(value DESC)",
    "CREATE INDEX IF NOT EXISTS idx_utxo_height"
        " ON utxos(height)",
    "CREATE INDEX IF NOT EXISTS idx_utxo_height_value"
        " ON utxos(height, value)",
    "CREATE INDEX IF NOT EXISTS idx_tx_block"
        " ON transactions(block_hash)",
    "CREATE INDEX IF NOT EXISTS idx_tx_height"
        " ON transactions(block_height)",
    /* Explorer projection secondary indexes (mirror database_migrate.c v9). */
    "CREATE INDEX IF NOT EXISTS idx_txo_addr"
        " ON tx_outputs(address_hash) WHERE address_hash IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS idx_txo_height"
        " ON tx_outputs(block_height)",
    "CREATE INDEX IF NOT EXISTS idx_txo_hodl_scan"
        " ON tx_outputs(block_height, value, txid, vout)",
    "CREATE INDEX IF NOT EXISTS idx_txi_prev"
        " ON tx_inputs(prev_txid, prev_vout)",
    "CREATE INDEX IF NOT EXISTS idx_txi_prev_height"
        " ON tx_inputs(prev_txid, prev_vout, block_height)",
    "CREATE INDEX IF NOT EXISTS idx_txi_height"
        " ON tx_inputs(block_height)",
    "CREATE INDEX IF NOT EXISTS idx_ss_nf"
        " ON sapling_spends(nullifier)",
    "CREATE INDEX IF NOT EXISTS idx_ss_height"
        " ON sapling_spends(block_height)",
    "CREATE INDEX IF NOT EXISTS idx_so_height"
        " ON sapling_outputs(block_height)",
    "CREATE INDEX IF NOT EXISTS idx_js_height"
        " ON joinsplits(block_height)",
    "CREATE INDEX IF NOT EXISTS idx_spnf_height"
        " ON sprout_nullifiers(block_height)",
    "CREATE INDEX IF NOT EXISTS idx_opret_height"
        " ON op_returns(block_height)",
    "CREATE INDEX IF NOT EXISTS idx_opret_slp"
        " ON op_returns(is_slp) WHERE is_slp = 1",
};
#define NUM_DB_INDEXES (sizeof(DB_DROP_INDEXES) / sizeof(DB_DROP_INDEXES[0]))

bool node_db_drop_indexes(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return false;
    bool all_ok = true;
    for (size_t i = 0; i < NUM_DB_INDEXES; i++) {
        if (db_exec_checked(ndb->db, DB_DROP_INDEXES[i],
                            "drop_indexes") != SQLITE_OK)
            all_ok = false;
    }
    return all_ok;
}

bool node_db_rebuild_indexes(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return false;
    bool all_ok = true;
    for (size_t i = 0; i < NUM_DB_INDEXES; i++) {
        if (db_exec_checked(ndb->db, DB_CREATE_INDEXES[i],
                            "rebuild_indexes") != SQLITE_OK)
            all_ok = false;
    }
    return all_ok;
}

bool node_db_ibd_turbo_mode(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return false;
    /* Turbo-mode PRAGMAs are performance optimisations, not integrity
     * invariants — if any of them fail, fall back to the safe
     * defaults and carry on.  The previous silent path left the DB in
     * a partial-turbo state (e.g. synchronous=OFF succeeded but the WAL
     * bound did not, so the WAL grew unbounded). */
    /* Bulk sync checkpoints RARELY, never NEVER. `wal_autocheckpoint=0` — what
     * this used to set — removes the bound entirely, and because bulk mode is
     * entered on every sync of more than 50,000 blocks and only left by
     * node_db_normal_mode() at the END of that sync, a process that dies
     * mid-sync spends its whole life with no bound at all. That is how single
     * runs reached 51-115 GB of WAL against a 10 GB database. The loose bound
     * below keeps the checkpoint rare enough to be cheap and the file bounded
     * enough to survive a slow disk, and journal_size_limit is what actually
     * returns the .wal file's blocks to the filesystem afterwards. */
    static const char *const turbo_pragmas[] = {
        "PRAGMA synchronous=OFF",
        "PRAGMA cache_size=-524288",
        "PRAGMA wal_autocheckpoint="
            ZCL_NODE_DB_PRAGMA_NUM(ZCL_NODE_DB_WAL_AUTOCKPT_PAGES_BULK),
        "PRAGMA journal_size_limit="
            ZCL_NODE_DB_PRAGMA_NUM(ZCL_NODE_DB_JOURNAL_SIZE_LIMIT_BULK),
        NULL,
    };
    bool turbo_ok = true;
    for (int i = 0; turbo_pragmas[i]; i++) {
        if (db_exec_checked(ndb->db, turbo_pragmas[i],
                            "ibd_turbo_mode pragma") != SQLITE_OK)
            turbo_ok = false;
    }
    sqlite3_busy_timeout(ndb->db, 10000);

    if (!turbo_ok) {
        LOG_WARN("db", "[db] ibd_turbo_mode: one or more PRAGMAs failed; " "falling back to safe defaults (IBD will be slower " "but correct)");
        db_exec_checked(ndb->db, "PRAGMA synchronous=NORMAL",
                        "turbo_fallback synchronous");
        db_exec_checked(ndb->db, "PRAGMA cache_size=-65536",
                        "turbo_fallback cache_size");
        db_exec_checked(ndb->db, "PRAGMA wal_autocheckpoint="
                        ZCL_NODE_DB_PRAGMA_NUM(ZCL_NODE_DB_WAL_AUTOCKPT_PAGES),
                        "turbo_fallback wal_autocheckpoint");
        db_exec_checked(ndb->db, "PRAGMA journal_size_limit="
                        ZCL_NODE_DB_PRAGMA_NUM(ZCL_NODE_DB_JOURNAL_SIZE_LIMIT),
                        "turbo_fallback journal_size_limit");
        node_db_note_turbo_mode(ndb, false, "ibd_turbo_mode_fallback",
                                SQLITE_ERROR);
        return false;
    }

    node_db_drop_indexes(ndb);
    node_db_note_turbo_mode(ndb, true, "ibd_turbo_mode", SQLITE_OK);
    printf("db: IBD turbo mode (synchronous=OFF, indexes dropped)\n");
    return true;
}

bool node_db_normal_mode(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return false;
    db_exec_checked(ndb->db, "PRAGMA synchronous=NORMAL",
                    "normal_mode synchronous");
    db_exec_checked(ndb->db, "PRAGMA cache_size=-65536",
                    "normal_mode cache_size");
    db_exec_checked(ndb->db, "PRAGMA wal_autocheckpoint="
                    ZCL_NODE_DB_PRAGMA_NUM(ZCL_NODE_DB_WAL_AUTOCKPT_PAGES),
                    "normal_mode wal_autocheckpoint");
    /* Cap the WAL FILE size after checkpoint. wal_autocheckpoint is PASSIVE: it
     * folds WAL pages into the db but leaves the .wal file at its high-water
     * mark, so one write burst can leave a large file sitting for the entire
     * life of a days-long node (a slow disk-fill the disk_full condition cannot
     * reclaim). journal_size_limit truncates the .wal back to the cap after each
     * checkpoint, bounding disk at the source — no reclaim thread, no deleting a
     * live WAL out from under an open handle. 64 MiB is generous headroom over
     * the ~4 MiB autocheckpoint trigger; it only caps pathological bursts. */
    db_exec_checked(ndb->db, "PRAGMA journal_size_limit="
                    ZCL_NODE_DB_PRAGMA_NUM(ZCL_NODE_DB_JOURNAL_SIZE_LIMIT),
                    "normal_mode journal_size_limit");
    node_db_rebuild_indexes(ndb);
    node_db_wal_checkpoint(ndb);
    node_db_note_turbo_mode(ndb, false, "normal_mode", SQLITE_OK);
    printf("db: normal mode (synchronous=NORMAL, indexes rebuilt)\n");
    return true;
}

bool node_db_wal_checkpoint_result(struct node_db *ndb,
                                   struct wal_ckpt_record *out)
{
    sqlite3_stmt *stmt = NULL;
    bool is_wal = false;

    /* Give `out` a definite meaning on every exit, including the two early
     * ones. A caller that reads a record this function never touched would be
     * reading the last checkpoint's numbers as if they were this one's. */
    if (out) {
        static const struct wal_ckpt_record unattempted = {
            .outcome = WAL_CKPT_UNKNOWN, .rc = 0,
            .log_frames = -1, .ckpt_frames = -1, .source = "node_db",
        };
        *out = unattempted;
    }

    if (!ndb || !ndb->open) return false;
    struct db_lifetime_scope lifetime_scope;
    db_lifetime_scope_enter(
        &lifetime_scope, "node_db.checkpoint",
        ndb->lifetime_backing_owner ? DB_LIFETIME_BACKING_OWNER
                                    : DB_LIFETIME_HANDLE_OWNER,
        ndb->lifetime_generation);
    if (sqlite3_prepare_v2(ndb->db, "PRAGMA journal_mode", -1, &stmt, NULL) == SQLITE_OK &&
        stmt && sqlite3_step(stmt) == SQLITE_ROW) {  // raw-sql-ok:read-only-introspection
        /* sqlite3_column_text points INTO the stmt; it is freed by
         * sqlite3_finalize below. Capture the comparison while the stmt is
         * still live — reading `mode` after finalize is a use-after-free. */
        const char *mode = (const char *)sqlite3_column_text(stmt, 0);
        is_wal = (mode && strcmp(mode, "wal") == 0);
    }
    if (stmt)
        sqlite3_finalize(stmt);
    if (!is_wal) {
        /* Not a WAL database (an in-memory or rollback-journal handle): there
         * is no write-ahead log to reclaim, so this is exempt, not drained.
         * Nothing is recorded — counting it would dilute the ratios an
         * operator reads off a real WAL connection. */
        if (out)
            out->outcome = WAL_CKPT_DRAINED;
        node_db_note_activity(ndb, "wal_checkpoint", SQLITE_OK);
        db_lifetime_scope_leave(&lifetime_scope);
        return true;
    }
    /* Two checkpoint calls, in this order, and the order is the whole point.
     *
     * PASSIVE FIRST, because it is the only one that reports what happened.
     * pnLog/pnCkpt come back from TRUNCATE as 0/0 on success no matter how
     * much work it did — truncation resets the log, so the "after" numbers
     * are always zero — which means a TRUNCATE can tell you it succeeded but
     * never how much it reclaimed. PASSIVE reports the real pair: frames in
     * the log, and frames folded into the database. So PASSIVE is what
     * classifies the outcome, and it is also the call that does the actual
     * work of moving frames. It never blocks on another connection.
     *
     * TRUNCATE SECOND, purely to return the .wal file's blocks to the
     * filesystem. By then the frames are already folded, so a busy TRUNCATE
     * costs nothing but a still-large file — which journal_size_limit caps
     * anyway at the next autocheckpoint. That is why its result is NOT an
     * error here and NOT the verdict: the reclamation already happened or
     * already failed one call earlier, and reporting the file-reset step's
     * lock race as the checkpoint's outcome is what used to make a busy
     * multi-connection node.db look like a checkpoint failure.
     *
     * Passing NULL for both counts — what this function used to do — collapses
     * "folded the whole log away" and "moved zero frames because a reader is
     * parked on the oldest one" into one indistinguishable SQLITE_OK. That is
     * how a WAL 9.2 times the size of its database stayed invisible. */
    int log_frames = -1, ckpt_frames = -1;
    int passive_rc = sqlite3_wal_checkpoint_v2(ndb->db, NULL,
                                                SQLITE_CHECKPOINT_PASSIVE,
                                                &log_frames, &ckpt_frames);
    int truncate_rc = -1;
    if (passive_rc == SQLITE_OK)
        truncate_rc = sqlite3_wal_checkpoint_v2(ndb->db, NULL,
                                                 SQLITE_CHECKPOINT_TRUNCATE,
                                                 NULL, NULL);
    bool truncate_hard_failure =
        truncate_rc != -1 && truncate_rc != SQLITE_OK &&
        truncate_rc != SQLITE_BUSY && truncate_rc != SQLITE_LOCKED;
    int rc = truncate_hard_failure ? truncate_rc : passive_rc;
    if (truncate_hard_failure)
        LOG_ERROR("db",
                  "[db] wal file reset failed after PASSIVE checkpoint: "
                  "truncate_rc=%d wal_frames=%d moved=%d",
                  truncate_rc, log_frames, ckpt_frames);

    struct wal_ckpt_record rec = {
        .outcome = wal_ckpt_classify(rc == SQLITE_OK,
                                     rc == SQLITE_BUSY || rc == SQLITE_LOCKED,
                                     log_frames, ckpt_frames),
        .rc = rc,
        .log_frames = log_frames,
        .ckpt_frames = ckpt_frames,
        .source = "node_db",
    };
    wal_ckpt_stats_note(&rec);
    if (out)
        *out = rec;

    /* A checkpoint that completed and reclaimed nothing is not an error, so
     * it must not be reported as one — but it is not silence either. Say what
     * happened, once, with the numbers that prove it. */
    if (wal_ckpt_outcome_reclaimed_nothing(rec.outcome))
        LOG_WARN("db",
                 "[db] wal checkpoint reclaimed nothing: outcome=%s rc=%d "
                 "wal_frames=%lld moved=%lld",
                 wal_ckpt_outcome_name(rec.outcome), rc,
                 (long long)log_frames, (long long)ckpt_frames);

    node_db_note_activity(ndb, "wal_checkpoint", rc);
    db_lifetime_scope_leave(&lifetime_scope);
    return rc == SQLITE_OK;
}

bool node_db_wal_checkpoint(struct node_db *ndb)
{
    return node_db_wal_checkpoint_result(ndb, NULL);
}
