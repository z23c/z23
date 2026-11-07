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

#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "models/activerecord.h"
#include "models/database.h"
#include "models/database_lifetime.h"
#include "models/database_internal.h"
#include "models/database_progress.h"
#include "models/utxo_count_cache.h"
#include "platform/time_compat.h"
#include "storage/utxo_mirror_schema.h"
#include "support/log_throttle.h"
#include "util/thread_registry.h"
#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* ── UTXO Lifecycle ────────────────────────────────────────────── */

bool node_db_wipe_utxos(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return false;
    int64_t existing = 0;
    /* An unread count is not an empty set: the size guard must see it. */
    if (!node_db_utxo_count_checked(ndb, &existing)) {
        LOG_WARN("db", "db: refused to wipe UTXOs: the row count could not be "
                 "read");
        return false;
    }
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

bool node_db_clear_rejected_import(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return false;
    bool ok = node_db_exec(ndb, "DELETE FROM utxos");
    ok &= node_db_exec(ndb, "DELETE FROM node_state WHERE key IN ("
                            "'coins_best_block','utxo_commitment',"
                            "'" UTXO_MIRROR_SYNC_CURSOR_KEY "',"
                            "'leveldb_utxo_migrated')");
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

bool node_db_utxo_count_checked(struct node_db *ndb, int64_t *out)
{
    if (!ndb || !ndb->open || !ndb->db || !out)
        return false;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(ndb->db, "SELECT count(*) FROM utxos",
                           -1, &stmt, NULL) != SQLITE_OK)
        return false;
    bool ok = ar_step_checked(stmt, "db: utxo count", NULL) == ZCL_STEP_ROW;
    if (ok)
        *out = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return ok;
}

/* UTXO row count for periodic gauges: the exact count, at most
 * UTXO_COUNT_GAUGE_MAX_AGE_SECS old. A full count is only run when the cached
 * value has expired or belongs to another handle; consensus and audit callers
 * use node_db_utxo_count / _checked. Returns the last value when a refresh
 * cannot read the table, and 0 when there has never been one. */
static struct utxo_count_cache g_utxo_gauge_cache;
static _Atomic(const struct node_db *) g_utxo_gauge_owner;
static _Atomic unsigned long g_utxo_gauge_full_counts;
#ifdef ZCL_TESTING
static int64_t (*g_utxo_gauge_test_clock)(void);
#endif

static int64_t utxo_gauge_now_secs(void)
{
#ifdef ZCL_TESTING
    if (g_utxo_gauge_test_clock)
        return g_utxo_gauge_test_clock();
#endif
    return platform_time_monotonic_ms() / 1000;
}

int64_t node_db_utxo_count_gauge(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        return 0;
    int64_t now = utxo_gauge_now_secs();
    int64_t count = 0;
    if (atomic_load(&g_utxo_gauge_owner) == ndb &&
        utxo_count_cache_get(&g_utxo_gauge_cache, now,
                             UTXO_COUNT_GAUGE_MAX_AGE_SECS, &count))
        return count;
    atomic_fetch_add(&g_utxo_gauge_full_counts, 1);
    if (!node_db_utxo_count_checked(ndb, &count)) {
        static struct log_throttle warn = LOG_THROTTLE_INIT;
        uint64_t reps = 0;
        int64_t last = 0;
        bool have_good = atomic_load(&g_utxo_gauge_owner) == ndb &&
                         utxo_count_cache_last_good(&g_utxo_gauge_cache, &last);
        if (log_throttle_should_emit(&warn, 1, now,
                                     UTXO_COUNT_REFRESH_WARN_SECS, &reps)) {
            if (have_good)
                LOG_WARN("db", "[db] utxo count gauge: refresh failed (%s); "
                         "serving the last good value", ndb->path);
            else
                LOG_WARN("db", "[db] utxo count gauge: refresh failed (%s); "
                         "no good value yet, serving 0", ndb->path);
        }
        return have_good ? last : 0;
    }
    /* Value first, owner second: a reader that sees the owner sees its count. */
    utxo_count_cache_put(&g_utxo_gauge_cache, now, count);
    atomic_store(&g_utxo_gauge_owner, ndb);
    return count;
}

#ifdef ZCL_TESTING
unsigned long node_db_utxo_count_gauge_test_full_counts(void)
{
    return atomic_load(&g_utxo_gauge_full_counts);
}

void node_db_utxo_count_gauge_test_reset(int64_t (*clock)(void))
{
    g_utxo_gauge_test_clock = clock;
    atomic_store(&g_utxo_gauge_owner, NULL);
    atomic_store(&g_utxo_gauge_cache.at_secs, 0);
    atomic_store(&g_utxo_gauge_full_counts, 0);
}
#endif

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

/* A shutdown request ends the index rebuild. Every index here is derived data
 * that create_schema() recreates on the next open, while a rebuild over a
 * multi-GB node.db holds the shared connection, and the DB worker running it,
 * for minutes: longer than the shutdown watchdog grants a durability-critical
 * stage, so waiting for it turns a stop into a forced unclean exit. Rows,
 * commits and checkpoints are unaffected. The rebuild checks before each
 * index and, through a progress handler, inside one. The handler belongs to
 * the shared connection, so it acts only on the rebuilding thread and never
 * interrupts a statement another thread runs between two rebuild statements. */
#define INDEX_REBUILD_PROGRESS_OPS 1000

static _Thread_local bool t_index_rebuild_running;

#ifdef ZCL_TESTING
static void (*g_index_rebuild_test_hook)(void *ctx);
static void *g_index_rebuild_test_ctx;

void node_db_index_rebuild_test_set_hook(void (*hook)(void *ctx), void *ctx)
{
    g_index_rebuild_test_hook = hook;
    g_index_rebuild_test_ctx = ctx;
}
#endif

/* True when interrupting the running rebuild statement rolls back only that
 * statement. SQLite answers an interrupted write statement by rolling back
 * the connection's whole transaction (sqlite3VdbeHalt), and on the shared
 * connection that transaction can hold another thread's work: an explicit
 * transaction, or the uncommitted rows of another write statement still in
 * progress. The progress handler runs inside the rebuild statement with the
 * connection mutex held, so no other thread can begin a transaction or step,
 * prepare or finalize a statement while this reads them; the rebuild
 * statement is the one busy write statement expected. */
static bool index_rebuild_interrupt_is_local(sqlite3 *db)
{
    int writers = 0;
    for (sqlite3_stmt *s = sqlite3_next_stmt(db, NULL); s;
         s = sqlite3_next_stmt(db, s))
        if (sqlite3_stmt_busy(s) && !sqlite3_stmt_readonly(s))
            writers++;
    return sqlite3_get_autocommit(db) && writers == 1;
}

static int index_rebuild_progress(void *arg)
{
    if (!t_index_rebuild_running)
        return 0;
#ifdef ZCL_TESTING
    if (g_index_rebuild_test_hook)
        g_index_rebuild_test_hook(g_index_rebuild_test_ctx);
#endif
    return thread_registry_shutdown_requested() &&
           index_rebuild_interrupt_is_local(arg);
}

/* Creates one index with the progress handler registered. It joins the other
 * handlers on the shared connection (a dbquery time budget) instead of
 * replacing and then clearing them. Whether an interrupt is safe is decided
 * inside the handler, not before the statement: another thread can begin a
 * transaction between such a check and the statement. */
static int index_rebuild_one(struct node_db *ndb, const char *sql)
{
    t_index_rebuild_running = true;
    bool hooked = db_progress_add(ndb->db, INDEX_REBUILD_PROGRESS_OPS,
                                  index_rebuild_progress, ndb->db);
    int rc = db_exec_checked(ndb->db, sql, "rebuild_indexes");
    if (hooked)
        db_progress_remove(ndb->db, index_rebuild_progress, ndb->db);
    t_index_rebuild_running = false;
    return rc;
}

/* Creates each secondary index until a shutdown is requested; *deferred_out
 * says the request left the remaining ones for the next open. */
static bool index_rebuild_run(struct node_db *ndb, bool *deferred_out)
{
    bool all_ok = true;
    size_t built = 0;
    *deferred_out = false;
    for (size_t i = 0; i < NUM_DB_INDEXES && !*deferred_out; i++) {
        int rc = thread_registry_shutdown_requested()
            ? SQLITE_INTERRUPT
            : index_rebuild_one(ndb, DB_CREATE_INDEXES[i]);
        if (rc == SQLITE_OK)
            built++;
        else if (rc == SQLITE_INTERRUPT && thread_registry_shutdown_requested())
            *deferred_out = true;
        else
            all_ok = false;
    }
    if (*deferred_out)
        LOG_WARN("db", "[db] index rebuild stopped by a shutdown request "
                 "after %zu of %zu indexes; the next open recreates the rest",
                 built, (size_t)NUM_DB_INDEXES);
    return all_ok;
}

bool node_db_rebuild_indexes(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return false;
    bool deferred = false;
    return index_rebuild_run(ndb, &deferred) && !deferred;
}

static bool wal_checkpoint_run(struct node_db *ndb, struct wal_ckpt_record *out,
                              bool bounded);

#define TURBO_FOLD_ATTEMPTS 3
#define TURBO_FOLD_RETRY_MS 50

/* Fold the whole log into the database and sync it, at the connection's
 * current level, before synchronous=OFF. Rows committed in normal mode may
 * still be only in the log; the first checkpoint under OFF would fold them
 * into the database without a sync and reset the log, so a power loss could
 * take back a row that was reported durable (a receive-index record, for one).
 * A reader holding an old snapshot, or a statement stepped and not reset on
 * this connection, leaves the fold partial or refused; it is retried briefly,
 * and when it stays incomplete the bulk pass keeps synchronous=NORMAL: slower,
 * durable, and never a reason to stop catch-up or an import. The fold is
 * bounded: it never waits on a reader, because the connection mutex is held
 * for the wait and every other caller would stall behind it. */
static bool turbo_fold_log(struct node_db *ndb)
{
    struct wal_ckpt_record rec;
    for (int attempt = 1; attempt <= TURBO_FOLD_ATTEMPTS; attempt++) {
        if (wal_checkpoint_run(ndb, &rec, true) &&
            rec.outcome == WAL_CKPT_DRAINED)
            return true;
        if (attempt < TURBO_FOLD_ATTEMPTS)
            platform_sleep_ms(TURBO_FOLD_RETRY_MS);
    }
    LOG_WARN("db", "[db] ibd_turbo_mode: the log was not fully folded "
             "(outcome=%s rc=%d wal_frames=%lld moved=%lld); this bulk pass "
             "keeps synchronous=NORMAL", wal_ckpt_outcome_name(rec.outcome),
             rec.rc, (long long)rec.log_frames, (long long)rec.ckpt_frames);
    return false;
}

bool node_db_ibd_turbo_mode(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return false;
    /* Turbo-mode PRAGMAs are performance optimisations, not integrity
     * invariants — if any of them fail, fall back to the safe
     * defaults and carry on, never leaving a partial-turbo state (e.g.
     * synchronous=OFF applied but the WAL bound not, so the WAL grows
     * unbounded). */
    /* Bulk sync checkpoints RARELY, never NEVER. `wal_autocheckpoint=0`
     * removes the bound entirely, and bulk mode is only left by
     * node_db_normal_mode() at the END of a sync, so a process that dies
     * mid-sync would run with no bound at all. The loose bound
     * below keeps the checkpoint rare enough to be cheap and the file bounded
     * enough to survive a slow disk, and journal_size_limit is what actually
     * returns the .wal file's blocks to the filesystem afterwards. */
    static const char *const turbo_pragmas[] = {
        "PRAGMA wal_autocheckpoint="
            ZCL_NODE_DB_PRAGMA_NUM(ZCL_NODE_DB_WAL_AUTOCKPT_PAGES_BULK),
        "PRAGMA journal_size_limit="
            ZCL_NODE_DB_PRAGMA_NUM(ZCL_NODE_DB_JOURNAL_SIZE_LIMIT_BULK),
        NULL,
    };
    char cache_sql[48];
    snprintf(cache_sql, sizeof(cache_sql), "PRAGMA cache_size=-%lld",
             (long long)node_db_turbo_cache_kib());
    bool turbo_ok = db_exec_checked(ndb->db, cache_sql,
                                    "ibd_turbo_mode cache") == SQLITE_OK;
    for (int i = 0; turbo_pragmas[i]; i++) {
        if (db_exec_checked(ndb->db, turbo_pragmas[i],
                            "ibd_turbo_mode pragma") != SQLITE_OK)
            turbo_ok = false;
    }
    bool unsynced = turbo_fold_log(ndb);
    if (unsynced && db_exec_checked(ndb->db, "PRAGMA synchronous=OFF",
                                    "ibd_turbo_mode synchronous") != SQLITE_OK)
        turbo_ok = unsynced = false;
    sqlite3_busy_timeout(ndb->db, ZCL_NODE_DB_BUSY_TIMEOUT_MS);

    if (!turbo_ok) {
        LOG_WARN("db", "[db] ibd_turbo_mode: one or more PRAGMAs failed; " "falling back to safe defaults (IBD will be slower " "but correct)");
        db_exec_checked(ndb->db, "PRAGMA synchronous=NORMAL",
                        "turbo_fallback synchronous");
        node_db_restore_cache_size(ndb);
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
    printf("db: IBD turbo mode (synchronous=%s, indexes dropped)\n",
           unsynced ? "OFF" : "NORMAL");
    return true;
}

bool node_db_restore_cache_size(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return false;
    char sql[48];
    snprintf(sql, sizeof(sql), "PRAGMA cache_size=-%lld",
             (long long)node_db_budget_cache_kib());
    return db_exec_checked(ndb->db, sql, "restore_cache_size") == SQLITE_OK;
}

static bool modes_read_sync(struct node_db *ndb, int *level)
{
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s, "PRAGMA synchronous", (void)0,
                      *level = (int)AR_COL_INT(s, 0));
}

int node_db_synchronous_level(struct node_db *ndb)
{
    int level = -1;
    if (!ndb || !ndb->open || !modes_read_sync(ndb, &level))
        return -1;
    return level;
}

bool node_db_normal_mode(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return false;
    bool ok = db_exec_checked(ndb->db, "PRAGMA synchronous=NORMAL",
                    "normal_mode synchronous") == SQLITE_OK;
    ok &= node_db_restore_cache_size(ndb);
    ok &= db_exec_checked(ndb->db, "PRAGMA wal_autocheckpoint="
                    ZCL_NODE_DB_PRAGMA_NUM(ZCL_NODE_DB_WAL_AUTOCKPT_PAGES),
                    "normal_mode wal_autocheckpoint") == SQLITE_OK;
    /* Cap the WAL FILE size after checkpoint. wal_autocheckpoint is PASSIVE: it
     * folds WAL pages into the db but leaves the .wal file at its high-water
     * mark, so one write burst can leave a large file sitting for the entire
     * life of a days-long node (a slow disk-fill the disk_full condition cannot
     * reclaim). journal_size_limit truncates the .wal back to the cap after each
     * checkpoint, bounding disk at the source — no reclaim thread, no deleting a
     * live WAL out from under an open handle. 64 MiB is generous headroom over
     * the ~4 MiB autocheckpoint trigger; it only caps pathological bursts. */
    ok &= db_exec_checked(ndb->db, "PRAGMA journal_size_limit="
                    ZCL_NODE_DB_PRAGMA_NUM(ZCL_NODE_DB_JOURNAL_SIZE_LIMIT),
                    "normal_mode journal_size_limit") == SQLITE_OK;
    bool deferred = false;
    ok &= index_rebuild_run(ndb, &deferred);
    if (!ok) return false;
    node_db_wal_checkpoint(ndb);
    node_db_note_turbo_mode(ndb, false, "normal_mode", SQLITE_OK);
    printf("db: normal mode (synchronous=NORMAL, %s)\n",
           deferred ? "index rebuild left for the next open"
                    : "indexes rebuilt");
    return true;
}

/* Size-triggered passive checkpoint for bulk/turbo runs — see database.h.
 * Called at batch-commit boundaries where no write transaction is open, so
 * the PASSIVE fold inside node_db_wal_checkpoint() can move frames instead
 * of reporting BUSY against our own open transaction. */
bool node_db_turbo_maybe_checkpoint(struct node_db *ndb,
                                    int64_t wal_max_bytes)
{
    if (!ndb || !ndb->open || !ndb->db)
        LOG_FAIL("db", "turbo_maybe_checkpoint: null or closed db");
    if (wal_max_bytes <= 0)
        return false;
    const char *main_path = sqlite3_db_filename(ndb->db, "main");
    if (!main_path || !main_path[0] || strcmp(main_path, ":memory:") == 0)
        return false;
    char wal_path[1088];
    int n = snprintf(wal_path, sizeof(wal_path), "%s-wal", main_path);
    if (n < 0 || (size_t)n >= sizeof(wal_path))
        LOG_FAIL("db", "turbo_maybe_checkpoint: db path too long");
    struct stat fst;
    if (stat(wal_path, &fst) != 0)
        return false;
    if ((int64_t)fst.st_size <= wal_max_bytes)
        return false;
    LOG_INFO("db", "turbo_maybe_checkpoint: WAL %lld bytes over ceiling "
             "%lld — checkpointing mid-run",
             (long long)fst.st_size, (long long)wal_max_bytes);
    if (!node_db_wal_checkpoint(ndb)) {
        LOG_WARN("db", "turbo_maybe_checkpoint: mid-run checkpoint failed "
                 "(WAL %lld bytes, ceiling %lld)",
                 (long long)fst.st_size, (long long)wal_max_bytes);
        return false;
    }
    return true;
}

/* True only when the connection's journal mode is actually WAL — in-memory
 * and rollback-journal handles report something else here. */
static bool wal_checkpoint_journal_mode_is_wal(sqlite3 *db)
{
    sqlite3_stmt *stmt = NULL;
    bool is_wal = false;
    if (sqlite3_prepare_v2(db, "PRAGMA journal_mode", -1, &stmt, NULL) == SQLITE_OK &&
        stmt && sqlite3_step(stmt) == SQLITE_ROW) {  // raw-sql-ok:read-only-introspection
        /* sqlite3_column_text points INTO the stmt; it is freed by
         * sqlite3_finalize below. Capture the comparison while the stmt is
         * still live — reading `mode` after finalize is a use-after-free. */
        const char *mode = (const char *)sqlite3_column_text(stmt, 0);
        is_wal = (mode && strcmp(mode, "wal") == 0);
    }
    if (stmt)
        sqlite3_finalize(stmt);
    return is_wal;
}

/* A .wal file reset (TRUNCATE) failure that is a real error: not "never
 * ran" (-1), not success, and not the benign reader-lock race (BUSY/LOCKED)
 * that PASSIVE already owns the verdict for. */
static bool wal_checkpoint_truncate_hard_failure(int truncate_rc)
{
    return truncate_rc != -1 && truncate_rc != SQLITE_OK &&
           truncate_rc != SQLITE_BUSY && truncate_rc != SQLITE_LOCKED;
}

#define CKPT_LOCKED_SQL_MAX 120

/* The connection mutex is held across the autocommit read and the whole
 * statement walk: sqlite3_stmt_busy and sqlite3_sql take no mutex, so another
 * thread finalizing a statement mid-walk would be a use-after-free. The mutex
 * is recursive, so a caller already inside the connection is unaffected. */
int node_db_describe_open_statements(sqlite3 *db, char *out, size_t cap)
{
    int busy = 0;
    if (!out || cap == 0)
        return 0;
    out[0] = '\0';
    if (!db)
        return 0;
    sqlite3_mutex *mu = sqlite3_db_mutex(db);
    sqlite3_mutex_enter(mu);
    size_t n = (size_t)snprintf(out, cap, "autocommit=%d",
                                sqlite3_get_autocommit(db));
    for (sqlite3_stmt *s = sqlite3_next_stmt(db, NULL); s;
         s = sqlite3_next_stmt(db, s)) {
        if (!sqlite3_stmt_busy(s))
            continue;
        busy++;
        const char *sql = sqlite3_sql(s);
        if (n < cap)
            n += (size_t)snprintf(out + n, cap - n, " busy[%d]=\"%.*s\"", busy,
                                  CKPT_LOCKED_SQL_MAX, sql ? sql : "(null)");
    }
    sqlite3_mutex_leave(mu);
    return busy;
}

/* Report on the first refusal of a streak, and again after
 * CKPT_LOCKED_REPORT_RETRY further refusals while a capture came back empty,
 * so one empty capture cannot silence the diagnostic. The streak ends on the
 * next PASSIVE success. State is per handle: two node_db handles exist. */
#define CKPT_LOCKED_REPORT_RETRY 20

static void wal_checkpoint_note_locked(struct node_db *ndb, int passive_rc)
{
    if (passive_rc == SQLITE_OK) {
        atomic_store(&ndb->ckpt_locked_refusals, 0);
        atomic_store(&ndb->ckpt_locked_next_report, 0);
        return;
    }
    if (passive_rc != SQLITE_LOCKED)
        return;
    int n = atomic_fetch_add(&ndb->ckpt_locked_refusals, 1) + 1;
    if (n < atomic_load(&ndb->ckpt_locked_next_report))
        return;
    char what[1024];
    int busy = node_db_describe_open_statements(ndb->db, what, sizeof(what));
    bool empty = busy == 0 && strstr(what, "autocommit=1") != NULL;
    atomic_store(&ndb->ckpt_locked_next_report,
                 empty ? n + CKPT_LOCKED_REPORT_RETRY : INT_MAX);
    /* Sampled just after the refusal, not at its exact instant. */
    LOG_WARN("db", "[db] wal checkpoint refused (SQLITE_LOCKED, refusal #%d): "
             "%d statement(s) stepped and not reset, sampled just after the "
             "refusal; %s", n, busy, what);
}

/* Build the outcome record from the PASSIVE checkpoint's verdict and counts. */
static struct wal_ckpt_record wal_checkpoint_record_from_result(
    int rc, int log_frames, int ckpt_frames)
{
    struct wal_ckpt_record rec = {
        .outcome = wal_ckpt_classify(rc == SQLITE_OK,
                                     rc == SQLITE_BUSY || rc == SQLITE_LOCKED,
                                     log_frames, ckpt_frames),
        .rc = rc,
        .log_frames = log_frames,
        .ckpt_frames = ckpt_frames,
        .source = "node_db",
    };
    return rec;
}

/* Pre-fill *out so an untouched record can never be mistaken for a result. */
static void wal_checkpoint_out_set_unattempted(struct wal_ckpt_record *out)
{
    if (out) {
        static const struct wal_ckpt_record unattempted = {
            .outcome = WAL_CKPT_UNKNOWN, .rc = 0,
            .log_frames = -1, .ckpt_frames = -1, .source = "node_db",
        };
        *out = unattempted;
    }
}

bool node_db_wal_checkpoint_result(struct node_db *ndb,
                                   struct wal_ckpt_record *out)
{
    return wal_checkpoint_run(ndb, out, false);
}

/* The file reset after PASSIVE; -1 when it is not attempted. A bounded caller
 * resets only after PASSIVE folded the whole log, and does not wait. */
static int wal_checkpoint_reset_file(struct node_db *ndb, int passive_rc,
                                     int log_frames, int ckpt_frames,
                                     bool bounded)
{
    if (passive_rc != SQLITE_OK)
        return -1;
    if (bounded) {
        if (log_frames < 0 || ckpt_frames < log_frames)
            return -1;
        sqlite3_busy_timeout(ndb->db, 0);
    }
    int rc = sqlite3_wal_checkpoint_v2(ndb->db, NULL, SQLITE_CHECKPOINT_TRUNCATE,
                                         NULL, NULL);
    if (bounded)
        sqlite3_busy_timeout(ndb->db, ZCL_NODE_DB_BUSY_TIMEOUT_MS);
    return rc;
}

/* `bounded` is for a caller that must not hold the connection while another
 * connection's reader drains: the file reset runs only after PASSIVE folded
 * the whole log, and without the busy-timeout wait. A partial fold can never
 * be drained, so resetting the file after it would only wait. */
static bool wal_checkpoint_run(struct node_db *ndb, struct wal_ckpt_record *out,
                              bool bounded)
{
    /* Give `out` a definite meaning on every exit, including the two early
     * ones. A caller that reads a record this function never touched would be
     * reading the last checkpoint's numbers as if they were this one's. */
    wal_checkpoint_out_set_unattempted(out);

    if (!ndb || !ndb->open) return false;
    struct db_lifetime_scope lifetime_scope;
    db_lifetime_scope_enter(
        &lifetime_scope, "node_db.checkpoint",
        ndb->lifetime_backing_owner ? DB_LIFETIME_BACKING_OWNER
                                    : DB_LIFETIME_HANDLE_OWNER,
        ndb->lifetime_generation);
    bool is_wal = wal_checkpoint_journal_mode_is_wal(ndb->db);
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
     * already failed one call earlier, and the file-reset step's lock race
     * must not be reported as the checkpoint's outcome.
     *
     * Passing NULL for both counts would collapse "folded the whole log
     * away" and "moved zero frames because a reader is parked on the oldest
     * one" into one indistinguishable SQLITE_OK. */
    int log_frames = -1, ckpt_frames = -1;
    int passive_rc = sqlite3_wal_checkpoint_v2(ndb->db, NULL,
                                                SQLITE_CHECKPOINT_PASSIVE,
                                                &log_frames, &ckpt_frames);
    wal_checkpoint_note_locked(ndb, passive_rc);
    int truncate_rc = wal_checkpoint_reset_file(ndb, passive_rc, log_frames,
                                                ckpt_frames, bounded);
    bool truncate_hard_failure =
        wal_checkpoint_truncate_hard_failure(truncate_rc);
    int rc = truncate_hard_failure ? truncate_rc : passive_rc;
    if (truncate_hard_failure)
        LOG_ERROR("db",
                  "[db] wal file reset failed after PASSIVE checkpoint: "
                  "truncate_rc=%d wal_frames=%d moved=%d",
                  truncate_rc, log_frames, ckpt_frames);

    struct wal_ckpt_record rec =
        wal_checkpoint_record_from_result(rc, log_frames, ckpt_frames);
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
