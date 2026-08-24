/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * consensus_state_snapshot_install_activate.c — ACTIVATE mode for
 * zcl.consensus_state_bundle.v1: the consumer side of the sovereign shielded-
 * state cure. Kept in its own file (one focused responsibility) from the
 * contained admission preview in consensus_state_snapshot_install.c.
 *
 * Atomically installs a complete bundle's coins + Sprout/Sapling anchors +
 * nullifiers + the 8 reducer stage cursors into the LIVE progress store, with a
 * physically restorable prior generation. Full contract:
 * config/consensus_state_snapshot_install.h. */

#include "config/consensus_state_snapshot_install.h"
#include "consensus_state_snapshot_install_internal.h" /* lease + authority resolver */
#include "jobs/reducer_frontier.h"       /* reducer_frontier_compute_hstar,
                                          * REDUCER_TRUSTED_BASE_*_KEY */
#include "jobs/reducer_frontier_schema.h"
#include "jobs/refold_progress.h"
#include "jobs/stage_helpers.h"
#include "jobs/stage_repair_internal.h"  /* stage_repair_force_stage_cursor */
#include "jobs/tip_finalize_stage.h"     /* tip_finalize_stage_seed_anchor */
#include "jobs/utxo_apply_stage.h"
#include "services/consensus_state_publication_cas.h"
#include "services/nullifier_backfill_service.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/consensus_state_bundle_codec.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"      /* progress_store_tx_lock/unlock,
                                          * progress_meta_set/delete_in_tx */
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ACTIVATE_SUBSYS "consensus_bundle_activate"

/* Reuse the content-verify heartbeat primitive for the multi-minute activate
 * phases so a long install is never silent (VALIDATE_SUBSYS aliases here). */
#define VALIDATE_SUBSYS ACTIVATE_SUBSYS
#include "consensus_state_bundle_validate_heartbeat.h"

/* Compact per-phase progress lines for the multi-minute activate verify phases
 * (never-silent doctrine): begin names the phase in flight, done reports
 * elapsed. Paired via the returned start time. */
static int64_t activate_phase_begin(const char *phase, uint64_t count)
{
    LOG_INFO(ACTIVATE_SUBSYS, "activate verify: phase=%s begin count=%llu",
             phase, (unsigned long long)count);
    return GetTimeMicros();
}
static void activate_phase_done(const char *phase, int64_t started_us)
{
    LOG_INFO(ACTIVATE_SUBSYS, "activate verify: phase=%s ok elapsed=%.0fs",
             phase, (double)(GetTimeMicros() - started_us) / 1000000.0);
}

#ifdef ZCL_TESTING
static void (*g_activate_after_stream_hook)(void *) = NULL;
static void *g_activate_after_stream_hook_ctx = NULL;
static void (*g_activate_after_backup_hook)(void *) = NULL;
static void *g_activate_after_backup_hook_ctx = NULL;
static bool g_activate_fail_seed_once = false;
static bool g_activate_fail_after_seed_once = false;

void consensus_state_snapshot_install_activate_test_set_after_stream_hook(
    void (*hook)(void *), void *ctx)
{
    g_activate_after_stream_hook = hook;
    g_activate_after_stream_hook_ctx = ctx;
}

void consensus_state_snapshot_install_activate_test_set_after_backup_hook(
    void (*hook)(void *), void *ctx)
{
    g_activate_after_backup_hook = hook;
    g_activate_after_backup_hook_ctx = ctx;
}

void consensus_state_snapshot_install_activate_test_fail_seed_once(void)
{
    g_activate_fail_seed_once = true;
}

void consensus_state_snapshot_install_activate_test_fail_after_seed_once(void)
{
    g_activate_fail_after_seed_once = true;
}

static void activate_run_after_stream_hook(void)
{
    void (*hook)(void *) = g_activate_after_stream_hook;
    void *ctx = g_activate_after_stream_hook_ctx;
    g_activate_after_stream_hook = NULL;
    g_activate_after_stream_hook_ctx = NULL;
    if (hook)
        hook(ctx);
}

static void activate_run_after_backup_hook(void)
{
    void (*hook)(void *) = g_activate_after_backup_hook;
    void *ctx = g_activate_after_backup_hook_ctx;
    g_activate_after_backup_hook = NULL;
    g_activate_after_backup_hook_ctx = NULL;
    if (hook)
        hook(ctx);
}

static bool activate_consume_fail_seed(void)
{
    bool fail = g_activate_fail_seed_once;
    g_activate_fail_seed_once = false;
    return fail;
}

static bool activate_consume_fail_after_seed(void)
{
    bool fail = g_activate_fail_after_seed_once;
    g_activate_fail_after_seed_once = false;
    return fail;
}
#else
static void activate_run_after_stream_hook(void) { }
static void activate_run_after_backup_hook(void) { }
static bool activate_consume_fail_seed(void) { return false; }
static bool activate_consume_fail_after_seed(void) { return false; }
#endif

/* Reducer-derived tables cleared on cutover — the exact list
 * boot_refold_from_anchor_reset uses (a "no such table" is tolerated). */
static const char *const k_activate_derived_tables[] = {
    "validate_headers_log", "body_fetch_log", "body_persist_log",
    "script_validate_log", "proof_validate_log", "utxo_apply_log",
    "tip_finalize_log", "utxo_apply_delta", "created_outputs",
};
static const char *const k_activate_stages[] = {
    "header_admit", "validate_headers", "body_fetch", "body_persist",
    "script_validate", "proof_validate", "utxo_apply", "tip_finalize",
};
static const char *const k_activate_generation_tables[] = {
    "consensus_state_producer_session",
    "consensus_state_source_receipt",
};

#define ACTIVATE_TIPFIN_WITNESS_KEY "tipfin_backfill.progress"

static bool activate_fail(struct consensus_state_activate_result *result,
                          enum consensus_state_install_status status,
                          const char *fmt, ...)
{
    char reason[CONSENSUS_STATE_ACTIVATE_REASON_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(reason, sizeof(reason), fmt, ap);
    va_end(ap);
    if (result) {
        result->status = status;
        result->activated = false;
        snprintf(result->reason, sizeof(result->reason), "%s", reason);
    }
    LOG_WARN(ACTIVATE_SUBSYS, "%s", reason);
    return false;
}

static bool activate_digest_nonzero(const uint8_t digest[32])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 32; i++)
        any |= digest[i];
    return any != 0;
}

/* Bind one source column into the destination statement, preserving type.
 * Local copy of the candidate builder's helper (different translation unit). */
static bool activate_bind_column(sqlite3_stmt *dst, int dst_col,
                                 sqlite3_stmt *src, int src_col)
{
    switch (sqlite3_column_type(src, src_col)) {
    case SQLITE_INTEGER:
        return sqlite3_bind_int64(dst, dst_col,
                                  sqlite3_column_int64(src, src_col)) ==
               SQLITE_OK;
    case SQLITE_TEXT:
        return sqlite3_bind_text(dst, dst_col,
                                 (const char *)sqlite3_column_text(src, src_col),
                                 sqlite3_column_bytes(src, src_col),
                                 SQLITE_TRANSIENT) == SQLITE_OK;
    case SQLITE_BLOB: {
        int bytes = sqlite3_column_bytes(src, src_col);
        /* sqlite3_column_blob() may return NULL for a zero-length BLOB.  Bind
         * an explicit zero BLOB so type and NOT NULL semantics survive the
         * copy instead of accidentally binding SQL NULL. */
        if (bytes == 0)
            return sqlite3_bind_zeroblob(dst, dst_col, 0) == SQLITE_OK;
        const void *blob = sqlite3_column_blob(src, src_col);
        return blob && sqlite3_bind_blob(dst, dst_col, blob, bytes,
                                         SQLITE_TRANSIENT) == SQLITE_OK;
    }
    case SQLITE_NULL:
        return sqlite3_bind_null(dst, dst_col) == SQLITE_OK;
    default:
        return false;
    }
}

/* Stream every row selected from the immutable bundle into the live progress
 * store. Runs inside the caller's open BEGIN IMMEDIATE, so a failure rolls back
 * with the whole install. Emitted SQL uses named columns so the on-disk column
 * order of either store is irrelevant. */
static bool activate_stream_copy(sqlite3 *src, sqlite3 *dst,
                                 const char *select_sql, const char *insert_sql,
                                 int columns, const char *stage,
                                 uint64_t expected_total, uint64_t *rows_out)
{
    sqlite3_stmt *read = NULL;
    sqlite3_stmt *write = NULL;
    bool ok = sqlite3_prepare_v2(src, select_sql, -1, &read, NULL) == SQLITE_OK &&
              sqlite3_prepare_v2(dst, insert_sql, -1, &write, NULL) == SQLITE_OK;
    uint64_t rows = 0;
    struct validate_heartbeat hb;
    heartbeat_begin(&hb, stage, expected_total);
    int rc = SQLITE_ERROR;
    while (ok && (rc = sqlite3_step(read)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        heartbeat_tick(&hb, rows);
        ok = sqlite3_reset(write) == SQLITE_OK &&
             sqlite3_clear_bindings(write) == SQLITE_OK;
        for (int i = 0; ok && i < columns; i++)
            ok = activate_bind_column(write, i + 1, read, i);
        if (ok)
            ok = sqlite3_step(write) == SQLITE_DONE; // raw-sql-ok:progress-kv-kernel-store
        if (ok && rows == UINT64_MAX)
            ok = false;
        if (ok)
            rows++;
    }
    if (ok)
        ok = rc == SQLITE_DONE;
    if (!ok)
        LOG_WARN(ACTIVATE_SUBSYS, "row stream failed: src=%s dst=%s",
                 sqlite3_errmsg(src), sqlite3_errmsg(dst));
    if (read)
        sqlite3_finalize(read);
    if (write)
        sqlite3_finalize(write);
    if (rows_out)
        *rows_out = rows;
    return ok;
}

static bool activate_sqlite_quick_check(sqlite3 *db)
{
    sqlite3_stmt *stmt = NULL;
    if (!db || sqlite3_prepare_v2(db, "PRAGMA quick_check(1)", -1, &stmt,
                                  NULL) != SQLITE_OK)
        return false;
    int rc = sqlite3_step(stmt); // raw-sql-ok:read-only-introspection
    bool ok = rc == SQLITE_ROW &&
              sqlite3_column_type(stmt, 0) == SQLITE_TEXT;
    const unsigned char *text = ok ? sqlite3_column_text(stmt, 0) : NULL;
    ok = ok && text && strcmp((const char *)text, "ok") == 0;
    rc = ok ? sqlite3_step(stmt) : SQLITE_ERROR; // raw-sql-ok:read-only-introspection
    ok = ok && rc == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

/* Fail if the singleton's already-open main inode no longer occupies its
 * original name. This VFS-backed check catches out-of-band rename/replacement
 * around backup and cutover. */
static bool activate_progress_file_unmoved(sqlite3 *db)
{
    int moved = 1;
    return db &&
           sqlite3_file_control(db, "main", SQLITE_FCNTL_HAS_MOVED, &moved) ==
               SQLITE_OK &&
           moved == 0;
}

static bool activate_data_version(sqlite3 *db, sqlite3_int64 *version)
{
    sqlite3_stmt *stmt = NULL;
    if (!db || !version ||
        sqlite3_prepare_v2(db, "PRAGMA data_version", -1, &stmt, NULL) !=
            SQLITE_OK)
        return false;
    int rc = sqlite3_step(stmt); // raw-sql-ok:read-only-introspection
    bool ok = rc == SQLITE_ROW &&
              sqlite3_column_type(stmt, 0) == SQLITE_INTEGER;
    if (ok)
        *version = sqlite3_column_int64(stmt, 0);
    rc = ok ? sqlite3_step(stmt) : SQLITE_ERROR; // raw-sql-ok:read-only-introspection
    ok = ok && rc == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

static bool activate_backup_sidecars_absent(int datadir_fd, const char *name)
{
    static const char *const suffixes[] = {"-journal", "-wal", "-shm"};
    char sidecar[160];
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        int n = snprintf(sidecar, sizeof(sidecar), "%s%s", name,
                         suffixes[i]);
        struct stat st;
        errno = 0;
        if (n <= 0 || (size_t)n >= sizeof(sidecar) ||
            fstatat(datadir_fd, sidecar, &st, AT_SYMLINK_NOFOLLOW) == 0 ||
            errno != ENOENT)
            return false;
    }
    return true;
}

/* Capture a physically restorable prior generation through the retained
 * directory capability.  The caller MUST hold progress_store_tx_lock while
 * progress_db remains in autocommit. VACUUM INTO reads the already-open
 * singleton (never a pathname-reopened source). The caller immediately takes
 * BEGIN IMMEDIATE and compares the returned data-version/total-change fence
 * before making any cutover write, closing the only inter-process commit
 * window. A successful return means the standalone SQLite image was
 * independently reopened, quick-checked, file-fsynced, sidecar-free, and made
 * name-durable by fsyncing its parent directory. */
static bool activate_backup_prior_generation(sqlite3 *progress_db,
                                             int datadir_fd,
                                             const char *datadir_display,
                                             char *out_path, size_t out_cap,
                                             sqlite3_int64 *data_version_out,
                                             sqlite3_int64 *changes_out)
{
    static _Atomic uint64_t s_backup_seq = 0;
    if (!progress_db || datadir_fd < 0 || !datadir_display ||
        !datadir_display[0] || !out_path || out_cap == 0 ||
        !data_version_out || !changes_out ||
        sqlite3_get_autocommit(progress_db) == 0 ||
        !activate_progress_file_unmoved(progress_db))
        return false;
    out_path[0] = '\0';
    struct stat dir_st;
    if (fstat(datadir_fd, &dir_st) != 0 || !S_ISDIR(dir_st.st_mode))
        return false;

    int64_t stamp = (int64_t)platform_time_wall_time_t();
    uint64_t seq = atomic_fetch_add_explicit(&s_backup_seq, 1,
                                             memory_order_relaxed) + 1;
    char name[128]; /* A4: VACUUM backs up the consensus.db kernel singleton */
    int n = snprintf(name, sizeof(name),
                     "consensus.db.preinstall.%lld.%ld.%llu",
                     (long long)stamp, (long)getpid(),
                     (unsigned long long)seq);
    if (n <= 0 || (size_t)n >= sizeof(name))
        return false;

    char destination_name_path[PATH_MAX];
    n = snprintf(destination_name_path, sizeof(destination_name_path),
                 "/proc/self/fd/%d/%s", datadir_fd, name);
    if (n <= 0 || (size_t)n >= sizeof(destination_name_path))
        return false;
    n = snprintf(out_path, out_cap, "%s/%s", datadir_display, name);
    if (n <= 0 || (size_t)n >= out_cap) {
        out_path[0] = '\0';
        return false;
    }

    if (!activate_backup_sidecars_absent(datadir_fd, name)) {
        out_path[0] = '\0';
        return false;
    }

    /* sqlite3_open_v2's SQLITE_OPEN_EXCLUSIVE flag is intentionally a no-op;
     * reserve a zero-length output with openat(O_EXCL). VACUUM INTO accepts an
     * existing empty file. Retaining the descriptor lets every later cleanup
     * prove it still owns the published name. */
    int fd = openat(datadir_fd, name,
                    O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    0600);
    bool reserved_identity = false;
    dev_t reserved_dev = 0;
    ino_t reserved_ino = 0;
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_nlink != 1) {
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation backup target reservation failed: %s",
                 strerror(errno));
        if (fd >= 0)
            (void)close(fd);
        fd = -1;
        goto cleanup;
    }
    reserved_identity = true;
    reserved_dev = st.st_dev;
    reserved_ino = st.st_ino;

    sqlite3_int64 version_before = -1;
    sqlite3_int64 version_after = -1;
    sqlite3_int64 changes_before = sqlite3_total_changes64(progress_db);
    sqlite3_stmt *stmt = NULL;
    bool ok = activate_data_version(progress_db, &version_before) &&
              sqlite3_prepare_v2(progress_db, "VACUUM main INTO ?1", -1,
                                 &stmt, NULL) == SQLITE_OK &&
              sqlite3_bind_text(stmt, 1, destination_name_path, -1,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:progress-kv-kernel-store
    if (stmt)
        sqlite3_finalize(stmt);
    ok = ok && activate_data_version(progress_db, &version_after) &&
         version_before == version_after &&
         changes_before == sqlite3_total_changes64(progress_db) &&
         activate_progress_file_unmoved(progress_db) &&
         activate_backup_sidecars_absent(datadir_fd, name);
    if (!ok) {
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation VACUUM/data-version fence failed while "
                 "the progress-store lock was held");
        (void)close(fd);
        fd = -1;
        goto cleanup;
    }

    struct stat named_st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        st.st_dev != reserved_dev || st.st_ino != reserved_ino ||
        fstatat(datadir_fd, name, &named_st, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(named_st.st_mode) || named_st.st_nlink != 1 ||
        named_st.st_dev != reserved_dev || named_st.st_ino != reserved_ino ||
        fchmod(fd, 0400) != 0 || fsync(fd) != 0) {
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation file durability verification failed");
        (void)close(fd);
        fd = -1;
        ok = false;
        goto cleanup;
    }

    sqlite3 *verify = NULL;
    ok = sqlite3_open_v2(destination_name_path, &verify,
                         SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX,
                         NULL) == SQLITE_OK && verify &&
         sqlite3_db_readonly(verify, "main") == 1 &&
         activate_sqlite_quick_check(verify);
    if (verify) {
        int close_rc = sqlite3_close(verify);
        if (close_rc != SQLITE_OK) {
            ok = false;
            (void)sqlite3_close_v2(verify);
        }
    }
    if (!ok) {
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation independent reopen/quick_check failed");
        (void)close(fd);
        fd = -1;
        goto cleanup;
    }
    /* Re-check the published name after the independent reopen. */
    if (fstatat(datadir_fd, name, &named_st, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(named_st.st_mode) || named_st.st_nlink != 1 ||
        named_st.st_dev != reserved_dev || named_st.st_ino != reserved_ino) {
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation backup name no longer identifies the "
                 "reserved inode");
        (void)close(fd);
        fd = -1;
        goto cleanup;
    }
    (void)close(fd);
    fd = -1;
    if (fsync(datadir_fd) != 0) {
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation parent directory fsync failed: %s",
                 strerror(errno));
        ok = false;
        goto cleanup;
    }
    *data_version_out = version_after;
    *changes_out = changes_before;
    return true;

cleanup:
    if (fd >= 0)
        (void)close(fd);
    struct stat cleanup_st;
    bool owned_name = reserved_identity &&
        fstatat(datadir_fd, name, &cleanup_st, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(cleanup_st.st_mode) && cleanup_st.st_dev == reserved_dev &&
        cleanup_st.st_ino == reserved_ino;
    if (owned_name) {
        if (unlinkat(datadir_fd, name, 0) != 0 && errno != ENOENT)
            LOG_WARN(ACTIVATE_SUBSYS,
                     "prior-generation owned-output cleanup failed: %s",
                     strerror(errno));
    } else if (reserved_identity) {
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation output name changed; refusing to unlink "
                 "an unowned replacement");
    }
    if (!activate_backup_sidecars_absent(datadir_fd, name))
        LOG_WARN(ACTIVATE_SUBSYS,
                 "prior-generation sidecar remains; refusing unsafe cleanup");
    (void)fsync(datadir_fd);
    out_path[0] = '\0';
    return false;
}

/* Producer receipts, validation epochs, and one-shot repair witnesses belong
 * to the pre-install state generation.  None may survive a replacement: doing
 * so could make a new chainstate appear locally replay-proven or cause a later
 * repair to skip work already attempted against the old generation.  This
 * runs under the cutover BEGIN IMMEDIATE, so any later failure restores every
 * row/key together with the prior state. */
static bool activate_clear_generation_metadata(
    sqlite3 *progress_db, struct consensus_state_activate_result *result)
{
    char *err = NULL;
    for (size_t i = 0;
         i < sizeof(k_activate_generation_tables) /
                 sizeof(k_activate_generation_tables[0]); i++) {
        char sql[96];
        int n = snprintf(sql, sizeof(sql), "DELETE FROM %s",
                         k_activate_generation_tables[i]);
        if (n <= 0 || (size_t)n >= sizeof(sql))
            return activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                                 "generation-table cleanup SQL overflow");
        if (sqlite3_exec(progress_db, sql, NULL, NULL, &err) != SQLITE_OK) {
            bool absent = err && strstr(err, "no such table");
            if (err) {
                sqlite3_free(err);
                err = NULL;
            }
            if (!absent)
                return activate_fail(
                    result, CONSENSUS_INSTALL_STORE_ERROR,
                    "clearing generation table %s failed",
                    k_activate_generation_tables[i]);
        }
    }

    static const char delete_sql[] =
        "DELETE FROM progress_meta WHERE key IN(?1,?2) "
        "OR key GLOB 'reducer_frontier.*_repair.*' "
        "OR key GLOB 'utxo_apply.*_repair.*' "
        "OR key GLOB 'utxo_apply.coin_backfill.outpoint.*' "
        "OR key GLOB 'coin_backfill.scan.*' "
        "OR key GLOB 'coin_backfill.rounds.*' "
        "OR key GLOB 'coin_backfill.refused.*'";
    sqlite3_stmt *stmt = NULL;
    bool ok = sqlite3_prepare_v2(progress_db, delete_sql, -1, &stmt, NULL) ==
                  SQLITE_OK &&
              sqlite3_bind_text(stmt, 1,
                                CONSENSUS_STATE_SOURCE_EPOCH_META_KEY, -1,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_text(stmt, 2, ACTIVATE_TIPFIN_WITNESS_KEY, -1,
                                SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:progress-kv-kernel-store
    if (stmt)
        sqlite3_finalize(stmt);
    if (!ok)
        return activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                             "clearing generation-scoped progress metadata "
                             "failed");
    return true;
}

/* The single atomic install transaction. Assumes the progress-store tx lock is
 * held and BEGIN IMMEDIATE is open on progress_db. Returns false (with the
 * caller rolling back) on any failure. Never partially applies. */
static bool activate_apply_in_tx(
    sqlite3 *progress_db, sqlite3 *bundle_db,
    const struct consensus_state_bundle_manifest *m, bool assisted_tier,
    struct consensus_state_activate_result *result)
{
    char *err = NULL;

    /* 1. Clear the reducer-derived logs/deltas (tolerate absent tables). */
    for (size_t i = 0;
         i < sizeof(k_activate_derived_tables) /
                 sizeof(k_activate_derived_tables[0]); i++) {
        char dsql[96];
        snprintf(dsql, sizeof(dsql), "DELETE FROM %s",
                 k_activate_derived_tables[i]);
        if (sqlite3_exec(progress_db, dsql, NULL, NULL, &err) != SQLITE_OK) {
            bool absent = err && strstr(err, "no such table");
            if (err) { sqlite3_free(err); err = NULL; }
            if (!absent)
                return activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                                     "clearing derived table %s failed",
                                     k_activate_derived_tables[i]);
        }
    }

    /* Replace coins in our txn; reset_for_reseed owns a separate BEGIN. */
    if (sqlite3_exec(progress_db, "DELETE FROM coins", NULL, NULL, &err)
        != SQLITE_OK) {
        if (err) { sqlite3_free(err); err = NULL; }
        return activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                             "clearing coins failed");
    }
    if (!coins_kv_bump_authority_generation_in_tx(progress_db))
        return activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR, "advancing coins authority generation failed");
    /* 3. Reset both anchor tables + nullifier set to a COMPLETE (activation
     *    cursor 0) history, THEN install the actual rows. This is the exact
     *    difference from the wedge-causing refold: complete history, not an
     *    empty table with a positive cursor. The reset primitives join our
     *    open transaction. */
    if (!anchor_kv_reset_mark_complete_in_tx(progress_db) ||
        !nullifier_kv_reset_mark_complete_in_tx(progress_db))
        return activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                             "shielded history reset to complete failed");
    /* The atomic bundle supersedes every partial shielded recovery session.
     * Leaving any cursor/binding behind can make the next boot resume a stale
     * replay generation over the newly installed complete state. */
    if (!shielded_history_cancel_full_replay_in_tx(progress_db) ||
        !progress_meta_delete_in_tx(progress_db,
                                    NULLIFIER_BACKFILL_RESUME_KEY) ||
        !progress_meta_delete_in_tx(progress_db,
                                    NULLIFIER_BACKFILL_CHAIN_KEY) ||
        !progress_meta_delete_in_tx(progress_db, REFOLD_IN_PROGRESS_KEY) ||
        !progress_meta_delete_in_tx(progress_db, REFOLD_FROM_ANCHOR_KEY) ||
        !progress_meta_delete_in_tx(progress_db,
                                    REFOLD_FROM_ANCHOR_TARGET_KEY))
        return activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                             "clearing stale recovery-generation markers "
                             "failed");
    if (!activate_clear_generation_metadata(progress_db, result))
        return false; // raw-return-ok:logged-by-activate_fail

    /* 4. Stream coins + anchors (by pool) + nullifiers from the bundle. */
    uint64_t coins = 0, sprout = 0, sapling = 0, nfs = 0;
    if (!activate_stream_copy(bundle_db, progress_db,
            "SELECT txid,vout,value,height,is_coinbase,script "
            "FROM coins ORDER BY txid,vout",
            "INSERT INTO coins(txid,vout,value,height,is_coinbase,script) "
            "VALUES(?,?,?,?,?,?)", 6, "activate_stream_coins",
            m->utxo_count, &coins) ||
        coins != m->utxo_count)
        return activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                             "coin stream count mismatch (%llu want %llu)",
                             (unsigned long long)coins,
                             (unsigned long long)m->utxo_count);
    if (!activate_stream_copy(bundle_db, progress_db,
            "SELECT anchor,height,tree FROM anchors WHERE pool=0 ORDER BY anchor",
            "INSERT INTO sprout_anchors(anchor,height,tree) VALUES(?,?,?)",
            3, "activate_stream_sprout_anchors", 0, &sprout) ||
        !activate_stream_copy(bundle_db, progress_db,
            "SELECT anchor,height,tree FROM anchors WHERE pool=1 ORDER BY anchor",
            "INSERT INTO sapling_anchors(anchor,height,tree) VALUES(?,?,?)",
            3, "activate_stream_sapling_anchors", 0, &sapling) ||
        sprout > UINT64_MAX - sapling ||
        sprout + sapling != m->anchor_count)
        return activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                             "anchor stream count mismatch (%llu want %llu)",
                             (unsigned long long)(sprout + sapling),
                             (unsigned long long)m->anchor_count);
    if (!activate_stream_copy(bundle_db, progress_db,
            "SELECT nf,pool,height FROM nullifiers ORDER BY pool,nf",
            "INSERT INTO nullifiers(nf,pool,height) VALUES(?,?,?)", 3,
            "activate_stream_nullifiers", m->nullifier_count, &nfs) ||
        nfs != m->nullifier_count)
        return activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                             "nullifier stream count mismatch (%llu want %llu)",
                             (unsigned long long)nfs,
                             (unsigned long long)m->nullifier_count);

    /* 5. Force the 8 stage cursors to the canonical anchor frontier: the seven
     *    upstream stages "processed through the anchor" (next-height cursor =
     *    height+1) and tip_finalize's next-to-finalize = height. This is the
     *    exact layout the validated candidate generation uses and the one the
     *    tip_finalize anchor seed produces, so the fold resumes AT height+1
     *    against on-disk bodies. */
    for (size_t i = 0;
         i < sizeof(k_activate_stages) / sizeof(k_activate_stages[0]); i++) {
        int cursor = (i == sizeof(k_activate_stages) /
                              sizeof(k_activate_stages[0]) - 1)
                         ? m->height        /* tip_finalize */
                         : m->height + 1;   /* upstream stages */
        if (!stage_repair_force_stage_cursor(progress_db, k_activate_stages[i],
                                             cursor))
            return activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                                 "forcing stage cursor %s failed",
                                 k_activate_stages[i]);
    }
    if (!utxo_apply_frontier_set_in_tx(progress_db, m->height + 1))
        return activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                             "setting coins_applied_height failed");

    /* 6. Provenance markers — the tier boundary. MIGRATION_COMPLETE (operational:
     * serve a validated tip + receive) is stamped on BOTH tiers. SELF_FOLDED (the
     * SOVEREIGN bit: mine/spend/export/seed) is stamped ONLY on a sovereign
     * install (!assisted_tier). On an ASSISTED above-checkpoint install the
     * content below the seam is borrowed, so self_folded is WITHHELD and the seam
     * (height + the three manifest commitments) is recorded IN THIS SAME TXN for
     * background promotion to later re-derive and ratify. sync_trust_derive(
     * proven=1, self_folded=0) → RELEASE_ASSISTED_READY. */
    uint8_t one = 1;
    if (!progress_meta_set_in_tx(progress_db, COINS_KV_MIGRATION_COMPLETE_KEY,
                                 &one, 1))
        return activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                             "setting coins migration-complete marker failed");
    if (!assisted_tier) {
        if (!progress_meta_set_in_tx(progress_db, COINS_KV_SELF_FOLDED_KEY,
                                     &one, 1))
            return activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                                 "setting coins self-folded marker failed");
    } else {
        if (!consensus_state_install_record_assisted_seam(
                progress_db, m->height, m->utxo_root, m->anchor_digest,
                m->nullifier_digest))
            return activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                                 "recording assisted-tier promotion seam failed");
        LOG_INFO(ACTIVATE_SUBSYS,
                 "assisted-tier install: migration-complete stamped, self_folded "
                 "WITHHELD, promotion seam recorded at h=%d (RELEASE_ASSISTED "
                 "until background re-derivation ratifies)", m->height);
    }
    if (!progress_meta_delete_in_tx(progress_db,
                                    REDUCER_TRUSTED_BASE_HEIGHT_KEY) ||
        !progress_meta_delete_in_tx(progress_db,
                                    REDUCER_TRUSTED_BASE_HASH_KEY))
        return activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                             "clearing stale trusted-base declaration failed");

    /* 6b. External-seed floor: a bundle install is a genuine external-seed
     * path — the extent at/below m->height was not connected by THIS node,
     * so bg-validation's fresh walk starts above it (no undo data below).
     * Absent-guarded: keep the first declaration — an earlier, lower floor
     * is the conservative start (longer walk, never skips self-derived
     * extent). Advisory: the install must not fail over the marker. */
    if (!reducer_seed_floor_declare_if_absent(progress_db, m->height))
        LOG_WARN(ACTIVATE_SUBSYS,
                 "seed-floor declare failed h=%d (bg-validation will walk "
                 "from genesis — slow, correct)", m->height);

    result->utxo_count = coins;
    result->anchor_count = sprout + sapling;
    result->nullifier_count = nfs;
    return true;
}

/* Recompute every installed state commitment from the destination while the
 * activation transaction is still uncommitted. Source evidence alone is not
 * enough: a retained writer could transiently alter source pages during the
 * stream and restore the source before its final rehash. The destination is
 * the state that will become authoritative, so it must independently reproduce
 * all three manifest commitments and both shielded frontiers. */
static bool activate_verify_destination(
    sqlite3 *progress_db,
    const struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_activate_result *result)
{
    /* Each re-verify phase can be multi-minute on a full bundle; name every one
     * so the phase in flight is never silent (anchors is now tip-Pedersen +
     * byte-floor, no longer a full re-fold). */
    int64_t t = activate_phase_begin("dest_coins", manifest->utxo_count);
    uint8_t got_root[32] = {0};
    int64_t got_count = coins_kv_count(progress_db);
    if (coins_kv_commitment(progress_db, got_root) != 0 ||
        got_count != (int64_t)manifest->utxo_count ||
        memcmp(got_root, manifest->utxo_root, 32) != 0)
        return activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                             "installed destination failed UTXO root/count "
                             "parity (count=%lld want=%llu)",
                             (long long)got_count,
                             (unsigned long long)manifest->utxo_count);
    activate_phase_done("dest_coins", t);

    t = activate_phase_begin("dest_anchors", manifest->anchor_count);
    if (!consensus_state_snapshot_destination_anchors_valid(progress_db,
                                                             manifest))
        return activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                             "installed destination failed anchor digest/"
                             "frontier parity");
    activate_phase_done("dest_anchors", t);

    t = activate_phase_begin("dest_nullifiers", manifest->nullifier_count);
    if (!consensus_state_snapshot_destination_nullifiers_valid(progress_db,
                                                                manifest))
        return activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                             "installed destination failed nullifier digest/"
                             "count parity");
    activate_phase_done("dest_nullifiers", t);
    return true;
}

static bool activate_decision_matches(
    const struct consensus_state_publication_decision_record *decision,
    const struct consensus_state_bundle_manifest *manifest,
    const uint8_t artifact_receipt_digest[32],
    struct consensus_state_activate_result *result)
{
    uint8_t recomputed[32] = {0};
    if (!decision || !manifest ||
        !consensus_state_publication_decision_digest(decision, recomputed) ||
        memcmp(recomputed, decision->decision_digest, 32) != 0 ||
        decision->decision != CONSENSUS_PUBLICATION_ADMIT ||
        decision->refusal != CONSENSUS_PUBLICATION_REFUSAL_NONE ||
        decision->target_lane <= CONSENSUS_STATE_TARGET_LANE_UNKNOWN ||
        decision->target_lane > CONSENSUS_STATE_TARGET_LANE_CANONICAL ||
        decision->bundle_height != manifest->height ||
        memcmp(decision->bundle_hash, manifest->block_hash, 32) != 0 ||
        memcmp(decision->artifact_receipt_digest,
               artifact_receipt_digest, 32) != 0 ||
        decision->validation_profile != manifest->validation_profile)
        return activate_fail(result, CONSENSUS_INSTALL_REFUSED,
                             "durable publication ADMIT record is missing, "
                             "stale, corrupt, or not bound to this artifact");
    return true;
}

static bool activate_verify_terminal_in_tx(
    sqlite3 *progress_db,
    const struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_activate_result *result)
{
    int64_t t = activate_phase_begin("terminal_frontier",
                                     (uint64_t)manifest->height);
    int32_t hstar = -1;
    int32_t served = -1;
    int32_t applied = -1;
    int durable_height = -1;
    uint8_t durable_hash[32] = {0};
    bool applied_found = false;
    if (!reducer_frontier_compute_hstar(progress_db, &hstar, &served) ||
        !coins_kv_get_applied_height(progress_db, &applied, &applied_found) ||
        !tip_finalize_stage_resolve_durable_tip(
            progress_db, &durable_height, durable_hash) ||
        !applied_found || hstar != manifest->height ||
        served != manifest->height || applied != manifest->height + 1 ||
        durable_height != manifest->height ||
        memcmp(durable_hash, manifest->block_hash, 32) != 0) {
        return activate_fail(
            result, CONSENSUS_INSTALL_STORE_ERROR,
            "post-install frontier mismatch H*=%d served=%d "
            "coins_applied=%d durable_tip=%d want=%d/%d/%d/%d",
            hstar, served, applied, durable_height, manifest->height,
            manifest->height, manifest->height + 1, manifest->height);
    }
    for (size_t i = 0;
         i < sizeof(k_activate_stages) / sizeof(k_activate_stages[0]); i++) {
        struct stage_cursor_read_result cursor =
            stage_cursor_read_persisted(progress_db, k_activate_stages[i],
                                        ACTIVATE_SUBSYS);
        uint64_t expected = i + 1 == sizeof(k_activate_stages) /
                                      sizeof(k_activate_stages[0])
                                ? (uint64_t)manifest->height
                                : (uint64_t)manifest->height + 1u;
        if (!cursor.ok || !cursor.found || cursor.cursor != expected) {
            return activate_fail(
                result, CONSENSUS_INSTALL_STORE_ERROR,
                "post-install stage cursor mismatch stage=%s got=%llu want=%llu",
                k_activate_stages[i],
                (unsigned long long)(cursor.found ? cursor.cursor : 0),
                (unsigned long long)expected);
        }
    }
    result->hstar = hstar;
    result->coins_applied_height = applied;
    activate_phase_done("terminal_frontier", t);
    return true;
}

bool consensus_state_snapshot_install_activate(
    sqlite3 *progress_db,
    const struct consensus_state_activate_request *request,
    struct consensus_state_activate_result *result)
{
    if (!result) {
        LOG_WARN(ACTIVATE_SUBSYS, "activation requires a result object");
        return false;
    }
    memset(result, 0, sizeof(*result));
    if (!progress_db || !request || !request->bundle_path ||
        request->datadir_fd < 0 || !request->datadir_display ||
        !request->datadir_display[0])
        return activate_fail(result, CONSENSUS_INSTALL_REFUSED,
                             "invalid progress store/request/bundle/datadir "
                             "capability");
    if (progress_store_db() != progress_db ||
        !progress_store_directory_matches_fd(progress_db,
                                             request->datadir_fd))
        return activate_fail(result, CONSENSUS_INSTALL_REFUSED,
                             "progress store is not the singleton opened "
                             "through the classified datadir capability");

    /* 1. Admit + validate the immutable bundle (recomputes UTXO root/count/
     *    supply, verifies every anchor tree->root, and the nullifier digest). */
    struct consensus_state_artifact_evidence *evidence = NULL;
    struct zcl_result admitted =
        consensus_state_artifact_evidence_open(
            request->bundle_path, request->datadir_fd, &evidence);
    if (!admitted.ok)
        return activate_fail(result, CONSENSUS_INSTALL_REFUSED,
                             "bundle admission failed: %s", admitted.message);

    /* The pathname is only a locator. Authority comes from the exact artifact
     * receipt persisted by the publication CAS (logical digest + whole-file
     * digest + descriptor identity). This closes the ADMIT-to-activate rename
     * window, including replacement by another valid same-height/hash bundle. */
    uint8_t reopened_receipt_digest[32];
    if (!activate_digest_nonzero(
            request->expected_artifact_receipt_digest) ||
        !consensus_state_artifact_evidence_receipt_digest(
            evidence, reopened_receipt_digest) ||
        memcmp(reopened_receipt_digest,
               request->expected_artifact_receipt_digest, 32) != 0) {
        consensus_state_artifact_evidence_free(evidence);
        return activate_fail(result, CONSENSUS_INSTALL_REFUSED,
                             "reopened bundle is not the exact CAS-admitted "
                             "artifact receipt");
    }

    struct consensus_state_bundle_manifest manifest;
    if (!consensus_state_artifact_evidence_manifest_copy(evidence, &manifest)) {
        consensus_state_artifact_evidence_free(evidence);
        return activate_fail(result, CONSENSUS_INSTALL_REFUSED,
                             "artifact evidence became stale after admission");
    }

    /* 2. Caller height/hash assertion (catches selecting the wrong artifact). */
    if (request->expected_height != manifest.height ||
        memcmp(request->expected_block_hash, manifest.block_hash, 32) != 0) {
        consensus_state_artifact_evidence_free(evidence);
        return activate_fail(result, CONSENSUS_INSTALL_REFUSED,
                             "bundle height/hash does not match caller "
                             "assertion");
    }

    struct consensus_state_publication_decision_record admitted_decision;
    memset(&admitted_decision, 0, sizeof(admitted_decision));
    if (request->publication_decision)
        admitted_decision = *request->publication_decision;
    if (!activate_decision_matches(
            request->publication_decision ? &admitted_decision : NULL,
            &manifest, reopened_receipt_digest, result)) {
        consensus_state_artifact_evidence_free(evidence);
        return false; // raw-return-ok:logged-by-activate_fail
    }

    /* 3. ACTIVATE requires a COMPLETE genesis-derived history — a current-only
     *    (positive activation boundary) bundle would reinstate the very gap this
     *    cure closes. Mixed provenance is forbidden. */
    if (!manifest.history_complete || manifest.activation_boundary != 0 ||
        manifest.sprout_source_cursor != 0 ||
        manifest.sapling_source_cursor != 0 ||
        manifest.nullifier_source_cursor != 0 ||
        manifest.source_fold_cursor != (int64_t)manifest.height + 1) {
        consensus_state_artifact_evidence_free(evidence);
        return activate_fail(result, CONSENSUS_INSTALL_REFUSED,
                             "activation requires a complete genesis-derived "
                             "history bundle (no mixed provenance)");
    }

    result->height = manifest.height;

    /* 3b. Fail-closed ignition whitelist (contract: header + authority.c). */
    char contained_reason[192];
    enum consensus_state_activate_authority authority =
        consensus_state_activate_resolve_authority(
            evidence, request->datadir_fd, &manifest, request,
            contained_reason, sizeof(contained_reason));
    if (authority != CONSENSUS_STATE_ACTIVATE_AUTHORITY_RECEIPT &&
        authority != CONSENSUS_STATE_ACTIVATE_AUTHORITY_CHECKPOINT_ROM &&
        authority != CONSENSUS_STATE_ACTIVATE_AUTHORITY_CHECKPOINT_CONTENT &&
        authority != CONSENSUS_STATE_ACTIVATE_AUTHORITY_ASSISTED) {
        consensus_state_artifact_evidence_free(evidence);
        return activate_fail(result, CONSENSUS_INSTALL_VERIFIED_CONTAINED,
                             "%s", contained_reason);
    }
    /* The tier is the RESOLVED authority, the single source of truth for the
     * provenance stamp: ASSISTED (borrowed above-checkpoint) → withhold
     * self_folded; the three sovereign authorities → stamp it. Deriving from the
     * resolved authority (not the raw request flag) STRUCTURALLY prevents a
     * mis-set request from demoting a sovereign install — a compiled-checkpoint /
     * self-validated bundle resolves to RECEIPT/ROM/CONTENT (higher precedence),
     * never ASSISTED. */
    bool install_is_assisted =
        authority == CONSENSUS_STATE_ACTIVATE_AUTHORITY_ASSISTED;

    /* 4. Lease the immutable read transaction (revalidates the pinned file),
     *    then run the one atomic install transaction under the progress-store
     *    tx lock (stage_repair_force_stage_cursor requires both). */
    struct consensus_state_bundle_manifest leased_manifest;
    uint8_t receipt_digest[32];
    sqlite3 *bundle_db = NULL;
    if (!consensus_state_artifact_evidence_candidate_lease_begin(
            evidence, &leased_manifest, receipt_digest, &bundle_db)) {
        consensus_state_artifact_evidence_free(evidence);
        return activate_fail(result, CONSENSUS_INSTALL_REFUSED,
                             "artifact evidence lease refused (stale)");
    }
    if (memcmp(receipt_digest, reopened_receipt_digest, 32) != 0) {
        consensus_state_artifact_evidence_candidate_lease_end(evidence);
        consensus_state_artifact_evidence_free(evidence);
        return activate_fail(result, CONSENSUS_INSTALL_REFUSED,
                             "leased artifact identity differs from the "
                             "CAS-admitted receipt");
    }

    bool ok = true;
    char *err = NULL;
    progress_store_tx_lock();
    sqlite3_int64 backup_data_version = -1;
    sqlite3_int64 backup_changes = -1;
    if (!activate_backup_prior_generation(
            progress_db, request->datadir_fd, request->datadir_display,
            result->prior_generation_path,
            sizeof(result->prior_generation_path), &backup_data_version,
            &backup_changes))
        ok = activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                           "prior-generation backup failed; refusing to "
                           "install without a rollback point");
    if (ok)
        activate_run_after_backup_hook();
    if (ok && sqlite3_exec(progress_db, "BEGIN IMMEDIATE", NULL, NULL, &err)
                  != SQLITE_OK) {
        if (err) { sqlite3_free(err); err = NULL; }
        ok = activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                           "install transaction begin failed");
    }
    sqlite3_int64 begin_data_version = -1;
    if (ok && (!activate_data_version(progress_db, &begin_data_version) ||
               begin_data_version != backup_data_version ||
               sqlite3_total_changes64(progress_db) != backup_changes ||
               !activate_progress_file_unmoved(progress_db)))
        ok = activate_fail(result, CONSENSUS_INSTALL_REFUSED,
                           "progress store changed between prior-generation "
                           "backup and cutover reservation");
    /* Check the durable ADMIT's compare-and-swap frontier while the same
     * BEGIN IMMEDIATE + process lock that spans the cutover is held. */
    int32_t current_frontier = -1;
    uint8_t current_frontier_hash[32] = {0};
    if (ok &&
        (!consensus_state_publication_cas_capture_frontier_locked(
             progress_db, &current_frontier, current_frontier_hash) ||
         !consensus_state_publication_cas_decision_is_current(
             &admitted_decision, current_frontier,
             current_frontier_hash)))
        ok = activate_fail(result, CONSENSUS_INSTALL_REFUSED,
                           "publication ADMIT frontier changed before "
                           "activation (admitted h=%d, live h=%d)",
                           admitted_decision.expected_frontier_height,
                           current_frontier);
    /* Schema creation belongs to the cutover transaction; a failed ensure
     * must leave the pre-install store exactly unchanged. */
    if (ok && (!coins_kv_ensure_schema(progress_db) ||
               !anchor_kv_ensure_schema(progress_db) ||
               !nullifier_kv_ensure_schema(progress_db) ||
               !reducer_frontier_ensure_schema(progress_db)))
        ok = activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                           "ensuring live coin/shielded/frontier schema failed");
    if (ok)
        ok = activate_apply_in_tx(progress_db, bundle_db, &leased_manifest,
                                  install_is_assisted, result);
    if (ok) {
        activate_run_after_stream_hook();
        ok = activate_verify_destination(progress_db, &leased_manifest,
                                         result);
    }
    if (ok && !consensus_state_artifact_evidence_revalidate(evidence)) {
        ok = activate_fail(result, CONSENSUS_INSTALL_REFUSED,
                           "artifact evidence changed during activation "
                           "stream");
    }
    if (ok && activate_consume_fail_seed())
        ok = activate_fail(result, CONSENSUS_INSTALL_INJECTED_FAILURE,
                           "injected tip-finalize seed failure");
    if (ok && !tip_finalize_stage_seed_anchor(
                  leased_manifest.height, leased_manifest.block_hash, true))
        ok = activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                           "tip-finalize anchor seed failed inside cutover "
                           "transaction");
    if (ok && activate_consume_fail_after_seed())
        ok = activate_fail(result, CONSENSUS_INSTALL_INJECTED_FAILURE,
                           "injected post-seed cutover failure");
    if (ok)
        ok = activate_verify_terminal_in_tx(progress_db, &leased_manifest,
                                            result);
    if (ok && !consensus_state_artifact_evidence_revalidate(evidence))
        ok = activate_fail(result, CONSENSUS_INSTALL_REFUSED,
                           "artifact evidence changed before activation "
                           "commit");
    bool outcome_unknown = false;
    if (ok && sqlite3_exec(progress_db, "COMMIT", NULL, NULL, &err)
                  != SQLITE_OK) {
        char commit_detail[128];
        snprintf(commit_detail, sizeof(commit_detail), "%s",
                 err ? err : sqlite3_errmsg(progress_db));
        /* When SQLite leaves the transaction active, an acknowledged
         * ROLLBACK proves the prior generation still owns the store. If
         * autocommit is already on, COMMIT may have committed or auto-rolled
         * back before reporting the I/O error; never guess which. */
        if (sqlite3_get_autocommit(progress_db) == 0) {
            int rrc = sqlite3_exec(progress_db, "ROLLBACK", NULL, NULL, NULL);
            outcome_unknown = rrc != SQLITE_OK ||
                              sqlite3_get_autocommit(progress_db) == 0;
        } else {
            outcome_unknown = true;
        }
        if (outcome_unknown)
            ok = activate_fail(
                result, CONSENSUS_INSTALL_COMMIT_OUTCOME_UNKNOWN,
                "install COMMIT outcome is unknown (%s); stop and inspect "
                "or restore the durable prior generation at %s",
                commit_detail, result->prior_generation_path);
        else
            ok = activate_fail(result, CONSENSUS_INSTALL_STORE_ERROR,
                               "install COMMIT failed and the cutover "
                               "transaction was rolled back (%s)",
                               commit_detail);
        if (err) { sqlite3_free(err); err = NULL; }
    }
    if (!ok && !outcome_unknown &&
        sqlite3_get_autocommit(progress_db) == 0) {
        int rrc = sqlite3_exec(progress_db, "ROLLBACK", NULL, NULL, NULL);
        if (rrc != SQLITE_OK || sqlite3_get_autocommit(progress_db) == 0) {
            outcome_unknown = true;
            (void)activate_fail(
                result, CONSENSUS_INSTALL_COMMIT_OUTCOME_UNKNOWN,
                "install rollback outcome is unknown; stop and inspect or "
                "restore the durable prior generation at %s",
                result->prior_generation_path);
        }
    }
    progress_store_tx_unlock();

    consensus_state_artifact_evidence_candidate_lease_end(evidence);
    consensus_state_artifact_evidence_free(evidence);

    if (!ok) {
        /* On ordinary refusals the transaction was proven rolled back. The
         * typed OUTCOME_UNKNOWN status deliberately makes no such claim and
         * points at the independently durable prior generation. */
        return false; // raw-return-ok:logged-by-activate_fail
    }

    /* The durable bundle superseded any prior refold generation. Refresh the
     * hot-path atomics after commit so a long-lived caller cannot keep normal
     * sync/self-repair suppressed. The terminal boot adapter exits next; a
     * read error already forces the refresh implementation's safe-false cache. */
    if (!refold_progress_refresh(progress_db))
        LOG_WARN(ACTIVATE_SUBSYS,
                 "activated state committed but refold cache refresh logged "
                 "a read failure; normal boot will refresh it again");

    result->status = CONSENSUS_INSTALL_ACTIVATED;
    result->activated = true;
    snprintf(result->reason, sizeof(result->reason),
             "activated %s h=%d coins=%llu anchors=%llu nullifiers=%llu H*=%d "
             "applied=%d authority=%s; prior generation preserved at %s",
             CONSENSUS_STATE_BUNDLE_SCHEMA, manifest.height,
             (unsigned long long)result->utxo_count,
             (unsigned long long)result->anchor_count,
             (unsigned long long)result->nullifier_count, result->hstar,
             result->coins_applied_height,
             consensus_state_activate_authority_name(authority),
             result->prior_generation_path);
    LOG_INFO(ACTIVATE_SUBSYS, "%s", result->reason);
    return true;
}
