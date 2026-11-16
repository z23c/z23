/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * wallet_backup_store_sqlite — sqlite implementation of
 * wallet_backup_store_port.
 *
 * The four methods below are the raw sqlite ops behind the port: EXACT same
 * SQL text, per-table existence probe, open flags, and AR step macros, so
 * the produced backup file and its verification are bit-for-bit identical.
 *
 * Writes: the CREATE TABLE AS SELECT copies go through sqlite3_exec — the
 * AR-compatible exec path (the AR lint gate forbids raw sqlite3_step in app
 * code; sqlite3_exec is the blessed statement-less write path, and the
 * ATTACH step uses the AR_STEP macro). No raw sqlite3_step appears here.
 */

#include "adapters/outbound/persistence/wallet_backup_store_sqlite.h"

#include "platform/private_file.h"
#include "util/ar_step_readonly.h"

#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Upper bound on the requested table list. The wallet table set is a fixed
 * seven (WALLET_TABLES in wallet_backup_service.c); this cap lets the
 * snapshot build its per-table manifest on the stack with no allocation.
 * A caller asking for more is refused rather than silently truncated. */
#define WBS_MAX_TABLES 16

/* SQLite closes the completed snapshot before this runs.  Reopen that exact
 * no-follow pathname, take the private-file lock, drive an authority-grade
 * device barrier, then persist the new directory entry.  On Darwin the file
 * barrier is F_FULLFSYNC rather than ordinary fsync; failure is a failed
 * backup, never a silently weaker success. */
static bool wbs_store_authority_publish(const char *path,
                                        char *out_err, size_t out_err_cap)
{
    char resolved[1024], parent[1024];
    if (!platform_private_destination_resolve(
            path, resolved, sizeof(resolved), parent, sizeof(parent))) {
        if (out_err && out_err_cap)
            snprintf(out_err, out_err_cap,
                     "cannot resolve completed backup path %s", path);
        return false;
    }

    struct platform_private_file file;
    platform_private_file_init(&file);
    if (!platform_private_file_open_locked(resolved, &file)) {
        if (out_err && out_err_cap)
            snprintf(out_err, out_err_cap,
                     "cannot reopen completed backup for authority flush: %s",
                     resolved);
        return false;
    }
    bool ok = platform_private_file_authority_flush(&file);
    platform_private_file_close(&file);
    if (!ok) {
        if (out_err && out_err_cap)
            snprintf(out_err, out_err_cap,
                     "authority durability barrier failed for %s", resolved);
        return false;
    }
    if (!platform_private_parent_flush(parent)) {
        if (out_err && out_err_cap)
            snprintf(out_err, out_err_cap,
                     "backup parent durability barrier failed for %s",
                     parent);
        return false;
    }
    return true;
}

static inline struct wallet_backup_store_sqlite_ctx *ctx_of(void *self)
{
    return (struct wallet_backup_store_sqlite_ctx *)self;
}

/* sqlite3_db_filename(src,"main") — absolute on-disk path of the source.
 * Empty for an in-memory DB. */
static bool wbs_store_source_path(void *self, char *out, size_t cap)
{
    if (out && cap)
        out[0] = '\0';
    struct wallet_backup_store_sqlite_ctx *c = ctx_of(self);
    if (!c || !c->src_db || !out || cap == 0)
        return false;
    const char *p = sqlite3_db_filename(c->src_db, "main");
    if (!p || !*p)
        return false;
    size_t len = strlen(p);
    if (len >= cap) {
        out[0] = '\0';
        return false;
    }
    memcpy(out, p, len + 1);
    return true;
}

/* "SELECT count(*) FROM <table>" over the bound source connection. */
static bool wbs_store_count_rows(void *self, const char *table, int64_t *out)
{
    struct wallet_backup_store_sqlite_ctx *c = ctx_of(self);
    if (!c || !c->src_db || !table || !out)
        return false;
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT count(*) FROM %s", table);
    sqlite3_stmt *st = NULL;
    bool ok = false;
    if (sqlite3_prepare_v2(c->src_db, sql, -1, &st, NULL) == SQLITE_OK && st) {
        if (AR_STEP_ROW_READONLY(st) == SQLITE_ROW) {
            *out = sqlite3_column_int64(st, 0);
            ok = true;
        }
        sqlite3_finalize(st);
    }
    return ok;
}

/* count(*) of `table` in the ATTACHed source over the dst connection.
 * Returns -1 when the statement cannot run. */
static int64_t wbs_store_src_count(sqlite3 *dst, const char *table)
{
    char sql[192];
    snprintf(sql, sizeof(sql), "SELECT count(*) FROM src.%s", table);
    sqlite3_stmt *st = NULL;
    int64_t n = -1;
    if (sqlite3_prepare_v2(dst, sql, -1, &st, NULL) == SQLITE_OK && st) {
        if (AR_STEP_ROW_READONLY(st) == SQLITE_ROW)
            n = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    return n;
}

/* Write WALLET_BACKUP_MANIFEST_TABLE into dst: one row per REQUESTED table,
 * carrying whether the source had it and how many rows were copied. This is
 * what makes a short copy detectable AFTER the fact — a reader can tell
 * "the source had 4 sapling keys and this file has 4" from "the source had
 * 4 and this file has none". */
static bool wbs_store_write_manifest(sqlite3 *dst,
                                     const struct wallet_backup_table_stat *stats,
                                     size_t n_tables)
{
    if (sqlite3_exec(dst, WALLET_BACKUP_MANIFEST_DDL, NULL, NULL, NULL)
            != SQLITE_OK)
        return false;
    sqlite3_stmt *ins = NULL;
    if (sqlite3_prepare_v2(dst,
            "INSERT INTO " WALLET_BACKUP_MANIFEST_TABLE
            "(table_name,present_in_source,row_count) VALUES(?,?,?)",
            -1, &ins, NULL) != SQLITE_OK || !ins) {
        if (ins) sqlite3_finalize(ins);
        return false;
    }
    bool ok = true;
    for (size_t i = 0; i < n_tables && ok; i++) {
        sqlite3_reset(ins);
        sqlite3_bind_text(ins, 1, stats[i].table, -1, SQLITE_STATIC);
        sqlite3_bind_int(ins, 2, stats[i].present_in_source ? 1 : 0);
        sqlite3_bind_int64(ins, 3, stats[i].rows);
        ok = AR_STEP_WRITE(ins) == SQLITE_DONE;
    }
    sqlite3_finalize(ins);
    return ok;
}

/* Open dst, ATTACH source by path, CREATE TABLE AS SELECT per existing
 * table, write the manifest, DETACH, close. */
/* Formats a diagnostic into the caller's buffer when it supplied one. */
static void wbs_err(char *err, size_t err_cap, const char *fmt, ...)
{
    if (!err || !err_cap)
        return;
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(err, err_cap, fmt, ap);
    va_end(ap);
}

static void wbs_stats_init(struct wallet_backup_table_stat *out_stats,
                           const char *const *tables, size_t n_tables)
{
    if (!out_stats)
        return;
    for (size_t i = 0; i < n_tables; i++) {
        out_stats[i].table[0] = '\0';
        if (tables && tables[i])
            snprintf(out_stats[i].table, sizeof(out_stats[i].table),
                     "%s", tables[i]);
        out_stats[i].present_in_source = false;
        out_stats[i].rows = -1;
    }
}

/* ATTACH the source by absolute path under alias "src". */
static bool wbs_attach_source(sqlite3 *dst, const char *src_path)
{
    sqlite3_stmt *att = NULL;
    int rc = sqlite3_prepare_v2(dst, "ATTACH DATABASE ? AS src", -1, &att,
                                NULL);
    if (rc != SQLITE_OK || !att) {
        if (att) sqlite3_finalize(att);
        return false;
    }
    sqlite3_bind_text(att, 1, src_path, -1, SQLITE_STATIC);
    bool done = AR_STEP_ROW_READONLY(att) == SQLITE_DONE;
    sqlite3_finalize(att);
    return done;
}

static bool wbs_source_has_table(sqlite3 *dst, const char *table)
{
    char exists_sql[256];
    snprintf(exists_sql, sizeof(exists_sql),
        "SELECT name FROM src.sqlite_master "
        "WHERE type='table' AND name='%s'", table);
    sqlite3_stmt *chk = NULL;
    bool src_has = false;
    if (sqlite3_prepare_v2(dst, exists_sql, -1, &chk, NULL) == SQLITE_OK && chk) {
        src_has = AR_STEP_ROW_READONLY(chk) == SQLITE_ROW;
        sqlite3_finalize(chk);
    }
    return src_has;
}

#ifdef ZCL_TESTING
/* Fixture-only seam, declared by the wallet-backup fixture: runs after each
 * copied table with the count so far and the file being written. Returning
 * false injects a copy failure at that point; returning true lets the test
 * observe the directory exactly as a crash at that moment would leave it. */
static bool (*_Atomic g_wbs_store_test_copy_hook)(size_t copied,
                                                 const char *dst_path);
void wallet_backup_store_sqlite_test_set_copy_hook(
    bool (*fn)(size_t copied, const char *dst_path))
{
    atomic_store(&g_wbs_store_test_copy_hook, fn);
}
#endif

/* True when the fixture seam (ZCL_TESTING only) asks for a copy failure
 * after `copied` tables; always false in a production build. */
static bool wbs_test_copy_refused(size_t copied, const char *dst_path)
{
#ifdef ZCL_TESTING
    bool (*fn)(size_t, const char *) =
        atomic_load(&g_wbs_store_test_copy_hook);
    return fn && !fn(copied, dst_path);
#else
    (void)copied;
    (void)dst_path;
    return false;
#endif
}

/* For each wallet table, run CREATE TABLE t AS SELECT ... The AS SELECT
 * form copies both schema and rows in one statement. A table the source
 * does not have is not copied — but it IS recorded in `stat` (and hence
 * in the manifest), because "the source never had it" and "the copy
 * dropped it" are the two things a restoring user most needs told apart. */
static bool wbs_copy_tables(sqlite3 *dst, const char *dst_path,
                            const char *const *tables, size_t n_tables,
                            struct wallet_backup_table_stat *stat,
                            char *out_copy_err, size_t copy_err_cap)
{
    size_t copied = 0;
    for (size_t i = 0; i < n_tables; i++) {
        const char *table = tables[i];
        snprintf(stat[i].table, sizeof(stat[i].table), "%s",
                 table ? table : "");
        stat[i].rows = -1;
        if (!wbs_source_has_table(dst, table)) continue;
        stat[i].present_in_source = true;

        char sql[256];
        char *errmsg = NULL;
        snprintf(sql, sizeof(sql),
            "CREATE TABLE %s AS SELECT * FROM src.%s", table, table);
        if (sqlite3_exec(dst, sql, NULL, NULL, &errmsg) != SQLITE_OK) {
            wbs_err(out_copy_err, copy_err_cap, "copy %s: %s", table,
                    errmsg ? errmsg : "?");
            sqlite3_free(errmsg);
            return false;
        }
        stat[i].rows = wbs_store_src_count(dst, table);
        if (wbs_test_copy_refused(++copied, dst_path)) {
            wbs_err(out_copy_err, copy_err_cap,
                    "copy %s: injected test failure after %zu tables",
                    table, copied);
            return false;
        }
    }
    return true;
}

/* Maps the copy, manifest and close outcomes to the snapshot status. */
static enum wallet_backup_store_status wbs_snapshot_status(
    bool all_ok, bool manifest_ok, int close_rc, const char *dst_path,
    char *out_copy_err, size_t copy_err_cap)
{
    if (!all_ok)
        return WB_STORE_COPY_FAILED;
    if (!manifest_ok) {
        wbs_err(out_copy_err, copy_err_cap, "manifest write failed for %s",
                dst_path);
        return WB_STORE_MANIFEST_FAILED;
    }
    if (close_rc != SQLITE_OK ||
        !wbs_store_authority_publish(dst_path, out_copy_err, copy_err_cap)) {
        if (out_copy_err && copy_err_cap && out_copy_err[0] == '\0')
            wbs_err(out_copy_err, copy_err_cap,
                    "close/authority durability failed for %s (sqlite rc=%d)",
                    dst_path, close_rc);
        return WB_STORE_COPY_FAILED;
    }
    return WB_STORE_OK;
}

static enum wallet_backup_store_status wbs_store_write_snapshot(
    void *self,
    const char *dst_path,
    const char *src_path,
    const char *const *tables,
    size_t n_tables,
    struct wallet_backup_table_stat *out_stats,
    char *out_copy_err,
    size_t copy_err_cap)
{
    struct wallet_backup_store_sqlite_ctx *c = ctx_of(self);
    if (out_copy_err && copy_err_cap)
        out_copy_err[0] = '\0';
    wbs_stats_init(out_stats, tables, n_tables);
    if (!c || !dst_path || !src_path || (!tables && n_tables > 0))
        return WB_STORE_OPEN_DST_FAILED;
    if (n_tables > WBS_MAX_TABLES) {
        wbs_err(out_copy_err, copy_err_cap,
                "table list of %zu exceeds the %d-table snapshot cap",
                n_tables, WBS_MAX_TABLES);
        return WB_STORE_COPY_FAILED;
    }

    /* Open the destination as a fresh empty db. */
    sqlite3 *dst = NULL;
    int rc = sqlite3_open_v2(dst_path, &dst,
        SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE, NULL);
    if (rc != SQLITE_OK) {
        if (dst) sqlite3_close(dst);
        unlink(dst_path);
        return WB_STORE_OPEN_DST_FAILED;
    }
    if (!wbs_attach_source(dst, src_path)) {
        sqlite3_close(dst);
        unlink(dst_path);
        return WB_STORE_ATTACH_FAILED;
    }

    struct wallet_backup_table_stat stat[WBS_MAX_TABLES];
    memset(stat, 0, sizeof(stat));
    bool all_ok = wbs_copy_tables(dst, dst_path, tables, n_tables, stat,
                                  out_copy_err, copy_err_cap);

    /* Manifest last, so it describes what actually landed. Only written on a
     * complete copy — a half-copied file must not carry a manifest that
     * would read as authoritative. */
    bool manifest_ok = true;
    if (all_ok)
        manifest_ok = wbs_store_write_manifest(dst, stat, n_tables);

    /* Detach + close. */
    (void)sqlite3_exec(dst, "DETACH DATABASE src", NULL, NULL, NULL);
    int close_rc = sqlite3_close(dst);

    if (out_stats)
        memcpy(out_stats, stat, n_tables * sizeof(stat[0]));

    return wbs_snapshot_status(all_ok, manifest_ok, close_rc, dst_path,
                               out_copy_err, copy_err_cap);
}

/* Reopen a backup file READ-ONLY and count rows in a table; -1 on miss. */
static int64_t wbs_store_count_rows_in_file(void *self,
                                            const char *file_path,
                                            const char *table)
{
    (void)self;
    if (!file_path || !table)
        return -1;
    int64_t n = -1;
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(file_path, &db, SQLITE_OPEN_READONLY, NULL)
            == SQLITE_OK) {
        char sql[128];
        snprintf(sql, sizeof(sql), "SELECT count(*) FROM %s", table);
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK && st) {
            if (AR_STEP_ROW_READONLY(st) == SQLITE_ROW)
                n = sqlite3_column_int64(st, 0);
            sqlite3_finalize(st);
        }
        sqlite3_close(db);
    } else if (db) {
        sqlite3_close(db);
    }
    return n;
}

bool wallet_backup_store_sqlite_bind(struct wallet_backup_store_sqlite_ctx *ctx,
                                     sqlite3 *src_db,
                                     struct wallet_backup_store_port *out_port)
{
    if (!ctx || !out_port)
        return false;
    ctx->src_db = src_db;
    *out_port = (struct wallet_backup_store_port){
        .self               = ctx,
        .source_path        = wbs_store_source_path,
        .count_rows         = wbs_store_count_rows,
        .write_snapshot     = wbs_store_write_snapshot,
        .count_rows_in_file = wbs_store_count_rows_in_file,
    };
    return true;
}
