/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * wallet_restore_store_sqlite — sqlite implementation of
 * wallet_restore_store_port: inspect a wallet backup file, and merge its
 * rows into an already-open, schema-correct node.db.
 *
 * Writes go through sqlite3_exec / AR_STEP_WRITE on this adapter's own
 * ATTACHed handle (the AR lint gate forbids raw sqlite3_step in app code;
 * sqlite3_exec is the blessed statement-less write path, exactly as the
 * sibling backup adapter uses it).
 *
 * Table and column names interpolated into SQL here are never
 * caller-supplied strings: table names come from the service's fixed
 * WALLET_TABLES list, and column names come from sqlite's own
 * PRAGMA table_info over those tables. Both are validated by
 * wrs_ident_ok() before they reach a format string.
 */

#include "adapters/outbound/persistence/wallet_restore_store_sqlite.h"

#include "util/ar_step_readonly.h"

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* Wallet tables are narrow; 64 columns is far above any of them. */
#define WRS_MAX_COLUMNS 64
#define WRS_IDENT_MAX   64

static inline struct wallet_restore_store_sqlite_ctx *ctx_of(void *self)
{
    return (struct wallet_restore_store_sqlite_ctx *)self;
}

/* A SQL identifier we are willing to interpolate: ASCII letters, digits and
 * underscore, starting with a letter or underscore, non-empty and bounded.
 * Everything reaching a format string in this file passes through here. */
static bool wrs_ident_ok(const char *s)
{
    if (!s || !s[0])
        return false;
    if (!(isalpha((unsigned char)s[0]) || s[0] == '_'))
        return false;
    size_t n = 0;
    for (const char *p = s; *p; p++, n++) {
        if (n >= WRS_IDENT_MAX)
            return false;
        if (!(isalnum((unsigned char)*p) || *p == '_'))
            return false;
    }
    return true;
}

static void wrs_report_init(struct wallet_restore_table_report *r,
                            const char *table)
{
    memset(r, 0, sizeof(*r));
    if (table)
        snprintf(r->table, sizeof(r->table), "%s", table);
    r->in_backup = false;
    r->rows_in_backup = -1;
    r->manifest_present_in_source = false;
    r->manifest_row_count = -1;
    r->rows_before = -1;
    r->rows_inserted = -1;
    r->rows_collided = -1;
    r->rows_rejected = -1;
    r->rows_after = -1;
}

/* "SELECT count(*) FROM <schema>.<table>"; -1 when the statement cannot run
 * (which, for an attached schema, means the table is absent). */
static int64_t wrs_count(sqlite3 *db, const char *schema, const char *table)
{
    if (!db || !wrs_ident_ok(schema) || !wrs_ident_ok(table))
        return -1;
    char sql[192];
    snprintf(sql, sizeof(sql), "SELECT count(*) FROM %s.%s", schema, table);
    sqlite3_stmt *st = NULL;
    int64_t n = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK && st) {
        if (AR_STEP_ROW_READONLY(st) == SQLITE_ROW)
            n = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    return n;
}

static bool wrs_table_exists(sqlite3 *db, const char *schema, const char *table)
{
    if (!db || !wrs_ident_ok(schema) || !wrs_ident_ok(table))
        return false;
    char sql[192];
    snprintf(sql, sizeof(sql),
             "SELECT 1 FROM %s.sqlite_master WHERE type='table' AND name=?",
             schema);
    sqlite3_stmt *st = NULL;
    bool found = false;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK && st) {
        sqlite3_bind_text(st, 1, table, -1, SQLITE_STATIC);
        found = AR_STEP_ROW_READONLY(st) == SQLITE_ROW;
        sqlite3_finalize(st);
    }
    return found;
}

/* Read the manifest row for `table` out of an attached backup schema.
 * Returns false when the file carries no manifest or no row for it. */
static bool wrs_manifest_row(sqlite3 *db, const char *schema,
                             const char *table, bool *out_present,
                             int64_t *out_rows)
{
    if (!wrs_table_exists(db, schema, WALLET_BACKUP_MANIFEST_TABLE))
        return false;
    char sql[256];
    snprintf(sql, sizeof(sql),
             "SELECT present_in_source,row_count FROM %s."
             WALLET_BACKUP_MANIFEST_TABLE " WHERE table_name=?", schema);
    sqlite3_stmt *st = NULL;
    bool got = false;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK && st) {
        sqlite3_bind_text(st, 1, table, -1, SQLITE_STATIC);
        if (AR_STEP_ROW_READONLY(st) == SQLITE_ROW) {
            *out_present = sqlite3_column_int(st, 0) != 0;
            *out_rows = sqlite3_column_int64(st, 1);
            got = true;
        }
        sqlite3_finalize(st);
    }
    return got;
}

/* Column names of <schema>.<table> in declaration order. Returns the count
 * written into `names` (each WRS_IDENT_MAX wide), or -1 on failure. When
 * `pk_flags` is non-NULL it receives 1 for each primary-key column. */
static int wrs_columns(sqlite3 *db, const char *schema, const char *table,
                       char (*names)[WRS_IDENT_MAX], int *pk_flags, int max)
{
    if (!wrs_ident_ok(schema) || !wrs_ident_ok(table))
        return -1;
    char sql[192];
    snprintf(sql, sizeof(sql), "PRAGMA %s.table_info(%s)", schema, table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK || !st) {
        if (st) sqlite3_finalize(st);
        return -1;
    }
    int n = 0;
    while (AR_STEP_ROW_READONLY(st) == SQLITE_ROW && n < max) {
        const unsigned char *nm = sqlite3_column_text(st, 1);
        if (!nm)
            continue;
        snprintf(names[n], WRS_IDENT_MAX, "%s", (const char *)nm);
        if (!wrs_ident_ok(names[n]))
            continue;               /* an identifier we will not interpolate */
        if (pk_flags)
            pk_flags[n] = sqlite3_column_int(st, 5);
        n++;
    }
    sqlite3_finalize(st);
    return n;
}

/* ── inspect ────────────────────────────────────────────────── */

static enum wallet_restore_store_status wrs_inspect_backup(
    void *self,
    const char *backup_path,
    const char *const *tables,
    size_t n_tables,
    struct wallet_restore_table_report *reports,
    char *err, size_t err_cap)
{
    (void)self;
    if (err && err_cap) err[0] = '\0';
    if (reports)
        for (size_t i = 0; i < n_tables; i++)
            wrs_report_init(&reports[i], tables ? tables[i] : NULL);
    if (!backup_path || !reports || (!tables && n_tables > 0)) {
        if (err && err_cap)
            snprintf(err, err_cap, "inspect_backup: null argument");
        return WR_STORE_OPEN_BACKUP_FAILED;
    }

    sqlite3 *db = NULL;
    if (sqlite3_open_v2(backup_path, &db, SQLITE_OPEN_READONLY, NULL)
            != SQLITE_OK) {
        if (err && err_cap)
            snprintf(err, err_cap, "cannot open backup %s: %s", backup_path,
                     db ? sqlite3_errmsg(db) : "open failed");
        if (db) sqlite3_close(db);
        return WR_STORE_OPEN_BACKUP_FAILED;
    }

    /* sqlite3_open_v2 is lazy: a text file opens fine and only fails on the
     * first read. Probe the catalog so "this is not a database" is reported
     * as such rather than as "the backup held no wallet tables". */
    {
        sqlite3_stmt *probe = NULL;
        bool readable = false;
        if (sqlite3_prepare_v2(db, "SELECT count(*) FROM sqlite_master", -1,
                               &probe, NULL) == SQLITE_OK && probe) {
            readable = AR_STEP_ROW_READONLY(probe) == SQLITE_ROW;
            sqlite3_finalize(probe);
        }
        if (!readable) {
            if (err && err_cap)
                snprintf(err, err_cap,
                         "%s is not a readable SQLite database: %s",
                         backup_path, sqlite3_errmsg(db));
            sqlite3_close(db);
            return WR_STORE_OPEN_BACKUP_FAILED;
        }
    }

    for (size_t i = 0; i < n_tables; i++) {
        const char *t = tables[i];
        if (!wrs_ident_ok(t))
            continue;
        reports[i].in_backup = wrs_table_exists(db, "main", t);
        if (reports[i].in_backup)
            reports[i].rows_in_backup = wrs_count(db, "main", t);
        bool mpresent = false;
        int64_t mrows = -1;
        if (wrs_manifest_row(db, "main", t, &mpresent, &mrows)) {
            reports[i].manifest_present_in_source = mpresent;
            reports[i].manifest_row_count = mrows;
        }
    }
    sqlite3_close(db);
    return WR_STORE_OK;
}

/* ── merge ──────────────────────────────────────────────────── */

/* ATTACH `path` as "bak", read-only via the URI form when `read_only` is
 * set. Returns true when the attach succeeded AND the attached file reads
 * as a database (an ATTACH of a non-sqlite file succeeds lazily and only
 * fails on the first read, so probe sqlite_master here). */
static bool wrs_attach(sqlite3 *db, const char *path, bool read_only)
{
    char spec[1200];
    if (read_only)
        snprintf(spec, sizeof(spec), "file:%s?mode=ro", path);
    else
        snprintf(spec, sizeof(spec), "%s", path);

    sqlite3_stmt *att = NULL;
    if (sqlite3_prepare_v2(db, "ATTACH DATABASE ? AS bak", -1, &att, NULL)
            != SQLITE_OK || !att) {
        if (att) sqlite3_finalize(att);
        return false;
    }
    sqlite3_bind_text(att, 1, spec, -1, SQLITE_STATIC);
    bool ok = AR_STEP_ROW_READONLY(att) == SQLITE_DONE;
    sqlite3_finalize(att);
    if (!ok)
        return false;

    sqlite3_stmt *probe = NULL;
    bool readable = false;
    if (sqlite3_prepare_v2(db, "SELECT count(*) FROM bak.sqlite_master", -1,
                           &probe, NULL) == SQLITE_OK && probe) {
        readable = AR_STEP_ROW_READONLY(probe) == SQLITE_ROW;
        sqlite3_finalize(probe);
    }
    if (!readable)
        (void)sqlite3_exec(db, "DETACH DATABASE bak", NULL, NULL, NULL);
    return readable;
}

/* Build "c1,c2,..." over the column names present in BOTH schemas. Returns
 * the number of shared columns, 0 when there is no overlap. */
static int wrs_shared_columns(sqlite3 *db, const char *table,
                              char *out, size_t out_cap,
                              char (*pk_out)[WRS_IDENT_MAX], int pk_max,
                              int *out_n_pk)
{
    char tgt[WRS_MAX_COLUMNS][WRS_IDENT_MAX];
    char bak[WRS_MAX_COLUMNS][WRS_IDENT_MAX];
    int tgt_pk[WRS_MAX_COLUMNS] = {0};
    int n_tgt = wrs_columns(db, "main", table, tgt, tgt_pk, WRS_MAX_COLUMNS);
    int n_bak = wrs_columns(db, "bak", table, bak, NULL, WRS_MAX_COLUMNS);
    if (n_tgt <= 0 || n_bak <= 0)
        return 0;

    out[0] = '\0';
    size_t used = 0;
    int shared = 0;
    int n_pk = 0;
    for (int i = 0; i < n_tgt; i++) {
        bool in_bak = false;
        for (int j = 0; j < n_bak && !in_bak; j++)
            in_bak = strcmp(tgt[i], bak[j]) == 0;
        if (!in_bak)
            continue;
        size_t need = strlen(tgt[i]) + (shared ? 1 : 0);
        if (used + need + 1 >= out_cap)
            return 0;               /* refuse a truncated column list */
        if (shared)
            out[used++] = ',';
        memcpy(out + used, tgt[i], strlen(tgt[i]));
        used += strlen(tgt[i]);
        out[used] = '\0';
        shared++;
        if (tgt_pk[i] > 0 && pk_out && n_pk < pk_max)
            snprintf(pk_out[n_pk++], WRS_IDENT_MAX, "%s", tgt[i]);
    }
    if (out_n_pk)
        *out_n_pk = n_pk;
    return shared;
}

/* How many backup rows have a primary key that already exists in the
 * target. -1 when it cannot be computed (no shared PK columns). */
static int64_t wrs_count_collisions(sqlite3 *db, const char *table,
                                    char (*pk)[WRS_IDENT_MAX], int n_pk)
{
    if (n_pk <= 0)
        return -1;
    char pred[512];
    pred[0] = '\0';
    size_t used = 0;
    for (int i = 0; i < n_pk; i++) {
        char clause[160];
        int n = snprintf(clause, sizeof(clause), "%sm.%s=b.%s",
                         i ? " AND " : "", pk[i], pk[i]);
        if (n < 0 || used + (size_t)n + 1 >= sizeof(pred))
            return -1;
        memcpy(pred + used, clause, (size_t)n + 1);
        used += (size_t)n;
    }
    char sql[1024];
    snprintf(sql, sizeof(sql),
             "SELECT count(*) FROM bak.%s b WHERE EXISTS"
             "(SELECT 1 FROM main.%s m WHERE %s)", table, table, pred);
    sqlite3_stmt *st = NULL;
    int64_t n = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK && st) {
        if (AR_STEP_ROW_READONLY(st) == SQLITE_ROW)
            n = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    return n;
}

/* A target and backup may each carry WKD1 rows only when they name the same
 * wrapped DEK. INSERT OR IGNORE on id=1 would otherwise keep the target
 * wrapper while importing ciphertext encrypted under the backup's different
 * DEK, producing durable but permanently unreadable keys. */
static bool wrs_key_encryption_compatible(sqlite3 *db)
{
    if (!wrs_table_exists(db, "main", "wallet_key_encryption") ||
        !wrs_table_exists(db, "bak", "wallet_key_encryption"))
        return true;
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT m.wrapped_dek=b.wrapped_dek "
        "FROM main.wallet_key_encryption m "
        "CROSS JOIN bak.wallet_key_encryption b "
        "WHERE m.id=1 AND b.id=1";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK || !stmt) {
        if (stmt) sqlite3_finalize(stmt);
        return false;
    }
    int rc = AR_STEP_ROW_READONLY(stmt);
    bool compatible = rc == SQLITE_DONE ||
        (rc == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 1);
    sqlite3_finalize(stmt);
    return compatible;
}

static enum wallet_restore_store_status wrs_merge_into_target(
    void *self,
    const char *backup_path,
    const char *const *tables,
    size_t n_tables,
    bool dry_run,
    struct wallet_restore_table_report *reports,
    char *err, size_t err_cap)
{
    struct wallet_restore_store_sqlite_ctx *c = ctx_of(self);
    if (err && err_cap) err[0] = '\0';
    if (reports)
        for (size_t i = 0; i < n_tables; i++)
            wrs_report_init(&reports[i], tables ? tables[i] : NULL);
    if (!c || !c->target_db) {
        if (err && err_cap)
            snprintf(err, err_cap, "merge: no target connection bound");
        return WR_STORE_NO_TARGET;
    }
    if (!backup_path || !reports || (!tables && n_tables > 0)) {
        if (err && err_cap)
            snprintf(err, err_cap, "merge: null argument");
        return WR_STORE_OPEN_BACKUP_FAILED;
    }

    sqlite3 *db = c->target_db;

    /* ATTACH the backup under alias "bak". Preferred form is the read-only
     * URI — a restore must never be able to write the file it is recovering
     * from — but URI filename handling is a build/connection option, so fall
     * back to the plain path when the URI form is rejected. Nothing below
     * ever writes to `bak` either way. */
    if (!wrs_attach(db, backup_path, /*read_only=*/true) &&
        !wrs_attach(db, backup_path, /*read_only=*/false)) {
        if (err && err_cap)
            snprintf(err, err_cap, "cannot attach backup %s: %s",
                     backup_path, sqlite3_errmsg(db));
        return WR_STORE_ATTACH_FAILED;
    }

    enum wallet_restore_store_status status = WR_STORE_OK;

    if (!wrs_key_encryption_compatible(db)) {
        if (err && err_cap)
            snprintf(err, err_cap,
                     "backup wallet-key encryption identity conflicts with "
                     "the target; restore into a fresh datadir");
        (void)sqlite3_exec(db, "DETACH DATABASE bak", NULL, NULL, NULL);
        return WR_STORE_MERGE_FAILED;
    }

    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        if (err && err_cap)
            snprintf(err, err_cap, "cannot begin restore transaction: %s",
                     sqlite3_errmsg(db));
        (void)sqlite3_exec(db, "DETACH DATABASE bak", NULL, NULL, NULL);
        return WR_STORE_MERGE_FAILED;
    }

    for (size_t i = 0; i < n_tables && status == WR_STORE_OK; i++) {
        const char *t = tables[i];
        if (!wrs_ident_ok(t))
            continue;
        struct wallet_restore_table_report *r = &reports[i];

        bool mpresent = false;
        int64_t mrows = -1;
        if (wrs_manifest_row(db, "bak", t, &mpresent, &mrows)) {
            r->manifest_present_in_source = mpresent;
            r->manifest_row_count = mrows;
        }

        r->rows_before = wrs_count(db, "main", t);
        r->in_backup = wrs_table_exists(db, "bak", t);
        if (!r->in_backup) {
            /* Nothing to merge. Reported, not skipped in silence. */
            r->rows_inserted = 0;
            r->rows_collided = 0;
            r->rows_rejected = 0;
            r->rows_after = r->rows_before;
            continue;
        }
        r->rows_in_backup = wrs_count(db, "bak", t);
        if (r->rows_before < 0) {
            /* The TARGET lacks the table — the caller was supposed to open
             * it through the schema path. Refuse loudly rather than create
             * a constraint-free table behind the operator's back. */
            if (err && err_cap)
                snprintf(err, err_cap,
                         "target has no %s table (open the datadir through "
                         "the node schema first)", t);
            status = WR_STORE_MERGE_FAILED;
            break;
        }

        char cols[2048];
        char pk[8][WRS_IDENT_MAX];
        int n_pk = 0;
        int shared = wrs_shared_columns(db, t, cols, sizeof(cols), pk,
                                        (int)(sizeof(pk) / sizeof(pk[0])),
                                        &n_pk);
        if (shared <= 0) {
            if (err && err_cap)
                snprintf(err, err_cap,
                         "backup %s shares no columns with the target schema",
                         t);
            status = WR_STORE_MERGE_FAILED;
            break;
        }

        r->rows_collided = wrs_count_collisions(db, t, pk, n_pk);

        char sql[4096];
        snprintf(sql, sizeof(sql),
                 "INSERT OR IGNORE INTO main.%s (%s) SELECT %s FROM bak.%s",
                 t, cols, cols, t);
        char *emsg = NULL;
        if (sqlite3_exec(db, sql, NULL, NULL, &emsg) != SQLITE_OK) {
            if (err && err_cap)
                snprintf(err, err_cap, "merge %s: %s", t,
                         emsg ? emsg : "insert failed");
            sqlite3_free(emsg);
            status = WR_STORE_MERGE_FAILED;
            break;
        }
        sqlite3_free(emsg);

        r->rows_after = wrs_count(db, "main", t);
        r->rows_inserted = (r->rows_after >= 0 && r->rows_before >= 0)
                           ? r->rows_after - r->rows_before : -1;
        if (r->rows_inserted >= 0 && r->rows_in_backup >= 0) {
            int64_t collided = r->rows_collided >= 0 ? r->rows_collided : 0;
            int64_t rejected =
                r->rows_in_backup - r->rows_inserted - collided;
            r->rows_rejected = rejected > 0 ? rejected : 0;
        }
    }

    const char *finish = (status == WR_STORE_OK && !dry_run)
                         ? "COMMIT" : "ROLLBACK";
    if (sqlite3_exec(db, finish, NULL, NULL, NULL) != SQLITE_OK &&
        status == WR_STORE_OK) {
        if (err && err_cap)
            snprintf(err, err_cap, "cannot commit restore: %s",
                     sqlite3_errmsg(db));
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        status = WR_STORE_MERGE_FAILED;
    }
    (void)sqlite3_exec(db, "DETACH DATABASE bak", NULL, NULL, NULL);
    return status;
}

bool wallet_restore_store_sqlite_bind(struct wallet_restore_store_sqlite_ctx *ctx,
                                      sqlite3 *target_db,
                                      struct wallet_restore_store_port *out_port)
{
    if (!ctx || !out_port)
        return false;
    ctx->target_db = target_db;
    *out_port = (struct wallet_restore_store_port){
        .self              = ctx,
        .inspect_backup    = wrs_inspect_backup,
        .merge_into_target = wrs_merge_into_target,
    };
    return true;
}
