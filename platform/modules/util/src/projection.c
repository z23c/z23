/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Projection primitive — implementation. See util/projection.h.
 *
 * The handle owns one private sqlite connection. We open it in
 * read-only mode (SQLITE_OPEN_READONLY) so any mistaken write attempt
 * fails loudly at prepare time rather than corrupting the writer's
 * view.
 *
 * After open we BEGIN DEFERRED + SELECT 1 to lock in the snapshot
 * view. Holding that transaction until close gives MVCC snapshot
 * isolation in WAL mode (and shared-lock snapshot isolation in
 * rollback-journal mode). */

#include "util/projection.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct projection {
    sqlite3 *db;
    bool     open;
};

/* ── Helpers ───────────────────────────────────────────────────────── */

/* Run a sentinel SELECT 1 to ensure SQLite materializes the read
 * snapshot view; without it, a deferred transaction defers all locking
 * (and snapshot capture) to the first real query. */
static bool prime_snapshot(sqlite3 *db)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT 1", -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "[projection] prime prepare: %s\n",  // obs-ok:projection-prime-failure
                sqlite3_errmsg(db));
        return false;
    }
    int rc = sqlite3_step(stmt);  // raw-sql-ok:kernel-primitive
    sqlite3_finalize(stmt);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        fprintf(stderr, "[projection] prime step: rc=%d %s\n",  // obs-ok:projection-prime-failure
                rc, sqlite3_errmsg(db));
        return false;
    }
    return true;
}

/* ── Lifecycle ─────────────────────────────────────────────────────── */

projection_t *projection_open(const char *path)
{
    if (!path || path[0] == '\0')
        LOG_NULL("projection", "open: empty path");

    projection_t *p = zcl_calloc(1, sizeof(*p), "projection_t");
    if (!p) LOG_NULL("projection", "open: alloc failed");

    int rc = sqlite3_open_v2(path, &p->db,
                              SQLITE_OPEN_READONLY, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[projection] open '%s': rc=%d %s\n",  // obs-ok:projection-open-failure
                path, rc, p->db ? sqlite3_errmsg(p->db) : "(no handle)");
        if (p->db) sqlite3_close(p->db);
        free(p);
        return NULL;
    }
    sqlite3_busy_timeout(p->db, 1000);

    char *err = NULL;
    if (sqlite3_exec(p->db, "BEGIN DEFERRED", NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "[projection] BEGIN DEFERRED: %s\n",  // obs-ok:projection-begin-failure
                err ? err : "(no message)");
        if (err) sqlite3_free(err);
        sqlite3_close(p->db);
        free(p);
        return NULL;
    }

    if (!prime_snapshot(p->db)) {
        sqlite3_exec(p->db, "ROLLBACK", NULL, NULL, NULL);
        sqlite3_close(p->db);
        free(p);
        return NULL;
    }

    p->open = true;
    return p;
}

void projection_close(projection_t *p)
{
    if (!p) return;
    if (p->db) {
        if (p->open) {
            sqlite3_exec(p->db, "ROLLBACK", NULL, NULL, NULL);
        }
        sqlite3_close(p->db);
    }
    free(p);
}

bool projection_is_open(const projection_t *p)
{
    return p && p->open;
}

/* ── Queries ───────────────────────────────────────────────────────── */

int projection_query_int64(projection_t *p, const char *sql, int64_t *out)
{
    if (!p || !p->open || !sql || !out) {
        fprintf(stderr,  // obs-ok:projection-arg-failure
            "[projection] query_int64: bad arg (p=%p open=%d sql=%p out=%p)\n",
            (void *)p, p ? (int)p->open : -1,
            (const void *)sql, (void *)out);
        return -1;
    }

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "[projection] prepare: %s\n",  // obs-ok:projection-prepare-failure
                sqlite3_errmsg(p->db));
        return -1;
    }

    int rc = sqlite3_step(stmt);  // raw-sql-ok:kernel-primitive
    if (rc != SQLITE_ROW) {
        fprintf(stderr, "[projection] query: no rows (rc=%d)\n",  // obs-ok:projection-no-row
                rc);
        sqlite3_finalize(stmt);
        return -1;
    }
    if (sqlite3_column_count(stmt) < 1) {
        fprintf(stderr, "[projection] query: zero columns\n");  // obs-ok:projection-bad-shape
        sqlite3_finalize(stmt);
        return -1;
    }
    if (sqlite3_column_type(stmt, 0) != SQLITE_INTEGER) {
        fprintf(stderr,  // obs-ok:projection-bad-shape
            "[projection] query: col0 type=%d (want INTEGER)\n",
            sqlite3_column_type(stmt, 0));
        sqlite3_finalize(stmt);
        return -1;
    }
    *out = (int64_t)sqlite3_column_int64(stmt, 0);

    /* Reject multi-row results to keep the typed contract crisp. */
    int rc2 = sqlite3_step(stmt);  // raw-sql-ok:kernel-primitive
    sqlite3_finalize(stmt);
    if (rc2 == SQLITE_ROW) {
        fprintf(stderr,  // obs-ok:projection-bad-shape
            "[projection] query: more than one row, use a richer typed query\n");
        return -1;
    }
    return 0;
}

int projection_query_text(projection_t *p, const char *sql,
                          char *out, size_t out_cap)
{
    if (!p || !p->open || !sql || !out || out_cap == 0) {
        fprintf(stderr,  // obs-ok:projection-arg-failure
            "[projection] query_text: bad arg (p=%p open=%d sql=%p out=%p cap=%zu)\n",
            (void *)p, p ? (int)p->open : -1,
            (const void *)sql, (void *)out, out_cap);
        return -1;
    }
    out[0] = '\0';

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "[projection] prepare: %s\n",  // obs-ok:projection-prepare-failure
                sqlite3_errmsg(p->db));
        return -1;
    }

    int rc = sqlite3_step(stmt);  // raw-sql-ok:kernel-primitive
    if (rc != SQLITE_ROW) {
        fprintf(stderr, "[projection] query_text: no rows (rc=%d)\n",  // obs-ok:projection-no-row
                rc);
        sqlite3_finalize(stmt);
        return -1;
    }
    if (sqlite3_column_count(stmt) < 1) {
        fprintf(stderr, "[projection] query_text: zero columns\n");  // obs-ok:projection-bad-shape
        sqlite3_finalize(stmt);
        return -1;
    }
    if (sqlite3_column_type(stmt, 0) != SQLITE_TEXT) {
        fprintf(stderr,  // obs-ok:projection-bad-shape
            "[projection] query_text: col0 type=%d (want TEXT)\n",
            sqlite3_column_type(stmt, 0));
        sqlite3_finalize(stmt);
        return -1;
    }

    const unsigned char *txt = sqlite3_column_text(stmt, 0);
    snprintf(out, out_cap, "%s", txt ? (const char *)txt : "");

    int rc2 = sqlite3_step(stmt);  // raw-sql-ok:kernel-primitive
    sqlite3_finalize(stmt);
    if (rc2 == SQLITE_ROW) {
        fprintf(stderr,  // obs-ok:projection-bad-shape
            "[projection] query_text: more than one row, use a richer typed query\n");
        out[0] = '\0';
        return -1;
    }
    return 0;
}

int projection_query_double(projection_t *p, const char *sql, double *out)
{
    if (!p || !p->open || !sql || !out) {
        fprintf(stderr,  // obs-ok:projection-arg-failure
            "[projection] query_double: bad arg (p=%p open=%d sql=%p out=%p)\n",
            (void *)p, p ? (int)p->open : -1,
            (const void *)sql, (void *)out);
        return -1;
    }

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "[projection] prepare: %s\n",  // obs-ok:projection-prepare-failure
                sqlite3_errmsg(p->db));
        return -1;
    }

    int rc = sqlite3_step(stmt);  // raw-sql-ok:kernel-primitive
    if (rc != SQLITE_ROW) {
        fprintf(stderr, "[projection] query_double: no rows (rc=%d)\n",  // obs-ok:projection-no-row
                rc);
        sqlite3_finalize(stmt);
        return -1;
    }
    if (sqlite3_column_count(stmt) < 1) {
        fprintf(stderr, "[projection] query_double: zero columns\n");  // obs-ok:projection-bad-shape
        sqlite3_finalize(stmt);
        return -1;
    }
    int typ = sqlite3_column_type(stmt, 0);
    if (typ != SQLITE_FLOAT && typ != SQLITE_INTEGER) {
        fprintf(stderr,  // obs-ok:projection-bad-shape
            "[projection] query_double: col0 type=%d (want REAL)\n", typ);
        sqlite3_finalize(stmt);
        return -1;
    }
    *out = sqlite3_column_double(stmt, 0);

    int rc2 = sqlite3_step(stmt);  // raw-sql-ok:kernel-primitive
    sqlite3_finalize(stmt);
    if (rc2 == SQLITE_ROW) {
        fprintf(stderr,  // obs-ok:projection-bad-shape
            "[projection] query_double: more than one row, use a richer typed query\n");
        return -1;
    }
    return 0;
}
