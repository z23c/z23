/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * db_maintenance_sqlite — sqlite implementation of db_maintenance_port.
 *
 * The maintenance ops below run sqlite3_exec over a fixed SQL string per
 * op, with the SQLite error message captured into the caller's buffer.
 * The SQL text and the sqlite3_exec / sqlite3_free error handling are the
 * exact exec path so the EV_DB_MAINTENANCE_* surface is identical.
 */

#include "adapters/outbound/persistence/db_maintenance_sqlite.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>

static inline struct db_maintenance_sqlite_ctx *ctx_of(void *self)
{
    return (struct db_maintenance_sqlite_ctx *)self;
}

/* Copy a NUL-terminated error string into the caller's buffer, leaving it
 * a valid C string in every path. Shared by the three ops. */
static void dbm_set_err(char *err, size_t errsz, const char *msg)
{
    if (!err || errsz == 0)
        return;
    snprintf(err, errsz, "%s", msg ? msg : "sqlite error");
}

/* Run one fixed maintenance statement via sqlite3_exec. Returns true on
 * SQLITE_OK; on failure copies the sqlite error text into `err` and frees
 * it. */
static bool dbm_exec(void *self, const char *sql, char *err, size_t errsz)
{
    struct db_maintenance_sqlite_ctx *c = ctx_of(self);
    if (!c || !c->db) {
        dbm_set_err(err, errsz, "db_maint: null or closed db");
        return false;
    }
    char *errmsg = NULL;
    int rc = sqlite3_exec(c->db, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        dbm_set_err(err, errsz, errmsg ? errmsg : "sqlite error");
        sqlite3_free(errmsg);
        return false;
    }
    sqlite3_free(errmsg);
    if (err && errsz)
        err[0] = '\0';
    return true;
}

/* WAL checkpoint, with the numbers that say whether it did anything.
 *
 * `PRAGMA wal_checkpoint(TRUNCATE)` run through sqlite3_exec with a NULL
 * callback throws away its result row — and that row is the whole story:
 * (busy, log, checkpointed). SQLite reports internal contention as
 * SQLITE_OK with busy=1 IN THAT ROW, so a discarded row turns "the
 * checkpoint never ran" into "the checkpoint succeeded". Discarding
 * `checkpointed` likewise makes a pass that moved zero frames identical to
 * one that drained the entire log. sqlite3_wal_checkpoint_v2 hands both
 * numbers back as out-parameters, so that is what this uses. */
static bool dbm_wal_checkpoint(void *self, struct db_maintenance_wal_outcome *out,
                               char *err, size_t errsz)
{
    struct db_maintenance_sqlite_ctx *c = ctx_of(self);

    if (out) {
        out->log_frames = -1;
        out->ckpt_frames = -1;
        out->busy = false;
    }
    if (!c || !c->db) {
        dbm_set_err(err, errsz, "db_maint: null or closed db");
        return false;
    }

    /* PASSIVE first, TRUNCATE second. TRUNCATE reports its counts as 0/0 on
     * success whatever it did — truncation resets the log, so the "after"
     * numbers are always zero — so it can say it succeeded but never how much
     * it reclaimed. PASSIVE returns the real pair and does the frame-moving
     * work; the TRUNCATE that follows only returns the .wal file's blocks to
     * the filesystem, and losing a lock race on THAT step is not a failed
     * checkpoint. */
    int log_frames = -1, ckpt_frames = -1;
    int rc = sqlite3_wal_checkpoint_v2(c->db, NULL,
                                       SQLITE_CHECKPOINT_PASSIVE,
                                       &log_frames, &ckpt_frames);
    if (rc == SQLITE_OK)
        (void)sqlite3_wal_checkpoint_v2(c->db, NULL,
                                        SQLITE_CHECKPOINT_TRUNCATE,
                                        NULL, NULL);
    if (out) {
        out->log_frames = log_frames;
        out->ckpt_frames = ckpt_frames;
        out->busy = (rc == SQLITE_BUSY || rc == SQLITE_LOCKED);
    }
    if (rc != SQLITE_OK) {
        const char *msg = sqlite3_errmsg(c->db);
        dbm_set_err(err, errsz, msg && msg[0] ? msg : "wal checkpoint failed");
        return false;
    }
    if (err && errsz)
        err[0] = '\0';
    return true;
}

static bool dbm_analyze(void *self, char *err, size_t errsz)
{
    return dbm_exec(self, "ANALYZE;", err, errsz);
}

static bool dbm_vacuum(void *self, char *err, size_t errsz)
{
    return dbm_exec(self, "VACUUM;", err, errsz);
}

/* Resolve the wrapped connection's "main" filename, then stat
 * "<path>-wal" — the WAL-size probe. */
static bool dbm_wal_size_bytes(void *self, int64_t *out)
{
    struct db_maintenance_sqlite_ctx *c = ctx_of(self);
    if (!c || !c->db || !out)
        return false;
    const char *db_path = sqlite3_db_filename(c->db, "main");
    if (!db_path || !db_path[0])
        return false;
    char wal_path[1024];
    struct stat st;
    snprintf(wal_path, sizeof(wal_path), "%s-wal", db_path);
    if (stat(wal_path, &st) != 0)
        return false;
    *out = (int64_t)st.st_size;
    return true;
}

bool db_maintenance_sqlite_bind(struct db_maintenance_sqlite_ctx *ctx,
                                sqlite3 *db,
                                struct db_maintenance_port *out_port)
{
    if (!ctx || !out_port)
        return false;
    ctx->db = db;
    *out_port = (struct db_maintenance_port){
        .self           = ctx,
        .wal_checkpoint = dbm_wal_checkpoint,
        .analyze        = dbm_analyze,
        .vacuum         = dbm_vacuum,
        .wal_size_bytes = dbm_wal_size_bytes,
    };
    return true;
}
