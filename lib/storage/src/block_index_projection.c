/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * block_index_projection — SQLite-backed projection over EV_BLOCK_HEADER
 * events. See storage/block_index_projection.h for the contract.
 *
 * Implementation notes
 * --------------------
 * - The projection owns its own sqlite3 handle (one file per
 *   projection, mirroring how progress_store owns progress.kv). This
 *   keeps cursor/catch-up commits off node.db's WAL hot path.
 *
 * - Raw sqlite3_step is used throughout because, like progress_store
 *   and event_log, the projection is a kernel storage primitive that
 *   sits below the AR (ActiveRecord) lifecycle. The `raw-sql-ok:
 *   kernel-primitive` markers carry the same justification.
 *
 * - INSERT OR REPLACE per header: the last EV_BLOCK_HEADER for a given
 *   hash wins. Reorgs that re-emit a header with new nStatus are
 *   naturally handled. The diff tool only checks the *fields* in the
 *   commitment digest, so a status-only update doesn't false-positive.
 *
 * - last_consumed_offset advances after each batch of events. Crash
 *   mid-batch re-consumes the un-committed events on next boot
 *   (idempotent thanks to INSERT OR REPLACE). */

#include "platform/time_compat.h"
#include "storage/block_index_projection.h"
#include "block_index_projection_internal.h"

#include "storage/event_log_payloads.h"
#include "event/event.h"
#include "json/json.h"
#include "util/boot_scan.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "crypto/sha3.h"

#include <inttypes.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BIP_SCHEMA_VERSION  1

/* struct block_index_projection / struct catch_up_ctx / BIP_BATCH_EVENTS
 * live in block_index_projection_internal.h — shared with
 * block_index_projection_status.c's catch_up_apply_status(). */

/* ── singleton glue (boot wires this; native diagnostics read it) ──── */

static _Atomic(block_index_projection_t *) g_singleton = NULL;

block_index_projection_t *block_index_projection_singleton(void)
{
    return atomic_load_explicit(&g_singleton, memory_order_acquire);
}

void block_index_projection_set_singleton(block_index_projection_t *p)
{
    atomic_store_explicit(&g_singleton, p, memory_order_release);
}

/* ── helpers ───────────────────────────────────────────────────────── */

static int64_t wall_now_s(void)
{
    struct timespec ts;
    platform_time_realtime_timespec(&ts);
    return (int64_t)ts.tv_sec;
}

static int64_t mono_now_ms(void)
{
    struct timespec ts;
    platform_time_monotonic_timespec(&ts);
    return (int64_t)ts.tv_sec * 1000 + (int64_t)ts.tv_nsec / 1000000;
}

static void checkpoint_wal(sqlite3 *db, const char *when)
{
    char *err = NULL;
    if (sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE)",
                     NULL, NULL, &err) != SQLITE_OK)
        fprintf(stderr,  // obs-ok:block-index-projection-lifecycle
                "[block_index_projection] checkpoint %s: %s\n",
                when, err ? err : "(no message)");
    if (err) sqlite3_free(err);
}

static bool apply_pragmas(sqlite3 *db)
{
    static const char *const pragmas[] = {
        "PRAGMA journal_mode=WAL",
        "PRAGMA synchronous=NORMAL",
        "PRAGMA foreign_keys=ON",
        "PRAGMA busy_timeout=5000",
        "PRAGMA temp_store=MEMORY",
        NULL,
    };
    for (size_t i = 0; pragmas[i]; i++) {
        char *err = NULL;
        if (sqlite3_exec(db, pragmas[i], NULL, NULL, &err) != SQLITE_OK) {
            fprintf(stderr,  // obs-ok:block-index-projection-open-failure
                    "[block_index_projection] pragma failed (%s): %s\n",
                    pragmas[i], err ? err : "(no message)");
            if (err) sqlite3_free(err);
            return false;
        }
    }
    return true;
}

static bool create_schema(sqlite3 *db)
{
    static const char *const ddls[] = {
        "CREATE TABLE IF NOT EXISTS block_index ("
        "  hash       BLOB PRIMARY KEY,"
        "  height     INTEGER NOT NULL,"
        "  n_status   INTEGER NOT NULL,"
        "  n_file     INTEGER NOT NULL,"
        "  n_data_pos INTEGER NOT NULL,"
        "  n_undo_pos INTEGER NOT NULL,"
        "  n_time     INTEGER NOT NULL,"
        "  n_bits     INTEGER NOT NULL,"
        "  n_version  INTEGER NOT NULL,"
        "  n_tx       INTEGER NOT NULL,"
        "  blob       BLOB NOT NULL"
        ") WITHOUT ROWID",
        "CREATE INDEX IF NOT EXISTS block_index_height_idx "
        "  ON block_index(height)",
        "CREATE TABLE IF NOT EXISTS projection_meta ("
        "  k TEXT PRIMARY KEY,"
        "  v TEXT NOT NULL"
        ")",
        NULL,
    };
    for (size_t i = 0; ddls[i]; i++) {
        char *err = NULL;
        if (sqlite3_exec(db, ddls[i], NULL, NULL, &err) != SQLITE_OK) {
            event_emitf(EV_DB_ERROR, 0,
                "block_index_projection_create_schema ddl_index=%zu errmsg=%s",
                i, err ? err : "(no message)");
            fprintf(stderr,  // obs-ok:block-index-projection-open-failure
                    "[block_index_projection] schema ddl[%zu] failed: %s\n",
                    i, err ? err : "(no message)");
            if (err) sqlite3_free(err);
            return false;
        }
    }
    /* Schema-version sentinel — INSERT OR IGNORE so first open writes,
     * subsequent opens leave the value alone. Future projection schema
     * changes bump this value. */
    char *err = NULL;
    char buf[128];
    snprintf(buf, sizeof(buf),
             "INSERT OR IGNORE INTO projection_meta(k, v) "
             "VALUES('schema_version', '%d')", BIP_SCHEMA_VERSION);
    if (sqlite3_exec(db, buf, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:block-index-projection-open-failure
                "[block_index_projection] schema_version insert failed: %s\n",
                err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

/* Read a u64 from projection_meta or return `def`. */
static uint64_t meta_get_u64(sqlite3 *db, const char *k, uint64_t def)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT v FROM projection_meta WHERE k = ?",
            -1, &stmt, NULL) != SQLITE_OK)
        return def;
    sqlite3_bind_text(stmt, 1, k, -1, SQLITE_TRANSIENT);
    uint64_t v = def;
    if (sqlite3_step(stmt) == SQLITE_ROW) {  // raw-sql-ok:kernel-primitive
        const unsigned char *s = sqlite3_column_text(stmt, 0);
        if (s) {
            char *end = NULL;
            unsigned long long x = strtoull((const char *)s, &end, 10);
            if (end != (const char *)s) v = (uint64_t)x;
        }
    }
    sqlite3_finalize(stmt);
    return v;
}

static bool meta_set_u64(sqlite3 *db, const char *k, uint64_t v)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO projection_meta(k, v) VALUES(?, ?)",
            -1, &stmt, NULL) != SQLITE_OK)
        return false;
    char buf[32];
    snprintf(buf, sizeof(buf), "%" PRIu64, v);
    sqlite3_bind_text(stmt, 1, k,   -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, buf, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);  // raw-sql-ok:kernel-primitive
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

/* ── open / close ──────────────────────────────────────────────────── */

block_index_projection_t *block_index_projection_open(const char *path,
                                                      event_log_t *log)
{
    if (!path || !path[0]) {
        LOG_NULL("block_index_projection", "open: empty path");
    }

    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(path, &db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:block-index-projection-open-failure
                "[block_index_projection] sqlite3_open_v2(%s) failed: %s\n",
                path, db ? sqlite3_errmsg(db) : sqlite3_errstr(rc));
        if (db) sqlite3_close(db);
        return NULL;
    }
    if (!apply_pragmas(db) || !create_schema(db)) {
        sqlite3_close(db);
        return NULL;
    }

    block_index_projection_t *p = (block_index_projection_t *)
        zcl_malloc(sizeof(*p), "block_index_projection/handle");
    if (!p) {
        sqlite3_close(db);
        return NULL;
    }
    memset(p, 0, sizeof(*p));
    p->db  = db;
    p->log = log;
    pthread_mutex_init(&p->mu, NULL);
    snprintf(p->path, sizeof(p->path), "%s", path);
    p->opened_at = wall_now_s();

    /* Restore cursor + counters from prior session. */
    p->last_consumed_offset    = meta_get_u64(db, "last_consumed_offset", 0);
    p->events_consumed_total   = meta_get_u64(db, "events_consumed_total", 0);
    p->replace_collisions_total= meta_get_u64(db, "replace_collisions_total", 0);
    p->last_catch_up_ms        = (int64_t)meta_get_u64(db, "last_catch_up_ms", 0);

    fprintf(stderr,  // obs-ok:block-index-projection-lifecycle
            "[block_index_projection] opened %s (WAL, "
            "last_consumed_offset=%" PRIu64 ", events_total=%" PRIu64 ")\n",
            path, p->last_consumed_offset, p->events_consumed_total);
    return p;
}

void block_index_projection_close(block_index_projection_t *p)
{
    if (!p) return;
    pthread_mutex_lock(&p->mu);
    if (p->db) {
        checkpoint_wal(p->db, "on close");
        int rc = sqlite3_close(p->db);
        if (rc != SQLITE_OK) {
            fprintf(stderr,  // obs-ok:block-index-projection-lifecycle
                    "[block_index_projection] sqlite3_close: rc=%d (%s)\n",
                    rc, sqlite3_errstr(rc));
        } else {
            fprintf(stderr,  // obs-ok:block-index-projection-lifecycle
                    "[block_index_projection] closed %s\n", p->path);
        }
        p->db = NULL;
    }
    pthread_mutex_unlock(&p->mu);
    pthread_mutex_destroy(&p->mu);
    free(p);
}

/* ── catch_up ──────────────────────────────────────────────────────── */

bool batch_begin(struct catch_up_ctx *c)
{
    char *err = NULL;
    if (sqlite3_exec(c->p->db, "BEGIN IMMEDIATE",
                     NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:block-index-projection-catch-up-failure
                "[block_index_projection] BEGIN failed: %s\n",
                err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

bool batch_commit(struct catch_up_ctx *c)
{
    /* Persist the cursor + counters inside the same txn. */
    if (!meta_set_u64(c->p->db, "last_consumed_offset",
                      c->last_offset_after) ||
        !meta_set_u64(c->p->db, "events_consumed_total",
                      c->p->events_consumed_total + c->batch_count) ||
        !meta_set_u64(c->p->db, "replace_collisions_total",
                      c->p->replace_collisions_total + c->collisions)) {
        char *err = NULL;
        sqlite3_exec(c->p->db, "ROLLBACK", NULL, NULL, &err);
        if (err) sqlite3_free(err);
        return false;
    }
    char *err = NULL;
    if (sqlite3_exec(c->p->db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:block-index-projection-catch-up-failure
                "[block_index_projection] COMMIT failed: %s\n",
                err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    /* On commit, update the in-memory counters. */
    c->p->last_consumed_offset       = c->last_offset_after;
    c->p->events_consumed_total     += c->batch_count;
    c->p->replace_collisions_total  += c->collisions;
    c->total_consumed               += c->batch_count;
    c->batch_count                   = 0;
    c->collisions                    = 0;
    return true;
}

/* catch_up_apply_status() (the EV_BLOCK_STATUS consumer) lives in
 * block_index_projection_status.c — split out to keep this file under the
 * file-size ceiling. It shares struct catch_up_ctx + batch_begin/commit via
 * block_index_projection_internal.h. */

/* The event_log_stream callback. Returns false to stop on any error. */
static bool catch_up_cb(uint64_t offset, enum event_log_type type,
                        const void *payload, size_t len, void *user)
{
    struct catch_up_ctx *c = (struct catch_up_ctx *)user;

    /* Always advance the cursor past this event, regardless of type —
     * irrelevant types are simply skipped. */
    uint64_t event_end = offset + EVENT_LOG_FRAME_OVERHEAD + (uint64_t)len;  /* hdr + payload + sentinel */
    c->last_offset_after = event_end;

    if (type == EV_BLOCK_STATUS)
        return catch_up_apply_status(c, payload, len);

    if (type != EV_BLOCK_HEADER) {
        /* Not for us. Don't count it toward the batch (cursor still
         * advances). */
        return true;
    }

    struct ev_block_header h;
    const uint8_t *solution = NULL;
    if (!ev_block_header_parse((const uint8_t *)payload, len, &h, &solution)) {
        fprintf(stderr,  // obs-ok:block-index-projection-catch-up-failure
                "[block_index_projection] parse failed at offset=%" PRIu64
                " (len=%zu)\n", offset, len);
        c->error = true;
        return false;
    }

    /* First event in the batch — open a transaction. */
    if (c->batch_count == 0) {
        if (!batch_begin(c)) {
            c->error = true;
            return false;
        }
    }

    /* Did this hash exist before? (Used for replace_collisions metric.)
     * Statement is prepared once for the whole catch_up (see
     * block_index_projection_catch_up()) and reset+rebound here, mirroring
     * the ins_stmt lifecycle below. */
    bool was_present = false;
    sqlite3_reset(c->exists_stmt);
    sqlite3_clear_bindings(c->exists_stmt);
    sqlite3_bind_blob(c->exists_stmt, 1, h.hash, 32, SQLITE_TRANSIENT);
    if (sqlite3_step(c->exists_stmt) == SQLITE_ROW)  // raw-sql-ok:kernel-primitive
        was_present = true;

    /* INSERT OR REPLACE. */
    sqlite3_reset(c->ins_stmt);
    sqlite3_clear_bindings(c->ins_stmt);
    sqlite3_bind_blob (c->ins_stmt, 1, h.hash, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(c->ins_stmt, 2, (sqlite3_int64)h.height);
    sqlite3_bind_int64(c->ins_stmt, 3, (sqlite3_int64)h.nStatus);
    sqlite3_bind_int64(c->ins_stmt, 4, (sqlite3_int64)h.nFile);
    sqlite3_bind_int64(c->ins_stmt, 5, (sqlite3_int64)h.nDataPos);
    sqlite3_bind_int64(c->ins_stmt, 6, (sqlite3_int64)h.nUndoPos);
    sqlite3_bind_int64(c->ins_stmt, 7, (sqlite3_int64)h.nTime);
    sqlite3_bind_int64(c->ins_stmt, 8, (sqlite3_int64)h.nBits);
    sqlite3_bind_int64(c->ins_stmt, 9, (sqlite3_int64)h.nVersion);
    sqlite3_bind_int64(c->ins_stmt,10, (sqlite3_int64)h.nTx);
    sqlite3_bind_blob (c->ins_stmt,11, payload, (int)len, SQLITE_TRANSIENT);

    int rc = sqlite3_step(c->ins_stmt);  // raw-sql-ok:kernel-primitive
    if (rc != SQLITE_DONE) {
        fprintf(stderr,  // obs-ok:block-index-projection-catch-up-failure
                "[block_index_projection] INSERT step rc=%d (%s)\n",
                rc, sqlite3_errstr(rc));
        char *err = NULL;
        sqlite3_exec(c->p->db, "ROLLBACK", NULL, NULL, &err);
        if (err) sqlite3_free(err);
        c->batch_count = 0;
        c->collisions = 0;
        c->error = true;
        return false;
    }
    c->batch_count++;
    if (was_present) c->collisions++;
    /* O(delta) witness: one header event folded into the projection. On a warm
     * boot this streams only events past the persisted last_consumed_offset —
     * the delta — so this counter tracks new headers, not chain length. A
     * regression that replays from offset 0 on a warm boot balloons it. */
    boot_scan_bump(c->scan_ctr);

    /* Commit periodically. */
    if (c->batch_count >= BIP_BATCH_EVENTS) {
        if (!batch_commit(c)) {
            c->error = true;
            return false;
        }
    }
    return true;
}

uint64_t block_index_projection_catch_up(block_index_projection_t *p)
{
    if (!p || !p->db || !p->log) {
        return (uint64_t)-1;
    }
    pthread_mutex_lock(&p->mu);
    int64_t t0 = mono_now_ms();

    struct catch_up_ctx c = {0};
    c.p = p;
    c.last_offset_after = p->last_consumed_offset;
    c.scan_ctr = boot_scan_counter("block_index_projection.catch_up_events");

    /* Prepare the INSERT statement once for the whole catch_up. */
    if (sqlite3_prepare_v2(p->db,
            "INSERT OR REPLACE INTO block_index"
            "(hash, height, n_status, n_file, n_data_pos, n_undo_pos,"
            " n_time, n_bits, n_version, n_tx, blob) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            -1, &c.ins_stmt, NULL) != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:block-index-projection-catch-up-failure
                "[block_index_projection] prepare INSERT failed: %s\n",
                sqlite3_errmsg(p->db));
        pthread_mutex_unlock(&p->mu);
        return (uint64_t)-1;
    }

    /* Prepare the exists-check SELECT once for the whole catch_up, same
     * lifecycle as ins_stmt above (reset+rebound per event in
     * catch_up_cb(), finalized once below). */
    if (sqlite3_prepare_v2(p->db,
            "SELECT 1 FROM block_index WHERE hash = ? LIMIT 1",
            -1, &c.exists_stmt, NULL) != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:block-index-projection-catch-up-failure
                "[block_index_projection] prepare SELECT failed: %s\n",
                sqlite3_errmsg(p->db));
        sqlite3_finalize(c.ins_stmt);
        pthread_mutex_unlock(&p->mu);
        return (uint64_t)-1;
    }

    /* Prepare the blob-fetch SELECT once for the whole catch_up — used only
     * by EV_BLOCK_STATUS application (catch_up_apply_status) to read back
     * the prior EV_BLOCK_HEADER row it patches. Same reset+rebound lifecycle,
     * finalized once below. */
    if (sqlite3_prepare_v2(p->db,
            "SELECT blob FROM block_index WHERE hash = ?",
            -1, &c.blob_stmt, NULL) != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:block-index-projection-catch-up-failure
                "[block_index_projection] prepare blob SELECT failed: %s\n",
                sqlite3_errmsg(p->db));
        sqlite3_finalize(c.ins_stmt);
        sqlite3_finalize(c.exists_stmt);
        pthread_mutex_unlock(&p->mu);
        return (uint64_t)-1;
    }

    int rc = event_log_stream(p->log, p->last_consumed_offset,
                              catch_up_cb, &c);
    /* Flush trailing batch (if any) — must run even on stream error
     * to checkpoint partial progress, but ONLY if no per-event error
     * occurred (otherwise we rolled back already). */
    if (!c.error && c.batch_count > 0) {
        if (!batch_commit(&c)) {
            c.error = true;
        }
    }
    sqlite3_finalize(c.ins_stmt);
    sqlite3_finalize(c.exists_stmt);
    sqlite3_finalize(c.blob_stmt);

    if (c.status_orphans > 0)
        fprintf(stderr,  // obs-ok:block-index-projection-status-orphans
                "[block_index_projection] %" PRIu64 " EV_BLOCK_STATUS "
                "event(s) had no prior row (durable-log ordering defect; "
                "skipped, cursor still advanced)\n", c.status_orphans);

    /* Always persist last_catch_up_ms (one tiny standalone txn). */
    int64_t elapsed = mono_now_ms() - t0;
    p->last_catch_up_ms = elapsed;
    char *err = NULL;
    if (sqlite3_exec(p->db, "BEGIN IMMEDIATE",
                     NULL, NULL, &err) == SQLITE_OK) {
        meta_set_u64(p->db, "last_catch_up_ms", (uint64_t)elapsed);
        sqlite3_exec(p->db, "COMMIT", NULL, NULL, &err);
    }
    if (err) sqlite3_free(err);

    /* A multi-million-header first catch-up can otherwise leave a WAL as
     * large as the projection itself, making the next boot replay it before
     * RPC can open. No projection statements or transaction remain here. */
    if (rc >= 0 && !c.error && c.total_consumed > 0)
        checkpoint_wal(p->db, "after catch-up");

    pthread_mutex_unlock(&p->mu);

    if (rc < 0 || c.error)
        return (uint64_t)-1;
    return p->last_consumed_offset;
}

/* ── readers ───────────────────────────────────────────────────────── */

/* Parse a `blob` column back into a disk_block_index. */
static bool blob_to_disk_block_index(const uint8_t *blob, size_t blob_len,
                                     struct disk_block_index *out)
{
    struct ev_block_header h;
    const uint8_t *solution = NULL;
    if (!ev_block_header_parse(blob, blob_len, &h, &solution))
        return false;

    disk_block_index_init(out);
    memcpy(out->hashPrev.data, h.hashPrev, 32);
    out->nHeight    = h.height;
    out->nStatus    = h.nStatus;
    out->nTx        = h.nTx;
    out->nFile      = h.nFile;
    out->nDataPos   = h.nDataPos;
    out->nUndoPos   = h.nUndoPos;
    out->nVersion   = h.nVersion;
    memcpy(out->hashMerkleRoot.data, h.hashMerkleRoot, 32);
    memcpy(out->hashFinalSaplingRoot.data, h.hashFinalSaplingRoot, 32);
    out->nTime      = h.nTime;
    out->nBits      = h.nBits;
    memcpy(out->nNonce.data, h.nNonce, 32);
    out->nSolutionSize = h.nSolutionSize;
    if (h.nSolutionSize > 0 && solution) {
        size_t copy = h.nSolutionSize <= sizeof(out->nSolution)
                      ? h.nSolutionSize : sizeof(out->nSolution);
        memcpy(out->nSolution, solution, copy);
    }
    return true;
}

bool block_index_projection_get(block_index_projection_t *p,
                                const uint8_t hash[32],
                                struct disk_block_index *out)
{
    if (!p || !p->db || !hash || !out) return false;
    pthread_mutex_lock(&p->mu);
    sqlite3_stmt *stmt = NULL;
    bool found = false;
    if (sqlite3_prepare_v2(p->db,
            "SELECT blob FROM block_index WHERE hash = ?",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, hash, 32, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {  // raw-sql-ok:kernel-primitive
            const void *blob = sqlite3_column_blob(stmt, 0);
            int blob_len = sqlite3_column_bytes(stmt, 0);
            if (blob && blob_len > 0 &&
                blob_to_disk_block_index((const uint8_t *)blob,
                                         (size_t)blob_len, out)) {
                found = true;
            }
        }
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&p->mu);
    return found;
}

bool block_index_projection_get_by_height(block_index_projection_t *p,
                                          int height,
                                          struct disk_block_index *out)
{
    if (!p || !p->db || !out) return false;
    pthread_mutex_lock(&p->mu);
    sqlite3_stmt *stmt = NULL;
    bool found = false;
    if (sqlite3_prepare_v2(p->db,
            "SELECT blob FROM block_index WHERE height = ? "
            "ORDER BY hash ASC LIMIT 1",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, (sqlite3_int64)height);
        if (sqlite3_step(stmt) == SQLITE_ROW) {  // raw-sql-ok:kernel-primitive
            const void *blob = sqlite3_column_blob(stmt, 0);
            int blob_len = sqlite3_column_bytes(stmt, 0);
            if (blob && blob_len > 0 &&
                blob_to_disk_block_index((const uint8_t *)blob,
                                         (size_t)blob_len, out)) {
                found = true;
            }
        }
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&p->mu);
    return found;
}

static int iterate_query(block_index_projection_t *p,
                         block_index_projection_cb cb, void *user,
                         const char *sql)
{
    if (!p || !p->db || !cb || !sql) return -1;
    pthread_mutex_lock(&p->mu);
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&p->mu);
        return -1;
    }
    int result = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:kernel-primitive
        const void *hashb = sqlite3_column_blob(stmt, 0);
        int hashlen = sqlite3_column_bytes(stmt, 0);
        const void *blob = sqlite3_column_blob(stmt, 1);
        int bloblen = sqlite3_column_bytes(stmt, 1);
        if (!hashb || hashlen != 32 || !blob || bloblen <= 0)
            continue;
        struct disk_block_index dbi;
        if (!blob_to_disk_block_index((const uint8_t *)blob,
                                       (size_t)bloblen, &dbi))
            continue;
        uint8_t hash32[32];
        memcpy(hash32, hashb, 32);
        if (!cb(hash32, &dbi, user))
            break;
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW)
        result = -1;
    pthread_mutex_unlock(&p->mu);
    return result;
}

int block_index_projection_iterate(block_index_projection_t *p,
                                   block_index_projection_cb cb,
                                   void *user)
{
    return iterate_query(p, cb, user,
        "SELECT hash, blob FROM block_index "
        "ORDER BY height ASC, hash ASC");
}

int block_index_projection_iterate_storage_order(
    block_index_projection_t *p, block_index_projection_cb cb, void *user)
{
    return iterate_query(p, cb, user, "SELECT hash, blob FROM block_index");
}

uint64_t block_index_projection_count(block_index_projection_t *p)
{
    if (!p || !p->db) return 0;
    pthread_mutex_lock(&p->mu);
    sqlite3_stmt *stmt = NULL;
    uint64_t n = 0;
    if (sqlite3_prepare_v2(p->db,
            "SELECT COUNT(*) FROM block_index", -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW)  // raw-sql-ok:kernel-primitive
            n = (uint64_t)sqlite3_column_int64(stmt, 0);
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&p->mu);
    return n;
}

/* SHA3-256 over (height, hash) canonical order, absorbing for each
 * entry the same load-bearing fields the diff tool checks. */
int block_index_projection_commitment(block_index_projection_t *p,
                                      uint8_t out[32])
{
    if (!p || !p->db || !out) return -1;
    pthread_mutex_lock(&p->mu);
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(p->db,
            "SELECT hash, height, n_status, n_file, n_data_pos, "
            "       n_undo_pos, n_time, n_bits "
            "FROM block_index "
            "ORDER BY height ASC, hash ASC",
            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&p->mu);
        return -1;
    }
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:kernel-primitive
        const void *hashb = sqlite3_column_blob(stmt, 0);
        int hashlen = sqlite3_column_bytes(stmt, 0);
        if (!hashb || hashlen != 32) continue;

        int32_t  height   = (int32_t)sqlite3_column_int64(stmt, 1);
        uint32_t n_status = (uint32_t)sqlite3_column_int64(stmt, 2);
        int32_t  n_file   = (int32_t)sqlite3_column_int64(stmt, 3);
        uint32_t ndatapos = (uint32_t)sqlite3_column_int64(stmt, 4);
        uint32_t nundopos = (uint32_t)sqlite3_column_int64(stmt, 5);
        uint32_t ntime    = (uint32_t)sqlite3_column_int64(stmt, 6);
        uint32_t nbits    = (uint32_t)sqlite3_column_int64(stmt, 7);

        uint8_t buf[32 + 4*7];
        memcpy(buf, hashb, 32);
        uint8_t *q = buf + 32;
        uint32_t h32 = (uint32_t)height;
        for (int i = 0; i < 4; i++) q[i] = (uint8_t)((h32 >> (i*8)) & 0xFF);
        q += 4;
        for (int i = 0; i < 4; i++) q[i] = (uint8_t)((n_status >> (i*8)) & 0xFF);
        q += 4;
        uint32_t f32 = (uint32_t)n_file;
        for (int i = 0; i < 4; i++) q[i] = (uint8_t)((f32 >> (i*8)) & 0xFF);
        q += 4;
        for (int i = 0; i < 4; i++) q[i] = (uint8_t)((ndatapos >> (i*8)) & 0xFF);
        q += 4;
        for (int i = 0; i < 4; i++) q[i] = (uint8_t)((nundopos >> (i*8)) & 0xFF);
        q += 4;
        for (int i = 0; i < 4; i++) q[i] = (uint8_t)((ntime >> (i*8)) & 0xFF);
        q += 4;
        for (int i = 0; i < 4; i++) q[i] = (uint8_t)((nbits >> (i*8)) & 0xFF);

        sha3_256_write(&h, buf, sizeof(buf));
    }
    sqlite3_finalize(stmt);
    sha3_256_finalize(&h, out);
    pthread_mutex_unlock(&p->mu);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

/* ── diagnostics ───────────────────────────────────────────────────── */

bool block_index_projection_dump_state_json(struct json_value *out,
                                            const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);

    block_index_projection_t *p = block_index_projection_singleton();
    if (!p) {
        json_push_kv_bool(out, "open", false);
        json_push_kv_int (out, "last_consumed_offset", 0);
        json_push_kv_int (out, "entry_count", 0);
        json_push_kv_int (out, "events_consumed_total", 0);
        json_push_kv_int (out, "replace_collisions_total", 0);
        json_push_kv_int (out, "last_catch_up_ms", 0);
        /* Reserved `_health` key — see the non-NULL branch below for the
         * rationale; maps the same "open" signal. */
        diag_push_health(out, false, "block_index_projection not open");
        return true;
    }

    /* Snapshot counters under the lock. */
    pthread_mutex_lock(&p->mu);
    bool is_open                 = (p->db != NULL);
    uint64_t last_offset         = p->last_consumed_offset;
    uint64_t events_consumed     = p->events_consumed_total;
    uint64_t replace_collisions  = p->replace_collisions_total;
    int64_t  last_catch_up_ms    = p->last_catch_up_ms;
    char     path_snap[1024];
    snprintf(path_snap, sizeof(path_snap), "%s", p->path);
    pthread_mutex_unlock(&p->mu);

    /* count() takes the lock itself — call outside. */
    uint64_t cnt = block_index_projection_count(p);

    json_push_kv_bool(out, "open", is_open);
    json_push_kv_str (out, "path", path_snap);
    json_push_kv_int (out, "last_consumed_offset", (int64_t)last_offset);
    json_push_kv_int (out, "entry_count", (int64_t)cnt);
    json_push_kv_int (out, "events_consumed_total", (int64_t)events_consumed);
    json_push_kv_int (out, "replace_collisions_total", (int64_t)replace_collisions);
    json_push_kv_int (out, "last_catch_up_ms", last_catch_up_ms);
    json_push_kv_int (out, "opened_at", p->opened_at);

    /* Reserved `_health` key (see docs/work "Adding state introspection" +
     * app/controllers/src/diagnostics_health_rollup.c): { ok, reason }.
     * Maps the already-computed is_open signal above — no new health
     * logic. */
    diag_push_health(out, is_open,
                     is_open ? "" : "block_index_projection not open");
    return true;
}
