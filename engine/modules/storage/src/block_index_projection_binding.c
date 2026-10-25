/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Crash-safe binding between an embedded-SHA3 block-index flat snapshot and
 * the projection cursor's transactional dirty set. */

#include "block_index_projection_internal.h"
#include "base/hex.h"
#include "storage/event_log_payloads.h"
#include "util/hw_profile.h"
#include "util/log_macros.h"
#include "util/thread_registry.h"

#include <pthread.h>
#include <inttypes.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool block_index_projection_prepare_dirty(struct catch_up_ctx *ctx)
{
    if (sqlite3_prepare_v2(ctx->p->db,
            "INSERT OR IGNORE INTO block_index_dirty(hash) VALUES(?)", -1,
            &ctx->dirty_stmt, NULL) == SQLITE_OK)
        return true;
    fprintf(stderr, // obs-ok:block-index-projection-storage-boundary
            "[block_index_projection] prepare dirty INSERT failed: %s\n",
            sqlite3_errmsg(ctx->p->db));
    return false;
}

bool block_index_projection_mark_dirty(struct catch_up_ctx *ctx,
                                       const uint8_t hash[32])
{
    sqlite3_reset(ctx->dirty_stmt);
    sqlite3_clear_bindings(ctx->dirty_stmt);
    sqlite3_bind_blob(ctx->dirty_stmt, 1, hash, 32, SQLITE_TRANSIENT);
    int rc = sqlite3_step(ctx->dirty_stmt); // raw-sql-ok:kernel-primitive
    if (rc != SQLITE_DONE)
        fprintf(stderr, // obs-ok:block-index-projection-storage-boundary
                "[block_index_projection] dirty INSERT rc=%d: %s\n",
                rc, sqlite3_errmsg(ctx->p->db));
    return rc == SQLITE_DONE;
}

static uint64_t binding_meta_u64(sqlite3 *db, const char *key, uint64_t def)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT v FROM projection_meta WHERE k=?", -1,
                           &stmt, NULL) != SQLITE_OK)
        return def;
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT);
    uint64_t value = def;
    if (sqlite3_step(stmt) == SQLITE_ROW) { // raw-sql-ok:kernel-primitive
        const unsigned char *text = sqlite3_column_text(stmt, 0);
        int len = sqlite3_column_bytes(stmt, 0);
        if (text && text[0] >= '0' && text[0] <= '9') {
            char *end = NULL;
            errno = 0;
            unsigned long long parsed = strtoull((const char *)text, &end, 10);
            if (errno != ERANGE && end == (const char *)text + len)
                value = (uint64_t)parsed;
        }
    }
    sqlite3_finalize(stmt);
    return value;
}

static bool binding_meta_set(sqlite3 *db, const char *key, const char *value)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO projection_meta(k,v) VALUES(?,?)", -1,
            &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, // obs-ok:block-index-projection-storage-boundary
                "[block_index_projection] meta write prepare failed "
                "key=%s: %s\n", key, sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, value, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt); // raw-sql-ok:kernel-primitive
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        fprintf(stderr, // obs-ok:block-index-projection-storage-boundary
                "[block_index_projection] meta write failed key=%s "
                "rc=%d: %s\n", key, rc, sqlite3_errmsg(db));
    return rc == SQLITE_DONE;
}

static bool binding_meta_set_u64(sqlite3 *db, const char *key, uint64_t value)
{
    char text[32];
    snprintf(text, sizeof(text), "%" PRIu64, value);
    return binding_meta_set(db, key, text);
}

static bool binding_meta_text(sqlite3 *db, const char *key,
                              char *out, size_t cap)
{
    sqlite3_stmt *stmt = NULL;
    if (!out || cap == 0 || sqlite3_prepare_v2(db,
            "SELECT v FROM projection_meta WHERE k=?", -1,
            &stmt, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT);
    bool ok = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) { // raw-sql-ok:kernel-primitive
        const unsigned char *text = sqlite3_column_text(stmt, 0);
        int len = sqlite3_column_bytes(stmt, 0);
        if (text && len >= 0 && (size_t)len < cap) {
            memcpy(out, text, (size_t)len);
            out[len] = '\0';
            ok = true;
        }
    }
    sqlite3_finalize(stmt);
    return ok;
}

static bool binding_blob_parse(const void *blob, int len,
                               struct disk_block_index *out)
{
    struct ev_block_header h;
    const uint8_t *solution = NULL;
    if (!blob || len <= 0 ||
        !ev_block_header_parse(blob, (size_t)len, &h, &solution))
        return false;
    disk_block_index_init(out);
    memcpy(out->hashPrev.data, h.hashPrev, 32);
    out->nHeight = h.height; out->nStatus = h.nStatus; out->nTx = h.nTx;
    out->nFile = h.nFile; out->nDataPos = h.nDataPos;
    out->nUndoPos = h.nUndoPos; out->nVersion = h.nVersion;
    memcpy(out->hashMerkleRoot.data, h.hashMerkleRoot, 32);
    memcpy(out->hashFinalSaplingRoot.data, h.hashFinalSaplingRoot, 32);
    out->nTime = h.nTime; out->nBits = h.nBits;
    memcpy(out->nNonce.data, h.nNonce, 32);
    return true;
}

static bool binding_commit(block_index_projection_t *p,
                           const char digest_hex[65], uint64_t size,
                           uint64_t rows)
{
    char number[32];
    bool ok = sqlite3_exec(p->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
    snprintf(number, sizeof(number), "%" PRIu64, p->last_consumed_offset);
    if (ok)
        ok = binding_meta_set(p->db, "flat_payload_sha3", digest_hex) &&
             binding_meta_set_u64(p->db, "flat_payload_size", size) &&
             binding_meta_set_u64(p->db, "flat_row_count", rows) &&
             binding_meta_set(p->db, "flat_covered_offset", number) &&
             sqlite3_exec(p->db, "DELETE FROM block_index_dirty", NULL,
                          NULL, NULL) == SQLITE_OK;
    ok = ok && sqlite3_exec(p->db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
    if (!ok) (void)sqlite3_exec(p->db, "ROLLBACK", NULL, NULL, NULL);
    if (!ok)
        fprintf(stderr, // obs-ok:block-index-projection-storage-boundary
                "[block_index_projection] flat bind transaction "
                "failed: %s\n", sqlite3_errmsg(p->db));
    return ok;
}

bool block_index_projection_bind_flat(block_index_projection_t *p,
                                      const uint8_t digest[32],
                                      uint64_t size, uint64_t rows)
{
    if (!p || !p->db || !digest) {
        fprintf(stderr, // obs-ok:block-index-projection-storage-boundary
                "[block_index_projection] flat bind invalid argument\n");
        return false;
    }
    char digest_hex[65];
    zcl_hex_encode(digest, 32, digest_hex);
    pthread_mutex_lock(&p->mu);
    uint64_t projection_rows = UINT64_MAX;
    sqlite3_stmt *stmt = NULL;
    int count_rc = sqlite3_prepare_v2(p->db,
        "SELECT COUNT(*) FROM block_index", -1, &stmt, NULL);
    if (count_rc == SQLITE_OK) {
        count_rc = sqlite3_step(stmt); // raw-sql-ok:kernel-primitive
        if (count_rc == SQLITE_ROW)
            projection_rows = (uint64_t)sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    if (projection_rows != rows) {
        fprintf(stderr, // obs-ok:block-index-projection-storage-boundary
                "[block_index_projection] flat bind row mismatch "
                "projection=%" PRIu64 " flat=%" PRIu64 " rc=%d\n",
                projection_rows, rows, count_rc);
        pthread_mutex_unlock(&p->mu);
        return false;
    }
    bool ok = binding_commit(p, digest_hex, size, rows);
    pthread_mutex_unlock(&p->mu);
    return ok;
}

/* ---- Parallel full-table coverage proof ------------------------------
 * The shutdown bind verifies every projection row against the frozen
 * in-memory map. The table is WITHOUT ROWID keyed on hash, so it is split on
 * the first hash byte into up to BIND_WORKERS_MAX disjoint key ranges that
 * together cover every possible key. Range 0 runs on the caller's handle,
 * the others on their own read-only connections. A range a worker could not
 * run is verified by the caller afterwards, so the verdict never depends on
 * thread or connection availability. */

#define BIND_WORKERS_MAX        8u
#define BIND_PARALLEL_MIN_ROWS  65536u

enum bind_range_state { BIND_RANGE_NOT_RUN = 0, BIND_RANGE_OK, BIND_RANGE_REFUSED };

struct bind_range {
    const char *path;
    unsigned idx, n;
    uint64_t max_rows;
    block_index_projection_cb covered;
    void *user;
    uint64_t rows;
    int state;
    int rc;
};

#ifdef ZCL_TESTING
static unsigned g_bind_workers_override;

/* Test seam: pin the verify worker count (0 restores the production rule). */
void block_index_projection_bind_workers_for_test(unsigned workers)
{
    g_bind_workers_override = workers;
}
#endif

/* [lo, hi) as blob bounds: an empty lo and a 33-byte 0xFF hi are the open
 * ends (an empty blob sorts below, 33 x 0xFF above, every 32-byte hash). */
static void bind_range_bounds(const struct bind_range *r, uint8_t lo[1],
                              int *lo_len, uint8_t hi[33], int *hi_len)
{
    lo[0] = (uint8_t)((r->idx * 256u) / r->n);
    *lo_len = r->idx == 0 ? 0 : 1;
    hi[0] = (uint8_t)(((r->idx + 1u) * 256u) / r->n);
    *hi_len = 1;
    if (r->idx + 1u == r->n) {
        memset(hi, 0xFF, 33);
        *hi_len = 33;
    }
}

/* One row: parse and apply the coverage callback. */
static bool bind_row_covered(sqlite3_stmt *stmt, block_index_projection_cb cb,
                             void *user)
{
    const void *hash = sqlite3_column_blob(stmt, 0);
    int hash_len = sqlite3_column_bytes(stmt, 0);
    struct disk_block_index idx;
    uint8_t hash_copy[32];
    if (!hash || hash_len != 32 || !binding_blob_parse(
            sqlite3_column_blob(stmt, 1), sqlite3_column_bytes(stmt, 1),
            &idx))
        return false;
    memcpy(hash_copy, hash, sizeof(hash_copy));
    return cb(hash_copy, &idx, user);
}

/* Verify one key range on `db`; sets state OK or REFUSED and the row count. */
static void bind_range_verify(sqlite3 *db, struct bind_range *r)
{
    uint8_t lo[1], hi[33];
    int lo_len, hi_len;
    bind_range_bounds(r, lo, &lo_len, hi, &hi_len);
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT hash,blob FROM block_index WHERE hash>=?1 AND hash<?2",
        -1, &stmt, NULL);
    bool ok = rc == SQLITE_OK;
    if (ok) {
        sqlite3_bind_blob(stmt, 1, lo, lo_len, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 2, hi, hi_len, SQLITE_STATIC);
    }
    r->rows = 0;
    while (ok && (rc = sqlite3_step(stmt)) == SQLITE_ROW) { // raw-sql-ok:kernel-primitive
        r->rows++;
        ok = r->rows <= r->max_rows &&
             bind_row_covered(stmt, r->covered, r->user);
    }
    if (rc != SQLITE_DONE && rc != SQLITE_ROW)
        ok = false;
    sqlite3_finalize(stmt);
    r->rc = rc;
    r->state = ok ? BIND_RANGE_OK : BIND_RANGE_REFUSED;
}

static void *bind_worker_main(void *arg)
{
    struct bind_range *r = arg;
    sqlite3 *db = NULL;
    r->state = BIND_RANGE_NOT_RUN;
    if (sqlite3_open_v2(r->path, &db,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, NULL) == SQLITE_OK &&
        sqlite3_exec(db, "PRAGMA busy_timeout=5000", NULL, NULL, NULL) ==
            SQLITE_OK &&
        sqlite3_exec(db, "PRAGMA query_only=ON", NULL, NULL, NULL) ==
            SQLITE_OK)
        bind_range_verify(db, r);
    if (db)
        sqlite3_close(db);
    return NULL;
}

/* In-memory or unnamed databases cannot be reopened by path. */
static bool bind_path_reopenable(const char *path)
{
    return path && path[0] && strcmp(path, ":memory:") != 0 &&
           strncmp(path, "file::memory:", 13) != 0;
}

static unsigned bind_worker_count(const block_index_projection_t *p,
                                  uint64_t projection_rows)
{
    unsigned want = 0;
#ifdef ZCL_TESTING
    want = g_bind_workers_override;
#endif
    if (!bind_path_reopenable(p->path))
        return 1;
    if (want == 0) {
        int online = hw_profile_online_cores();
        want = online > 0 ? (unsigned)online : 1u;
        if (projection_rows < BIND_PARALLEL_MIN_ROWS)
            want = 1;
    }
    return want > BIND_WORKERS_MAX ? BIND_WORKERS_MAX : want;
}

/* Verify every projection row; true only when each range passed and the
 * rows verified add up to `expect_rows`. */
static bool bind_verify_ranges(block_index_projection_t *p, unsigned n,
                               uint64_t expect_rows, uint64_t max_rows,
                               block_index_projection_cb covered, void *user,
                               uint64_t *verified)
{
    struct bind_range ranges[BIND_WORKERS_MAX];
    pthread_t tids[BIND_WORKERS_MAX];
    bool spawned[BIND_WORKERS_MAX] = {false};
    for (unsigned i = 0; i < n; i++)
        ranges[i] = (struct bind_range){ .path = p->path, .idx = i, .n = n,
            .max_rows = max_rows, .covered = covered, .user = user };
    for (unsigned i = 1; i < n; i++)
        // thread-supervision-ok: bounded read-only verify workers, joined below
        spawned[i] = thread_registry_spawn("bip-bind", bind_worker_main,
                                           &ranges[i], &tids[i]) == 0;
    bind_range_verify(p->db, &ranges[0]);
    for (unsigned i = 1; i < n; i++)
        if (spawned[i])
            pthread_join(tids[i], NULL);
    bool ok = true;
    *verified = 0;
    for (unsigned i = 0; i < n; i++) {
        if (ranges[i].state == BIND_RANGE_NOT_RUN)
            bind_range_verify(p->db, &ranges[i]);
        *verified += ranges[i].rows;
        if (ranges[i].state != BIND_RANGE_OK) {
            ok = false;
            LOG_ERROR("block_index_projection", "covered flat bind range "
                      "%u/%u refused rows=%" PRIu64 " rc=%d", i, n,
                      ranges[i].rows, ranges[i].rc);
        }
    }
    return ok && *verified == expect_rows;
}

static uint64_t bind_count_rows(sqlite3 *db, int *rc_out)
{
    sqlite3_stmt *stmt = NULL;
    uint64_t rows = UINT64_MAX;
    int rc = sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM block_index", -1,
                                &stmt, NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_step(stmt); // raw-sql-ok:kernel-primitive
        if (rc == SQLITE_ROW)
            rows = (uint64_t)sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    *rc_out = rc;
    return rows;
}

unsigned block_index_projection_last_bind_threads(block_index_projection_t *p)
{
    if (!p)
        return 0;
    pthread_mutex_lock(&p->mu);
    unsigned n = p->last_bind_threads;
    pthread_mutex_unlock(&p->mu);
    return n;
}

bool block_index_projection_bind_flat_if_covered(
    block_index_projection_t *p, const uint8_t digest[32], uint64_t size,
    uint64_t rows, block_index_projection_cb covered, void *user)
{
    if (!p || !p->db || !digest || !covered) {
        fprintf(stderr, // obs-ok:block-index-projection-storage-boundary
                "[block_index_projection] covered flat bind invalid argument\n");
        return false;
    }

    char digest_hex[65];
    zcl_hex_encode(digest, 32, digest_hex);
    pthread_mutex_lock(&p->mu);
    int rc = SQLITE_OK;
    uint64_t projection_rows = bind_count_rows(p->db, &rc);
    unsigned n = bind_worker_count(p, projection_rows);
    uint64_t verified = 0;
    p->last_bind_threads = n;
    bool ok = projection_rows <= rows &&
        bind_verify_ranges(p, n, projection_rows, rows, covered, user,
                           &verified);
    if (!ok) {
        fprintf(stderr, // obs-ok:block-index-projection-storage-boundary
                "[block_index_projection] covered flat bind refused "
                "projection=%" PRIu64 " verified=%" PRIu64 " flat=%" PRIu64
                " threads=%u rc=%d\n", projection_rows, verified, rows, n, rc);
        pthread_mutex_unlock(&p->mu);
        return false;
    }
    ok = binding_commit(p, digest_hex, size, rows);
    pthread_mutex_unlock(&p->mu);
    return ok;
}

static bool binding_matches(block_index_projection_t *p,
                            const uint8_t digest[32], uint64_t size,
                            uint64_t rows)
{
    char want[65], got[65];
    zcl_hex_encode(digest, 32, want);
    return binding_meta_text(p->db, "flat_payload_sha3", got, sizeof(got)) &&
           strcmp(got, want) == 0 &&
           binding_meta_u64(p->db, "flat_payload_size", UINT64_MAX) == size &&
           binding_meta_u64(p->db, "flat_row_count", UINT64_MAX) == rows &&
           binding_meta_u64(p->db, "flat_covered_offset", UINT64_MAX) <=
               p->last_consumed_offset;
}

/* Dirty-iterate argument gate: every pointer the scan dereferences. */
static bool bind_dirty_iterate_args_valid(const block_index_projection_t *p,
                                          const uint8_t digest[32],
                                          block_index_projection_cb cb)
{
    return p && p->db && digest && cb;
}

/* One dirty row: copy the hash out and parse the joined blob. False marks a
 * malformed row, which the caller must distinguish from a callback refusal
 * (bind_row_covered merges the two cases). */
static bool bind_dirty_row_parse(sqlite3_stmt *stmt, uint8_t hash_copy[32],
                                 struct disk_block_index *idx)
{
    const void *hash = sqlite3_column_blob(stmt, 0);
    int hash_len = sqlite3_column_bytes(stmt, 0);
    if (!hash || hash_len != 32 || !binding_blob_parse(
            sqlite3_column_blob(stmt, 1), sqlite3_column_bytes(stmt, 1),
            idx))
        return false;
    memcpy(hash_copy, hash, 32);
    return true;
}

/* True when the dirty scan ended on an sqlite step failure rather than a
 * clean DONE or a break with rc still on the current row. */
static bool bind_dirty_scan_step_failed(int result, int rc)
{
    return result == 1 && rc != SQLITE_DONE && rc != SQLITE_ROW;
}

int block_index_projection_iterate_dirty_if_bound(
    block_index_projection_t *p, const uint8_t digest[32], uint64_t size,
    uint64_t rows, block_index_projection_cb cb, void *user)
{
    if (!bind_dirty_iterate_args_valid(p, digest, cb)) {
        fprintf(stderr, // obs-ok:block-index-projection-storage-boundary
                "[block_index_projection] dirty iterate invalid argument\n");
        return -1;
    }
    pthread_mutex_lock(&p->mu);
    if (!binding_matches(p, digest, size, rows)) {
        pthread_mutex_unlock(&p->mu);
        return 0;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(p->db,
        "SELECT d.hash,b.blob FROM block_index_dirty d LEFT JOIN block_index b "
        "ON b.hash=d.hash", -1, &stmt, NULL);
    int result = rc == SQLITE_OK ? 1 : -1;
    if (rc != SQLITE_OK)
        fprintf(stderr, // obs-ok:block-index-projection-storage-boundary
                "[block_index_projection] dirty iterate prepare "
                "failed: %s\n", sqlite3_errmsg(p->db));
    while (result == 1 && (rc = sqlite3_step(stmt)) == SQLITE_ROW) { // raw-sql-ok:kernel-primitive
        struct disk_block_index idx;
        uint8_t hash_copy[32];
        if (!bind_dirty_row_parse(stmt, hash_copy, &idx)) {
            fprintf(stderr, // obs-ok:block-index-projection-storage-boundary
                    "[block_index_projection] malformed bound dirty "
                    "row; refusing partial delta\n");
            result = -1;
            break;
        }
        if (!cb(hash_copy, &idx, user)) break;
    }
    if (bind_dirty_scan_step_failed(result, rc)) {
        fprintf(stderr, // obs-ok:block-index-projection-storage-boundary
                "[block_index_projection] dirty iterate step failed "
                "rc=%d: %s\n", rc, sqlite3_errmsg(p->db));
        result = -1;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&p->mu);
    return result;
}

uint64_t block_index_projection_count(block_index_projection_t *p)
{
    if (!p || !p->db) return 0;
    pthread_mutex_lock(&p->mu);
    sqlite3_stmt *stmt = NULL;
    uint64_t count = 0;
    int rc = sqlite3_prepare_v2(p->db, "SELECT COUNT(*) FROM block_index", -1,
                                &stmt, NULL);
    if (rc == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW) // raw-sql-ok:kernel-primitive
        count = (uint64_t)sqlite3_column_int64(stmt, 0);
    else
        fprintf(stderr, // obs-ok:block-index-projection-storage-boundary
                "[block_index_projection] count failed: %s\n",
                sqlite3_errmsg(p->db));
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&p->mu);
    return count;
}
