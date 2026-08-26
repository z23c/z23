/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Crash-safe binding between an embedded-SHA3 block-index flat snapshot and
 * the projection cursor's transactional dirty set. */

#include "block_index_projection_internal.h"
#include "base/hex.h"
#include "storage/event_log_payloads.h"

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

bool block_index_projection_bind_flat(block_index_projection_t *p,
                                      const uint8_t digest[32],
                                      uint64_t size, uint64_t rows)
{
    if (!p || !p->db || !digest) {
        fprintf(stderr, // obs-ok:block-index-projection-storage-boundary
                "[block_index_projection] flat bind invalid argument\n");
        return false;
    }
    char digest_hex[65], number[32];
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

int block_index_projection_iterate_dirty_if_bound(
    block_index_projection_t *p, const uint8_t digest[32], uint64_t size,
    uint64_t rows, block_index_projection_cb cb, void *user)
{
    if (!p || !p->db || !digest || !cb) {
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
        const void *hash = sqlite3_column_blob(stmt, 0);
        int hash_len = sqlite3_column_bytes(stmt, 0);
        struct disk_block_index idx;
        uint8_t hash_copy[32];
        if (!hash || hash_len != 32 || !binding_blob_parse(
                sqlite3_column_blob(stmt, 1), sqlite3_column_bytes(stmt, 1),
                &idx)) {
            fprintf(stderr, // obs-ok:block-index-projection-storage-boundary
                    "[block_index_projection] malformed bound dirty "
                    "row; refusing partial delta\n");
            result = -1;
            break;
        }
        memcpy(hash_copy, hash, 32);
        if (!cb(hash_copy, &idx, user)) break;
    }
    if (result == 1 && rc != SQLITE_DONE && rc != SQLITE_ROW) {
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
