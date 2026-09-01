/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Incremental UTXO set commitment using XOR-hash accumulator.
 *
 * For each UTXO, we compute SHA256(txid || vout_le || value_le || height_le)
 * and XOR it into a 32-byte accumulator. Since XOR is self-inverse,
 * adding and removing a UTXO are the same operation.
 *
 * This gives O(1) updates per UTXO change, versus O(n) for a full
 * Merkle tree rebuild. The commitment can be verified by computing
 * from scratch over the full UTXO set and comparing. */

#include "coins/utxo_commitment.h"
#include "crypto/sha256.h"
#include "crypto/sha3.h"
#include "util/log_macros.h"
#include <string.h>
#include <stdio.h>
#include <stdatomic.h>
#include <sqlite3.h>
#include "util/ar_step_readonly.h"

/* Log helper for non-bool paths in this file.  `return false` /
 * `return` paths already use LOG_FAIL / bare logging; these void
 * helpers need a log-and-return pattern that LOG_FAIL doesn't fit. */
// obs-ok:prepare-fail-terminal — every call site returns immediately after.
#define UTXO_CMT_LOG_PREPARE(db, sql) \
    fprintf(stderr, "[utxo_cmt] %s:%d %s(): prepare failed: %s " \
            "(sql=%s)\n", __FILE__, __LINE__, __func__, \
            sqlite3_errmsg(db), (sql))

_Atomic bool g_utxo_commitment_skip = false;

/* Hash a single UTXO to 32 bytes via SHA256(txid || vout || value || height) */
static void hash_utxo(uint8_t out[32],
                       const uint8_t txid[32], uint32_t vout,
                       int64_t value, int32_t height)
{
    /* txid(32) + vout(4) + value(8) + height(4) = 48 bytes */
    uint8_t buf[48];
    memcpy(buf, txid, 32);
    buf[32] = (uint8_t)(vout & 0xFF);
    buf[33] = (uint8_t)((vout >> 8) & 0xFF);
    buf[34] = (uint8_t)((vout >> 16) & 0xFF);
    buf[35] = (uint8_t)((vout >> 24) & 0xFF);
    uint64_t v = (uint64_t)value;
    for (int i = 0; i < 8; i++)
        buf[36 + i] = (uint8_t)((v >> (8 * i)) & 0xFF);
    uint32_t h = (uint32_t)height;
    buf[44] = (uint8_t)(h & 0xFF);
    buf[45] = (uint8_t)((h >> 8) & 0xFF);
    buf[46] = (uint8_t)((h >> 16) & 0xFF);
    buf[47] = (uint8_t)((h >> 24) & 0xFF);

    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_write(&ctx, buf, 48);
    sha256_finalize(&ctx, out);
}

/* XOR 32 bytes from src into dst */
static void xor32(uint8_t dst[32], const uint8_t src[32])
{
    for (int i = 0; i < 32; i++)
        dst[i] ^= src[i];
}

void utxo_commitment_init(struct utxo_commitment *uc)
{
    memset(uc->accumulator, 0, 32);
    uc->count = 0;
}

void utxo_commitment_add(struct utxo_commitment *uc,
                          const uint8_t txid[32], uint32_t vout,
                          int64_t value, int32_t height)
{
    if (atomic_load_explicit(&g_utxo_commitment_skip, memory_order_relaxed))
        return;
    uint8_t h[32];
    hash_utxo(h, txid, vout, value, height);
    xor32(uc->accumulator, h);
    uc->count++;
}

void utxo_commitment_remove(struct utxo_commitment *uc,
                             const uint8_t txid[32], uint32_t vout,
                             int64_t value, int32_t height)
{
    if (atomic_load_explicit(&g_utxo_commitment_skip, memory_order_relaxed))
        return;
    uint8_t h[32];
    hash_utxo(h, txid, vout, value, height);
    xor32(uc->accumulator, h);
    if (uc->count > 0) uc->count--;
}

void utxo_commitment_merge(struct utxo_commitment *dst,
                            const struct utxo_commitment *src)
{
    xor32(dst->accumulator, src->accumulator);
    dst->count += src->count;
}

void utxo_commitment_serialize(const struct utxo_commitment *uc,
                                uint8_t buf[UTXO_COMMITMENT_SERIALIZED_SIZE])
{
    memcpy(buf, uc->accumulator, 32);
    uint64_t c = uc->count;
    for (int i = 0; i < 8; i++)
        buf[32 + i] = (uint8_t)((c >> (8 * i)) & 0xFF);
}

bool utxo_commitment_deserialize(struct utxo_commitment *uc,
                                  const uint8_t *buf, size_t len)
{
    if (len < UTXO_COMMITMENT_SERIALIZED_SIZE) return false;
    memcpy(uc->accumulator, buf, 32);
    uc->count = 0;
    for (int i = 0; i < 8; i++)
        uc->count |= (uint64_t)buf[32 + i] << (8 * i);
    return true;
}

bool utxo_commitment_equal(const struct utxo_commitment *a,
                            const struct utxo_commitment *b)
{
    return a->count == b->count &&
           memcmp(a->accumulator, b->accumulator, 32) == 0;
}

/* ── Checkpoint: full UTXO set verification ──────────────── */

void utxo_commitment_compute_db(sqlite3 *db, struct utxo_commitment *out)
{
    utxo_commitment_init(out);
    if (!db) return;

    sqlite3_stmt *s = NULL;
    const char *sql_iter =
        "SELECT txid, vout, value, height FROM utxos "
        "ORDER BY txid, vout";
    if (sqlite3_prepare_v2(db, sql_iter, -1, &s, NULL) != SQLITE_OK) {
        UTXO_CMT_LOG_PREPARE(db, sql_iter);
        return;
    }

    while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
        const uint8_t *txid = (const uint8_t *)sqlite3_column_blob(s, 0);
        if (!txid || sqlite3_column_bytes(s, 0) < 32) continue;
        uint32_t vout = (uint32_t)sqlite3_column_int(s, 1);
        int64_t value = sqlite3_column_int64(s, 2);
        int32_t height = sqlite3_column_int(s, 3);

        uint8_t h[32];
        hash_utxo(h, txid, vout, value, height);
        xor32(out->accumulator, h);
        out->count++;
    }
    sqlite3_finalize(s);
}

bool utxo_commitment_verify_db(sqlite3 *db,
                                const struct utxo_commitment *expected)
{
    if (!db || !expected) return false;
    struct utxo_commitment computed;
    utxo_commitment_compute_db(db, &computed);
    bool ok = utxo_commitment_equal(&computed, expected);
    if (!ok) {
        // obs-ok:mismatch-returned-to-caller — `ok` is returned to caller below.
        fprintf(stderr, "UTXO commitment mismatch: expected count=%lu, "
                "got count=%lu\n",
                (unsigned long)expected->count,
                (unsigned long)computed.count);
    }
    return ok;
}

bool utxo_commitment_save_checkpoint(sqlite3 *db,
                                      const struct utxo_commitment *uc)
{
    if (!db || !uc) return false;
    uint8_t buf[UTXO_COMMITMENT_SERIALIZED_SIZE];
    utxo_commitment_serialize(uc, buf);

    sqlite3_stmt *s = NULL;
    const char *sql_save =
        "INSERT OR REPLACE INTO node_state(key,value) "
        "VALUES('utxo_commitment',?)";
    if (sqlite3_prepare_v2(db, sql_save, -1, &s, NULL) != SQLITE_OK)
        LOG_FAIL("utxo_cmt", "prepare %s: %s",
                 sql_save, sqlite3_errmsg(db));
    sqlite3_bind_blob(s, 1, buf, UTXO_COMMITMENT_SERIALIZED_SIZE, SQLITE_STATIC);
    int rc = AR_STEP_WRITE(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        LOG_FAIL("utxo_cmt", "step utxo_commitment save rc=%d: %s",
                 rc, sqlite3_errmsg(db));

    /* This call makes no covering-height claim — clear any stamp left by a
     * prior _at_height save so a later incremental-maintenance reader
     * (utxo_mirror_delta_apply) never trusts a height that doesn't describe
     * *this* blob. Best-effort: a failure here just leaves behind a height
     * key an _at_height reader will independently invalidate the moment the
     * blob it's paired with stops matching what that height implies. */
    (void)ar_exec_write_sql(db,
        "DELETE FROM node_state WHERE key='" UTXO_COMMITMENT_HEIGHT_KEY "'");
    return true;
}

bool utxo_commitment_load_checkpoint(sqlite3 *db,
                                      struct utxo_commitment *uc)
{
    if (!db || !uc) return false;
    sqlite3_stmt *s = NULL;
    const char *sql_load =
        "SELECT value FROM node_state WHERE key='utxo_commitment'";
    if (sqlite3_prepare_v2(db, sql_load, -1, &s, NULL) != SQLITE_OK)
        LOG_FAIL("utxo_cmt", "prepare %s: %s",
                 sql_load, sqlite3_errmsg(db));

    bool ok = false;
    if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(s, 0);
        int len = sqlite3_column_bytes(s, 0);
        if (blob && len >= UTXO_COMMITMENT_SERIALIZED_SIZE)
            ok = utxo_commitment_deserialize(uc, blob, (size_t)len);
    }
    sqlite3_finalize(s);
    return ok;
}

bool utxo_commitment_save_checkpoint_at_height(sqlite3 *db,
                                               const struct utxo_commitment *uc,
                                               int32_t height)
{
    if (!db || !uc || height < 0) return false;
    uint8_t buf[UTXO_COMMITMENT_SERIALIZED_SIZE];
    utxo_commitment_serialize(uc, buf);

    sqlite3_stmt *s = NULL;
    const char *sql_save =
        "INSERT OR REPLACE INTO node_state(key,value) "
        "VALUES('utxo_commitment',?)";
    if (sqlite3_prepare_v2(db, sql_save, -1, &s, NULL) != SQLITE_OK)
        LOG_FAIL("utxo_cmt", "prepare %s: %s",
                 sql_save, sqlite3_errmsg(db));
    sqlite3_bind_blob(s, 1, buf, UTXO_COMMITMENT_SERIALIZED_SIZE, SQLITE_STATIC);
    int rc = AR_STEP_WRITE(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        LOG_FAIL("utxo_cmt", "step utxo_commitment save rc=%d: %s",
                 rc, sqlite3_errmsg(db));

    sqlite3_stmt *hs = NULL;
    const char *sql_height =
        "INSERT OR REPLACE INTO node_state(key,value) "
        "VALUES('" UTXO_COMMITMENT_HEIGHT_KEY "',?)";
    if (sqlite3_prepare_v2(db, sql_height, -1, &hs, NULL) != SQLITE_OK)
        LOG_FAIL("utxo_cmt", "prepare %s: %s",
                 sql_height, sqlite3_errmsg(db));
    int64_t h64 = (int64_t)height;
    sqlite3_bind_blob(hs, 1, &h64, sizeof(h64), SQLITE_STATIC);
    int hrc = AR_STEP_WRITE(hs);
    sqlite3_finalize(hs);
    if (hrc != SQLITE_DONE)
        LOG_FAIL("utxo_cmt", "step %s save rc=%d: %s",
                 UTXO_COMMITMENT_HEIGHT_KEY, hrc, sqlite3_errmsg(db));
    return true;
}

bool utxo_commitment_load_checkpoint_at_height(sqlite3 *db,
                                               struct utxo_commitment *uc,
                                               int32_t *out_height)
{
    if (!db || !uc || !out_height) return false;
    struct utxo_commitment tmp;
    if (!utxo_commitment_load_checkpoint(db, &tmp))
        return false;

    sqlite3_stmt *s = NULL;
    const char *sql_load =
        "SELECT value FROM node_state WHERE key='" UTXO_COMMITMENT_HEIGHT_KEY "'";
    if (sqlite3_prepare_v2(db, sql_load, -1, &s, NULL) != SQLITE_OK)
        LOG_FAIL("utxo_cmt", "prepare %s: %s",
                 sql_load, sqlite3_errmsg(db));

    bool ok = false;
    int64_t h64 = -1;
    if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(s, 0);
        int len = sqlite3_column_bytes(s, 0);
        if (blob && len >= (int)sizeof(h64)) {
            memcpy(&h64, blob, sizeof(h64));
            ok = h64 >= 0 && h64 <= INT32_MAX;
        }
    }
    sqlite3_finalize(s);
    if (!ok) return false;

    *uc = tmp;
    *out_height = (int32_t)h64;
    return true;
}

bool utxo_commitment_boot_check_and_refresh(sqlite3 *db, int32_t mirror_height,
                                            struct utxo_commitment *out_computed,
                                            bool *out_refreshed)
{
    if (out_refreshed) *out_refreshed = false;
    if (!db) return false;

    /* Fast path: a live-tracked checkpoint (utxo_mirror_delta_apply /
     * mirror_rebuild_from_coins_kv stamp it at every commit that mutates the
     * mirror) whose covering height equals the mirror's OWN persisted cursor
     * is accurate by construction — skip the O(n) `utxos` scan entirely. This
     * is the common case on a cleanly-shut-down node: no refresh, no scan. */
    struct utxo_commitment saved;
    int32_t saved_h = -1;
    if (mirror_height >= 0 &&
        utxo_commitment_load_checkpoint_at_height(db, &saved, &saved_h) &&
        saved_h == mirror_height) {
        if (out_computed) *out_computed = saved;
        return true;
    }

    /* Slow path: no trustworthy height stamp (never tracked, or a torn
     * shutdown left the stamp behind) — recompute and compare/refresh, the
     * pre-existing O(n) safety net for genuinely-stale state. */
    memset(&saved, 0, sizeof(saved));
    if (!utxo_commitment_load_checkpoint(db, &saved))
        return true; /* nothing stored yet — nothing to check */

    struct utxo_commitment computed;
    utxo_commitment_init(&computed);
    utxo_commitment_compute_db(db, &computed);
    if (out_computed) *out_computed = computed;
    if (utxo_commitment_equal(&saved, &computed))
        return true; /* accurate; just never got a height stamp — leave it */

    bool saved_ok = mirror_height >= 0
        ? utxo_commitment_save_checkpoint_at_height(db, &computed, mirror_height)
        : utxo_commitment_save_checkpoint(db, &computed);
    if (saved_ok && out_refreshed) *out_refreshed = true;
    LOG_INFO("utxo_cmt",
             "[utxo_cmt] XOR checkpoint stale (saved_count=%llu computed_count=%llu) "
             "— %s%s",
             (unsigned long long)saved.count, (unsigned long long)computed.count,
             saved_ok ? "refreshed" : "refresh FAILED",
             (saved_ok && mirror_height >= 0) ? " (height-stamped)" : "");
    return saved_ok;
}

bool utxo_commitment_resync_from_db(sqlite3 *db,
                                    struct utxo_commitment *out_optional)
{
    if (!db) return false;
    struct utxo_commitment uc;
    utxo_commitment_init(&uc);
    utxo_commitment_compute_db(db, &uc);
    bool ok = utxo_commitment_save_checkpoint(db, &uc);
    if (ok)
        LOG_INFO("utxo_cmt",
                 "[utxo_cmt] XOR checkpoint resynced from utxos table: count=%llu",
                 (unsigned long long)uc.count);
    else
        LOG_WARN("utxo_cmt",
                 "[utxo_cmt] XOR checkpoint resync save failed (count=%llu)",
                 (unsigned long long)uc.count);
    if (out_optional) *out_optional = uc;
    return ok;
}

/* ── Bounded keyspace-window commitment (state_auditor) ────── */

bool utxo_commitment_compute_range(sqlite3 *db, const char *table,
                                   const uint8_t txid_lo[32], int max_rows,
                                   struct utxo_commitment *out,
                                   size_t *out_rows,
                                   int32_t *out_min_height,
                                   int32_t *out_max_height,
                                   uint8_t out_last_txid[32])
{
    if (out) utxo_commitment_init(out);
    if (out_rows) *out_rows = 0;
    if (out_min_height) *out_min_height = INT32_MAX;
    if (out_max_height) *out_max_height = INT32_MIN;

    if (!db || !out || !txid_lo || max_rows <= 0)
        return false;
    if (!table || (strcmp(table, "coins") != 0 && strcmp(table, "utxos") != 0)) {
        LOG_WARN("utxo_cmt", "compute_range: refusing unknown table '%s'",
                 table ? table : "(null)");
        return false;
    }

    char sql[128];
    snprintf(sql, sizeof(sql),
             "SELECT txid, vout, value, height FROM %s "
             "WHERE txid >= ? ORDER BY txid, vout LIMIT ?", table);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK) {
        UTXO_CMT_LOG_PREPARE(db, sql);
        return false;
    }
    sqlite3_bind_blob(s, 1, txid_lo, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, max_rows);

    size_t n = 0;
    uint8_t last_txid[32] = {0};
    while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
        const uint8_t *txid = (const uint8_t *)sqlite3_column_blob(s, 0);
        if (!txid || sqlite3_column_bytes(s, 0) < 32) continue;
        uint32_t vout = (uint32_t)sqlite3_column_int(s, 1);
        int64_t value = sqlite3_column_int64(s, 2);
        int32_t height = sqlite3_column_int(s, 3);

        uint8_t h[32];
        hash_utxo(h, txid, vout, value, height);
        xor32(out->accumulator, h);
        out->count++;
        n++;
        memcpy(last_txid, txid, 32);
        if (out_min_height && height < *out_min_height) *out_min_height = height;
        if (out_max_height && height > *out_max_height) *out_max_height = height;
    }
    sqlite3_finalize(s);

    if (out_rows) *out_rows = n;
    if (out_last_txid && n > 0) memcpy(out_last_txid, last_txid, 32);
    return true;
}

/* ── SHA3-256 full-set commitment ────────────────────────── */

bool utxo_sha3_serialize_record(uint8_t *buf, size_t buf_cap, size_t *out_len,
                                const uint8_t txid[32], uint32_t vout,
                                int64_t value,
                                const uint8_t *script, uint32_t script_len,
                                uint32_t height, uint8_t is_coinbase)
{
    if (out_len) *out_len = 0;
    if (!buf || !out_len || !txid) return false;

    /* Emit nothing for the script if the pointer is NULL (matches the
     * legacy callers, which gated the script write on `script && len>0`). */
    uint32_t slen = (script != NULL) ? script_len : 0;
    if (buf_cap < UTXO_SHA3_RECORD_MAX(slen)) return false;

    uint8_t *p = buf;
    memcpy(p, txid, 32);                                       p += 32;
    *p++ = (uint8_t)(vout);       *p++ = (uint8_t)(vout >> 8);
    *p++ = (uint8_t)(vout >> 16); *p++ = (uint8_t)(vout >> 24);
    uint64_t v = (uint64_t)value;
    for (int i = 0; i < 8; i++) *p++ = (uint8_t)(v >> (8 * i));
    *p++ = (uint8_t)(slen);       *p++ = (uint8_t)(slen >> 8);
    *p++ = (uint8_t)(slen >> 16); *p++ = (uint8_t)(slen >> 24);
    if (slen > 0) { memcpy(p, script, slen); p += slen; }
    uint32_t ht = height;
    *p++ = (uint8_t)(ht);       *p++ = (uint8_t)(ht >> 8);
    *p++ = (uint8_t)(ht >> 16); *p++ = (uint8_t)(ht >> 24);
    *p++ = (uint8_t)(is_coinbase ? 1 : 0);

    *out_len = (size_t)(p - buf);
    return true;
}

void utxo_commitment_sha3_write_record(struct sha3_256_ctx *ctx,
                                       const uint8_t txid[32], uint32_t vout,
                                       int64_t value,
                                       const uint8_t *script,
                                       uint32_t script_len,
                                       uint32_t height, uint8_t is_coinbase)
{
    if (!ctx || !txid) return;

    uint32_t slen = (script != NULL) ? script_len : 0;

    /* Pack the record into one stack buffer and absorb it in a single write.
     * A sponge does not distinguish write boundaries, so this is byte-for-byte
     * identical to streaming the fields separately — but does one write instead
     * of seven in the hot loop over ~1.3M UTXOs. Real ZCL output scripts fit
     * easily in SCRIPT_INLINE_CAP; the rare oversized script streams the fields
     * field-by-field through the same canonical layout so behavior stays
     * unconditional. */
    enum { SCRIPT_INLINE_CAP = 1024 };
    uint8_t rec[UTXO_SHA3_RECORD_MAX(SCRIPT_INLINE_CAP)];
    size_t rec_len = 0;
    if (utxo_sha3_serialize_record(rec, sizeof(rec), &rec_len,
                                   txid, vout, value, script, slen,
                                   height, is_coinbase)) {
        sha3_256_write(ctx, rec, rec_len);
        return;
    }

    /* Script too large for the inline buffer: stream the fields in the SAME
     * canonical order. */
    sha3_256_write(ctx, txid, 32);
    uint8_t le4[4];
    le4[0] = (uint8_t)(vout);       le4[1] = (uint8_t)(vout >>  8);
    le4[2] = (uint8_t)(vout >> 16); le4[3] = (uint8_t)(vout >> 24);
    sha3_256_write(ctx, le4, 4);
    uint8_t le8[8];
    uint64_t v = (uint64_t)value;
    for (int i = 0; i < 8; i++) le8[i] = (uint8_t)(v >> (8 * i));
    sha3_256_write(ctx, le8, 8);
    le4[0] = (uint8_t)(slen);       le4[1] = (uint8_t)(slen >>  8);
    le4[2] = (uint8_t)(slen >> 16); le4[3] = (uint8_t)(slen >> 24);
    sha3_256_write(ctx, le4, 4);
    if (slen > 0)
        sha3_256_write(ctx, script, (size_t)slen);
    le4[0] = (uint8_t)(height);       le4[1] = (uint8_t)(height >>  8);
    le4[2] = (uint8_t)(height >> 16); le4[3] = (uint8_t)(height >> 24);
    sha3_256_write(ctx, le4, 4);
    uint8_t cb = (uint8_t)(is_coinbase ? 1 : 0);
    sha3_256_write(ctx, &cb, 1);
}

void utxo_commitment_sha3_compute_table(sqlite3 *db, const char *table,
                                        uint8_t out[32],
                                        uint64_t *utxo_count)
{
    memset(out, 0, 32);
    if (utxo_count) *utxo_count = 0;
    if (!db) return;
    if (!table ||
        (strcmp(table, "utxos") != 0 &&
         strcmp(table, "snapshot_staging_utxos") != 0)) {
        fprintf(stderr, "[utxo_cmt] refused SHA3 for invalid table '%s'\n",
                table ? table : "(null)");
        return;
    }

    sqlite3_stmt *s = NULL;
    char sql_sha3[192];
    snprintf(sql_sha3, sizeof(sql_sha3),
             "SELECT txid, vout, value, script, height, is_coinbase"
             " FROM %s ORDER BY txid, vout", table);
    if (sqlite3_prepare_v2(db, sql_sha3, -1, &s, NULL) != SQLITE_OK) {
        UTXO_CMT_LOG_PREPARE(db, sql_sha3);
        return;
    }

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    uint64_t count = 0;

    while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
        const uint8_t *txid = (const uint8_t *)sqlite3_column_blob(s, 0);
        if (!txid || sqlite3_column_bytes(s, 0) < 32) continue;

        uint32_t vout = (uint32_t)sqlite3_column_int(s, 1);
        int64_t value = sqlite3_column_int64(s, 2);
        const uint8_t *script = (const uint8_t *)sqlite3_column_blob(s, 3);
        int script_len = sqlite3_column_bytes(s, 3);
        int32_t height = sqlite3_column_int(s, 4);
        int is_coinbase = sqlite3_column_int(s, 5);

        utxo_commitment_sha3_write_record(&ctx, txid, vout, value,
                                          (script_len > 0) ? script : NULL,
                                          (uint32_t)(script_len > 0 ? script_len : 0),
                                          (uint32_t)height,
                                          (uint8_t)(is_coinbase ? 1 : 0));

        count++;
    }
    sqlite3_finalize(s);

    sha3_256_finalize(&ctx, out);
    if (utxo_count) *utxo_count = count;
}

void utxo_commitment_sha3_compute(sqlite3 *db, uint8_t out[32],
                                   uint64_t *utxo_count)
{
    utxo_commitment_sha3_compute_table(db, "utxos", out, utxo_count);
}

bool utxo_commitment_sha3_save(sqlite3 *db, const uint8_t hash[32],
                                int32_t height, uint64_t count)
{
    if (!db) return false;
    uint8_t buf[44];
    memcpy(buf, hash, 32);
    buf[32] = (uint8_t)(height); buf[33] = (uint8_t)(height >> 8);
    buf[34] = (uint8_t)(height >> 16); buf[35] = (uint8_t)(height >> 24);
    for (int i = 0; i < 8; i++) buf[36 + i] = (uint8_t)(count >> (8 * i));

    sqlite3_stmt *st = NULL;
    const char *sql_sha3_save =
        "INSERT OR REPLACE INTO node_state(key,value) "
        "VALUES('utxo_sha3',?)";
    if (sqlite3_prepare_v2(db, sql_sha3_save, -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("utxo_cmt", "prepare %s: %s",
                 sql_sha3_save, sqlite3_errmsg(db));
    sqlite3_bind_blob(st, 1, buf, 44, SQLITE_STATIC);
    int rc = AR_STEP_WRITE(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        LOG_FAIL("utxo_cmt", "step utxo_sha3 save rc=%d: %s",
                 rc, sqlite3_errmsg(db));
    return true;
}

bool utxo_commitment_sha3_load(sqlite3 *db, uint8_t hash[32],
                                int32_t *height, uint64_t *count)
{
    if (!db) return false;
    sqlite3_stmt *st = NULL;
    const char *sql_sha3_load =
        "SELECT value FROM node_state WHERE key='utxo_sha3'";
    if (sqlite3_prepare_v2(db, sql_sha3_load, -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("utxo_cmt", "prepare %s: %s",
                 sql_sha3_load, sqlite3_errmsg(db));

    bool ok = false;
    if (AR_STEP_ROW_READONLY(st) == SQLITE_ROW) {
        const uint8_t *blob = (const uint8_t *)sqlite3_column_blob(st, 0);
        int len = sqlite3_column_bytes(st, 0);
        if (blob && len >= 44) {
            memcpy(hash, blob, 32);
            if (height)
                *height = (int32_t)blob[32] | ((int32_t)blob[33] << 8) |
                          ((int32_t)blob[34] << 16) | ((int32_t)blob[35] << 24);
            if (count) {
                *count = 0;
                for (int i = 0; i < 8; i++)
                    *count |= (uint64_t)blob[36 + i] << (8 * i);
            }
            ok = true;
        }
    }
    sqlite3_finalize(st);
    return ok;
}

/* ── Full data integrity hash ────────────────────────────── */

/* Hash all rows of a table: stream every column of every row in order
 * into a SHA3-256 context. NULL blobs are hashed as 4 zero bytes. */
static void hash_table(sqlite3 *db, const char *sql, uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK) {
        UTXO_CMT_LOG_PREPARE(db, sql);
        sha3_256_finalize(&ctx, out);
        return;
    }

    int ncols = sqlite3_column_count(s);
    while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
        for (int c = 0; c < ncols; c++) {
            int type = sqlite3_column_type(s, c);
            if (type == SQLITE_BLOB || type == SQLITE_TEXT) {
                const uint8_t *data = (const uint8_t *)sqlite3_column_blob(s, c);
                int len = sqlite3_column_bytes(s, c);
                /* Write length prefix + data */
                uint8_t le4[4];
                uint32_t ulen = (uint32_t)(len > 0 ? len : 0);
                le4[0] = (uint8_t)(ulen); le4[1] = (uint8_t)(ulen >> 8);
                le4[2] = (uint8_t)(ulen >> 16); le4[3] = (uint8_t)(ulen >> 24);
                sha3_256_write(&ctx, le4, 4);
                if (data && len > 0)
                    sha3_256_write(&ctx, data, (size_t)len);
            } else if (type == SQLITE_INTEGER) {
                int64_t val = sqlite3_column_int64(s, c);
                uint8_t le8[8];
                uint64_t v = (uint64_t)val;
                for (int i = 0; i < 8; i++) le8[i] = (uint8_t)(v >> (8 * i));
                sha3_256_write(&ctx, le8, 8);
            } else if (type == SQLITE_FLOAT) {
                double val = sqlite3_column_double(s, c);
                uint8_t buf[8];
                memcpy(buf, &val, 8);
                sha3_256_write(&ctx, buf, 8);
            } else {
                /* NULL — write 4 zero bytes as sentinel */
                uint8_t z[4] = {0};
                sha3_256_write(&ctx, z, 4);
            }
        }
    }
    sqlite3_finalize(s);
    sha3_256_finalize(&ctx, out);
}

void data_integrity_compute(sqlite3 *db, struct data_integrity_detail *out)
{
    memset(out, 0, sizeof(*out));
    if (!db) return;

    /* Hash each consensus-critical table in canonical order.
     * Primary key ordering ensures deterministic results. */

    hash_table(db,
        "SELECT hash,height,prev_hash,version,merkle_root,time,bits,"
        "nonce,num_tx,sapling_value,sprout_value"
        " FROM blocks ORDER BY hash",
        out->blocks);

    hash_table(db,
        "SELECT txid,block_hash,block_height,tx_index,file_num,file_pos,"
        "is_coinbase FROM transactions ORDER BY txid",
        out->transactions);

    hash_table(db,
        "SELECT * FROM tx_inputs ORDER BY rowid",
        out->tx_inputs);

    hash_table(db,
        "SELECT * FROM tx_outputs ORDER BY rowid",
        out->tx_outputs);

    hash_table(db,
        "SELECT txid,vout,value,script,script_type,address_hash,"
        "height,is_coinbase FROM utxos ORDER BY txid,vout",
        out->utxos);

    hash_table(db,
        "SELECT nullifier FROM sapling_nullifiers ORDER BY nullifier",
        out->sapling_nullifiers);

    hash_table(db,
        "SELECT * FROM sapling_outputs ORDER BY rowid",
        out->sapling_outputs);

    hash_table(db,
        "SELECT * FROM sapling_spends ORDER BY rowid",
        out->sapling_spends);

    hash_table(db,
        "SELECT * FROM sprout_nullifiers ORDER BY rowid",
        out->sprout_nullifiers);

    hash_table(db,
        "SELECT * FROM joinsplits ORDER BY rowid",
        out->joinsplits);

    hash_table(db,
        "SELECT token_id,ticker,name,decimals,document_url,"
        "genesis_height,total_minted,total_burned"
        " FROM zslp_tokens ORDER BY token_id",
        out->zslp_tokens);

    hash_table(db,
        "SELECT * FROM zslp_transfers ORDER BY rowid",
        out->zslp_transfers);

    /* Master hash: SHA3-256 of all per-table hashes concatenated */
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, out->blocks, 32);
    sha3_256_write(&ctx, out->transactions, 32);
    sha3_256_write(&ctx, out->tx_inputs, 32);
    sha3_256_write(&ctx, out->tx_outputs, 32);
    sha3_256_write(&ctx, out->utxos, 32);
    sha3_256_write(&ctx, out->sapling_nullifiers, 32);
    sha3_256_write(&ctx, out->sapling_outputs, 32);
    sha3_256_write(&ctx, out->sapling_spends, 32);
    sha3_256_write(&ctx, out->sprout_nullifiers, 32);
    sha3_256_write(&ctx, out->joinsplits, 32);
    sha3_256_write(&ctx, out->zslp_tokens, 32);
    sha3_256_write(&ctx, out->zslp_transfers, 32);
    sha3_256_finalize(&ctx, out->master);
}
