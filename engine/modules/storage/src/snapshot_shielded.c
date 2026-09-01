/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * snapshot_shielded — implementation.  See storage/snapshot_shielded.h for the
 * v3 shielded-section byte layout and its trust scope. */

#include "storage/snapshot_shielded.h"

#include "core/serialize.h"
#include "core/uint256.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/anchor_kv.h"
#include "storage/nullifier_kv.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

/* Write `buf` to BOTH the file and the SHA3 sponge, so file bytes == hash
 * input.  On a short write returns false; the caller aborts the temp file. */
static bool emit(FILE *out, struct sha3_256_ctx *ctx,
                 const uint8_t *buf, size_t len)
{
    if (len == 0)
        return true;
    if (fwrite(buf, 1, len, out) != len)
        return false;
    sha3_256_write(ctx, buf, len);
    return true;
}

void snapshot_shielded_pack_nf(uint8_t rec[SNAPSHOT_NF_RECORD_BYTES],
                               uint8_t pool, const uint8_t nf[32],
                               int64_t height)
{
    rec[0] = pool;
    memcpy(rec + 1, nf, 32);
    zcl_write_u64_le(rec + 33, (uint64_t)height);
}

void snapshot_shielded_unpack_nf(const uint8_t rec[SNAPSHOT_NF_RECORD_BYTES],
                                 uint8_t *pool, uint8_t nf[32],
                                 int64_t *height)
{
    if (pool) *pool = rec[0];
    if (nf)   memcpy(nf, rec + 1, 32);
    if (height) {
        *height = zcl_read_i64_le(rec + 33);
    }
}

/* Serialize the live active-chain frontier for `pool` into a freshly-malloc'd
 * buffer (caller frees). The frontier is anchor_kv_latest_tree's cumulative
 * tree — for a from-genesis fold at the seed height its root equals the
 * PoW-committed hashFinalSaplingRoot / hashFinalSproutRoot, so a restore can
 * root-verify it. Returns false (and frees nothing new) on a store error or a
 * frontier that is not FOUND (a seed that cannot present its shielded frontier
 * must fail loud, never emit a coins-only-mislabeled snapshot). */
static bool collect_frontier(struct sqlite3 *db, int pool,
                             uint8_t **buf_out, uint32_t *len_out)
{
    *buf_out = NULL; *len_out = 0;
    struct incremental_merkle_tree tree;
    struct uint256 root; int64_t h = -1;
    enum anchor_kv_lookup_result r =
        anchor_kv_latest_tree(db, pool, &tree, &root, &h);
    if (r != ANCHOR_KV_FOUND) {
        LOG_FAIL("snap_shielded",
                 "collect: pool=%d frontier not FOUND (result=%d)", pool, (int)r);
        return false;
    }
    struct byte_stream bs;
    stream_init(&bs, 4096);
    if (!incremental_tree_serialize(&tree, &bs)) {
        stream_free(&bs);
        LOG_FAIL("snap_shielded", "collect: pool=%d frontier serialize failed",
                 pool);
        return false;
    }
    uint8_t *b = zcl_malloc(bs.size ? bs.size : 1, "snap_shielded_frontier");
    if (!b) {
        stream_free(&bs);
        LOG_FAIL("snap_shielded", "collect: pool=%d frontier OOM (%zu bytes)",
                 pool, bs.size);
        return false;
    }
    memcpy(b, bs.data, bs.size);
    *buf_out = b;
    *len_out = (uint32_t)bs.size;
    stream_free(&bs);
    return true;
}

/* Pack every revealed nullifier at height <= `height` (both pools) into a
 * freshly-malloc'd array of SNAPSHOT_NF_RECORD_BYTES records (caller frees), in
 * deterministic (pool, nf) order so the artifact bytes are reproducible. An
 * absent `nullifiers` table is a clean zero-record success (fail-open: the set
 * is simply empty). Returns false only on a real store error. */
static bool collect_nullifiers(struct sqlite3 *db, int64_t height,
                               uint8_t **buf_out, uint64_t *count_out)
{
    *buf_out = NULL; *count_out = 0;
    if (!nullifier_kv_table_exists(db))
        return true;   /* no set yet — v3 with an empty nullifier section */

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT nf, pool, height FROM nullifiers "
            "WHERE height <= ?1 ORDER BY pool, nf", -1, &s, NULL) != SQLITE_OK) {
        LOG_FAIL("snap_shielded", "collect: nullifier prepare failed: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int64(s, 1, (sqlite3_int64)height);

    uint8_t *buf = NULL;
    size_t cap = 0, cnt = 0;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        const uint8_t *nf = (const uint8_t *)sqlite3_column_blob(s, 0);
        int nf_len = sqlite3_column_bytes(s, 0);
        if (!nf || nf_len != 32) {
            LOG_FAIL("snap_shielded", "collect: bad nullifier blob (len=%d)",
                     nf_len);
            ok = false;
            break;
        }
        uint8_t pool = (uint8_t)sqlite3_column_int(s, 1);
        int64_t h = sqlite3_column_int64(s, 2);
        if (cnt == cap) {
            size_t ncap = cap ? cap * 2 : 256;
            uint8_t *nb = zcl_realloc(buf, ncap * SNAPSHOT_NF_RECORD_BYTES,
                                      "snap_shielded_nf");
            if (!nb) {
                LOG_FAIL("snap_shielded", "collect: nullifier OOM (%zu recs)",
                         ncap);
                ok = false;
                break;
            }
            buf = nb;
            cap = ncap;
        }
        snapshot_shielded_pack_nf(buf + cnt * SNAPSHOT_NF_RECORD_BYTES,
                                  pool, nf, h);
        cnt++;
    }
    if (ok && rc != SQLITE_DONE && rc != SQLITE_ROW) {
        LOG_FAIL("snap_shielded", "collect: nullifier scan failed (rc=%d)", rc);
        ok = false;
    }
    sqlite3_finalize(s);
    if (!ok) {
        free(buf);
        return false;
    }
    *buf_out = buf;
    *count_out = (uint64_t)cnt;
    return true;
}

bool snapshot_shielded_collect_from_db(struct sqlite3 *db, int64_t height,
                                       struct snapshot_shielded *out)
{
    if (!db || !out) {
        LOG_FAIL("snap_shielded", "collect: null db/out");
        return false;
    }
    memset(out, 0, sizeof(*out));

    uint8_t *sap = NULL, *spr = NULL, *nfs = NULL;
    uint32_t sap_len = 0, spr_len = 0;
    uint64_t nf_count = 0;

    if (!collect_frontier(db, ANCHOR_POOL_SAPLING, &sap, &sap_len))
        return false;
    if (!collect_frontier(db, ANCHOR_POOL_SPROUT, &spr, &spr_len)) {
        free(sap);
        return false;
    }
    if (!collect_nullifiers(db, height, &nfs, &nf_count)) {
        free(sap);
        free(spr);
        return false;
    }

    out->sapling = sap;    out->sapling_len = sap_len;
    out->sprout  = spr;    out->sprout_len  = spr_len;
    out->nf_records = nfs; out->nf_count    = nf_count;
    return true;
}

void snapshot_shielded_free_collected(struct snapshot_shielded *s)
{
    if (!s)
        return;
    /* collect_* allocated these via zcl_malloc/zcl_realloc; cast away const. */
    free((void *)s->sapling);
    free((void *)s->sprout);
    free((void *)s->nf_records);
    memset(s, 0, sizeof(*s));
}

bool snapshot_shielded_write(FILE *out, struct sha3_256_ctx *ctx,
                             const struct snapshot_shielded *s)
{
    if (!out || !ctx || !s) {
        LOG_FAIL("snap_shielded", "write: null arg");
        return false;
    }
    if ((s->sapling_len > 0 && !s->sapling) ||
        (s->sprout_len  > 0 && !s->sprout)  ||
        (s->nf_count    > 0 && !s->nf_records)) {
        LOG_FAIL("snap_shielded", "write: nonzero length with null blob");
        return false;
    }

    uint8_t hdr[8];
    /* [u32 sapling_len][sapling] */
    zcl_write_u32_le(hdr, s->sapling_len);
    if (!emit(out, ctx, hdr, 4) ||
        !emit(out, ctx, s->sapling, s->sapling_len)) {
        LOG_FAIL("snap_shielded", "write: sapling section failed");
        return false;
    }
    /* [u32 sprout_len][sprout] */
    zcl_write_u32_le(hdr, s->sprout_len);
    if (!emit(out, ctx, hdr, 4) ||
        !emit(out, ctx, s->sprout, s->sprout_len)) {
        LOG_FAIL("snap_shielded", "write: sprout section failed");
        return false;
    }
    /* [u64 nf_count][records] */
    zcl_write_u64_le(hdr, s->nf_count);
    if (!emit(out, ctx, hdr, 8) ||
        !emit(out, ctx, s->nf_records,
              (size_t)s->nf_count * SNAPSHOT_NF_RECORD_BYTES)) {
        LOG_FAIL("snap_shielded", "write: nullifier section failed");
        return false;
    }
    return true;
}
