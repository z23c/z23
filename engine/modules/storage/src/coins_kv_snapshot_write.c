/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * coins_kv_snapshot_write — the ANCHOR-SET MINT writer. See
 * storage/coins_kv.h coins_kv_snapshot_write() for the contract and the
 * on-disk format (the same record layout as core/modules/chain/src/utxo_snapshot_loader.c
 * and the `--gen-utxo-snapshot` tool).
 *
 * The body is streamed in canonical (txid,vout) order using the SAME single
 * record encoder as coins_kv_commitment (utxo_sha3_serialize_record), so the
 * body SHA3 written here equals coins_kv_commitment(db) — and is
 * therefore directly comparable to the compiled checkpoint root.
 *
 * Raw sqlite carries // raw-sql-ok:progress-kv-kernel-store — coins_kv lives on
 * the cross-thread progress.kv handle (no cached statement), the same hatch the
 * rest of coins_kv.c uses. This is a read-only SELECT over `coins`.
 */

#include "storage/coins_kv.h"

#include "coins/utxo_commitment.h"
#include "crypto/sha3.h"
#include "storage/coins_ram.h"
#include "storage/snapshot_shielded.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define USS_HEADER_BYTES 104

static void le32(uint8_t b[4], uint32_t v)
{
    b[0] = (uint8_t)v; b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16); b[3] = (uint8_t)(v >> 24);
}
static void le64(uint8_t b[8], uint64_t v)
{
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (8 * i));
}

/* Inline-buffer cap for the per-record serialise (real ZCL scripts fit; an
 * oversized script falls back to a heap buffer). */
enum { SNAP_SCRIPT_INLINE_CAP = 1024 };

/* Outcome of streaming one coins row into a snapshot body.  The row helpers
 * below report one of these; stream_coins_body logs the failures. */
enum snap_row_status {
    SNAP_ROW_WRITTEN,    /* record serialised, written to the file and folded */
    SNAP_ROW_SKIPPED,    /* row carries no canonical 32-byte txid: not in set */
    SNAP_ROW_OOM,        /* heap record buffer for an oversized script failed */
    SNAP_ROW_SERIALISE,  /* the shared per-record encoder rejected the row */
    SNAP_ROW_FWRITE      /* the record fwrite to the temp file failed */
};

/* Serialise ONE (txid,vout) row with the SAME per-record encoder as
 * coins_kv_commitment, then stream the record to BOTH `out` and the sponge
 * `ctx`.  Returns SNAP_ROW_WRITTEN, SNAP_ROW_SERIALISE or SNAP_ROW_FWRITE;
 * the caller logs the failure. */
static enum snap_row_status snapshot_emit_record(FILE *out,
                                                 struct sha3_256_ctx *ctx,
                                                 uint8_t *rec, size_t cap,
                                                 const uint8_t *txid,
                                                 uint32_t vout, int64_t value,
                                                 const uint8_t *script,
                                                 uint32_t slen,
                                                 int32_t height, int cb_int)
{
    size_t rec_len = 0;
    if (!utxo_sha3_serialize_record(rec, cap, &rec_len, txid, vout, value,
                                    script, slen, (uint32_t)height,
                                    (uint8_t)(cb_int ? 1 : 0)))
        return SNAP_ROW_SERIALISE;
    if (fwrite(rec, 1, rec_len, out) != rec_len)
        return SNAP_ROW_FWRITE;
    sha3_256_write(ctx, rec, rec_len);
    return SNAP_ROW_WRITTEN;
}

/* Stream ONE stepped coins row: re-read its columns, skip it when it has no
 * canonical 32-byte txid, size the inline/heap record buffer for its script,
 * then emit the record.  Always reports the row's effective script length in
 * *eff_slen_out (the OOM log needs it) and, on SNAP_ROW_WRITTEN, its value in
 * *value_out.  The heap record buffer (if any) is handed back in *heap_out and
 * stays owned by the caller, who frees it after logging a failure.  Returns the
 * row status; the caller logs the failures. */
static enum snap_row_status snapshot_stream_row(FILE *out,
                                                struct sha3_256_ctx *ctx,
                                                sqlite3_stmt *s,
                                                uint32_t *eff_slen_out,
                                                int64_t *value_out,
                                                uint8_t **heap_out)
{
    const uint8_t *txid = (const uint8_t *)sqlite3_column_blob(s, 0);
    int txid_len = sqlite3_column_bytes(s, 0);
    if (!txid || txid_len < 32) return SNAP_ROW_SKIPPED;

    uint32_t vout   = (uint32_t)sqlite3_column_int(s, 1);
    int64_t  value  = sqlite3_column_int64(s, 2);
    const uint8_t *script = (const uint8_t *)sqlite3_column_blob(s, 3);
    int script_len = sqlite3_column_bytes(s, 3);
    int32_t  height_c = sqlite3_column_int(s, 4);
    int cb_int = sqlite3_column_int(s, 5);

    const uint8_t *eff_script = (script_len > 0) ? script : NULL;
    uint32_t eff_slen = (uint32_t)(script_len > 0 ? script_len : 0);
    *eff_slen_out = eff_slen;

    uint8_t inline_buf[UTXO_SHA3_RECORD_MAX(SNAP_SCRIPT_INLINE_CAP)];
    uint8_t *rec = inline_buf;
    uint8_t *heap = NULL;
    size_t cap = sizeof(inline_buf);
    if (eff_slen > SNAP_SCRIPT_INLINE_CAP) {
        cap = UTXO_SHA3_RECORD_MAX(eff_slen);
        heap = zcl_malloc(cap, "coins_kv_snapshot_record");
        if (!heap) return SNAP_ROW_OOM;
        *heap_out = heap;
        rec = heap;
    }
    enum snap_row_status emitted = snapshot_emit_record(
        out, ctx, rec, cap, txid, vout, value, eff_script, eff_slen,
        height_c, cb_int);
    if (emitted != SNAP_ROW_WRITTEN) return emitted;

    *value_out = value;
    return SNAP_ROW_WRITTEN;
}

/* Publish a completed snapshot's results through the caller's optional
 * out-params: the body SHA3 (only when both sha3 sides are given — the
 * streaming body has no final digest yet) plus the count/total_supply
 * totals.  Nothing is written unless the body completed (`ok`). */
static void snapshot_publish_results(bool ok, const uint8_t *body_sha3,
                                     uint64_t count, int64_t total_supply,
                                     uint8_t out_sha3[32], uint64_t *out_count,
                                     int64_t *out_total_supply)
{
    if (!ok) return;
    if (out_sha3) memcpy(out_sha3, body_sha3, 32);
    if (out_count) *out_count = count;
    if (out_total_supply) *out_total_supply = total_supply;
}

/* Stream every coins row in canonical (txid,vout) order to BOTH `out` and the
 * SHA3 sponge `ctx`, using the SAME per-record encoder as coins_kv_commitment,
 * so file body == SHA3 input == coins_kv_commitment input.  On success sets
 * *count / *total_supply.  Shared by the v2 (Sapling-only) and v3 (Sapling +
 * Sprout + nullifier) writers so the proven per-record encoding lives once. */
static bool stream_coins_body(FILE *out, sqlite3 *db, struct sha3_256_ctx *ctx,
                              uint64_t *count_out, int64_t *supply_out)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT txid, vout, value, script, height, is_coinbase "
            "FROM coins ORDER BY txid, vout", -1, &s, NULL) != SQLITE_OK) {
        LOG_WARN("coins_kv", "snapshot_write: prepare failed: %s",
                 sqlite3_errmsg(db));
        return false;
    }

    uint64_t count = 0;
    int64_t  total_supply = 0;
    bool ok = true;
    int rc;
    while (ok && (rc = sqlite3_step(s)) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        uint32_t eff_slen = 0;
        int64_t value = 0;
        uint8_t *heap = NULL;
        enum snap_row_status row =
            snapshot_stream_row(out, ctx, s, &eff_slen, &value, &heap);
        if (row == SNAP_ROW_SKIPPED) continue;
        if (row == SNAP_ROW_OOM) {
            LOG_WARN("coins_kv", "snapshot_write: oom for script_len=%u",
                     eff_slen);
            ok = false;
            break;
        }
        if (row == SNAP_ROW_SERIALISE) {
            LOG_WARN("coins_kv", "snapshot_write: serialise failed");
            if (heap) free(heap);
            ok = false;
            break;
        }
        if (row == SNAP_ROW_FWRITE) {
            LOG_WARN("coins_kv", "snapshot_write: record fwrite failed");
            if (heap) free(heap);
            ok = false;
            break;
        }
        if (heap) free(heap);
        total_supply += value;
        count++;
    }
    if (ok && rc != SQLITE_DONE && rc != SQLITE_ROW)
        ok = false;
    sqlite3_finalize(s);

    snapshot_publish_results(ok, NULL, count, total_supply, NULL,
                             count_out, supply_out);
    return ok;
}

/* Finalize header + atomic rename for a coins snapshot temp file.  `version` is
 * 1/2/3; `body_sha3` is the completed sponge over records+section. */
static bool snapshot_finalize(FILE *out, const char *tmp_path,
                              const char *out_path, uint32_t version,
                              int32_t height,
                              const uint8_t anchor_block_hash[32],
                              uint64_t count, int64_t total_supply,
                              const uint8_t body_sha3[32])
{
    uint8_t header[USS_HEADER_BYTES] = {0};
    memcpy(header, "ZCLUTXO\x00", 8);
    le32(header + 8, version);
    le32(header + 16, (uint32_t)height);
    le64(header + 24, count);
    le64(header + 32, (uint64_t)total_supply);
    if (anchor_block_hash) memcpy(header + 40, anchor_block_hash, 32);
    memcpy(header + 72, body_sha3, 32);

    if (fseek(out, 0, SEEK_SET) != 0 ||
        fwrite(header, 1, sizeof(header), out) != sizeof(header)) {
        LOG_WARN("coins_kv", "snapshot_write: header rewrite failed");
        fclose(out);
        unlink(tmp_path);
        return false;
    }
    if (fflush(out) != 0) {
        LOG_WARN("coins_kv", "snapshot_write: fflush failed");
        fclose(out);
        unlink(tmp_path);
        return false;
    }
    fclose(out);
    if (rename(tmp_path, out_path) != 0) {
        LOG_WARN("coins_kv", "snapshot_write: rename(%s -> %s) failed",
                 tmp_path, out_path);
        unlink(tmp_path);
        return false;
    }
    return true;
}

/* Classify the shielded argument into an on-disk format version. NULL => v1
 * (coins only). A Sapling-only frontier (no Sprout, no nullifiers) => v2 (the
 * single-frontier section). A Sprout frontier and/or a nullifier set => v3 (the
 * full storage/snapshot_shielded.h section). This is the ONE place the version
 * byte is derived from DATA, so the writer is named once, not per format. */
static uint32_t snapshot_version_for(const struct snapshot_shielded *sh)
{
    if (!sh) return 1;
    if (sh->sprout_len > 0 || sh->nf_count > 0) return 3;
    if (sh->sapling_len > 0) return 2;
    return 1;
}

/* Append the shielded section for `version` (2 or 3) to `out`, folding the
 * IDENTICAL bytes into `ctx`. v2 writes only [u32 sapling_len][sapling]
 * (byte-identical to the historical Sapling-frontier section); v3 writes the
 * full Sapling+Sprout+nullifier section. Returns false on a short write. */
static bool snapshot_append_shielded(FILE *out, struct sha3_256_ctx *ctx,
                                     uint32_t version,
                                     const struct snapshot_shielded *sh)
{
    if (version == 2) {
        uint8_t lenbuf[4];
        le32(lenbuf, sh->sapling_len);
        if (fwrite(lenbuf, 1, 4, out) != 4 ||
            (sh->sapling_len &&
             fwrite(sh->sapling, 1, sh->sapling_len, out) != sh->sapling_len)) {
            LOG_WARN("coins_kv", "snapshot_write: sapling frontier write failed");
            return false;
        }
        sha3_256_write(ctx, lenbuf, 4);
        if (sh->sapling_len)
            sha3_256_write(ctx, sh->sapling, sh->sapling_len);
        return true;
    }
    /* version 3 */
    return snapshot_shielded_write(out, ctx, sh);
}

/* A snapshot write needs a live db handle and a non-empty destination path;
 * the caller reports the rejection. */
static bool snapshot_write_args_invalid(sqlite3 *db, const char *out_path)
{
    return !db || !out_path || !out_path[0];
}

bool coins_kv_snapshot_write(sqlite3 *db, const char *out_path,
                             int32_t height, const uint8_t anchor_block_hash[32],
                             const struct snapshot_shielded *shielded_or_null,
                             uint8_t out_sha3[32], uint64_t *out_count,
                             int64_t *out_total_supply)
{
    if (snapshot_write_args_invalid(db, out_path)) {
        LOG_FAIL("coins_kv", "snapshot_write: null db/path");
        return false;
    }

    /* Bulk-fold in-RAM overlay active (e.g. the anchor self-mint runs while the
     * fold's un-flushed tail still lives in RAM): stream the EFFECTIVE set so
     * the artifact is complete and its body SHA3 still equals the compiled
     * checkpoint. With the flag off this is a single bool load that is false. */
    if (coins_ram_active())
        return coins_ram_snapshot_write(out_path, height, anchor_block_hash,
                                        shielded_or_null, out_sha3, out_count,
                                        out_total_supply);

    uint32_t snap_version = snapshot_version_for(shielded_or_null);

    char tmp_path[1100];
    int np = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", out_path);
    if (np < 0 || (size_t)np >= sizeof(tmp_path)) {
        LOG_WARN("coins_kv", "snapshot_write: out_path too long");
        return false;
    }

    FILE *out = fopen(tmp_path, "wb");
    if (!out) {
        LOG_WARN("coins_kv", "snapshot_write: fopen(%s) failed", tmp_path);
        return false;
    }

    /* Reserve the header; rewritten at the end once count/supply/sha3 known. */
    uint8_t header[USS_HEADER_BYTES] = {0};
    if (fwrite(header, 1, sizeof(header), out) != sizeof(header)) {
        LOG_WARN("coins_kv", "snapshot_write: header reserve fwrite failed");
        fclose(out);
        unlink(tmp_path);
        return false;
    }

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    uint64_t count = 0;
    int64_t  total_supply = 0;
    if (!stream_coins_body(out, db, &ctx, &count, &total_supply)) {
        fclose(out);
        unlink(tmp_path);
        return false;
    }

    /* OPTIONAL shielded section, appended AFTER the UTXO records and BEFORE the
     * header rewrite so it falls inside the body SHA3 region (everything after
     * offset 104). v2 => single Sapling frontier; v3 => full shielded section. */
    if (snap_version >= 2 &&
        !snapshot_append_shielded(out, &ctx, snap_version, shielded_or_null)) {
        fclose(out);
        unlink(tmp_path);
        return false;
    }

    uint8_t body_sha3[32];
    sha3_256_finalize(&ctx, body_sha3);

    if (!snapshot_finalize(out, tmp_path, out_path, snap_version, height,
                           anchor_block_hash, count, total_supply, body_sha3))
        return false;

    snapshot_publish_results(true, body_sha3, count, total_supply, out_sha3,
                             out_count, out_total_supply);
    return true;
}
