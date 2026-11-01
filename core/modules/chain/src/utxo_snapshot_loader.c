/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "chain/utxo_snapshot_loader.h"
#include "crypto/sha256.h"
#include "coins/utxo_commitment.h"
#include "core/amount.h"
#include "crypto/sha3.h"
#include "storage/snapshot_shielded.h"
#include "platform/positioned_file.h"
#include "platform/read_mapping.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define USS_HEADER_BYTES 104
#define USS_MAGIC        "ZCLUTXO\x00"

struct uss_handle {
    const uint8_t *base;
    size_t         size;       /* total file size */
    size_t         body_off;   /* offset where body starts (= 104) */
    size_t         body_len;
    struct uss_header hdr;
    struct platform_positioned_file file;
    struct platform_read_mapping mapping;
    struct platform_positioned_file_snapshot snapshot;
};

static bool uss_snapshot_equal(
    const struct platform_positioned_file_snapshot *a,
    const struct platform_positioned_file_snapshot *b)
{
    return a->size == b->size &&
           a->modified_seconds == b->modified_seconds &&
           a->modified_nanoseconds == b->modified_nanoseconds &&
           a->changed_seconds == b->changed_seconds &&
           a->changed_nanoseconds == b->changed_nanoseconds &&
           a->volume == b->volume && a->file_low == b->file_low &&
           a->file_high == b->file_high;
}

#define USS_VERSION_V1 1u
#define USS_VERSION_V2 2u   /* v1 + trailing Sapling-frontier section */
#define USS_VERSION_V3 3u   /* v1 + shielded section (Sapling + Sprout + nfs) */

static uint32_t rd_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t rd_le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= ((uint64_t)p[i]) << (8 * i);
    return v;
}

static void set_err(char *buf, size_t cap, const char *fmt, ...)
{
    if (!buf || cap == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, cap, fmt, ap);
    va_end(ap);
}

/* Accept a v1 body that stops on the last UTXO byte. */
static bool uss_layout_v1_end(const uint8_t *p, const uint8_t *end,
                              char *err, size_t err_sz)
{
    if (p != end) {
        set_err(err, err_sz, "v1 trailing payload bytes");
        return false;
    }
    return true;
}

/* Read the Sapling section, or report it missing or truncated. */
static bool uss_layout_sapling(const uint8_t **cursor, const uint8_t *end,
                               uint32_t *sapling_len, char *err, size_t err_sz)
{
    *sapling_len = 0;
    if ((size_t)(end - *cursor) < 4u) {
        set_err(err, err_sz, "missing Sapling section length");
        return false;
    }
    *sapling_len = rd_le32(*cursor);
    *cursor += 4;
    if ((uint64_t)(end - *cursor) < (uint64_t)*sapling_len) {
        set_err(err, err_sz, "truncated Sapling section");
        return false;
    }
    *cursor += *sapling_len;
    return true;
}

/* Accept a non-empty v2 Sapling section that ends the body. */
static bool uss_layout_v2_end(const uint8_t *p, const uint8_t *end,
                              uint32_t sapling_len, char *err, size_t err_sz)
{
    if (sapling_len == 0 || p != end) {
        set_err(err, err_sz, sapling_len == 0
                                 ? "empty v2 Sapling section"
                                 : "v2 trailing payload bytes");
        return false;
    }
    return true;
}

/* Read Sprout, then require the nullifier bytes to end the body. */
static bool uss_layout_v3_tail(const uint8_t *p, const uint8_t *end,
                               char *err, size_t err_sz)
{
    if ((size_t)(end - p) < 4u) {
        set_err(err, err_sz, "missing Sprout section length");
        return false;
    }
    uint32_t sprout_len = rd_le32(p);
    p += 4;
    if ((uint64_t)(end - p) < (uint64_t)sprout_len) {
        set_err(err, err_sz, "truncated Sprout section");
        return false;
    }
    p += sprout_len;
    if ((size_t)(end - p) < 8u) {
        set_err(err, err_sz, "missing nullifier count");
        return false;
    }
    uint64_t nf_count = rd_le64(p);
    p += 8;
    if (nf_count > UINT64_MAX / SNAPSHOT_NF_RECORD_BYTES) {
        set_err(err, err_sz, "nullifier count overflow");
        return false;
    }
    uint64_t nf_bytes = nf_count * (uint64_t)SNAPSHOT_NF_RECORD_BYTES;
    if ((uint64_t)(end - p) != nf_bytes) {
        set_err(err, err_sz, (uint64_t)(end - p) < nf_bytes
                                 ? "truncated nullifier section"
                                 : "v3 trailing payload bytes");
        return false;
    }
    return true;
}

/* Parse the complete declared payload without interpreting its consensus
 * contents.  A body digest authenticates bytes; it does not make an ambiguous
 * byte layout safe.  Requiring exact consumption here prevents a producer from
 * appending an unknown region that an older reader silently ignores. */
static bool uss_layout_exact(const struct uss_handle *h,
                             char *err, size_t err_sz)
{
    if (!h) {
        set_err(err, err_sz, "null snapshot layout");
        return false;
    }
    const uint8_t *p = h->base + h->body_off;
    const uint8_t *end = h->base + h->size;
    for (uint64_t i = 0; i < h->hdr.count; i++) {
        if ((size_t)(end - p) < 32u + 4u + 8u + 4u) {
            set_err(err, err_sz, "truncated UTXO record %llu",
                    (unsigned long long)i);
            return false;
        }
        p += 32u + 4u + 8u;
        uint32_t script_len = rd_le32(p);
        p += 4;
        if ((uint64_t)(end - p) < (uint64_t)script_len + 4u + 1u) {
            set_err(err, err_sz, "truncated UTXO script %llu",
                    (unsigned long long)i);
            return false;
        }
        p += (size_t)script_len + 4u + 1u;
    }

    if (h->hdr.version == USS_VERSION_V1)
        return uss_layout_v1_end(p, end, err, err_sz);
    uint32_t sapling_len = 0;
    bool sapling_ok = uss_layout_sapling(&p, end, &sapling_len, err, err_sz);
    if (!sapling_ok)
        return false;
    if (h->hdr.version == USS_VERSION_V2)
        return uss_layout_v2_end(p, end, sapling_len, err, err_sz);
    return uss_layout_v3_tail(p, end, err, err_sz);
}

/* True when the snapshot call succeeds and size is at least a header, at most SIZE_MAX. */
static bool uss_open_span_ok(const struct platform_positioned_file *file,
                             struct platform_positioned_file_snapshot *snapshot)
{
    memset(snapshot, 0, sizeof(*snapshot));
    return platform_positioned_file_snapshot(file, snapshot) &&
           !(snapshot->size < USS_HEADER_BYTES || snapshot->size > SIZE_MAX);
}

/* True for snapshot versions 1, 2, and 3. */
static bool uss_version_known(uint32_t version)
{
    return version == USS_VERSION_V1 || version == USS_VERSION_V2 ||
           version == USS_VERSION_V3;
}

/* True when header bytes 12..15 and 20..23 are zero. */
static bool uss_header_reserved_clear(const uint8_t *base)
{
    return base[12] == 0 && base[13] == 0 && base[14] == 0 && base[15] == 0 &&
           base[20] == 0 && base[21] == 0 && base[22] == 0 && base[23] == 0;
}

/* Reject a negative header supply; otherwise require an exact body layout. */
static bool uss_header_supply_layout_ok(struct uss_handle *h,
                                        char *err, size_t err_sz)
{
    if (h->hdr.total_supply < 0) {
        set_err(err, err_sz, "negative header supply");
        return false;
    }
    return uss_layout_exact(h, err, err_sz);
}

/* True when no expected hash was passed or it matches the header. */
static bool uss_expected_sha3_ok(const uint8_t *actual,
                                 const uint8_t *expected_sha3)
{
    return !expected_sha3 || memcmp(actual, expected_sha3, 32) == 0;
}

/* True when full-body SHA3 was not requested or it matches the header. */
static bool uss_body_sha3_ok(const struct uss_handle *h, bool verify_full_sha3)
{
    if (!verify_full_sha3)
        return true;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, h->base + h->body_off, h->body_len);
    uint8_t computed[32];
    sha3_256_finalize(&ctx, computed);
    return memcmp(computed, h->hdr.sha3_hash, 32) == 0;
}

/* True when a fresh file snapshot matches the one taken at open. */
static bool uss_snapshot_still_held(const struct uss_handle *h)
{
    struct platform_positioned_file_snapshot after;
    return platform_positioned_file_snapshot(&h->file, &after) &&
           uss_snapshot_equal(&h->snapshot, &after);
}

/* Copy the header out when the caller provided a destination. */
static void uss_header_export(const struct uss_handle *h,
                              struct uss_header *hdr_out)
{
    if (hdr_out)
        *hdr_out = h->hdr;
}

struct uss_handle *uss_open(const char *path,
                            bool verify_full_sha3,
                            const uint8_t *expected_sha3,
                            struct uss_header *hdr_out,
                            char *err, size_t err_sz)
{
    if (!path) {
        set_err(err, err_sz, "null path");
        LOG_NULL("uss", "open: null path");
        return NULL;
    }
    struct platform_positioned_file file;
    struct platform_read_mapping mapping;
    struct platform_positioned_file_snapshot snapshot;
    platform_positioned_file_init(&file);
    platform_read_mapping_init(&mapping);
    if (!platform_positioned_file_open(&file, path)) {
        set_err(err, err_sz, "open(%s): %s", path, strerror(errno));
        LOG_NULL("uss", "open failed: %s", strerror(errno));
        return NULL;
    }
    bool span_ok = uss_open_span_ok(&file, &snapshot);
    if (!span_ok) {
        set_err(err, err_sz, "too small or metadata failed");
        platform_positioned_file_close(&file);
        LOG_NULL("uss", "metadata or size");
        return NULL;
    }
    if (!platform_read_mapping_open_positioned(
            &mapping, &file, (size_t)snapshot.size)) {
        set_err(err, err_sz, "read mapping failed");
        platform_positioned_file_close(&file);
        LOG_NULL("uss", "read mapping failed");
        return NULL;
    }
    platform_read_mapping_advise_sequential(&mapping);

    const uint8_t *base = mapping.data;
    if (memcmp(base, USS_MAGIC, 8) != 0) {
        set_err(err, err_sz, "bad magic");
        platform_read_mapping_close(&mapping);
        platform_positioned_file_close(&file);
        LOG_NULL("uss", "bad magic");
        return NULL;
    }

    struct uss_handle *h = zcl_malloc(sizeof(*h), "uss.handle");
    if (!h) {
        set_err(err, err_sz, "oom");
        platform_read_mapping_close(&mapping);
        platform_positioned_file_close(&file);
        return NULL;
    }
    h->file = file;
    h->mapping = mapping;
    h->snapshot = snapshot;
    h->base = base;
    h->size = (size_t)snapshot.size;
    h->body_off = USS_HEADER_BYTES;
    h->body_len = h->size - USS_HEADER_BYTES;

    h->hdr.version = rd_le32(base + 8);
    h->hdr.height  = rd_le32(base + 16);
    h->hdr.count   = rd_le64(base + 24);
    h->hdr.total_supply = (int64_t)rd_le64(base + 32);
    memcpy(h->hdr.anchor_block_hash, base + 40, 32);
    memcpy(h->hdr.sha3_hash,         base + 72, 32);

    bool version_ok = uss_version_known(h->hdr.version);
    if (!version_ok) {
        set_err(err, err_sz, "bad version %u", h->hdr.version);
        uss_close(h);
        LOG_NULL("uss", "version");
        return NULL;
    }
    bool reserved_clear = uss_header_reserved_clear(base);
    if (!reserved_clear) {
        set_err(err, err_sz, "nonzero reserved header bytes");
        uss_close(h);
        LOG_NULL("uss", "nonzero reserved header bytes");
        return NULL;
    }
    bool layout_ok = uss_header_supply_layout_ok(h, err, err_sz);
    if (!layout_ok) {
        uss_close(h);
        LOG_NULL("uss", "invalid exact layout");
        return NULL;
    }
    bool expected_ok = uss_expected_sha3_ok(h->hdr.sha3_hash, expected_sha3);
    if (!expected_ok) {
        set_err(err, err_sz, "expected sha3 mismatch");
        uss_close(h);
        LOG_NULL("uss", "expected sha3 mismatch");
        return NULL;
    }
    bool body_ok = uss_body_sha3_ok(h, verify_full_sha3);
    if (!body_ok) {
        set_err(err, err_sz, "body sha3 mismatch");
        uss_close(h);
        LOG_NULL("uss", "body sha3 mismatch");
        return NULL;
    }
    bool held = uss_snapshot_still_held(h);
    if (!held) {
        set_err(err, err_sz, "snapshot changed during validation");
        uss_close(h);
        LOG_NULL("uss", "snapshot identity changed");
        return NULL;
    }
    uss_header_export(h, hdr_out);
    return h;
}

void uss_close(struct uss_handle *h)
{
    if (!h) return;
    platform_read_mapping_close(&h->mapping);
    platform_positioned_file_close(&h->file);
    free(h);
}

bool uss_artifact_sha256(const struct uss_handle *h, uint8_t out[32])
{
    if (!h || !h->base || !out) return false;
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_write(&ctx, h->base, h->size);
    sha256_finalize(&ctx, out);
    return true;
}

int64_t uss_iter(struct uss_handle *h, uss_record_cb cb, void *ctx)
{
    if (!h || !cb) return -1;
    const uint8_t *p = h->base + h->body_off;
    const uint8_t *end = h->base + h->size;
    int64_t n = 0;
    for (uint64_t i = 0; i < h->hdr.count; i++) {
        if ((size_t)(end - p) < 32 + 4 + 8 + 4) return -1;
        struct uss_record r;
        r.txid = p; p += 32;
        r.vout = rd_le32(p); p += 4;
        r.value = (int64_t)rd_le64(p); p += 8;
        r.script_len = rd_le32(p); p += 4;
        if ((uint64_t)(end - p) < (uint64_t)r.script_len + 4 + 1) return -1;
        r.script = r.script_len ? p : NULL;
        p += r.script_len;
        r.height = rd_le32(p); p += 4;
        r.is_coinbase = *p++;
        if (!cb(&r, ctx)) return n + 1;
        n++;
    }
    return n;
}

struct uss_component_ctx {
    struct sha3_256_ctx sha3;
    uint64_t count;
    int64_t total_supply;
    bool failed;
    const char *reason;
    uint8_t prior_txid[32];
    uint32_t prior_vout;
    bool have_prior;
    uint32_t snapshot_height;
};

/* Return false for a null context or record, no txid, or script_len without a script. */
static bool uss_component_record_wellformed(const struct uss_record *r,
                                            struct uss_component_ctx *ctx)
{
    if (!ctx || !r || !r->txid ||
        (r->script_len > 0 && !r->script)) {
        if (ctx) {
            ctx->failed = true;
            ctx->reason = "malformed UTXO record";
        }
        return false;
    }
    return true;
}

/* When a prior outpoint exists, reject a record that does not follow it. */
static bool uss_component_record_ordered(struct uss_component_ctx *ctx,
                                         const struct uss_record *r)
{
    if (!ctx->have_prior)
        return true;
    int order = memcmp(ctx->prior_txid, r->txid, 32);
    if (order > 0 || (order == 0 && ctx->prior_vout >= r->vout)) {
        ctx->failed = true;
        ctx->reason = "non-canonical or duplicate UTXO order";
        return false;
    }
    return true;
}

static bool uss_component_record(const struct uss_record *r, void *vctx)
{
    struct uss_component_ctx *ctx = vctx;
    bool wellformed = uss_component_record_wellformed(r, ctx);
    if (!wellformed)
        return false;
    if (!MoneyRange(r->value)) {
        ctx->failed = true;
        ctx->reason = "UTXO value outside MoneyRange";
        return false;
    }
    if (r->height > ctx->snapshot_height) {
        ctx->failed = true;
        ctx->reason = "UTXO height above snapshot";
        return false;
    }
    if (r->is_coinbase > 1) {
        ctx->failed = true;
        ctx->reason = "non-canonical coinbase flag";
        return false;
    }
    bool ordered = uss_component_record_ordered(ctx, r);
    if (!ordered)
        return false;
    int64_t next_supply = 0;
    if (__builtin_add_overflow(ctx->total_supply, r->value, &next_supply)) {
        ctx->failed = true;
        ctx->reason = "UTXO supply overflow";
        return false;
    }
    if (!MoneyRange(next_supply)) {
        ctx->failed = true;
        ctx->reason = "UTXO supply outside MoneyRange";
        return false;
    }
    utxo_commitment_sha3_write_record(
        &ctx->sha3, r->txid, r->vout, r->value, r->script, r->script_len,
        r->height, r->is_coinbase);
    ctx->total_supply = next_supply;
    memcpy(ctx->prior_txid, r->txid, sizeof(ctx->prior_txid));
    ctx->prior_vout = r->vout;
    ctx->have_prior = true;
    ctx->count++;
    return true;
}

bool uss_utxo_component_compute(struct uss_handle *h,
                                struct uss_utxo_component *out,
                                char *err, size_t err_sz)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (!h || !out) {
        set_err(err, err_sz, "null UTXO component argument");
        LOG_FAIL("uss", "component_compute: null h/out");
        return false;
    }
    struct uss_component_ctx ctx = {0};
    ctx.snapshot_height = h->hdr.height;
    sha3_256_init(&ctx.sha3);
    int64_t emitted = uss_iter(h, uss_component_record, &ctx);
    if (ctx.failed) {
        set_err(err, err_sz, "%s", ctx.reason ? ctx.reason
                                               : "malformed UTXO component");
        LOG_FAIL("uss", "component_compute: %s",
                 ctx.reason ? ctx.reason : "record callback failed");
        return false;
    }
    if (emitted < 0 || (uint64_t)emitted != h->hdr.count ||
        ctx.count != h->hdr.count) {
        set_err(err, err_sz,
                "UTXO record count mismatch emitted=%lld computed=%llu header=%llu",
                (long long)emitted, (unsigned long long)ctx.count,
                (unsigned long long)h->hdr.count);
        LOG_FAIL("uss", "component_compute: record count mismatch");
        return false;
    }
    if (ctx.total_supply != h->hdr.total_supply) {
        set_err(err, err_sz,
                "UTXO supply mismatch computed=%lld header=%lld",
                (long long)ctx.total_supply, (long long)h->hdr.total_supply);
        LOG_FAIL("uss", "component_compute: supply mismatch");
        return false;
    }
    sha3_256_finalize(&ctx.sha3, out->sha3_hash);
    out->count = ctx.count;
    out->total_supply = ctx.total_supply;
    return true;
}

uint32_t uss_version(const struct uss_handle *h)
{
    return h ? h->hdr.version : 0;
}

/* Walk PAST the `count` UTXO records (identical decode to uss_iter) and return
 * the pointer at the first byte AFTER them — the start of any trailing shielded
 * section. Returns NULL on truncation. */
static const uint8_t *uss_body_after_records(struct uss_handle *h,
                                             const uint8_t **end_out)
{
    const uint8_t *p = h->base + h->body_off;
    const uint8_t *end = h->base + h->size;
    if (end_out) *end_out = end;
    for (uint64_t i = 0; i < h->hdr.count; i++) {
        if ((size_t)(end - p) < 32 + 4 + 8 + 4) return NULL;
        p += 32;            /* txid   */
        p += 4;             /* vout   */
        p += 8;             /* value  */
        uint32_t slen = rd_le32(p); p += 4;
        if ((uint64_t)(end - p) < (uint64_t)slen + 4 + 1) return NULL;
        p += slen;          /* script */
        p += 4;             /* height */
        p += 1;             /* is_coinbase */
    }
    return p;
}

bool uss_frontier(struct uss_handle *h, const uint8_t **blob_out,
                  uint32_t *len_out)
{
    if (blob_out) *blob_out = NULL;
    if (len_out)  *len_out = 0;
    if (!h) return false;
    /* The Sapling frontier is the FIRST trailing section in BOTH v2 (only that
     * section) and v3 (Sapling then Sprout then nullifiers), so the same
     * [u32 len][blob] decode serves both. The section lives inside the body
     * SHA3 region uss_open's verify_full_sha3 already bound. */
    if (h->hdr.version != USS_VERSION_V2 && h->hdr.version != USS_VERSION_V3)
        return false;

    const uint8_t *end = NULL;
    const uint8_t *p = uss_body_after_records(h, &end);
    if (!p) return false;
    if ((size_t)(end - p) < 4) return false;
    uint32_t flen = rd_le32(p); p += 4;
    if (flen == 0 || (uint64_t)(end - p) < (uint64_t)flen) return false;
    if (blob_out) *blob_out = p;
    if (len_out)  *len_out  = flen;
    return true;
}

/* Assign each non-NULL shielded output from the span passed for it. */
static void uss_shielded_set_outs(
    const uint8_t **sapling_out, uint32_t *sapling_len_out,
    const uint8_t **sprout_out, uint32_t *sprout_len_out,
    const uint8_t **nf_out, uint64_t *nf_count_out,
    const uint8_t *sap, uint32_t sap_len,
    const uint8_t *spr, uint32_t spr_len,
    const uint8_t *nf, uint64_t nf_count)
{
    if (sapling_out) *sapling_out = sap;
    if (sapling_len_out) *sapling_len_out = sap_len;
    if (sprout_out) *sprout_out = spr;
    if (sprout_len_out) *sprout_len_out = spr_len;
    if (nf_out) *nf_out = nf;
    if (nf_count_out) *nf_count_out = nf_count;
}

/* Read one [u32 length][bytes] section into *blob and *len, or return false. */
static bool uss_shielded_u32_section(const uint8_t **cursor, const uint8_t *end,
                                     const uint8_t **blob, uint32_t *len)
{
    *blob = NULL;
    *len = 0;
    if ((size_t)(end - *cursor) < 4)
        return false;
    uint32_t n = rd_le32(*cursor);
    *cursor += 4;
    if ((uint64_t)(end - *cursor) < (uint64_t)n)
        return false;
    *blob = n ? *cursor : NULL;
    *len = n;
    *cursor += n;
    return true;
}

/* Read the nullifier count and record bytes, or return false. */
static bool uss_shielded_nullifiers(const uint8_t **cursor, const uint8_t *end,
                                    const uint8_t **blob, uint64_t *count)
{
    *blob = NULL;
    *count = 0;
    if ((size_t)(end - *cursor) < 8)
        return false;
    uint64_t nf_count = rd_le64(*cursor);
    *cursor += 8;
    uint64_t nf_bytes = nf_count * (uint64_t)SNAPSHOT_NF_RECORD_BYTES;
    if (nf_count > (UINT64_MAX / SNAPSHOT_NF_RECORD_BYTES))
        return false;
    if ((uint64_t)(end - *cursor) < nf_bytes)
        return false;
    *blob = nf_count ? *cursor : NULL;
    *count = nf_count;
    return true;
}

bool uss_shielded(struct uss_handle *h,
                  const uint8_t **sapling_out, uint32_t *sapling_len_out,
                  const uint8_t **sprout_out,  uint32_t *sprout_len_out,
                  const uint8_t **nf_out,      uint64_t *nf_count_out)
{
    uss_shielded_set_outs(sapling_out, sapling_len_out,
                          sprout_out, sprout_len_out,
                          nf_out, nf_count_out,
                          NULL, 0, NULL, 0, NULL, 0);
    if (!h || h->hdr.version != USS_VERSION_V3) return false;

    const uint8_t *end = NULL;
    const uint8_t *p = uss_body_after_records(h, &end);
    if (!p) return false;

    const uint8_t *sap = NULL;
    uint32_t sap_len = 0;
    /* [u32 sapling_len][sapling] */
    bool sap_ok = uss_shielded_u32_section(&p, end, &sap, &sap_len);
    if (!sap_ok) return false;

    const uint8_t *spr = NULL;
    uint32_t spr_len = 0;
    /* [u32 sprout_len][sprout] */
    bool spr_ok = uss_shielded_u32_section(&p, end, &spr, &spr_len);
    if (!spr_ok) return false;

    const uint8_t *nf = NULL;
    uint64_t nf_count = 0;
    /* [u64 nf_count][records] */
    bool nf_ok = uss_shielded_nullifiers(&p, end, &nf, &nf_count);
    if (!nf_ok) return false;

    uss_shielded_set_outs(sapling_out, sapling_len_out,
                          sprout_out, sprout_len_out,
                          nf_out, nf_count_out,
                          sap, sap_len, spr, spr_len, nf, nf_count);
    return true;
}
