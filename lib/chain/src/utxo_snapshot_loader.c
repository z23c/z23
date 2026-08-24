/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "chain/utxo_snapshot_loader.h"
#include "crypto/sha256.h"
#include "coins/utxo_commitment.h"
#include "core/amount.h"
#include "crypto/sha3.h"
#include "storage/snapshot_shielded.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define USS_HEADER_BYTES 104
#define USS_MAGIC        "ZCLUTXO\x00"

struct uss_handle {
    const uint8_t *base;
    size_t         size;       /* total file size */
    size_t         body_off;   /* offset where body starts (= 104) */
    size_t         body_len;
    struct uss_header hdr;
};

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

    if (h->hdr.version == USS_VERSION_V1) {
        if (p != end) {
            set_err(err, err_sz, "v1 trailing payload bytes");
            return false;
        }
        return true;
    }

    if ((size_t)(end - p) < 4u) {
        set_err(err, err_sz, "missing Sapling section length");
        return false;
    }
    uint32_t sapling_len = rd_le32(p);
    p += 4;
    if ((uint64_t)(end - p) < (uint64_t)sapling_len) {
        set_err(err, err_sz, "truncated Sapling section");
        return false;
    }
    p += sapling_len;

    if (h->hdr.version == USS_VERSION_V2) {
        if (sapling_len == 0 || p != end) {
            set_err(err, err_sz, sapling_len == 0
                                     ? "empty v2 Sapling section"
                                     : "v2 trailing payload bytes");
            return false;
        }
        return true;
    }

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
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        set_err(err, err_sz, "open(%s): %s", path, strerror(errno));
        LOG_NULL("uss", "open failed: %s", strerror(errno));
        return NULL;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < USS_HEADER_BYTES) {
        set_err(err, err_sz, "too small or fstat failed");
        close(fd);
        LOG_NULL("uss", "fstat or size");
        return NULL;
    }
    void *mp = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mp == MAP_FAILED) {
        set_err(err, err_sz, "mmap: %s", strerror(errno));
        LOG_NULL("uss", "mmap failed");
        return NULL;
    }
    posix_madvise(mp, (size_t)st.st_size, POSIX_MADV_SEQUENTIAL);

    const uint8_t *base = (const uint8_t *)mp;
    if (memcmp(base, USS_MAGIC, 8) != 0) {
        set_err(err, err_sz, "bad magic");
        munmap(mp, (size_t)st.st_size);
        LOG_NULL("uss", "bad magic");
        return NULL;
    }

    struct uss_handle *h = zcl_malloc(sizeof(*h), "uss.handle");
    if (!h) {
        set_err(err, err_sz, "oom");
        munmap(mp, (size_t)st.st_size);
        return NULL;
    }
    h->base = base;
    h->size = (size_t)st.st_size;
    h->body_off = USS_HEADER_BYTES;
    h->body_len = h->size - USS_HEADER_BYTES;

    h->hdr.version = rd_le32(base + 8);
    h->hdr.height  = rd_le32(base + 16);
    h->hdr.count   = rd_le64(base + 24);
    h->hdr.total_supply = (int64_t)rd_le64(base + 32);
    memcpy(h->hdr.anchor_block_hash, base + 40, 32);
    memcpy(h->hdr.sha3_hash,         base + 72, 32);

    if (h->hdr.version != USS_VERSION_V1 && h->hdr.version != USS_VERSION_V2 &&
        h->hdr.version != USS_VERSION_V3) {
        set_err(err, err_sz, "bad version %u", h->hdr.version);
        munmap(mp, (size_t)st.st_size);
        free(h);
        LOG_NULL("uss", "version");
        return NULL;
    }
    if (base[12] != 0 || base[13] != 0 || base[14] != 0 || base[15] != 0 ||
        base[20] != 0 || base[21] != 0 || base[22] != 0 || base[23] != 0) {
        set_err(err, err_sz, "nonzero reserved header bytes");
        munmap(mp, (size_t)st.st_size);
        free(h);
        LOG_NULL("uss", "nonzero reserved header bytes");
        return NULL;
    }
    if (h->hdr.total_supply < 0 || !uss_layout_exact(h, err, err_sz)) {
        if (h->hdr.total_supply < 0)
            set_err(err, err_sz, "negative header supply");
        munmap(mp, (size_t)st.st_size);
        free(h);
        LOG_NULL("uss", "invalid exact layout");
        return NULL;
    }
    if (expected_sha3 &&
        memcmp(h->hdr.sha3_hash, expected_sha3, 32) != 0) {
        set_err(err, err_sz, "expected sha3 mismatch");
        munmap(mp, (size_t)st.st_size);
        free(h);
        LOG_NULL("uss", "expected sha3 mismatch");
        return NULL;
    }
    if (verify_full_sha3) {
        struct sha3_256_ctx ctx;
        sha3_256_init(&ctx);
        sha3_256_write(&ctx, base + h->body_off, h->body_len);
        uint8_t computed[32];
        sha3_256_finalize(&ctx, computed);
        if (memcmp(computed, h->hdr.sha3_hash, 32) != 0) {
            set_err(err, err_sz, "body sha3 mismatch");
            munmap(mp, (size_t)st.st_size);
            free(h);
            LOG_NULL("uss", "body sha3 mismatch");
            return NULL;
        }
    }
    if (hdr_out) *hdr_out = h->hdr;
    return h;
}

void uss_close(struct uss_handle *h)
{
    if (!h) return;
    if (h->base) munmap((void *)h->base, h->size);
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

static bool uss_component_record(const struct uss_record *r, void *vctx)
{
    struct uss_component_ctx *ctx = vctx;
    if (!ctx || !r || !r->txid ||
        (r->script_len > 0 && !r->script)) {
        if (ctx) {
            ctx->failed = true;
            ctx->reason = "malformed UTXO record";
        }
        return false;
    }
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
    if (ctx->have_prior) {
        int order = memcmp(ctx->prior_txid, r->txid, 32);
        if (order > 0 || (order == 0 && ctx->prior_vout >= r->vout)) {
            ctx->failed = true;
            ctx->reason = "non-canonical or duplicate UTXO order";
            return false;
        }
    }
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

bool uss_shielded(struct uss_handle *h,
                  const uint8_t **sapling_out, uint32_t *sapling_len_out,
                  const uint8_t **sprout_out,  uint32_t *sprout_len_out,
                  const uint8_t **nf_out,      uint64_t *nf_count_out)
{
    if (sapling_out)     *sapling_out = NULL;
    if (sapling_len_out) *sapling_len_out = 0;
    if (sprout_out)      *sprout_out = NULL;
    if (sprout_len_out)  *sprout_len_out = 0;
    if (nf_out)          *nf_out = NULL;
    if (nf_count_out)    *nf_count_out = 0;
    if (!h || h->hdr.version != USS_VERSION_V3) return false;

    const uint8_t *end = NULL;
    const uint8_t *p = uss_body_after_records(h, &end);
    if (!p) return false;

    /* [u32 sapling_len][sapling] */
    if ((size_t)(end - p) < 4) return false;
    uint32_t sap_len = rd_le32(p); p += 4;
    if ((uint64_t)(end - p) < (uint64_t)sap_len) return false;
    const uint8_t *sap = sap_len ? p : NULL;
    p += sap_len;

    /* [u32 sprout_len][sprout] */
    if ((size_t)(end - p) < 4) return false;
    uint32_t spr_len = rd_le32(p); p += 4;
    if ((uint64_t)(end - p) < (uint64_t)spr_len) return false;
    const uint8_t *spr = spr_len ? p : NULL;
    p += spr_len;

    /* [u64 nf_count][records] */
    if ((size_t)(end - p) < 8) return false;
    uint64_t nf_count = rd_le64(p); p += 8;
    uint64_t nf_bytes = nf_count * (uint64_t)SNAPSHOT_NF_RECORD_BYTES;
    if (nf_count > (UINT64_MAX / SNAPSHOT_NF_RECORD_BYTES)) return false;
    if ((uint64_t)(end - p) < nf_bytes) return false;
    const uint8_t *nf = nf_count ? p : NULL;

    if (sapling_out)     *sapling_out = sap;
    if (sapling_len_out) *sapling_len_out = sap_len;
    if (sprout_out)      *sprout_out = spr;
    if (sprout_len_out)  *sprout_len_out = spr_len;
    if (nf_out)          *nf_out = nf;
    if (nf_count_out)    *nf_count_out = nf_count;
    return true;
}
