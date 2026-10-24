/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * In-place incremental save of the block-index flat file: only the rows that
 * changed since the previous save are rewritten, the payload is synced
 * BEFORE the 48-byte embedded header, and the result is byte-identical to the
 * full atomic rewrite of the same in-memory index. */
// one-result-type-ok:flat-inplace-internal-bool-helpers

#include "block_index_flat_internal.h"
#include "services/block_index_flat_anchor.h"
#include "services/block_index_integrity.h"
#include "storage/sha3_sidecar_io.h"
#include "chain/chain.h"
#include "crypto/sha3.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include "platform/file_sync.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#define BFI_ROW sizeof(struct block_index_flat)
#define BFI_HDR SSIO_EMBEDDED_HEADER_BYTES
#define BFI_PREFIX 8u
#define BFI_CHUNK_ROWS 8192u

#ifdef ZCL_TESTING
int g_block_index_flat_inplace_fault;
#endif

struct bfi_run { uint64_t first; uint64_t rows; };

struct bfi {
    int fd;
    struct block_index **sorted;
    size_t n;
    uint64_t old_size;
    struct bfi_run *runs;
    size_t nruns;
    uint64_t changed;
    uint8_t prefix[BFI_PREFIX];
    uint8_t old_prefix[BFI_PREFIX];
    uint8_t anchor[BIFA_TRAILER_MAX];
    size_t anchor_len;
    uint8_t *enc;
    uint8_t *old;
    uint64_t written;
    bool crashed;
    struct sha3_256_ctx sha3;
    struct sha3_256_ctx diff_sha3;
};

static bool bfi_pread_full(int fd, void *buf, size_t len, uint64_t off,
                           size_t *got)
{
    size_t done = 0;
    while (done < len) {
        ssize_t r = pread(fd, (uint8_t *)buf + done, len - done,
                          (off_t)(off + done));
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) return false;
        if (r == 0) break;
        done += (size_t)r;
    }
    *got = done;
    return true;
}

static bool bfi_pwrite_full(struct bfi *b, const void *buf, size_t len,
                            uint64_t off)
{
    size_t done = 0;
    while (done < len) {
        ssize_t w = pwrite(b->fd, (const uint8_t *)buf + done, len - done,
                           (off_t)(off + done));
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return false;
        done += (size_t)w;
    }
    b->written += len;
    return true;
}

/* The old header must be an intact embedded header of this magic/version
 * whose declared size matches the file; the payload prefix must carry the
 * flat magic and a row count whose rows (at the CURRENT row size) leave at
 * most one anchor trailer. Anything else is a full rewrite. */
static bool bfi_old_shape_ok(struct bfi *b)
{
    struct ssio_sidecar_header h;
    size_t got = 0;
    if (b->old_size < BFI_HDR + BFI_PREFIX ||
        !bfi_pread_full(b->fd, &h, sizeof(h), 0, &got) || got != sizeof(h))
        return false;
    if (memcmp(h.magic, BII_EMBEDDED_MAGIC, 4) != 0 ||
        h.version != BII_EMBEDDED_VERSION ||
        h.body_size != b->old_size - BFI_HDR)
        return false;
    uint32_t magic, count;
    if (!bfi_pread_full(b->fd, b->old_prefix, BFI_PREFIX, BFI_HDR, &got) ||
        got != BFI_PREFIX)
        return false;
    memcpy(&magic, b->old_prefix, 4);
    memcpy(&count, b->old_prefix + 4, 4);
    if (magic != 0x5A434C49 || h.body_size < BFI_PREFIX + (uint64_t)count * BFI_ROW)
        return false;
    return h.body_size - BFI_PREFIX - (uint64_t)count * BFI_ROW <=
           BIFA_TRAILER_MAX;
}

/* Encode rows [first, first+cnt) into b->enc. */
static void bfi_encode_rows(struct bfi *b, uint64_t first, size_t cnt)
{
    for (size_t j = 0; j < cnt; j++) {
        struct block_index_flat row;
        block_index_flat_encode_row(b->sorted[first + j], &row);
        memcpy(b->enc + j * BFI_ROW, &row, BFI_ROW);
    }
}

static bool bfi_note_row(struct bfi *b, uint64_t row)
{
    if (b->nruns && b->runs[b->nruns - 1].first +
                    b->runs[b->nruns - 1].rows == row) {
        b->runs[b->nruns - 1].rows++;
    } else {
        b->runs[b->nruns].first = row;
        b->runs[b->nruns].rows = 1;
        b->nruns++;
    }
    b->changed++;
    return b->changed <= b->n / 4;
}

/* Pass 1 over one chunk: hash every encoded row, diff against the file. */
static bool bfi_scan_chunk(struct bfi *b, uint64_t first, size_t cnt)
{
    bfi_encode_rows(b, first, cnt);
    sha3_256_write(&b->sha3, b->enc, cnt * BFI_ROW);
    uint64_t off = BFI_HDR + BFI_PREFIX + first * BFI_ROW;
    size_t got = 0;
    if (off < b->old_size && !bfi_pread_full(b->fd, b->old, cnt * BFI_ROW,
                                             off, &got))
        return false;
    for (size_t j = 0; j < cnt; j++) {
        bool same = (j + 1) * BFI_ROW <= got &&
            memcmp(b->enc + j * BFI_ROW, b->old + j * BFI_ROW, BFI_ROW) == 0;
        if (same) continue;
        sha3_256_write(&b->diff_sha3, b->enc + j * BFI_ROW, BFI_ROW);
        if (!bfi_note_row(b, first + j)) return false;
    }
    return true;
}

static bool bfi_scan_rows(struct bfi *b)
{
    for (uint64_t i = 0; i < b->n; i += BFI_CHUNK_ROWS) {
        size_t cnt = b->n - i < BFI_CHUNK_ROWS ? (size_t)(b->n - i)
                                               : BFI_CHUNK_ROWS;
        if (!bfi_scan_chunk(b, i, cnt)) return false;
    }
    return true;
}

static bool bfi_scan(struct bfi *b, struct main_state *ms,
                     uint8_t sha3_out[32], uint64_t *size_out)
{
    uint32_t magic = 0x5A434C49, count = (uint32_t)b->n;
    memcpy(b->prefix, &magic, 4);
    memcpy(b->prefix + 4, &count, 4);
    sha3_256_init(&b->sha3);
    sha3_256_init(&b->diff_sha3);
    sha3_256_write(&b->sha3, b->prefix, BFI_PREFIX);
    if (!bfi_scan_rows(b)) return false;
    if (!block_index_flat_anchor_encode(ms, b->sorted, b->n, b->anchor,
                                        sizeof(b->anchor), &b->anchor_len).ok)
        return false;
    sha3_256_write(&b->sha3, b->anchor, b->anchor_len);
    sha3_256_finalize(&b->sha3, sha3_out);
    *size_out = BFI_PREFIX + (uint64_t)b->n * BFI_ROW + b->anchor_len;
    return true;
}

/* Pass 2: write the changed runs, re-encoding them and re-checking that the
 * bytes are the ones pass 1 hashed (a concurrent mutation aborts to the
 * full rewrite instead of publishing a digest over different bytes). */
static bool bfi_write_runs(struct bfi *b)
{
    struct sha3_256_ctx again;
    sha3_256_init(&again);
    for (size_t r = 0; r < b->nruns; r++) {
        for (uint64_t k = 0; k < b->runs[r].rows; k += BFI_CHUNK_ROWS) {
            uint64_t left = b->runs[r].rows - k;
            size_t cnt = left < BFI_CHUNK_ROWS ? (size_t)left : BFI_CHUNK_ROWS;
            uint64_t first = b->runs[r].first + k;
            bfi_encode_rows(b, first, cnt);
            sha3_256_write(&again, b->enc, cnt * BFI_ROW);
            if (!bfi_pwrite_full(b, b->enc, cnt * BFI_ROW,
                                 BFI_HDR + BFI_PREFIX + first * BFI_ROW))
                return false;
        }
    }
    uint8_t a[32], d[32];
    sha3_256_finalize(&again, a);
    sha3_256_finalize(&b->diff_sha3, d);
    return memcmp(a, d, 32) == 0;
}

static bool bfi_write_tail(struct bfi *b, uint64_t payload_size)
{
    uint64_t atail = BFI_HDR + BFI_PREFIX + (uint64_t)b->n * BFI_ROW;
    if (memcmp(b->prefix, b->old_prefix, BFI_PREFIX) != 0 &&
        !bfi_pwrite_full(b, b->prefix, BFI_PREFIX, BFI_HDR))
        return false;
    size_t got = 0;
    uint8_t oldtail[BIFA_TRAILER_MAX];
    if (atail < b->old_size &&
        !bfi_pread_full(b->fd, oldtail, b->anchor_len, atail, &got))
        return false;
    bool same_tail = atail + b->anchor_len <= b->old_size &&
                     got == b->anchor_len &&
                     memcmp(oldtail, b->anchor, b->anchor_len) == 0;
    if (b->anchor_len && !same_tail &&
        !bfi_pwrite_full(b, b->anchor, b->anchor_len, atail))
        return false;
    if (b->old_size > BFI_HDR + payload_size &&
        ftruncate(b->fd, (off_t)(BFI_HDR + payload_size)) != 0)
        return false;
    return true;
}

static bool bfi_write_header(struct bfi *b, uint64_t payload_size,
                             const uint8_t sha3[32])
{
    struct ssio_sidecar_header h;
    memset(&h, 0, sizeof(h));
    memcpy(h.magic, BII_EMBEDDED_MAGIC, 4);
    h.version = BII_EMBEDDED_VERSION;
    h.body_size = payload_size;
    memcpy(h.body_sha3, sha3, 32);
    return bfi_pwrite_full(b, &h, sizeof(h), 0) &&
           platform_file_sync(b->fd) == 0;
}

static void bfi_sync_dir(const char *datadir)
{
    char side[1100];
    snprintf(side, sizeof(side), "%s/block_index.bin.sha3", datadir);
    (void)unlink(side); /* legacy sidecar is redundant, as in the full path */
    int dfd = open(datadir, O_RDONLY | O_DIRECTORY);
    if (dfd >= 0) {
        (void)platform_file_sync(dfd);
        close(dfd);
    }
}

/* Crash-order argument. The old header (offset 0..47) commits to the OLD
 * payload digest and size. Every payload byte is changed in place while that
 * old header is still on disk, and the payload is fsynced BEFORE the header
 * is rewritten. A crash during the payload writes therefore leaves a file
 * whose old header does not verify over the half-new payload (bii_verify_
 * embedded re-hashes it and returns STALE, so boot falls back to a slower
 * load rung); a crash after the payload sync but before the header write
 * leaves the same rejected file; a crash after the header write but before
 * its sync leaves either the old header (rejected) or the new header over a
 * fully durable payload (valid). The new header is written only after every
 * row, the anchor and the truncation are durable, so no state exists in
 * which a header verifies over rows that are not all written. */
static bool bfi_publish(struct bfi *b, const char *datadir,
                        uint64_t payload_size, const uint8_t sha3[32])
{
    if (!bfi_write_runs(b) || !bfi_write_tail(b, payload_size) ||
        platform_file_sync(b->fd) != 0)
        return false;
#ifdef ZCL_TESTING
    if (g_block_index_flat_inplace_fault) { b->crashed = true; return false; }
#endif
    if (!bfi_write_header(b, payload_size, sha3)) return false;
    bfi_sync_dir(datadir);
    return true;
}

static bool bfi_open(struct bfi *b, const char *datadir, size_t n)
{
    char path[1100];
    struct stat st;
    snprintf(path, sizeof(path), "%s/block_index.bin", datadir);
    b->fd = open(path, O_RDWR | O_CLOEXEC);
    if (b->fd < 0) return false;
    if (fstat(b->fd, &st) != 0 || !S_ISREG(st.st_mode)) return false;
    b->old_size = (uint64_t)st.st_size;
    b->runs = zcl_malloc((n / 4 + 1) * sizeof(*b->runs), "bfi runs");
    b->enc = zcl_malloc(BFI_CHUNK_ROWS * BFI_ROW, "bfi enc");
    b->old = zcl_malloc(BFI_CHUNK_ROWS * BFI_ROW, "bfi old");
    return b->runs && b->enc && b->old && bfi_old_shape_ok(b);
}

static void bfi_close(struct bfi *b)
{
    if (b->fd >= 0) close(b->fd);
    free(b->runs); free(b->enc); free(b->old);
}

enum bif_inplace block_index_flat_save_inplace(
    const char *datadir, struct main_state *ms, struct block_index **sorted,
    size_t n, struct block_index_flat_identity *ident, uint64_t *rewritten)
{
    struct bfi b;
    memset(&b, 0, sizeof(b));
    b.fd = -1; b.sorted = sorted; b.n = n;
    uint8_t sha3[32]; uint64_t size = 0;
    enum bif_inplace verdict = BIF_INPLACE_DECLINED;
    if (n && bfi_open(&b, datadir, n) && bfi_scan(&b, ms, sha3, &size)) {
        verdict = bfi_publish(&b, datadir, size, sha3) ? BIF_INPLACE_DONE
                                                       : BIF_INPLACE_FAILED;
        if (b.crashed) verdict = BIF_INPLACE_CRASHED;
        if (verdict == BIF_INPLACE_DONE) {
            memcpy(ident->payload_sha3, sha3, 32);
            ident->payload_size = size; ident->row_count = n;
            *rewritten = b.written;
        }
    }
    bfi_close(&b);
    return verdict;
}

#else /* _WIN32 */

enum bif_inplace block_index_flat_save_inplace(
    const char *datadir, struct main_state *ms, struct block_index **sorted,
    size_t n, struct block_index_flat_identity *ident, uint64_t *rewritten)
{
    (void)datadir; (void)ms; (void)sorted; (void)n; (void)ident;
    (void)rewritten;
    return BIF_INPLACE_DECLINED;
}

#endif
