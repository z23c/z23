/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: read integrity-bound headers from the flat block index, one
 * shot at a time (block_index_flat_header_at) or as a batched cursor
 * (block_index_flat_cursor_*), which also names the best header and its
 * ancestors.
 *
 * Locking: none. Both entry points only open/mmap/read; they never take
 * the reducer drive lock, coins_kv, cs_main, or any coverage lock, so
 * there is no lock order to invert (drive holds coins_kv; readers here
 * hold nothing). A cursor pins its fd + mapping until close; it does
 * not observe files replaced under it, which is exactly the snapshot
 * semantic a range scan wants. */

#include "block_index_flat_internal.h"
#include "chain/chain.h"                  /* block status bits */
#include "core/arith_uint256.h"           /* chain work */
#include "platform/read_mapping.h"
#include "services/block_index_integrity.h"
#include "services/block_index_loader.h"
#include "storage/sha3_sidecar_io.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if defined(_WIN32)
#include <io.h>
#define flat_close _close
#else
#include <unistd.h>
#define flat_close close
#endif

/* Owned by block_index_flat_cursor_open; freed by
 * block_index_flat_cursor_close. The entries pointer borrows the
 * mapping, so close must unmap before freeing the handle. */
struct block_index_flat_cursor {
    int fd;
    struct platform_read_mapping mapping;
    const struct block_index_flat *entries;
    uint32_t count;
    int32_t tip_height;
    uint32_t best;          /* row of the best header; count until found */
};

static _Atomic uint64_t g_flat_cursor_opens = 0;

static void flat_header_mapping_close(struct platform_read_mapping *mapping,
                                      int fd)
{
    platform_read_mapping_close(mapping);
    if (fd >= 0) (void)flat_close(fd);
}

/* Shared open+verify+index prologue. `who` selects the message prefix so
 * the single-shot path keeps its historical strings byte for byte while
 * the cursor path carries its own name. On success the caller owns
 * (*out_mapping, fd) and receives the resolved row table. */
static struct zcl_result flat_open_resolved(
    const char *datadir, const char *who, int fd,
    struct platform_read_mapping *out_mapping,
    const struct block_index_flat **out_entries, uint32_t *out_count,
    int32_t *out_tip)
{
    struct stat st;
    if (fstat(fd, &st) != 0) {
        int saved_errno = errno;
        (void)flat_close(fd);
        return ZCL_ERR(-102, "%s: fstat: %s", who, strerror(saved_errno));
    }
    size_t file_size = (size_t)st.st_size;
    if (file_size < 8) {
        (void)flat_close(fd);
        return ZCL_ERR(-103, "%s: file too small (%zu bytes)",
                       who, file_size);
    }
    platform_read_mapping_init(out_mapping);
    if (!platform_read_mapping_open(out_mapping, fd, file_size)) {
        (void)flat_close(fd);
        return ZCL_ERR(-104, "%s: mapping failed (%zu bytes)",
                       who, file_size);
    }
    platform_read_mapping_advise_sequential(out_mapping);
    const uint8_t *data = out_mapping->data;
    uint64_t payload_off = 0;
    uint32_t lead, embedded_magic;
    memcpy(&lead, data, 4);
    memcpy(&embedded_magic, BII_EMBEDDED_MAGIC, 4);
    if (lead != embedded_magic) {
        flat_header_mapping_close(out_mapping, fd);
        return ZCL_ERR(-105, "%s: no embedded integrity header; refusing "
                       "unverified legacy bytes", who);
    }
    struct ssio_sidecar_header header;
    int verdict = bii_verify_embedded(datadir, &header, &payload_off);
    if (verdict != 0) {
        flat_header_mapping_close(out_mapping, fd);
        return ZCL_ERR(-106, "%s: embedded integrity check failed "
                       "(verdict=%d)", who, verdict);
    }
    uint32_t magic, count;
    if (payload_off > file_size - 8) {
        flat_header_mapping_close(out_mapping, fd);
        return ZCL_ERR(-107, "%s: payload offset %llu exceeds mapped file "
                       "(%zu bytes)", who,
                       (unsigned long long)payload_off, file_size);
    }
    memcpy(&magic, data + payload_off, 4);
    memcpy(&count, data + payload_off + 4, 4);
    if (magic != 0x5A434C49 || count == 0 || count > 10000000) {
        flat_header_mapping_close(out_mapping, fd);
        return ZCL_ERR(-108, "%s: invalid magic/count (magic=0x%08x "
                       "count=%u)", who, magic, count);
    }
    size_t expected = payload_off + 8 +
                      (size_t)count * sizeof(struct block_index_flat);
    if (file_size < expected) {
        flat_header_mapping_close(out_mapping, fd);
        return ZCL_ERR(-109, "%s: truncated (%zu < %zu bytes for %u "
                       "entries)", who, file_size, expected, count);
    }
    *out_entries =
        (const struct block_index_flat *)(data + payload_off + 8);
    *out_count = count;
    *out_tip = (*out_entries)[count - 1].height;
    return ZCL_OK;
}

/* The first row at or above `height` in the height-sorted table; count when
 * every row is lower. */
static uint32_t flat_lower_bound(const struct block_index_flat *entries,
                                 uint32_t count, int32_t height)
{
    uint32_t lo = 0, hi = count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (entries[mid].height < height) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

/* Shared height lookup over a resolved row table. `who` selects the
 * message prefix, mirroring flat_open_resolved. */
static struct zcl_result flat_lookup(const char *who,
                                     const struct block_index_flat *entries,
                                     uint32_t count, int32_t tip_height,
                                     int32_t height,
                                     uint8_t out_hash[32],
                                     uint8_t out_root[32])
{
    uint32_t lo = flat_lower_bound(entries, count, height);
    if (lo >= count || entries[lo].height != height) {
        return ZCL_ERR(-110, "%s: no row at height %d (flat tip %d)",
                       who, height, tip_height);
    }
    memcpy(out_hash, entries[lo].hash, 32);
    memcpy(out_root, entries[lo].sapling_root, 32);
    return ZCL_OK;
}

struct zcl_result block_index_flat_cursor_open(
    const char *datadir, struct block_index_flat_cursor **out)
{
    static const char *who = "block_index_flat_cursor_open";
    if (!datadir || !out)
        return ZCL_ERR(-100, "%s: bad args", who);
    *out = NULL;
    char path[1024];
    snprintf(path, sizeof(path), "%s/block_index.bin", datadir);
    atomic_fetch_add(&g_flat_cursor_opens, 1);
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return ZCL_ERR(-101, "%s: cannot open %s: %s", who, path,
                       strerror(errno));
    struct block_index_flat_cursor *cur = zcl_malloc(sizeof(*cur),
                                                     "flat header cursor");
    if (!cur) {
        (void)flat_close(fd);
        return ZCL_ERR(-111, "%s: cursor alloc failed", who);
    }
    cur->fd = fd;
    const struct block_index_flat *entries = NULL;
    uint32_t count = 0;
    int32_t tip = 0;
    struct zcl_result r = flat_open_resolved(datadir, who, fd,
                                             &cur->mapping, &entries,
                                             &count, &tip);
    if (!r.ok) {
        free(cur);
        return r;
    }
    cur->entries = entries;
    cur->count = count;
    cur->tip_height = tip;
    cur->best = count;
    *out = cur;
    return ZCL_OK;
}

struct zcl_result block_index_flat_cursor_read(
    struct block_index_flat_cursor *cur, int32_t height,
    uint8_t out_hash[32], uint8_t out_root[32])
{
    static const char *who = "block_index_flat_cursor_read";
    if (!cur || height < 0 || !out_hash || !out_root)
        return ZCL_ERR(-100, "%s: bad args", who);
    return flat_lookup(who, cur->entries, cur->count, cur->tip_height,
                       height, out_hash, out_root);
}

/* A header row the node accepted and has not since marked failed. */
static bool flat_row_accepted(const struct block_index_flat *row)
{
    return (row->n_status & BLOCK_FAILED_ANY_MASK) == 0 &&
           (row->n_status & BLOCK_VALID_MASK) >= BLOCK_VALID_TREE;
}

static bool flat_row_more_work(const struct block_index_flat *a,
                               const struct block_index_flat *b)
{
    struct arith_uint256 wa, wb;
    memcpy(wa.pn, a->chain_work, sizeof(wa.pn));
    memcpy(wb.pn, b->chain_work, sizeof(wb.pn));
    return arith_uint256_compare(&wa, &wb) > 0;
}

/* One pass from the top: an equal-work row lower down never replaces one
 * found above it. */
static void flat_find_best(struct block_index_flat_cursor *cur)
{
    for (uint32_t i = cur->count; i > 0; i--) {
        const struct block_index_flat *row = &cur->entries[i - 1];
        if (flat_row_accepted(row) &&
            (cur->best == cur->count ||
             flat_row_more_work(row, &cur->entries[cur->best])))
            cur->best = i - 1;
    }
}

struct zcl_result block_index_flat_cursor_best(
    struct block_index_flat_cursor *cur, int32_t *height)
{
    static const char *who = "block_index_flat_cursor_best";
    if (!cur || !height)
        return ZCL_ERR(-100, "%s: bad args", who);
    if (cur->best == cur->count)
        flat_find_best(cur);
    if (cur->best == cur->count)
        return ZCL_ERR(-112, "%s: no accepted header row (flat tip %d)", who,
                       cur->tip_height);
    *height = cur->entries[cur->best].height;
    return ZCL_OK;
}

/* The row at `height` whose hash is `hash`, or NULL. */
static const struct block_index_flat *flat_row_with_hash(
    const struct block_index_flat_cursor *cur, int32_t height,
    const uint8_t hash[32])
{
    for (uint32_t i = flat_lower_bound(cur->entries, cur->count, height);
         i < cur->count && cur->entries[i].height == height; i++)
        if (memcmp(cur->entries[i].hash, hash, 32) == 0)
            return &cur->entries[i];
    return NULL;
}

struct zcl_result block_index_flat_cursor_best_ancestor(
    struct block_index_flat_cursor *cur, int32_t height, uint8_t out_hash[32])
{
    static const char *who = "block_index_flat_cursor_best_ancestor";
    int32_t best = 0;
    if (!cur || height < 0 || !out_hash)
        return ZCL_ERR(-100, "%s: bad args", who);
    struct zcl_result r = block_index_flat_cursor_best(cur, &best);
    if (!r.ok)
        return r;
    if (height > best)
        return ZCL_ERR(-110, "%s: height %d is above the best header %d", who,
                       height, best);
    const struct block_index_flat *row = &cur->entries[cur->best];
    while (row && row->height > height)
        row = flat_row_with_hash(cur, row->height - 1, row->prev_hash);
    if (!row)
        return ZCL_ERR(-113, "%s: the best header's ancestry breaks above "
                       "height %d", who, height);
    memcpy(out_hash, row->hash, 32);
    return ZCL_OK;
}

void block_index_flat_cursor_close(struct block_index_flat_cursor *cur)
{
    if (!cur)
        return;
    flat_header_mapping_close(&cur->mapping, cur->fd);
    free(cur);
}

uint64_t block_index_flat_cursor_opens_for_testing(void)
{
    return atomic_load(&g_flat_cursor_opens);
}

struct zcl_result block_index_flat_header_at(const char *datadir,
                                             int32_t height,
                                             uint8_t out_hash[32],
                                             uint8_t out_root[32])
{
    static const char *who = "block_index_flat_header_at";
    if (!datadir || height < 0 || !out_hash || !out_root)
        return ZCL_ERR(-100, "%s: bad args", who);
    char path[1024];
    snprintf(path, sizeof(path), "%s/block_index.bin", datadir);
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return ZCL_ERR(-101, "%s: cannot open %s: %s", who, path,
                       strerror(errno));
    /* Single-shot: open, verify, look up, close. The open and lookup run
     * through the same shared prologue/helpers as the batched cursor, so
     * one code path defines both; only the lifetime differs. */
    struct platform_read_mapping mapping;
    const struct block_index_flat *entries = NULL;
    uint32_t count = 0;
    int32_t tip = 0;
    struct zcl_result r = flat_open_resolved(datadir, who, fd, &mapping,
                                             &entries, &count, &tip);
    if (!r.ok)
        return r;
    r = flat_lookup(who, entries, count, tip, height, out_hash, out_root);
    flat_header_mapping_close(&mapping, fd);
    return r;
}
