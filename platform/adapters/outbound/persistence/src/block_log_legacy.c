/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton */

#include "adapters/outbound/persistence/block_log_legacy.h"

#include "storage/blocks_index_legacy_reader.h"
#include "storage/blocks_mmap_reader.h"
#include "core/uint256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct block_log_legacy {
    /* Owned readers. */
    struct bilr        *bilr;
    struct blocks_mmap *bmr;

    /* Height map from the legacy index. Indexed [0 .. height_count-1].
     * Slots without a block have height = -1. */
    struct legacy_block_loc *height_map;
    size_t                   height_count;

    /* Highest height with a valid entry, or UINT32_MAX if empty. */
    uint32_t                 tip_height_cached;
};

static bool entry_valid(const struct legacy_block_loc *e)
{
    return e && e->height >= 0;
}

static void recompute_tip(struct block_log_legacy *h)
{
    h->tip_height_cached = UINT32_MAX;
    if (h->height_count == 0)
        return;
    /* Walk from the top down — first valid entry is the tip. */
    for (size_t i = h->height_count; i > 0; --i) {
        if (entry_valid(&h->height_map[i - 1])) {
            h->tip_height_cached = (uint32_t)(i - 1);
            return;
        }
    }
}

/* ── Port methods ───────────────────────────────────────────── */

static struct zcl_result
legacy_append(void *self,
              uint32_t height,
              const struct block_hash *hash,
              const uint8_t *bytes,
              size_t len)
{
    (void)self; (void)height; (void)hash; (void)bytes; (void)len;
    return ZCL_ERR(BLOCK_LOG_ERR_NOT_SUPPORTED,
                   "block_log_legacy: read-only adapter; append rejected");
}

static struct zcl_result
legacy_read_at_height(void *self,
                      uint32_t height,
                      const uint8_t **bytes_out,
                      size_t *len_out)
{
    struct block_log_legacy *h = self;
    if (!h || !bytes_out || !len_out)
        return ZCL_ERR(BLOCK_LOG_ERR_IO, "read_at_height: null args");
    if (height >= h->height_count || !entry_valid(&h->height_map[height]))
        return ZCL_ERR(BLOCK_LOG_ERR_NOT_FOUND,
                       "block_log_legacy: no block at height %u", height);
    const struct legacy_block_loc *loc = &h->height_map[height];
    size_t plen = 0;
    const uint8_t *p = bmr_get_payload(h->bmr, loc->nFile, loc->nDataPos, &plen);
    if (!p)
        return ZCL_ERR(BLOCK_LOG_ERR_IO,
                       "block_log_legacy: bmr miss at h=%u file=%d pos=%u",
                       height, loc->nFile, loc->nDataPos);
    *bytes_out = p;
    *len_out = plen;
    return ZCL_OK;
}

static struct zcl_result
legacy_read_by_hash(void *self,
                    const struct block_hash *hash,
                    const uint8_t **bytes_out,
                    size_t *len_out)
{
    struct block_log_legacy *h = self;
    if (!h || !hash || !bytes_out || !len_out)
        return ZCL_ERR(BLOCK_LOG_ERR_IO, "read_by_hash: null args");
    /* Linear scan over the height map. ~3M entries × 32B compare ≈
     * O(N) per call; acceptable for the shadow soak where reads are
     * dominated by sequential iter_from (which uses read_at_height
     * internally). If a future use case needs frequent random hash
     * lookups, swap in a hashmap at open() time. */
    for (size_t i = 0; i < h->height_count; ++i) {
        const struct legacy_block_loc *e = &h->height_map[i];
        if (!entry_valid(e)) continue;
        if (memcmp(e->hash.data, hash->bytes, 32) == 0)
            return legacy_read_at_height(self, (uint32_t)i,
                                         bytes_out, len_out);
    }
    return ZCL_ERR(BLOCK_LOG_ERR_NOT_FOUND,
                   "block_log_legacy: hash not present in legacy index");
}

static uint32_t legacy_tip_height(void *self)
{
    struct block_log_legacy *h = self;
    if (!h) return UINT32_MAX;
    return h->tip_height_cached;
}

static struct zcl_result
legacy_iter_from(void *self,
                 uint32_t start_height,
                 block_log_iter_fn cb,
                 void *user_data)
{
    struct block_log_legacy *h = self;
    if (!h || !cb)
        return ZCL_ERR(BLOCK_LOG_ERR_IO, "iter_from: null args");
    if (h->tip_height_cached == UINT32_MAX || start_height > h->tip_height_cached)
        return ZCL_OK;  /* empty range; not an error */
    for (uint32_t height = start_height;
         height <= h->tip_height_cached;
         ++height)
    {
        if (height >= h->height_count) break;
        if (!entry_valid(&h->height_map[height])) continue;
        const struct legacy_block_loc *loc = &h->height_map[height];
        size_t plen = 0;
        const uint8_t *p = bmr_get_payload(h->bmr, loc->nFile, loc->nDataPos,
                                           &plen);
        if (!p)
            return ZCL_ERR(BLOCK_LOG_ERR_IO,
                           "block_log_legacy: iter bmr miss at h=%u", height);
        struct block_hash bh;
        memcpy(bh.bytes, loc->hash.data, 32);
        if (!cb(height, &bh, p, plen, user_data))
            return ZCL_OK;
    }
    return ZCL_OK;
}

/* ── Lifecycle ──────────────────────────────────────────────── */

struct zcl_result block_log_legacy_open(const char *datadir,
                                        struct block_log_legacy **out_handle,
                                        struct block_log_port *out_port)
{
    if (!datadir || !out_handle || !out_port)
        return ZCL_ERR(BLOCK_LOG_ERR_IO, "block_log_legacy_open: null args");

    char blocks_dir[1024];
    snprintf(blocks_dir, sizeof blocks_dir, "%s/blocks", datadir);
    struct stat st;
    if (stat(blocks_dir, &st) != 0)
        return ZCL_ERR(BLOCK_LOG_ERR_NOT_FOUND,
                       "block_log_legacy_open: %s missing", blocks_dir);

    char index_dir[1024];
    snprintf(index_dir, sizeof index_dir, "%s/blocks/index", datadir);

    struct block_log_legacy *h = calloc(1, sizeof *h);
    if (!h)
        return ZCL_ERR(BLOCK_LOG_ERR_IO,
                       "block_log_legacy_open: calloc handle");
    h->tip_height_cached = UINT32_MAX;

    if (!bilr_open(index_dir, &h->bilr)) {
        free(h);
        return ZCL_ERR(BLOCK_LOG_ERR_IO,
                       "block_log_legacy_open: bilr_open(%s) failed "
                       "(LOCK held by zclassicd?)", index_dir);
    }
    if (!bilr_load_height_map(h->bilr, &h->height_map, &h->height_count)) {
        bilr_close(h->bilr);
        free(h);
        return ZCL_ERR(BLOCK_LOG_ERR_CORRUPT,
                       "block_log_legacy_open: bilr_load_height_map failed");
    }
    if (!bmr_open(blocks_dir, &h->bmr)) {
        bilr_free_height_map(h->height_map);
        bilr_close(h->bilr);
        free(h);
        return ZCL_ERR(BLOCK_LOG_ERR_IO,
                       "block_log_legacy_open: bmr_open(%s) failed",
                       blocks_dir);
    }

    recompute_tip(h);

    *out_port = (struct block_log_port){
        .self           = h,
        .append         = legacy_append,
        .read_by_hash   = legacy_read_by_hash,
        .read_at_height = legacy_read_at_height,
        .tip_height     = legacy_tip_height,
        .iter_from      = legacy_iter_from,
    };
    *out_handle = h;
    return ZCL_OK;
}

void block_log_legacy_close(struct block_log_legacy *h)
{
    if (!h) return;
    if (h->bmr)        bmr_close(h->bmr);
    if (h->height_map) bilr_free_height_map(h->height_map);
    if (h->bilr)       bilr_close(h->bilr);
    free(h);
}

size_t block_log_legacy_loaded_count(const struct block_log_legacy *h)
{
    if (!h) return 0;
    size_t n = 0;
    for (size_t i = 0; i < h->height_count; ++i) {
        if (entry_valid(&h->height_map[i])) ++n;
    }
    return n;
}
