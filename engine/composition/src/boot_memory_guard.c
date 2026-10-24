/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "config/boot_memory_guard.h"

#include "chain/chain.h"
#include "platform/system_memory.h"
#include "validation/chainstate.h"

#include "base/log_macros.h"
#include "core/arith_uint256.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t boot_system_ram_bytes(void)
{
    uint64_t bytes = 0;
    if (!platform_system_memory_bytes(&bytes) || bytes > SIZE_MAX)
        return 0;
    return (size_t)bytes;
}

int64_t boot_block_index_estimate_count(int64_t persisted_height)
{
    return persisted_height > 0 ? persisted_height
                                : BOOT_BLOCK_INDEX_DEFAULT_ESTIMATE_COUNT;
}

size_t boot_block_index_estimate_bytes(int64_t entry_count)
{
    if (entry_count <= 0)
        return 0;

    const size_t bytes_per_entry =
        sizeof(struct block_index) + 2 * sizeof(struct block_map_entry);
    size_t count = (size_t)entry_count;
    if (count > SIZE_MAX / bytes_per_entry)
        return SIZE_MAX;
    return count * bytes_per_entry;
}

bool boot_block_index_memory_should_warn(size_t estimate_bytes,
                                         size_t system_ram_bytes)
{
    return system_ram_bytes > 0 && estimate_bytes > system_ram_bytes / 2;
}

void boot_block_index_memory_warn(int64_t persisted_height)
{
    size_t sys_ram = boot_system_ram_bytes();
    if (sys_ram == 0)
        return;

    int64_t est_count = boot_block_index_estimate_count(persisted_height);
    size_t est_mem = boot_block_index_estimate_bytes(est_count);
    if (boot_block_index_memory_should_warn(est_mem, sys_ram)) {
        fprintf(stderr,
            "[boot] WARNING: block index estimated at %zuMB "
            "(%lld entries x %zu bytes + hash map)\n"
            "[boot] System has %zuMB RAM. This may cause OOM.\n",
            est_mem / (1024 * 1024), (long long)est_count,
            sizeof(struct block_index),
            sys_ram / (1024 * 1024));
    }
    printf("[boot] system_ram=%zuMB block_index_estimate=%zuMB "
           "(%lld entries)\n",
           sys_ram / (1024 * 1024), est_mem / (1024 * 1024),
           (long long)est_count);
}

void boot_block_index_memory_log_loaded(size_t entry_count,
                                        size_t map_capacity)
{
    size_t entry_bytes = entry_count * sizeof(struct block_index);
    size_t map_bytes = map_capacity * sizeof(struct block_map_entry);
    size_t total_bytes = entry_bytes + map_bytes;
    printf("[boot] block_index: %zu entries, %zu bytes/entry, "
           "index=%zuMB map=%zuMB total=%zuMB\n",
           entry_count, sizeof(struct block_index),
           entry_bytes / (1024 * 1024),
           map_bytes / (1024 * 1024),
           total_bytes / (1024 * 1024));
}

static int boot_root_cmp(const void *a, const void *b)
{
    const struct uint256 *x = *(const struct uint256 *const *)a;
    const struct uint256 *y = *(const struct uint256 *const *)b;
    return memcmp(x->data, y->data, sizeof(x->data));
}

/* Collect a pointer to every entry's Sapling root and track the widest
 * nChainWork. Returns the number of roots collected. */
static size_t boot_collect_roots(const struct block_map *m,
                                 const struct uint256 **roots,
                                 unsigned int *max_work_bits)
{
    size_t n = 0, iter = 0;
    const struct uint256 *key = NULL;
    struct block_index *bi = NULL;
    *max_work_bits = 0;
    while (block_map_next(m, &iter, &key, &bi)) {
        unsigned int bits = arith_uint256_bits(&bi->nChainWork);
        if (bits > *max_work_bits)
            *max_work_bits = bits;
        roots[n++] = &bi->hashFinalSaplingRoot;
    }
    return n;
}

void boot_block_index_log_shape(const struct block_map *m)
{
    size_t count = block_map_count(m);
    if (count == 0)
        return;
    const struct uint256 **roots =
        zcl_calloc(count, sizeof(*roots), "boot_blkidx_shape");
    if (!roots) {
        LOG_WARN("boot", "block_index shape: allocation of %zu roots failed",
                 count);
        return;
    }
    unsigned int max_bits = 0;
    size_t n = boot_collect_roots(m, roots, &max_bits);
    qsort(roots, n, sizeof(*roots), boot_root_cmp);
    size_t distinct = 0;
    for (size_t i = 0; i < n; i++) {
        if (i == 0 || boot_root_cmp(&roots[i - 1], &roots[i]) != 0)
            distinct++;
    }
    free(roots);
    LOG_INFO("boot",
             "block_index shape: %zu entries, %zu distinct sapling roots, "
             "max chain-work bit length %u",
             n, distinct, max_bits);
}

bool boot_reindex_cache_should_flush(int height, size_t entry_count,
                                     size_t memory_bytes)
{
    return (height >= 0 && height % 10000 == 0) ||
           entry_count > BOOT_REINDEX_CACHE_MAX_ENTRIES ||
           memory_bytes >= BOOT_REINDEX_CACHE_MAX_BYTES;
}
