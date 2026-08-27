/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "config/boot_memory_guard.h"

#include "chain/chain.h"
#include "platform/system_memory.h"
#include "validation/chainstate.h"

#include <stdio.h>

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

bool boot_reindex_cache_should_flush(int height, size_t entry_count,
                                     size_t memory_bytes)
{
    return (height >= 0 && height % 10000 == 0) ||
           entry_count > BOOT_REINDEX_CACHE_MAX_ENTRIES ||
           memory_bytes >= BOOT_REINDEX_CACHE_MAX_BYTES;
}
