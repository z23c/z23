/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "config/boot_memory_guard.h"
#include "chain/chain.h"
#include "validation/chainstate.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>

#define BMG_CHECK(name, expr) do {                                      \
    printf("boot_memory_guard: %s... ", (name));                      \
    if (expr) printf("OK\n");                                         \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

int test_boot_memory_guard(void)
{
    int failures = 0;

    BMG_CHECK("estimate count uses persisted positive height",
              boot_block_index_estimate_count(42) == 42);

    BMG_CHECK("estimate count falls back for missing height",
              boot_block_index_estimate_count(0) ==
                  BOOT_BLOCK_INDEX_DEFAULT_ESTIMATE_COUNT &&
              boot_block_index_estimate_count(-7) ==
                  BOOT_BLOCK_INDEX_DEFAULT_ESTIMATE_COUNT);

    {
        const int64_t count = 17;
        size_t expected = (size_t)count *
            (sizeof(struct block_index) + 2 * sizeof(struct block_map_entry));
        BMG_CHECK("estimate bytes match block index plus hash map formula",
                  boot_block_index_estimate_bytes(count) == expected);
    }

    BMG_CHECK("estimate bytes handles non-positive counts",
              boot_block_index_estimate_bytes(0) == 0 &&
              boot_block_index_estimate_bytes(-1) == 0);

    BMG_CHECK("estimate bytes saturates on overflow",
              boot_block_index_estimate_bytes(INT64_MAX) == SIZE_MAX);

    BMG_CHECK("warning threshold is strictly above half of RAM",
              !boot_block_index_memory_should_warn(50, 100) &&
              boot_block_index_memory_should_warn(51, 100) &&
              !boot_block_index_memory_should_warn(51, 0));

    BMG_CHECK("reindex flushes at the byte cap even with few txids",
              !boot_reindex_cache_should_flush(
                  1, 1, BOOT_REINDEX_CACHE_MAX_BYTES - 1) &&
              boot_reindex_cache_should_flush(
                  1, 1, BOOT_REINDEX_CACHE_MAX_BYTES));

    BMG_CHECK("reindex retains periodic and txid safety caps",
              boot_reindex_cache_should_flush(10000, 0, 0) &&
              boot_reindex_cache_should_flush(
                  1, BOOT_REINDEX_CACHE_MAX_ENTRIES + 1, 0) &&
              !boot_reindex_cache_should_flush(
                  1, BOOT_REINDEX_CACHE_MAX_ENTRIES, 0));

    return failures;
}
