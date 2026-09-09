/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: sequential projection prefetch with a bounded SQLite working set.
 * Prefetched bytes confer no authority and are never parsed here. SQLite
 * retains ownership of WAL recovery, page validation, and durable writes. */
#include "block_index_projection_internal.h"
#include "platform/os_proc.h"
#include "util/boot_phase.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/storage_pacing.h"
#include "util/thread_registry.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#define BIP_CACHE_MAX_BYTES UINT64_C(2147483648)
#define BIP_CACHE_MIN_FILE_BYTES UINT64_C(33554432)
#define BIP_CACHE_READ_BYTES 65536

static uint64_t cache_limit_headroom(uint64_t budget, int64_t limit,
                                    int64_t current)
{
    if (limit < 0)
        return budget;
    if (current < 0 || current >= limit)
        return 0;
    uint64_t available = (uint64_t)(limit - current) / 4;
    return available < budget ? available : budget;
}

uint64_t block_index_projection_cache_budget(uint64_t bytes,
                                             const struct os_proc_mem *mem)
{
    if (!mem || mem->sys_total_bytes <= 0 || mem->sys_avail_bytes <= 0 ||
        bytes < BIP_CACHE_MIN_FILE_BYTES || bytes > BIP_CACHE_MAX_BYTES)
        return 0;
    uint64_t budget = (uint64_t)mem->sys_total_bytes / 8;
    uint64_t available = (uint64_t)mem->sys_avail_bytes / 4;
    if (available < budget) budget = available;
    if (budget > BIP_CACHE_MAX_BYTES) budget = BIP_CACHE_MAX_BYTES;
    budget = cache_limit_headroom(budget, mem->cgroup_high,
                                  mem->cgroup_current);
    budget = cache_limit_headroom(budget, mem->cgroup_max,
                                  mem->cgroup_current);
    /* Allow growth without preallocating it. cache_size counts page bytes;
     * SQLite metadata and other node memory still need separate headroom. */
    uint64_t wanted = bytes + bytes / 4;
    uint64_t baseline = (uint64_t)BIP_PAGE_CACHE_KIB * 1024;
    if (wanted < baseline) wanted = baseline;
    wanted = (wanted + 1023) / 1024 * 1024;
    return wanted <= budget ? wanted : 0;
}

uint64_t block_index_projection_cache_warm(sqlite3_file *file, uint64_t bytes)
{
    if (!file || !file->pMethods || !file->pMethods->xRead ||
        bytes == 0 || bytes > BIP_CACHE_MAX_BYTES)
        return 0;
    void *buffer = zcl_malloc(BIP_CACHE_READ_BYTES, "projection.prefetch");
    if (!buffer) {
        LOG_WARN("block_index_projection", "prefetch allocation unavailable");
        return 0;
    }
    uint64_t offset = 0;
    while (offset < bytes && !thread_registry_shutdown_requested()) {
        uint64_t left = bytes - offset;
        int amount = left < BIP_CACHE_READ_BYTES ? (int)left
                                                : BIP_CACHE_READ_BYTES;
        int rc = file->pMethods->xRead(file, buffer, amount,
                                      (sqlite3_int64)offset);
        if (rc != SQLITE_OK) {
            LOG_WARN("block_index_projection",
                     "prefetch stopped at byte=%" PRIu64 " rc=%d",
                     offset, rc);
            break;
        }
        offset += (uint64_t)amount;
        boot_progress_note("block_index.sequential_prefetch", offset, bytes);
    }
    free(buffer);
    return offset;
}

void block_index_projection_cache_prepare(sqlite3 *db)
{
    if (!db || storage_pacing_class() != PLATFORM_STORAGE_CLASS_ROTATIONAL)
        return;
    struct os_proc_mem mem;
    if (!os_proc_mem_read(&mem))
        return;
    sqlite3_file *file = NULL;
    sqlite3_int64 bytes = 0;
    if (sqlite3_file_control(db, "main", SQLITE_FCNTL_FILE_POINTER,
                             &file) != SQLITE_OK ||
        !file || !file->pMethods || !file->pMethods->xFileSize ||
        file->pMethods->xFileSize(file, &bytes) != SQLITE_OK || bytes <= 0)
        return;
    uint64_t budget = block_index_projection_cache_budget((uint64_t)bytes,
                                                          &mem);
    if (!budget)
        return;
    char pragma[64];
    snprintf(pragma, sizeof(pragma), "PRAGMA cache_size=-%" PRIu64,
             (budget + 1023) / 1024);
    if (sqlite3_exec(db, pragma, NULL, NULL, NULL) != SQLITE_OK) {
        LOG_WARN("block_index_projection", "automatic cache sizing failed: %s",
                 sqlite3_errmsg(db));
        return;
    }
    LOG_INFO("block_index_projection",
             "sequential prefetch begin bytes=%" PRId64 " cache_kib=%" PRIu64,
             (int64_t)bytes, (budget + 1023) / 1024);
    uint64_t warmed = block_index_projection_cache_warm(file, (uint64_t)bytes);
    LOG_INFO("block_index_projection",
             "sequential prefetch finished bytes=%" PRIu64 "/%" PRId64,
             warmed, (int64_t)bytes);
}
