/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: own read-only access to live consensus nullifier evidence. */

#include "services/chain_nullifier_evidence_service.h"

#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <sqlite3.h>

static bool chain_nullifier_pool_storage_value(
    enum chain_nullifier_pool pool,
    int *storage_pool)
{
    if (!storage_pool)
        return false;
    switch (pool) {
    case CHAIN_NULLIFIER_POOL_SPROUT:
        *storage_pool = NULLIFIER_POOL_SPROUT;
        return true;
    case CHAIN_NULLIFIER_POOL_SAPLING:
        *storage_pool = NULLIFIER_POOL_SAPLING;
        return true;
    }
    return false;
}

struct zcl_result chain_nullifier_evidence_lookup_set(
    const struct chain_nullifier_query *queries,
    size_t query_count,
    enum chain_nullifier_pool pool,
    struct chain_nullifier_set_evidence *out)
{
    if (out) {
        out->any_found = false;
        out->heights_consistent = false;
        out->height = -1;
    }
    int storage_pool = -1;
    if (!queries || query_count == 0 || !out ||
        !chain_nullifier_pool_storage_value(pool, &storage_pool)) {
        LOG_WARN("chain_nullifier_evidence",
                 "lookup_set: invalid arguments count=%zu", query_count);
        return ZCL_ERR(-1, "chain nullifier set lookup invalid arguments");
    }
    for (size_t i = 0; i < query_count; i++) {
        if (!queries[i].bytes) {
            LOG_WARN("chain_nullifier_evidence",
                     "lookup_set: null query at index=%zu", i);
            return ZCL_ERR(-2, "nullifier query %zu is null", i);
        }
    }

    /* The tx lock is also the handle lifetime lock: close exchanges g_db and
     * calls sqlite3_close while holding it. Load the pointer only after this
     * lock is held so a concurrent close cannot leave us with a stale handle. */
    progress_store_tx_lock();
    sqlite3 *db = progress_store_db();
    if (!db) {
        progress_store_tx_unlock();
        LOG_WARN("chain_nullifier_evidence",
                 "lookup_set: consensus kernel unavailable");
        return ZCL_ERR(-3, "consensus kernel unavailable");
    }

    bool any_found = false;
    bool consistent = true;
    int64_t common_height = -1;
    for (size_t i = 0; i < query_count; i++) {
        bool found = false;
        int64_t height = -1;
        if (!nullifier_kv_get(db, queries[i].bytes, storage_pool,
                              &found, &height)) {
            progress_store_tx_unlock();
            LOG_WARN("chain_nullifier_evidence",
                     "lookup_set: store read failed pool=%d index=%zu",
                     storage_pool, i);
            return ZCL_ERR(-4,
                           "nullifier evidence read failed at query %zu", i);
        }
        if (!found)
            continue;
        any_found = true;
        if (common_height < 0)
            common_height = height;
        else if (common_height != height)
            consistent = false;
    }
    progress_store_tx_unlock();

    out->any_found = any_found;
    out->heights_consistent = consistent;
    out->height = any_found ? common_height : -1;
    return ZCL_OK;
}
