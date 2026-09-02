/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Validate exact source and compiler-input freshness profiles for code-index readers. */

#include "codeindex_priv.h"
#include "codeindex/codeindex_build.h"
#include "codeindex/codeindex_merkle.h"

#include "util/log_macros.h"

#include <string.h>

static bool store_is_stale_profile(struct codeindex *ci,
                                   bool check_depfiles, bool *stale)
{
    if (stale) *stale = true;
    if (!ci || !ci->store) LOG_FAIL("codeindex", "null arg to is_stale");
    ci_merkle_free(ci->pending_merkle);
    ci->pending_merkle_snapshot_used = false;
    ci->pending_merkle_full_rescan = false;
    ci->pending_merkle_inventory_changed = false;
    struct ci_merkle_cost merkle_cost = {0};
    ci->pending_merkle = ci_merkle_refresh_reconciled(
        ci->root, &merkle_cost);
    ci->pending_merkle_snapshot_used = merkle_cost.snapshot_used;
    ci->pending_merkle_full_rescan = merkle_cost.full_rescan;
    ci->pending_merkle_inventory_changed = merkle_cost.inventory_changed;
    struct ci_merkle_node source;
    if (!ci->pending_merkle || !ci_merkle_root(ci->pending_merkle, &source))
        LOG_FAIL("codeindex", "compute source Merkle root");
    uint8_t cur_dep_stats[32] = {0};
    if (check_depfiles && !ci_deps_stat_root_sha3(ci->root, cur_dep_stats))
        LOG_FAIL("codeindex", "compute dep_stat_root_sha3");
    uint8_t stored_merkle[32], stored_dep_stats[32];
    char stored_format[64], stored_schema[64];
    size_t merkle_len = 0, dep_len = 0, format_len = 0, schema_len = 0;
    bool merkle_found = false, dep_found = false, format_found = false;
    bool schema_found = false;
    if (!ci_store_meta_get(ci->store, "source_merkle_root_sha3", stored_merkle,
                           sizeof(stored_merkle), &merkle_len, &merkle_found) ||
        !ci_store_meta_get(ci->store, "dep_stat_root_sha3", stored_dep_stats,
                           sizeof(stored_dep_stats), &dep_len, &dep_found) ||
        !ci_store_meta_get(ci->store, "store_format", stored_format,
                           sizeof(stored_format), &format_len, &format_found) ||
        !ci_store_meta_get(ci->store, "ci_schema_version", stored_schema,
                           sizeof(stored_schema), &schema_len, &schema_found))
        LOG_FAIL("codeindex", "read freshness metadata");
    bool metadata_current =
        merkle_found && merkle_len == 32 &&
        memcmp(source.digest.bytes, stored_merkle, 32) == 0 &&
        (!check_depfiles ||
         (dep_found && dep_len == 32 &&
          memcmp(cur_dep_stats, stored_dep_stats, 32) == 0)) &&
        format_found && format_len == sizeof(CI_STORE_FORMAT) - 1 &&
        memcmp(stored_format, CI_STORE_FORMAT,
               sizeof(CI_STORE_FORMAT) - 1) == 0 &&
        schema_found && schema_len == sizeof(CI_SCHEMA_VERSION) - 1 &&
        memcmp(stored_schema, CI_SCHEMA_VERSION,
               sizeof(CI_SCHEMA_VERSION) - 1) == 0;
    if (stale) *stale = !metadata_current;
    if (metadata_current) {
        ci_merkle_free(ci->pending_merkle);
        ci->pending_merkle = NULL;
    }
    return true;
}

bool codeindex_is_stale(struct codeindex *ci, bool *stale)
{
    if (!ci || !ci->store) LOG_FAIL("codeindex", "null arg to is_stale");
    return store_is_stale_profile(ci, true, stale);
}

bool ci_codeindex_source_view_is_stale(struct codeindex *ci, bool *stale)
{
    if (!ci || !ci->store)
        LOG_FAIL("codeindex", "null arg to source_view_is_stale");
    return store_is_stale_profile(ci, false, stale);
}

bool codeindex_source_view_is_current(struct codeindex *ci, bool *current)
{
    if (current) *current = false;
    if (!ci || !current)
        LOG_FAIL("codeindex", "null arg to source_view_is_current");
    bool stale = true;
    if (!ci_codeindex_source_view_is_stale(ci, &stale)) return false;
    *current = !stale;
    return true;
}
