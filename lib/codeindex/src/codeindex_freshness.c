/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Validate exact source and compiler-input freshness profiles for code-index readers. */

#include "codeindex_priv.h"
#include "codeindex/codeindex_build.h"

#include "util/log_macros.h"

#include <string.h>

static const char ci_store_format[] = "zcl.codeindex.store.v4";

static bool store_is_stale_profile(const char *root, struct ci_store *store,
                                   bool check_depfiles, bool *stale)
{
    if (stale) *stale = true;
    if (!root || !store) LOG_FAIL("codeindex", "null arg to is_stale");
    /* Exact content roots are sealed during rebuild. Warm readers validate
     * inode/size/mtime/ctime keys, so even same-size edits with restored mtime
     * invalidate without rereading source or depfile bytes. */
    uint8_t cur_stats[32], cur_dep_stats[32] = {0};
    if (!ci_source_stat_root_sha3(root, cur_stats))
        LOG_FAIL("codeindex", "compute source_stat_root_sha3");
    if (check_depfiles && !ci_deps_stat_root_sha3(root, cur_dep_stats))
        LOG_FAIL("codeindex", "compute dep_stat_root_sha3");
    uint8_t stored_stats[32], stored_dep_stats[32];
    char stored_format[64], stored_schema[64];
    size_t stat_len = 0, dep_len = 0, format_len = 0, schema_len = 0;
    bool stat_found = false, dep_found = false, format_found = false;
    bool schema_found = false;
    if (!ci_store_meta_get(store, "source_stat_root_sha3", stored_stats,
                           sizeof(stored_stats), &stat_len, &stat_found) ||
        !ci_store_meta_get(store, "dep_stat_root_sha3", stored_dep_stats,
                           sizeof(stored_dep_stats), &dep_len, &dep_found) ||
        !ci_store_meta_get(store, "store_format", stored_format,
                           sizeof(stored_format), &format_len, &format_found) ||
        !ci_store_meta_get(store, "ci_schema_version", stored_schema,
                           sizeof(stored_schema), &schema_len, &schema_found))
        LOG_FAIL("codeindex", "read freshness metadata");
    if (stale)
        *stale = !(stat_found && stat_len == 32 &&
                   memcmp(cur_stats, stored_stats, 32) == 0 &&
                   (!check_depfiles ||
                    (dep_found && dep_len == 32 &&
                     memcmp(cur_dep_stats, stored_dep_stats, 32) == 0)) &&
                   format_found && format_len == sizeof(ci_store_format) - 1 &&
                   memcmp(stored_format, ci_store_format,
                          sizeof(ci_store_format) - 1) == 0 &&
                   schema_found &&
                   schema_len == sizeof(CI_SCHEMA_VERSION) - 1 &&
                   memcmp(stored_schema, CI_SCHEMA_VERSION,
                          sizeof(CI_SCHEMA_VERSION) - 1) == 0);
    return true;
}

bool codeindex_is_stale(struct codeindex *ci, bool *stale)
{
    if (!ci || !ci->store) LOG_FAIL("codeindex", "null arg to is_stale");
    return store_is_stale_profile(ci->root, ci->store, true, stale);
}

bool ci_codeindex_source_view_is_stale(struct codeindex *ci, bool *stale)
{
    if (!ci || !ci->store)
        LOG_FAIL("codeindex", "null arg to source_view_is_stale");
    return store_is_stale_profile(ci->root, ci->store, false, stale);
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
