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
    memcpy(ci->fresh_merkle, source.digest.bytes, 32);
    memcpy(ci->fresh_dep, cur_dep_stats, 32);
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

static bool source_view_metadata_matches(struct ci_store *s,
                                         const uint8_t snap_root[32])
{
    uint8_t stored_merkle[32];
    char stored_format[64], stored_schema[64];
    size_t merkle_len = 0, format_len = 0, schema_len = 0;
    bool merkle_found = false, format_found = false, schema_found = false;
    if (!ci_store_meta_get(s, "source_merkle_root_sha3", stored_merkle,
                           sizeof(stored_merkle), &merkle_len, &merkle_found) ||
        !ci_store_meta_get(s, "store_format", stored_format,
                           sizeof(stored_format), &format_len, &format_found) ||
        !ci_store_meta_get(s, "ci_schema_version", stored_schema,
                           sizeof(stored_schema), &schema_len, &schema_found))
        LOG_FAIL("codeindex", "read source-view freshness metadata");
    return merkle_found && merkle_len == 32 &&
           memcmp(snap_root, stored_merkle, 32) == 0 &&
           format_found && format_len == sizeof(CI_STORE_FORMAT) - 1 &&
           memcmp(stored_format, CI_STORE_FORMAT,
                  sizeof(CI_STORE_FORMAT) - 1) == 0 &&
           schema_found && schema_len == sizeof(CI_SCHEMA_VERSION) - 1 &&
           memcmp(stored_schema, CI_SCHEMA_VERSION,
                  sizeof(CI_SCHEMA_VERSION) - 1) == 0;
}

static bool ci_is_stale_uncached(struct codeindex *ci, bool *stale)
{
    if (stale) *stale = true;
    if (!ci || !ci->store) LOG_FAIL("codeindex", "null arg to is_stale");
    bool have_snapshot = false, unchanged = false;
    uint8_t source_root[32];
    if (!ci_merkle_snapshot_inventory_current(ci->root, &have_snapshot,
                                              &unchanged, source_root))
        return false;
    if (!have_snapshot || !unchanged)
        return store_is_stale_profile(ci, true, stale);

    /* Settled source keys reuse the sealed root; include edges still require
     * their complete active depfile metadata observation. */
    uint8_t current_deps[32], stored_deps[32];
    size_t len = 0;
    bool found = false;
    if (!ci_deps_stat_root_sha3(ci->root, current_deps) ||
        !ci_store_meta_get(ci->store, "dep_stat_root_sha3", stored_deps,
                           sizeof(stored_deps), &len, &found))
        LOG_FAIL("codeindex", "read full-view depfile freshness");
    bool current = source_view_metadata_matches(ci->store, source_root) &&
        found && len == sizeof(stored_deps) &&
        memcmp(current_deps, stored_deps, sizeof(stored_deps)) == 0;
    memcpy(ci->fresh_merkle, source_root, 32);
    memcpy(ci->fresh_dep, current_deps, 32);
    ci_merkle_free(ci->pending_merkle);
    ci->pending_merkle = NULL;
    ci->pending_merkle_snapshot_used = false;
    ci->pending_merkle_full_rescan = false;
    ci->pending_merkle_inventory_changed = false;
    if (stale) *stale = !current;
    return true;
}

static bool ci_digest_known(const uint8_t d[32])
{
    uint8_t any = 0;
    for (int i = 0; i < 32; i++) any |= d[i];
    return any != 0;
}

bool codeindex_is_stale(struct codeindex *ci, bool *stale)
{
    if (stale) *stale = true;
    if (!ci || !ci->store) LOG_FAIL("codeindex", "null arg to is_stale");
    if (ci_fresh_memo_hit(ci)) {
        /* Same bookkeeping the uncached fresh path does. */
        ci_merkle_free(ci->pending_merkle);
        ci->pending_merkle = NULL;
        ci->pending_merkle_snapshot_used = false;
        ci->pending_merkle_full_rescan = false;
        ci->pending_merkle_inventory_changed = false;
        if (stale) *stale = false;
        return true;
    }
    /* Arm the change watch BEFORE the walk so an edit that lands during or
     * after it is still reported to the memo. */
    struct ci_fresh_watch *watch = ci_fresh_arm(ci->root);
    ci_test_note_freshness_walk();
    memset(ci->fresh_merkle, 0, sizeof(ci->fresh_merkle));
    memset(ci->fresh_dep, 0, sizeof(ci->fresh_dep));
    bool verdict = true;
    bool ok = ci_is_stale_uncached(ci, &verdict);
    /* Never record a memo entry from digests the walk did not produce. */
    ci_fresh_finish(watch, ci, ok && !verdict &&
                    ci_digest_known(ci->fresh_merkle) &&
                    ci_digest_known(ci->fresh_dep));
    if (stale) *stale = verdict;
    return ok;
}

bool ci_codeindex_source_view_is_stale(struct codeindex *ci, bool *stale)
{
    if (stale) *stale = true;
    if (!ci || !ci->store)
        LOG_FAIL("codeindex", "null arg to source_view_is_stale");
    /* Metrics and other source-view readers only need current vs stale.
     * Rebuilding the Merkle tree (and, on inventory drift, a second cold
     * byte pass) made warm code.index.metrics miss its 750 ms FOREGROUND
     * budget: 411 ms of the 808 ms sample was this check. Stat the live
     * inventory against the sealed snapshot instead; that still detects
     * a changed file and never hashes file bytes. */
    bool have_snapshot = false, unchanged = false;
    uint8_t snap_root[32];
    if (!ci_merkle_snapshot_inventory_current(ci->root, &have_snapshot,
                                              &unchanged, snap_root))
        return false;
    /* A just-written tree stores poisoned mtime_nsec so the next pass
     * re-reads bytes (racy-clean). Those keys will not match a live stat,
     * which is not the same as inventory drift — fall back to the full
     * Merkle refresh, which re-reads and keeps the leaf clean on digest
     * match. The 6k-file warm case that blows the 750 ms budget has
     * settled keys and takes the fast path. */
    if (!have_snapshot || !unchanged)
        return store_is_stale_profile(ci, false, stale);
    bool metadata_current =
        source_view_metadata_matches(ci->store, snap_root);
    if (stale) *stale = !metadata_current;
    return true;
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
