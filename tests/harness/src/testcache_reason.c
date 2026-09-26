/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
/* Shared cache reason vocabulary. Keeping this leaf separate lets callers
 * check the labels without depending on the cache store and key machinery. */

#include "test/testcache.h"

const char *testcache_reason_label(enum testcache_reason r)
{
    static const char *const labels[TESTCACHE_R__COUNT] = {
        [TESTCACHE_R_OK] = "cacheable",
        [TESTCACHE_R_NO_HANDLE] = "no-cache-handle",
        [TESTCACHE_R_EXTERNAL_INPUT] = "external-input-denylist",
        [TESTCACHE_R_CLOSURE_ERROR] = "closure-query-error",
        [TESTCACHE_R_ENTRY_UNRESOLVED] = "entry-symbol-unresolved",
        [TESTCACHE_R_TRUNCATED] = "closure-truncated",
        [TESTCACHE_R_EMPTY_CLOSURE] = "empty-closure",
        [TESTCACHE_R_FILE_UNREADABLE] = "input-file-unreadable",
        [TESTCACHE_R_NO_INCLUDE_GRAPH] = "no-include-graph",
        [TESTCACHE_R_GRAPH_STALE] = "input-newer-than-include-graph",
        [TESTCACHE_R_CHANGED_INPUT] = "changed-input-runs-fresh",
        [TESTCACHE_R_ACTIVE_PROOF_CONTRACT] = "active-proof-contract",
        [TESTCACHE_R_PROOF_CONTRACT_INVALID] = "invalid-proof-contract",
        [TESTCACHE_R_HARNESS_GRAPH] = "harness-include-graph-incomplete",
        [TESTCACHE_R_GROUP_UNADMISSIBLE] = "group-unadmissible",
        [TESTCACHE_R_INPUT_MISSING] = "input-missing-from-checkout",
    };
    return (unsigned)r < TESTCACHE_R__COUNT && labels[r]
        ? labels[r] : "unknown";
}
