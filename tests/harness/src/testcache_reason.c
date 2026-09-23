/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
/* Shared cache reason vocabulary. Keeping this leaf separate lets callers
 * check the labels without depending on the cache store and key machinery. */

#include "test/testcache.h"

const char *testcache_reason_label(enum testcache_reason r)
{
    switch (r) {
    case TESTCACHE_R_OK:               return "cacheable";
    case TESTCACHE_R_NO_HANDLE:        return "no-cache-handle";
    case TESTCACHE_R_EXTERNAL_INPUT:   return "external-input-denylist";
    case TESTCACHE_R_CLOSURE_ERROR:    return "closure-query-error";
    case TESTCACHE_R_ENTRY_UNRESOLVED: return "entry-symbol-unresolved";
    case TESTCACHE_R_TRUNCATED:        return "closure-truncated";
    case TESTCACHE_R_EMPTY_CLOSURE:    return "empty-closure";
    case TESTCACHE_R_FILE_UNREADABLE:  return "input-file-unreadable";
    case TESTCACHE_R_NO_INCLUDE_GRAPH: return "no-include-graph";
    case TESTCACHE_R_GRAPH_STALE:      return "input-newer-than-include-graph";
    case TESTCACHE_R_CHANGED_INPUT:    return "changed-input-runs-fresh";
    case TESTCACHE_R_ACTIVE_PROOF_CONTRACT:
        return "active-proof-contract";
    case TESTCACHE_R_PROOF_CONTRACT_INVALID:
        return "invalid-proof-contract";
    case TESTCACHE_R__COUNT:           break;
    }
    return "unknown";
}
