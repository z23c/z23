/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * testcache — the content-addressed per-group test result cache.
 *
 * Bazel-style: a test GROUP is SKIPPED when its exact transitive INPUT closure
 * is byte-identical to the last time that group PASSED. The input closure is
 * the forward (callee) closure of the group's entry symbol — every in-tree
 * source file whose bytes can change the group's verdict — plus the toolchain
 * fingerprint. The key is SHA3-256 over that closure; a stored PASS at that key
 * (in the .zvcs object store) is a proof the group would pass again.
 *
 * SOUNDNESS is the whole point. A cached SKIP must be provably equivalent to a
 * fresh PASS, so this module NEVER caches a group whose real inputs it cannot
 * bound:
 *   - the forward closure truncated (a cap/fan-out/depth limit) -> UNCACHEABLE
 *   - the entry symbol does not resolve in the code index      -> UNCACHEABLE
 *   - the group is on the external-input denylist (reads fixtures/live DB/
 *     network/params/built binaries beyond its source closure)  -> UNCACHEABLE
 *   - the depfile-derived include graph is absent entirely      -> UNCACHEABLE
 *   - any closure input is NEWER than the newest depfile the graph was built
 *     from, i.e. the graph cannot describe that input yet       -> UNCACHEABLE
 *   - the runner activated an exact proof contract               -> UNCACHEABLE
 *   - only PASS verdicts are ever stored (a fail is never cached)
 * An UNCACHEABLE group ALWAYS runs.
 *
 * Two things that are NOT source bytes are folded into the key, because both
 * change a group's verdict without changing a single file:
 *   - the toolchain fingerprint AND the effective compile flags (an -O1 fast
 *     profile and an -O3 release profile must never share a keyspace), and
 *   - the coverage-gating environment (ZCL_STRESS_TESTS and friends). ~16
 *     groups `return 0` from a `SKIP (set ZCL_STRESS_TESTS=1 ...)` path, so a
 *     normal run stores a PASS for the SKIPPING variant; without the env in the
 *     key a later ZCL_STRESS_TESTS=1 run would hit that PASS and never execute
 *     the stress lane at all.
 *
 * The residual assumption (the call graph captures a test's dependency edges by
 * name; an indirect/function-pointer edge is invisible to source scanning) is
 * backed by the --cold-audit path: it re-runs every group fresh and asserts
 * every cache HIT would have matched the fresh verdict.
 *
 * This is a TEST-BINARY-ONLY module (tests/harness/include/test/), never linked into the node. */

#ifndef ZCL_TEST_TESTCACHE_H
#define ZCL_TEST_TESTCACHE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Opaque handle: open once per run in the parent, before any fork. */
struct testcache;

/* Open the cache for the source tree rooted at repo_root (NULL selects
 * ZCL_DEV_SOURCE_ROOT, else "."). Opens/rebuilds the code index and ensures the
 * .zvcs object store exists. Returns NULL on hard failure — the caller then
 * runs every group (fail-safe: no cache, never a wrong skip). */
struct testcache *testcache_open(const char *repo_root);
/* Resident save-cycle variant: open only the already-verified index snapshot
 * and bind the exact changed source set. A group's old forward closure may be
 * reused only when it excludes every changed source; any affected group runs
 * fresh. Missing snapshots fail safe by returning NULL, never rebuilding the
 * full index in the feedback path. */
struct testcache *testcache_open_snapshot(
    const char *repo_root, const char *const *changed_sources,
    size_t changed_source_count);
void testcache_close(struct testcache *tc);

/* Why a group was (not) cacheable. A STABLE identity for histogram bucketing —
 * it deliberately carries no volatile data (counts, paths), unlike the free-text
 * `reason` beside it. Keep testcache_reason_label() in sync. */
enum testcache_reason {
    TESTCACHE_R_OK = 0,            /* cacheable */
    TESTCACHE_R_NO_HANDLE,         /* no cache handle / bad argument */
    TESTCACHE_R_EXTERNAL_INPUT,    /* on the external-input denylist */
    TESTCACHE_R_CLOSURE_ERROR,     /* the closure query itself failed */
    TESTCACHE_R_ENTRY_UNRESOLVED,  /* entry symbol not in the code index */
    TESTCACHE_R_TRUNCATED,         /* closure hit a cap/fan-out/depth limit */
    TESTCACHE_R_EMPTY_CLOSURE,     /* resolved to zero input files */
    TESTCACHE_R_FILE_UNREADABLE,   /* an input file could not be hashed */
    TESTCACHE_R_NO_INCLUDE_GRAPH,  /* build/ carries no depfiles at all */
    TESTCACHE_R_GRAPH_STALE,       /* an input is newer than the include graph */
    TESTCACHE_R_CHANGED_INPUT,     /* resident snapshot closure reaches edit */
    TESTCACHE_R_ACTIVE_PROOF_CONTRACT, /* activated exact proof always runs */
    TESTCACHE_R__COUNT
};

/* Stable short label for a reason code (histogram/report text). */
const char *testcache_reason_label(enum testcache_reason r);

/* The per-group cache decision. */
struct testcache_probe {
    bool    cacheable;    /* false => the group MUST run this time */
    bool    hit;          /* true  => a stored PASS exists at this exact key */
    uint8_t key[32];      /* the content-addressed key (valid iff cacheable) */
    int     n_closure;    /* number of input files hashed (diagnostic) */
    enum testcache_reason code;  /* stable bucket for the reason histogram */
    char    reason[96];   /* why uncacheable, or a short closure note */
};

/* Compute group_name's key + cacheability + whether a stored PASS exists.
 * group_name is the registry name and the entry symbol both ("test_<x>" /
 * "spec_<x>"). Never aborts: on ANY internal failure the group is reported
 * UNCACHEABLE (fail-safe). *out is always fully populated. */
void testcache_probe_group(struct testcache *tc, const char *group_name,
                           struct testcache_probe *out);

/* True when group_name is on the external-input denylist (never cacheable).
 * Exposed so the contract test can re-derive the exec-a-built-binary set from
 * the source tree and assert the list still covers it. */
bool testcache_group_is_denylisted(const char *group_name);

/* Store a PASS verdict at key[32] (best effort; a store failure is ignored —
 * it only costs a future re-run, never correctness). Pass the key from a
 * prior cacheable probe of a group that then ran and PASSED. */
void testcache_store_pass(struct testcache *tc, const uint8_t key[32]);

/* Diagnostic: print group_name's closure file list, key, and cacheability to
 * stdout. Drives the ZCL_TEST_CACHE_DUMP=<group> operator surface and the
 * soundness proofs. */
void testcache_dump_group(struct testcache *tc, const char *group_name);

/* The compiled-in toolchain+flags fingerprint folded into every key (a compiler
 * OR compile-flag change busts the whole cache). Exposed for the dump surface. */
const char *testcache_toolkey(void);

/* First 12 hex chars of SHA3-256(toolkey), for compact run headers. `out` must
 * hold 13 bytes. Always NUL-terminated. */
void testcache_toolkey_digest12(char out[13]);

/* Number of depfiles the include graph was built from. ZERO means the graph is
 * absent (a fresh clone / after `make clean`), which is NOT "a closure with no
 * headers" — it is no closure at all, and every group reports uncacheable. */
size_t testcache_depfile_count(const struct testcache *tc);

#endif /* ZCL_TEST_TESTCACHE_H */
