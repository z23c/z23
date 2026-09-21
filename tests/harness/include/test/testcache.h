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

#include "test_group_catalog.h"

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
    TESTCACHE_R_PROOF_CONTRACT_INVALID, /* unknown activation policy */
    TESTCACHE_R__COUNT
};

/* Stable short label for a reason code (histogram/report text). */
const char *testcache_reason_label(enum testcache_reason r);

/* The per-group cache decision. */
struct testcache_probe {
    /* Derived identity within the verified closure model. It does not alone
     * prove complete behavior and may be valid when reuse remains forbidden. */
    bool    key_valid;
    bool    cacheable;    /* false => the group MUST run this time */
    bool    hit;          /* true  => a stored PASS exists at this exact key */
    /* true => that stored PASS was minted by a rerun-alone policy pass (the
     * group FAILed or was WEDGED once under a contended pool before passing
     * alone — see test_parallel.c's rerun_load_flaky_groups). A cache HIT
     * with this set must be reported (LOAD-FLAKY ...), never served silently
     * as an ordinary pass: the flake happened, and the cache must never be
     * the mechanism that makes it invisible again. */
    bool    hit_flaky;
    uint8_t key[32];      /* valid iff key_valid */
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

/* Cumulative per-handle counters. Observability only: reading or resetting
 * them never changes a key, a verdict, or cacheability. */
struct testcache_stats {
    uint64_t closure_queries;     /* codeindex_forward_closure calls */
    uint64_t file_hash_reads;     /* unique files read from disk + hashed */
    uint64_t file_hash_memo_hits; /* closure files served from the path memo */
    uint64_t sha3_content_bytes;  /* file-content bytes folded into SHA3 */
    uint64_t verdict_lookups;     /* addressed verdict existence probes */
    uint64_t verdict_hits;        /* verified stored PASS records served */
};
void testcache_stats(const struct testcache *tc,
                     struct testcache_stats *out);
void testcache_stats_reset(struct testcache *tc);

/* The current environment digest without a handle: exactly what an open
 * handle would fold into its keys. The capsule consumer recomputes this
 * live and refuses a capsule whose env moved since the write. */
void testcache_current_envkey(uint8_t out[32]);

/* Probe capsule: one proof cycle's batch verdicts as ephemeral scratch.
 *
 * The capsule binds, in order: the caller-supplied candidate identity
 * below, the live toolkey string, the live env digest, dep-graph
 * provenance (count + newest + the caller's graph content root), then the
 * ordered per-group slots (name, proof contract, key, code, cacheable,
 * hit, flaky, closure size), then a SHA3-256 over every preceding byte.
 *
 * The trailing hash is INTEGRITY ONLY. It never addresses a verdict and
 * never gates a skip by itself: a consumer still reads each slot's own
 * key/code/cacheable/hit, and any byte difference — corruption,
 * truncation, trailing garbage, reordered slots — fails the hash and
 * refuses the whole capsule. There is no aggregate "all groups" key and
 * no new verdict store; the capsule never accepts anything, it only
 * carries what the batch already decided.
 *
 * Graph freshness authority stays with the caller (the proof worker pins
 * the graph content root at prefork and hands the same value to the
 * writer and the reader): dep_count/dep_newest ride along as
 * tamper-evident provenance but are never re-walked here. */
struct testcache_capsule_bindings {
    char source_id[65];       /* caller tree identity, NUL-terminated */
    char mutation_id[65];     /* caller mutation identity, NUL-terminated */
    char source_cas[65];      /* caller content root (hex text), if present */
    bool source_cas_present;
    char graph_root[65];      /* caller dep-graph content root, if present */
    bool graph_root_present;
    uint64_t dep_count;       /* provenance only, not revalidated */
    int64_t dep_newest_ns;    /* provenance only, not revalidated */
};
struct testcache_capsule_info {
    size_t n_slots;
    uint64_t dep_count;       /* capsule's dep-graph provenance */
    char toolkey_hex12[13];   /* capsule toolkey prefix, for log lines */
};
/* One consumed slot: the group name it was written under plus its
 * independent probe. Names ride with the slots so the consumer can map
 * them onto any selected set without reopening anything. */
struct testcache_capsule_slot {
    char name[128];
    struct testcache_probe probe;
};
/* Serialize the batch result. The dep-graph provenance comes from the live
 * handle; everything else from bind/slots. Bounded (at most 8192 slots,
 * names at most 128 bytes, file at most 8 MiB); anything over refuses.
 * Never aborts: false means "no capsule", and the caller falls back to a
 * fresh probe. */
bool testcache_capsule_write(struct testcache *tc, const char *path,
                             const char *const *names,
                             const enum zcl_test_proof_contract *contracts,
                             size_t n, const struct testcache_probe *probes,
                             const struct testcache_capsule_bindings *bind);
/* Load, verify, and bind-check a capsule WITHOUT opening any handle: no
 * codeindex open, no dep-graph walk, no closure query, no file hash. Reads
 * at most cap slots into out (more slots than cap refuses), then fills
 * info. `expected` carries the caller's CURRENT bindings; `why` (at least
 * 64 bytes) names the first refusal. False means "no usable capsule" and
 * the caller fresh-opens and reprobes. */
bool testcache_capsule_consume(const char *path,
                               const struct testcache_capsule_bindings *expected,
                               struct testcache_capsule_slot *out, size_t cap,
                               struct testcache_capsule_info *info,
                               char *why, size_t why_len);
/* Map consumed slots onto a selected set by exact name: a selected group
 * with no slot reports NO_HANDLE uncacheable (it runs), extra slots are
 * ignored, order never matters. Fail-closed revalidation: a slot's HIT
 * copies through only while its backing PASS record still verifies
 * (magic/PASS/key-echo, the same check a fresh probe performs) under
 * store_root; a HIT with no verifying record demotes to MISS (it runs).
 * store_root NULL/empty resolves exactly as testcache_open(NULL) does, so
 * the runner passes NULL and checks against the store its own fresh probe
 * would use. */
void testcache_capsule_apply(const struct testcache_capsule_slot *slots,
                             size_t n_slots,
                             const char *const *want_names, size_t n_want,
                             struct testcache_probe *out,
                             const char *store_root);
/* Live-key revalidation for consumed capsule HITs. names[i] is the group
 * probes[i] was mapped from; a HIT keeps its skip only while a fresh live
 * probe of that group reaches the identical key (inputs byte-identical
 * since mint) and independently HITs it. Any divergence — changed content,
 * stale graph, unreadable input, vanished record — replaces the slot with
 * the live probe, so the group runs instead of skipping on dead evidence.
 * A NULL handle cannot verify liveness and demotes every HIT (fail closed).
 * Non-HIT slots pass through untouched. */
void testcache_capsule_revalidate(struct testcache *tc,
                                  const char *const *names,
                                  struct testcache_probe *probes, size_t n);

/* Batch probe: N canonical group names in, N independent per-group results
 * out, through this ONE handle (one verified dep graph, one shared
 * path→SHA3 memo). Exactly equivalent to calling testcache_probe_group[_proof]
 * once per slot on the same handle: same keys, same codes, same hits — there
 * is no aggregate "all groups" key and verdicts stay per-group. Slots are
 * independent: a bad name, truncated closure, or unreadable input reports
 * UNCACHEABLE in its own slot and never perturbs another slot's result.
 * `contracts` may be NULL (every slot takes the ordinary reusable identity);
 * otherwise contracts[i] selects slot i's proof-contract variant exactly as
 * testcache_probe_group_proof would. n_groups==0 is a no-op success. Returns
 * false (every slot then reports NO_HANDLE uncacheable) when tc is NULL or
 * when names/out is NULL with n_groups>0. */
bool testcache_probe_groups(struct testcache *tc,
                            const char *const *group_names,
                            const enum zcl_test_proof_contract *contracts,
                            size_t n_groups,
                            struct testcache_probe *out);

/* Compute the key for an activated proof contract. The result domain-wraps
 * the byte-identical ordinary v4 key with the canonical contract assignment.
 * A valid activated key is evidence identity only: it is never cacheable,
 * never reports a hit, and must never be passed to testcache_store_pass(). */
void testcache_probe_group_proof(
    struct testcache *tc, const char *group_name,
    enum zcl_test_proof_contract contract, struct testcache_probe *out);

/* True when group_name is on the external-input denylist (never cacheable).
 * Exposed so the contract test can re-derive the exec-a-built-binary set from
 * the source tree and assert the list still covers it. */
bool testcache_group_is_denylisted(const char *group_name);

/* Store a PASS verdict at key[32] (best effort; a store failure is ignored —
 * it only costs a future re-run, never correctness). Pass the key from a
 * prior cacheable probe of a group that then ran and PASSED. */
void testcache_store_pass(struct testcache *tc, const uint8_t key[32]);

/* Store a PASS verdict exactly like testcache_store_pass, but flagged
 * load-flaky: the group FAILed or was WEDGED once under a contended pool
 * before passing alone (see test_parallel.c's rerun_load_flaky_groups). A
 * later probe of this key reports it via testcache_probe's out->hit_flaky so
 * the flake is reprinted on every future cache hit, never laundered into an
 * indistinguishable ordinary pass. */
void testcache_store_pass_flaky(struct testcache *tc, const uint8_t key[32]);

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
