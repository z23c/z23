/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * testcache — content-addressed per-group test result cache (see testcache.h).
 *
 * The key for a group is SHA3-256 over: a domain tag; the compiled-in
 * toolchain+flags fingerprint; the coverage-gating environment; the group name;
 * and, for every file in the group's forward (callee) input closure sorted by
 * path, the file's path and its SHA3-256 content hash. A stored PASS record
 * addressed by that key (in the .zvcs object store) means the exact same inputs
 * already passed. Only PASS is ever stored, a truncated/unresolved closure or a
 * denylisted external-input group is never cacheable, and the cold-audit path
 * re-verifies every hit against a fresh run.
 *
 * Fail-CLOSED on anything the module cannot bound: an internal error, an absent
 * include graph, or an input newer than the graph all report the group
 * UNCACHEABLE (so it runs). Only a *store* is best-effort — a skipped store
 * costs a re-run, never correctness. */

#include "test/testcache.h"

#include "codeindex/codeindex.h"
#include "vcs/vcs_object.h"
#include "crypto/sha3.h"
#include "platform/time_compat.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

extern char **environ;

/* The toolchain+flags fingerprint is injected at compile time by the Makefile
 * (BUILD_COMPILER_ID plus the profile's effective compile-flag digest — see
 * TESTCACHE_TOOLKEY_CPPFLAGS). Without that -D we fall back to the compiler's
 * own version string, which pins the compiler but NOT the flags — so the
 * fallback additionally refuses to share a keyspace with any -D'd build by
 * tagging itself. A missing -D must never silently alias a real profile. */
#ifndef ZCL_TESTCACHE_TOOLKEY
#define ZCL_TESTCACHE_TOOLKEY "no-toolkey-define/" __VERSION__
#endif

/* Largest input closure we will hold for one group. A closure larger than this
 * overflows codeindex_forward_closure's cap and comes back *truncated -> the
 * group is UNCACHEABLE, which is exactly what we want for a giant blast radius. */
#define TRC_MAX_CLOSURE 8192
#define TRC_CHANGED_MAX 32
#define TRC_PATH_MAX 256

/* ── on-disk verdict record (fixed 56 bytes, addressed BY the cache key) ── */
#define TRC_MAGIC "ZTCACHE1"      /* 8 bytes, no NUL */
#define TRC_STATUS_PASS 1u
struct trc_record {
    char    magic[8];
    uint8_t status;
    uint8_t rsvd[7];
    uint8_t key_echo[32];         /* self-check vs the lookup address */
    uint8_t generation_le[8];     /* store wall-clock stamp (observability) */
};

/* ── file-hash memo (path -> SHA3-256 + mtime), open addressing, per-run ── */
struct trc_memo_ent {
    char    *path;        /* NULL == empty slot */
    uint8_t  hash[32];
    int64_t  mtime_ns;    /* content mtime, for the graph-freshness check */
};
struct trc_memo {
    struct trc_memo_ent *slots;
    size_t cap;           /* power of two */
    size_t len;
};

struct testcache {
    struct codeindex *ci;
    char              root[4096];
    struct trc_memo   memo;
    char            (*closure)[256];   /* TRC_MAX_CLOSURE scratch rows */
    /* Include-graph liveness, from the graph itself, measured once at open. */
    size_t            dep_count;       /* depfiles the graph was built from */
    int64_t           dep_newest_ns;   /* newest depfile mtime */
    uint8_t           envkey[32];      /* SHA3 of the coverage-gating env */
    char              changed[TRC_CHANGED_MAX][TRC_PATH_MAX];
    size_t            changed_count;
    bool              snapshot_mode;
};

static uint64_t trc_hash_str(const char *s)
{
    uint64_t h = 1469598103934665603ULL;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h ^= *p;
        h *= 1099511628211ULL;
    }
    return h;
}

static bool trc_memo_init(struct trc_memo *m, size_t cap)
{
    m->slots = zcl_calloc(cap, sizeof(*m->slots), "trc_memo");
    if (!m->slots)
        return false;
    m->cap = cap;
    m->len = 0;
    return true;
}

static void trc_memo_free(struct trc_memo *m)
{
    if (!m->slots)
        return;
    for (size_t i = 0; i < m->cap; i++)
        free(m->slots[i].path);
    free(m->slots);
    m->slots = NULL;
    m->cap = m->len = 0;
}

static bool trc_memo_grow(struct trc_memo *m)
{
    size_t ncap = m->cap * 2;
    struct trc_memo_ent *ns = zcl_calloc(ncap, sizeof(*ns), "trc_memo_grow");
    if (!ns)
        return false;
    for (size_t i = 0; i < m->cap; i++) {
        if (!m->slots[i].path)
            continue;
        size_t j = (size_t)trc_hash_str(m->slots[i].path) & (ncap - 1);
        while (ns[j].path)
            j = (j + 1) & (ncap - 1);
        ns[j] = m->slots[i];
    }
    free(m->slots);
    m->slots = ns;
    m->cap = ncap;
    return true;
}

static int64_t trc_stat_mtime_ns(const struct stat *st)
{
    return (int64_t)st->st_mtim.tv_sec * INT64_C(1000000000) +
           (int64_t)st->st_mtim.tv_nsec;
}

/* SHA3-256 the bytes of <root>/<relpath> via a streaming read (no whole-file
 * buffer), and report the file's mtime. Returns false (and logs) if the file
 * cannot be opened/read. */
static bool trc_hash_file(const char *root, const char *relpath,
                          uint8_t out[32], int64_t *out_mtime_ns)
{
    char path[4200];
    int n = snprintf(path, sizeof(path), "%s/%s", root, relpath);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        ZCL_LOG_EMIT_AT(ZCL_LOG_WARN, "[testcache] path overflow: %s\n", relpath);
        return false;
    }
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        ZCL_LOG_EMIT_AT(ZCL_LOG_WARN, "[testcache] open failed: %s\n", path);
        return false;
    }
    struct stat st;
    if (fstat(fileno(fp), &st) != 0) {
        ZCL_LOG_EMIT_AT(ZCL_LOG_WARN, "[testcache] fstat failed: %s\n", path);
        fclose(fp);
        return false;
    }
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    unsigned char buf[65536];
    size_t got;
    bool ok = true;
    while ((got = fread(buf, 1, sizeof(buf), fp)) > 0)
        sha3_256_write(&ctx, buf, got);
    if (ferror(fp)) {
        ZCL_LOG_EMIT_AT(ZCL_LOG_WARN, "[testcache] read error: %s\n", path);
        ok = false;
    }
    fclose(fp);
    if (ok) {
        sha3_256_finalize(&ctx, out);
        *out_mtime_ns = trc_stat_mtime_ns(&st);
    }
    return ok;
}

/* Memoized content hash + mtime of one closure file. Returns false on read
 * failure (the caller then treats the whole group as UNCACHEABLE). */
static bool trc_file_hash(struct testcache *tc, const char *relpath,
                          uint8_t out[32], int64_t *out_mtime_ns)
{
    struct trc_memo *m = &tc->memo;
    if (m->len * 10 >= m->cap * 7 && !trc_memo_grow(m))
        return false;
    size_t j = (size_t)trc_hash_str(relpath) & (m->cap - 1);
    while (m->slots[j].path) {
        if (strcmp(m->slots[j].path, relpath) == 0) {
            memcpy(out, m->slots[j].hash, 32);
            *out_mtime_ns = m->slots[j].mtime_ns;
            return true;
        }
        j = (j + 1) & (m->cap - 1);
    }
    uint8_t h[32];
    int64_t mt = 0;
    if (!trc_hash_file(tc->root, relpath, h, &mt))
        return false;
    char *dup = zcl_strdup(relpath, "trc_memo_key");
    if (!dup)
        return false;
    m->slots[j].path = dup;
    memcpy(m->slots[j].hash, h, 32);
    m->slots[j].mtime_ns = mt;
    m->len++;
    memcpy(out, h, 32);
    *out_mtime_ns = mt;
    return true;
}

/* ── include-graph liveness ────────────────────────────────────────────────
 *
 * codeindex builds its include edges from the compiler's depfiles under build/.
 * Two ways that graph can be a lie, both of which used to pass silently:
 *
 *   1. There are NO depfiles (a fresh clone, or after `make clean`). Then every
 *      closure is just the .c files reachable by call graph — a SMALLER set that
 *      looks complete. Nothing is reported truncated, so every key silently
 *      covered zero headers.
 *   2. The depfiles that exist are OLDER than the sources. Then the graph
 *      describes a tree that no longer exists, and an include added since is
 *      invisible to the key.
 *
 * So we ask the graph for its own inventory — the count and the newest mtime of
 * the depfiles it read. A group whose inputs are all older than that bound is
 * describable by the graph; anything else is UNCACHEABLE.
 *
 * This used to be a private copy of codeindex's walk, kept in sync by comment.
 * It drifted the moment the build moved its depfiles into per-build compile
 * epochs: both copies then looked where the compiler no longer writes, and the
 * cache reported an ABSENT include graph for every group. One traversal, one
 * answer — codeindex_depfile_graph() is that traversal. */

/* ── coverage-gating environment ───────────────────────────────────────────
 *
 * ~16 groups return SUCCESS from a `SKIP (set ZCL_STRESS_TESTS=1 ...)` path.
 * Their source bytes are identical either way, so without the environment in
 * the key a normal run stores a PASS for the SKIPPING variant and a later
 * ZCL_STRESS_TESTS=1 run gets a HIT and never executes the stress lane —
 * reporting green for coverage that did not run.
 *
 * Hashing the environment beats denylisting the ~16 groups: it is exhaustive by
 * construction and cannot rot when someone adds the 17th gate. We fold every
 * ZCL_-prefixed variable (they are this project's namespace: gates, fuzz seeds,
 * fixture path overrides, tunables) plus HOME (the ~/.zcash-params root) and the
 * two legacy-named gates.
 *
 * EXCLUDED, and it must stay that way: the cache's OWN control variables and
 * the ZCL_FAST_* orchestration namespace. Fast-CI exports its frozen source
 * record, changed-path hints, compiler choice and scheduling knobs; source
 * bytes/toolchain/flags are already bound elsewhere in the key and none of
 * those controls changes a group's verdict. Folding them in globally busts
 * every per-group receipt after any edit or docs-only rebase. */
static bool trc_env_is_cache_control(const char *name, size_t namelen)
{
    static const char *const ctl[] = {
        "ZCL_TEST_CACHE", "ZCL_TEST_CACHE_DUMP",
    };
    for (size_t i = 0; i < sizeof(ctl) / sizeof(ctl[0]); i++)
        if (strlen(ctl[i]) == namelen && strncmp(name, ctl[i], namelen) == 0)
            return true;
    if (namelen > 9 && strncmp(name, "ZCL_FAST_", 9) == 0)
        return true;
    return false;
}

static bool trc_env_is_relevant(const char *entry)
{
    const char *eq = strchr(entry, '=');
    if (!eq)
        return false;
    size_t namelen = (size_t)(eq - entry);
    if (trc_env_is_cache_control(entry, namelen))
        return false;
    if (namelen > 4 && strncmp(entry, "ZCL_", 4) == 0)
        return true;
    static const char *const extra[] = { "HOME", "EQUIHASH_TEST",
                                         "REDUCER_FUZZ_SEED" };
    for (size_t i = 0; i < sizeof(extra) / sizeof(extra[0]); i++)
        if (strlen(extra[i]) == namelen &&
            strncmp(entry, extra[i], namelen) == 0)
            return true;
    return false;
}

static int trc_str_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* SHA3 the sorted, relevant NAME=VALUE entries. On any allocation failure we
 * fall back to a sentinel digest that is deliberately UNIQUE per run, so the
 * keys computed under it can never collide with a real environment's keys. */
static void trc_env_digest(uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    static const char DOMAIN[] = "zcl.testcache.env.v1";
    sha3_256_write(&ctx, (const unsigned char *)DOMAIN, sizeof(DOMAIN));

    size_t n = 0;
    for (char **e = environ; e && *e; e++)
        if (trc_env_is_relevant(*e))
            n++;
    if (n == 0) {
        sha3_256_finalize(&ctx, out);
        return;
    }
    const char **items = zcl_malloc(n * sizeof(*items), "trc_env_items");
    if (!items) {
        /* Poison rather than silently hash an empty environment. */
        uint64_t uniq = (uint64_t)platform_time_wall_time_t() ^
                        (uint64_t)(uintptr_t)&ctx;
        sha3_256_write(&ctx, (const unsigned char *)&uniq, sizeof(uniq));
        sha3_256_finalize(&ctx, out);
        return;
    }
    size_t k = 0;
    for (char **e = environ; e && *e && k < n; e++)
        if (trc_env_is_relevant(*e))
            items[k++] = *e;
    qsort(items, k, sizeof(*items), trc_str_cmp);
    for (size_t i = 0; i < k; i++)
        sha3_256_write(&ctx, (const unsigned char *)items[i],
                       strlen(items[i]) + 1);
    free((void *)items);
    sha3_256_finalize(&ctx, out);
}

/* Groups whose verdict depends on inputs OUTSIDE their source closure — on-disk
 * fixtures, the live node DB, an external zclassicd, ~/.zcash-params, a legacy
 * datadir, or (the big one) a BUILT BINARY they exec. These are NEVER cached.
 *
 * Matching is on the EXACT group name, not a substring. The old strstr() form
 * was both too loose and too tight: "explorer" also swallowed any future
 * explorer_* group, while "net" could not be listed at all because it would
 * have swallowed netmask/subnet/net_bootstrap — which is precisely why
 * test_net, a group that execs built binaries, reads /proc, spawns threads AND
 * gates coverage on ZCL_STRESS_TESTS, was never denylisted.
 *
 * The exec-a-binary entries are the load-bearing ones: a child process's
 * behavior comes from the WHOLE LINK of the binary it runs, and the forward
 * source closure of the test never reaches it. Editing any node source changes
 * that child's behavior while leaving the test's own closure key untouched.
 *
 * Derived by grepping lib/test/src for `build/bin/`, popen/system/exec of a
 * repo artifact, /proc readers, and CPU-feature dispatch. Kept in sorted order.
 * `name` may carry the test_/spec_ prefix. */
static bool group_reads_external_inputs(const char *name)
{
    if (strncmp(name, "test_", 5) == 0 || strncmp(name, "spec_", 5) == 0)
        name += 5;
    static const char *const ext[] = {
        /* --- execs a built binary or a repo script (whole-link input) --- */
        "agent_copy_prove",
        "chain_advance_atomicity",
        "chaos_harness",                  /* reads tests/fixtures block files */
        "cli_argv_strict",
        "cli_auth_robust",
        "cold_start_sync",
        "crypto_perf_selftest",
        "dev_platform",                   /* reads lib/test/fixtures source */
        "importblockindex_cli_dispatch",
        "kill9_recovery",
        "make_lint_gates",                /* plants fixtures + compiles the tree */
        "net",
        "no_hardcoded_home",              /* scans tree + env for home usage */
        "onion_bootstrap",
        "onion_bootstrap_slice",
        "replay_canary_verdict",
        "secrets_hygiene",
        "self_folded_anchor",
        "shielded_payment_gate",
        "syncdiag_rpc",
        "utxo_root_ladder",
        "verify_bench_selftest",
        "wallet_persistence_cycle",
        "wallet_view",
        /* --- live node DB / external zclassicd / datadir / built artifacts --- */
        "binary_ab_fallback",
        "binary_staleness",
        "chainstate_legacy_reader",
        "coldimport_restart_fragility",
        "consensus_state_snapshot_export", /* fd-dup + atomic bundle publish to
                                            * a datadir; load-flaky, so its PASS
                                            * is not reliably reproducible */
        "consensus_state_snapshot_install",
        "e2e_cold_start",
        "explorer",
        "explorer_index",
        "explorer_rpc_call",
        "importblockindex_roundtrip",
        "load_verify_boot",
        "offline_datadir_query",
        "oracle_policy",
        "soak_attestation",
        "soak_harness",
        "zclassicd_oracle",
        /* --- ~/.zcash-params / Sapling+Sprout proving keys --- */
        "bls12_381_adversarial",
        "chainstate_sapling_anchor",
        "groth16_selfverify",
        "mint_proof_harness",
        "phgr13_fix",
        "proof_validate_stage",
        "pv_lookahead",
        "replay_verify",
        "sapling",
        "sapling_anchor_frontier_condition",
        "sapling_ckpt_persist",
        "sapling_crypto",
        "sapling_nullifier_adversarial",
        "sapling_prover_rng_determinism",
        "shielded_history_import",
        "shielded_receive_slice",
        "shielded_spend_slice",
        "simnet_sapling_shielded_send",
        "simnet_shielded_wallet_e2e",
        "simnet_wallet_reorg",
        "simnet_zmsg_onchain",
        "snark_kat",
        "sprout_phgr13_kat",
        /* --- /proc + CPU-feature dispatch (the host, not the tree) --- */
        "boot_self_respawn",
        "canary_sentinel_watch",
        "confine",
        "os_sandbox",
        "sha3_256_x4",
        /* --- asserts on wall-clock timing (host load, not the tree) --- */
        "parallel_range_fold",
        /* --- reads repo files outside its own closure (Makefile, the runner
         * source, the gate script) to pin the cache's own contracts --- */
        "testcache",
    };
    for (size_t i = 0; i < sizeof(ext) / sizeof(ext[0]); i++)
        if (strcmp(name, ext[i]) == 0)
            return true;
    return false;
}

/* Exposed for the contract test, which re-derives the exec-a-binary set from
 * the source tree and asserts this list still covers it. */
bool testcache_group_is_denylisted(const char *name)
{
    return name && name[0] && group_reads_external_inputs(name);
}

static void trc_put_u32le(unsigned char b[4], uint32_t v)
{
    b[0] = (unsigned char)(v);
    b[1] = (unsigned char)(v >> 8);
    b[2] = (unsigned char)(v >> 16);
    b[3] = (unsigned char)(v >> 24);
}

/* Fold the closure into the SHA3 key. Files are already sorted by
 * codeindex_forward_closure. Returns false on a file-read failure; sets
 * *stale when any input is newer than the include graph that produced it. */
static bool trc_compute_key(struct testcache *tc, const char *group_name,
                            int n_closure, uint8_t out_key[32], bool *stale)
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);

    /* v3: only skip-free executions may mint reusable PASS records. Retire
     * v2 because it could store a zero-exit group that printed SKIP; the
     * environment digest distinguished skip modes but did not make a skip a
     * proof. v2 already added the coverage-gating environment over v1. */
    static const char DOMAIN[] = "zcl.testcache.key.v3";
    sha3_256_write(&ctx, (const unsigned char *)DOMAIN, sizeof(DOMAIN)); /* +NUL */

    const char *tk = ZCL_TESTCACHE_TOOLKEY;
    sha3_256_write(&ctx, (const unsigned char *)tk, strlen(tk) + 1);
    sha3_256_write(&ctx, tc->envkey, sizeof(tc->envkey));
    sha3_256_write(&ctx, (const unsigned char *)group_name,
                   strlen(group_name) + 1);

    unsigned char le[4];
    trc_put_u32le(le, (uint32_t)n_closure);
    sha3_256_write(&ctx, le, 4);

    for (int i = 0; i < n_closure; i++) {
        const char *p = tc->closure[i];
        uint8_t fh[32];
        int64_t mt = 0;
        if (!trc_file_hash(tc, p, fh, &mt))
            return false;
        if (mt > tc->dep_newest_ns)
            *stale = true;
        sha3_256_write(&ctx, (const unsigned char *)p, strlen(p) + 1);
        sha3_256_write(&ctx, fh, 32);
    }

    /* Reserved fixture-count slot (0 today: fixture-reading groups are
     * denylisted UNCACHEABLE). Keeps the preimage layout stable for a future
     * per-group declared-fixture extension without a key-version bump. */
    trc_put_u32le(le, 0);
    sha3_256_write(&ctx, le, 4);

    sha3_256_finalize(&ctx, out_key);
    return true;
}

static struct testcache *testcache_open_mode(
    const char *repo_root, const char *const *changed_sources,
    size_t changed_source_count, bool snapshot_mode)
{
    const char *root = repo_root;
    if (!root || !root[0]) {
        const char *env = getenv("ZCL_DEV_SOURCE_ROOT");
        root = (env && env[0]) ? env : ".";
    }

    if ((changed_source_count > 0 && !changed_sources) ||
        changed_source_count > TRC_CHANGED_MAX)
        LOG_NULL("testcache", "invalid changed source set");

    struct testcache *tc = zcl_calloc(1, sizeof(*tc), "testcache");
    if (!tc)
        LOG_NULL("testcache", "alloc handle failed");

    int n = snprintf(tc->root, sizeof(tc->root), "%s", root);
    if (n < 0 || (size_t)n >= sizeof(tc->root)) {
        free(tc);
        LOG_NULL("testcache", "root path overflow");
    }

    if (!vcs_object_store_init(tc->root)) {
        free(tc);
        LOG_NULL("testcache", "vcs object store init failed under %s", root);
    }

    tc->closure = zcl_malloc(sizeof(*tc->closure) * TRC_MAX_CLOSURE,
                             "testcache_closure");
    if (!tc->closure) {
        free(tc);
        LOG_NULL("testcache", "closure scratch alloc failed");
    }

    if (!trc_memo_init(&tc->memo, 4096)) {
        free(tc->closure);
        free(tc);
        LOG_NULL("testcache", "memo init failed");
    }

    trc_env_digest(tc->envkey);
    tc->snapshot_mode = snapshot_mode;
    for (size_t i = 0; i < changed_source_count; i++) {
        const char *path = changed_sources[i];
        if (!path || !path[0] || path[0] == '/' || strstr(path, "..") ||
            strlen(path) >= sizeof(tc->changed[0])) {
            testcache_close(tc);
            LOG_NULL("testcache", "invalid changed source path");
        }
        snprintf(tc->changed[tc->changed_count++],
                 sizeof(tc->changed[0]), "%s", path);
    }
    if (!codeindex_depfile_graph(tc->root, &tc->dep_count,
                                 &tc->dep_newest_ns)) {
        tc->dep_count = 0;
        tc->dep_newest_ns = 0;
    }

    tc->ci = snapshot_mode ? codeindex_open_existing(tc->root)
                           : codeindex_open(tc->root);
    if (!tc->ci) {
        trc_memo_free(&tc->memo);
        free(tc->closure);
        free(tc);
        LOG_NULL("testcache", "codeindex_open failed under %s", root);
    }
    return tc;
}

struct testcache *testcache_open(const char *repo_root)
{
    return testcache_open_mode(repo_root, NULL, 0, false);
}

struct testcache *testcache_open_snapshot(
    const char *repo_root, const char *const *changed_sources,
    size_t changed_source_count)
{
    if (!changed_sources || changed_source_count == 0)
        return NULL;
    return testcache_open_mode(repo_root, changed_sources,
                               changed_source_count, true);
}

size_t testcache_depfile_count(const struct testcache *tc)
{
    return tc ? tc->dep_count : 0;
}

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
    case TESTCACHE_R__COUNT:           break;
    }
    return "unknown";
}

void testcache_toolkey_digest12(char out[13])
{
    const char *tk = ZCL_TESTCACHE_TOOLKEY;
    uint8_t d[32];
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)tk, strlen(tk));
    sha3_256_finalize(&ctx, d);
    for (int i = 0; i < 6; i++)
        snprintf(out + i * 2, 3, "%02x", d[i]);
    out[12] = '\0';
}

void testcache_close(struct testcache *tc)
{
    if (!tc)
        return;
    if (tc->ci)
        codeindex_close(tc->ci);
    trc_memo_free(&tc->memo);
    free(tc->closure);
    free(tc);
}

const char *testcache_toolkey(void)
{
    return ZCL_TESTCACHE_TOOLKEY;
}

/* Populate *out for group_name. Fail-open: any failure => uncacheable. */
void testcache_probe_group(struct testcache *tc, const char *group_name,
                           struct testcache_probe *out)
{
    memset(out, 0, sizeof(*out));
    if (!tc || !tc->ci || !group_name || !group_name[0]) {
        out->code = TESTCACHE_R_NO_HANDLE;
        snprintf(out->reason, sizeof(out->reason), "no cache handle");
        return;
    }

    if (group_reads_external_inputs(group_name)) {
        out->code = TESTCACHE_R_EXTERNAL_INPUT;
        snprintf(out->reason, sizeof(out->reason), "external-input denylist");
        return;
    }

    /* No depfiles at all => the include graph is ABSENT, not empty. Every
     * closure would then be call-graph-only: a strictly smaller set that is
     * never reported truncated and so looks complete. Refuse the whole
     * keyspace rather than mint header-free keys. */
    if (tc->dep_count == 0) {
        out->code = TESTCACHE_R_NO_INCLUDE_GRAPH;
        snprintf(out->reason, sizeof(out->reason),
                 "no depfiles under build/ (include graph absent)");
        return;
    }

    bool truncated = false, root_found = false;
    int nc = codeindex_forward_closure(tc->ci, group_name, tc->closure,
                                       TRC_MAX_CLOSURE, &truncated, &root_found);
    if (nc < 0) {
        out->code = TESTCACHE_R_CLOSURE_ERROR;
        snprintf(out->reason, sizeof(out->reason), "closure query error");
        return;
    }
    if (!root_found) {
        out->code = TESTCACHE_R_ENTRY_UNRESOLVED;
        snprintf(out->reason, sizeof(out->reason), "entry symbol unresolved");
        return;
    }
    if (truncated) {
        out->code = TESTCACHE_R_TRUNCATED;
        snprintf(out->reason, sizeof(out->reason),
                 "closure truncated (%d files, cap hit)", nc);
        return;
    }
    if (nc == 0) {
        out->code = TESTCACHE_R_EMPTY_CLOSURE;
        snprintf(out->reason, sizeof(out->reason), "empty closure");
        return;
    }

    /* A verified snapshot describes the generation immediately before the
     * resident edit. It is sound for an unchanged group's closure. If that
     * closure reaches any edited TU, run the group fresh: the edit may have
     * changed its outgoing call/include edges, so the old closure is not a
     * complete cache key for it. */
    if (tc->snapshot_mode) {
        for (int i = 0; i < nc; i++) {
            for (size_t c = 0; c < tc->changed_count; c++) {
                if (strcmp(tc->closure[i], tc->changed[c]) != 0)
                    continue;
                out->code = TESTCACHE_R_CHANGED_INPUT;
                snprintf(out->reason, sizeof(out->reason),
                         "closure reaches changed source");
                return;
            }
        }
    }

    bool stale = false;
    if (!trc_compute_key(tc, group_name, nc, out->key, &stale)) {
        out->code = TESTCACHE_R_FILE_UNREADABLE;
        snprintf(out->reason, sizeof(out->reason), "input file unreadable");
        return;
    }
    /* An input newer than every depfile cannot be described by the graph those
     * depfiles built: an include added since is invisible to this key. */
    if (stale) {
        out->code = TESTCACHE_R_GRAPH_STALE;
        snprintf(out->reason, sizeof(out->reason),
                 "input newer than include graph (rebuild to refresh)");
        return;
    }

    out->cacheable = true;
    out->code = TESTCACHE_R_OK;
    out->n_closure = nc;
    snprintf(out->reason, sizeof(out->reason), "%d input files", nc);

    /* Is there a stored PASS at this exact key? Probe existence first (a quiet
     * access() — a MISS is the common, non-error case) before the verifying
     * load, so a cold cache never spams the log with "object not found". */
    if (vcs_object_has(tc->root, out->key)) {
        uint8_t *buf = NULL;
        size_t len = 0;
        if (vcs_object_load_raw(tc->root, out->key, &buf, &len) == 0 && buf) {
            if (len >= sizeof(struct trc_record)) {
                const struct trc_record *r = (const struct trc_record *)buf;
                if (memcmp(r->magic, TRC_MAGIC, 8) == 0 &&
                    r->status == TRC_STATUS_PASS &&
                    memcmp(r->key_echo, out->key, 32) == 0)
                    out->hit = true;
            }
            free(buf);
        }
    }
}

void testcache_store_pass(struct testcache *tc, const uint8_t key[32])
{
    if (!tc || !key)
        return;
    struct trc_record r;
    memset(&r, 0, sizeof(r));
    memcpy(r.magic, TRC_MAGIC, 8);
    r.status = TRC_STATUS_PASS;
    memcpy(r.key_echo, key, 32);
    /* Best-effort observability stamp; correctness never depends on it. */
    uint64_t gen = (uint64_t)platform_time_wall_time_t();
    for (int i = 0; i < 8; i++)
        r.generation_le[i] = (uint8_t)(gen >> (8 * i));
    if (!vcs_object_put_addressed(tc->root, key,
                                  (const uint8_t *)&r, sizeof(r)))
        ZCL_LOG_EMIT_AT(ZCL_LOG_WARN,
                        "[testcache] store_pass put_addressed failed\n");
}

void testcache_dump_group(struct testcache *tc, const char *group_name)
{
    if (!tc || !group_name) {
        printf("testcache: no handle/group\n");
        return;
    }
    struct testcache_probe p;
    testcache_probe_group(tc, group_name, &p);
    char tkd[13];
    testcache_toolkey_digest12(tkd);
    printf("testcache dump: group=%s\n", group_name);
    printf("  toolkey=%s (digest %s)\n", testcache_toolkey(), tkd);
    printf("  depfiles=%zu (include graph %s)\n", tc->dep_count,
           tc->dep_count ? "present" : "ABSENT");
    printf("  cacheable=%s  hit=%s  n_closure=%d  code=%s  reason=%s\n",
           p.cacheable ? "yes" : "no", p.hit ? "yes" : "no",
           p.n_closure, testcache_reason_label(p.code), p.reason);
    if (p.cacheable) {
        char kh[65];
        for (int i = 0; i < 32; i++)
            snprintf(kh + i * 2, 3, "%02x", p.key[i]);
        printf("  key=%s\n", kh);
    }
    /* Always list the closure, cacheable or not. When a group is UNCACHEABLE
     * the closure is the evidence for WHY — in particular, a closure of .c
     * files with zero headers is what an absent include graph looks like, and
     * that is the shape that used to be keyed and cached silently. */
    {
        /* Recompute the closure for the listing (probe consumed tc->closure). */
        bool truncated = false, root_found = false;
        int nc = codeindex_forward_closure(tc->ci, group_name, tc->closure,
                                           TRC_MAX_CLOSURE, &truncated,
                                           &root_found);
        /* Counted BY EXTENSION, which is not the same as "reached via an
         * include edge": a .h can enter the closure as the DEFINITION file of
         * an inline function or macro even when the include graph is empty.
         * Read this beside the depfiles= line above, never instead of it. */
        int hdr_ext = 0;
        for (int i = 0; i < nc; i++) {
            size_t l = strlen(tc->closure[i]);
            if ((l > 2 && strcmp(tc->closure[i] + l - 2, ".h") == 0) ||
                (l > 4 && strcmp(tc->closure[i] + l - 4, ".def") == 0))
                hdr_ext++;
        }
        printf("  closure (%d files, %d with a .h/.def extension, "
               "truncated=%s):\n", nc, hdr_ext, truncated ? "yes" : "no");
        for (int i = 0; i < nc; i++)
            printf("    %s\n", tc->closure[i]);
    }
}
