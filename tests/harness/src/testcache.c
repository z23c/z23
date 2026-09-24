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
#include "dev_proof_receipt.h"

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
/* rsvd[0] bit 0: this PASS was minted by the rerun-alone policy — the group
 * FAILed or was WEDGED once under a contended pool before passing alone (see
 * test_parallel.c's rerun_load_flaky_groups). A record with this bit set must
 * report hit_flaky=true on every probe, so a cache HIT can never make the
 * flake invisible again. rsvd[0] is 0 on every record written before this
 * field existed, which reads as "not flaky" — the only meaning an old record
 * can honestly carry. */
#define TRC_FLAKY_BIT 0x01u
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
    char              store_root[4096];
    struct trc_memo   memo;
    struct testcache_stats stats;
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
#if defined(_WIN32)
    /* UCRT struct stat has second resolution only. */
    return (int64_t)st->st_mtime * INT64_C(1000000000);
#else
    return (int64_t)st->st_mtim.tv_sec * INT64_C(1000000000) +
           (int64_t)st->st_mtim.tv_nsec;
#endif
}

/* SHA3-256 the bytes of <root>/<relpath> via a streaming read (no whole-file
 * buffer), and report the file's mtime and content byte count (the stats
 * ledger for "cost grows with new information"). Returns false (and logs)
 * if the file cannot be opened/read. */
static bool trc_hash_file(const char *root, const char *relpath,
                          uint8_t out[32], int64_t *out_mtime_ns,
                          size_t *out_bytes)
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
    size_t total = 0;
    bool ok = true;
    while ((got = fread(buf, 1, sizeof(buf), fp)) > 0) {
        sha3_256_write(&ctx, buf, got);
        total += got;
    }
    if (ferror(fp)) {
        ZCL_LOG_EMIT_AT(ZCL_LOG_WARN, "[testcache] read error: %s\n", path);
        ok = false;
    }
    fclose(fp);
    if (ok) {
        sha3_256_finalize(&ctx, out);
        *out_mtime_ns = trc_stat_mtime_ns(&st);
        *out_bytes = total;
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
            tc->stats.file_hash_memo_hits++;
            return true;
        }
        j = (j + 1) & (m->cap - 1);
    }
    uint8_t h[32];
    int64_t mt = 0;
    size_t nbytes = 0;
    if (!trc_hash_file(tc->root, relpath, h, &mt, &nbytes))
        return false;
    tc->stats.file_hash_reads++;
    tc->stats.sha3_content_bytes += (uint64_t)nbytes;
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
 * ZCL_FAST_* and the lint-only ZCL_LINT_TU_CACHE switch. Fast-CI exports its
 * frozen source record, changed-path hints, compiler choice, and scheduling
 * knobs; source bytes/toolchain/flags are bound elsewhere in the key and none of
 * those controls changes a group's verdict. Folding them in globally busts
 * every per-group receipt after any edit or docs-only rebase. */
static bool trc_env_is_cache_control(const char *name, size_t namelen)
{
    static const char *const ctl[] = {
        "ZCL_TEST_CACHE", "ZCL_TEST_CACHE_DUMP",
        "ZCL_TESTCACHE_STORE_ROOT", "ZCL_LINT_TU_CACHE",
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
 * Derived by grepping tests/harness/src for `build/bin/`, popen/system/exec of a
 * repo artifact, /proc readers, and CPU-feature dispatch. Kept in sorted order.
 * `name` may carry the test_/spec_ prefix. */
static bool group_reads_external_inputs(const char *name)
{
    if (strncmp(name, "test_", 5) == 0 || strncmp(name, "spec_", 5) == 0)
        name += 5;
    static const char *const ext[] = {
        /* --- execs a built binary or a repo script (whole-link input) --- */
        "acme_worker",                  /* executes zclassic23-acme selftests */
        "agent_copy_prove",
        "chain_advance_atomicity",
        "chaos_harness",                  /* reads tests/fixtures block files */
        "cli_argv_strict",
        "cli_auth_robust",
        "cold_start_sync",
        "crypto_perf_selftest",
        "dev_platform",                   /* reads tests/harness/fixtures source */
        "importblockindex_cli_dispatch",
        "kill9_recovery",
        "make_lint_gates",                /* plants fixtures + compiles the tree */
        /* The whole make_lint_gates FAMILY, not just the base group. Matching
         * here is EXACT, so "make_lint_gates" alone covered exactly one of the
         * 13 registered names. Every sibling copies or scans the worktree and
         * runs repo SCRIPTS, none of which its forward C closure reaches:
         * heavy_01/heavy_02 exec the prove-selftest scripts under tools, realroot
         * git-greps the real tree, partition sandboxes it. Measured: breaking
         * tools/scripts/fresh-boot-weld-prove-selftest.sh left heavy_02's
         * 17-file key unchanged, so a stored PASS was served while a cold run
         * of the same tree FAILED. shard_01..08 are macro-generated, so the
         * code index cannot resolve them and they report empty-closure today —
         * listed anyway so de-macroing them cannot silently make them cacheable. */
        "make_lint_gates_heavy_01",
        "make_lint_gates_heavy_02",
        "make_lint_gates_partition",
        "make_lint_gates_realroot",
        "make_lint_gates_shard_01",
        "make_lint_gates_shard_02",
        "make_lint_gates_shard_03",
        "make_lint_gates_shard_04",
        "make_lint_gates_shard_05",
        "make_lint_gates_shard_06",
        "make_lint_gates_shard_07",
        "make_lint_gates_shard_08",
        "net",
        "no_hardcoded_home",              /* scans tree + env for home usage */
        "onion_bootstrap",
        "onion_bootstrap_slice",
        "replay_canary_verdict",
        "secrets_hygiene",
        "self_folded_anchor",
        "shielded_payment_gate",
        /* sources tools/scripts/source_identity_lib.sh and execs a shell
         * fixture: the reader whose behaviour it pins is a repo file outside
         * this group's C include closure, so a stored PASS would survive an
         * edit to that reader. */
        "source_identity_authority",
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

static void trc_wrap_proof_key(
    const uint8_t ordinary_key[32], enum zcl_test_proof_contract contract,
    const char *env_name, const char *env_value, uint8_t out_key[32])
{
    static const char DOMAIN[] = "zcl.testcache.proof-key.v1";
    struct sha3_256_ctx ctx;
    unsigned char le[4];
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)DOMAIN, sizeof(DOMAIN));
    sha3_256_write(&ctx, ordinary_key, 32);
    trc_put_u32le(le, (uint32_t)contract);
    sha3_256_write(&ctx, le, sizeof(le));
    sha3_256_write(&ctx, (const unsigned char *)env_name,
                   strlen(env_name) + 1);
    sha3_256_write(&ctx, (const unsigned char *)env_value,
                   strlen(env_value) + 1);
    sha3_256_finalize(&ctx, out_key);
}

/* The two common translation units can change every group's execution or
 * cache policy without appearing in a group's call graph. Hash their source
 * and compiler-reported transitive prerequisites. No depfile row for either
 * unit means the common harness closure is unknown, even when some other TU
 * supplied enough depfiles to make the graph look live. */
static bool trc_hash_harness(struct testcache *tc, struct sha3_256_ctx *sha,
                             bool *stale, bool *graph_incomplete)
{
    static const char *const units[] = {
        "tests/harness/src/test_parallel.c",
        "tests/harness/src/testcache.c",
    };
    char deps[64][256];
    for (size_t u = 0; u < sizeof(units) / sizeof(units[0]); u++) {
        uint8_t hash[32];
        int64_t mtime = 0;
        if (!trc_file_hash(tc, units[u], hash, &mtime)) return false;
        if (mtime > tc->dep_newest_ns) *stale = true;
        sha3_256_write(sha, (const uint8_t *)units[u], strlen(units[u]) + 1);
        sha3_256_write(sha, hash, sizeof(hash));
        int offset = 0;
        for (;;) {
            int n = codeindex_includes_of_file_page(tc->ci, units[u], offset,
                                                     deps, 64);
            if (n < 0 || offset + n > TRC_MAX_CLOSURE ||
                (n == 0 && offset == 0)) {
                *graph_incomplete = true;
                return false;
            }
            if (n == 0) break;
            for (int i = 0; i < n; i++) {
                if (!trc_file_hash(tc, deps[i], hash, &mtime)) return false;
                if (mtime > tc->dep_newest_ns) *stale = true;
                sha3_256_write(sha, (const uint8_t *)deps[i],
                               strlen(deps[i]) + 1);
                sha3_256_write(sha, hash, sizeof(hash));
            }
            offset += n;
        }
    }
    return true;
}

/* Fold the complete closure into the SHA3 key. An activated proof runs fresh,
 * but its key can later identify an observation offered for reuse. It must
 * meet the same closure requirements as an ordinary cache key. */
static bool trc_compute_key(struct testcache *tc, const char *group_name,
                            int n_closure, uint8_t out_key[32], bool *stale,
                            bool *graph_incomplete)
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);

    /* v5 adds the common harness source and generated include closure. v4
     * records lacked this input and cannot safely be reused. v4 had already
     * retired v3 PASS records minted while activated proof contracts still
     * shared this ordinary keyspace. Active proofs now bypass lookup/storage;
     * retiring v3 also prevents one of those old records becoming reachable
     * if its contract row is later removed. v3 first rejected skipped PASSes,
     * and v2 added the coverage-gating environment over v1. */
    static const char DOMAIN[] = "zcl.testcache.key.v5";
    sha3_256_write(&ctx, (const unsigned char *)DOMAIN, sizeof(DOMAIN)); /* +NUL */

    const char *tk = ZCL_TESTCACHE_TOOLKEY;
    sha3_256_write(&ctx, (const unsigned char *)tk, strlen(tk) + 1);
    sha3_256_write(&ctx, tc->envkey, sizeof(tc->envkey));
    sha3_256_write(&ctx, (const unsigned char *)group_name,
                   strlen(group_name) + 1);
    if (!trc_hash_harness(tc, &ctx, stale, graph_incomplete)) return false;

    unsigned char le[4];
    trc_put_u32le(le, (uint32_t)n_closure);
    sha3_256_write(&ctx, le, 4);

    for (int i = 0; i < n_closure; i++) {
        const char *p = tc->closure[i];
        uint8_t fh[32];
        int64_t mt = 0;
        if (!trc_file_hash(tc, p, fh, &mt)) return false;
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

    const char *configured_store = getenv("ZCL_TESTCACHE_STORE_ROOT");
    const char *store_root = configured_store && configured_store[0]
        ? configured_store : root;
    n = snprintf(tc->store_root, sizeof(tc->store_root), "%s", store_root);
    if (n < 0 || (size_t)n >= sizeof(tc->store_root)) {
        free(tc);
        LOG_NULL("testcache", "store root path overflow");
    }

    if (!vcs_object_store_init(tc->store_root)) {
        free(tc);
        LOG_NULL("testcache", "vcs object store init failed under %s",
                 store_root);
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

const char *testcache_store_root(const struct testcache *tc)
{
    return tc ? tc->store_root : NULL;
}

const char *testcache_toolkey(void)
{
    return ZCL_TESTCACHE_TOOLKEY;
}

/* The one backing-record check every HIT interpretation shares: the
 * addressed record must exist, load, and carry magic/PASS/key-echo. The
 * fresh probe uses it at lookup time; capsule apply reuses it at consume
 * time, so a vanished record can never authorize a skip. */
static bool trc_record_verifies(const char *store_root, const uint8_t key[32],
                                bool *flaky_out)
{
    uint8_t *buf = NULL;
    size_t len = 0;
    bool ok = false;
    if (!store_root || !store_root[0] || !key)
        return false;
    if (!vcs_object_has(store_root, key))
        return false;
    if (vcs_object_load_raw(store_root, key, &buf, &len) != 0 || !buf)
        return false;
    if (len >= sizeof(struct trc_record)) {
        const struct trc_record *r = (const struct trc_record *)buf;
        if (memcmp(r->magic, TRC_MAGIC, 8) == 0 &&
            r->status == TRC_STATUS_PASS &&
            memcmp(r->key_echo, key, 32) == 0) {
            ok = true;
            if (flaky_out)
                *flaky_out = (r->rsvd[0] & TRC_FLAKY_BIT) != 0;
        }
    }
    free(buf);
    return ok;
}

/* Resolve the verdict store exactly as testcache_open_mode does, so a
 * NULL/empty root checks the store a fresh probe in this process would. */
static const char *trc_effective_store_root(const char *store_root)
{
    if (store_root && store_root[0])
        return store_root;
    store_root = getenv("ZCL_TESTCACHE_STORE_ROOT");
    if (store_root && store_root[0])
        return store_root;
    store_root = getenv("ZCL_DEV_SOURCE_ROOT");
    return (store_root && store_root[0]) ? store_root : ".";
}

/* Populate *out for group_name. Fail-safe: any failure => uncacheable. */
static void testcache_probe_group_internal(
    struct testcache *tc, const char *group_name,
    enum zcl_test_proof_contract contract, bool activated,
    struct testcache_probe *out)
{
    memset(out, 0, sizeof(*out));
    const char *env_name = NULL;
    const char *env_value = NULL;
    if (activated &&
        (!zcl_test_proof_contract_environment(contract, &env_name,
                                               &env_value) ||
         contract == ZCL_TEST_PROOF_NONE || !env_name || !env_value)) {
        out->code = TESTCACHE_R_PROOF_CONTRACT_INVALID;
        snprintf(out->reason, sizeof(out->reason),
                 "invalid activated proof contract");
        return;
    }
    if (!tc || !tc->ci || !group_name || !group_name[0]) {
        out->code = TESTCACHE_R_NO_HANDLE;
        snprintf(out->reason, sizeof(out->reason), "no cache handle");
        return;
    }
    if (strlen(group_name) > ZCL_DEV_VERDICT_LEAF_GROUP_MAX) {
        out->code = TESTCACHE_R_GROUP_UNADMISSIBLE;
        snprintf(out->reason, sizeof(out->reason),
                 "group exceeds signed observation name bound");
        return;
    }

    if (group_reads_external_inputs(group_name)) {
        out->code = TESTCACHE_R_EXTERNAL_INPUT;
        snprintf(out->reason, sizeof(out->reason), "external-input denylist");
        return;
    }

    /* No depfiles means the include closure is unknown. Even a freshly run
     * proof cannot mint a reusable key from that incomplete input set. */
    if (tc->dep_count == 0) {
        out->code = TESTCACHE_R_NO_INCLUDE_GRAPH;
        snprintf(out->reason, sizeof(out->reason),
                 "no depfiles under build/ (include graph absent)");
        return;
    }

    bool truncated = false, root_found = false;
    int nc = codeindex_forward_closure(tc->ci, group_name, tc->closure,
                                       TRC_MAX_CLOSURE, &truncated, &root_found);
    tc->stats.closure_queries++;
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

    bool stale = false, harness_graph_incomplete = false;
    if (!trc_compute_key(tc, group_name, nc, out->key, &stale,
                         &harness_graph_incomplete)) {
        out->code = harness_graph_incomplete ? TESTCACHE_R_HARNESS_GRAPH
                                             : TESTCACHE_R_FILE_UNREADABLE;
        snprintf(out->reason, sizeof(out->reason), "%s",
                 harness_graph_incomplete ? "harness depfile graph incomplete"
                                          : "input file unreadable");
        return;
    }
    /* An input newer than every depfile may have new unseen dependencies. */
    if (stale) {
        out->code = TESTCACHE_R_GRAPH_STALE;
        snprintf(out->reason, sizeof(out->reason),
                 "input newer than include graph (rebuild to refresh)");
        return;
    }

    out->key_valid = true;
    if (activated) {
        uint8_t ordinary_key[32];
        memcpy(ordinary_key, out->key, sizeof(ordinary_key));
        trc_wrap_proof_key(ordinary_key, contract, env_name, env_value,
                           out->key);
        out->code = TESTCACHE_R_ACTIVE_PROOF_CONTRACT;
        out->n_closure = nc;
        snprintf(out->reason, sizeof(out->reason),
                 "activated proof contract runs fresh (%d inputs)", nc);
        return;
    }

    out->cacheable = true;
    out->code = TESTCACHE_R_OK;
    out->n_closure = nc;
    snprintf(out->reason, sizeof(out->reason), "%d input files", nc);

    /* Is there a stored PASS at this exact key? Probe existence first (a quiet
     * access() — a MISS is the common, non-error case) before the verifying
     * load, so a cold cache never spams the log with "object not found". */
    tc->stats.verdict_lookups++;
    {
        bool flaky = false;
        if (trc_record_verifies(tc->store_root, out->key, &flaky)) {
            out->hit = true;
            out->hit_flaky = flaky;
            tc->stats.verdict_hits++;
        }
    }
}

void testcache_probe_group(struct testcache *tc, const char *group_name,
                           struct testcache_probe *out)
{
    testcache_probe_group_internal(tc, group_name, ZCL_TEST_PROOF_NONE,
                                   false, out);
}

void testcache_probe_group_proof(
    struct testcache *tc, const char *group_name,
    enum zcl_test_proof_contract contract, struct testcache_probe *out)
{
    if (contract == ZCL_TEST_PROOF_NONE) {
        testcache_probe_group(tc, group_name, out);
        return;
    }
    testcache_probe_group_internal(tc, group_name, contract, true, out);
}

void testcache_stats(const struct testcache *tc, struct testcache_stats *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (tc && out) memcpy(out, &tc->stats, sizeof(*out));
}

void testcache_stats_reset(struct testcache *tc)
{
    if (tc) memset(&tc->stats, 0, sizeof(tc->stats));
}

void testcache_current_envkey(uint8_t out[32])
{
    if (out) trc_env_digest(out);
}

/* ── Probe capsule ───────────────────────────────────────────────────────
 * Layout (all integers little-endian; see testcache.h for the contract):
 *   magic[8] "ZTCAP1\0\0" | version u32=1
 *   toolkey: u32 len + bytes (live toolkey string, compared live)
 *   envkey[32] (compared against a live recompute)
 *   caller bindings: source_id u32+bytes(<=64), mutation_id u32+bytes,
 *     cas_present u8 + cas u32+bytes, graph_present u8 + graph u32+bytes,
 *     dep_count u64, dep_newest_ns u64-bits
 *   slots: u32 n (<=8192) + per slot: name u32+bytes(1..128),
 *     contract u32 (<=GOLDEN_TIMING), key_valid u8, key[32],
 *     cacheable/hit/hit_flaky u8, code u32 (<R__COUNT), n_closure i32
 *   capsule SHA3-256 over every preceding byte (domain-separated)
 * Strict: trailing bytes after the hash refuse; anything over cap
 * (names, slots, file size) refuses. The hash is integrity only — it
 * never addresses a verdict. */
#define TRC_CAP_MAGIC "ZTCAP1\0\0"
#define TRC_CAP_VERSION 1u
#define TRC_CAP_MAX_SLOTS 8192u
#define TRC_CAP_MAX_NAME 128u
#define TRC_CAP_MAX_FILE (8u * 1024u * 1024u)
#define TRC_CAP_DOMAIN "zcl.testcache.capsule.v1"

static void trc_cap_put_u64(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

/* Bounded NUL-terminated text: length, or SIZE_MAX when unterminated /
 * over cap. */
static size_t trc_cap_text_len(const char *s, size_t cap)
{
    size_t n = 0;
    if (!s) return SIZE_MAX;
    while (n < cap && s[n]) n++;
    if (n >= cap) return SIZE_MAX;
    return n;
}

/* Serialized body size, or 0 when any bound refuses. */
static size_t trc_cap_body_size(const char *const *names, size_t n,
                                const struct testcache_capsule_bindings *bind,
                                size_t toolkey_len)
{
    size_t sid, mid, cas, graph, total, i;
    if (!names || !bind || n > TRC_CAP_MAX_SLOTS) return 0;
    sid = trc_cap_text_len(bind->source_id, 65);
    mid = trc_cap_text_len(bind->mutation_id, 65);
    if (sid > 64 || mid > 64) return 0;
    cas = bind->source_cas_present
        ? trc_cap_text_len(bind->source_cas, 65) : 0;
    graph = bind->graph_root_present
        ? trc_cap_text_len(bind->graph_root, 65) : 0;
    if (cas > 64 || graph > 64) return 0;
    total = 8 + 4 + 4 + toolkey_len + 32 + 4 + sid + 4 + mid + 1 + 4 + cas +
            1 + 4 + graph + 8 + 8 + 4;
    for (i = 0; i < n; i++) {
        size_t nl;
        if (!names[i]) return 0;
        nl = strlen(names[i]);
        if (nl == 0 || nl > TRC_CAP_MAX_NAME) return 0;
        total += 4 + nl + 4 + 1 + 32 + 1 + 1 + 1 + 4 + 4;
        if (total > TRC_CAP_MAX_FILE) return 0;
    }
    return total;
}

static uint8_t *trc_cap_emit_text(uint8_t *p, const char *s, size_t len)
{
    trc_put_u32le(p, (uint32_t)len);
    memcpy(p + 4, s, len);
    return p + 4 + len;
}

/* Argument validation for the writer: bounded slots, a bounded toolkey,
 * and a body that fits the file cap with its 32-byte seal. */
static bool trc_cap_write_pre(struct testcache *tc, const char *path,
                              const char *const *names, size_t n,
                              const struct testcache_probe *probes,
                              const struct testcache_capsule_bindings *bind,
                              const char **toolkey_out, size_t *tk_len_out,
                              size_t *body_len_out)
{
    const char *toolkey;
    size_t toolkey_len, body_len;
    if (!tc || !path || !path[0] || !probes || !bind || !names) return false;
    if (n > TRC_CAP_MAX_SLOTS) return false;
    toolkey = testcache_toolkey();
    toolkey_len = strlen(toolkey);
    if (toolkey_len > 4096) return false;
    body_len = trc_cap_body_size(names, n, bind, toolkey_len);
    if (body_len == 0 || body_len + 32 > TRC_CAP_MAX_FILE) return false;
    *toolkey_out = toolkey;
    *tk_len_out = toolkey_len;
    *body_len_out = body_len;
    return true;
}

/* Header emit: magic, version, toolkey, live env digest, source/mutation
 * identity, optional CAS/graph presence, and dep-graph facts. */
static uint8_t *trc_cap_emit_head(uint8_t *p, struct testcache *tc,
                                  const struct testcache_capsule_bindings *bind,
                                  const char *toolkey, size_t toolkey_len)
{
    size_t cas_len, graph_len;
    memcpy(p, TRC_CAP_MAGIC, 8);
    p += 8;
    trc_put_u32le(p, TRC_CAP_VERSION);
    p += 4;
    p = trc_cap_emit_text(p, toolkey, toolkey_len);
    trc_env_digest(p);
    p += 32;
    p = trc_cap_emit_text(p, bind->source_id, strlen(bind->source_id));
    p = trc_cap_emit_text(p, bind->mutation_id, strlen(bind->mutation_id));
    *p++ = bind->source_cas_present ? 1 : 0;
    cas_len = bind->source_cas_present ? strlen(bind->source_cas) : 0;
    p = trc_cap_emit_text(p, bind->source_cas, cas_len);
    *p++ = bind->graph_root_present ? 1 : 0;
    graph_len = bind->graph_root_present ? strlen(bind->graph_root) : 0;
    p = trc_cap_emit_text(p, bind->graph_root, graph_len);
    trc_cap_put_u64(p, (uint64_t)tc->dep_count);
    p += 8;
    trc_cap_put_u64(p, (uint64_t)tc->dep_newest_ns);
    p += 8;
    return p;
}

/* Slot emit: count, then one ordered record per group. */
static uint8_t *trc_cap_emit_slots(uint8_t *p, const char *const *names,
                                   const enum zcl_test_proof_contract *contracts,
                                   size_t n,
                                   const struct testcache_probe *probes)
{
    size_t i;
    trc_put_u32le(p, (uint32_t)n);
    p += 4;
    for (i = 0; i < n; i++) {
        size_t nl = strlen(names[i]);
        enum zcl_test_proof_contract contract = ZCL_TEST_PROOF_NONE;
        if (contracts) contract = contracts[i];
        trc_put_u32le(p, (uint32_t)nl);
        p += 4;
        memcpy(p, names[i], nl);
        p += nl;
        trc_put_u32le(p, (uint32_t)contract);
        p += 4;
        *p++ = probes[i].key_valid ? 1 : 0;
        memcpy(p, probes[i].key, 32);
        p += 32;
        *p++ = probes[i].cacheable ? 1 : 0;
        *p++ = probes[i].hit ? 1 : 0;
        *p++ = probes[i].hit_flaky ? 1 : 0;
        trc_put_u32le(p, (uint32_t)probes[i].code);
        p += 4;
        trc_put_u32le(p, (uint32_t)probes[i].n_closure);
        p += 4;
    }
    return p;
}

/* Seal and store: SHA3 over the domain plus body, digest appended, one
 * write with a close check. */
static bool trc_cap_seal_store(uint8_t *body, size_t body_len, const char *path)
{
    struct sha3_256_ctx ctx;
    uint8_t digest[32];
    FILE *f;
    bool ok;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const uint8_t *)TRC_CAP_DOMAIN,
                   strlen(TRC_CAP_DOMAIN));
    sha3_256_write(&ctx, body, body_len);
    sha3_256_finalize(&ctx, digest);
    memcpy(body + body_len, digest, 32);
    f = fopen(path, "wb");
    ok = f && fwrite(body, 1, body_len + 32, f) == body_len + 32;
    if (f) {
        if (fclose(f) != 0) ok = false;
    } else {
        ok = false;
    }
    return ok;
}

bool testcache_capsule_write(struct testcache *tc, const char *path,
                             const char *const *names,
                             const enum zcl_test_proof_contract *contracts,
                             size_t n, const struct testcache_probe *probes,
                             const struct testcache_capsule_bindings *bind)
{
    const char *toolkey;
    size_t toolkey_len, body_len;
    uint8_t *body, *p;
    bool ok;
    if (!trc_cap_write_pre(tc, path, names, n, probes, bind, &toolkey,
                           &toolkey_len, &body_len))
        return false;
    body = zcl_malloc(body_len + 32, "testcache_capsule");
    if (!body) return false;
    p = body;
    p = trc_cap_emit_head(p, tc, bind, toolkey, toolkey_len);
    p = trc_cap_emit_slots(p, names, contracts, n, probes);
    ok = trc_cap_seal_store(body, body_len, path);
    free(body);
    return ok;
}

/* Bounded cursor over the capsule body: every read advances or latches
 * `ok = false`, so a truncated file refuses instead of over-reading. */
struct trc_cap_cursor {
    const uint8_t *p;
    size_t left;
    bool ok;
};

static uint32_t trc_cap_u32(struct trc_cap_cursor *c)
{
    uint32_t v = 0;
    if (!c || c->left < 4) {
        if (c) c->ok = false;
        return 0;
    }
    v = (uint32_t)c->p[0] | ((uint32_t)c->p[1] << 8) |
        ((uint32_t)c->p[2] << 16) | ((uint32_t)c->p[3] << 24);
    c->p += 4;
    c->left -= 4;
    return v;
}

static uint64_t trc_cap_u64(struct trc_cap_cursor *c)
{
    uint64_t lo = trc_cap_u32(c), hi = trc_cap_u32(c);
    return lo | (hi << 32);
}

static bool trc_cap_bytes(struct trc_cap_cursor *c, uint8_t *out, size_t n)
{
    if (!c || !out || c->left < n) {
        if (c) c->ok = false;
        return false;
    }
    memcpy(out, c->p, n);
    c->p += n;
    c->left -= n;
    return true;
}

static void trc_cap_why(char *why, size_t why_len, const char *msg)
{
    if (why && why_len > 0) {
        snprintf(why, why_len, "%s", msg ? msg : "capsule refused");
    }
}

/* Whole-file bounded read for the consumer: the capsule is written by us,
 * but the file beside scratch is untrusted input — cap it hard. */
static bool trc_cap_read(const char *path, uint8_t **bytes_out,
                         size_t *len_out, char *why, size_t why_len)
{
    FILE *f;
    long tell;
    size_t len;
    uint8_t *bytes;
    if (!path || !path[0] || !bytes_out || !len_out) {
        trc_cap_why(why, why_len, "no capsule path");
        return false;
    }
    f = fopen(path, "rb");
    if (!f) {
        trc_cap_why(why, why_len, "capsule unreadable");
        return false;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        trc_cap_why(why, why_len, "capsule unseekable");
        return false;
    }
    tell = ftell(f);
    if (tell < 0 || (uint64_t)tell > TRC_CAP_MAX_FILE + 32) {
        fclose(f);
        trc_cap_why(why, why_len, "capsule too large");
        return false;
    }
    len = (size_t)tell;
    rewind(f);
    bytes = zcl_malloc(len > 0 ? len : 1, "testcache_capsule_read");
    if (!bytes) {
        fclose(f);
        trc_cap_why(why, why_len, "capsule alloc failed");
        return false;
    }
    if (len > 0 && fread(bytes, 1, len, f) != len) {
        free(bytes);
        fclose(f);
        trc_cap_why(why, why_len, "capsule unreadable");
        return false;
    }
    fclose(f);
    *bytes_out = bytes;
    *len_out = len;
    return true;
}

/* Magic, version, and the trailing integrity hash. Returns the body
 * cursor on success: any byte difference anywhere refuses. */
static bool trc_cap_verify(const uint8_t *bytes, size_t len,
                           struct trc_cap_cursor *body, char *why,
                           size_t why_len)
{
    struct sha3_256_ctx ctx;
    uint8_t digest[32];
    uint32_t version;
    if (!bytes || len < 8 + 4 + 32 || !body) {
        trc_cap_why(why, why_len, "capsule truncated");
        return false;
    }
    if (memcmp(bytes, TRC_CAP_MAGIC, 8) != 0) {
        trc_cap_why(why, why_len, "bad capsule magic");
        return false;
    }
    version = (uint32_t)bytes[8] | ((uint32_t)bytes[9] << 8) |
              ((uint32_t)bytes[10] << 16) | ((uint32_t)bytes[11] << 24);
    if (version != TRC_CAP_VERSION) {
        trc_cap_why(why, why_len, "capsule version drift");
        return false;
    }
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const uint8_t *)TRC_CAP_DOMAIN,
                   strlen(TRC_CAP_DOMAIN));
    sha3_256_write(&ctx, bytes, len - 32);
    sha3_256_finalize(&ctx, digest);
    if (memcmp(digest, bytes + len - 32, 32) != 0) {
        trc_cap_why(why, why_len, "capsule hash mismatch");
        return false;
    }
    body->p = bytes + 12;
    body->left = len - 12 - 32;
    body->ok = true;
    return true;
}

/* Compare one parsed text binding against expectation. */
static bool trc_cap_bind_text(const char *got, bool got_present,
                              const char *want, bool want_present,
                              char *why, size_t why_len, const char *what)
{
    char msg[64];
    if (got_present != want_present) {
        snprintf(msg, sizeof(msg), "%s presence drift", what);
        trc_cap_why(why, why_len, msg);
        return false;
    }
    if (want_present && strcmp(got, want) != 0) {
        snprintf(msg, sizeof(msg), "%s drift", what);
        trc_cap_why(why, why_len, msg);
        return false;
    }
    return true;
}

static uint8_t trc_cap_u8(struct trc_cap_cursor *c)
{
    uint8_t v = 0;
    if (!c || c->left < 1) {
        if (c) c->ok = false;
        return 0;
    }
    v = c->p[0];
    c->p += 1;
    c->left -= 1;
    return v;
}

/* Parsed capsule header: everything before the slot vector. */
struct trc_cap_head {
    char toolkey[4097];
    uint8_t envkey[32];
    char sid[65];
    char mid[65];
    char cas[65];
    bool cas_present;
    char graph[65];
    bool graph_present;
    uint64_t dep_count;
    uint64_t dep_newest;
    uint32_t n_slots;
};

/* Length-prefixed text with an explicit bound; NUL-terminates field. */
static bool trc_cap_field(struct trc_cap_cursor *c, char *field,
                          size_t field_size, size_t maxtext, bool nonempty)
{
    uint32_t len = trc_cap_u32(c);
    if (!c->ok || !field || len > maxtext || len + 1 > field_size) {
        c->ok = false;
        return false;
    }
    memset(field, 0, field_size);
    if (len > 0 && !trc_cap_bytes(c, (uint8_t *)field, len)) return false;
    if (len == 0 && nonempty) {
        c->ok = false;
        return false;
    }
    return true;
}

/* Toolkey string + live env digest. */
static bool trc_cap_parse_toolenv(struct trc_cap_cursor *c,
                                  struct trc_cap_head *h)
{
    uint32_t toolkey_len = trc_cap_u32(c);
    if (!c->ok || toolkey_len == 0 || toolkey_len > 4096) {
        c->ok = false;
        return false;
    }
    memset(h->toolkey, 0, sizeof(h->toolkey));
    if (!trc_cap_bytes(c, (uint8_t *)h->toolkey, toolkey_len)) return false;
    return trc_cap_bytes(c, h->envkey, 32);
}

/* Required ids plus the two optional presence-framed roots. */
static bool trc_cap_parse_ids(struct trc_cap_cursor *c,
                              struct trc_cap_head *h)
{
    if (!trc_cap_field(c, h->sid, sizeof(h->sid), 64, true)) return false;
    if (!trc_cap_field(c, h->mid, sizeof(h->mid), 64, true)) return false;
    h->cas_present = trc_cap_u8(c) != 0;
    if (!c->ok) return false;
    if (!trc_cap_field(c, h->cas, sizeof(h->cas), 64, false)) return false;
    h->graph_present = trc_cap_u8(c) != 0;
    if (!c->ok) return false;
    if (!trc_cap_field(c, h->graph, sizeof(h->graph), 64, false))
        return false;
    return true;
}

/* Dep provenance + slot count. */
static bool trc_cap_parse_meta(struct trc_cap_cursor *c,
                               struct trc_cap_head *h)
{
    h->dep_count = trc_cap_u64(c);
    h->dep_newest = trc_cap_u64(c);
    h->n_slots = trc_cap_u32(c);
    if (!c->ok || h->n_slots > TRC_CAP_MAX_SLOTS) {
        c->ok = false;
        return false;
    }
    return true;
}

/* The caller's CURRENT bindings must be well-formed before they can
 * accept anything: NUL-terminated ids, optional roots gated on presence. */
static bool trc_cap_expected_ok(const struct testcache_capsule_bindings *e)
{
    size_t sid, mid, cas, graph;
    if (!e) return false;
    sid = trc_cap_text_len(e->source_id, 65);
    mid = trc_cap_text_len(e->mutation_id, 65);
    if (sid == SIZE_MAX || mid == SIZE_MAX || sid == 0 || mid == 0 ||
        sid > 64 || mid > 64)
        return false;
    cas = e->source_cas_present ? trc_cap_text_len(e->source_cas, 65) : 0;
    graph = e->graph_root_present ? trc_cap_text_len(e->graph_root, 65) : 0;
    return cas <= 64 && graph <= 64;
}

/* One range-checked u32 field: advances past it or latches the refusal. */
static bool trc_cap_field_u32(struct trc_cap_cursor *c, uint32_t max,
                              uint32_t *out)
{
    uint32_t v = trc_cap_u32(c);
    if (!c || !c->ok || v > max) {
        if (c) c->ok = false;
        return false;
    }
    *out = v;
    return true;
}

/* One flag byte: 0 or 1, or the capsule refuses. */
static bool trc_cap_field_flag(struct trc_cap_cursor *c, bool *out)
{
    uint8_t v = trc_cap_u8(c);
    if (!c || !c->ok || v > 1) {
        if (c) c->ok = false;
        return false;
    }
    *out = v != 0;
    return true;
}

/* Slot name: a nonempty NUL-terminated copy that fits the fixed field. */
static bool trc_cap_parse_name(struct trc_cap_cursor *c,
                               struct testcache_capsule_slot *slot)
{
    uint32_t namelen;
    if (!c || !slot) {
        if (c) c->ok = false;
        return false;
    }
    namelen = trc_cap_u32(c);
    if (!c->ok || namelen == 0 || namelen >= sizeof(slot->name)) {
        c->ok = false;
        return false;
    }
    if (!trc_cap_bytes(c, (uint8_t *)slot->name, namelen)) return false;
    slot->name[namelen] = '\0';
    return true;
}

/* One slot into out: every field range-checked, fail closed. The read
 * order matches the writer's emit order exactly. */
static bool trc_cap_parse_slot(struct trc_cap_cursor *c,
                               struct testcache_capsule_slot *slot)
{
    uint32_t contract, code, ncl;
    bool key_valid, cacheable, hit, hit_flaky;
    if (!c || !slot) {
        if (c) c->ok = false;
        return false;
    }
    memset(slot, 0, sizeof(*slot));
    if (!trc_cap_parse_name(c, slot)) return false;
    if (!trc_cap_field_u32(c, (uint32_t)ZCL_TEST_PROOF_GOLDEN_TIMING,
                           &contract))
        return false;
    if (!trc_cap_field_flag(c, &key_valid)) return false;
    if (!trc_cap_bytes(c, slot->probe.key, 32)) return false;
    if (!trc_cap_field_flag(c, &cacheable)) return false;
    if (!trc_cap_field_flag(c, &hit)) return false;
    if (!trc_cap_field_flag(c, &hit_flaky)) return false;
    if (!trc_cap_field_u32(c, (uint32_t)TESTCACHE_R__COUNT - 1, &code))
        return false;
    if (!trc_cap_field_u32(c, (uint32_t)(1 << 20), &ncl)) return false;
    slot->probe.key_valid = key_valid;
    slot->probe.cacheable = cacheable;
    slot->probe.hit = hit;
    slot->probe.hit_flaky = hit_flaky;
    slot->probe.code = (enum testcache_reason)code;
    slot->probe.n_closure = (int)ncl;
    snprintf(slot->probe.reason, sizeof(slot->probe.reason), "%s",
             testcache_reason_label(slot->probe.code));
    (void)contract;
    return true;
}

/* Toolchain and environment bindings: the capsule's toolkey must be this
 * binary's, and its env digest must match the live process env. */
static bool trc_cap_check_toolenv(const struct trc_cap_head *h,
                                  char *why, size_t why_len)
{
    uint8_t live_env[32];
    if (strcmp(h->toolkey, testcache_toolkey()) != 0) {
        trc_cap_why(why, why_len, "toolkey drift");
        return false;
    }
    testcache_current_envkey(live_env);
    if (memcmp(h->envkey, live_env, 32) != 0) {
        trc_cap_why(why, why_len, "env drift");
        return false;
    }
    return true;
}

/* Source identity bindings: candidate ids plus the optional CAS and
 * graph roots, presence-gated on both sides. */
static bool trc_cap_check_ids(const struct trc_cap_head *h,
                              const struct testcache_capsule_bindings *expected,
                              char *why, size_t why_len)
{
    if (strcmp(h->sid, expected->source_id) != 0 ||
        strcmp(h->mid, expected->mutation_id) != 0) {
        trc_cap_why(why, why_len, "source binding drift");
        return false;
    }
    if (!trc_cap_bind_text(h->cas, h->cas_present, expected->source_cas,
                           expected->source_cas_present, why, why_len,
                           "source CAS"))
        return false;
    if (!trc_cap_bind_text(h->graph, h->graph_present,
                           expected->graph_root,
                           expected->graph_root_present, why, why_len,
                           "graph root"))
        return false;
    return true;
}

/* Slot vector: fits the caller's cap, every slot parses, no trailing
 * bytes. A slot that fails to parse refuses exactly as before, with
 * whatever reason the earlier checks left. */
static bool trc_cap_read_slots(struct trc_cap_cursor *body,
                               const struct trc_cap_head *h,
                               struct testcache_capsule_slot *out, size_t cap,
                               char *why, size_t why_len)
{
    size_t i;
    bool ok = true;
    if (h->n_slots > cap) {
        trc_cap_why(why, why_len, "too many slots");
        return false;
    }
    for (i = 0; ok && i < h->n_slots; i++)
        ok = trc_cap_parse_slot(body, &out[i]);
    if (ok && body->left != 0) {
        trc_cap_why(why, why_len, "capsule trailing bytes");
        ok = false;
    }
    return ok;
}

/* Provenance account for the caller: slot count, dep facts, toolkey head. */
static void trc_cap_fill_info(struct testcache_capsule_info *info,
                              const struct trc_cap_head *h)
{
    size_t tk = strlen(h->toolkey);
    size_t n = tk < 12 ? tk : 12;
    info->n_slots = h->n_slots;
    info->dep_count = h->dep_count;
    memcpy(info->toolkey_hex12, h->toolkey, n);
    info->toolkey_hex12[n] = '\0';
}

bool testcache_capsule_consume(const char *path,
                               const struct testcache_capsule_bindings *expected,
                               struct testcache_capsule_slot *out, size_t cap,
                               struct testcache_capsule_info *info,
                               char *why, size_t why_len)
{
    uint8_t *bytes = NULL;
    size_t len = 0;
    struct trc_cap_cursor body;
    struct trc_cap_head h;
    bool ok;
    memset(&h, 0, sizeof(h));
    if (!expected || !out || cap == 0 || !info ||
        !trc_cap_expected_ok(expected)) {
        trc_cap_why(why, why_len, "capsule refused");
        return false;
    }
    memset(info, 0, sizeof(*info));
    if (!trc_cap_read(path, &bytes, &len, why, why_len)) return false;
    ok = trc_cap_verify(bytes, len, &body, why, why_len) &&
         trc_cap_parse_toolenv(&body, &h) &&
         trc_cap_parse_ids(&body, &h) &&
         trc_cap_parse_meta(&body, &h);
    ok = ok && trc_cap_check_toolenv(&h, why, why_len);
    ok = ok && trc_cap_check_ids(&h, expected, why, why_len);
    ok = ok && trc_cap_read_slots(&body, &h, out, cap, why, why_len);
    if (ok) trc_cap_fill_info(info, &h);
    free(bytes);
    return ok;
}

void testcache_capsule_apply(const struct testcache_capsule_slot *slots,
                             size_t n_slots,
                             const char *const *want_names, size_t n_want,
                             struct testcache_probe *out,
                             const char *store_root)
{
    size_t i, s;
    const char *root = trc_effective_store_root(store_root);
    if (!out) return;
    for (i = 0; i < n_want; i++) {
        memset(&out[i], 0, sizeof(out[i]));
        out[i].code = TESTCACHE_R_NO_HANDLE;
        snprintf(out[i].reason, sizeof(out[i].reason),
                 "capsule slot absent");
        if (!want_names || !want_names[i] || !slots) continue;
        for (s = 0; s < n_slots; s++) {
            if (strcmp(slots[s].name, want_names[i]) != 0) continue;
            out[i] = slots[s].probe;
            break;
        }
        /* Fail-closed: a stored HIT authorizes a skip only while its
         * backing PASS record still verifies. A vanished record demotes
         * to MISS — the group runs instead of skipping on dead evidence. */
        if (out[i].hit && !trc_record_verifies(root, out[i].key, NULL)) {
            out[i].hit = false;
            out[i].hit_flaky = false;
            snprintf(out[i].reason, sizeof(out[i].reason),
                     "capsule hit unbacked (runs)");
        }
    }
}

/* Live-key revalidation: the slot key is a mint-time claim, so a consumed
 * HIT keeps its skip only while live bytes reproduce it. */
void testcache_capsule_revalidate(struct testcache *tc,
                                  const char *const *names,
                                  struct testcache_probe *probes, size_t n)
{
    size_t i;
    if (!names || !probes) return;
    for (i = 0; i < n; i++) {
        struct testcache_probe live;
        if (!probes[i].hit) continue;
        memset(&live, 0, sizeof(live));
        if (tc && names[i] && names[i][0])
            testcache_probe_group(tc, names[i], &live);
        if (live.key_valid && live.hit &&
            memcmp(live.key, probes[i].key, 32) == 0)
            continue;
        probes[i] = live;
        if (!probes[i].key_valid) {
            probes[i].code = TESTCACHE_R_NO_HANDLE;
            snprintf(probes[i].reason, sizeof(probes[i].reason),
                     "capsule hit unverified live (runs)");
        }
    }
}

/* One slot of a batch: the ordinary reusable identity, or the slot's
 * activated proof-contract variant — the same branch the per-group loop in
 * test_parallel.c takes, so the seam can serve that loop without changing
 * what any group means. */
static void trc_probe_slot(struct testcache *tc, const char *name,
                           enum zcl_test_proof_contract contract,
                           struct testcache_probe *out)
{
    if (contract == ZCL_TEST_PROOF_NONE)
        testcache_probe_group_internal(tc, name, ZCL_TEST_PROOF_NONE,
                                       false, out);
    else
        testcache_probe_group_internal(tc, name, contract, true, out);
}

bool testcache_probe_groups(struct testcache *tc,
                            const char *const *group_names,
                            const enum zcl_test_proof_contract *contracts,
                            size_t n_groups,
                            struct testcache_probe *out)
{
    if (!tc || (n_groups > 0 && (!group_names || !out))) {
        if (out) {
            for (size_t i = 0; i < n_groups; i++) {
                memset(&out[i], 0, sizeof(out[i]));
                out[i].code = TESTCACHE_R_NO_HANDLE;
                snprintf(out[i].reason, sizeof(out[i].reason),
                         "no cache handle");
            }
        }
        return false;
    }
    /* Sequentially, on the shared scratch + memo: each slot runs the exact
     * same internal probe a solo call would, so keys are byte-identical by
     * construction and one slot's truncation/non-resolution never reaches
     * another slot's result. The memo only ever maps a path to the bytes
     * read from it, so sharing it across slots changes no verdict. */
    for (size_t i = 0; i < n_groups; i++) {
        enum zcl_test_proof_contract contract = ZCL_TEST_PROOF_NONE;
        if (contracts) contract = contracts[i];
        trc_probe_slot(tc, group_names[i], contract, &out[i]);
    }
    return true;
}

static void trc_store_pass_ex(struct testcache *tc, const uint8_t key[32],
                              bool flaky)
{
    if (!tc || !key)
        return;
    struct trc_record r;
    memset(&r, 0, sizeof(r));
    memcpy(r.magic, TRC_MAGIC, 8);
    r.status = TRC_STATUS_PASS;
    if (flaky)
        r.rsvd[0] |= TRC_FLAKY_BIT;
    memcpy(r.key_echo, key, 32);
    /* Best-effort observability stamp; correctness never depends on it. */
    uint64_t gen = (uint64_t)platform_time_wall_time_t();
    for (int i = 0; i < 8; i++)
        r.generation_le[i] = (uint8_t)(gen >> (8 * i));
    /* A later store at the SAME key legitimately differs from an earlier one
     * (the flaky bit, the generation stamp) — this is not corruption, it is
     * the flaky-vs-ordinary PASS distinction being recorded. Plain
     * vcs_object_put_addressed is no-clobber (first writer wins), so it would
     * silently keep a stale flaky record forever. The _repair variant
     * replaces an existing object at this address when the bytes differ,
     * which is exactly the update semantics a verdict record needs. */
    if (!vcs_object_put_addressed_repair(tc->store_root, key,
                                        (const uint8_t *)&r, sizeof(r), NULL))
        ZCL_LOG_EMIT_AT(ZCL_LOG_WARN,
                        "[testcache] store_pass put_addressed failed\n");
}

void testcache_store_pass(struct testcache *tc, const uint8_t key[32])
{
    trc_store_pass_ex(tc, key, false);
}

void testcache_store_pass_flaky(struct testcache *tc, const uint8_t key[32])
{
    trc_store_pass_ex(tc, key, true);
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
