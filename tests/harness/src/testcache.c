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

#include <errno.h>
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

/* ── exec-signal memo (path -> verdict), open addressing, per-run ─────────
 * The exec rail below scans a closure file once per handle; the verdict is
 * memoized exactly like the content hash above. detail == NULL means scanned
 * clean; a non-NULL detail is a static string naming the matched signal. */
/* Per-group cap on bound exec artifacts, and the relpath cap for one. A
 * group whose scanned files name more distinct artifacts than the cap refuses
 * rather than under-binding. */
#define TRC_BIND_MAX 8
#define TRC_BIND_PATH 128

struct trc_sig_ent {
    char       *path;    /* NULL == empty slot */
    const char *detail;  /* refuse-class detail; NULL when clean/bindable */
    char      (*binds)[TRC_BIND_PATH]; /* heap, only when nbinds > 0 */
    int         nbinds;
};
struct trc_sigmemo {
    struct trc_sig_ent *slots;
    size_t cap;          /* power of two */
    size_t len;
};

struct testcache {
    struct codeindex *ci;
    char              root[4096];
    char              store_root[4096];
    struct trc_memo   memo;
    struct trc_sigmemo sigmemo;
    struct testcache_stats stats;
    char            (*closure)[256];   /* TRC_MAX_CLOSURE scratch rows */
    /* Include-graph liveness, from the graph itself, measured once at open. */
    size_t            dep_count;       /* depfiles the graph was built from */
    int64_t           dep_newest_ns;   /* newest depfile mtime */
    uint8_t           envkey[32];      /* SHA3 of the coverage-gating env */
    char              changed[TRC_CHANGED_MAX][TRC_PATH_MAX];
    size_t            changed_count;
    bool              snapshot_mode;
    bool              input_missing;   /* last hash miss: path is absent */
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

static bool trc_sigmemo_init(struct trc_sigmemo *m, size_t cap)
{
    m->slots = zcl_calloc(cap, sizeof(*m->slots), "trc_sigmemo");
    if (!m->slots)
        return false;
    m->cap = cap;
    m->len = 0;
    return true;
}

static void trc_sigmemo_free(struct trc_sigmemo *m)
{
    if (!m->slots)
        return;
    for (size_t i = 0; i < m->cap; i++) {
        free(m->slots[i].path);
        free(m->slots[i].binds);
    }
    free(m->slots);
    m->slots = NULL;
    m->cap = m->len = 0;
}

static bool trc_sigmemo_grow(struct trc_sigmemo *m)
{
    size_t ncap = m->cap * 2;
    struct trc_sig_ent *ns = zcl_calloc(ncap, sizeof(*ns), "trc_sigmemo_grow");
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

/* Both per-run memos; the content memo is torn down again when the signal
 * memo cannot be allocated. */
static bool trc_memos_init(struct testcache *tc)
{
    if (!trc_memo_init(&tc->memo, 4096))
        return false;
    if (!trc_sigmemo_init(&tc->sigmemo, 1024)) {
        trc_memo_free(&tc->memo);
        return false;
    }
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
        int saved = errno;
        ZCL_LOG_EMIT_AT(ZCL_LOG_WARN, "[testcache] open failed: %s\n", path);
        errno = saved;
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
 * failure (the caller then treats the whole group as UNCACHEABLE); an absent
 * path also raises tc->input_missing so the refusal can say so. */
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
    errno = 0;
    if (!trc_hash_file(tc->root, relpath, h, &mt, &nbytes)) {
        if (errno == ENOENT) tc->input_missing = true;
        return false;
    }
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
        "ZCL_DEV_OBSERVATION_STORE",
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
 * `name` may carry the test_/spec_ prefix.
 *
 * Completeness no longer rests on that grep: the exec rail below
 * (trc_closure_exec_signal) re-derives the exec-a-tree-artifact class from the
 * closure itself at probe time and refuses caching for any group that carries
 * it, listed or not — or, for a plain build/bin artifact literal, binds the
 * artifact's content hash into the key instead. The categories the rail
 * cannot see — fixture reads, a
 * live node DB, params presence, wall-clock assertions — still rest on this
 * list alone. */
static bool group_reads_external_inputs(const char *name)
{
    if (strncmp(name, "test_", 5) == 0 || strncmp(name, "spec_", 5) == 0)
        name += 5;
    static const char *const ext[] = {
        /* --- execs a built binary or a repo script (whole-link input) --- */
        "agent_copy_prove",
        /* fork/execs tools/lint/check_peer_floor_single_source.sh. */
        "anchor_peers",
        "chain_advance_atomicity",
        "chaos_harness",                  /* reads tests/fixtures block files */
        "cli_argv_strict",
        "cli_auth_robust",
        "cold_start_sync",
        "crypto_perf_selftest",
        /* dvo_run_checker spawns ./tools/lint/check_orient_facts.sh.
         * No exec-family call sits in the entry file, so the rail neither
         * refuses nor binds that script. */
        "dev_orient",
        "dev_platform",                   /* reads tests/harness/fixtures source */
        /* The request-size fixture delegates real CLI execution through a
         * variable filename; the per-group rail does not bind those bytes. */
        "rpc",
        /* Delegated host capture executes export_snapshot outside the
         * group's scanned closure; its executable bytes are not bound. */
        "export_snapshot",
        /* execv zclassic23-package-verify next to the test image.
         * That verifier's link is outside the group's forward C closure. */
        "fastobj_carrier",
        /* Spawns build/bin/fbsh through a macro-expanded helper the rail
         * does not scan — no literal in the scanned files. Verified: removed,
         * probed plain cacheable with no binding, restored. */
        "freebsd_sh",
        "importblockindex_cli_dispatch",
        "kill9_recovery",
        "make_lint_gates",                /* plants fixtures + compiles the tree */
        /* The whole make_lint_gates FAMILY, not just the base group. Matching
         * here is EXACT, so "make_lint_gates" alone covered exactly one of the
         * 14 registered names. Every sibling copies or scans the worktree and
         * runs repo SCRIPTS, none of which its forward C closure reaches:
         * heavy_01/heavy_02/heavy_03 exec fixture scripts under tools, realroot
         * git-greps the real tree, partition sandboxes it. Measured: breaking
         * tools/scripts/fresh-boot-weld-prove-selftest.sh left heavy_02's
         * 17-file key unchanged, so a stored PASS was served while a cold run
         * of the same tree FAILED. shard_01..08 are macro-generated, so the
         * code index cannot resolve them and they report empty-closure today —
         * listed anyway so de-macroing them cannot silently make them cacheable. */
        "make_lint_gates_heavy_01",
        "make_lint_gates_heavy_02",
        "make_lint_gates_heavy_03",
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
        /* mesh_terminal_worker_spawn execve's build/bin/fbsh from engine
         * code the rail does not scan — the group's entry file carries no
         * literal, so binding cannot see it. Verified: removed, probed plain
         * cacheable with no binding, restored. */
        "mesh_terminal_worker",
        /* agent_broker_spawn_confined execve's this process image from
         * cognition code the rail does not scan. The entry file carries
         * no exec-family call. Verified: probed plain cacheable with no
         * binding, so a stored PASS would skip that re-exec after the
         * image link changes. */
        "metaverse_agent_broker",
        "net",
        "no_hardcoded_home",              /* scans tree + env for home usage */
        "onion_bootstrap",
        "onion_bootstrap_slice",
        /* fork/execs tools/scripts/onion_pair_watch.sh and the node binary. */
        "onion_pair_watch_live",
        /* Runs build/bin/p2_invariant_check through zcl_spawn_* wrappers the
         * rail's exec tokens do not recognize, so this per-group key would
         * hash no checker bytes. The whole-test receipt still binds the
         * checker through its BUILD_NEED row; only this group key is denied. */
        "p2_invariant_check",
        /* The stdin adapter executes jsonq outside the entry-file scanner.
         * BUILD_NEED binds the whole proof, but no per-group artifact key. */
        "jsonq",
        /* Trusted host capture runs sqlq without a scanner-visible exec
         * call in the fixture. Refuse reuse until its bytes are bound. */
        "sqlq",
        "replay_canary_verdict",
        /* package_lifecycle_commit spawns zclassic23-package-verify-dev from
         * engine code the rail does not scan — the entry file's literals are
         * not the exec target. Verified: removed, probed plain cacheable with
         * no binding, restored. */
        "resident_launch_contract",
        "secrets_hygiene",
        "self_folded_anchor",
        /* Re-hashes the snapshot named by ZCL_SELF_FOLD_ANCHOR_FIXTURE.
         * The env value is in the key; the artifact bytes are not. */
        "self_folded_anchor_heavy",
        /* read tests/fixtures/semantic_consumer; the sibling execs the
         * sensor and cc. */
        "semantic_consumer",
        "semantic_consumer_live",
        /* read the tests/fixtures/semantic_facts manifests; the sibling
         * execs the libclang sensor build/bin/z23-clang-manifest. */
        "semantic_facts",
        "semantic_facts_live",
        /* compiles and senses generated projects with the sensor's clang */
        "semantic_facts_fuzz",
        /* reads tests/fixtures/semantic_manifest/<name>.bin; the sibling execs
         * build/bin/z23-clang-manifest (an optional libclang tool whose
         * link the test closure never reaches). */
        "semantic_manifest",
        "semantic_sensor",
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
        /* pkgl_run_worker spawns zclassic23-package-verify-dev from
         * commons lifecycle code the rail does not scan. The entry file
         * has no exec-family call, so the build/bin literal is not bound.
         * Verified: probed plain cacheable, so a stored PASS would skip
         * that worker after its link changes. */
        "zcode_add",
        /* The umbrella and shard_01 re-exec this test image
         * (--exact=test_zcode_package_dev). That image's link is
         * outside the group's forward C closure. */
        "zcode_package_dev",
        "zcode_package_dev_shard_01",
        /* Compiles and runs the commons journey seed sources with the host
         * compiler at run time; those fixture files are outside the closure. */
        "zcode_recipe",
        /* zv_run_verifier spawns build/bin/zclassic23-package-verify-dev.
         * That verifier's link is outside this group's forward C closure. */
        "zcode_verify",
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
        /* Reads sapling-spend.params and verifies under the pinned file's
         * key; the real proving leg runs only when the params exist. */
        "native_spend_proof",
        /* The real-file leg runs only when ~/.zcash-params is present, so a
         * stored PASS records whichever coverage the storing host had. */
        "params_fetch",
        /* Probes ~/.zcash-params for the verifying-key source when present. */
        "params_vk_embedded",
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
        /* Act 3 (shielded) gates on ~/.zcash-params presence. */
        "wallet_destruction_drill",
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

/* ── out-of-closure exec rail ─────────────────────────────────────────────
 *
 * The denylist above names the groups a reviewer has already classified.
 * This rail is the part that does not wait for a reviewer: when a group's
 * closure files EXEC a tree-built binary, a repo script, make, or the test
 * image itself, the verdict is decided by bytes the closure key does not
 * hash (a whole link, a script body, the Makefile). A stored PASS at such a
 * key is served unchanged after those bytes change — the failure mode the
 * denylist used to repair one group at a time (acme_worker, the
 * fleet_gateway shards, freebsd_sh, consensus_rule_sweep, fastobj_carrier,
 * cli_render and sem_replay were each found and listed by hand).
 *
 * So the probe classifies every scanned file. A REFUSE-class signal — a repo
 * script, make, a self re-exec, an own-image path lookup, or an artifact
 * literal that is parameterized or too numerous to bind — refuses caching,
 * whether or not the denylist knows the group yet. Over-refusal is
 * the safe direction: an unreviewed group simply always runs, and the
 * refusal names the file and the matched signal so the reviewer can
 * classify it. A flagged group a reviewer has proven sound — its execs run
 * host tools against fixture trees it authors, never a tree artifact —
 * carries an exact-name exception in trc_signal_exception() with the
 * reasoning, the same evidentiary standard as a denylist entry.
 *
 * The BINDABLE half: a plain build/bin artifact literal names a file whose
 * bytes fully determine the exec'd child's behavior (the toolchain and host
 * are already in the key through the toolkey, and the link is deterministic).
 * The artifact's content hash joins the group key (key domain v6): an edited
 * binary moves the key and an untouched one keeps the hit. An artifact that
 * is absent or unreadable at probe time refuses fail-closed — the group runs
 * fresh until the tree is built. Repo scripts do not bind: an interpreted
 * script's behavior is its bytes plus everything it invokes, which no single
 * content hash can cover.
 *
 * Precision, deliberately simple: per scanned FILE, after comment stripping,
 * an exec-family call site AND a tree-artifact literal in the same file flag
 * it. Artifact macros (CR_BIN, GW_TEST_BIN_DEFAULT, FBSH_BIN) keep the
 * literal in the same file as the exec, which is why the pairing is
 * per-file. An exec that only receives the artifact path as a parameter —
 * the node/library pattern — carries no literal and does not flag, and
 * exec'ing host tools (rm, git, sh) against fixture paths flags nothing
 * because no tree-artifact literal is present.
 *
 * Which files get scanned is the other half of precision; see
 * trc_rail_scans_file. The name-resolved closure carries passengers (a
 * same-named static in an unrelated file puts that file in the closure), so
 * only the group's own entry file and shared harness helpers are scanned —
 * never another group's entry file, never library or tool machinery whose
 * exec argument is written by its caller. */

/* Reviewed exceptions to the exec rail. The reason comment must name what
 * was reviewed; an entry whose reasoning stops being true is a stored-PASS
 * hole, exactly like a stale denylist entry. */
static bool trc_signal_exception(const char *name)
{
    if (strncmp(name, "test_", 5) == 0 || strncmp(name, "spec_", 5) == 0)
        name += 5;
    static const char *const ex[] = {
        /* system() runs rm/mkdir against the CI_FIX fixture tree the test
         * authors itself; the tools/...sh literal is a "generated-by"
         * provenance needle planted INTO a fixture file's content — never an
         * exec target. */
        "code_inventory",
        /* system()/popen() run git/rm/ls against fixture repositories the
         * test authors itself; the build/bin literals in this file are
         * fixture paths it WRITES and build-need needles it asserts on —
         * never exec targets. */
        "impact_composition",
    };
    for (size_t i = 0; i < sizeof(ex) / sizeof(ex[0]); i++)
        if (strcmp(name, ex[i]) == 0)
            return true;
    return false;
}

/* Identifier left boundary: the byte before p must not continue a name
 * (so "system(" never matches "mysystem("). */
static bool trc_left_boundary(const char *b, const char *p)
{
    if (p == b)
        return true;
    unsigned char c = (unsigned char)p[-1];
    return !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
             (c >= '0' && c <= '9') || c == '_');
}

/* Identifier-boundary token search: `tok` must not be the tail of a longer
 * identifier. */
static bool trc_has_token(const char *b, const char *tok, const char **hit)
{
    size_t tl = strlen(tok);
    const char *p = b;
    while ((p = strstr(p, tok)) != NULL) {
        if (trc_left_boundary(b, p)) {
            if (hit)
                *hit = p;
            return true;
        }
        p += tl;
    }
    return false;
}

/* Skip a string or char literal starting at the quote b[*i]. */
static void trc_skip_literal(const char *b, size_t n, size_t *i)
{
    char q = b[(*i)++];
    while (*i < n && b[*i] != q) {
        if (b[*i] == '\\' && *i + 1 < n)
            (*i)++;
        (*i)++;
    }
    if (*i < n)
        (*i)++;
}

/* Blank a // comment starting at b[*i]. */
static void trc_blank_line_comment(char *b, size_t n, size_t *i)
{
    while (*i < n && b[*i] != '\n')
        b[(*i)++] = ' ';
}

/* Blank a block comment starting at the slash b[*i]; newlines survive so
 * line numbers still line up with the unscanned source. */
static void trc_blank_block_comment(char *b, size_t n, size_t *i)
{
    size_t j = *i;
    b[j] = ' ';
    b[j + 1] = ' ';
    j += 2;
    while (j + 1 < n && !(b[j] == '*' && b[j + 1] == '/')) {
        if (b[j] != '\n')
            b[j] = ' ';
        j++;
    }
    if (j + 1 < n) {
        b[j] = ' ';
        b[j + 1] = ' ';
        j += 2;
    }
    *i = j;
}

/* Blank out // and block comments in place (newlines preserved), keeping
 * string and char literals byte-exact — the literals ARE the signals. */
static void trc_strip_comments(char *b, size_t n)
{
    size_t i = 0;
    while (i < n) {
        if (b[i] == '"' || b[i] == '\'')
            trc_skip_literal(b, n, &i);
        else if (b[i] == '/' && i + 1 < n && b[i + 1] == '/')
            trc_blank_line_comment(b, n, &i);
        else if (b[i] == '/' && i + 1 < n && b[i + 1] == '*')
            trc_blank_block_comment(b, n, &i);
        else
            i++;
    }
}

/* The exec-family call sites the rail recognizes. */
static const char *const TRC_EXEC_TOKENS[] = {
    "execve(",  "execvp(",      "execv(", "execlp(", "execl(",
    "fexecve(", "posix_spawnp(", "posix_spawn(", "popen(", "system(",
};

/* True when some exec-family call site is fed argv[0]: the process re-execs
 * the image it was started from, so the whole link is the real input. */
static bool trc_self_reexec(const char *b)
{
    for (size_t i = 0; i < sizeof(TRC_EXEC_TOKENS) / sizeof(TRC_EXEC_TOKENS[0]);
         i++) {
        const char *h = NULL;
        if (!trc_has_token(b, TRC_EXEC_TOKENS[i], &h))
            continue;
        const char *q = h + strlen(TRC_EXEC_TOKENS[i]);
        while (*q == ' ' || *q == '\t')
            q++;
        if (strncmp(q, "argv[0]", 7) == 0)
            return true;
    }
    return false;
}

/* True when any exec-family call site is present. */
static bool trc_has_exec_call(const char *b)
{
    for (size_t i = 0; i < sizeof(TRC_EXEC_TOKENS) / sizeof(TRC_EXEC_TOKENS[0]);
         i++)
        if (trc_has_token(b, TRC_EXEC_TOKENS[i], NULL))
            return true;
    return false;
}

/* The .sh word ending inside the literal starting at q (just after a
 * boundary-clean "tools/"). The suffix must terminate the word: closing
 * quote, space, escape, or NUL. */
static bool trc_literal_has_sh_suffix(const char *q)
{
    size_t span = 0;
    while (q[span] && q[span] != '"' && span < 256) {
        if (q[span] == '.' && q[span + 1] == 's' && q[span + 2] == 'h' &&
            (q[span + 3] == '"' || q[span + 3] == ' ' ||
             q[span + 3] == '\\' || q[span + 3] == '\0'))
            return true;
        span++;
    }
    return false;
}

/* A tools/...sh script literal; the quote may be escaped inside a wrapper
 * string ("bash -lc \"./tools/x.sh ...\""), so match the path itself and
 * require the .sh suffix inside the same literal. */
static bool trc_toolscript_literal(const char *b)
{
    for (const char *p = b; (p = strstr(p, "tools/")) != NULL; p += 6)
        if (trc_left_boundary(b, p) && trc_literal_has_sh_suffix(p + 6))
            return true;
    return false;
}

/* A byte that terminates the artifact token inside a literal: closing quote,
 * whitespace (arguments follow), escape, or NUL. */
static bool trc_bind_token_end(char c)
{
    return c == '"' || c == ' ' || c == '\t' || c == '\\' || c == '\0';
}

/* A character that makes an extracted artifact token unbindable: the literal
 * is a format string or a shell fragment, so no single file's bytes determine
 * what runs. */
static bool trc_bind_token_bad_char(char c)
{
    return c == '%' || c == '$' || c == '`' || c == ';' || c == '|' ||
           c == '&' || c == '<' || c == '>' || c == '*';
}

/* One scanned file's rail verdict: a refuse-class detail string, or the
 * extracted build/bin artifact literals to bind into the key. */
struct trc_filesig {
    const char *detail;
    char      (*binds)[TRC_BIND_PATH];
    int         nbinds;
    bool        overflow;
};

/* Record one extracted artifact relpath, deduplicated within the file. */
static void trc_bind_record(struct trc_filesig *fs, const char *relpath)
{
    for (int i = 0; i < fs->nbinds; i++)
        if (strcmp(fs->binds[i], relpath) == 0)
            return;
    if (fs->nbinds >= TRC_BIND_MAX) {
        fs->overflow = true;
        return;
    }
    snprintf(fs->binds[fs->nbinds], TRC_BIND_PATH, "%s", relpath);
    fs->nbinds++;
}

/* Extract the quoted build/bin artifact literal starting at the opening
 * quote q ("build/bin/..." or "./build/bin/..."). Returns false without
 * recording when the token is absent, malformed, or parameterized — the
 * caller then refuses. */
static bool trc_bind_extract_one(const char *q, struct trc_filesig *fs)
{
    const char *p = q + 1;
    if (p[0] == '.' && p[1] == '/')
        p += 2;
    if (strncmp(p, "build/bin/", 10) != 0)
        return true; /* not an artifact literal at all: keep scanning */
    const char *t = p + 10;
    size_t len = 0;
    while (!trc_bind_token_end(t[len]) && len < TRC_BIND_PATH - 11) {
        if (trc_bind_token_bad_char(t[len]))
            return false;
        len++;
    }
    if (len == 0 || !trc_bind_token_end(t[len]))
        return false;
    char rel[TRC_BIND_PATH];
    memcpy(rel, "build/bin/", 10);
    memcpy(rel + 10, t, len);
    rel[10 + len] = '\0';
    trc_bind_record(fs, rel);
    return true;
}

/* Extract every quoted build/bin artifact literal in the buffer. Any
 * malformed or parameterized literal refuses the file (fail closed). */
static void trc_bind_extract_all(const char *b, struct trc_filesig *fs)
{
    for (const char *p = b; *p && !fs->overflow && !fs->detail; p++) {
        if (*p != '"' && *p != '\'')
            continue;
        if (!trc_bind_extract_one(p, fs))
            fs->detail = "exec with a parameterized build/bin literal";
    }
    if (fs->overflow)
        fs->detail = "too many exec artifact literals to bind";
}

/* Classify one comment-stripped source buffer for the exec rail: refuse-class
 * signals set fs->detail; the bindable class fills fs->binds. An exec-family
 * call must be present for any literal to count (the pairing discipline), and
 * every refuse class dominates the bindable one. */
static void trc_classify_file(const char *b, struct trc_filesig *fs)
{
    fs->detail = NULL;
    fs->nbinds = 0;
    fs->overflow = false;
    if (trc_self_reexec(b)) {
        fs->detail = "self re-exec of the test image (exec argv[0])";
        return;
    }
    if (!trc_has_exec_call(b))
        return;
    if (trc_toolscript_literal(b)) {
        fs->detail = "exec with a tools/*.sh script literal";
        return;
    }
    /* make reads the Makefile: an out-of-closure tree input. */
    if (strstr(b, "\"make ") || strstr(b, "\"make\t") ||
        strstr(b, "\"make\"")) {
        fs->detail = "exec of make (verdict reads the Makefile)";
        return;
    }
    /* popen/system of a command built from the test image's own path. */
    if (trc_has_token(b, "os_proc_exe_path(", NULL)) {
        fs->detail = "exec paired with an own-image path lookup";
        return;
    }
    trc_bind_extract_all(b, fs);
}

#define TRC_SIG_READ_CAP (4u * 1024u * 1024u)

/* Memoized signal scan of one closure file, copied into out. A clean file
 * yields a NULL detail and no binds. A file that cannot be OPENED yields the
 * same: identity computation reads every closure input right behind this scan
 * and already refuses fail-closed on any read failure, so the rail leaves
 * that diagnosis to it. A present file too large to scan whole is different —
 * the key would mint while the rail saw only a prefix — so that file flags on
 * its own detail. */
static void trc_sig_scan_file(struct testcache *tc, const char *relpath,
                              struct trc_filesig *out)
{
    struct trc_sigmemo *m = &tc->sigmemo;
    out->detail = NULL;
    out->binds = NULL;
    out->nbinds = 0;
    out->overflow = false;
    if (m->len * 10 >= m->cap * 7 && !trc_sigmemo_grow(m)) {
        out->detail = "signal memo exhaustion";
        return;
    }
    size_t j = (size_t)trc_hash_str(relpath) & (m->cap - 1);
    while (m->slots[j].path) {
        if (strcmp(m->slots[j].path, relpath) == 0) {
            out->detail = m->slots[j].detail;
            out->binds = m->slots[j].binds;
            out->nbinds = m->slots[j].nbinds;
            return;
        }
        j = (j + 1) & (m->cap - 1);
    }

    char stack_binds[TRC_BIND_MAX][TRC_BIND_PATH];
    struct trc_filesig fs = { NULL, stack_binds, 0, false };
    char full[4096];
    int n = snprintf(full, sizeof(full), "%s/%s", tc->root, relpath);
    if (n > 0 && (size_t)n < sizeof(full)) {
        FILE *f = fopen(full, "rb");
        if (f) {
            char *buf = zcl_malloc(TRC_SIG_READ_CAP + 2, "trc_sig_read");
            if (!buf) {
                fs.detail = "signal scan allocation failed";
            } else {
                size_t got = fread(buf, 1, TRC_SIG_READ_CAP + 1, f);
                if (ferror(f)) {
                    fs.detail = NULL; /* unreadable: the key path refuses it */
                } else if (got > TRC_SIG_READ_CAP) {
                    fs.detail = "closure input exceeds the exec rail's scan cap";
                } else {
                    buf[got] = '\0';
                    trc_strip_comments(buf, got);
                    trc_classify_file(buf, &fs);
                }
                free(buf);
            }
            fclose(f);
        }
    }

    char *dup = zcl_strdup(relpath, "trc_sigmemo_key");
    if (!dup) {
        out->detail = "signal memo key allocation failed";
        return;
    }
    char (*binds)[TRC_BIND_PATH] = NULL;
    if (fs.nbinds > 0) {
        binds = zcl_malloc(sizeof(stack_binds), "trc_sigmemo_binds");
        if (!binds) {
            free(dup);
            out->detail = "signal memo binds allocation failed";
            return;
        }
        memcpy(binds, stack_binds, sizeof(stack_binds));
    }
    m->slots[j].path = dup;
    m->slots[j].detail = fs.detail;
    m->slots[j].binds = binds;
    m->slots[j].nbinds = fs.nbinds;
    m->len++;
    out->detail = fs.detail;
    out->binds = binds;
    out->nbinds = fs.nbinds;
}

/* Which closure files the rail scans. The forward closure is NAME-resolved:
 * same-named statics in different translation units collide in the index, so
 * a closure routinely carries files the group never executes (a bench tool
 * defining a static run_cmd lands in hundreds of closures). Scanning every
 * closure file would refuse those hundreds of groups over bytes they never
 * run. The signal that matters is authored by the group's own test: the entry
 * file (the root symbol's def_path — unique per registered group) plus shared
 * harness helpers the group genuinely links. Another group's entry file in
 * the closure is a name-collision passenger and is skipped; platform, tools
 * and engine files provide parameterized exec machinery whose artifact
 * argument is written by the caller, and the caller is a scanned file. An
 * exec delegated entirely to a tools/ helper (the sem_replay build pattern)
 * is invisible here and remains denylist territory. */
static bool trc_rail_scans_file(const char *path, const char *entry)
{
    if (entry[0] && strcmp(path, entry) == 0)
        return true;
    if (strncmp(path, "tests/harness/", 14) != 0)
        return false;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    if (strncmp(base, "test_", 5) == 0 || strncmp(base, "spec_", 5) == 0)
        return false;  /* another group's entry file, here by name collision */
    return true;
}

/* A group's collected rail outcome: the distinct build/bin artifacts to bind
 * into the key (bind.n == 0 when none were found), plus the first scanned
 * file that produced one, for diagnostics. */
struct trc_bind {
    char   paths[TRC_BIND_MAX][TRC_BIND_PATH];
    int    n;
    char   src[256]; /* first scanned file a binding was extracted from */
};

/* Walk the files the rail trusts. A refuse-class signal in any scanned file
 * populates out_path/out_detail and returns true. Otherwise the extracted
 * build/bin artifact literals accumulate into bind (deduplicated, capped —
 * overflow refuses via the caller). */
static bool trc_closure_exec_signal(struct testcache *tc,
                                    const char *group_name, int nc,
                                    struct trc_bind *bind,
                                    const char **out_path,
                                    const char **out_detail)
{
    char entry[256] = "";
    struct ci_symbol sym;
    bool found = false;
    if (codeindex_symbol(tc->ci, group_name, &sym, &found) && found)
        snprintf(entry, sizeof(entry), "%s", sym.def_path);
    for (int i = 0; i < nc; i++) {
        if (!trc_rail_scans_file(tc->closure[i], entry))
            continue;
        struct trc_filesig fs;
        trc_sig_scan_file(tc, tc->closure[i], &fs);
        if (fs.detail) {
            *out_path = tc->closure[i];
            *out_detail = fs.detail;
            return true;
        }
        for (int k = 0; k < fs.nbinds; k++) {
            bool seen = false;
            for (int e = 0; e < bind->n; e++)
                if (strcmp(bind->paths[e], fs.binds[k]) == 0)
                    seen = true;
            if (seen)
                continue;
            if (bind->n >= TRC_BIND_MAX) {
                *out_path = tc->closure[i];
                *out_detail = "too many exec artifacts to bind";
                return true;
            }
            snprintf(bind->paths[bind->n], TRC_BIND_PATH, "%s", fs.binds[k]);
            if (bind->n == 0)
                snprintf(bind->src, sizeof(bind->src), "%s", tc->closure[i]);
            bind->n++;
        }
    }
    return false;
}

/* The rail gate at probe time. A refuse-class exec signal (repo script, make,
 * self re-exec, own-path lookup, parameterized or overflowing artifact
 * literal) refuses caching unless a reviewed exception covers the group. A
 * build/bin artifact literal alone is BINDABLE: the artifact's bytes fully
 * determine the exec'd child's behavior, so the caller mixes their hashes
 * into the key instead of refusing. */
static bool trc_rail_refuses(struct testcache *tc, const char *group_name,
                             int nc, struct trc_bind *bind,
                             struct testcache_probe *out)
{
    const char *sig_path = NULL, *sig_detail = NULL;
    bool signaled = trc_closure_exec_signal(tc, group_name, nc, bind,
                                            &sig_path, &sig_detail);
    if (trc_signal_exception(group_name)) {
        /* Reviewed: the group's literals are fixture paths or needles, never
         * exec targets — no refusal AND no binding (the planted paths may
         * not exist at probe time; a miss must not refuse this group). */
        bind->n = 0;
        return false;
    }
    if (!signaled)
        return false;
    out->code = TESTCACHE_R_EXTERNAL_INPUT;
    snprintf(out->reason, sizeof(out->reason),
             "closure exec signal in %s: %s", sig_path, sig_detail);
    return true;
}

/* Hash every bound artifact's content (fail closed: an absent or unreadable
 * artifact refuses caching, reported through the original signal's file). */
static bool trc_hash_binds(struct testcache *tc, const struct trc_bind *bind,
                           uint8_t (*hashes)[32], struct testcache_probe *out)
{
    for (int i = 0; i < bind->n; i++) {
        int64_t mt = 0;
        if (!trc_file_hash(tc, bind->paths[i], hashes[i], &mt)) {
            out->code = TESTCACHE_R_EXTERNAL_INPUT;
            snprintf(out->reason, sizeof(out->reason),
                     "closure exec signal in %s: exec artifact %s is absent "
                     "or unreadable",
                     bind->src, bind->paths[i]);
            return false;
        }
    }
    return true;
}

/* The cacheable verdict line names the binding when one happened. */
static void trc_probe_reason_ok(struct testcache_probe *out, int nc,
                                int nbind)
{
    if (nbind > 0)
        snprintf(out->reason, sizeof(out->reason),
                 "%d input files, %d exec artifacts bound", nc, nbind);
    else
        snprintf(out->reason, sizeof(out->reason), "%d input files", nc);
}

/* Run the exec rail and hash any bound artifacts. Returns true when the
 * probe refuses (out populated with the refusal). */
static bool trc_rail_gate(struct testcache *tc, const char *group_name,
                          int nc, struct trc_bind *bind,
                          uint8_t (*bind_hashes)[32],
                          struct testcache_probe *out)
{
    if (trc_rail_refuses(tc, group_name, nc, bind, out))
        return true;
    return !trc_hash_binds(tc, bind, bind_hashes, out);
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
                            int n_closure, const struct trc_bind *bind,
                            const uint8_t (*bind_hashes)[32],
                            uint8_t out_key[32], bool *stale,
                            bool *graph_incomplete)
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);

    /* v6 mixes the content hashes of exec'd build/bin artifacts the rail
     * bound at probe time. v5 adds the common harness source and generated
     * include closure. v4
     * records lacked this input and cannot safely be reused. v4 had already
     * retired v3 PASS records minted while activated proof contracts still
     * shared this ordinary keyspace. Active proofs now bypass lookup/storage;
     * retiring v3 also prevents one of those old records becoming reachable
     * if its contract row is later removed. v3 first rejected skipped PASSes,
     * and v2 added the coverage-gating environment over v1. */
    static const char DOMAIN[] = "zcl.testcache.key.v6";
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

    /* Bound exec artifacts: path + content hash each. The bytes of an exec'd
     * binary fully determine the child's behavior (the toolchain and host are
     * bound by the toolkey above), so an edited artifact moves the key and an
     * untouched one keeps it. */
    trc_put_u32le(le, (uint32_t)bind->n);
    sha3_256_write(&ctx, le, 4);
    for (int i = 0; i < bind->n; i++) {
        sha3_256_write(&ctx, (const unsigned char *)bind->paths[i],
                       strlen(bind->paths[i]) + 1);
        sha3_256_write(&ctx, bind_hashes[i], 32);
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

    if (!trc_memos_init(tc)) {
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
        trc_sigmemo_free(&tc->sigmemo);
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
    trc_sigmemo_free(&tc->sigmemo);
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

/* Is there a stored PASS at this exact key? Probe existence first (a quiet
 * access() — a MISS is the common, non-error case) inside the verifying load,
 * so a cold cache never spams the log with "object not found". */
static void trc_lookup_verdict(struct testcache *tc,
                               struct testcache_probe *out)
{
    tc->stats.verdict_lookups++;
    bool flaky = false;
    if (trc_record_verifies(tc->store_root, out->key, &flaky)) {
        out->hit = true;
        out->hit_flaky = flaky;
        tc->stats.verdict_hits++;
    }
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

/* Why no key could be formed. The include graph keeps every prerequisite the
 * compiler listed, including one this checkout no longer holds; that input
 * has no bytes to hash, so the graph describes an older tree. Say so, rather
 * than calling it unreadable, and never mint a key without it. */
static void trc_key_refusal(const struct testcache *tc, bool harness_incomplete,
                            struct testcache_probe *out)
{
    const char *reason = "input file unreadable";
    out->code = TESTCACHE_R_FILE_UNREADABLE;
    if (harness_incomplete) {
        out->code = TESTCACHE_R_HARNESS_GRAPH;
        reason = "harness depfile graph incomplete";
    } else if (tc->input_missing) {
        out->code = TESTCACHE_R_INPUT_MISSING;
        reason = "include graph names an input the checkout no longer "
                 "contains (rebuild to refresh)";
    }
    snprintf(out->reason, sizeof(out->reason), "%s", reason);
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

    /* The exec rail: a cacheable closure that execs a repo script, make, or
     * the test image itself decides its verdict from bytes the key never
     * hashes. Refuse before any hashing or store lookup, so an unreviewed
     * exec can neither mint nor serve a verdict. A build/bin artifact literal
     * binds instead: the artifact's bytes join the key below. */
    struct trc_bind bind = { .n = 0 };
    uint8_t bind_hashes[TRC_BIND_MAX][32];
    if (trc_rail_gate(tc, group_name, nc, &bind, bind_hashes, out))
        return;

    bool stale = false, harness_graph_incomplete = false;
    tc->input_missing = false;
    if (!trc_compute_key(tc, group_name, nc, &bind, bind_hashes, out->key,
                         &stale, &harness_graph_incomplete)) {
        trc_key_refusal(tc, harness_graph_incomplete, out);
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
    trc_probe_reason_ok(out, nc, bind.n);

    trc_lookup_verdict(tc, out);
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

/* ── action-input accessor (see testcache.h for the exact/approx/missing
 * accounting) ──────────────────────────────────────────────────────────
 *
 * Every helper below is READ-ONLY with respect to cache behavior: none of
 * them writes tc->stats, looks up or stores a verdict, or changes what
 * trc_compute_key folds into a real key. They reuse tc->closure and
 * trc_file_hash exactly as testcache_probe_group_internal does (same memo,
 * same bytes), then derive additional, differently-domain-tagged digests
 * purely for the action preimage. */

/* First 512 bytes of <root>/<relpath>, NUL-terminated, for a cheap
 * generated-file marker scan. This is a SEPARATE small read from
 * trc_file_hash's streaming hash (which never buffers content) — the
 * extra I/O is one short read per closure file, not a second full hash. */
static bool trc_path_looks_generated(const char *root, const char *relpath)
{
    char path[4200];
    int n = snprintf(path, sizeof(path), "%s/%s", root, relpath);
    if (n < 0 || (size_t)n >= sizeof(path))
        return false;
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return false;
    char buf[513];
    size_t got = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[got] = '\0';
    static const char *const markers[] = {
        "DO NOT EDIT", "@generated", "AUTOGENERATED", "auto-generated",
        "GENERATED FILE", "generated by",
    };
    for (size_t i = 0; i < sizeof(markers) / sizeof(markers[0]); i++)
        if (strstr(buf, markers[i]))
            return true;
    return false;
}

/* Path-shape fixture heuristic: a known fixtures directory, or a basename
 * that names itself a fixture. See testcache.h for what this misses (a
 * group that reads a fixtures directory by SCANNING it at run time, never
 * through its call-graph closure, is invisible to this — that is exactly
 * why such groups are on the external-input denylist today). */
static bool trc_path_looks_fixture(const char *relpath)
{
    if (strstr(relpath, "tests/fixtures/") || strstr(relpath, "/fixtures/"))
        return true;
    const char *base = strrchr(relpath, '/');
    base = base ? base + 1 : relpath;
    return strstr(base, "fixture") != NULL;
}

/* Standalone digest over the same two shared-harness units (and their
 * compiler-derived include closure) trc_hash_harness folds into the real
 * key — domain-tagged differently so this can never be mistaken for, or
 * collide with, a real testcache key. */
static bool trc_action_harness_root(struct testcache *tc, uint8_t out[32],
                                    bool *stale)
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    static const char DOMAIN[] = "zcl.testcache.action.harness-root.v1";
    sha3_256_write(&ctx, (const unsigned char *)DOMAIN, sizeof(DOMAIN));
    bool graph_incomplete = false;
    if (!trc_hash_harness(tc, &ctx, stale, &graph_incomplete))
        return false;
    sha3_256_finalize(&ctx, out);
    return true;
}

/* SHA3 over the sorted (already sorted: closure[] preserves codeindex's own
 * path order) fixture-shaped subset of the closure. Zero root + count==0 is
 * the ordinary case for most groups (they reach no fixture-shaped path). */
static void trc_action_fixtures_root(struct testcache_action_inputs *out)
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    static const char DOMAIN[] = "zcl.testcache.action.fixtures-root.v1";
    sha3_256_write(&ctx, (const unsigned char *)DOMAIN, sizeof(DOMAIN));
    int count = 0;
    for (int i = 0; i < out->n_closure; i++) {
        if (!out->closure[i].fixture)
            continue;
        const char *p = out->closure[i].path;
        sha3_256_write(&ctx, (const unsigned char *)p, strlen(p) + 1);
        sha3_256_write(&ctx, out->closure[i].sha3, 32);
        count++;
    }
    sha3_256_finalize(&ctx, out->fixtures_root);
    out->n_fixture_paths = count;
}

/* SHA3 over the ordinary (non-activated) proof-contract identity: the
 * contract enum this accessor always assumes (ZCL_TEST_PROOF_NONE, matching
 * testcache_group_action_inputs's no-contract-parameter signature) plus the
 * denylist verdict, which is the other half of "what policy governs this
 * group" that trc_wrap_proof_key/group_reads_external_inputs already carry. */
static void trc_action_policy_root(bool denylisted, uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    static const char DOMAIN[] = "zcl.testcache.action.policy-root.v1";
    sha3_256_write(&ctx, (const unsigned char *)DOMAIN, sizeof(DOMAIN));
    unsigned char le[4];
    trc_put_u32le(le, (uint32_t)ZCL_TEST_PROOF_NONE);
    sha3_256_write(&ctx, le, sizeof(le));
    unsigned char deny = denylisted ? 1 : 0;
    sha3_256_write(&ctx, &deny, 1);
    sha3_256_finalize(&ctx, out);
}

/* Ordered allowlisted env NAME=VALUE pairs, identical selection + sort order
 * to trc_env_digest's own preimage. */
static void trc_action_collect_env(struct testcache_action_inputs *out)
{
    size_t n = 0;
    for (char **e = environ; e && *e; e++)
        if (trc_env_is_relevant(*e))
            n++;
    out->n_env = 0;
    out->env_truncated = false;
    if (n == 0)
        return;
    const char **items = zcl_malloc(n * sizeof(*items), "trc_action_env");
    if (!items)
        return; /* fail-safe: report no env pairs rather than a wrong set */
    size_t k = 0;
    for (char **e = environ; e && *e && k < n; e++)
        if (trc_env_is_relevant(*e))
            items[k++] = *e;
    qsort(items, k, sizeof(*items), trc_str_cmp);
    size_t cap = k < TESTCACHE_ACTION_MAX_ENV ? k : TESTCACHE_ACTION_MAX_ENV;
    for (size_t i = 0; i < cap; i++)
        snprintf(out->env[i].text, sizeof(out->env[i].text), "%s", items[i]);
    out->n_env = (int)cap;
    out->env_truncated = (cap < k);
    free((void *)items);
}

/* Fill out->closure[0..nc) from tc->closure (already sorted by
 * codeindex_forward_closure). Split out of testcache_group_action_inputs
 * purely to keep that function's own decision count under the complexity
 * cap; behavior is identical to having this inline. Returns false (fail-
 * safe) on the first unreadable/overlong path. */
static bool trc_action_fill_closure(struct testcache *tc, int nc,
                                    struct testcache_action_inputs *out)
{
    for (int i = 0; i < nc; i++) {
        const char *p = tc->closure[i];
        struct testcache_action_closure_entry *e = &out->closure[i];
        int w = snprintf(e->path, sizeof(e->path), "%s", p);
        if (w < 0 || (size_t)w >= sizeof(e->path))
            return false;
        int64_t mt = 0;
        if (!trc_file_hash(tc, p, e->sha3, &mt))
            return false; /* unreadable input: cannot report sound inputs */
        e->generated = trc_path_looks_generated(tc->root, p);
        e->fixture = trc_path_looks_fixture(p);
    }
    out->n_closure = nc;
    return true;
}

bool testcache_group_action_inputs(struct testcache *tc,
                                   const char *group_name,
                                   struct testcache_action_inputs *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!tc || !tc->ci || !group_name || !group_name[0])
        return false;

    out->denylisted = group_reads_external_inputs(group_name);

    /* No depfiles means the include closure is unknown — the same fail-
     * closed condition testcache_probe_group_internal enforces. */
    if (tc->dep_count == 0)
        return false;

    bool truncated = false, root_found = false;
    int nc = codeindex_forward_closure(tc->ci, group_name, tc->closure,
                                       TRC_MAX_CLOSURE, &truncated,
                                       &root_found);
    tc->stats.closure_queries++;
    if (nc < 0 || !root_found || truncated || nc == 0)
        return false;
    if (nc > TESTCACHE_ACTION_MAX_CLOSURE)
        return false; /* cannot happen: caps are equal, guarded defensively */

    if (!trc_action_fill_closure(tc, nc, out))
        return false;

    trc_action_collect_env(out);
    snprintf(out->toolkey, sizeof(out->toolkey), "%s", ZCL_TESTCACHE_TOOLKEY);
    out->harness_root_valid =
        trc_action_harness_root(tc, out->harness_root, &out->harness_root_stale);
    trc_action_fixtures_root(out);
    trc_action_policy_root(out->denylisted, out->policy_root);

    return true;
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

/* ── load-flaky first-attempt excerpt (see testcache.h) ─────────────────── */

static bool tc_excerpt_is_mark(const char *text)
{
    return strstr(text, "FAIL") || strstr(text, "assert") ||
           strstr(text, "Assertion");
}

/* Reads the next logical line of fp into buf (its first chunk only; any
 * over-long remainder is consumed and dropped) with the newline stripped.
 * False at end of file. */
static bool tc_excerpt_next_line(FILE *fp, char *buf, size_t cap)
{
    if (!fgets(buf, (int)cap, fp)) return false;
    size_t len = strlen(buf);
    bool complete = len > 0 && buf[len - 1] == '\n';
    if (complete) buf[--len] = '\0';
    char spill[512];
    while (!complete && fgets(spill, sizeof(spill), fp)) {
        size_t sl = strlen(spill);
        complete = sl > 0 && spill[sl - 1] == '\n';
    }
    return true;
}

static void tc_excerpt_print(FILE *out, const char *prefix, size_t lineno,
                             const char *text)
{
    fprintf(out, "%sL%zu: %.*s%s\n", prefix, lineno,
            (int)TESTCACHE_EXCERPT_LINE_MAX, text,
            strlen(text) > TESTCACHE_EXCERPT_LINE_MAX ? " [truncated]" : "");
}

size_t testcache_print_log_excerpt(FILE *out, const char *path,
                                   const char *prefix, size_t max_marks,
                                   size_t max_tail)
{
    if (!out || !path || !path[0]) return 0;
    if (!prefix) prefix = "";
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    char line[4096];
    size_t total = 0;
    while (tc_excerpt_next_line(fp, line, sizeof(line))) total++;
    size_t tail_start = total > max_tail ? total - max_tail + 1 : 1;
    rewind(fp);
    size_t printed = 0, marks = 0;
    for (size_t n = 1; tc_excerpt_next_line(fp, line, sizeof(line)); n++) {
        bool in_tail = n >= tail_start;
        if (!in_tail && (marks >= max_marks || !tc_excerpt_is_mark(line)))
            continue;
        if (!in_tail) marks++;
        tc_excerpt_print(out, prefix, n, line);
        printed++;
    }
    fclose(fp);
    return printed;
}
