/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fork-parallel driver for the z23 test suite.
 *
 * The sequential runner (`build/bin/test_zcl`, `main()` in test.c) executes
 * every group back-to-back on a single CPU. On a 32-core box that uses a few
 * percent of available compute and the suite takes many minutes. (The group
 * count is deliberately not pinned here — it moves every few commits and the
 * old hand-written "~170" was off by a factor of four before anyone noticed.
 * The runner prints the live count on every start.)
 *
 * This binary runs the same groups concurrently. Every group gets its
 * own child process via fork(), with output captured to a per-child
 * temp file. The parent waits for all children and then replays their
 * output in group order so a human sees a deterministic transcript.
 *
 * The in-process call pattern of the sequential runner — one
 * ecc_start() for everything — doesn't translate directly to a
 * parallel runner. Each child does its own `chain_params_select` +
 * `ecc_start` + `ecc_verify_init` before running its group, then
 * `ecc_verify_destroy` + `ecc_stop` before exit. The extra setup cost
 * is paid once per group and is dwarfed by the per-group test time.
 *
 * Maintenance note: the registry below is CANONICAL — `make test-parallel`
 * is the doctrine runner and the acceptance gate, and build/bin/test_zcl
 * (test.c, the legacy sequential shape) is never run. So a test dispatched
 * by test.c but absent here does not merely "skip the parallel runner": it
 * executes in NO gate at all and proves nothing.
 *
 * That drift is no longer unpoliced. tools/scripts/check_test_registration.sh
 * has two prongs: (A) every filename-matching entry point is dispatched by at
 * least one runner, and (B) every name dispatched by test.c is either in
 * the canonical catalog or is a sub-test of a file whose own group IS
 * registered. Prong B is HARD and has no baseline. When it first ran
 * (2026-07-25) it found 5 such names; one of them, test_lcc_write_rules, was
 * not just dead but WRONG — it failed the moment it was finally executed. */

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#if defined(__linux__)
/* wait4() reports the reaped child's peak RSS; glibc hides it behind
 * _DEFAULT_SOURCE once _POSIX_C_SOURCE pins the feature set. */
#define _DEFAULT_SOURCE 1
#endif

#include "platform/time_compat.h"
#include "platform/directory_compat.h"
#include "platform/logical_cpu.h"
#include "platform/private_directory.h"
#include "platform/rng.h"
#include "command/native_dev_hotswap.h"
#include "config/command_catalog.h"
#include "hotswap/hotswap.h"
#include "hotswap/hotswap_module.h"
#include "kernel/command_registry.h"
#include "session/agent_broker.h"
#include "devloop_reflex_runner.h"
#include "test/runner_admission.h"
#include "test/selection_build_needs.h"
#include "test/test_group_selector.h"
#include "test/test_home_isolation.h"
#include "test_group_catalog.h"
#include "test_group_weights.h"
#include "test/test_helpers.h"
#include "test/testcache.h"
#include "dev_proof_observation.h"
#include "base/hex.h"
#include "event/event.h"
#include "util/signal_handler.h"
#include "util/clientversion.h"
#include "util/log_json.h"
#include "test/test_verdict_json.h"

#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/wait.h>
#include <sys/resource.h>
#endif
#include <time.h>
#include <unistd.h>
/* gcc defines __SANITIZE_ADDRESS__; clang reports ASan only through
 * __has_feature(address_sanitizer). */
#if defined(__SANITIZE_ADDRESS__)
#define TP_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define TP_ASAN 1
#endif
#endif
#if defined(TP_ASAN)
#include <sanitizer/lsan_interface.h>
/* Z23 keeps the block index for the life of the process: block_map_free
 * skips freeing it ("block_index lives for process lifetime") because
 * lock-free readers still dereference pprev and phashBlock. A test that
 * builds and drops a chainstate therefore leaves these allocations reachable
 * only through that never-freed index. Each entry names an allocator whose
 * objects hang off the block index. LeakSanitizer reads this default list
 * only in the ASan test binary. */
__attribute__((used))
const char *__lsan_default_suppressions(void)
{
    return "leak:chainstate_insert_block_index\n"
           "leak:add_to_block_index\n"
           "leak:block_index_hdrext_get_or_alloc\n"
           "leak:block_index_set_solution\n"
           "leak:load_block_index_flat\n";
}
#endif
#if defined(__linux__)
#include <sys/vfs.h>
#include <linux/magic.h>

static char g_tmpfs_root[PATH_MAX];
static pid_t g_tmpfs_owner;
static bool g_tmpfs_green;
static bool g_tmpfs_retained;
static bool g_tmpfs_started;   /* a group ran: the root may hold evidence */

static void tmpfs_finish(int exit_code, int load_flaky_groups)
{
    g_tmpfs_green = exit_code == 0 && load_flaky_groups == 0;
}

static void tmpfs_note_group_started(void)
{
    g_tmpfs_started = true;
}

static void tmpfs_cleanup(void)
{
    if (g_tmpfs_owner != getpid() || !g_tmpfs_root[0]) return;
    /* An exit before any group ran (usage, listing, empty selection) holds no
     * evidence: remove the root whatever the exit code. */
    if (g_tmpfs_started && (!g_tmpfs_green || g_tmpfs_retained)) {
        fprintf(stderr, "test_parallel: retained tmpfs root=%s\n", g_tmpfs_root);
        return;
    }
    if (test_rm_rf_recursive(g_tmpfs_root) != 0)
        fprintf(stderr, "test_parallel: tmpfs cleanup failed: %s\n", strerror(errno));
}
/* The parent directory is named "z23-scratch" on purpose: leaves such as
 * zcode.workspace.source.bundle.fetch accept an output path only when a
 * segment of it (and of its canonical form) is "tmp", "test-tmp" or contains
 * "scratch" (zcl_native_zcode_workspace_is_explicit_scratch). A bare "z23t"
 * made every fixture under the tmpfs root fail that check. */
static bool tmpfs_create_root(void)
{
    struct statfs fs;
    if (statfs("/dev/shm", &fs) != 0 ||
        (unsigned long)fs.f_type != (unsigned long)TMPFS_MAGIC) return false;
    if (mkdir("/dev/shm/z23-scratch", 0700) != 0 && errno != EEXIST) return false;
    if (!test_tmpfs_parent_safe("/dev/shm/z23-scratch")) return false;
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) return false;
    uint32_t hash = 2166136261u;
    for (const unsigned char *p = (const unsigned char *)cwd; *p; ++p)
        hash = (hash ^ *p) * 16777619u;
    int n = snprintf(g_tmpfs_root, sizeof(g_tmpfs_root),
                     "/dev/shm/z23-scratch/%08x.XXXXXX", hash);
    if (n < 0 || (size_t)n >= sizeof(g_tmpfs_root) || !mkdtemp(g_tmpfs_root)) {
        g_tmpfs_root[0] = '\0';
        return false;
    }
    g_tmpfs_owner = getpid();
    return true;
}

static void tmpfs_setup(void)
{
    const char *enabled = getenv("ZCL_TEST_TMPFS");
    const char *existing = getenv("ZCL_TEST_TMPROOT");
    if (existing && *existing) return;
    if (!enabled) return;
    if (!strcmp(enabled, "0") || !tmpfs_create_root()) goto fallback;
    if (setenv("ZCL_TEST_TMPROOT", g_tmpfs_root, 1) != 0 ||
        setenv("ZCL_TEST_TMPFS_ACTIVE", g_tmpfs_root, 1) != 0 ||
        atexit(tmpfs_cleanup) != 0) {
        (void)unsetenv("ZCL_TEST_TMPROOT");
        (void)unsetenv("ZCL_TEST_TMPFS_ACTIVE");
        g_tmpfs_green = true;
        tmpfs_cleanup();
        g_tmpfs_green = false;
        g_tmpfs_root[0] = '\0';
        goto fallback;
    }
    return;
fallback:
    fprintf(stderr, "test_parallel: tmpfs unavailable or disabled; using test-tmp\n");
}

#else
static inline void tmpfs_note_group_started(void) {}
#endif

/* Required by process_block.c (normally in main.c) */
volatile sig_atomic_t g_shutdown_requested = 0;

/* ── Test registry ─────────────────────────────────────────────────
 *
 * tools/dev/test_group_catalog.def is expanded twice below:
 *   DECL  — produces extern int test_<name>(void) / spec_<name>(void);
 *   ENTRY — produces canonical full-ID dispatch rows
 *
 * Keep in sync with the dispatch list in tests/harness/src/test.c.
 */

/* The declarations, dispatch rows, native catalog, shell resolver, and lint
 * gates all consume this one list. Never add a parallel registry. */

/* Forward declarations */
#define ZCL_TEST_GROUP(name) extern int test_##name(void);
#define ZCL_SPEC_GROUP(name) extern int spec_##name(void);
#include "test_group_catalog.def"
#undef ZCL_SPEC_GROUP
#undef ZCL_TEST_GROUP

struct test_group {
    const char *name;
    int (*fn)(void);
};

static const struct test_group g_groups[] = {
#define ZCL_TEST_GROUP(name) {"test_" #name, test_##name},
#define ZCL_SPEC_GROUP(name) {"spec_" #name, spec_##name},
#include "test_group_catalog.def"
#undef ZCL_SPEC_GROUP
#undef ZCL_TEST_GROUP
};

static const size_t g_num_groups =
    sizeof(g_groups) / sizeof(g_groups[0]);

/* ── Dispatch order ────────────────────────────────────────────────────
 *
 * The parallel phases hand out groups longest-expected-first (LPT), so the
 * long poles start while every worker is still busy instead of starting
 * last and leaving the pool idle behind them. Expected seconds come from the
 * tracked tools/dev/test_group_weights.tsv, which a fresh proof generation
 * carries. It is read at run time: regenerating it changes no binary and no
 * test-cache key. Groups without a row weigh 0 and keep catalog order among
 * themselves; a missing or malformed file is plain catalog order. Only the
 * ORDER changes: selection, isolation, environment, the exclusive pre-pass
 * and the rerun-alone tail are untouched, and the transcript still replays
 * in catalog order. .cache/test-timing/last-run.json is deliberately not
 * consulted: it holds whatever subset ran last, and a proof never sees it,
 * so local runs order exactly as proofs do. */
static unsigned g_expected_seconds[sizeof(g_groups) / sizeof(g_groups[0])];
static size_t g_dispatch_order[sizeof(g_groups) / sizeof(g_groups[0])];

static void dispatch_order_prepare(void)
{
    size_t weighted = zcl_test_group_weights_read(
        ZCL_TEST_GROUP_WEIGHTS_PATH, g_expected_seconds, g_num_groups);
    zcl_test_group_order_longest_first(g_expected_seconds, g_num_groups,
                                       g_dispatch_order);
    printf("test_parallel: dispatch longest-expected-first, %zu weighted "
           "groups from %s\n", weighted, ZCL_TEST_GROUP_WEIGHTS_PATH);
}

/* ── Parent-side worker pool ───────────────────────────────────────*/

/* One worker-process handle. POSIX: the fork()ed child's pid (0 = free slot).
 * Windows: no fork() exists, so the parent re-execs THIS binary with
 * --child-run=<idx> (see child_spawn and the --child-run dispatch in main)
 * and the slot carries the child's process HANDLE (NULL = free slot). */
#if defined(_WIN32)
typedef HANDLE zcl_child_t;
#define ZCL_CHILD_NONE NULL
#else
typedef pid_t zcl_child_t;
#define ZCL_CHILD_NONE ((pid_t)0)
#endif

struct child_slot {
    zcl_child_t pid;     /* ZCL_CHILD_NONE if slot is free */
    size_t group_idx;    /* index into g_groups for the running group */
    char out_path[128];  /* tempfile path for this child's stdout+stderr */
    int64_t start_us;    /* monotonic start, for the memory admission ramp */
};

/* The reap accounting below is written against the waitpid() status word.
 * On Windows the value the child arm stores IS the process exit code, so
 * these shims map it onto the same shape: a child the watchdog killed exits
 * with ZCL_WIN_KILL_EXIT (passed to TerminateProcess), which WIFSIGNALED maps
 * onto the POSIX SIGKILL accounting; every other exit is WIFEXITED with the
 * code verbatim (0 = pass, 1 = test failures, 2 = harness error). */
#if defined(_WIN32)
#define ZCL_WIN_KILL_EXIT ((DWORD)0x8000000Au)
#define WIFEXITED(s)   ((int)(s) != (int)ZCL_WIN_KILL_EXIT)
#define WEXITSTATUS(s) ((int)(s))
#define WIFSIGNALED(s) ((int)(s) == (int)ZCL_WIN_KILL_EXIT)
#define WTERMSIG(s)    9
#endif

struct group_result {
    int status;          /* -1 if not yet run, else wait-status from waitpid */
    int signaled;        /* 1 if killed by a signal */
    int exit_code;       /* only valid if signaled == 0 */
    double wall_seconds; /* 0 until measured */
    time_t start;
    char out_path[128];  /* owned by the slot; copied here on reap */
    int skipped;         /* 1 if selector/params gate excluded it (not run) */
    int skip_markers;    /* "SKIP (" sentinel lines in captured output */
    int env_unobserved;  /* "UNOBSERVED (" lines: the group RAN and its
                          * subject was hard-asserted, but one leg depended on
                          * an environment that did not deliver in-window. Not
                          * a skip; never cached. See count_marker_lines. */
    int cached;          /* 1 if returned from the content-addressed cache */
    int measured;        /* 1 once an actual group child was started */
    /* ── progress watchdog state (see group_watchdog_expired) ───────────── */
    time_t last_progress;  /* when this group's output last grew */
    long long last_size;   /* bytes of captured output at that moment */
    int wedged;            /* 1 if WE killed it for going silent */
    int silent_seconds;    /* how long it had been silent when we killed it */
    /* ── rerun-alone policy (see rerun_load_flaky_groups) ─────────────────
     * A group that FAILs or is WEDGED during the shared, multi-worker pool
     * gets exactly one rerun, alone, with the pool otherwise idle. If that
     * rerun passes, the group counts as PASS for the suite verdict but is
     * never allowed to look identical to an ordinary pass: load_flaky stays
     * set, and the first (contended) attempt's capture is preserved so a
     * human can see what the shared pool actually did. */
    int load_flaky;             /* 1 if FAIL/WEDGED under the pool, PASS alone */
    int flaky_first_wedged;     /* 1 if the first attempt was a watchdog kill */
    char flaky_first_log[128];  /* preserved first-attempt capture, "" if n/a */
    /* 1 if the first attempt PASSED but printed "UNOBSERVED (" and the alone
     * rerun PASSED with zero UNOBSERVED lines. Reuses load_flaky/
     * flaky_first_log for reporting (never a silent re-run), but — unlike an
     * ordinary load-flaky PASS — this result is never handed to the verdict
     * store: see the store gate in the cache-accounting block. */
    int load_unobserved;
};

/* Fill the compact slot arrays with the selected groups; returns the slot
 * count. Skipped groups leave no slot, so the batch never sees them. */
static size_t probe_slots_fill(const struct group_result *results,
                               const char **names,
                               enum zcl_test_proof_contract *contracts,
                               size_t *back, bool activate_proof_contracts);

/* Probe-only needs the cache on: with it off or auditing there is nothing
 * reusable to report. */
static bool probe_only_refused(bool cli_probe_only, bool cache_on)
{
    return cli_probe_only && !cache_on;
}

/* Fill the compact slot arrays with the selected groups; returns the slot
 * count. Skipped groups leave no slot, so the batch never sees them. */
static size_t probe_slots_fill(const struct group_result *results,
                               const char **names,
                               enum zcl_test_proof_contract *contracts,
                               size_t *back, bool activate_proof_contracts)
{
    size_t k = 0;
    for (size_t i = 0; i < g_num_groups; i++) {
        if (results[i].skipped)
            continue;
        names[k] = g_groups[i].name;
        contracts[k] = activate_proof_contracts
            ? zcl_test_group_proof_contract(g_groups[i].name)
            : ZCL_TEST_PROOF_NONE;
        back[k] = i;
        k++;
    }
    return k;
}

/* ── Probe capsule CLI + acquisition ────────────────────────────────────
 * --write-capsule=PATH serializes the batch this process probes (the
 * preflight path); --use-capsule=PATH consumes a capsule instead of
 * opening testcache at all (the dimension path). The four --capsule-*
 * binding flags carry the worker's sealed candidate identity on both
 * sides; the consumer refuses unless the capsule matches them AND the
 * live toolkey/envkey. A refused or absent capsule falls back to a fresh
 * open+probe — never to running blind. */
struct capsule_cli {
    const char *write_path;
    const char *use_path;
    const char *source_id;
    const char *mutation_id;
    const char *source_cas;   /* NULL/empty when absent */
    const char *graph_root;   /* NULL/empty when absent */
};

static bool cli_opt_capsule(const char *arg, struct capsule_cli *cap)
{
    if (!arg || !cap) return false;
    if (strncmp(arg, "--write-capsule=",
                sizeof("--write-capsule=") - 1) == 0) {
        cap->write_path = arg + sizeof("--write-capsule=") - 1;
        return true;
    }
    if (strncmp(arg, "--use-capsule=",
                sizeof("--use-capsule=") - 1) == 0) {
        cap->use_path = arg + sizeof("--use-capsule=") - 1;
        return true;
    }
    if (strncmp(arg, "--capsule-source-id=",
                sizeof("--capsule-source-id=") - 1) == 0) {
        cap->source_id = arg + sizeof("--capsule-source-id=") - 1;
        return true;
    }
    if (strncmp(arg, "--capsule-mutation-id=",
                sizeof("--capsule-mutation-id=") - 1) == 0) {
        cap->mutation_id = arg + sizeof("--capsule-mutation-id=") - 1;
        return true;
    }
    if (strncmp(arg, "--capsule-source-cas=",
                sizeof("--capsule-source-cas=") - 1) == 0) {
        cap->source_cas = arg + sizeof("--capsule-source-cas=") - 1;
        return true;
    }
    if (strncmp(arg, "--capsule-graph-root=",
                sizeof("--capsule-graph-root=") - 1) == 0) {
        cap->graph_root = arg + sizeof("--capsule-graph-root=") - 1;
        return true;
    }
    return false;
}

struct capsule_state {
    struct capsule_cli cli;
    size_t depfiles;  /* capsule dep_count when consumed, else 0 */
    bool used;        /* consume succeeded: probes[] are capsule slots */
};

/* Binding token rule: 1..64 chars of [0-9A-Za-z._-]. The worker passes
 * sealed hex ids; anything else refuses the capsule (fresh probe). */
static bool capsule_token_ok(const char *s)
{
    size_t n = 0;
    if (!s || !s[0]) return false;
    while (s[n]) {
        char c = s[n];
        bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                  (c >= 'A' && c <= 'Z') || c == '.' || c == '_' ||
                  c == '-';
        if (!ok || n >= 64) return false;
        n++;
    }
    return true;
}

static bool capsule_bindings_parse(const struct capsule_cli *cli,
                                   struct testcache_capsule_bindings *out)
{
    if (!cli || !out) return false;
    memset(out, 0, sizeof(*out));
    if (!capsule_token_ok(cli->source_id)) return false;
    if (!capsule_token_ok(cli->mutation_id)) return false;
    snprintf(out->source_id, sizeof(out->source_id), "%s", cli->source_id);
    snprintf(out->mutation_id, sizeof(out->mutation_id), "%s",
             cli->mutation_id);
    if (cli->source_cas && cli->source_cas[0]) {
        if (!capsule_token_ok(cli->source_cas)) return false;
        snprintf(out->source_cas, sizeof(out->source_cas), "%s",
                 cli->source_cas);
        out->source_cas_present = true;
    }
    if (cli->graph_root && cli->graph_root[0]) {
        if (!capsule_token_ok(cli->graph_root)) return false;
        snprintf(out->graph_root, sizeof(out->graph_root), "%s",
                 cli->graph_root);
        out->graph_root_present = true;
    }
    return true;
}

/* Compact selected name/index vectors for capsule mapping. */
static bool capsule_selected_names(const struct group_result *results,
                                   const char ***want_out, size_t **back_out,
                                   size_t *n_out)
{
    const char **want = NULL;
    size_t *back = NULL, n_sel = 0, k = 0, i;
    for (i = 0; i < (size_t)g_num_groups; i++)
        if (!results[i].skipped)
            n_sel++;
    want = calloc(n_sel ? n_sel : 1, sizeof(*want));
    back = calloc(n_sel ? n_sel : 1, sizeof(*back));
    if (!want || !back) {
        free(want);
        free(back);
        return false;
    }
    for (i = 0; i < (size_t)g_num_groups; i++) {
        if (results[i].skipped)
            continue;
        want[k] = g_groups[i].name;
        back[k] = i;
        k++;
    }
    *want_out = want;
    *back_out = back;
    *n_out = n_sel;
    return true;
}

/* Consume a capsule into the group-indexed probes[]: structural, binding,
 * and store-record checks only — no liveness proof. Prints ACCEPTED with
 * the slot count or rejected+why; the caller revalidates every HIT against
 * live keys (opening the same handle a fresh probe would use) and
 * fresh-probes on any refusal. */
static bool capsule_try_consume(struct capsule_state *st,
                                const struct group_result *results,
                                struct testcache_probe *probes)
{
    struct testcache_capsule_bindings expected;
    struct testcache_capsule_slot *slots = NULL;
    struct testcache_capsule_info info;
    const char **want = NULL;
    size_t *back = NULL, n_sel = 0, s;
    char why[96];
    bool ok = false;
    if (!st || !results || !probes) return false;
    if (!capsule_bindings_parse(&st->cli, &expected)) {
        printf("test_parallel: capsule rejected (bad binding flags), "
               "fresh probe\n");
        return false;
    }
    slots = calloc((size_t)g_num_groups ? (size_t)g_num_groups : 1,
                   sizeof(*slots));
    if (!slots) {
        printf("test_parallel: capsule rejected (slot alloc failed), "
               "fresh probe\n");
        return false;
    }
    if (!testcache_capsule_consume(st->cli.use_path, &expected, slots,
                                   (size_t)g_num_groups, &info, why,
                                   sizeof(why))) {
        printf("test_parallel: capsule rejected (%s), fresh probe\n", why);
        free(slots);
        return false;
    }
    if (!capsule_selected_names(results, &want, &back, &n_sel)) {
        printf("test_parallel: capsule rejected (select alloc failed), "
               "fresh probe\n");
        free(slots);
        return false;
    }
    for (s = 0; s < n_sel; s++) {
        struct testcache_probe mapped;
        testcache_capsule_apply(slots, info.n_slots, &want[s], 1, &mapped,
                                NULL);
        probes[back[s]] = mapped;
    }
    st->depfiles = (size_t)info.dep_count;
    st->used = true;
    ok = true;
    printf("test_parallel: capsule ACCEPTED %zu slot(s) for %zu selected "
           "group(s), toolkey %s, live revalidation follows\n",
           info.n_slots, n_sel, info.toolkey_hex12);
    free(want);
    free(back);
    free(slots);
    return ok;
}

/* Serialize the just-probed batch beside the run. A write failure only
 * loses future reuse (the dimension falls back); the probes at hand stay
 * valid, so this never fails the run. */
static void maybe_write_capsule(struct testcache *tc,
                                const char *const *names,
                                const enum zcl_test_proof_contract *contracts,
                                size_t n,
                                const struct testcache_probe *probes,
                                const struct capsule_cli *cli)
{
    struct testcache_capsule_bindings bind;
    if (!tc || !cli || !cli->write_path || !cli->write_path[0]) return;
    if (!capsule_bindings_parse(cli, &bind)) {
        fprintf(stderr, "test_parallel: capsule not written (bad binding "
                        "flags)\n");
        return;
    }
    if (!testcache_capsule_write(tc, cli->write_path, names, contracts, n,
                                 probes, &bind))
        fprintf(stderr, "test_parallel: capsule not written\n");
}

enum acquire_result { ACQUIRE_OK, ACQUIRE_DOWNGRADE };

/* The four parallel probe arrays, sized to the selected-group count. */
struct acquire_slots {
    const char **names;
    enum zcl_test_proof_contract *contracts;
    struct testcache_probe *slot;
    size_t *back;
    size_t n_sel;
};

static size_t acquire_count_selected(const struct group_result *results)
{
    size_t n_sel = 0;
    for (size_t i = 0; i < (size_t)g_num_groups; i++)
        if (!results[i].skipped)
            n_sel++;
    return n_sel;
}

static bool acquire_slots_alloc(struct acquire_slots *a, size_t n_sel)
{
    size_t n = n_sel ? n_sel : 1;
    a->names = calloc(n, sizeof(*a->names));
    a->contracts = calloc(n, sizeof(*a->contracts));
    a->slot = calloc(n, sizeof(*a->slot));
    a->back = calloc(n, sizeof(*a->back));
    a->n_sel = n_sel;
    if (!a->names || !a->contracts || !a->slot || !a->back) {
        free(a->names);
        free(a->contracts);
        free(a->slot);
        free(a->back);
        return false;
    }
    return true;
}

static void acquire_slots_free(struct acquire_slots *a)
{
    free(a->names);
    free(a->contracts);
    free(a->slot);
    free(a->back);
}

/* Snapshot-or-live open plus the one batch probe over the shared memo.
 * On success the slots are scattered back and the capsule is written;
 * the caller owns close-on-failure. */
static bool acquire_open_probe(struct testcache **tc,
                               struct acquire_slots *a, bool snapshot,
                               const char **changed_sources, size_t n_changed,
                               const struct group_result *results,
                               struct testcache_probe *probes,
                               bool activate_proof_contracts,
                               const struct capsule_cli *cli)
{
    size_t n_fill, s;
    bool served;
    *tc = snapshot
        ? testcache_open_snapshot(NULL, changed_sources, n_changed)
        : testcache_open(NULL);
    if (!*tc) return false;
    n_fill = probe_slots_fill(results, a->names, a->contracts, a->back,
                              activate_proof_contracts);
    served = testcache_probe_groups(*tc, a->names, a->contracts, n_fill,
                                    a->slot);
    if (served) {
        for (s = 0; s < n_fill; s++)
            probes[a->back[s]] = a->slot[s];
        maybe_write_capsule(*tc, a->names, a->contracts, n_fill, a->slot,
                            cli);
    }
    return served;
}

/* Revalidate consumed HITs against live keys: the capsule spared the mint
 * side no work, but consumption must still prove inputs byte-identical
 * since mint — a slot key is a claim, not evidence. Opens the same live
 * handle a fresh probe would use; any failure downgrades to run-all. */
static bool capsule_revalidate_live(struct testcache **tc,
                                    struct testcache_probe *probes)
{
    const char **names = NULL;
    size_t i;
    if (!tc || !probes) return false;
    *tc = testcache_open(NULL);
    if (!*tc) return false;
    names = calloc((size_t)g_num_groups ? (size_t)g_num_groups : 1,
                   sizeof(*names));
    if (!names) {
        testcache_close(*tc);
        *tc = NULL;
        return false;
    }
    for (i = 0; i < (size_t)g_num_groups; i++)
        names[i] = g_groups[i].name;
    testcache_capsule_revalidate(*tc, names, probes, (size_t)g_num_groups);
    free(names);
    return true;
}

/* Probe acquisition: a validated capsule first (structure, bindings, store
 * records, then live keys — the open it spares is nothing the skip rests
 * on), else the snapshot-or-live open plus the one batch probe over the
 * shared memo. DOWNGRADE means "open or alloc failed" and the caller runs
 * everything. */
static enum acquire_result acquire_probes(struct testcache **tc,
        const struct group_result *results, struct testcache_probe *probes,
        bool activate_proof_contracts, bool snapshot,
        const char **changed_sources, size_t n_changed,
        struct capsule_state *st)
{
    struct acquire_slots a;
    bool served;
    if (!tc || !results || !probes || !st) return ACQUIRE_DOWNGRADE;
    if (!snapshot && st->cli.use_path && st->cli.use_path[0] &&
        capsule_try_consume(st, results, probes)) {
        if (!capsule_revalidate_live(tc, probes)) {
            testcache_close(*tc);
            *tc = NULL;
            return ACQUIRE_DOWNGRADE;
        }
        /* Live provenance supersedes the capsule's mint-time dep count in
         * the PLAN diagnostics below. */
        st->depfiles = 0;
        return ACQUIRE_OK;
    }
    memset(&a, 0, sizeof(a));
    if (!acquire_slots_alloc(&a, acquire_count_selected(results)))
        return ACQUIRE_DOWNGRADE;
    served = acquire_open_probe(tc, &a, snapshot, changed_sources, n_changed,
                                results, probes, activate_proof_contracts,
                                &st->cli);
    acquire_slots_free(&a);
    if (!served) {
        testcache_close(*tc);
        *tc = NULL;
        return ACQUIRE_DOWNGRADE;
    }
    return ACQUIRE_OK;
}

/* Mark one cache HIT as CACHED (excluded from dispatch). Returns true
 * when the group was a HIT. */
static bool group_cache_hit_marked(struct group_result *results, size_t i,
                                   const struct testcache_probe *probes,
                                   size_t *cached_count)
{
    if (results[i].skipped) return false;
    if (!probes[i].cacheable || !probes[i].hit) return false;
    results[i].status = 0;
    results[i].cached = 1;
    (*cached_count)++;
    /* A stored PASS earned by an alone rerun after a contended FAIL/WEDGED
     * must never come back looking like an ordinary cache hit — that would
     * hide the flake on every subsequent cached run forever. Reprint it. */
    if (probes[i].hit_flaky) {
        results[i].load_flaky = 1;
        printf("LOAD-FLAKY %s first=CACHED alone=PASS "
               "first_log=(prior run) alone_log=(cache hit; "
               "see the run that stored this key)\n",
               g_groups[i].name);
    }
    return true;
}
static bool selected_all_external(const struct group_result *results);
enum cache_mode { CACHE_OFF, CACHE_ON, CACHE_COLD_AUDIT };

static enum cache_mode runner_cache_mode(bool cold, bool no_cache, bool cache)
{
    const char *env = getenv("ZCL_TEST_CACHE");
    bool env_on = env && env[0] && strcmp(env, "0") != 0;
    if (cold) return CACHE_COLD_AUDIT;
    if (no_cache) return CACHE_OFF;
    if (cache || env_on) return CACHE_ON;
    return CACHE_OFF;
}
static void print_external_probe_only(const struct group_result *results);
static void external_cache_prepare(const struct group_result *, size_t, enum cache_mode *);
static void print_probe_only(const struct group_result *results,
                             const struct testcache_probe *probes,
                             const struct testcache *tc)
{
    size_t n = 0, reuse = 0, uncacheable = 0;
    if (!tc || !probes) {
        if (selected_all_external(results)) {
            print_external_probe_only(results); return;
        }
        printf("PROBE-ERROR no-verified-graph\n");
        return;
    }
    for (size_t i = 0; i < g_num_groups; i++) {
        const struct testcache_probe *p;
        const char *verdict;
        char key12[13];
        if (results[i].skipped)
            continue;
        p = &probes[i];
        n++;
        if (!p->cacheable) {
            verdict = "UNCACHEABLE";
            uncacheable++;
        } else if (p->hit) {
            verdict = "HIT";
            reuse++;
        } else {
            verdict = "MISS";
        }
        if (p->key_valid) {
            for (int b = 0; b < 6; b++)
                snprintf(key12 + b * 2, 3, "%02x", p->key[b]);
        } else {
            snprintf(key12, sizeof(key12), "-");
        }
        printf("PROBE %s %s %s %s%s\n", g_groups[i].name, verdict,
               testcache_reason_label(p->code), key12,
               p->hit_flaky ? " flaky" : "");
    }
    printf("PROBE-SUMMARY groups=%zu would_reuse=%zu must_run=%zu "
           "uncacheable=%zu\n",
           n, reuse, n - reuse, uncacheable);
    struct testcache_stats s;
    testcache_stats(tc, &s);
    printf("PROBE-STATS graph_opens=1 depfiles=%zu closure_queries=%llu "
           "file_hash_reads=%llu memo_hits=%llu sha3_bytes=%llu "
           "verdict_lookups=%llu verdict_hits=%llu\n",
           testcache_depfile_count(tc),
           (unsigned long long)s.closure_queries,
           (unsigned long long)s.file_hash_reads,
           (unsigned long long)s.file_hash_memo_hits,
           (unsigned long long)s.sha3_content_bytes,
           (unsigned long long)s.verdict_lookups,
           (unsigned long long)s.verdict_hits);
}

/* ── The per-group watchdog is on SILENCE, not on runtime ──────────────────
 *
 * This used to be `now - start > timeout_secs`, i.e. SIGKILL any group that
 * ran longer than 300 s of wall time. That grades the machine, not the code.
 * With 32 workers on 32 cores every group is contending, and a box with a
 * 7200rpm disk — measured under 2 MB/s on this project's own fleet — takes
 * several times longer to do exactly the same, correct work. A duration
 * ceiling turns those machines into red builds, which is both a lie about the
 * code and a reason people stop keeping slow machines around. This project
 * wants them: they are the only instrument that finds where the code assumes
 * fast storage.
 *
 * Raising 300 s would not fix it, it would just move the cliff and make a
 * genuine hang take longer to surface. What separates a wedged group from a
 * slow one is not how long it has run — it is whether it is still PRODUCING
 * ANYTHING. Every group streams its assertions to its capture file, so:
 *
 *   * slow box  -> same lines, further apart -> the timer keeps resetting;
 *   * deadlock  -> the file stops growing entirely -> killed and reported.
 *
 * The number below is therefore unchanged in value and completely changed in
 * meaning: 300 s of continuous SILENCE. The longest legitimately silent
 * stretch in the suite is a single long-running assertion inside one group
 * (test_merkle_tree's ~110 s standalone body is the measured worst case), so
 * 300 s is ~2.7x that on an idle box and scales with nothing — a box 10x
 * slower still passes as long as it is still emitting.
 *
 * Returns true when the group has been silent for longer than the bound, and
 * fills in how long it had been silent so the report can say so.
 */
static bool group_watchdog_expired(struct group_result *r, const char *out_path,
                                   time_t now, int max_silent_secs)
{
    struct stat st;
    long long size = (stat(out_path, &st) == 0) ? (long long)st.st_size : -1;
    if (r->last_progress == 0) {
        r->last_progress = r->start;
        r->last_size = size;
    }
    if (size != r->last_size) {
        r->last_size = size;
        r->last_progress = now;
        return false;
    }
    if (now - r->last_progress <= max_silent_secs)
        return false;
    r->silent_seconds = (int)(now - r->last_progress);
    return true;
}

/* One line of load context beside a watchdog kill, so a reader can tell a
 * hung test from a saturated box without re-running anything. */
static void print_watchdog_kill(size_t idx, const char *name,
                                const struct group_result *r, time_t now,
                                int max_silent_secs)
{
    char load[80] = "unknown";
    FILE *fp = fopen("/proc/loadavg", "rb");
    if (fp) {
        if (fgets(load, sizeof(load), fp)) {
            char *nl = strchr(load, '\n');
            if (nl) *nl = '\0';
        }
        fclose(fp);
    }
    printf("[wedged  ] [%zu] %s — NO OUTPUT for %ds (bound: %ds of silence, "
           "not of runtime); %llds total elapsed; loadavg %s.\n"
           "           This is a HANG report, not a failed assertion: a slow "
           "or loaded box keeps\n"
           "           emitting and never lands here. Captured output so far: "
           "%s\n",
           idx, name, r->silent_seconds, max_silent_secs,
           (long long)(now - r->start), load, r->out_path[0] ? r->out_path : "(none)");
    fflush(stdout);
}

/* Peak resident bytes one runner worker (a test group plus its children) is
 * budgeted under a sanitizer, used only to keep workers inside the cgroup
 * memory ceiling. Unsanitized builds are not capped. TSan shadow memory makes
 * a worker several times heavier: 28 TSan workers reached 8.0 GiB and were
 * OOM-killed under a devbuild scope whose MemoryMax is 8 GiB, so ~300 MiB
 * would still admit 27 and not prevent it; 512 MiB admits 16. */
/* gcc defines __SANITIZE_*; clang reports sanitizers only through
 * __has_feature. */
#if defined(__SANITIZE_THREAD__)
#define RUNNER_TSAN 1
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define RUNNER_TSAN 1
#endif
#endif
#if defined(RUNNER_TSAN)
#define RUNNER_WORKER_BYTES (INT64_C(512) * 1024 * 1024)
#define RUNNER_WORKER_KIND "tsan"
#elif defined(TP_ASAN)
#define RUNNER_WORKER_BYTES (INT64_C(256) * 1024 * 1024)
#define RUNNER_WORKER_KIND "asan"
#else
#define RUNNER_WORKER_BYTES INT64_C(0)
#define RUNNER_WORKER_KIND ""
#endif

static char g_jobs_reason[96] = "cpus";

/* Memory-aware admission. The static per-worker figure above only bounds the
 * worker count; a heavy group (test_si under TSan) is several times a light
 * one, so 16 admitted workers still reached the cgroup ceiling. The runner
 * therefore also reads the headroom under its own cgroup's memory.max before
 * each fork, charges the group its measured peak RSS from an earlier run in
 * this process (wait4 ru_maxrss; the static figure until then), and holds the
 * fork while the headroom would not cover it plus a reserve. With nothing
 * running it always admits one, so a group heavier than the whole cgroup
 * still runs, alone. Off Linux there is no cgroup and nothing changes.
 * The pure decisions live in test/runner_admission.h and are unit-tested by
 * test_runner_admission. */

/* Peak RSS seen so far: live (VmHWM, still rising) and finished (wait4). */
[[maybe_unused]] static int64_t g_group_peak_bytes[sizeof(g_groups) / sizeof(g_groups[0])];
[[maybe_unused]] static int64_t g_group_done_bytes[sizeof(g_groups) / sizeof(g_groups[0])];
[[maybe_unused]] static int64_t g_pool_peak_bytes;

[[maybe_unused]] static int64_t group_memory_estimate(size_t idx)
{
    return runner_admission_estimate(RUNNER_WORKER_BYTES,
                                     g_group_done_bytes[idx],
                                     g_pool_peak_bytes);
}

static bool phase_memory_admits(const struct child_slot *slots, int jobs,
                                size_t next_idx)
{
#if defined(__linux__)
    if (RUNNER_WORKER_BYTES <= 0) return true;
    int running = 0;
    int young = 0;
    int64_t pending = 0;
    int64_t now = platform_time_monotonic_us();
    for (int i = 0; i < jobs; i++) {
        if (slots[i].pid == ZCL_CHILD_NONE) continue;
        running++;
        if (runner_admission_is_young(now, slots[i].start_us)) young++;
        pending += runner_admission_pending(
            group_memory_estimate(slots[i].group_idx),
            g_group_peak_bytes[slots[i].group_idx]);
    }
    if (running == 0) return true;
    int64_t headroom = platform_cgroup_memory_headroom();
    int64_t estimate = group_memory_estimate(next_idx);
    bool admit = runner_admission_admit(running, young, headroom, pending, estimate);
    static size_t held_idx = (size_t)-1;
    if (!admit && held_idx != next_idx) {
        held_idx = next_idx;   /* once per held group, not once per poll */
        printf("test_parallel: memory hold group=%s running=%d young=%d "
               "headroom=%lld MiB pending=%lld MiB estimate=%lld MiB\n",
               g_groups[next_idx].name, running, young,
               (long long)(headroom >> 20), (long long)(pending >> 20),
               (long long)(estimate >> 20));
        fflush(stdout);
    }
    return admit;
#else
    (void)slots; (void)jobs; (void)next_idx;
    return true;
#endif
}

#if defined(__linux__)
/* Peak resident bytes of a live process (VmHWM), 0 when unreadable. */
static int64_t proc_peak_rss_bytes(pid_t pid)
{
    char path[64];
    char line[128];
    snprintf(path, sizeof path, "/proc/%d/status", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int64_t kib = 0;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "VmHWM:", 6) != 0) continue;
        for (const char *p = line + 6; *p; p++)
            if (*p >= '0' && *p <= '9') kib = kib * 10 + (*p - '0');
            else if (kib > 0) break;
        break;
    }
    fclose(f);
    return kib * 1024;
}
#endif

/* Poll the live workers about 4 times a second: raise each group's learned
 * peak from its VmHWM while it runs (a group that dies at the ceiling never
 * reaches the wait4 figure), and leave one trail line when the cgroup
 * headroom moved 256 MiB or more since the last line. A runner killed by the
 * memory ceiling leaves no other record of how it got there. */
static void phase_memory_sample(const struct child_slot *slots, int jobs)
{
#if defined(__linux__)
    if (RUNNER_WORKER_BYTES <= 0) return;
    static int64_t last_us;
    static int64_t last_headroom = -1;
    int64_t now = platform_time_monotonic_us();
    if (now - last_us < 250000) return;
    last_us = now;
    int running = 0;
    for (int i = 0; i < jobs; i++) {
        if (slots[i].pid == ZCL_CHILD_NONE) continue;
        running++;
        int64_t rss = proc_peak_rss_bytes(slots[i].pid);
        runner_admission_note_peak(rss, false,
                                   &g_group_peak_bytes[slots[i].group_idx],
                                   &g_group_done_bytes[slots[i].group_idx],
                                   &g_pool_peak_bytes);
    }
    int64_t headroom = platform_cgroup_memory_headroom();
    if (headroom < 0) return;
    int64_t delta = headroom - last_headroom;
    if (last_headroom >= 0 && delta < (INT64_C(256) << 20) &&
        -delta < (INT64_C(256) << 20))
        return;
    last_headroom = headroom;
    printf("test_parallel: memory headroom=%lld MiB running=%d heavy:",
           (long long)(headroom >> 20), running);
    for (int i = 0; i < jobs; i++) {
        if (slots[i].pid == ZCL_CHILD_NONE) continue;
        int64_t peak = g_group_peak_bytes[slots[i].group_idx];
        if (peak >= (INT64_C(256) << 20))
            printf(" %s=%lld", g_groups[slots[i].group_idx].name,
                   (long long)(peak >> 20));
    }
    printf("\n");
    fflush(stdout);
#else
    (void)slots; (void)jobs;
#endif
}

static int get_nproc(void)
{
    uint32_t n = platform_available_cpu_count();
    if (n > 1024u) n = 1024u;
    if (RUNNER_WORKER_BYTES > 0) {
        int64_t budget = platform_build_memory_budget_bytes();
        uint32_t capped =
            platform_memory_worker_cap(n, budget, RUNNER_WORKER_BYTES);
        if (capped < n) {
            snprintf(g_jobs_reason, sizeof g_jobs_reason,
                     "%s memory cap: %lld MiB / %lld MiB per worker, cpus %u",
                     RUNNER_WORKER_KIND, (long long)(budget >> 20),
                     (long long)(RUNNER_WORKER_BYTES >> 20), n);
            n = capped;
        }
    }
    return (int)n;
}

static bool activate_proof_contract(size_t idx)
{
    const char *env_name = NULL;
    enum zcl_test_proof_contract contract =
        zcl_test_group_proof_contract(g_groups[idx].name);
    if (contract == ZCL_TEST_PROOF_NONE)
        return true;
    const char *env_value = NULL;
    if (!zcl_test_proof_contract_environment(contract, &env_name,
                                              &env_value)) {
        fprintf(stderr,
                "test_parallel: invalid proof contract group=%s\n",
                g_groups[idx].name);
        return false;
    }
    if (setenv(env_name, env_value, 1) != 0) {
        fprintf(stderr,
                "test_parallel: proof contract activation failed group=%s "
                "env=%s: %s\n",
                g_groups[idx].name, env_name, strerror(errno));
        return false;
    }
    printf("test_parallel: proof contract group=%s env=%s\n",
           g_groups[idx].name, env_name);
    return true;
}

static bool g_state_isolation_probe;
static unsigned g_retry_evidence_probe;
extern void zcl_test_group_selector_state_probe(bool enabled);

static bool retry_probe_parse(const char *arg)
{
    static const char *const flags[] = {
        "--retry-evidence-probe", "--retry-evidence-unobserved",
        "--retry-evidence-rename-failure"
    };
    for (unsigned i = 0; i < 3; i++) {
        if (strcmp(arg, flags[i]) == 0) {
            g_retry_evidence_probe = i + 1;
            return true;
        }
    }
    return false;
}

static bool retry_probe_options(int argc, char **argv)
{
    static const char *const allowed[] = {
        "--jobs=2", "--verbose", "--no-cache", "--exact=test_hex_codec",
        "--retry-evidence-probe", "--retry-evidence-unobserved",
        "--retry-evidence-rename-failure"
    };
    unsigned seen[7] = {0};
    for (int i = 1; i < argc; i++) {
        size_t j = 0;
        while (j < 7 && strcmp(argv[i], allowed[j]) != 0) j++;
        if (j == 7 || seen[j]++) return false;
    }
    return seen[2] == 1 && seen[3] == 1 &&
        seen[4] + seen[5] + seen[6] == 1 && !getenv("ZCL_TEST_CACHE_DUMP");
}

static bool retry_probe_admit(int argc, char **argv)
{
    if (!g_retry_evidence_probe) return true;
    if (!retry_probe_options(argc, argv)) {
        fprintf(stderr, "retry evidence fixture requires --no-cache and exact test_hex_codec only\n");
        return false;
    }
    printf("SYNTHETIC RETRY EVIDENCE FIXTURE: forced failure, no verdict reuse\n");
    return true;
}

static int retry_probe_exit(size_t failed, int diverged, int refused)
{
    return (!g_retry_evidence_probe && failed == 0 && diverged == 0 &&
            refused == 0) ? 0 : 1;
}

static bool retry_probe_block_rename(const char *out_path)
{
    char blocked[PATH_MAX];
    int n = snprintf(blocked, sizeof(blocked), "%s.first", out_path);
    return n >= 0 && (size_t)n < sizeof(blocked) &&
           platform_directory_create(blocked, 0700) == 0;
}

static int retry_evidence_probe(const char *out_path)
{
    FILE *f = fopen("retry-evidence-count", "r");
    unsigned count = 0;
    if (f) {
        bool read_ok = fscanf(f, "%u", &count) == 1;
        if (fclose(f) != 0) read_ok = false;
        if (!read_ok || count >= 2) return 2;
    }
    f = fopen("retry-evidence-count", "w");
    if (!f) return 2;
    bool ok = fprintf(f, "%u\n", count + 1) > 0;
    if (fclose(f) != 0) ok = false;
    printf("RETRY-EVIDENCE-%s\n", count == 0 ? "FIRST" : "RETRY");
    if (g_retry_evidence_probe == 3 && count == 0) {
        if (!retry_probe_block_rename(out_path)) return 2;
    }
    if (g_retry_evidence_probe == 2 && ok) {
        printf("UNOBSERVED (synthetic retry evidence fixture)\n");
        return 0;
    }
    return ok ? 1 : 2;
}

#if !defined(_WIN32)
/* Land's receiver only admits source checkouts under the checkout policy.
 * Its fixture repositories therefore stay under cwd/test-tmp. */
static bool child_fixture_root_select(size_t idx)
{
    return strncmp(g_groups[idx].name, "test_dev_land", 13) != 0 ||
           unsetenv("ZCL_TEST_TMPROOT") == 0;
}
#endif

/* Children end with _exit, which skips atexit, so LeakSanitizer never
 * reaches its own exit-time check. ZCL_TEST_LEAK_CHECK=report prints
 * LEAKS for a group that leaks; =fail also makes that group red. Any other
 * value (or unset) leaves the child exactly as it was. */
#if defined(TP_ASAN)
static int child_leak_check(int failures, const char *group)
{
    const char *mode = getenv("ZCL_TEST_LEAK_CHECK");
    int fail = mode && strcmp(mode, "fail") == 0;
    if (!fail && !(mode && strcmp(mode, "report") == 0))
        return failures;
    if (__lsan_do_recoverable_leak_check() == 0)
        return failures;
    fprintf(stderr, "test_parallel: leak-check: LEAKS group=%s\n", group);
    return fail && failures == 0 ? 1 : failures;
}
#else
static int child_leak_check(int failures, const char *group)
{
    (void)group;
    return failures;
}
#endif

static void child_run(size_t idx, const char *out_path, const char *state_path,
                      bool activate_proof_contracts)
{
    /* Redirect stdout + stderr to our tempfile. */
    int fd = open(out_path,
                  O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        /* Can't redirect — run anyway; parent will see empty output. */
        perror("test_parallel: open tempfile");
    } else {
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        close(fd);
    }
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

#if !defined(_WIN32)
    if (!child_fixture_root_select(idx)) _exit(2);
#endif
    if (!state_path || !state_path[0] ||
        setenv("XDG_STATE_HOME", state_path, 1) != 0) {
        fprintf(stderr, "test_parallel: private state activation failed: %s\n",
                strerror(errno));
        _exit(2);
    }
#if defined(_WIN32)
    if (setenv("ZCL_STATE_ROOT", state_path, 1) != 0) {
        fprintf(stderr, "test_parallel: native state activation failed: %s\n",
                strerror(errno));
        _exit(2);
    }
#endif
    /* Private HOME + XDG dirs under the same retained dir, datadir env vars
     * unset, canonical datadir exported for the storage writer guard: no
     * default-datadir fallback in any group can reach the operator's node. */
    {
        char iso_err[512];
        if (!zcl_test_isolate_environment(state_path, iso_err, sizeof(iso_err))) {
            fprintf(stderr, "test_parallel: HOME isolation failed: %s\n",
                    iso_err);
            _exit(2);
        }
    }
    printf("test_parallel: private state retained=%s\n", state_path);
    zcl_test_group_selector_state_probe(g_state_isolation_probe &&
        strcmp(g_groups[idx].name, "test_test_group_selector") == 0);

    if (activate_proof_contracts && !activate_proof_contract(idx))
        _exit(2);

    /* A fatal signal (SIGSEGV/SIGBUS/SIGABRT/SIGFPE) in a group's fn() used
     * to reach the kernel default disposition with no diagnostics captured
     * anywhere: the parent only ever learns WIFSIGNALED + the signal number
     * (see the reap paths below), and the failing group's own stdout/stderr
     * capture — the one artifact print_captured() replays for a SIGNALED
     * group — stayed empty. That made a segfault indistinguishable from a
     * silent hang and gave zero lead on root cause. Installing the same
     * async-signal-safe handler the live node installs at boot (boot.c)
     * means a crash now writes a symbolized backtrace to stderr — which is
     * already redirected to this group's own log file above — before
     * re-raising the signal so the parent's WIFSIGNALED/WTERMSIG accounting
     * is unchanged. Best-effort: if installation fails, run uninstrumented
     * rather than skip the group. */
    (void)signal_handler_install();

    chain_params_select(CHAIN_MAIN);
    ecc_start();
    ecc_verify_init();
    event_log_init();

    int failures = g_retry_evidence_probe &&
        strcmp(g_groups[idx].name, "test_hex_codec") == 0
        ? retry_evidence_probe(out_path) : g_groups[idx].fn();

    ecc_verify_destroy();
    ecc_stop();
    failures = child_leak_check(failures, g_groups[idx].name);

    fflush(stdout);
    fflush(stderr);
    _exit(failures ? 1 : 0);
}

#if defined(_WIN32)
/* Return true only when an internal worker dispatch was requested. */
static bool child_dispatch(int argc, char **argv)
{
    long idx = -1;
    const char *out = NULL, *state = NULL;
    bool proof = false;
    for (int i = 1; i < argc; ++i) {
        if (strncmp(argv[i], "--child-run=", 12) == 0)
            idx = strtol(argv[i] + 12, NULL, 10);
        else if (strncmp(argv[i], "--child-out=", 12) == 0)
            out = argv[i] + 12;
        else if (strncmp(argv[i], "--child-state=", 14) == 0)
            state = argv[i] + 14;
        else if (strcmp(argv[i], "--child-proof") == 0)
            proof = true;
        else if (strcmp(argv[i], "--state-isolation-probe") == 0)
            g_state_isolation_probe = true;
        else if (strcmp(argv[i], "--retry-evidence-probe") == 0)
            g_retry_evidence_probe = 1;
        else if (strcmp(argv[i], "--retry-evidence-unobserved") == 0)
            g_retry_evidence_probe = 2;
        else if (strcmp(argv[i], "--retry-evidence-rename-failure") == 0)
            g_retry_evidence_probe = 3;
    }
    if (idx < 0) return false;
    if (!out || !state || (unsigned long)idx >= (unsigned long)g_num_groups) {
        fprintf(stderr, "test_parallel: bad --child-run dispatch\n");
        return true;
    }
    child_run((size_t)idx, out, state, proof);
    return true;
}
#endif

/* Spawn one group's worker. POSIX forks and the child runs child_run in
 * place. Windows has no fork(), so the parent re-execs this same binary with
 * --child-run=<idx> --child-out=<path>; the early dispatch in main() hands
 * those arguments straight to child_run, which does its own stdout/stderr
 * redirection exactly as the forked child does. Returns 0 and fills `out`,
 * or -1 (already logged). */
/* Validate the externally supplied root before using it for attempt state. */
#if !defined(_WIN32)
static bool child_state_env_parent(const char *root, char *parent)
{
    struct stat st;
    return root[0] == '/' && lstat(root, &st) == 0 && S_ISDIR(st.st_mode) &&
           st.st_uid == geteuid() && (st.st_mode & 07777) == 0700 &&
           realpath(root, parent) != NULL;
}
#endif

/* Attempt roots are retained fixtures, like failed logs in test-tmp. The
 * parent creates them before dispatch; retries never reuse a prior root. */
static bool child_state_create(char *out, size_t cap)
{
    char parent[PATH_MAX];
#if !defined(_WIN32)
    /* ZCL_TEST_TMPROOT (set by the Makefile runner to a 0700 tmpfs directory)
     * holds the attempt roots too; an unusable value fails, never falls back. */
    const char *env_root = getenv("ZCL_TEST_TMPROOT");
    if (env_root && env_root[0]) {
        if (!child_state_env_parent(env_root, parent)) return false;
    } else
#endif
    {
        if (platform_directory_create("test-tmp", 0755) != 0 && errno != EEXIST)
            return false;
#if defined(_WIN32)
        if (!_fullpath(parent, "test-tmp", sizeof(parent))) return false;
#else
        if (!realpath("test-tmp", parent)) return false;
#endif
    }
    for (unsigned attempt = 0; attempt < 64; ++attempt) {
        uint8_t nonce[9];
        char hex[19];
        if (!rng_fill(nonce, 8)) { errno = EIO; return false; }
        nonce[8] = (uint8_t)attempt;
        zcl_hex_encode(nonce, sizeof(nonce), hex);
        int n = snprintf(out, cap, "%s/runner-state-%s", parent, hex);
        if (n < 0 || (size_t)n >= cap) { errno = ENAMETOOLONG; return false; }
        if (platform_private_directory_create(out)) return true;
        if (errno != EEXIST) return false;
    }
    errno = EEXIST;
    return false;
}

static int child_spawn(size_t idx, const char *out_path,
                       bool activate_proof_contracts, zcl_child_t *out)
{
#if defined(__linux__)
    test_tmpfs_guard();
#endif
    char state_path[PATH_MAX];
    if (!child_state_create(state_path, sizeof(state_path))) {
        fprintf(stderr, "test_parallel: private state setup failed group=%s: %s\n",
                g_groups[idx].name, strerror(errno));
        return -1;
    }
    printf("test_parallel: attempt group=%s retained_state=%s\n",
           g_groups[idx].name, state_path);
    fflush(stdout);
#if defined(_WIN32)
    char exe[PATH_MAX];
    DWORD n = GetModuleFileNameA(NULL, exe, (DWORD)sizeof(exe));
    if (n == 0 || n >= (DWORD)sizeof(exe)) {
        fprintf(stderr, "test_parallel: GetModuleFileName failed (%lu)\n",
                (unsigned long)GetLastError());
        return -1;
    }
    char cmd[3 * PATH_MAX + 320];
    int len = snprintf(cmd, sizeof(cmd),
                       "\"%s\" --child-run=%zu \"--child-out=%s\" "
                       "\"--child-state=%s\"%s%s%s",
                       exe, idx, out_path, state_path,
                       activate_proof_contracts ? " --child-proof" : "",
                       g_state_isolation_probe ? " --state-isolation-probe" : "",
                       g_retry_evidence_probe == 1 ? " --retry-evidence-probe" :
                       g_retry_evidence_probe == 2 ? " --retry-evidence-unobserved" :
                       g_retry_evidence_probe == 3 ? " --retry-evidence-rename-failure" : "");
    if (len < 0 || (size_t)len >= sizeof(cmd)) {
        fprintf(stderr, "test_parallel: child command line too long\n");
        return -1;
    }
    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL,
                        &si, &pi)) {
        fprintf(stderr, "test_parallel: CreateProcess failed (%lu) for %s\n",
                (unsigned long)GetLastError(), g_groups[idx].name);
        return -1;
    }
    CloseHandle(pi.hThread);
    *out = pi.hProcess;
    return 0;
#else
    pid_t pid = fork();
    if (pid < 0) {
        perror("test_parallel: fork");
        return -1;
    }
    if (pid == 0) {
        child_run(idx, out_path, state_path, activate_proof_contracts);
        _exit(2); /* unreachable */
    }
    tmpfs_note_group_started();
    *out = pid;
    return 0;
#endif
}

/* Non-blocking reap of one worker: 1 = exited (*status set), 0 = still
 * running, -1 = harness error (already logged). */
static int child_poll(zcl_child_t child, int *status)
{
#if defined(_WIN32)
    DWORD wr = WaitForSingleObject(child, 0);
    if (wr == WAIT_TIMEOUT) return 0;
    if (wr != WAIT_OBJECT_0) {
        fprintf(stderr, "test_parallel: WaitForSingleObject failed (%lu)\n",
                (unsigned long)GetLastError());
        return -1;
    }
    DWORD code = 0;
    if (!GetExitCodeProcess(child, &code)) {
        fprintf(stderr, "test_parallel: GetExitCodeProcess failed (%lu)\n",
                (unsigned long)GetLastError());
        return -1;
    }
    *status = (int)code;
    return 1;
#else
    pid_t done = waitpid(child, status, WNOHANG);
    if (done == 0) return 0;
    if (done < 0) {
        if (errno == EINTR) return 0;
        perror("test_parallel: waitpid");
        return -1;
    }
    return 1;
#endif
}

/* Blocking reap, used only on the scheduler-teardown path. */
static int child_wait(zcl_child_t child, int *status)
{
#if defined(_WIN32)
    if (WaitForSingleObject(child, INFINITE) != WAIT_OBJECT_0) {
        fprintf(stderr, "test_parallel: WaitForSingleObject failed (%lu)\n",
                (unsigned long)GetLastError());
        return -1;
    }
    DWORD code = 0;
    if (!GetExitCodeProcess(child, &code)) {
        fprintf(stderr, "test_parallel: GetExitCodeProcess failed (%lu)\n",
                (unsigned long)GetLastError());
        return -1;
    }
    *status = (int)code;
    return 0;
#else
    while (waitpid(child, status, 0) < 0) {
        if (errno == EINTR) continue;
        perror("test_parallel: waitpid");
        return -1;
    }
    return 0;
#endif
}

/* The watchdog's kill: SIGKILL on POSIX, TerminateProcess with the sentinel
 * exit code on Windows so the reap accounting still reads "signaled". */
static void child_kill(zcl_child_t child)
{
#if defined(_WIN32)
    (void)TerminateProcess(child, ZCL_WIN_KILL_EXIT);
#else
    (void)kill(child, SIGKILL);
#endif
}

static void child_close(zcl_child_t child)
{
#if defined(_WIN32)
    CloseHandle(child);
#else
    (void)child;   /* a reaped pid_t needs no release */
#endif
}

/* Reap one finished child from the slot set. Returns the slot index, -2 when
 * no child has exited yet, -1 on harness error (already logged). */
#if !defined(_WIN32)
static int find_slot_by_pid(struct child_slot *slots, int jobs, pid_t pid);
#endif
static int reap_any(struct child_slot *slots, int jobs, int *status,
                    int64_t *peak_bytes)
{
    (void)peak_bytes;   /* only Linux wait4 reports a peak */
#if defined(_WIN32)
    for (int i = 0; i < jobs; i++) {
        if (slots[i].pid == ZCL_CHILD_NONE) continue;
        int r = child_poll(slots[i].pid, status);
        if (r == 1) return i;
        if (r < 0) return -1;
    }
    return -2;
#else
#if defined(__linux__)
    struct rusage ru;
    memset(&ru, 0, sizeof ru);
    pid_t done = wait4(-1, status, WNOHANG, &ru);
    if (done > 0)   /* Linux reports ru_maxrss in KiB */
        *peak_bytes = (int64_t)ru.ru_maxrss * 1024;
#else
    pid_t done = waitpid(-1, status, WNOHANG);
#endif
    if (done == 0) return -2;
    if (done < 0) {
        if (errno == EINTR) return -2;
        perror("test_parallel: waitpid");
        return -1;
    }
    /* A reaped child that owns no slot (should not happen) is ignored, not
     * fatal — the historic loop just continued. */
    return find_slot_by_pid(slots, jobs, done);
#endif
}

#if !defined(_WIN32)
static int find_slot_by_pid(struct child_slot *slots, int jobs, pid_t pid)
{
    for (int i = 0; i < jobs; i++)
        if (slots[i].pid == pid) return i;
    return -1;
}
#endif

static int find_free_slot(struct child_slot *slots, int jobs)
{
    for (int i = 0; i < jobs; i++)
        if (slots[i].pid == ZCL_CHILD_NONE) return i;
    return -1;
}

static void make_tempfile_path(char *buf, size_t sz, size_t idx, pid_t parent)
{
    snprintf(buf, sz, "./test-tmp/test_parallel_%lld_%zu.log",
             (long long)parent, idx);
}

static void ensure_tmp_dir(void)
{
    struct stat st;
    if (stat("./test-tmp", &st) == 0) return;
    if (platform_directory_create("./test-tmp", 0755) != 0 && errno != EEXIST)
        perror("test_parallel: mkdir ./test-tmp");
}

static void print_captured(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        printf("  (captured output missing at %s)\n", path);
        return;
    }
    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        fputs(line, stdout);
    }
    fclose(fp);
}

/* Count lines carrying a sentinel ("SKIP (" or "UNOBSERVED ("). Gated
 * groups (the five ZCL_STRESS_TESTS MVP acceptance gates, the stress
 * harnesses) and environment-starved subtests print it and still exit
 * 0, so a green run can hide unexecuted coverage. The summary counts
 * the markers so "ALL TESTS PASSED" can never silently absorb a skip;
 * the gates themselves stay opt-in (they are gated for runtime
 * reasons — visibility, not force-enabling, is the contract). */
struct marker_line_scan {
    size_t matched;
    bool seen;
    int lines;
};

static void marker_line_byte(struct marker_line_scan *scan, unsigned char byte,
                              const char *sentinel, size_t len)
{
    if (byte == '\n') {
        scan->lines += scan->seen;
        scan->seen = false;
        scan->matched = 0;
        return;
    }
    if (scan->seen) return;
    /* Neither canonical sentinel repeats its initial byte internally. */
    if (byte == (unsigned char)sentinel[scan->matched]) scan->matched++;
    else scan->matched = byte == (unsigned char)sentinel[0];
    if (scan->matched == len) scan->seen = true;
}

static int marker_stream_lines(FILE *fp, const char *sentinel)
{
    struct marker_line_scan scan = {0};
    unsigned char bytes[4096];
    size_t n, len = strlen(sentinel);
    while ((n = fread(bytes, 1, sizeof bytes, fp)) > 0)
        for (size_t i = 0; i < n; i++) marker_line_byte(&scan, bytes[i], sentinel, len);
    return scan.lines + scan.seen;
}

static int count_marker_lines(const char *path, const char *sentinel)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    int n = marker_stream_lines(fp, sentinel);
    fclose(fp);
    return n;
}

/* Two lint-gate self-tests plant a real file into the LIVE worktree — one
 * under engine/services/src/, one at the repo root — and then unlink() it. Those
 * paths sit inside other groups' lint scan surfaces, so a concurrent scanner
 * can readdir a fixture and then have open() race the unlink (grep exits 2,
 * which the gate treats as FATAL). The cure is to run the group that owns
 * those two checks ALONE (run_group_exclusive, a synchronous pre-pass) before
 * the parallel pool dispatches anything.
 *
 * That group is `make_lint_gates`. Its ~114 sibling checks live in
 * `make_lint_gates_shard_NN` and `make_lint_gates_realroot`, which never touch
 * the real tree. The eight source-copy shards stay parallel in a bounded quiet
 * phase; realroot and the rest of the suite use the general pool. The pre-pass
 * ordering is also what lets the shards build their private reflink-or-copy
 * sandboxes from a quiet tree.
 *
 * The policy itself lives in test_make_lint_gates.c next to the entry table
 * that makes it true, and is asserted in both directions by the
 * make_lint_gates_partition group. Do not re-implement it here: an earlier
 * bare strcmp against the un-prefixed name silently never matched and left
 * the guard dead, and a match too WIDE would drag every shard back into the
 * serial pre-pass and undo the split just as silently. */
static bool group_requires_exclusive_repo(const char *name)
{
    return lint_gates_group_is_exclusive(name);
}

/* Host-latency contracts must run before the worker pool starts.  Their
 * budget is meant to catch a slow command implementation, not scheduler
 * starvation caused by unrelated CPU-heavy groups. */
static bool group_requires_exclusive_run(const char *name)
{
    if (group_requires_exclusive_repo(name)) return true;
    return zcl_test_group_requires_exclusive_run(name);
}

static bool group_requires_quiet_pool(const char *name)
{
    return lint_gates_group_requires_quiet_pool(name);
}

/* Params-heavy opt-in gate. These groups load the multi-MB Sapling Groth16
 * proving keys from ~/.zcash-params and run REAL proving (seconds of CPU,
 * ~50 MB RAM each) — too slow/heavy for the fast default pool. They are
 * excluded from a default full run and opted in via ZCL_PARAMS_TESTS=1 (runs
 * them alongside everything) or by naming one with --only/--exact (explicit
 * selection). They stay fully registered so the opt-in paths reach them. */
static bool group_is_params_heavy(const char *name)
{
    if (!name) return false;
    if (strncmp(name, "test_", 5) == 0) name += 5;
    return strcmp(name, "sapling") == 0 ||
           strcmp(name, "simnet_sapling_shielded_send") == 0 ||
           strcmp(name, "wallet_e2e_regtest") == 0 ||
           strcmp(name, "simnet_shielded_wallet_e2e") == 0 ||
           strcmp(name, "simnet_zmsg_onchain") == 0 ||
           strcmp(name, "snark_kat") == 0 ||
           strcmp(name, "native_spend_proof") == 0 ||
           strcmp(name, "groth16_selfverify") == 0 ||
           strcmp(name, "wallet_destruction_drill") == 0 ||
           strcmp(name, "sapling_prover_rng_determinism") == 0;
}

/* Whether a group is still headed for dispatch after the selector pass. */
static bool group_still_selected(const char *full_id, void *ctx)
{
    const struct group_result *results = ctx;
    for (size_t i = 0; i < g_num_groups; i++)
        if (strcmp(g_groups[i].name, full_id) == 0)
            return !results[i].skipped;
    return false;
}

static void print_selected_groups(const struct group_result *results)
{
    size_t selected = 0;
    for (size_t i = 0; i < g_num_groups; i++) {
        if (results[i].skipped) continue;
        printf("SELECTED %s\n", g_groups[i].name);
        selected++;
    }
    printf("SELECTION-ONLY groups=%zu executed=0 cache_probes=0\n", selected);
}

/* An umbrella (tools/dev/test_group_umbrellas.def) runs whole when named with
 * --exact: every consumer of the historic id keeps every sub-suite. Any other
 * selection that also carries all of its shards -- the default full run, an
 * --only substring -- runs the shards instead, concurrently, and leaves the
 * umbrella out exactly as --only leaves out a non-matching group. */
static size_t fold_umbrellas_into_shards(struct group_result *results,
                                         bool only_exact)
{
    size_t folded = 0;
    if (only_exact)
        return 0;
    for (size_t i = 0; i < g_num_groups; i++) {
        if (results[i].skipped ||
            !zcl_test_group_umbrella_subsumed(g_groups[i].name,
                                              group_still_selected, results))
            continue;
        results[i].status = 0;
        results[i].skipped = 1;
        folded++;
        printf("test_parallel: %s runs as its %zu shards "
               "(--exact=%s runs it whole)\n", g_groups[i].name,
               zcl_test_group_umbrella_shard_count(g_groups[i].name),
               g_groups[i].name);
    }
    return folded;
}

/* True when the len bytes at p exactly name a registered group. */
static bool exact_selector_name_known(const char *p, size_t len)
{
    if (len == 0)
        return false;
    for (size_t i = 0; i < g_num_groups; i++) {
        if (strlen(g_groups[i].name) == len &&
            memcmp(g_groups[i].name, p, len) == 0)
            return true;
    }
    return false;
}

/* Fail before dispatch if an exact set names even one absent group. Without
 * this preflight, "valid,stale" would run the valid member and still report a
 * green suite — the multi-group version of the substring false-green. */
static bool exact_selector_set_valid(const char *selectors,
                                     const char **missing, size_t *missing_len)
{
    if (missing) *missing = NULL;
    if (missing_len) *missing_len = 0;
    if (!selectors || !selectors[0])
        return false;
    size_t selectors_len = strlen(selectors);
    if (selectors[0] == ',' || selectors[selectors_len - 1] == ',' ||
        strstr(selectors, ",,") != NULL)
        return false;
    const char *p = selectors;
    while (*p) {
        const char *end = strchr(p, ',');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (!exact_selector_name_known(p, len)) {
            if (missing) *missing = p;
            if (missing_len) *missing_len = len;
            return false;
        }
        if (!end)
            break;
        p = end + 1;
    }
    return true;
}

static void run_group_exclusive(size_t idx, pid_t parent_pid,
                                struct group_result *results,
                                int timeout_secs, bool verbose,
                                bool activate_proof_contracts)
{
    char out_path[128];
    make_tempfile_path(out_path, sizeof(out_path), idx, parent_pid);
    results[idx].start = platform_time_wall_time_t();

    zcl_child_t child = ZCL_CHILD_NONE;
    if (child_spawn(idx, out_path, activate_proof_contracts, &child) != 0) {
        results[idx].status = 1;
        results[idx].signaled = 0;
        results[idx].exit_code = 2;
        return;
    }
    if (verbose) {
#if defined(_WIN32)
        printf("[exclusive] [%zu] %s handle=%p\n", idx, g_groups[idx].name,
               (void *)child);
#else
        printf("[exclusive] [%zu] %s pid=%d\n", idx, g_groups[idx].name,
               (int)child);
#endif
    }

    int status = 0;
    bool killed = false;
    bool successfully_reaped = false;
    for (;;) {
        int pr = child_poll(child, &status);
        if (pr == 1) {
            successfully_reaped = true;
            break;
        }
        if (pr < 0) {
            status = 1;
            break;
        }
        time_t now = platform_time_wall_time_t();
        if (!killed &&
            group_watchdog_expired(&results[idx], out_path, now, timeout_secs)) {
            memcpy(results[idx].out_path, out_path,
                   sizeof(results[idx].out_path));
            results[idx].wedged = 1;
            print_watchdog_kill(idx, g_groups[idx].name, &results[idx], now,
                                timeout_secs);
            child_kill(child);
            killed = true;
        }
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    child_close(child);

    results[idx].status = status;
    if (WIFSIGNALED(status)) {
        results[idx].signaled = 1;
        results[idx].exit_code = WTERMSIG(status);
    } else {
        results[idx].signaled = 0;
        results[idx].exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }
    memcpy(results[idx].out_path, out_path, sizeof(results[idx].out_path));
    time_t now = platform_time_wall_time_t();
    results[idx].wall_seconds = (double)(now - results[idx].start);
    if (successfully_reaped)
        results[idx].measured = 1;
}

enum pool_phase {
    POOL_PHASE_QUIET_LINT = 1,
    POOL_PHASE_GENERAL = 2,
};

static bool pool_phase_selects(enum pool_phase phase, const char *name)
{
    bool quiet = group_requires_quiet_pool(name);
    return phase == POOL_PHASE_QUIET_LINT ? quiet : !quiet;
}

/* One whole line per finished phase: its makespan is the number the
 * dispatch order exists to shrink, so every transcript carries it. */
static void print_phase_done(enum pool_phase phase, size_t groups,
                             int64_t start_us)
{
    int64_t elapsed_us = platform_time_monotonic_us() - start_us;
    printf("test_parallel: %s phase done groups=%zu makespan_s=%.1f\n",
           phase == POOL_PHASE_QUIET_LINT ? "quiet-lint" : "general",
           groups, (double)elapsed_us / 1e6);
}

/* Shared state for one phase's dispatch, watchdog and reap steps. */
struct phase_run {
    enum pool_phase phase;
    struct child_slot *slots;
    int jobs;
    pid_t parent_pid;
    struct group_result *results;
    int timeout_secs;
    bool verbose;
    bool activate_proof_contracts;
};

/* Fill free slots with the next admissible groups. False: a spawn failed. */
static bool phase_dispatch_ready(const struct phase_run *pr, size_t *next_pos)
{
    while (*next_pos < g_num_groups) {
        size_t next_idx = g_dispatch_order[*next_pos];
        if (pr->results[next_idx].status != -1 ||
            !pool_phase_selects(pr->phase, g_groups[next_idx].name)) {
            (*next_pos)++;
            continue;
        }
        int slot = find_free_slot(pr->slots, pr->jobs);
        if (slot < 0) break;
        if (!phase_memory_admits(pr->slots, pr->jobs, next_idx)) break;
        make_tempfile_path(pr->slots[slot].out_path,
                           sizeof(pr->slots[slot].out_path),
                           next_idx, pr->parent_pid);
        pr->results[next_idx].start = platform_time_wall_time_t();
        if (child_spawn(next_idx, pr->slots[slot].out_path,
                        pr->activate_proof_contracts,
                        &pr->slots[slot].pid) != 0)
            return false;
        pr->slots[slot].group_idx = next_idx;
        pr->slots[slot].start_us = platform_time_monotonic_us();
        if (pr->verbose) {
            const char *label = pr->phase == POOL_PHASE_QUIET_LINT
                ? "quiet" : "dispatch";
#if defined(_WIN32)
            printf("[%-8s] [%zu/%zu] handle=%p %s\n",
                   label, next_idx + 1, g_num_groups,
                   (void *)pr->slots[slot].pid,
                   g_groups[next_idx].name);
#else
            printf("[%-8s] [%zu/%zu] pid=%d %s\n",
                   label, next_idx + 1, g_num_groups, pr->slots[slot].pid,
                   g_groups[next_idx].name);
#endif
        }
        (*next_pos)++;
    }
    return true;
}

static void phase_watchdog_sweep(const struct phase_run *pr)
{
    time_t now_tick = platform_time_wall_time_t();
    for (int i = 0; i < pr->jobs; i++) {
        if (pr->slots[i].pid == ZCL_CHILD_NONE) continue;
        size_t idx = pr->slots[i].group_idx;
        if (pr->results[idx].wedged) continue;   /* already killed, awaiting reap */
        if (!group_watchdog_expired(&pr->results[idx], pr->slots[i].out_path,
                                    now_tick, pr->timeout_secs))
            continue;
        memcpy(pr->results[idx].out_path, pr->slots[i].out_path,
               sizeof(pr->results[idx].out_path));
        pr->results[idx].wedged = 1;
        print_watchdog_kill(idx, g_groups[idx].name, &pr->results[idx],
                            now_tick, pr->timeout_secs);
        child_kill(pr->slots[i].pid);
    }
}

/* Record one reaped slot's exit status and capture into its group result. */
static void phase_record_reaped(const struct phase_run *pr, int slot, int status,
                                int64_t peak_bytes)
{
    size_t idx = pr->slots[slot].group_idx;
    struct group_result *r = &pr->results[idx];
    child_close(pr->slots[slot].pid);
    if (peak_bytes >= (INT64_C(256) << 20))
        printf("test_parallel: peak RSS group=%s %lld MiB\n",
               g_groups[idx].name, (long long)(peak_bytes >> 20));
    runner_admission_note_peak(peak_bytes, true, &g_group_peak_bytes[idx],
                               &g_group_done_bytes[idx], &g_pool_peak_bytes);
    r->status = status;
    if (WIFSIGNALED(status)) {
        r->signaled = 1;
        r->exit_code = WTERMSIG(status);
    } else {
        r->signaled = 0;
        r->exit_code = WIFEXITED(status)
            ? WEXITSTATUS(status) : -1;
    }
    memcpy(r->out_path, pr->slots[slot].out_path,
           sizeof(r->out_path));
    time_t now = platform_time_wall_time_t();
    r->wall_seconds = (double)(now - r->start);
    r->measured = 1;
    if (pr->verbose)
        printf("[done    ] [%zu] %s (%s, %.0fs)\n",
               idx, g_groups[idx].name,
               r->wedged ? "WEDGED (no output)" :
               r->signaled ? "SIGNALED" :
               (r->exit_code == 0 ? "PASS" : "FAIL"),
               r->wall_seconds);
    pr->slots[slot].pid = ZCL_CHILD_NONE;
}

/* Run one bounded parallel phase. The quiet lint phase and general phase use
 * the same fork, timeout, capture, and accounting machinery; only group
 * admission differs. That makes isolation a scheduling fact, never a timeout
 * exemption or a second test runner. */
static bool run_parallel_phase(
    enum pool_phase phase, struct child_slot *slots, int jobs,
    pid_t parent_pid, struct group_result *results, int timeout_secs,
    bool verbose, bool activate_proof_contracts, size_t *reaped)
{
    size_t remaining = 0;
    for (size_t i = 0; i < g_num_groups; i++)
        if (results[i].status == -1 &&
            pool_phase_selects(phase, g_groups[i].name))
            remaining++;
    const size_t phase_groups = remaining;
    const int64_t phase_start_us = platform_time_monotonic_us();
    struct phase_run pr = {
        .phase = phase, .slots = slots, .jobs = jobs,
        .parent_pid = parent_pid, .results = results,
        .timeout_secs = timeout_secs, .verbose = verbose,
        .activate_proof_contracts = activate_proof_contracts,
    };
    /* Walk the longest-expected-first permutation, not the catalog. */
    size_t next_pos = 0;
    while (remaining > 0) {
        if (!phase_dispatch_ready(&pr, &next_pos))
            return false;
        phase_watchdog_sweep(&pr);
        phase_memory_sample(slots, jobs);

        int status = 0;
        int64_t peak_bytes = 0;
        int slot = reap_any(slots, jobs, &status, &peak_bytes);
        if (slot == -2) {
            struct timespec ts = {
                .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000,
            };
            nanosleep(&ts, NULL);
            continue;
        }
        if (slot < 0) {
            if (slot == -1)
                return false;
            continue;   /* reaped a slot-less child; nothing to record */
        }
        phase_record_reaped(&pr, slot, status, peak_bytes);
        remaining--;
        (*reaped)++;
    }
    print_phase_done(phase, phase_groups, phase_start_us);
    return true;
}

/* ── Rerun-alone: a failed/wedged group gets one clean shot before it counts
 * ──────────────────────────────────────────────────────────────────────────
 *
 * Two red proofs on the same day were both a group that fails only under an
 * 8-worker contended pool and passes every time alone: a socket-deadline
 * case in test_file_market_delivery, and (earlier) test_zcode_swarm_net and
 * test_block_parse_cache going silent long enough to trip the watchdog. Each
 * red throws away a ~15-minute proof for a defect that is really "this
 * assertion assumes it has the CPU/scheduler to itself", not a code
 * regression.
 *
 * The fix is not raising bounds (that just moves the cliff — see
 * group_watchdog_expired's own rationale) and not silently retrying inside
 * the group (that would hide a real intermittent failure as a clean PASS).
 * Instead: after the shared pool finishes, every group that FAILed or was
 * WEDGED gets re-run EXACTLY ONCE, alone, with the pool otherwise idle
 * (run_group_exclusive — the same machinery host-latency-sensitive groups
 * already use). Three outcomes:
 *
 *   - fail again alone  -> stays FAIL. A real regression cannot hide behind
 *     this policy: it still has to fail once with no contention as an excuse.
 *   - pass alone         -> counts as PASS for the suite verdict, but
 *     load_flaky stays set forever on this result. The verdict line, the
 *     cache, and a cache HIT on a later run all keep saying so — a load-flaky
 *     group is never allowed to look like an ordinary green group.
 *
 * The first (contended) attempt's capture is preserved under a ".first" name
 * before the alone rerun reuses the same tempfile path, so both attempts stay
 * inspectable. Groups that already ran exclusively (group_requires_exclusive_run)
 * are excluded: they already ran with the pool idle, so a second alone run
 * would prove nothing new.
 *
 * A group whose first attempt PASSED but printed one or more "UNOBSERVED ("
 * lines gets the same one-shot rerun-alone treatment: the assertions already
 * passed, but a load-dependent leg (a bootstrap window, a timing budget)
 * never got its observation inside the shared pool's contention. If the
 * alone rerun passes AND prints zero UNOBSERVED lines, the leg is fully
 * observed now — env_unobserved drops to 0 for this group — but the result
 * is marked load_unobserved (and, for reporting parity, load_flaky) so it
 * never looks like an ordinary silent pass, and it is barred from the
 * verdict store outright (see the cache-accounting gate): a busy box must
 * never mint a cached receipt for a leg it only observed once, under
 * pressure to retry. If the alone rerun is still UNOBSERVED, or fails, the
 * alone attempt's own result stands unmodified — the box genuinely could
 * not observe the leg, and that is reported like any other run. */
/* True for a group rerun_load_flaky_groups must leave untouched: already
 * skipped/cached, required to run exclusively already (a second alone run
 * would prove nothing new), or SIGNALED for a reason the harness did not
 * cause (SIGSEGV/SIGABRT/SIGBUS/SIGFPE, or a SIGKILL nobody in this process
 * sent) — a real crash, not a load casualty, that stays a hard failure with
 * no rerun. Only `wedged` — set exactly where the per-group deadline
 * watchdog's own kill fires (group_watchdog_expired's call sites) — proves
 * the harness itself sent the kill; inferring that from the signal number
 * alone would also excuse an actual crash. */
static bool group_excluded_from_rerun(const struct group_result *r,
                                      const char *name)
{
    return r->skipped || r->cached || group_requires_exclusive_run(name) ||
           (r->signaled && !r->wedged);
}

/* The ".first" capture lives in the run's scratch root, which a proof
 * generation deletes with everything else — so the failing assertion of a
 * LOAD-FLAKY first attempt must be copied into the runner's own output or it
 * is lost. Bounded: at most LOAD_FLAKY_EXCERPT_MARKS early failure lines plus
 * the last LOAD_FLAKY_EXCERPT_TAIL lines, each line length-capped. */
#define LOAD_FLAKY_EXCERPT_MARKS 20
#define LOAD_FLAKY_EXCERPT_TAIL 40
static void print_load_flaky_first_excerpt(const char *name,
                                           const char *preserved_log)
{
    if (!preserved_log[0]) return;
    printf("LOAD-FLAKY-FIRST %s: failure lines and last %d lines of the "
           "contended attempt:\n", name, LOAD_FLAKY_EXCERPT_TAIL);
    size_t shown = testcache_print_log_excerpt(stdout, preserved_log,
                                               "  first| ",
                                               LOAD_FLAKY_EXCERPT_MARKS,
                                               LOAD_FLAKY_EXCERPT_TAIL);
    if (shown == 0) printf("  first| (empty or unreadable)\n");
}

static void preserve_retry_first(const char *name, const char *first,
                                  char preserved[144])
{
    if (!first[0]) return;
#if defined(__linux__)
    g_tmpfs_retained = true;
#endif
    print_load_flaky_first_excerpt(name, first);
    snprintf(preserved, 144, "%s.first", first);
    if (rename(first, preserved) != 0) {
        printf("RETRY-FIRST-PRESERVE-FAILED %s path=%s error=%s; "
               "first attempt excerpt retained above\n", name, first, strerror(errno));
        preserved[0] = '\0';
    } else {
        printf("RETRY-FIRST-PRESERVED %s first_log=%s\n", name, preserved);
    }
    fflush(stdout);
}

/* The "[rerun-alone]" announcement that opens one alone retry. */
static void rerun_announce(size_t i, const char *name, bool first_unobserved,
                           bool first_wedged)
{
    printf("[rerun-alone] [%zu] %s — first attempt %s under the shared "
           "pool; retrying alone with the pool idle (at most once)\n",
           i, name,
           first_unobserved ? "printed UNOBSERVED"
                             : (first_wedged ? "was WEDGED" : "FAILED"));
    fflush(stdout);
}

/* One clean, independent alone attempt at group i, with fresh state. */
static void rerun_attempt_alone(struct group_result *results, size_t i,
                                pid_t parent_pid, int timeout_secs,
                                bool verbose, bool activate_proof_contracts)
{
    /* Fresh watchdog/result state for a clean, independent attempt. */
    memset(&results[i], 0, sizeof(results[i]));
    results[i].status = -1;
    run_group_exclusive(i, parent_pid, results, timeout_secs, verbose,
                        activate_proof_contracts);
}

/* A FAIL or WEDGED first attempt that passed alone: load-flaky, not a fail. */
static void rerun_settle_flaky_pass(struct group_result *results, size_t i,
                                    const char *preserved_log,
                                    bool first_wedged)
{
    results[i].load_flaky = 1;
    results[i].flaky_first_wedged = first_wedged;
    snprintf(results[i].flaky_first_log,
            sizeof(results[i].flaky_first_log), "%s",
            preserved_log[0] ? preserved_log : "(unavailable)");
    printf("LOAD-FLAKY %s first=%s alone=PASS first_log=%s "
          "alone_log=%s\n",
          g_groups[i].name, first_wedged ? "WEDGED" : "FAIL",
          results[i].flaky_first_log,
          results[i].out_path[0] ? results[i].out_path : "(none)");
    fflush(stdout);
}

static void rerun_load_flaky_groups(struct group_result *results,
                                    pid_t parent_pid, int timeout_secs,
                                    bool verbose, bool activate_proof_contracts)
{
    for (size_t i = 0; i < g_num_groups; i++) {
        if (group_excluded_from_rerun(&results[i], g_groups[i].name)) continue;

        bool first_pass = !results[i].signaled && results[i].exit_code == 0;
        bool first_unobserved = false;
        if (first_pass) {
            int fu = results[i].out_path[0]
                ? count_marker_lines(results[i].out_path, "UNOBSERVED (") : 0;
            if (fu == 0) continue; /* an ordinary pass: nothing to rerun */
            first_unobserved = true;
        }

        bool first_wedged = results[i].wedged != 0;
        char first_log[128];
        snprintf(first_log, sizeof(first_log), "%s", results[i].out_path);
        char preserved_log[144] = "";
        preserve_retry_first(g_groups[i].name, first_log, preserved_log);

        rerun_announce(i, g_groups[i].name, first_unobserved, first_wedged);
        rerun_attempt_alone(results, i, parent_pid, timeout_secs, verbose,
                            activate_proof_contracts);

        bool alone_pass = !results[i].signaled && results[i].exit_code == 0;

        if (first_unobserved) {
            int alone_unobserved = results[i].out_path[0]
                ? count_marker_lines(results[i].out_path, "UNOBSERVED (") : 0;
            if (alone_pass && alone_unobserved == 0) {
                results[i].load_flaky = 1;
                results[i].load_unobserved = 1;
                snprintf(results[i].flaky_first_log,
                        sizeof(results[i].flaky_first_log), "%s",
                        preserved_log[0] ? preserved_log : "(unavailable)");
                printf("LOAD-UNOBSERVED %s first=UNOBSERVED alone=OBSERVED "
                      "first_log=%s alone_log=%s\n",
                      g_groups[i].name, results[i].flaky_first_log,
                      results[i].out_path[0] ? results[i].out_path : "(none)");
                fflush(stdout);
            }
            continue;
        }

        if (alone_pass) {
            rerun_settle_flaky_pass(results, i, preserved_log, first_wedged);
        } else {
            /* Still a hard failure alone too: record whether the first
             * attempt was a deadline kill so the failed-groups report can
             * say "timed out ... retried alone" instead of a plain FAIL. */
            results[i].flaky_first_wedged = first_wedged;
        }
    }
}

/* Prefix line for one entry in the "Failed groups:" report. A group whose
 * first (contended) attempt was killed by the harness's own per-group
 * deadline — flaky_first_wedged, set in rerun_load_flaky_groups only for a
 * group that stayed FAIL after its one alone retry — reads differently from
 * an ordinary FAIL/signal: it names the deadline and says a retry already
 * happened, so a reader does not chase a hang that was actually the box's
 * load. The signal/code suffix is printed by the caller either way. */
static void print_failed_group_prefix(const char *name,
                                      const struct group_result *r,
                                      int timeout_secs)
{
    if (r->flaky_first_wedged)
        printf("  - %s: timed out after %ds under the shared pool; retried "
               "alone, still %s",
               name, timeout_secs, r->signaled ? "signaled" : "exit");
    else
        printf("  - %s: %s", name, r->signaled ? "signaled" : "exit");
}

/* What a run actually DID, as opposed to what it concluded. Carried to both the
 * terminal (the SUITE VERDICT line) and .cache/test-timing/last-run.json so
 * neither can claim a cold pass for a run that executed almost nothing. */
struct suite_verdict {
    const char *mode;          /* "cold" | "cached" */
    size_t groups_total;
    size_t groups_ran;         /* actually forked */
    size_t groups_cached;      /* returned from cache, never forked */
    size_t groups_gated;       /* selector / params-heavy: excluded up front */
    size_t groups_cacheable;   /* probed cacheable this run */
    int    groups_failed;
    int    self_skips;         /* groups printing an in-test SKIP marker */
    int    env_unobserved;    /* groups that ran but could not observe a leg */
    int    load_flaky;        /* FAIL/WEDGED under the pool, PASS alone (this
                                * run's rerun, or a cache hit on a prior one) */
    char   toolkey[13];
};

static bool g_hotswap_module_active;
static char g_hotswap_module_sha[65];
static char g_hotswap_module_source[256];

static bool timing_json_string(FILE *fp, const char *text)
{
    char escaped[1537];
    if (!fp || !text || strnlen(text, 256) >= 256)
        return false;
    (void)log_json_escape(escaped, sizeof(escaped), text);
    return fprintf(fp, "\"%s\"", escaped) >= 0;
}

/* ZCL_TEST_TIMING_DIR redirects the report so a test that starts a nested
 * runner can read its own file instead of racing every other runner on the
 * shared default. Unset or empty keeps today's path. Returns the directory
 * after creating it, or NULL (already reported) on failure. */
static const char *test_timing_dir_prepare(void)
{
    const char *redirect = getenv("ZCL_TEST_TIMING_DIR");
    if (redirect && redirect[0] != '\0') {
        if (platform_directory_create(redirect, 0755) != 0 &&
            errno != EEXIST) {
            perror("test_parallel: mkdir ZCL_TEST_TIMING_DIR");
            return NULL;
        }
        return redirect;
    }
    const char *dir = ".cache/test-timing";
    if (platform_directory_create(".cache", 0755) != 0 && errno != EEXIST) {
        perror("test_parallel: mkdir .cache");
        return NULL;
    }
    if (platform_directory_create(dir, 0755) != 0 && errno != EEXIST) {
        perror("test_parallel: mkdir .cache/test-timing");
        return NULL;
    }
    return dir;
}

/* Whole-run facts the timing artifact reports alongside the per-group rows. */
struct timing_run {
    double startup_seconds;
    double wall_seconds;
    int jobs;
    size_t group_count;
    int failed_groups;
    size_t skipped_count;
    bool activate_proof_contracts;
    const struct suite_verdict *v;
};

static void timing_sort_slowest_first(size_t *order,
                                      const struct group_result *results,
                                      size_t group_count)
{
    for (size_t i = 0; i < group_count; i++)
        order[i] = i;
    /* Insertion sort by wall_seconds descending; skipped groups (never
     * measured) sort last. */
    for (size_t a = 1; a < group_count; a++) {
        size_t key = order[a];
        double key_w = results[key].skipped ? -1.0 : results[key].wall_seconds;
        size_t b = a;
        while (b > 0) {
            size_t prev = order[b - 1];
            double prev_w = results[prev].skipped ? -1.0 : results[prev].wall_seconds;
            if (prev_w >= key_w) break;
            order[b] = order[b - 1];
            b--;
        }
        order[b] = key;
    }
}

static bool timing_write_header(FILE *fp, const char *ts,
                                const struct timing_run *run)
{
    const struct suite_verdict *v = run->v;
    bool render_failed = false;
    fprintf(fp, "{\n");
    fprintf(fp, "  \"schema\":\"zcl.test_timing.v1\",\n");
    fprintf(fp, "  \"generated_at_utc\":\"%s\",\n", ts);
    fprintf(fp, "  \"startup_ms\":%lld,\n",
            (long long)(run->startup_seconds * 1000.0));
    fprintf(fp, "  \"test_body_ms\":%lld,\n",
            (long long)(run->wall_seconds * 1000.0));
    fprintf(fp, "  \"wall_ms\":%lld,\n", (long long)(run->wall_seconds * 1000.0));
    fprintf(fp, "  \"jobs\":%d,\n", run->jobs);
    fprintf(fp, "  \"group_count\":%zu,\n", run->group_count);
    fprintf(fp, "  \"failed_count\":%d,\n", run->failed_groups);
    fprintf(fp, "  \"skipped_count\":%zu,\n", run->skipped_count);
    /* The cache facts belong in the artifact, not only on the terminal: a
     * consumer of this file must be able to tell a run that EXECUTED 743 groups
     * from one that executed 1 and read 742 out of the cache. */
    fprintf(fp, "  \"mode\":\"%s\",\n", v->mode);
    fprintf(fp, "  \"groups_ran\":%zu,\n", v->groups_ran);
    fprintf(fp, "  \"groups_cached\":%zu,\n", v->groups_cached);
    fprintf(fp, "  \"groups_cacheable\":%zu,\n", v->groups_cacheable);
    fprintf(fp, "  \"toolkey\":\"%s\",\n", v->toolkey);
    fprintf(fp, "  \"self_skips\":%d,\n", v->self_skips);
    fprintf(fp, "  \"env_unobserved\":%d,\n", v->env_unobserved);
    fprintf(fp, "  \"load_flaky\":%d,\n", v->load_flaky);
    fprintf(fp, "  \"toolkey_full\":");
    if (!timing_json_string(fp, testcache_toolkey()))
        render_failed = true;
    return render_failed;
}

static bool timing_write_hotswap_fields(FILE *fp)
{
    bool render_failed = false;
    fprintf(fp, ",\n  \"hotswap_module_active\":%s,\n",
            g_hotswap_module_active ? "true" : "false");
    fprintf(fp, "  \"hotswap_module_sha256\":");
    if (g_hotswap_module_active) {
        if (!timing_json_string(fp, g_hotswap_module_sha))
            render_failed = true;
    }
    else
        fprintf(fp, "null");
    fprintf(fp, ",\n  \"hotswap_module_source\":");
    if (g_hotswap_module_active) {
        if (!timing_json_string(fp, g_hotswap_module_source))
            render_failed = true;
    }
    else
        fprintf(fp, "null");
    fprintf(fp, ",\n");
    return render_failed;
}

static void timing_write_input_key(FILE *fp,
                                   const struct testcache_probe *probe,
                                   bool key_valid)
{
    if (!key_valid) {
        fprintf(fp, "null");
        return;
    }
    fputc('"', fp);
    for (size_t b = 0; b < sizeof(probe->key); b++)
        fprintf(fp, "%02x", probe->key[b]);
    fputc('"', fp);
}

static void timing_write_group_row(FILE *fp, const struct group_result *r,
                                   const char *name,
                                   const struct testcache_probe *probe,
                                   bool activate_proof_contracts)
{
    long long ms = (long long)(r->wall_seconds * 1000.0);
    int rc = r->signaled ? -r->exit_code : r->exit_code;
    bool key_valid = !g_hotswap_module_active && probe && probe->key_valid;
    bool measured = r->measured != 0;
    enum zcl_test_proof_contract contract = activate_proof_contracts
        ? zcl_test_group_proof_contract(name)
        : ZCL_TEST_PROOF_NONE;
    fprintf(fp,
            "    {\"name\":\"%s\",\"ms\":%lld,\"rc\":%d,"
            "\"signaled\":%s,\"cached\":%s,\"measured\":%s,"
            "\"key_valid\":%s,\"input_key\":",
            name, ms, rc,
            r->signaled ? "true" : "false",
            r->cached ? "true" : "false",
            measured ? "true" : "false",
            key_valid ? "true" : "false");
    timing_write_input_key(fp, probe, key_valid);
    fprintf(fp,
            ",\"proof_contract\":%d,\"skip_markers\":%d,"
            "\"env_unobserved\":%d,\"load_flaky\":%d}",
            (int)contract, r->skip_markers,
            r->env_unobserved, r->load_flaky);
}

static void timing_write_groups(FILE *fp, const struct group_result *results,
                                const struct testcache_probe *probes,
                                const size_t *order,
                                const struct timing_run *run)
{
    fprintf(fp, "  \"groups\":[\n");
    int first = 1;
    for (size_t k = 0; k < run->group_count; k++) {
        size_t i = order[k];
        if (results[i].skipped)
            continue;
        if (!first)
            fprintf(fp, ",\n");
        first = 0;
        timing_write_group_row(fp, &results[i], g_groups[i].name,
                               probes ? &probes[i] : NULL,
                               run->activate_proof_contracts);
    }
    fprintf(fp, "\n  ]\n}\n");
}

static void timing_publish(const char *tmp_path, const char *final_path)
{
#if defined(_WIN32)
    /* Windows rename() refuses an existing target; the timing artifact is a
     * best-effort cache, so replacing last run's file is correct. */
    (void)remove(final_path);
#endif
    if (rename(tmp_path, final_path) != 0) {
        perror("test_parallel: rename timing artifact");
        (void)remove(tmp_path);
    }
}

/* Per-group JSON timing artifact — the same "make results visible so
 * regressions are visible" pattern as tools/lint/run_lint.sh's
 * .cache/lint-timing/last-run.json (schema zcl.lint_timing.v1), applied
 * to the parallel test runner: which test GROUP is the long pole. Written
 * once per invocation (a focused `make t-fast ONLY=X` writes its own
 * one-group snapshot too) — inspect with `jq . .cache/test-timing/
 * last-run.json`. Fixed-format printf, no JSON library, no new
 * dependency. Groups are ordered slowest-first (a plain insertion sort
 * over at most a few hundred entries — not worth a qsort comparator
 * closure). Best-effort: a write failure is reported but never fails
 * the run — this mutable diagnostic report is never signed evidence or an
 * admission authority. */
static void write_test_timing_json(const struct group_result *results,
                                   const struct testcache_probe *probes,
                                   bool activate_proof_contracts,
                                   double startup_seconds,
                                   double wall_seconds, int jobs,
                                   size_t group_count, int failed_groups,
                                   size_t skipped_count,
                                   const struct suite_verdict *v)
{
    const char *dir = test_timing_dir_prepare();
    if (!dir)
        return;

    size_t *order = malloc(group_count * sizeof(*order));
    if (!order) {
        fprintf(stderr, "test_parallel: timing order malloc failed\n");
        return;
    }
    timing_sort_slowest_first(order, results, group_count);

    char tmp_path[4200], final_path[4200];
    snprintf(tmp_path, sizeof(tmp_path), "%s/last-run.json.tmp", dir);
    snprintf(final_path, sizeof(final_path), "%s/last-run.json", dir);

    FILE *fp = fopen(tmp_path, "w");
    if (!fp) {
        perror("test_parallel: open timing tmp");
        free(order);
        return;
    }

    time_t now = platform_time_wall_time_t();
    struct tm tm_utc;
    if (!platform_time_utc_tm(now, &tm_utc)) {
        fprintf(stderr, "test_parallel: UTC timestamp conversion failed\n");
        fclose(fp);
        (void)remove(tmp_path);
        free(order);
        return;
    }
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);

    struct timing_run run = {
        .startup_seconds = startup_seconds, .wall_seconds = wall_seconds,
        .jobs = jobs, .group_count = group_count,
        .failed_groups = failed_groups, .skipped_count = skipped_count,
        .activate_proof_contracts = activate_proof_contracts, .v = v,
    };
    bool render_failed = timing_write_header(fp, ts, &run);
    if (timing_write_hotswap_fields(fp))
        render_failed = true;
    timing_write_groups(fp, results, probes, order, &run);
    bool write_failed = render_failed || ferror(fp) != 0;
    if (fclose(fp) != 0)
        write_failed = true;
    free(order);

    if (write_failed) {
        fprintf(stderr, "test_parallel: timing artifact write failed\n");
        (void)remove(tmp_path);
        return;
    }

    timing_publish(tmp_path, final_path);
}

/* Machine-readable verdict of THIS run: build/test-verdict.json (schema
 * zcl.test_verdict.v1), written on every run, pass or fail, beside the
 * SUITE VERDICT line. The host job ledger keeps command, rc and timings but no
 * output, so this file is what explains a failure after the fact. Best-effort:
 * a failed write prints one warning line and never changes the exit code. */
static void write_test_verdict_file(const struct group_result *results,
                                    const struct suite_verdict *v)
{
    const char *names[TEST_VERDICT_MAX_FAILED_NAMES];
    size_t n_names = 0;
    for (size_t i = 0; i < g_num_groups; i++) {
        if (results[i].skipped)
            continue;
        bool pass = !results[i].signaled && results[i].exit_code == 0;
        if (!pass && n_names < TEST_VERDICT_MAX_FAILED_NAMES)
            names[n_names++] = g_groups[i].name;
    }
    struct test_verdict_doc doc = {
        .mode = v->mode,
        .groups_total = v->groups_total,
        .groups_ran = v->groups_ran,
        .groups_cached = v->groups_cached,
        .groups_failed = (size_t)v->groups_failed,
        .failed_names = names,
        .failed_names_count = n_names,
        .toolkey = v->toolkey,
        .devbuild_lane = getenv("DEVBUILD_LANE"),
        .ended_unix = (long long)time(NULL),
    };
    static char body[40960];
    int len = test_verdict_json_format(body, sizeof(body), &doc);
    if (len < 0) {
        fprintf(stderr, "test_parallel: test verdict render failed; "
                        "build/test-verdict.json not written\n");
        return;
    }
    if (platform_directory_create("build", 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "test_parallel: mkdir build failed; "
                        "build/test-verdict.json not written\n");
        return;
    }

    /* Write-then-rename: a reader never sees a torn file. The pid in the tmp
     * name keeps two concurrent runners from sharing one tmp file. */
    char tmp_path[64];
    const char *final_path = "build/test-verdict.json";
    snprintf(tmp_path, sizeof(tmp_path), "build/test-verdict.json.tmp.%ld",
             (long)getpid());
    FILE *fp = fopen(tmp_path, "w");
    if (!fp) {
        fprintf(stderr, "test_parallel: cannot open %s: %s\n", tmp_path,
                strerror(errno));
        return;
    }
    bool wrote = fwrite(body, 1, (size_t)len, fp) == (size_t)len;
    if (fclose(fp) != 0)
        wrote = false;
    if (!wrote) {
        fprintf(stderr, "test_parallel: test verdict write failed: %s\n",
                tmp_path);
        (void)remove(tmp_path);
        return;
    }
#if defined(_WIN32)
    /* Windows rename() refuses an existing target; this file is replaced
     * wholesale on every run, so removing last run's copy is correct. */
    (void)remove(final_path);
#endif
    if (rename(tmp_path, final_path) != 0) {
        fprintf(stderr, "test_parallel: rename to %s failed: %s\n",
                final_path, strerror(errno));
        (void)remove(tmp_path);
    }
}

/* ── Module mode: run the real groups against a hot-swapped .so ────────────
 *
 * ZCL_HOTSWAP_TEST_MODULE=<abs path to module .so> makes this harness load the
 * module through THE production loader — hotswap_activate_local() in
 * engine/modules/hotswap/src/hotswap_activate.c, with the publish hooks from
 * tools/command/native_dev_hotswap.c — exactly as `zclassic23-dev` does for
 * ZCL_HOTSWAP_PRELOAD. Every production gate applies: path confinement, the
 * dev-datadir classification, ABI version, the engine/composition/hotswap_swappable.def
 * allowlist, leaf uniqueness, the module self_test, probe-before-publish
 * against the leaf's declared output schema, and the all-or-nothing registry
 * batch that re-checks READY + EFFECT_READ. There is NO test-only loader: a
 * module that would be refused in production is refused here, and this harness
 * then refuses to run at all rather than silently testing resident code.
 *
 * Divergence containment (see docs/dev/DEVELOPING.md "Module mode"):
 *   - the .so must live under the compile epoch this binary was built in
 *     (ZCL_TEST_COMPILE_EPOCH — a digest of the exact compiler, CFLAGS and
 *     LDFLAGS). Different flags => different epoch => refused, so the module's
 *     translation unit cannot have been compiled differently from the one the
 *     linked binary carries;
 *   - the run is never cached and never stores a cache entry;
 *   - the mode is stamped on the banner, the SUITE VERDICT line, and the
 *     headline, so module output can never be mistaken for a linked-binary run.
 *
 * Activation happens in the parent before any group is forked, so every worker
 * inherits both the mapping and the published overrides. */
#ifndef ZCL_TEST_COMPILE_EPOCH
#define ZCL_TEST_COMPILE_EPOCH ""
#endif

/* Returns false when module mode was requested but could not be honored — the
 * caller must exit non-zero rather than run against resident code. */
static bool hotswap_module_mode_begin(void)
{
    const char *so_path = getenv("ZCL_HOTSWAP_TEST_MODULE");
    if (!so_path || !so_path[0])
        return true; /* ordinary run against the linked binary */
    const char *authorization = getenv("ZCL_HOTSWAP_TEST_AUTH");
    if (!authorization ||
        strcmp(authorization, "explicit-t-hotswap-v1") != 0) {
        fprintf(stderr,
                "test_parallel: ZCL_HOTSWAP_TEST_MODULE requires the "
                "explicit t-hotswap authorization marker — refusing an "
                "inherited module in a linked-binary gate\n");
        return false;
    }

    const char *epoch = ZCL_TEST_COMPILE_EPOCH;
    if (!epoch[0]) {
        fprintf(stderr,
                "test_parallel: ZCL_HOTSWAP_TEST_MODULE set but this binary "
                "carries no compile epoch — refusing module mode\n");
        return false;
    }
    char needle[160];
    (void)snprintf(needle, sizeof(needle), "/%s/", epoch);
    if (!strstr(so_path, needle)) {
        fprintf(stderr,
                "test_parallel: module '%s' is not under this binary's compile "
                "epoch %s — its translation unit was built with different "
                "flags, so it could diverge from the linked binary. Refusing.\n"
                "  rebuild with: make hotswap-test-so FILE=<tu.c>\n",
                so_path, epoch);
        return false;
    }

    /* The loader classifies the datadir as a pure string (it is never opened
     * on this path — activate_run() only calls hotswap_datadir_is_dev on it).
     * Name the dev lane's path so the classification matches what production
     * requires; no datadir is created, read, or written by this harness. */
    const char *home = getenv("HOME");
    char dev_datadir[PATH_MAX];
    (void)snprintf(dev_datadir, sizeof(dev_datadir), "%s/.zclassic-c23-dev",
                   home && home[0] ? home : "");

    zcl_command_registry_set_active(zcl_command_catalog());

    struct hotswap_publish_hooks hooks;
    zcl_native_hotswap_publish_hooks(&hooks, /*with_quiesce=*/false);
    struct hotswap_activate_report report;
    bool ok = hotswap_activate_local(so_path, dev_datadir, &hooks, &report);
    zcl_native_hotswap_probe_rendered_clear();
    if (!ok || !report.activated) {
        fprintf(stderr,
                "test_parallel: HOT-SWAP REFUSED stage=%s error=%s module=%s\n",
                report.stage[0] ? report.stage : "activate",
                report.error[0] ? report.error : "(none)", so_path);
        return false;
    }

    g_hotswap_module_active = true;
    (void)snprintf(g_hotswap_module_sha, sizeof(g_hotswap_module_sha), "%s",
                   report.artifact_sha256);
    (void)snprintf(g_hotswap_module_source, sizeof(g_hotswap_module_source),
                   "%s", report.source_tu);
    printf("\n"
           "══════════════════ HOT-SWAP MODULE MODE ══════════════════\n"
           "  source_tu   %s\n"
           "  leaves      %s (%u)\n"
           "  probe_leaf  %s (probed=%s)\n"
           "  artifact    %s\n"
           "  sha256      %s\n"
           "  generation  %u\n"
           "  NOT a linked-binary run: these groups execute the module's\n"
           "  freshly compiled bodies. Re-run `make t-fast ONLY=<group>`\n"
           "  before treating any verdict as a gate.\n"
           "══════════════════════════════════════════════════════════\n\n",
           report.source_tu, report.leaves, report.leaf_count,
           report.probe_leaf, report.probed ? "yes" : "no", so_path,
           report.artifact_sha256, report.generation);
    return true;
}

/* Deep wallet groups overflow an 8 MiB stack and die with SIGSEGV, which reads
 * in a transcript as a real regression rather than as a missing shell setting.
 * Measured on this host with the stack hard limit pinned at 8 MiB, a full run
 * loses four groups this way — test_wallet_keystore,
 * test_simnet_wallet_import_backup, test_yardsale_wallet, test_vault_dispatch —
 * and loses none once the limit is raised. (Re-derive that list rather than
 * trusting it; the surviving folklore figure of "nine groups" no longer
 * matches what the suite actually does.)
 *
 * Makefile:2058 exports `ulimit -s unlimited` for `make test-parallel`, but the
 * documented way to run a subset is to invoke this binary directly, and that
 * path had no such protection: every caller who forgot the ulimit got four
 * plausible-looking crashes. So raise it here, where the program can do it for
 * itself, instead of leaving it an unwritten precondition on the caller.
 *
 * Raising the soft limit to the hard limit is enough on Linux and needs no
 * re-exec: the kernel checks the CURRENT RLIMIT_STACK when it expands the main
 * thread's stack VMA on a fault, not the value in force at execve. (Measured:
 * with soft=8 MiB / hard=unlimited a 1 MiB-per-frame recursion dies at 8
 * frames; after this call the same recursion passes 300.) Group children are
 * forked after this runs, so they inherit both the raised limit and the
 * parent's address-space layout.
 *
 * The Makefile's ulimit stays where it is. Two independent guards is the right
 * number for a failure whose symptom is indistinguishable from a real bug. */
static void raise_stack_limit(void)
{
#if !defined(_WIN32)
    struct rlimit limit;
    if (getrlimit(RLIMIT_STACK, &limit) != 0) {
        fprintf(stderr, "test_parallel: getrlimit(RLIMIT_STACK) failed: %s\n",
                strerror(errno));
        return;
    }
    if (limit.rlim_cur == limit.rlim_max)
        return;
    struct rlimit raised = limit;
    raised.rlim_cur = limit.rlim_max;
    if (setrlimit(RLIMIT_STACK, &raised) == 0)
        return;
    /* macOS refuses an unlimited main-thread stack (kern.maxssiz caps it), so
     * retry at the same large finite ceiling the release recipes use. */
    if (limit.rlim_max == RLIM_INFINITY) {
        raised.rlim_cur = (rlim_t)1024 * 1024 * 1024;
        if (raised.rlim_cur > limit.rlim_cur &&
            setrlimit(RLIMIT_STACK, &raised) == 0)
            return;
    }
    fprintf(stderr,
            "test_parallel: could not raise the stack soft limit from %llu to "
            "%llu (%s) — deep wallet/RPC groups may SIGSEGV; run under "
            "`ulimit -s unlimited`\n",
            (unsigned long long)limit.rlim_cur,
            (unsigned long long)limit.rlim_max, strerror(errno));
#endif
}

/* Selection retains the ordinary params opt-in even during a focused proof. */
static bool params_gated(const char *group)
{
    return getenv("ZCL_PARAMS_TESTS") == NULL && group_is_params_heavy(group);
}

static size_t params_gate_mark(struct group_result *results, const char *only)
{
    size_t gated = 0;
    if (only)
        return 0;
    for (size_t i = 0; i < g_num_groups; i++) {
        if (results[i].skipped || !params_gated(g_groups[i].name))
            continue;
        results[i].status = 0;
        results[i].skipped = 1;
        gated++;
    }
    return gated;
}

static size_t gate_params_groups(struct group_result *results,
                                const char *only)
{
    size_t gated = params_gate_mark(results, only);
    if (gated)
        printf("test_parallel: %zu params-heavy group(s) gated out "
               "(set ZCL_PARAMS_TESTS=1 or use --only/--exact to run)\n",
               gated);
    return gated;
}

/* --only=SUBSTR / --exact=FULL_ID[,FULL...]: mark every group the selector
 * does not carry so it is neither dispatched nor counted. Returns how many
 * were marked; no selector marks nothing. */
static size_t selector_premark(struct group_result *results, const char *only,
                               bool only_exact)
{
    size_t marked = 0;
    for (size_t i = 0; i < g_num_groups; i++) {
        if (test_group_selector_selects(g_groups[i].name, only, only_exact))
            continue;
        results[i].status = 0; /* excludes from dispatch loop */
        results[i].skipped = 1;
        marked++;
    }
    return marked;
}

static bool cache_snapshot_selection_valid(bool snapshot, size_t changed_count,
                                           bool cache_requested)
{
    return snapshot == (changed_count > 0) &&
           (!snapshot || cache_requested);
}

static bool exact_selection_valid(bool exact, const char *only)
{
    if (!exact) return true;
    const char *missing = NULL;
    size_t missing_len = 0;
    if (exact_selector_set_valid(only, &missing, &missing_len)) return true;
    fprintf(stderr, "test_parallel: --exact contains no registered group: "
                    "%.*s\n", (int)missing_len, missing ? missing : "");
    return false;
}

/* Every platform-qualified BUILD row bounds one distinct target. */
enum {
    BUILD_NEEDS_MAX = 0
#define ZCL_TEST_GROUP_NEED(id_, kind_, value_)
#define ZCL_TEST_GROUP_BUILD_NEED(id_, value_, target_) + 1
#include "test_group_host_needs.def"
#undef ZCL_TEST_GROUP_BUILD_NEED
#undef ZCL_TEST_GROUP_NEED
};
static_assert(BUILD_NEEDS_MAX > 0, "the declared BUILD catalog must be nonempty");

/* A matched group may declare no BUILD needs; an unmatched selector is
 * instead invalid, even when the collector returns an empty list. */
static bool build_needs_selection_valid(const char *only, bool only_exact)
{
    if (!only) return true;
    for (size_t i = 0; i < g_num_groups; i++) {
        if (test_group_selector_selects(g_groups[i].name, only, only_exact))
            return true;
    }
    fprintf(stderr, "test_parallel: --%s=%s matched no groups\n",
            only_exact ? "exact" : "only", only);
    return false;
}

/* --list-build-needs: print `<make-target> <path>` per BUILD need of the
 * groups this selector would dispatch (zcl_test_selection_build_needs, under
 * the same params gate), and nothing at all when they declare none. The
 * checkout-locked Makefile recipes (t, t-fast, t-fast-exact, test-parallel)
 * run one `make <target>` per line before the run and fail by name when the
 * path is still absent, so a local run builds what a landing proof's
 * test-needs step builds, from the same table. The runner itself never
 * builds: a proof execs it too. */
static int build_needs_list(const char *only, bool only_exact)
{
    struct zcl_test_group_host_need needs[BUILD_NEEDS_MAX];
    size_t n = 0;
    if (!exact_selection_valid(only_exact, only) ||
        !build_needs_selection_valid(only, only_exact) ||
        !zcl_test_selection_build_needs(only, only_exact,
                                        only ? NULL : params_gated, needs,
                                        BUILD_NEEDS_MAX, &n)) {
        fprintf(stderr, "test_parallel: build needs unresolved\n");
        return 2;
    }
    for (size_t k = 0; k < n; k++)
        printf("%s %s\n", needs[k].target, needs[k].value);
    return 0;
}

/* A cache hit, SKIP, load-flaky rerun, or missing closure is not a fresh
 * qualifying observation. The exact reason is returned before any signing. */
static const char *observation_ineligible_reason(
    const struct group_result *result, const struct testcache_probe *probe)
{
    if (!result->measured || result->cached)
        return "observation_not_independently_executed";
    if (result->skip_markers || result->env_unobserved ||
        result->load_flaky || result->load_unobserved || result->wedged)
        return "observation_execution_incomplete";
    if (!probe || !probe->key_valid)
        return "observation_input_closure_incomplete";
    return NULL;
}

static bool emit_one_group_observation(const char *name,
    const struct group_result *result, const struct testcache_probe *probe,
    const char *store_root)
{
    enum zcl_dev_verdict_leaf_verdict verdict =
        !result->signaled && result->exit_code == 0
            ? ZCL_DEV_VERDICT_LEAF_PASS : ZCL_DEV_VERDICT_LEAF_FAIL;
    uint8_t root[ZCL_DEV_PROOF_ROOT_BYTES];
    char why[96] = {0};
    uint64_t elapsed_ms = result->wall_seconds > 0
        ? (uint64_t)(result->wall_seconds * 1000.0) : 0;
    if (!zcl_dev_observation_record(store_root, probe->key, name,
            verdict, elapsed_ms, root, why, sizeof(why))) {
        printf("OBSERVATION REFUSE group=%s reason=%s\n", name,
               why[0] ? why : "observation_store_failed");
        return false;
    }
    enum zcl_dev_observation_verdict admitted =
        zcl_dev_observation_admit(store_root, probe->key, name,
            (const uint8_t (*)[32])&root, 1, NULL, why, sizeof(why));
    if (admitted != (verdict == ZCL_DEV_VERDICT_LEAF_PASS
                        ? ZCL_DEV_OBSERVATION_PASS
                        : ZCL_DEV_OBSERVATION_FAIL)) {
        printf("OBSERVATION REFUSE group=%s reason=%s\n", name,
               why[0] ? why : "observation_admission_mismatch");
        return false;
    }
    char root_hex[65], key_hex[65];
    zcl_hex_encode(root, sizeof(root), root_hex);
    zcl_hex_encode(probe->key, sizeof(probe->key), key_hex);
    printf("OBSERVATION group=%s verdict=%s key=%s root=%s "
           "source=independent_execution\n", name,
           verdict == ZCL_DEV_VERDICT_LEAF_PASS ? "PASS" : "FAIL",
           key_hex, root_hex);
    return true;
}

/* Where signed observation leaves land. A harness (the proof worker) names a
 * private CAS root so durable signed observations never share a tree with
 * the unsigned verdict records of this run's own cache store; a manual run
 * emits into the testcache store root it already opened. */
static const char *observation_store_root(struct testcache *tc)
{
    const char *env = getenv(ZCL_DEV_OBSERVATION_STORE_ENV);
    return (env && env[0]) ? env : testcache_store_root(tc);
}

static bool observation_known_denylist_omission(const char *name,
    const struct group_result *result, const struct testcache_probe *probe)
{
    return probe && testcache_group_is_denylisted(name) &&
           probe->code == TESTCACHE_R_EXTERNAL_INPUT && !probe->key_valid &&
           result->measured && !result->cached && !result->skip_markers &&
           !result->env_unobserved && !result->load_flaky &&
           !result->load_unobserved && !result->wedged;
}

static bool observation_options_valid(bool collect, bool emit,
                                      bool cold, bool exact)
{
    if (collect && emit) {
        fprintf(stderr, "test_parallel: choose complete emission or partial collection\n");
        return false;
    }
    if ((collect || emit) && (!cold || !exact)) {
        fprintf(stderr, "test_parallel: --emit-observations requires "
                        "--cold-audit and --exact\n");
        return false;
    }
    return true;
}

/* Self-admission proves runner bytes crossed CAS and the receiver codec. A
 * later proof set must still establish complete required roots and coverage. */
static int emit_group_observations(const struct group_result *results,
    const struct testcache_probe *probes, const char *store_root,
    bool collect_partial)
{
    int refused = 0;
    size_t eligible = 0, emitted = 0, unqualified = 0;
    for (size_t i = 0; i < g_num_groups; i++) {
        if (results[i].skipped) continue;
        const struct testcache_probe *probe = probes ? &probes[i] : NULL;
        const char *reason = observation_ineligible_reason(&results[i], probe);
        if (collect_partial && reason &&
            observation_known_denylist_omission(g_groups[i].name,
                                                &results[i], probe)) {
            printf("OBSERVATION UNQUALIFIED group=%s "
                   "reason=external_input_denylist coverage=missing\n",
                   g_groups[i].name);
            unqualified++;
        } else if (reason) {
            printf("OBSERVATION REFUSE group=%s reason=%s\n",
                   g_groups[i].name, reason);
            refused++;
        } else {
            eligible++;
            if (!emit_one_group_observation(g_groups[i].name, &results[i],
                                            probe, store_root))
                refused++;
            else
                emitted++;
        }
    }
    printf("OBSERVATION COVERAGE mode=%s eligible=%zu emitted=%zu unqualified=%zu "
           "refused=%d complete=%d\n",
           collect_partial ? "partial" : "complete", eligible, emitted, unqualified,
           refused, unqualified == 0 && refused == 0);
    return refused;
}

static bool selection_inspection_arg(const char *arg)
{
    return strcmp(arg, "--selection-only") == 0 || strcmp(arg, "--verbose") == 0 ||
        strcmp(arg, "--cache") == 0 || strcmp(arg, "--no-cache") == 0 ||
        strncmp(arg, "--jobs=", 7) == 0 || strncmp(arg, "--only=", 7) == 0 ||
        strncmp(arg, "--exact=", 8) == 0;
}

static bool selection_inspection_valid(int argc, char **argv)
{
    bool requested = false;
    for (int i = 1; i < argc; i++)
        requested |= strcmp(argv[i], "--selection-only") == 0;
    if (!requested) return true;
    if (getenv("ZCL_HOTSWAP_TEST_MODULE")) {
        fprintf(stderr, "selection-only refuses module activation\n");
        return false;
    }
    for (int i = 1; i < argc; i++) {
        if (!selection_inspection_arg(argv[i])) {
            fprintf(stderr, "selection-only refuses conflicting inspection or execution modes\n");
            return false;
        }
    }
    return true;
}

/* Cache accounting for one run: counters for the summary lines. */
struct cache_accounting {
    enum cache_mode mode;
    size_t cached_n;
    size_t ran;
    size_t stored;
    size_t audit_hits;
    int audit_diverged;
    int observation_refused;
};

/* Persist one fresh cacheable PASS, opening the store lazily on first use. */
static void store_fresh_pass(const struct group_result *results,
                             const struct testcache_probe *probes, size_t i,
                             struct testcache **tcp,
                             struct cache_accounting *acc)
{
    /* A flaky pass IS a pass — the group's actual code proved
     * itself, alone. But it must never come back on a later
     * cache hit looking indistinguishable from an ordinary
     * uncontended pass: store the flag alongside the verdict so
     * every future hit reprints LOAD-FLAKY (see the cache-hit
     * arm above). */
    /* Capsule-consumed runs arrive with no open handle: open
     * lazily on the first store so all-HIT cycles never pay an
     * open. A failed lazy open only loses future reuse, never
     * correctness — the PASS verdict already stands. */
    if (!*tcp) *tcp = testcache_open(NULL);
    struct testcache *tc = *tcp;
    if (tc) {
        if (results[i].load_flaky)
            testcache_store_pass_flaky(tc, probes[i].key);
        else
            testcache_store_pass(tc, probes[i].key);
        acc->stored++;
    }
}

/* One group the cache did not serve: store it if it is a reusable PASS, and
 * under cold-audit check a cache hit against this fresh verdict. */
static void account_group(const struct group_result *results,
                          const struct testcache_probe *probes, size_t i,
                          struct testcache **tc, struct cache_accounting *acc)
{
    bool pass = !results[i].signaled && results[i].exit_code == 0;
    /* A zero-exit group that printed SKIP did not prove its complete
     * contract. Never persist that partial run as a reusable PASS.
     * UNOBSERVED is the same story for a different reason: the group
     * ran and hard-asserted its load-free legs, but one leg never got
     * an observation. Caching that would let a busy box mint a receipt
     * a later run reuses as if the leg had been proven, so it is
     * barred from the cache exactly like a skip. It does NOT fail the
     * run — the box's spare capacity is not a code verdict. */
    /* A load-unobserved PASS (see rerun_load_flaky_groups) never
     * reaches the store at all, even though it passed with
     * env_unobserved == 0 here: the observation only happened once,
     * alone, under a busy box's own back-pressure, and a stored
     * receipt would let a later cache hit reuse it as if the leg
     * were reliably observed on this host. Ordinary load-flaky
     * PASSes (FAIL/WEDGED alone->PASS) are still cached, flagged, so
     * they keep reprinting LOAD-FLAKY on every future hit. */
    if (pass && results[i].skip_markers == 0 &&
        results[i].env_unobserved == 0 &&
        !results[i].load_unobserved && probes &&
        probes[i].cacheable) {
        store_fresh_pass(results, probes, i, tc, acc);
    }
    if (acc->mode == CACHE_COLD_AUDIT && probes &&
        probes[i].cacheable && probes[i].hit) {
        acc->audit_hits++;
        if (!pass) {
            acc->audit_diverged++;
            printf("COLD-AUDIT DIVERGENCE: %s carried a cached PASS at "
                   "its current key but FAILED a fresh run — the "
                   "closure/cache is UNSOUND\n", g_groups[i].name);
        }
    }
}

static void account_cache_run(const struct group_result *results,
                              const struct testcache_probe *probes,
                              struct testcache **tc,
                              struct cache_accounting *acc)
{
    for (size_t i = 0; i < g_num_groups; i++) {
        if (results[i].skipped) continue;
        if (results[i].cached) { acc->cached_n++; continue; }
        acc->ran++;
        account_group(results, probes, i, tc, acc);
    }
}

static void print_cache_summary(const struct cache_accounting *acc)
{
    printf("cached %zu / ran %zu%s\n", acc->cached_n, acc->ran,
           acc->mode == CACHE_COLD_AUDIT ? " [cold-audit]" : "");
    if (acc->mode == CACHE_COLD_AUDIT)
        printf("cold-audit: %zu cache-hit(s) verified against fresh runs, "
               "%d divergence(s)\n", acc->audit_hits, acc->audit_diverged);
    else if (acc->stored > 0)
        printf("cache: stored %zu fresh PASS verdict(s)\n", acc->stored);
}

/* Per-run counters filled by tally_group for the suite verdict. */
struct group_tally {
    int failed;
    int skip;
    int unobserved;
};

/* Load-flaky groups, counted from results so a cache hit that carries the
 * flag counts the same as a rerun that set it. */
static int count_load_flaky_groups(const struct group_result *results)
{
    int load_flaky_groups = 0;
    for (size_t i = 0; i < g_num_groups; i++) {
        if (results[i].load_flaky) load_flaky_groups++;
    }
    return load_flaky_groups;
}

static void print_group_banner(const char *name,
                               const struct group_result *r, bool pass,
                               const char *skip_note)
{
    printf("\n==================== %s (%s%s, %.0fs) ====================\n",
           name,
           r->wedged ? "WEDGED-NO-OUTPUT" :
           r->signaled ? "SIGNALED" :
           (pass ? "PASS" : "FAIL"),
           skip_note, r->wall_seconds);
}

static void tally_group(struct group_result *r, const char *name,
                        bool show_output, struct group_tally *t)
{
    bool pass = !r->signaled && r->exit_code == 0;
    r->skip_markers = r->out_path[0]
        ? count_marker_lines(r->out_path, "SKIP (") : 0;
    if (r->skip_markers > 0) t->skip++;
    r->env_unobserved = r->out_path[0]
        ? count_marker_lines(r->out_path, "UNOBSERVED (") : 0;
    if (r->env_unobserved > 0) t->unobserved++;
    char skip_note[32] = "";
    if (r->skip_markers > 0)
        snprintf(skip_note, sizeof(skip_note), ", %d SKIP",
                 r->skip_markers);
    if (!pass) t->failed++;
    if (show_output || !pass) {
        print_group_banner(name, r, pass, skip_note);
        print_captured(r->out_path);
    }
    /* A load-flaky PASS keeps its alone-run capture on disk (not just its
     * path string, already printed by the LOAD-FLAKY line above) so a
     * human can inspect it after the fact instead of only after the
     * process exits. */
    if (pass && !r->load_flaky && r->out_path[0])
        unlink(r->out_path);
}

static void print_suite_notes(const struct group_result *results,
                              int skip_groups, int unobserved_groups,
                              int load_flaky_groups)
{
    if (skip_groups > 0) {
        printf("Skipped coverage (self-skipped groups — most need "
               "ZCL_STRESS_TESTS=1 + an isolated run):\n");
        for (size_t i = 0; i < g_num_groups; i++) {
            if (results[i].skipped || results[i].skip_markers == 0) continue;
            printf("  - %s: %d skip marker(s)\n",
                   g_groups[i].name, results[i].skip_markers);
        }
    }
    if (unobserved_groups > 0) {
        printf("Unobserved legs (the group RAN and hard-asserted its load-free "
               "contract; an environment-dependent leg did not report "
               "in-window. Reported, not skipped, and never cached):\n");
        for (size_t i = 0; i < g_num_groups; i++) {
            if (results[i].skipped || results[i].env_unobserved == 0) continue;
            printf("  - %s: %d unobserved leg(s)\n",
                   g_groups[i].name, results[i].env_unobserved);
        }
    }
    if (load_flaky_groups > 0) {
        printf("Load-flaky groups (FAIL/WEDGED, or PASS-with-UNOBSERVED, "
               "under the shared pool; observed clean alone — counted as "
               "PASS, never a silent cache hit; see the LOAD-FLAKY / "
               "LOAD-UNOBSERVED lines above):\n");
        for (size_t i = 0; i < g_num_groups; i++) {
            if (results[i].skipped || !results[i].load_flaky) continue;
            printf("  - %s%s\n", g_groups[i].name,
                   results[i].load_unobserved ? " (was UNOBSERVED, never cached)"
                                               : "");
        }
    }
}

static void print_failed_groups_report(const struct group_result *results,
                                       int timeout_secs)
{
    printf("Failed groups:\n");
    for (size_t i = 0; i < g_num_groups; i++) {
        if (results[i].skipped) continue;
        bool pass =
            !results[i].signaled && results[i].exit_code == 0;
        if (pass) continue;
        print_failed_group_prefix(g_groups[i].name, &results[i],
                                  timeout_secs);
        if (results[i].signaled)
            printf(" signal=%d", results[i].exit_code);
        else
            printf(" code=%d", results[i].exit_code);
        if (results[i].out_path[0])
            printf(" log=%s", results[i].out_path);
        printf("\n");
        /* Exact focused rerun for this group — no whole-group wait.
         * Params-heavy groups (Groth16 proving; normally gated out
         * unless ZCL_PARAMS_TESTS/--only opted in) need the same env
         * opt-in on the rerun. */
        printf("      repro: %smake t-fast ONLY=%s\n",
               group_is_params_heavy(g_groups[i].name)
                   ? "ZCL_PARAMS_TESTS=1 " : "",
               g_groups[i].name);
    }
}

/* A stage of main that decides the run is over returns its exit code; a stage
 * that lets the run go on returns RUN_CONTINUE. */
enum { RUN_CONTINUE = -1 };

/* Everything main parses off the command line. */
struct run_opts {
    int jobs;
    int timeout_secs;
    bool verbose;
    bool list_only;
    bool selection_only;
    bool list_build_needs;
    const char *only; /* --only=SUBSTR or --exact=FULL_ID[,FULL...] */
    bool only_exact;
    /* Content-addressed test cache. Default OFF so the canonical push gate
     * stays COLD (a cached SKIP never gates a push). --cache / ZCL_TEST_CACHE=1
     * opt in for the inner dev loop; --no-cache forces off; --cold-audit runs
     * everything fresh and asserts every cache HIT matches its fresh verdict. */
    bool cli_cache;      /* --cache */
    bool cli_no_cache;   /* --no-cache */
    bool cli_cold_audit; /* --cold-audit */
    bool cli_probe_only; /* --cache-probe-only */
    bool cli_collect_observations;
    bool cli_emit_observations;
    struct capsule_state cap_state;
    bool activate_proof_contracts;
    bool cache_snapshot;
    const char *changed_sources[32];
    size_t changed_source_count;
};

/* The state the stages of main hand to one another. */
struct run_ctx {
    struct run_opts o;
    struct timespec process_start;
    struct timespec t_start;
    enum cache_mode cache_mode;
    struct group_result *results;
    size_t pre_skipped;
    struct testcache *tc;
    struct testcache_probe *probes;
    size_t cached_count;
    size_t cacheable_count;
    struct child_slot *slots;
    double startup_wall;
    pid_t parent_pid;
    size_t reaped;
    double wall;
    int failed_groups;
    int skip_groups;
    int unobserved_groups;
    int load_flaky_groups;
    struct suite_verdict verdict;
};

#if defined(_WIN32)
/* Fork-role dispatch: tests with a cross-process leg (SQLite owner lease,
 * kill -9 recovery, ...) re-exec this binary through
 * test_spawn_self_with_role(), which sets ZCL_TEST_FORK_GROUP/_ROLE. Run
 * the group DIRECTLY in this process — a second scheduler layer would put
 * a proxy between the parent and the worker and break the hard-kill
 * tests. The group entry branches on the role and runs only the child
 * body. Same chain/ecc/event setup as child_run. */
static bool main_fork_role(int *rc)
{
    const char *role = getenv("ZCL_TEST_FORK_ROLE");
    const char *gname = getenv("ZCL_TEST_FORK_GROUP");
    if (!(role && role[0])) return false;
    *rc = 2;
    if (!gname || !gname[0]) {
        fprintf(stderr, "test_parallel: ZCL_TEST_FORK_ROLE without "
                        "ZCL_TEST_FORK_GROUP\n");
        return true;
    }
    for (size_t i = 0; i < g_num_groups; i++) {
        if (strcmp(g_groups[i].name, gname) != 0) continue;
        chain_params_select(CHAIN_MAIN);
        ecc_start();
        ecc_verify_init();
        event_log_init();
        int failures = g_groups[i].fn();
        ecc_verify_destroy();
        ecc_stop();
        *rc = failures ? 1 : 0;
        return true;
    }
    fprintf(stderr, "test_parallel: ZCL_TEST_FORK_GROUP names no "
                    "registered group: %s\n", gname);
    return true;
}
#endif

/* Dispatch that must happen before any suite setup. True means main returns
 * *rc now. */
static bool main_early_modes(int argc, char **argv, int *rc)
{
    /* The confined-agent boundary re-execs THIS binary as the untrusted child
     * (session/agent_broker.h). It is dispatched before any test setup for the
     * same reason main.c dispatches it before node boot: the child arrives
     * already sandboxed, under a seccomp allow-list that would kill it for
     * most of what suite setup does. Never reached by an ordinary run. */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--metaverse-agent-confined") == 0) {
            *rc = agent_confined_mode_main(argc, argv);
            return true;
        }
    }
    /* The clean-zygote reflex runner re-execs THIS binary when a test drives
     * the resident runner client. Exact argv shape, dispatched before any
     * suite setup, exactly as main.c dispatches it before node boot. */
    zcl_reflex_runner_exit_if_requested(argc, argv);
#if defined(_WIN32)
    /* Windows worker entry. The parent cannot fork(), so child_spawn()
     * re-execs this binary with --child-run=<idx> --child-out=<path> per
     * group. Dispatch before any suite setup: child_run does its own
     * stdout/stderr redirection (same body the forked POSIX child runs), so
     * nothing may print before it. */
    if (child_dispatch(argc, argv)) {
        *rc = 2;
        return true;
    }
    if (main_fork_role(rc)) return true;
#endif
    if (argc == 2 && strcmp(argv[1], "--source-id") == 0) {
        printf("%s\n", zcl_build_source_id_sha256());
        *rc = 0;
        return true;
    }
    if (argc == 2 && strcmp(argv[1], "--source-record") == 0) {
        printf("%s 1 %s\n", zcl_build_source_id_sha256(),
               zcl_build_source_mutation_sha256());
        *rc = 0;
        return true;
    }
    return false;
}

/* --jobs=N, -jN, --timeout=SECS. */
static bool cli_parse_numeric(const char *a, struct run_opts *o)
{
    if (strncmp(a, "--jobs=", 7) == 0) {
        o->jobs = atoi(a + 7);
        snprintf(g_jobs_reason, sizeof g_jobs_reason, "explicit --jobs");
        if (o->jobs < 1) o->jobs = 1;
    } else if (strncmp(a, "-j", 2) == 0 && a[2]) {
        o->jobs = atoi(a + 2);
        snprintf(g_jobs_reason, sizeof g_jobs_reason, "explicit -j");
        if (o->jobs < 1) o->jobs = 1;
    } else if (strncmp(a, "--timeout=", 10) == 0) {
        o->timeout_secs = atoi(a + 10);
        if (o->timeout_secs < 1) o->timeout_secs = 1;
    } else {
        return false;
    }
    return true;
}

/* The flags that only set a mode. */
static bool cli_parse_mode(const char *a, struct run_opts *o)
{
    if (strcmp(a, "--verbose") == 0 ||
        strcmp(a, "-v") == 0) {
        o->verbose = true;
    } else if (strcmp(a, "--state-isolation-probe") == 0) {
        g_state_isolation_probe = true;
    } else if (retry_probe_parse(a)) {
        /* Internal fixture flags are validated together after parsing. */
    } else if (strcmp(a, "--list") == 0) {
        o->list_only = true;
    } else if (strcmp(a, "--selection-only") == 0) {
        o->selection_only = true;
    } else if (strcmp(a, "--list-build-needs") == 0) {
        o->list_build_needs = true;
    } else {
        return false;
    }
    return true;
}

/* --only= / --exact=: 0 not this flag, 1 taken, -1 refused. */
static int cli_parse_selector(const char *a, struct run_opts *o)
{
    bool exact = strncmp(a, "--exact=", 8) == 0;
    if (strncmp(a, "--only=", 7) != 0 && !exact) return 0;
    if (o->only) {
        fprintf(stderr,
                "test_parallel: pass only one of --only/--exact\n");
        return -1;
    }
    o->only = a + (exact ? 8 : 7);
    o->only_exact = exact;
    return 1;
}

/* --changed-source=: 0 not this flag, 1 taken, -1 refused. */
static int cli_parse_changed_source(const char *a, struct run_opts *o)
{
    if (strncmp(a, "--changed-source=", 17) != 0) return 0;
    const char *path = a + 17;
    if (!path[0] || path[0] == '/' || strstr(path, "..") ||
        strlen(path) >= 256 || o->changed_source_count >= 32) {
        fprintf(stderr,
                "test_parallel: invalid --changed-source path\n");
        return -1;
    }
    o->changed_sources[o->changed_source_count++] = path;
    return 1;
}

/* The cache, observation, capsule and proof-contract flags. */
static bool cli_parse_cache_flag(const char *a, struct run_opts *o)
{
    if (strcmp(a, "--cache") == 0) {
        o->cli_cache = true;
    } else if (strcmp(a, "--cache-snapshot") == 0) {
        o->cache_snapshot = true;
    } else if (strcmp(a, "--no-cache") == 0) {
        o->cli_no_cache = true;
    } else if (strcmp(a, "--cold-audit") == 0) {
        o->cli_cold_audit = true;
    } else if (strcmp(a, "--cache-probe-only") == 0) {
        o->cli_probe_only = true;
    } else if (strcmp(a, "--emit-observations") == 0) {
        o->cli_emit_observations = true;
    } else if (strcmp(a, "--collect-observations") == 0) {
        o->cli_collect_observations = true;
    } else if (cli_opt_capsule(a, &o->cap_state.cli)) {
        /* --write-capsule/--use-capsule/--capsule-*: honored only with
         * --cache; otherwise silently ignored like the cache env. */
    } else if (strcmp(a, "--activate-proof-contracts") == 0) {
        o->activate_proof_contracts = true;
    } else {
        return false;
    }
    return true;
}

/* One argument: 0 unknown, 1 taken, -1 refused. */
static int cli_parse_arg(const char *a, struct run_opts *o)
{
    if (cli_parse_numeric(a, o) || cli_parse_mode(a, o)) return 1;
    int r = cli_parse_selector(a, o);
    if (r != 0) return r;
    r = cli_parse_changed_source(a, o);
    if (r != 0) return r;
    return cli_parse_cache_flag(a, o) ? 1 : 0;
}

static void cli_usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [--jobs=N] [--timeout=SECS] [--verbose] "
            "[--list|--list-build-needs|--selection-only|--source-id|--source-record] "
            "[--only=SUBSTR|--exact=FULL_ID[,FULL...]] "
            "[--cache|--no-cache] "
            "[--cache-snapshot --changed-source=PATH] "
            "[--cold-audit] [--emit-observations|--collect-observations] "
            "[--activate-proof-contracts] "
            "[--cache-probe-only] "
            "[--write-capsule=PATH|--use-capsule=PATH "
            "--capsule-source-id=ID --capsule-mutation-id=ID "
            "--capsule-source-cas=HEX --capsule-graph-root=HEX]\n",
            argv0);
}

static int cli_parse(int argc, char **argv, struct run_opts *o)
{
    o->jobs = get_nproc();
    /* Per-group bound on SILENCE, not on runtime — see group_watchdog_expired
     * for the full rationale and the derivation. A group may run for as long
     * as it likes provided it keeps emitting; 300 s of a group producing
     * literally nothing is a hang. (--timeout= keeps its name for callers,
     * but it has never been a runtime budget since this changed.) */
    o->timeout_secs = 300;
    for (int i = 1; i < argc; i++) {
        int r = cli_parse_arg(argv[i], o);
        if (r < 0) return 2;
        if (r == 0) {
            cli_usage(argv[0]);
            return 2;
        }
    }
    return RUN_CONTINUE;
}

static int cli_validate(int argc, char **argv, struct run_opts *o)
{
    if (!retry_probe_admit(argc, argv)) return 2;
    if (o->list_build_needs) return build_needs_list(o->only, o->only_exact);
    if (!cache_snapshot_selection_valid(o->cache_snapshot,
                                        o->changed_source_count,
                                        o->cli_cache)) {
        fprintf(stderr, "test_parallel: cache snapshot requires --cache and "
                        "one or more --changed-source paths\n");
        return 2;
    }
    if (o->activate_proof_contracts &&
        (!o->only_exact || !zcl_test_group_proof_contracts_valid())) {
        fprintf(stderr,
                "test_parallel: --activate-proof-contracts requires an "
                "exact selector and a valid proof-contract catalog\n");
        return 2;
    }
    if (!observation_options_valid(o->cli_collect_observations,
                                   o->cli_emit_observations,
                                   o->cli_cold_audit, o->only_exact))
        return 2;
    o->cli_emit_observations |= o->cli_collect_observations;
    return RUN_CONTINUE;
}

/* Diagnostic surface: ZCL_TEST_CACHE_DUMP=<group> prints the group's forward
 * input closure, its content key, and its cacheability, then exits — the
 * operator/proof lens onto what the cache would key on. */
static int cache_dump_stage(const struct run_opts *o)
{
    const char *dump_group = getenv("ZCL_TEST_CACHE_DUMP");
    if (!o->selection_only && dump_group && dump_group[0]) {
        struct testcache *tc = testcache_open(NULL);
        if (!tc) {
            fprintf(stderr, "test_parallel: cache open failed for dump\n");
            return 1;
        }
        testcache_dump_group(tc, dump_group);
        testcache_close(tc);
        return 0;
    }
    return RUN_CONTINUE;
}

static int run_cache_mode(struct run_ctx *c)
{
    struct run_opts *o = &c->o;
    /* Resolve the cache mode. Precedence: --cold-audit > --no-cache >
     * (--cache | ZCL_TEST_CACHE!=0) > OFF. OFF reproduces the historical
     * behavior byte-for-byte (none of the cache code below runs). */
    c->cache_mode = runner_cache_mode(o->cli_cold_audit,
                                      o->cli_no_cache, o->cli_cache);
    /* A probe-only run reports what the cache WOULD reuse; with the cache
     * off or auditing there is nothing reusable to report. (Placed before
     * any allocation, so refusal here frees nothing.) */
    if (probe_only_refused(o->cli_probe_only, c->cache_mode == CACHE_ON)) {
        fprintf(stderr, "test_parallel: --cache-probe-only requires --cache "
                        "(--no-cache and --cold-audit probe nothing reusable)\n");
        return 2;
    }

    if (!o->list_only && !o->selection_only) {
        if (!hotswap_module_mode_begin())
            return 2;
        /* A verdict produced against a hot-swapped module must never be
         * reusable as a cached PASS for the linked binary, and must never be
         * served from one. */
        if (g_hotswap_module_active)
            c->cache_mode = CACHE_OFF;
    }

    if (o->cli_emit_observations && c->cache_mode != CACHE_COLD_AUDIT) {
        fprintf(stderr, "test_parallel: observation emission requires "
                        "an unchanged linked test image and cold audit\n");
        return 2;
    }
    return RUN_CONTINUE;
}

static int run_select(struct run_ctx *c)
{
    struct run_opts *o = &c->o;
    if (o->list_only) {
        for (size_t i = 0; i < g_num_groups; i++)
            printf("%s\n", g_groups[i].name);
        return 0;
    }

    if (!exact_selection_valid(o->only_exact, o->only)) return 2;

    setbuf(stdout, NULL);
    printf("test_parallel: %zu groups, %d workers, %ds per-group timeout "
           "(workers: %s)\n",
           g_num_groups, o->jobs, o->timeout_secs, g_jobs_reason);

    c->results = calloc(g_num_groups, sizeof(*c->results));
    if (!c->results) {
        fprintf(stderr, "test_parallel: calloc failed\n");
        return 1;
    }
    for (size_t i = 0; i < g_num_groups; i++) {
        c->results[i].status = -1;
    }

    /* --only=SUBSTR / --exact=FULL_ID[,FULL...]: pre-mark non-matching groups so
     * they are neither dispatched nor counted. Lets a dev iterate on one
     * group in ~seconds instead of waiting on the slowest group. Proof
     * automation uses --exact: a stale short id must not accidentally select
     * a differently named group and report green. */
    c->pre_skipped = selector_premark(c->results, o->only, o->only_exact);
    if (o->only && c->pre_skipped == g_num_groups) {
        fprintf(stderr, "test_parallel: --%s=%s matched no groups\n",
                o->only_exact ? "exact" : "only", o->only);
        free(c->results);
        return 2;
    }
    c->pre_skipped += fold_umbrellas_into_shards(c->results, o->only_exact);
    if (o->selection_only) {
        print_selected_groups(c->results);
        free(c->results);
        return 0;
    }
    ensure_tmp_dir();

    /* Params-heavy opt-in gate: exclude the Groth16-proving groups from a
     * default full run. They still run when ZCL_PARAMS_TESTS is set, or when
     * explicitly selected via --only/--exact (which leaves results[i].skipped
     * clear for the matching group). Folded into pre_skipped so they are not
     * dispatched and are excluded from the pass/fail denominator. */
    /* An explicit selector opts into its selected params-heavy group. */
    size_t params_gated = gate_params_groups(c->results, o->only);
    c->pre_skipped += params_gated;

    external_cache_prepare(c->results, c->pre_skipped, &c->cache_mode);
    return RUN_CONTINUE;
}

/* ── Content-addressed cache: probe every group's forward input closure,
 * and in CACHE_ON mark the provable HITS as CACHED so they are never
 * forked. Fail-safe: any open failure downgrades to CACHE_OFF (run all). */
static int cache_probes_alloc(struct run_ctx *c)
{
    c->probes = calloc(g_num_groups, sizeof(*c->probes));
    if (c->probes) return RUN_CONTINUE;
    if (c->o.cli_emit_observations) {
        fprintf(stderr, "OBSERVATION REFUSE reason=observation_probe_unavailable\n");
        free(c->results);
        return 1;
    }
    fprintf(stderr, "test_parallel: probe calloc failed — "
                    "running every group uncached\n");
    testcache_close(c->tc);
    c->tc = NULL;
    c->cache_mode = CACHE_OFF;
    return RUN_CONTINUE;
}

/* CACHE_ON: a provable stored PASS at the current key means the group
 * cannot have changed — mark it CACHED (status 0 excludes it from
 * dispatch; cached=1 records why). COLD_AUDIT never marks anything so
 * every group runs fresh and is verified after. */
static void cache_hits_mark(struct run_ctx *c)
{
    if (c->cache_mode != CACHE_ON) return;
    for (size_t i = 0; i < g_num_groups; i++)
        group_cache_hit_marked(c->results, i, c->probes, &c->cached_count);
}

static void cache_plan_tally(struct run_ctx *c, size_t *reason_hist)
{
    for (size_t i = 0; i < g_num_groups; i++) {
        if (c->results[i].skipped) continue;
        if (c->probes[i].cacheable) c->cacheable_count++;
    }
    for (size_t i = 0; i < g_num_groups; i++) {
        if (c->results[i].skipped) continue;
        if (c->probes[i].code < TESTCACHE_R__COUNT)
            reason_hist[c->probes[i].code]++;
    }
}

static void cache_plan_print(const struct run_ctx *c, const size_t *reason_hist)
{
    printf("test_parallel: cache PLAN — %zu cacheable, %zu cache HIT "
           "(will NOT run), %zu will run%s\n",
           c->cacheable_count, c->cached_count,
           g_num_groups - c->pre_skipped - c->cached_count,
           c->cache_mode == CACHE_COLD_AUDIT ? " [cold-audit: runs all]" : "");
    /* The uncacheable-reason histogram. probe.reason was already filled for
     * every group and thrown away; printing it is how a whole-run
     * degradation (an absent include graph making EVERY group uncacheable,
     * say) becomes visible instead of looking like a normal cold run. */
    printf("test_parallel: cacheability by reason:\n");
    for (int r = 0; r < TESTCACHE_R__COUNT; r++) {
        if (reason_hist[r] == 0) continue;
        printf("  %-32s %zu\n",
               testcache_reason_label((enum testcache_reason)r),
               reason_hist[r]);
    }
}

static void cache_plan_warn(const struct run_ctx *c, const size_t *reason_hist)
{
    /* Capsule-consumed runs revalidated against a live handle, so the
     * live dep-graph count is authoritative and the capsule's
     * mint-time count is zeroed at accept; the warnings below read
     * the same in both modes. */
    size_t plan_depfiles =
        testcache_depfile_count(c->tc) + c->o.cap_state.depfiles;
    if (plan_depfiles == 0)
        printf("test_parallel: !! NO DEPFILES under build/ — the include "
               "graph is ABSENT, so every group is UNCACHEABLE and the "
               "whole run is cold. Build first to restore caching. !!\n");
    else if (reason_hist[TESTCACHE_R_GRAPH_STALE] > 0)
        printf("test_parallel: !! %zu group(s) have inputs NEWER than the "
               "include graph (%zu depfiles) — the graph cannot describe "
               "them, so they are UNCACHEABLE. Rebuild to refresh. !!\n",
               reason_hist[TESTCACHE_R_GRAPH_STALE], plan_depfiles);
}

/* ── The PLAN, printed BEFORE dispatch ──────────────────────────────
 * Announcing "cached 742 / ran 1" only in the retrospective summary
 * means an operator watching a run cannot tell, while it is happening,
 * that almost nothing is being executed. Say it up front. */
static void cache_plan(struct run_ctx *c)
{
    size_t reason_hist[TESTCACHE_R__COUNT] = {0};
    cache_plan_tally(c, reason_hist);
    cache_plan_print(c, reason_hist);
    cache_plan_warn(c, reason_hist);
}

/* Probe acquisition: a validated capsule (no open at all), else
 * the one open plus the batch probe over the shared memo.
 * Fail-safe as before — any acquisition failure downgrades to
 * CACHE_OFF and runs everything, and the marking/PLAN below is
 * the else arm so a downgraded run prints no plan from zeroed
 * probes. */
static int cache_probes_acquire(struct run_ctx *c)
{
    struct run_opts *o = &c->o;
    if (acquire_probes(&c->tc, c->results, c->probes,
                       o->activate_proof_contracts, o->cache_snapshot,
                       o->changed_sources, o->changed_source_count,
                       &o->cap_state) == ACQUIRE_OK) {
        cache_hits_mark(c);
        cache_plan(c);
        return RUN_CONTINUE;
    }
    testcache_close(c->tc);
    c->tc = NULL;
    if (o->cli_emit_observations) {
        fprintf(stderr, "OBSERVATION REFUSE reason=observation_probe_unavailable\n");
        free(c->probes);
        free(c->results);
        return 1;
    }
    fprintf(stderr, "test_parallel: cache probe failed (open or "
                    "alloc) — running every group uncached\n");
    c->cache_mode = CACHE_OFF;
    return RUN_CONTINUE;
}

static int run_cache_probe(struct run_ctx *c)
{
    int rc;
    if (c->cache_mode != CACHE_OFF) {
        rc = cache_probes_alloc(c);
        if (rc != RUN_CONTINUE) return rc;
    }
    if (c->cache_mode != CACHE_OFF) {
        rc = cache_probes_acquire(c);
        if (rc != RUN_CONTINUE) return rc;
    }
    /* Probe-only: the batch verdicts above ARE the deliverable (the routed
     * set's preflight). Report them and exit before any fork: nothing here
     * runs, stores, or dispatches. After an allocation downgrade there is no
     * verified graph, so the report carries no SUMMARY and the caller's
     * self-check refuses it. */
    if (c->o.cli_probe_only) {
        print_probe_only(c->results, c->probes, c->tc);
        testcache_close(c->tc);
        free(c->probes);
        free(c->results);
        return 0;
    }
    return RUN_CONTINUE;
}

static int run_prepare(int argc, char **argv, struct run_ctx *c)
{
    int rc = cli_parse(argc, argv, &c->o);
    if (rc != RUN_CONTINUE) return rc;
    rc = cli_validate(argc, argv, &c->o);
    if (rc != RUN_CONTINUE) return rc;
    rc = cache_dump_stage(&c->o);
    if (rc != RUN_CONTINUE) return rc;
    rc = run_cache_mode(c);
    if (rc != RUN_CONTINUE) return rc;
    rc = run_select(c);
    if (rc != RUN_CONTINUE) return rc;
    return run_cache_probe(c);
}

static size_t run_exclusive_groups(struct run_ctx *c)
{
    size_t exclusive_ran = 0;
    for (size_t i = 0; i < g_num_groups; i++) {
        if (c->results[i].skipped || c->results[i].cached)
            continue;
        if (!group_requires_exclusive_run(g_groups[i].name))
            continue;
        if (c->o.verbose)
            printf("[exclusive] [%zu/%zu] %s\n",
                   i + 1, g_num_groups, g_groups[i].name);
        run_group_exclusive(i, c->parent_pid, c->results, c->o.timeout_secs,
                            c->o.verbose, c->o.activate_proof_contracts);
        c->reaped++;
        exclusive_ran++;
    }
    return exclusive_ran;
}

/* A shard invokes its own compiler/lint subprocesses, so eight shards per
 * checkout oversubscribe a 16-core host as soon as a second worktree runs
 * the same gate. Keep two normal developer streams inside the fixed
 * per-group timeout without serializing either checkout. */
static bool run_phases_ok(struct run_ctx *c)
{
    const struct run_opts *o = &c->o;
    int quiet_jobs = o->jobs < 4 ? o->jobs : 4;
    bool phases_ok = run_parallel_phase(
        POOL_PHASE_QUIET_LINT, c->slots, quiet_jobs, c->parent_pid,
        c->results, o->timeout_secs, o->verbose,
        o->activate_proof_contracts, &c->reaped);
    if (phases_ok)
        phases_ok = run_parallel_phase(
            POOL_PHASE_GENERAL, c->slots, o->jobs, c->parent_pid, c->results,
            o->timeout_secs, o->verbose, o->activate_proof_contracts,
            &c->reaped);
    return phases_ok && c->reaped == g_num_groups;
}

static int run_phases_abort(struct run_ctx *c)
{
    for (int i = 0; i < c->o.jobs; i++) {
        if (c->slots[i].pid == ZCL_CHILD_NONE) continue;
        child_kill(c->slots[i].pid);
        int st = 0;
        (void)child_wait(c->slots[i].pid, &st);
        child_close(c->slots[i].pid);
    }
    fprintf(stderr, "test_parallel: bounded phase scheduler failed\n");
    testcache_close(c->tc);
    free(c->probes);
    free(c->slots);
    free(c->results);
    return 1;
}

static int run_execute(struct run_ctx *c)
{
    c->slots = calloc((size_t)c->o.jobs, sizeof(*c->slots));
    if (!c->slots) {
        fprintf(stderr, "test_parallel: slot calloc failed\n");
        testcache_close(c->tc);
        free(c->probes);
        free(c->results);
        return 1;
    }

    platform_time_monotonic_timespec(&c->t_start);
    c->startup_wall =
        (double)(c->t_start.tv_sec - c->process_start.tv_sec) +
        (double)(c->t_start.tv_nsec - c->process_start.tv_nsec) / 1e9;

    c->parent_pid = getpid();
    /* pre_skipped (‑‑only / params) plus cache HITS are already accounted done. */
    c->reaped = c->pre_skipped + c->cached_count;
    size_t exclusive_ran = run_exclusive_groups(c);
    /* stdout is unbuffered, so this line reaches a proof's log whole the
     * moment the last run-alone group has been reaped. */
    printf("%s groups=%zu\n", ZCL_TEST_EXCLUSIVE_PASS_DONE, exclusive_ran);
    dispatch_order_prepare();

    if (!run_phases_ok(c)) return run_phases_abort(c);

    /* Every group that FAILed or was WEDGED under the shared pool gets one
     * clean shot alone before it counts — see rerun_load_flaky_groups. This
     * runs before the pass/fail accounting below so a load-flaky group's
     * alone verdict is what gets counted, cached, and reported. */
    rerun_load_flaky_groups(c->results, c->parent_pid, c->o.timeout_secs,
                            c->o.verbose, c->o.activate_proof_contracts);
    return RUN_CONTINUE;
}

static void report_tally(struct run_ctx *c)
{
    /* All children reaped. Full-suite green output is intentionally compact:
     * replaying hundreds of passing group logs produced ~46k lines / ~1M LLM
     * tokens with no diagnostic value. Focused runs retain their one group's
     * output, failures always replay their captured diagnostics, and --verbose
     * remains the explicit full transcript. */
    struct timespec t_end;
    platform_time_monotonic_timespec(&t_end);
    c->wall =
        (double)(t_end.tv_sec - c->t_start.tv_sec) +
        (double)(t_end.tv_nsec - c->t_start.tv_nsec) / 1e9;

    struct group_tally tally = {0};
    for (size_t i = 0; i < g_num_groups; i++) {
        if (c->results[i].skipped) continue;
        tally_group(&c->results[i], g_groups[i].name,
                    c->o.verbose || c->o.only != NULL, &tally);
    }
    c->failed_groups = tally.failed;
    c->skip_groups = tally.skip;
    c->unobserved_groups = tally.unobserved;
    c->load_flaky_groups = count_load_flaky_groups(c->results);
}

/* ── The verdict ────────────────────────────────────────────────────────
 * The old headline printed "ALL TESTS PASSED — 0/743 groups failed" whether
 * 743 groups ran or 1 ran and 742 were returned from cache: `pre_skipped`
 * counted only --only filtering and the params gate, never cache hits. The
 * push gate greps for exactly that string, so a run that executed nothing
 * reported GATE OK.
 *
 * Two fixes, both required:
 *   - a machine-greppable SUITE VERDICT line emitted BEFORE any verdict
 *     word, leading with groups_ran (what actually executed); and
 *   - the bare token "ALL TESTS PASSED" ONLY for a cold run. A cached run
 *     says "ALL TESTS PASSED (CACHED)", which a `grep -q "ALL TESTS
 *     PASSED"` still matches — so gate-and-report.sh is taught to reject
 *     the cached form explicitly rather than relying on the token alone.
 *
 * `mode` is derived from what the run actually SERVED from cache, not from
 * whether the cache was enabled. Keying it on the flag produced its own
 * misreport — `ZCL_TEST_CACHE=1 ... --only=<group>` printed
 * "mode=cached ... groups_cached=0" and the (CACHED) headline for a run in
 * which every selected group executed. A run with zero hits ran everything
 * and is a cold run; a run with one hit is not, and says so. */
static void report_verdict_build(struct run_ctx *c)
{
    size_t cached_count = c->cached_count;
    bool served_from_cache = (cached_count > 0);
    c->verdict = (struct suite_verdict){
        .mode          = served_from_cache ? "cached" : "cold",
        .groups_total  = g_num_groups,
        .groups_ran    = g_num_groups - c->pre_skipped - c->cached_count,
        .groups_cached = c->cached_count,
        .groups_gated  = c->pre_skipped,
        .groups_cacheable = c->cacheable_count,
        .groups_failed = c->failed_groups,
        .self_skips    = c->skip_groups,
        .env_unobserved = c->unobserved_groups,
        .load_flaky    = c->load_flaky_groups,
    };
    testcache_toolkey_digest12(c->verdict.toolkey);
}

static void report_write_files(struct run_ctx *c)
{
    write_test_timing_json(c->results, c->probes,
                           c->o.activate_proof_contracts,
                           c->startup_wall, c->wall, c->o.jobs, g_num_groups,
                           c->failed_groups,
                           c->pre_skipped, &c->verdict);
    write_test_verdict_file(c->results, &c->verdict);

    /* A compact receipt near the end of stdout lets the resident dev service
     * bind its identity/graph phases to the test runner's own startup/body
     * measurement without parsing human timing prose. */
    printf("{\"schema\":\"zcl.test_phase_receipt.v1\","
           "\"startup_ms\":%lld,\"test_body_ms\":%lld}\n",
           (long long)(c->startup_wall * 1000.0),
           (long long)(c->wall * 1000.0));
}

static void report_verdict_lines(const struct run_ctx *c)
{
    const struct suite_verdict *v = &c->verdict;
    /* A hot-swapped run is stamped on the machine-greppable verdict line and
     * on the headline. It ran the module's bodies, not the linked binary's:
     * nothing downstream may read it as an ordinary run. */
    char hotswap_verdict[128] = "";
    char hotswap_headline[128] = "";
    if (g_hotswap_module_active) {
        (void)snprintf(hotswap_verdict, sizeof(hotswap_verdict),
                       " hotswap_module=%.12s hotswap_source=%s",
                       g_hotswap_module_sha, g_hotswap_module_source);
        (void)snprintf(hotswap_headline, sizeof(hotswap_headline),
                       " (HOTSWAP MODULE %.12s)", g_hotswap_module_sha);
    }

    printf("\nSUITE VERDICT mode=%s groups_total=%zu groups_ran=%zu "
           "groups_cached=%zu groups_gated=%zu groups_failed=%d self_skips=%d "
           "env_unobserved=%d load_flaky=%d toolkey=%s%s\n",
           v->mode, v->groups_total, v->groups_ran,
           v->groups_cached, v->groups_gated, v->groups_failed,
           v->self_skips, v->env_unobserved, v->load_flaky,
           v->toolkey, hotswap_verdict);

    printf("%s%s — %d/%zu groups failed, %d skipped (%.1fs wall, %d workers)%s\n",
           c->failed_groups != 0 ? "SOME TESTS FAILED"
                                 : (c->cached_count > 0
                                        ? "ALL TESTS PASSED (CACHED)"
                                        : "ALL TESTS PASSED"),
           hotswap_headline,
           c->failed_groups, g_num_groups - c->pre_skipped, c->skip_groups,
           c->wall, c->o.jobs,
           c->o.only ? (c->o.only_exact ? " [--exact filtered]"
                                        : " [--only filtered]")
                     : "");
    print_suite_notes(c->results, c->skip_groups, c->unobserved_groups,
                      c->load_flaky_groups);
    if (c->failed_groups > 0)
        print_failed_groups_report(c->results, c->o.timeout_secs);
}

/* ── Cache accounting: store fresh cacheable PASSes, report cached/ran,
 * and (cold-audit) assert every stored PASS at a group's CURRENT key would
 * have matched its fresh verdict. A cold-audit divergence is a closure/cache
 * soundness bug and fails the run loudly (over and above the failing group
 * already counting toward failed_groups). */
static int report_cache_accounting(struct run_ctx *c, int *observation_refused)
{
    int audit_diverged = 0;
    *observation_refused = 0;
    if (c->cache_mode != CACHE_OFF) {
        struct cache_accounting acc = { .mode = c->cache_mode };
        account_cache_run(c->results, c->probes, &c->tc, &acc);
        print_cache_summary(&acc);
        if (c->o.cli_emit_observations)
            acc.observation_refused = emit_group_observations(c->results,
                                        c->probes,
                                        observation_store_root(c->tc),
                                        c->o.cli_collect_observations);
        audit_diverged = acc.audit_diverged;
        *observation_refused = acc.observation_refused;
        testcache_close(c->tc);
        free(c->probes);
    }
    return audit_diverged;
}

static int run_report(struct run_ctx *c)
{
    report_tally(c);
    report_verdict_build(c);
    report_write_files(c);
    report_verdict_lines(c);
    int observation_refused = 0;
    int audit_diverged = report_cache_accounting(c, &observation_refused);
    free(c->slots);
    free(c->results);
    return retry_probe_exit(c->failed_groups, audit_diverged,
                            observation_refused);
}

int main(int argc, char **argv)
{
    if (!selection_inspection_valid(argc, argv)) return 2;
    /* Narrow sealed-image process fixture dispatch, before runner init. */
    extern void supervised_fixture_exit_if_requested(int argc, char **argv);
    supervised_fixture_exit_if_requested(argc, argv);
    struct run_ctx c;
    memset(&c, 0, sizeof(c));
    platform_time_monotonic_timespec(&c.process_start);

    int rc = 0;
    if (main_early_modes(argc, argv, &rc)) return rc;

    /* Before any group forks. Not inside the confined-agent arm above: that
     * child is deliberately sandboxed and must not widen its own limits. */
    raise_stack_limit();
#if defined(__linux__)
    tmpfs_setup();
#endif

    rc = run_prepare(argc, argv, &c);
    if (rc != RUN_CONTINUE) return rc;
    rc = run_execute(&c);
    if (rc != RUN_CONTINUE) return rc;
    int exit_code = run_report(&c);
#if defined(__linux__)
    tmpfs_finish(exit_code, c.load_flaky_groups);
#endif
    return exit_code;
}

/* The exact external-input denylist refuses cache reuse before any key or
 * graph lookup. For an entirely denied selection, graph work has no value. */
static bool selected_all_external(const struct group_result *results)
{
    size_t selected = 0;
    for (size_t i = 0; i < g_num_groups; i++) {
        if (results[i].skipped) continue;
        selected++;
        if (!testcache_group_is_denylisted(g_groups[i].name)) return false;
    }
    return selected > 0;
}

static void print_external_probe_only(const struct group_result *results)
{
    size_t selected = 0;
    for (size_t i = 0; i < g_num_groups; i++) {
        if (results[i].skipped) continue;
        selected++;
        printf("PROBE %s UNCACHEABLE external-input-denylist -\n",
               g_groups[i].name);
    }
    printf("PROBE-SUMMARY groups=%zu would_reuse=0 must_run=%zu "
           "uncacheable=%zu\n", selected, selected, selected);
    printf("PROBE-STATS graph_opens=0 depfiles=0 closure_queries=0 "
           "file_hash_reads=0 memo_hits=0 sha3_bytes=0 "
           "verdict_lookups=0 verdict_hits=0\n");
}

static void external_cache_prepare(const struct group_result *results,
                                   size_t pre_skipped, enum cache_mode *mode)
{
    if (*mode != CACHE_ON || !selected_all_external(results)) return;
    size_t selected = g_num_groups - pre_skipped;
    printf("test_parallel: cache PLAN — 0 cacheable, 0 cache HIT "
           "(will NOT run), %zu will run\n", selected);
    printf("test_parallel: cacheability by reason:\n"
           "  %-32s %zu\n", "external-input-denylist", selected);
    *mode = CACHE_OFF;
}
