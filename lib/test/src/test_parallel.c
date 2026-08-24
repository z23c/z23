/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fork-parallel driver for the zclassic23 test suite.
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

#include "platform/time_compat.h"
#include "session/agent_broker.h"
#include "test/test_group_selector.h"
#include "test_group_catalog.h"
#include "test/test_helpers.h"
#include "test/testcache.h"
#include "event/event.h"
#include "util/signal_handler.h"
#include "util/clientversion.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Required by process_block.c (normally in main.c) */
volatile sig_atomic_t g_shutdown_requested = 0;

/* ── Test registry ─────────────────────────────────────────────────
 *
 * tools/dev/test_group_catalog.def is expanded twice below:
 *   DECL  — produces extern int test_<name>(void) / spec_<name>(void);
 *   ENTRY — produces canonical full-ID dispatch rows
 *
 * Keep in sync with the dispatch list in lib/test/src/test.c.
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

/* ── Parent-side worker pool ───────────────────────────────────────*/

struct child_slot {
    pid_t pid;           /* 0 if slot is free */
    size_t group_idx;    /* index into g_groups for the running group */
    char out_path[128];  /* tempfile path for this child's stdout+stderr */
};

struct group_result {
    int status;          /* -1 if not yet run, else wait-status from waitpid */
    int signaled;        /* 1 if killed by a signal */
    int exit_code;       /* only valid if signaled == 0 */
    double wall_seconds; /* 0 until measured */
    time_t start;
    char out_path[128];  /* owned by the slot; copied here on reap */
    int skipped;         /* 1 if selector/params gate excluded it (not run) */
    int skip_markers;    /* "SKIP (" sentinel lines in captured output */
    int cached;          /* 1 if returned from the content-addressed cache */
};

static int get_nproc(void)
{
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1) return 1;
    if (n > 1024) return 1024;
    return (int)n;
}

static bool activate_proof_contract(size_t idx)
{
    const char *env_name = NULL;
    switch (zcl_test_group_proof_contract(g_groups[idx].name)) {
    case ZCL_TEST_PROOF_NONE:
        return true;
    case ZCL_TEST_PROOF_STRESS:
        env_name = "ZCL_STRESS_TESTS";
        break;
    case ZCL_TEST_PROOF_EVENT_LOG_KILL9:
        env_name = "ZCL_EVENT_LOG_KILL9_FUZZ";
        break;
    case ZCL_TEST_PROOF_EVENT_LOG_BENCH:
        /* Push authority needs a bounded throughput proof.  The explicit
         * ZCL_EVENT_LOG_BENCH=1 contract remains the full standalone
         * measurement and is never enabled by the parallel gate. */
        env_name = "ZCL_EVENT_LOG_BENCH_PROOF";
        break;
    default:
        fprintf(stderr,
                "test_parallel: invalid proof contract group=%s\n",
                g_groups[idx].name);
        return false;
    }
    if (setenv(env_name, "1", 1) != 0) {
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

static void child_run(size_t idx, const char *out_path,
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

    int failures = g_groups[idx].fn();

    ecc_verify_destroy();
    ecc_stop();

    fflush(stdout);
    fflush(stderr);
    _exit(failures ? 1 : 0);
}

static int find_slot_by_pid(struct child_slot *slots, int jobs, pid_t pid)
{
    for (int i = 0; i < jobs; i++)
        if (slots[i].pid == pid) return i;
    return -1;
}

static int find_free_slot(struct child_slot *slots, int jobs)
{
    for (int i = 0; i < jobs; i++)
        if (slots[i].pid == 0) return i;
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
    if (mkdir("./test-tmp", 0755) != 0 && errno != EEXIST)
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

/* Count lines carrying the suite's skip sentinel ("SKIP ("). Gated
 * groups (the five ZCL_STRESS_TESTS MVP acceptance gates, the stress
 * harnesses) and environment-starved subtests print it and still exit
 * 0, so a green run can hide unexecuted coverage. The summary counts
 * the markers so "ALL TESTS PASSED" can never silently absorb a skip;
 * the gates themselves stay opt-in (they are gated for runtime
 * reasons — visibility, not force-enabling, is the contract). */
static int count_skip_markers(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    char line[4096];
    int n = 0;
    while (fgets(line, sizeof(line), fp))
        if (strstr(line, "SKIP ("))
            n++;
    fclose(fp);
    return n;
}

/* Two lint-gate self-tests plant a real file into the LIVE worktree — one
 * under app/services/src/, one at the repo root — and then unlink() it. Those
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
           strcmp(name, "simnet_shielded_wallet_e2e") == 0 ||
           strcmp(name, "simnet_zmsg_onchain") == 0 ||
           strcmp(name, "snark_kat") == 0 ||
           strcmp(name, "native_spend_proof") == 0 ||
           strcmp(name, "groth16_selfverify") == 0 ||
           strcmp(name, "wallet_destruction_drill") == 0 ||
           strcmp(name, "sapling_prover_rng_determinism") == 0;
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
        bool found = false;
        if (len > 0) {
            for (size_t i = 0; i < g_num_groups; i++) {
                if (strlen(g_groups[i].name) == len &&
                    memcmp(g_groups[i].name, p, len) == 0) {
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
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

    pid_t pid = fork();
    if (pid < 0) {
        perror("test_parallel: exclusive fork");
        results[idx].status = 1;
        results[idx].signaled = 0;
        results[idx].exit_code = 2;
        return;
    }
    if (pid == 0) {
        child_run(idx, out_path, activate_proof_contracts);
        _exit(2); /* unreachable */
    }

    int status = 0;
    bool killed = false;
    for (;;) {
        pid_t done = waitpid(pid, &status, WNOHANG);
        if (done == pid) break;
        if (done < 0 && errno == EINTR) continue;
        if (done < 0) {
            perror("test_parallel: exclusive waitpid");
            status = 1;
            break;
        }
        time_t now = platform_time_wall_time_t();
        if (!killed && now - results[idx].start > timeout_secs) {
            if (verbose)
                printf("[timeout ] [%zu] %s (after %ds)\n",
                       idx, g_groups[idx].name, timeout_secs);
            (void)kill(pid, SIGKILL);
            killed = true;
        }
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }

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
    size_t next_idx = 0;
    while (remaining > 0) {
        while (next_idx < g_num_groups) {
            if (results[next_idx].status != -1 ||
                !pool_phase_selects(phase, g_groups[next_idx].name)) {
                next_idx++;
                continue;
            }
            int slot = find_free_slot(slots, jobs);
            if (slot < 0) break;
            make_tempfile_path(slots[slot].out_path,
                               sizeof(slots[slot].out_path),
                               next_idx, parent_pid);
            results[next_idx].start = platform_time_wall_time_t();
            pid_t pid = fork();
            if (pid < 0) {
                perror("test_parallel: fork");
                return false;
            }
            if (pid == 0) {
                child_run(next_idx, slots[slot].out_path,
                          activate_proof_contracts);
                _exit(2);
            }
            slots[slot].pid = pid;
            slots[slot].group_idx = next_idx;
            if (verbose) {
                const char *label = phase == POOL_PHASE_QUIET_LINT
                    ? "quiet" : "dispatch";
                printf("[%-8s] [%zu/%zu] pid=%d %s\n",
                       label, next_idx + 1, g_num_groups, pid,
                       g_groups[next_idx].name);
            }
            next_idx++;
        }

        time_t now_tick = platform_time_wall_time_t();
        for (int i = 0; i < jobs; i++) {
            if (slots[i].pid == 0) continue;
            size_t idx = slots[i].group_idx;
            if (now_tick - results[idx].start <= timeout_secs) continue;
            if (verbose)
                printf("[timeout ] [%zu] %s (after %ds)\n",
                       idx, g_groups[idx].name, timeout_secs);
            (void)kill(slots[i].pid, SIGKILL);
        }

        int status = 0;
        pid_t done = waitpid(-1, &status, WNOHANG);
        if (done == 0) {
            struct timespec ts = {
                .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000,
            };
            nanosleep(&ts, NULL);
            continue;
        }
        if (done < 0) {
            if (errno == EINTR) continue;
            perror("test_parallel: waitpid");
            return false;
        }
        int slot = find_slot_by_pid(slots, jobs, done);
        if (slot < 0) continue;
        size_t idx = slots[slot].group_idx;
        results[idx].status = status;
        if (WIFSIGNALED(status)) {
            results[idx].signaled = 1;
            results[idx].exit_code = WTERMSIG(status);
        } else {
            results[idx].signaled = 0;
            results[idx].exit_code = WIFEXITED(status)
                ? WEXITSTATUS(status) : -1;
        }
        memcpy(results[idx].out_path, slots[slot].out_path,
               sizeof(results[idx].out_path));
        time_t now = platform_time_wall_time_t();
        results[idx].wall_seconds = (double)(now - results[idx].start);
        if (verbose)
            printf("[done    ] [%zu] %s (%s, %.0fs)\n",
                   idx, g_groups[idx].name,
                   results[idx].signaled ? "SIGNALED" :
                   (results[idx].exit_code == 0 ? "PASS" : "FAIL"),
                   results[idx].wall_seconds);
        slots[slot].pid = 0;
        remaining--;
        (*reaped)++;
    }
    return true;
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
    char   toolkey[13];
};

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
 * the run — this is an observability artifact, not a test outcome. */
static void write_test_timing_json(const struct group_result *results,
                                   double startup_seconds,
                                   double wall_seconds, int jobs,
                                   size_t group_count, int failed_groups,
                                   size_t skipped_count,
                                   const struct suite_verdict *v)
{
    const char *dir = ".cache/test-timing";
    if (mkdir(".cache", 0755) != 0 && errno != EEXIST) {
        perror("test_parallel: mkdir .cache");
        return;
    }
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        perror("test_parallel: mkdir .cache/test-timing");
        return;
    }

    size_t *order = malloc(group_count * sizeof(*order));
    if (!order) {
        fprintf(stderr, "test_parallel: timing order malloc failed\n");
        return;
    }
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

    char tmp_path[160], final_path[160];
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
    gmtime_r(&now, &tm_utc);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);

    fprintf(fp, "{\n");
    fprintf(fp, "  \"schema\":\"zcl.test_timing.v1\",\n");
    fprintf(fp, "  \"generated_at_utc\":\"%s\",\n", ts);
    fprintf(fp, "  \"startup_ms\":%lld,\n",
            (long long)(startup_seconds * 1000.0));
    fprintf(fp, "  \"test_body_ms\":%lld,\n",
            (long long)(wall_seconds * 1000.0));
    fprintf(fp, "  \"wall_ms\":%lld,\n", (long long)(wall_seconds * 1000.0));
    fprintf(fp, "  \"jobs\":%d,\n", jobs);
    fprintf(fp, "  \"group_count\":%zu,\n", group_count);
    fprintf(fp, "  \"failed_count\":%d,\n", failed_groups);
    fprintf(fp, "  \"skipped_count\":%zu,\n", skipped_count);
    /* The cache facts belong in the artifact, not only on the terminal: a
     * consumer of this file must be able to tell a run that EXECUTED 743 groups
     * from one that executed 1 and read 742 out of the cache. */
    fprintf(fp, "  \"mode\":\"%s\",\n", v->mode);
    fprintf(fp, "  \"groups_ran\":%zu,\n", v->groups_ran);
    fprintf(fp, "  \"groups_cached\":%zu,\n", v->groups_cached);
    fprintf(fp, "  \"groups_cacheable\":%zu,\n", v->groups_cacheable);
    fprintf(fp, "  \"toolkey\":\"%s\",\n", v->toolkey);
    fprintf(fp, "  \"groups\":[\n");
    int first = 1;
    for (size_t k = 0; k < group_count; k++) {
        size_t i = order[k];
        if (results[i].skipped)
            continue;
        if (!first)
            fprintf(fp, ",\n");
        first = 0;
        long long ms = (long long)(results[i].wall_seconds * 1000.0);
        int rc = results[i].signaled ? -results[i].exit_code
                                     : results[i].exit_code;
        fprintf(fp,
                "    {\"name\":\"%s\",\"ms\":%lld,\"rc\":%d,"
                "\"signaled\":%s,\"cached\":%s}",
                g_groups[i].name, ms, rc,
                results[i].signaled ? "true" : "false",
                results[i].cached ? "true" : "false");
    }
    fprintf(fp, "\n  ]\n}\n");
    fclose(fp);
    free(order);

    if (rename(tmp_path, final_path) != 0)
        perror("test_parallel: rename timing artifact");
}

int main(int argc, char **argv)
{
    struct timespec process_start;
    platform_time_monotonic_timespec(&process_start);

    /* The confined-agent boundary re-execs THIS binary as the untrusted child
     * (session/agent_broker.h). It is dispatched before any test setup for the
     * same reason main.c dispatches it before node boot: the child arrives
     * already sandboxed, under a seccomp allow-list that would kill it for
     * most of what suite setup does. Never reached by an ordinary run. */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--metaverse-agent-confined") == 0)
            return agent_confined_mode_main(argc, argv);
    }
    if (argc == 2 && strcmp(argv[1], "--source-id") == 0) {
        printf("%s\n", zcl_build_source_id_sha256());
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--source-record") == 0) {
        printf("%s 1 %s\n", zcl_build_source_id_sha256(),
               zcl_build_source_mutation_sha256());
        return 0;
    }

    int jobs = get_nproc();
    int timeout_secs = 300; /* per-group; generous so slow groups like
                             * test_merkle_tree (~110s standalone) don't
                             * get cut off the first time a machine is
                             * loaded. */
    bool verbose = false;
    bool list_only = false;
    const char *only = NULL; /* --only=SUBSTR or --exact=FULL_ID[,FULL...] */
    bool only_exact = false;
    /* Content-addressed test cache. Default OFF so the canonical push gate
     * stays COLD (a cached SKIP never gates a push). --cache / ZCL_TEST_CACHE=1
     * opt in for the inner dev loop; --no-cache forces off; --cold-audit runs
     * everything fresh and asserts every cache HIT matches its fresh verdict. */
    bool cli_cache = false;      /* --cache */
    bool cli_no_cache = false;   /* --no-cache */
    bool cli_cold_audit = false; /* --cold-audit */
    bool activate_proof_contracts = false;
    bool cache_snapshot = false;
    const char *changed_sources[32];
    size_t changed_source_count = 0;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--jobs=", 7) == 0) {
            jobs = atoi(argv[i] + 7);
            if (jobs < 1) jobs = 1;
        } else if (strncmp(argv[i], "-j", 2) == 0 && argv[i][2]) {
            jobs = atoi(argv[i] + 2);
            if (jobs < 1) jobs = 1;
        } else if (strncmp(argv[i], "--timeout=", 10) == 0) {
            timeout_secs = atoi(argv[i] + 10);
            if (timeout_secs < 1) timeout_secs = 1;
        } else if (strcmp(argv[i], "--verbose") == 0 ||
                   strcmp(argv[i], "-v") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "--list") == 0) {
            list_only = true;
        } else if (strncmp(argv[i], "--only=", 7) == 0) {
            if (only) {
                fprintf(stderr,
                        "test_parallel: pass only one of --only/--exact\n");
                return 2;
            }
            only = argv[i] + 7;
        } else if (strncmp(argv[i], "--exact=", 8) == 0) {
            if (only) {
                fprintf(stderr,
                        "test_parallel: pass only one of --only/--exact\n");
                return 2;
            }
            only = argv[i] + 8;
            only_exact = true;
        } else if (strcmp(argv[i], "--cache") == 0) {
            cli_cache = true;
        } else if (strcmp(argv[i], "--cache-snapshot") == 0) {
            cache_snapshot = true;
        } else if (strncmp(argv[i], "--changed-source=", 17) == 0) {
            const char *path = argv[i] + 17;
            if (!path[0] || path[0] == '/' || strstr(path, "..") ||
                strlen(path) >= 256 || changed_source_count >= 32) {
                fprintf(stderr,
                        "test_parallel: invalid --changed-source path\n");
                return 2;
            }
            changed_sources[changed_source_count++] = path;
        } else if (strcmp(argv[i], "--no-cache") == 0) {
            cli_no_cache = true;
        } else if (strcmp(argv[i], "--cold-audit") == 0) {
            cli_cold_audit = true;
        } else if (strcmp(argv[i], "--activate-proof-contracts") == 0) {
            activate_proof_contracts = true;
        } else {
            fprintf(stderr,
                    "Usage: %s [--jobs=N] [--timeout=SECS] [--verbose] "
                    "[--list|--source-id|--source-record] "
                    "[--only=SUBSTR|--exact=FULL_ID[,FULL...]] "
                    "[--cache|--no-cache] "
                    "[--cache-snapshot --changed-source=PATH] "
                    "[--cold-audit] [--activate-proof-contracts]\n",
                    argv[0]);
            return 2;
        }
    }
    if (cache_snapshot != (changed_source_count > 0) ||
        (cache_snapshot && !cli_cache)) {
        fprintf(stderr, "test_parallel: cache snapshot requires --cache and "
                        "one or more --changed-source paths\n");
        return 2;
    }
    if (activate_proof_contracts &&
        (!only_exact || !zcl_test_group_proof_contracts_valid())) {
        fprintf(stderr,
                "test_parallel: --activate-proof-contracts requires an "
                "exact selector and a valid proof-contract catalog\n");
        return 2;
    }

    /* Diagnostic surface: ZCL_TEST_CACHE_DUMP=<group> prints the group's forward
     * input closure, its content key, and its cacheability, then exits — the
     * operator/proof lens onto what the cache would key on. */
    const char *dump_group = getenv("ZCL_TEST_CACHE_DUMP");
    if (dump_group && dump_group[0]) {
        struct testcache *tc = testcache_open(NULL);
        if (!tc) {
            fprintf(stderr, "test_parallel: cache open failed for dump\n");
            return 1;
        }
        testcache_dump_group(tc, dump_group);
        testcache_close(tc);
        return 0;
    }

    /* Resolve the cache mode. Precedence: --cold-audit > --no-cache >
     * (--cache | ZCL_TEST_CACHE!=0) > OFF. OFF reproduces the historical
     * behavior byte-for-byte (none of the cache code below runs). */
    enum cache_mode { CACHE_OFF, CACHE_ON, CACHE_COLD_AUDIT } cache_mode;
    {
        const char *env = getenv("ZCL_TEST_CACHE");
        bool env_on = env && env[0] && strcmp(env, "0") != 0;
        if (cli_cold_audit)      cache_mode = CACHE_COLD_AUDIT;
        else if (cli_no_cache)   cache_mode = CACHE_OFF;
        else if (cli_cache || env_on) cache_mode = CACHE_ON;
        else                     cache_mode = CACHE_OFF;
    }

    if (list_only) {
        for (size_t i = 0; i < g_num_groups; i++)
            printf("%s\n", g_groups[i].name);
        return 0;
    }

    if (only_exact) {
        const char *missing = NULL;
        size_t missing_len = 0;
        if (!exact_selector_set_valid(only, &missing, &missing_len)) {
            fprintf(stderr,
                    "test_parallel: --exact contains no registered group: "
                    "%.*s\n", (int)missing_len, missing ? missing : "");
            return 2;
        }
    }

    ensure_tmp_dir();

    setbuf(stdout, NULL);
    printf("test_parallel: %zu groups, %d workers, %ds per-group timeout\n",
           g_num_groups, jobs, timeout_secs);

    struct group_result *results =
        calloc(g_num_groups, sizeof(*results));
    if (!results) {
        fprintf(stderr, "test_parallel: calloc failed\n");
        return 1;
    }
    for (size_t i = 0; i < g_num_groups; i++) {
        results[i].status = -1;
    }

    /* --only=SUBSTR / --exact=FULL_ID[,FULL...]: pre-mark non-matching groups so
     * they are neither dispatched nor counted. Lets a dev iterate on one
     * group in ~seconds instead of waiting on the slowest group. Proof
     * automation uses --exact: a stale short id must not accidentally select
     * a differently named group and report green. */
    size_t pre_skipped = 0;
    if (only) {
        for (size_t i = 0; i < g_num_groups; i++) {
            bool selected = only_exact
                                ? test_group_selector_matches_exact_set(
                                      g_groups[i].name, only)
                                : test_group_selector_matches(
                                      g_groups[i].name, only, false);
            if (!selected) {
                results[i].status = 0; /* excludes from dispatch loop */
                results[i].skipped = 1;
                pre_skipped++;
            }
        }
        if (pre_skipped == g_num_groups) {
            fprintf(stderr,
                    "test_parallel: --%s=%s matched no groups\n",
                    only_exact ? "exact" : "only", only);
            free(results);
            return 2;
        }
    }

    /* Params-heavy opt-in gate: exclude the Groth16-proving groups from a
     * default full run. They still run when ZCL_PARAMS_TESTS is set, or when
     * explicitly selected via --only/--exact (which leaves results[i].skipped
     * clear for the matching group). Folded into pre_skipped so they are not
     * dispatched and are excluded from the pass/fail denominator. */
    bool params_opt_in = getenv("ZCL_PARAMS_TESTS") != NULL;
    size_t params_gated = 0;
    /* An explicit selector is itself the opt-in for a params-heavy group,
     * so skip the gate entirely when a selector is in effect (the matching group
     * is the only one left unskipped above). */
    if (!params_opt_in && !only) {
        for (size_t i = 0; i < g_num_groups; i++) {
            if (results[i].skipped) continue;
            if (!group_is_params_heavy(g_groups[i].name)) continue;
            results[i].status = 0;              /* excludes from dispatch */
            results[i].skipped = 1;
            params_gated++;
        }
        pre_skipped += params_gated;
    }
    if (params_gated > 0)
        printf("test_parallel: %zu params-heavy group(s) gated out "
               "(set ZCL_PARAMS_TESTS=1 or use --only/--exact to run)\n",
               params_gated);

    /* ── Content-addressed cache: probe every group's forward input closure,
     * and in CACHE_ON mark the provable HITS as CACHED so they are never
     * forked. Fail-safe: any open failure downgrades to CACHE_OFF (run all). */
    struct testcache *tc = NULL;
    struct testcache_probe *probes = NULL;
    size_t cached_count = 0;
    size_t cacheable_count = 0;
    size_t reason_hist[TESTCACHE_R__COUNT] = {0};
    if (cache_mode != CACHE_OFF) {
        tc = cache_snapshot
            ? testcache_open_snapshot(NULL, changed_sources,
                                      changed_source_count)
            : testcache_open(NULL);
        if (!tc) {
            fprintf(stderr, "test_parallel: cache open failed — "
                            "running every group uncached\n");
            cache_mode = CACHE_OFF;
        }
    }
    if (cache_mode != CACHE_OFF) {
        probes = calloc(g_num_groups, sizeof(*probes));
        if (!probes) {
            fprintf(stderr, "test_parallel: probe calloc failed — "
                            "running every group uncached\n");
            testcache_close(tc);
            tc = NULL;
            cache_mode = CACHE_OFF;
        }
    }
    if (cache_mode != CACHE_OFF) {
        for (size_t i = 0; i < g_num_groups; i++) {
            if (results[i].skipped) continue;
            testcache_probe_group(tc, g_groups[i].name, &probes[i]);
        }
        /* CACHE_ON: a provable stored PASS at the current key means the group
         * cannot have changed — mark it CACHED (status 0 excludes it from
         * dispatch; cached=1 records why). COLD_AUDIT never marks anything so
         * every group runs fresh and is verified after. */
        if (cache_mode == CACHE_ON) {
            for (size_t i = 0; i < g_num_groups; i++) {
                if (results[i].skipped) continue;
                if (probes[i].cacheable && probes[i].hit) {
                    results[i].status = 0;
                    results[i].cached = 1;
                    cached_count++;
                }
            }
        }

        /* ── The PLAN, printed BEFORE dispatch ──────────────────────────────
         * Announcing "cached 742 / ran 1" only in the retrospective summary
         * means an operator watching a run cannot tell, while it is happening,
         * that almost nothing is being executed. Say it up front. */
        for (size_t i = 0; i < g_num_groups; i++) {
            if (results[i].skipped) continue;
            if (probes[i].cacheable) cacheable_count++;
        }
        for (size_t i = 0; i < g_num_groups; i++) {
            if (results[i].skipped) continue;
            if (probes[i].code < TESTCACHE_R__COUNT)
                reason_hist[probes[i].code]++;
        }
        printf("test_parallel: cache PLAN — %zu cacheable, %zu cache HIT "
               "(will NOT run), %zu will run%s\n",
               cacheable_count, cached_count,
               g_num_groups - pre_skipped - cached_count,
               cache_mode == CACHE_COLD_AUDIT ? " [cold-audit: runs all]" : "");
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
        if (testcache_depfile_count(tc) == 0)
            printf("test_parallel: !! NO DEPFILES under build/ — the include "
                   "graph is ABSENT, so every group is UNCACHEABLE and the "
                   "whole run is cold. Build first to restore caching. !!\n");
        else if (reason_hist[TESTCACHE_R_GRAPH_STALE] > 0)
            printf("test_parallel: !! %zu group(s) have inputs NEWER than the "
                   "include graph (%zu depfiles) — the graph cannot describe "
                   "them, so they are UNCACHEABLE. Rebuild to refresh. !!\n",
                   reason_hist[TESTCACHE_R_GRAPH_STALE],
                   testcache_depfile_count(tc));
    }

    struct child_slot *slots =
        calloc((size_t)jobs, sizeof(*slots));
    if (!slots) {
        fprintf(stderr, "test_parallel: slot calloc failed\n");
        testcache_close(tc);
        free(probes);
        free(results);
        return 1;
    }

    struct timespec t_start;
    platform_time_monotonic_timespec(&t_start);
    double startup_wall =
        (double)(t_start.tv_sec - process_start.tv_sec) +
        (double)(t_start.tv_nsec - process_start.tv_nsec) / 1e9;

    pid_t parent_pid = getpid();
    /* pre_skipped (‑‑only / params) plus cache HITS are already accounted done. */
    size_t reaped = pre_skipped + cached_count;

    for (size_t i = 0; i < g_num_groups; i++) {
        if (results[i].skipped || results[i].cached)
            continue;
        if (!group_requires_exclusive_run(g_groups[i].name))
            continue;
        if (verbose)
            printf("[exclusive] [%zu/%zu] %s\n",
                   i + 1, g_num_groups, g_groups[i].name);
        run_group_exclusive(i, parent_pid, results, timeout_secs, verbose,
                            activate_proof_contracts);
        reaped++;
    }

    /* A shard invokes its own compiler/lint subprocesses, so eight shards per
     * checkout oversubscribe a 16-core host as soon as a second worktree runs
     * the same gate. Keep two normal developer streams inside the fixed
     * per-group timeout without serializing either checkout. */
    int quiet_jobs = jobs < 4 ? jobs : 4;
    bool phases_ok = run_parallel_phase(
        POOL_PHASE_QUIET_LINT, slots, quiet_jobs, parent_pid, results,
        timeout_secs, verbose, activate_proof_contracts, &reaped);
    if (phases_ok)
        phases_ok = run_parallel_phase(
            POOL_PHASE_GENERAL, slots, jobs, parent_pid, results,
            timeout_secs, verbose, activate_proof_contracts, &reaped);
    if (!phases_ok || reaped != g_num_groups) {
        for (int i = 0; i < jobs; i++) {
            if (slots[i].pid <= 0) continue;
            (void)kill(slots[i].pid, SIGKILL);
            while (waitpid(slots[i].pid, NULL, 0) < 0 && errno == EINTR) {}
        }
        fprintf(stderr, "test_parallel: bounded phase scheduler failed\n");
        testcache_close(tc);
        free(probes);
        free(slots);
        free(results);
        return 1;
    }

    /* All children reaped. Full-suite green output is intentionally compact:
     * replaying hundreds of passing group logs produced ~46k lines / ~1M LLM
     * tokens with no diagnostic value. Focused runs retain their one group's
     * output, failures always replay their captured diagnostics, and --verbose
     * remains the explicit full transcript. */
    struct timespec t_end;
    platform_time_monotonic_timespec(&t_end);
    double wall =
        (double)(t_end.tv_sec - t_start.tv_sec) +
        (double)(t_end.tv_nsec - t_start.tv_nsec) / 1e9;

    int failed_groups = 0;
    int skip_groups = 0;
    for (size_t i = 0; i < g_num_groups; i++) {
        if (results[i].skipped) continue;
        bool pass =
            !results[i].signaled && results[i].exit_code == 0;
        results[i].skip_markers = results[i].out_path[0]
            ? count_skip_markers(results[i].out_path) : 0;
        if (results[i].skip_markers > 0) skip_groups++;
        char skip_note[32] = "";
        if (results[i].skip_markers > 0)
            snprintf(skip_note, sizeof(skip_note), ", %d SKIP",
                     results[i].skip_markers);
        if (!pass) failed_groups++;
        if (verbose || only || !pass) {
            printf("\n==================== %s (%s%s, %.0fs) ====================\n",
                   g_groups[i].name,
                   results[i].signaled ? "SIGNALED" :
                   (pass ? "PASS" : "FAIL"),
                   skip_note, results[i].wall_seconds);
            print_captured(results[i].out_path);
        }
        if (pass && results[i].out_path[0]) unlink(results[i].out_path);
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
    bool served_from_cache = (cached_count > 0);
    struct suite_verdict verdict = {
        .mode          = served_from_cache ? "cached" : "cold",
        .groups_total  = g_num_groups,
        .groups_ran    = g_num_groups - pre_skipped - cached_count,
        .groups_cached = cached_count,
        .groups_gated  = pre_skipped,
        .groups_cacheable = cacheable_count,
        .groups_failed = failed_groups,
        .self_skips    = skip_groups,
    };
    testcache_toolkey_digest12(verdict.toolkey);

    write_test_timing_json(results, startup_wall, wall, jobs, g_num_groups,
                           failed_groups,
                           pre_skipped, &verdict);

    /* A compact receipt near the end of stdout lets the resident dev service
     * bind its identity/graph phases to the test runner's own startup/body
     * measurement without parsing human timing prose. */
    printf("{\"schema\":\"zcl.test_phase_receipt.v1\","
           "\"startup_ms\":%lld,\"test_body_ms\":%lld}\n",
           (long long)(startup_wall * 1000.0),
           (long long)(wall * 1000.0));

    printf("\nSUITE VERDICT mode=%s groups_total=%zu groups_ran=%zu "
           "groups_cached=%zu groups_gated=%zu groups_failed=%d self_skips=%d "
           "toolkey=%s\n",
           verdict.mode, verdict.groups_total, verdict.groups_ran,
           verdict.groups_cached, verdict.groups_gated, verdict.groups_failed,
           verdict.self_skips, verdict.toolkey);

    printf("%s — %d/%zu groups failed, %d skipped (%.1fs wall, %d workers)%s\n",
           failed_groups != 0 ? "SOME TESTS FAILED"
                              : (served_from_cache
                                     ? "ALL TESTS PASSED (CACHED)"
                                     : "ALL TESTS PASSED"),
           failed_groups, g_num_groups - pre_skipped, skip_groups, wall, jobs,
           only ? (only_exact ? " [--exact filtered]"
                              : " [--only filtered]")
                : "");
    if (skip_groups > 0) {
        printf("Skipped coverage (self-skipped groups — most need "
               "ZCL_STRESS_TESTS=1 + an isolated run):\n");
        for (size_t i = 0; i < g_num_groups; i++) {
            if (results[i].skipped || results[i].skip_markers == 0) continue;
            printf("  - %s: %d skip marker(s)\n",
                   g_groups[i].name, results[i].skip_markers);
        }
    }
    if (failed_groups > 0) {
        printf("Failed groups:\n");
        for (size_t i = 0; i < g_num_groups; i++) {
            if (results[i].skipped) continue;
            bool pass =
                !results[i].signaled && results[i].exit_code == 0;
            if (pass) continue;
            printf("  - %s: %s",
                   g_groups[i].name,
                   results[i].signaled ? "signaled" : "exit");
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

    /* ── Cache accounting: store fresh cacheable PASSes, report cached/ran,
     * and (cold-audit) assert every stored PASS at a group's CURRENT key would
     * have matched its fresh verdict. A cold-audit divergence is a closure/cache
     * soundness bug and fails the run loudly (over and above the failing group
     * already counting toward failed_groups). */
    int audit_diverged = 0;
    if (cache_mode != CACHE_OFF) {
        size_t cached_n = 0, ran = 0, stored = 0, audit_hits = 0;
        for (size_t i = 0; i < g_num_groups; i++) {
            if (results[i].skipped) continue;
            if (results[i].cached) { cached_n++; continue; }
            ran++;
            bool pass = !results[i].signaled && results[i].exit_code == 0;
            /* A zero-exit group that printed SKIP did not prove its complete
             * contract. Never persist that partial run as a reusable PASS. */
            if (pass && results[i].skip_markers == 0 && probes &&
                probes[i].cacheable) {
                testcache_store_pass(tc, probes[i].key);
                stored++;
            }
            if (cache_mode == CACHE_COLD_AUDIT && probes &&
                probes[i].cacheable && probes[i].hit) {
                audit_hits++;
                if (!pass) {
                    audit_diverged++;
                    printf("COLD-AUDIT DIVERGENCE: %s carried a cached PASS at "
                           "its current key but FAILED a fresh run — the "
                           "closure/cache is UNSOUND\n", g_groups[i].name);
                }
            }
        }
        printf("cached %zu / ran %zu%s\n", cached_n, ran,
               cache_mode == CACHE_COLD_AUDIT ? " [cold-audit]" : "");
        if (cache_mode == CACHE_COLD_AUDIT)
            printf("cold-audit: %zu cache-hit(s) verified against fresh runs, "
                   "%d divergence(s)\n", audit_hits, audit_diverged);
        else if (stored > 0)
            printf("cache: stored %zu fresh PASS verdict(s)\n", stored);
        testcache_close(tc);
        free(probes);
    }

    free(slots);
    free(results);
    return (failed_groups == 0 && audit_diverged == 0) ? 0 : 1;
}
