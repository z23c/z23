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
#include "platform/directory_compat.h"
#include "command/native_dev_hotswap.h"
#include "config/command_catalog.h"
#include "hotswap/hotswap.h"
#include "hotswap/hotswap_module.h"
#include "kernel/command_registry.h"
#include "session/agent_broker.h"
#include "test/test_group_selector.h"
#include "test_group_catalog.h"
#include "test/test_helpers.h"
#include "test/testcache.h"
#include "event/event.h"
#include "util/signal_handler.h"
#include "util/clientversion.h"

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
    /* ── progress watchdog state (see group_watchdog_expired) ───────────── */
    time_t last_progress;  /* when this group's output last grew */
    long long last_size;   /* bytes of captured output at that moment */
    int wedged;            /* 1 if WE killed it for going silent */
    int silent_seconds;    /* how long it had been silent when we killed it */
};

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

static int get_nproc(void)
{
#if defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    DWORD n = si.dwNumberOfProcessors;
    if (n < 1) return 1;
    if (n > 1024) return 1024;
    return (int)n;
#else
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1) return 1;
    if (n > 1024) return 1024;
    return (int)n;
#endif
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

/* Spawn one group's worker. POSIX forks and the child runs child_run in
 * place. Windows has no fork(), so the parent re-execs this same binary with
 * --child-run=<idx> --child-out=<path>; the early dispatch in main() hands
 * those arguments straight to child_run, which does its own stdout/stderr
 * redirection exactly as the forked child does. Returns 0 and fills `out`,
 * or -1 (already logged). */
static int child_spawn(size_t idx, const char *out_path,
                       bool activate_proof_contracts, zcl_child_t *out)
{
#if defined(_WIN32)
    char exe[PATH_MAX];
    DWORD n = GetModuleFileNameA(NULL, exe, (DWORD)sizeof(exe));
    if (n == 0 || n >= (DWORD)sizeof(exe)) {
        fprintf(stderr, "test_parallel: GetModuleFileName failed (%lu)\n",
                (unsigned long)GetLastError());
        return -1;
    }
    char cmd[PATH_MAX + 320];
    int len = snprintf(cmd, sizeof(cmd),
                       "\"%s\" --child-run=%zu --child-out=%s%s",
                       exe, idx, out_path,
                       activate_proof_contracts ? " --child-proof" : "");
    if (len < 0 || (size_t)len >= sizeof(cmd)) {
        fprintf(stderr, "test_parallel: child command line too long\n");
        return -1;
    }
    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL,
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
        child_run(idx, out_path, activate_proof_contracts);
        _exit(2); /* unreachable */
    }
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
static int reap_any(struct child_slot *slots, int jobs, int *status)
{
#if defined(_WIN32)
    for (int i = 0; i < jobs; i++) {
        if (slots[i].pid == ZCL_CHILD_NONE) continue;
        int r = child_poll(slots[i].pid, status);
        if (r == 1) return i;
        if (r < 0) return -1;
    }
    return -2;
#else
    pid_t done = waitpid(-1, status, WNOHANG);
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
static int count_marker_lines(const char *path, const char *sentinel)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    char line[4096];
    int n = 0;
    while (fgets(line, sizeof(line), fp))
        if (strstr(line, sentinel))
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
    for (;;) {
        int pr = child_poll(child, &status);
        if (pr == 1) break;
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
            if (child_spawn(next_idx, slots[slot].out_path,
                            activate_proof_contracts,
                            &slots[slot].pid) != 0)
                return false;
            slots[slot].group_idx = next_idx;
            if (verbose) {
                const char *label = phase == POOL_PHASE_QUIET_LINT
                    ? "quiet" : "dispatch";
#if defined(_WIN32)
                printf("[%-8s] [%zu/%zu] handle=%p %s\n",
                       label, next_idx + 1, g_num_groups,
                       (void *)slots[slot].pid,
                       g_groups[next_idx].name);
#else
                printf("[%-8s] [%zu/%zu] pid=%d %s\n",
                       label, next_idx + 1, g_num_groups, slots[slot].pid,
                       g_groups[next_idx].name);
#endif
            }
            next_idx++;
        }

        time_t now_tick = platform_time_wall_time_t();
        for (int i = 0; i < jobs; i++) {
            if (slots[i].pid == ZCL_CHILD_NONE) continue;
            size_t idx = slots[i].group_idx;
            if (results[idx].wedged) continue;   /* already killed, awaiting reap */
            if (!group_watchdog_expired(&results[idx], slots[i].out_path,
                                        now_tick, timeout_secs))
                continue;
            memcpy(results[idx].out_path, slots[i].out_path,
                   sizeof(results[idx].out_path));
            results[idx].wedged = 1;
            print_watchdog_kill(idx, g_groups[idx].name, &results[idx],
                                now_tick, timeout_secs);
            child_kill(slots[i].pid);
        }

        int status = 0;
        int slot = reap_any(slots, jobs, &status);
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
        size_t idx = slots[slot].group_idx;
        child_close(slots[slot].pid);
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
                   results[idx].wedged ? "WEDGED (no output)" :
                   results[idx].signaled ? "SIGNALED" :
                   (results[idx].exit_code == 0 ? "PASS" : "FAIL"),
                   results[idx].wall_seconds);
        slots[slot].pid = ZCL_CHILD_NONE;
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
    int    env_unobserved;    /* groups that ran but could not observe a leg */
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
    if (platform_directory_create(".cache", 0755) != 0 && errno != EEXIST) {
        perror("test_parallel: mkdir .cache");
        return;
    }
    if (platform_directory_create(dir, 0755) != 0 && errno != EEXIST) {
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
    if (!platform_time_utc_tm(now, &tm_utc)) {
        fprintf(stderr, "test_parallel: UTC timestamp conversion failed\n");
        fclose(fp);
        (void)remove(tmp_path);
        free(order);
        return;
    }
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

#if defined(_WIN32)
    /* Windows rename() refuses an existing target; the timing artifact is a
     * best-effort cache, so replacing last run's file is correct. */
    (void)remove(final_path);
#endif
    if (rename(tmp_path, final_path) != 0)
        perror("test_parallel: rename timing artifact");
}

/* ── Module mode: run the real groups against a hot-swapped .so ────────────
 *
 * ZCL_HOTSWAP_TEST_MODULE=<abs path to module .so> makes this harness load the
 * module through THE production loader — hotswap_activate_local() in
 * lib/hotswap/src/hotswap_activate.c, with the publish hooks from
 * tools/command/native_dev_hotswap.c — exactly as `zclassic23-dev` does for
 * ZCL_HOTSWAP_PRELOAD. Every production gate applies: path confinement, the
 * dev-datadir classification, ABI version, the config/hotswap_swappable.def
 * allowlist, leaf uniqueness, the module self_test, probe-before-publish
 * against the leaf's declared output schema, and the all-or-nothing registry
 * batch that re-checks READY + EFFECT_READ. There is NO test-only loader: a
 * module that would be refused in production is refused here, and this harness
 * then refuses to run at all rather than silently testing resident code.
 *
 * Divergence containment (see docs/DEVELOPING.md "Module mode"):
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

static bool g_hotswap_module_active;
static char g_hotswap_module_sha[65];
static char g_hotswap_module_source[256];

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
#if defined(_WIN32)
    /* Windows worker entry. The parent cannot fork(), so child_spawn()
     * re-execs this binary with --child-run=<idx> --child-out=<path> per
     * group. Dispatch before any suite setup: child_run does its own
     * stdout/stderr redirection (same body the forked POSIX child runs), so
     * nothing may print before it. */
    {
        long child_idx = -1;
        const char *child_out = NULL;
        bool child_proof = false;
        for (int i = 1; i < argc; i++) {
            if (strncmp(argv[i], "--child-run=", 12) == 0)
                child_idx = strtol(argv[i] + 12, NULL, 10);
            else if (strncmp(argv[i], "--child-out=", 12) == 0)
                child_out = argv[i] + 12;
            else if (strcmp(argv[i], "--child-proof") == 0)
                child_proof = true;
        }
        if (child_idx >= 0) {
            if (!child_out || (unsigned long)child_idx >=
                              (unsigned long)g_num_groups) {
                fprintf(stderr, "test_parallel: bad --child-run dispatch\n");
                return 2;
            }
            child_run((size_t)child_idx, child_out, child_proof);
            return 2; /* unreachable: child_run _exit()s */
        }
    }

    /* Fork-role dispatch: tests with a cross-process leg (SQLite owner lease,
     * kill -9 recovery, ...) re-exec this binary through
     * test_spawn_self_with_role(), which sets ZCL_TEST_FORK_GROUP/_ROLE. Run
     * the group DIRECTLY in this process — a second scheduler layer would put
     * a proxy between the parent and the worker and break the hard-kill
     * tests. The group entry branches on the role and runs only the child
     * body. Same chain/ecc/event setup as child_run. */
    {
        const char *role = getenv("ZCL_TEST_FORK_ROLE");
        const char *gname = getenv("ZCL_TEST_FORK_GROUP");
        if (role && role[0]) {
            if (!gname || !gname[0]) {
                fprintf(stderr, "test_parallel: ZCL_TEST_FORK_ROLE without "
                                "ZCL_TEST_FORK_GROUP\n");
                return 2;
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
                return failures ? 1 : 0;
            }
            fprintf(stderr, "test_parallel: ZCL_TEST_FORK_GROUP names no "
                            "registered group: %s\n", gname);
            return 2;
        }
    }
#endif
    if (argc == 2 && strcmp(argv[1], "--source-id") == 0) {
        printf("%s\n", zcl_build_source_id_sha256());
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--source-record") == 0) {
        printf("%s 1 %s\n", zcl_build_source_id_sha256(),
               zcl_build_source_mutation_sha256());
        return 0;
    }

    /* Before any group forks. Not inside the confined-agent arm above: that
     * child is deliberately sandboxed and must not widen its own limits. */
    raise_stack_limit();

    int jobs = get_nproc();
    /* Per-group bound on SILENCE, not on runtime — see group_watchdog_expired
     * for the full rationale and the derivation. A group may run for as long
     * as it likes provided it keeps emitting; 300 s of a group producing
     * literally nothing is a hang. (--timeout= keeps its name for callers,
     * but it has never been a runtime budget since this changed.) */
    int timeout_secs = 300;
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

    if (!list_only) {
        if (!hotswap_module_mode_begin())
            return 2;
        /* A verdict produced against a hot-swapped module must never be
         * reusable as a cached PASS for the linked binary, and must never be
         * served from one. */
        if (g_hotswap_module_active)
            cache_mode = CACHE_OFF;
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
            /* Proof policy is applied in the child after the ordinary cache
             * key is computed. Never consult or populate that policy-blind
             * keyspace for an activated proof: exact push authority must
             * execute under the requested environment every time. */
            if (activate_proof_contracts &&
                zcl_test_group_proof_contract(g_groups[i].name) !=
                    ZCL_TEST_PROOF_NONE) {
                probes[i].code = TESTCACHE_R_ACTIVE_PROOF_CONTRACT;
                snprintf(probes[i].reason, sizeof(probes[i].reason),
                         "activated exact proof runs fresh");
                continue;
            }
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
            if (slots[i].pid == ZCL_CHILD_NONE) continue;
            child_kill(slots[i].pid);
            int st = 0;
            (void)child_wait(slots[i].pid, &st);
            child_close(slots[i].pid);
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
    int unobserved_groups = 0;
    for (size_t i = 0; i < g_num_groups; i++) {
        if (results[i].skipped) continue;
        bool pass =
            !results[i].signaled && results[i].exit_code == 0;
        results[i].skip_markers = results[i].out_path[0]
            ? count_marker_lines(results[i].out_path, "SKIP (") : 0;
        if (results[i].skip_markers > 0) skip_groups++;
        results[i].env_unobserved = results[i].out_path[0]
            ? count_marker_lines(results[i].out_path, "UNOBSERVED (") : 0;
        if (results[i].env_unobserved > 0) unobserved_groups++;
        char skip_note[32] = "";
        if (results[i].skip_markers > 0)
            snprintf(skip_note, sizeof(skip_note), ", %d SKIP",
                     results[i].skip_markers);
        if (!pass) failed_groups++;
        if (verbose || only || !pass) {
            printf("\n==================== %s (%s%s, %.0fs) ====================\n",
                   g_groups[i].name,
                   results[i].wedged ? "WEDGED-NO-OUTPUT" :
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
        .env_unobserved = unobserved_groups,
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
           "env_unobserved=%d toolkey=%s%s\n",
           verdict.mode, verdict.groups_total, verdict.groups_ran,
           verdict.groups_cached, verdict.groups_gated, verdict.groups_failed,
           verdict.self_skips, verdict.env_unobserved, verdict.toolkey,
           hotswap_verdict);

    printf("%s%s — %d/%zu groups failed, %d skipped (%.1fs wall, %d workers)%s\n",
           failed_groups != 0 ? "SOME TESTS FAILED"
                              : (served_from_cache
                                     ? "ALL TESTS PASSED (CACHED)"
                                     : "ALL TESTS PASSED"),
           hotswap_headline,
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
             * contract. Never persist that partial run as a reusable PASS.
             * UNOBSERVED is the same story for a different reason: the group
             * ran and hard-asserted its load-free legs, but one leg never got
             * an observation. Caching that would let a busy box mint a receipt
             * a later run reuses as if the leg had been proven, so it is
             * barred from the cache exactly like a skip. It does NOT fail the
             * run — the box's spare capacity is not a code verdict. */
            if (pass && results[i].skip_markers == 0 &&
                results[i].env_unobserved == 0 && probes &&
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
