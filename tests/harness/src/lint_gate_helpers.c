/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Plumbing shared by every check in the `make_lint_gates` self-test group:
 * file read/write/copy, directory walks over .c and .h, planting and removing
 * the transient fixtures, and the fork+exec wrappers that run a gate script
 * (plain, with worker files, with one or two environment overrides, or under
 * `timeout`) and report its exit status.
 *
 * Nothing here asserts. The checks that do live in the sibling
 * lint_gate_*.c files; see lint_gate_selftests.h for the map. */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

/* The lint-gate self-test family fork+execs POSIX bash gate scripts; native
 * Windows has no fork/exec/waitpid, so on _WIN32 every helper compiles out and
 * the registered group entry points (test_make_lint_gates.c) report a loud
 * skip instead. */
#if defined(ZCL_TESTING) && !defined(_WIN32)

#include "lint_gate_selftests.h"
#include "platform/clock.h"

/* Per-process scratch path under the (possibly sandboxed) repo root.
 *
 * Anything the REALROOT lane writes has to be pid-unique. The sandbox lane
 * gets isolation for free — repo_path() resolves into a private hardlink tree
 * — but the real-worktree checks now run inside the 32-worker pool, so two of
 * them sharing one fixed filename would truncate each other's file mid-read.
 * Everything still lands under ./test-tmp/, which check-no-stray-root-files
 * requires. */
int repo_path_pid(char *out, size_t outsz, const char *rel_prefix,
                  const char *suffix)
{
    if (!rel_prefix || !suffix) return -1;
    char rel[256];
    if (snprintf(rel, sizeof(rel), "%s_%ld%s", rel_prefix, (long)getpid(),
                 suffix) >= (int)sizeof(rel))
        return -1;
    return repo_path(out, outsz, rel);
}

/* The stdout+stderr sink every gate-script run redirects into. One fixed
 * "test-tmp/zcl_gate_lint.out" was safe only while this family ran as a single
 * exclusive group; the shards and the realroot lane run concurrently now. */
int lint_gate_out_path(char *out, size_t outsz)
{
    return repo_path_pid(out, outsz, "test-tmp/zcl_gate_lint", ".out");
}

int copy_file(const char *src, const char *dst)
{
    FILE *in = fopen(src, "rb");
    if (!in) {
        fprintf(stderr, "copy_file: fopen(%s) failed: %s\n",
                src, strerror(errno));
        return -1;
    }
    FILE *out = fopen(dst, "wb");
    if (!out) {
        fprintf(stderr, "copy_file: fopen(%s) failed: %s\n",
                dst, strerror(errno));
        fclose(in);
        return -1;
    }
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            fprintf(stderr, "copy_file: fwrite failed: %s\n",
                    strerror(errno));
            fclose(in); fclose(out);
            return -1;
        }
    }
    fclose(in);
    fclose(out);
    return 0;
}

/* Replace the first occurrence of `needle` in `hay` with `repl`, returning a
 * freshly malloc'd buffer (caller frees) or NULL if `needle` is absent or on
 * allocation failure. Test-only string-fixture helper (no production callers,
 * so plain malloc — test/ files are exempt from check-raw-malloc). */
char *str_replace_once(const char *hay, const char *needle,
                              const char *repl)
{
    const char *pos = strstr(hay, needle);
    if (!pos) return NULL;
    size_t pre = (size_t)(pos - hay);
    size_t hay_len = strlen(hay);
    size_t needle_len = strlen(needle);
    size_t repl_len = strlen(repl);
    size_t out_len = hay_len - needle_len + repl_len;
    char *out = malloc(out_len + 1);
    if (!out) return NULL;
    memcpy(out, hay, pre);
    memcpy(out + pre, repl, repl_len);
    memcpy(out + pre + repl_len, pos + needle_len, hay_len - pre - needle_len);
    out[out_len] = '\0';
    return out;
}

bool has_c_suffix(const char *path)
{
    size_t len = strlen(path);
    return len >= 2 && strcmp(path + len - 2, ".c") == 0;
}

bool has_ch_suffix(const char *path)
{
    size_t len = strlen(path);
    return len >= 2 &&
           (strcmp(path + len - 2, ".c") == 0 ||
            strcmp(path + len - 2, ".h") == 0);
}

int read_entire_file(const char *path, char **out_buf)
{
    *out_buf = NULL;
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }

    long len = ftell(fp);
    if (len < 0) {
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    char *buf = calloc((size_t)len + 1, 1);
    if (!buf) {
        fclose(fp);
        return -1;
    }

    if (len > 0 && fread(buf, 1, (size_t)len, fp) != (size_t)len) {
        free(buf);
        fclose(fp);
        return -1;
    }

    fclose(fp);
    *out_buf = buf;
    return 0;
}

size_t count_occurrences(const char *haystack, const char *needle)
{
    size_t step = strlen(needle);
    if (step == 0) return 0;
    size_t n = 0;
    for (const char *p = strstr(haystack, needle); p;
         p = strstr(p + step, needle))
        n++;
    return n;
}

int walk_c_files(const char *dirpath,
                        int (*check_file)(const char *path))
{
    DIR *dir = opendir(dirpath);
    if (!dir) return -1;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char path[PATH_MAX];
        if (snprintf(path, sizeof(path), "%s/%s", dirpath, ent->d_name) >=
            (int)sizeof(path)) {
            closedir(dir);
            return -1;
        }

        struct stat st;
        if (stat(path, &st) != 0) {
            closedir(dir);
            return -1;
        }

        if (S_ISDIR(st.st_mode)) {
            int rc = walk_c_files(path, check_file);
            if (rc != 0) {
                closedir(dir);
                return rc;
            }
            continue;
        }

        if (!S_ISREG(st.st_mode) || !has_c_suffix(path))
            continue;

        int rc = check_file(path);
        if (rc != 0) {
            closedir(dir);
            return rc;
        }
    }

    closedir(dir);
    return 0;
}

int walk_ch_files(const char *dirpath,
                         int (*check_file)(const char *path))
{
    DIR *dir = opendir(dirpath);
    if (!dir) return -1;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char path[PATH_MAX];
        if (snprintf(path, sizeof(path), "%s/%s", dirpath, ent->d_name) >=
            (int)sizeof(path)) {
            closedir(dir);
            return -1;
        }

        struct stat st;
        if (stat(path, &st) != 0) {
            closedir(dir);
            return -1;
        }

        if (S_ISDIR(st.st_mode)) {
            int rc = walk_ch_files(path, check_file);
            if (rc != 0) {
                closedir(dir);
                return rc;
            }
            continue;
        }

        if (!S_ISREG(st.st_mode) || !has_ch_suffix(path))
            continue;

        int rc = check_file(path);
        if (rc != 0) {
            closedir(dir);
            return rc;
        }
    }

    closedir(dir);
    return 0;
}

int write_file(const char *path, const char *contents)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    size_t n = strlen(contents);
    int ok = fwrite(contents, 1, n, fp) == n;
    fclose(fp);
    return ok ? 0 : -1;
}

/* fork() can transiently fail with EAGAIN (or ENOMEM, on some kernels
 * under similar pressure) when many concurrent gate-script forks race
 * other heavy work in the same run (e.g. several whole-program LTO links
 * from a parallel `make -j` or a dev-loop watcher cycle). Every gate-script
 * runner below (run_check_raw_malloc_script and the run_gate_script*
 * family) forks once per invocation and treats fork() < 0 as a hard
 * harness failure (-1), which several self-tests assert is 0 for a clean
 * baseline run (ASSERT(baseline_rc == 0)); a transient EAGAIN/ENOMEM
 * therefore rotates through those assertions as a spurious failure that
 * has nothing to do with the gate itself. Retry a small, bounded number of
 * times with a short sleep before giving up — a non-transient fork
 * failure (or exhausted retries) still returns -1 exactly as callers
 * already expect.
 *
 * SIZING (widened 2026-07-30 — see t_fuzz_artifact_ledger_gate flake hunt,
 * shard 07). The original margin here was 3 attempts * 20 ms fixed = 60 ms
 * of total backoff. That is thin next to what this SAME host tolerates for
 * the SAME class of contention one line later: every gate-script runner
 * below execs a bash script (check_fuzz_artifact_replay.sh among others)
 * that itself forks git/grep/sed/sort/find under the identical resource
 * pressure — and bash's own fork()-retry-on-EAGAIN loop (observable via the
 * "fork: retry: Resource temporarily unavailable" message bash prints while
 * it retries, confirmed present in the bash 5.2 binary on this host) backs
 * off across multiple *seconds*, not milliseconds, before giving up. This
 * harness was giving up roughly two orders of magnitude faster than the
 * shell forking the next process over, under the exact same contention —
 * so a burst of resource pressure long enough for bash to shrug off could
 * still exhaust this retry and turn "the gate is fine" into "harness
 * failure -1", which is indistinguishable from a real violation in
 * ASSERT(baseline_rc == 0).
 *
 * This was reproduced empirically only via 32-worker `make test-parallel`
 * runs on a host also running several other worktrees' builds concurrently
 * (load average 10-14 measured during this investigation); it did not
 * reproduce in 3 additional isolated full-suite runs taken back to back on
 * this same busy host, so the window is real but narrow. Deliberately not
 * fixed by inducing artificial memory/process-table exhaustion to force a
 * reproduction — that would risk starving the other concurrent worktrees
 * and the live node sharing this host, which is out of bounds.
 *
 * Widened to 8 attempts with exponential backoff (20ms, 40, 80, 160, 320,
 * 500, 500 — capped, ~1.6s worst-case total): an order of magnitude closer
 * to what bash itself already tolerates for the same fork() pressure,
 * while remaining a small fraction of both the 300s per-test-group timeout
 * and this gate's own ~14s isolated wall time, so a normal (non-contended)
 * run pays nothing extra — retries only fire when fork() itself is
 * actually failing. Each retry is now logged (not just final exhaustion),
 * so if this flake recurs its captured test-tmp/test_parallel_*.log will
 * show exactly how many attempts fired and which errno, instead of leaving
 * a bare "FAIL (baseline_rc == 0)" with no way to tell a harness fork
 * failure from a real gate violation. */
#define ZCL_FORK_RETRY_ATTEMPTS 8
#define ZCL_FORK_RETRY_BACKOFF_INITIAL_NS (20L * 1000L * 1000L)  /* 20 ms */
#define ZCL_FORK_RETRY_BACKOFF_CAP_NS     (500L * 1000L * 1000L) /* 500 ms */

pid_t fork_with_retry(void)
{
    long backoff_ns = ZCL_FORK_RETRY_BACKOFF_INITIAL_NS;
    for (int attempt = 1; attempt <= ZCL_FORK_RETRY_ATTEMPTS; attempt++) {
        pid_t pid = fork();
        if (pid >= 0)
            return pid;
        if (errno != EAGAIN && errno != ENOMEM)
            return pid;
        int fork_errno = errno;
        if (attempt < ZCL_FORK_RETRY_ATTEMPTS) {
            fprintf(stderr,
                    "[lint-gate] fork() attempt %d/%d failed (errno=%d %s) "
                    "— retrying after %ld ms\n",
                    attempt, ZCL_FORK_RETRY_ATTEMPTS, fork_errno,
                    strerror(fork_errno), backoff_ns / 1000000L);
            struct timespec backoff = {
                .tv_sec = backoff_ns / 1000000000L,
                .tv_nsec = backoff_ns % 1000000000L,
            };
            (void)nanosleep(&backoff, NULL);
            backoff_ns *= 2;
            if (backoff_ns > ZCL_FORK_RETRY_BACKOFF_CAP_NS)
                backoff_ns = ZCL_FORK_RETRY_BACKOFF_CAP_NS;
            errno = fork_errno;
        }
    }
    /* Retries exhausted: make this distinguishable from an ordinary gate
     * failure (rc != 0) in test output — a bare -1 from run_gate_script()
     * otherwise looks identical to any other harness-level failure. */
    fprintf(stderr,
            "[lint-gate] fork() failed all %d attempts (errno=%d %s) — "
            "harness failure under sustained resource pressure, not a gate "
            "failure\n",
            ZCL_FORK_RETRY_ATTEMPTS, errno, strerror(errno));
    return -1;
}

/* Generalized gate-script runner: fork/exec the script at repo-relative
 * path `script_rel`, optionally with ZCL_LINT_MODE set to `mode` (NULL to
 * leave unset) and optionally with one argv word `arg` (NULL for none).
 * Returns the script's exit status (0 = clean, non-zero = violations), or -1
 * on harness failure. Mirrors run_check_raw_malloc_script but parameterized so
 * the four E-series gates share one driver.
 *
 * `arg` exists for gates that own their own trip/recover matrix behind a
 * `--selftest` flag. Dispatching that flag is strictly better than restating
 * the matrix in C: the shell already builds and tears down the fixture
 * sandbox, and two copies of the same matrix are two things to keep in step. */
int run_gate_script_arg(const char *script_rel, const char *mode,
                        const char *arg)
{
    char script[PATH_MAX];
    if (repo_path(script, sizeof(script), script_rel) != 0)
        return -1;

    char out_path[PATH_MAX];
    if (lint_gate_out_path(out_path, sizeof(out_path)) != 0)
        return -1;

    struct sigaction old_chld;
    struct sigaction dfl_chld;
    int restore_chld = 0;
    memset(&old_chld, 0, sizeof(old_chld));
    memset(&dfl_chld, 0, sizeof(dfl_chld));
    dfl_chld.sa_handler = SIG_DFL;
    sigemptyset(&dfl_chld.sa_mask);
    if (sigaction(SIGCHLD, NULL, &old_chld) == 0 &&
        sigaction(SIGCHLD, &dfl_chld, NULL) == 0) {
        restore_chld = 1;
    }

    pid_t pid = fork_with_retry();
    if (pid < 0) {
        if (restore_chld)
            (void)sigaction(SIGCHLD, &old_chld, NULL);
        return -1;
    }
    if (pid == 0) {
        int fd = open(out_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (fd >= 0) {
            (void)dup2(fd, STDOUT_FILENO);
            (void)dup2(fd, STDERR_FILENO);
            close(fd);
        }
        if (mode)
            (void)setenv("ZCL_LINT_MODE", mode, 1);
        if (arg)
            execl(script, script, arg, (char *)NULL);
        else
            execl(script, script, (char *)NULL);
        _exit(127);
    }

    int rc = 0;
    while (waitpid(pid, &rc, 0) < 0) {
        if (errno == EINTR)
            continue;
        if (restore_chld)
            (void)sigaction(SIGCHLD, &old_chld, NULL);
        return -1;
    }
    if (restore_chld)
        (void)sigaction(SIGCHLD, &old_chld, NULL);
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    return -1;
}

int run_gate_script(const char *script_rel, const char *mode)
{
    return run_gate_script_arg(script_rel, mode, NULL);
}

/* Run a gate's own `--selftest`: the gate builds its known-bad inputs in a
 * throwaway directory, asserts every trip and recover case itself, and exits
 * 0 only if all of them held. 0 = the gate still bites. */
int run_gate_script_selftest(const char *script_rel)
{
    return run_gate_script_arg(script_rel, NULL, "--selftest");
}

/* Like run_gate_script but ALSO exports ZCL_SUPERVISOR_WORKER_FILES so the
 * widened Gate #21 background-worker scan reads a planted fixture file
 * instead of the live engine/composition/src/boot_background_workers.c. `worker_files`
 * is a space-separated repo-relative path list; it is resolved to absolute
 * paths before export so the gate (which runs from repo root) finds it
 * regardless of cwd. Mirrors run_gate_script's fork/exec/redirect plumbing. */
int run_gate_script_with_worker_files(const char *script_rel,
                                             const char *mode,
                                             const char *worker_files_rel)
{
    char script[PATH_MAX];
    if (repo_path(script, sizeof(script), script_rel) != 0)
        return -1;

    char worker_abs[PATH_MAX];
    if (worker_files_rel &&
        repo_path(worker_abs, sizeof(worker_abs), worker_files_rel) != 0)
        return -1;

    char out_path[PATH_MAX];
    if (lint_gate_out_path(out_path, sizeof(out_path)) != 0)
        return -1;

    struct sigaction old_chld;
    struct sigaction dfl_chld;
    int restore_chld = 0;
    memset(&old_chld, 0, sizeof(old_chld));
    memset(&dfl_chld, 0, sizeof(dfl_chld));
    dfl_chld.sa_handler = SIG_DFL;
    sigemptyset(&dfl_chld.sa_mask);
    if (sigaction(SIGCHLD, NULL, &old_chld) == 0 &&
        sigaction(SIGCHLD, &dfl_chld, NULL) == 0) {
        restore_chld = 1;
    }

    pid_t pid = fork_with_retry();
    if (pid < 0) {
        if (restore_chld)
            (void)sigaction(SIGCHLD, &old_chld, NULL);
        return -1;
    }
    if (pid == 0) {
        int fd = open(out_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (fd >= 0) {
            (void)dup2(fd, STDOUT_FILENO);
            (void)dup2(fd, STDERR_FILENO);
            close(fd);
        }
        if (mode)
            (void)setenv("ZCL_LINT_MODE", mode, 1);
        if (worker_files_rel)
            (void)setenv("ZCL_SUPERVISOR_WORKER_FILES", worker_abs, 1);
        execl(script, script, (char *)NULL);
        _exit(127);
    }

    int rc = 0;
    while (waitpid(pid, &rc, 0) < 0) {
        if (errno == EINTR)
            continue;
        if (restore_chld)
            (void)sigaction(SIGCHLD, &old_chld, NULL);
        return -1;
    }
    if (restore_chld)
        (void)sigaction(SIGCHLD, &old_chld, NULL);
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    return -1;
}

/* Like run_gate_script but exports ONE arbitrary env var (name=value) into the
 * gate's environment. Used by the META-GATE that points each hardened gate at
 * an empty scan dir (via its ZCL_*_SCAN_* override) and asserts exit 2 — the
 * proof that a fail-silent gate is now fail-LOUD on an empty scan set.
 * Mirrors run_gate_script's fork/exec/redirect plumbing. */
int run_gate_script_with_env(const char *script_rel,
                                    const char *env_name,
                                    const char *env_value)
{
    char script[PATH_MAX];
    if (repo_path(script, sizeof(script), script_rel) != 0)
        return -1;

    char out_path[PATH_MAX];
    if (lint_gate_out_path(out_path, sizeof(out_path)) != 0)
        return -1;

    struct sigaction old_chld;
    struct sigaction dfl_chld;
    int restore_chld = 0;
    memset(&old_chld, 0, sizeof(old_chld));
    memset(&dfl_chld, 0, sizeof(dfl_chld));
    dfl_chld.sa_handler = SIG_DFL;
    sigemptyset(&dfl_chld.sa_mask);
    if (sigaction(SIGCHLD, NULL, &old_chld) == 0 &&
        sigaction(SIGCHLD, &dfl_chld, NULL) == 0) {
        restore_chld = 1;
    }

    pid_t pid = fork_with_retry();
    if (pid < 0) {
        if (restore_chld)
            (void)sigaction(SIGCHLD, &old_chld, NULL);
        return -1;
    }
    if (pid == 0) {
        int fd = open(out_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (fd >= 0) {
            (void)dup2(fd, STDOUT_FILENO);
            (void)dup2(fd, STDERR_FILENO);
            close(fd);
        }
        if (env_name && env_value)
            (void)setenv(env_name, env_value, 1);
        execl(script, script, (char *)NULL);
        _exit(127);
    }

    int rc = 0;
    while (waitpid(pid, &rc, 0) < 0) {
        if (errno == EINTR)
            continue;
        if (restore_chld)
            (void)sigaction(SIGCHLD, &old_chld, NULL);
        return -1;
    }
    if (restore_chld)
        (void)sigaction(SIGCHLD, &old_chld, NULL);
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    return -1;
}

/* Like run_gate_script_with_env but exports TWO env vars. Used by the
 * service-result-convergence self-test, which needs to point the gate at
 * both an isolated scan dir AND an isolated baseline file simultaneously so
 * it never touches the real tree/baseline. Mirrors the same fork/exec/
 * redirect plumbing as its siblings. */
int run_gate_script_with_env2(const char *script_rel,
                                     const char *env_name1,
                                     const char *env_value1,
                                     const char *env_name2,
                                     const char *env_value2)
{
    char script[PATH_MAX];
    if (repo_path(script, sizeof(script), script_rel) != 0)
        return -1;

    char out_path[PATH_MAX];
    if (lint_gate_out_path(out_path, sizeof(out_path)) != 0)
        return -1;

    struct sigaction old_chld;
    struct sigaction dfl_chld;
    int restore_chld = 0;
    memset(&old_chld, 0, sizeof(old_chld));
    memset(&dfl_chld, 0, sizeof(dfl_chld));
    dfl_chld.sa_handler = SIG_DFL;
    sigemptyset(&dfl_chld.sa_mask);
    if (sigaction(SIGCHLD, NULL, &old_chld) == 0 &&
        sigaction(SIGCHLD, &dfl_chld, NULL) == 0) {
        restore_chld = 1;
    }

    pid_t pid = fork_with_retry();
    if (pid < 0) {
        if (restore_chld)
            (void)sigaction(SIGCHLD, &old_chld, NULL);
        return -1;
    }
    if (pid == 0) {
        int fd = open(out_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (fd >= 0) {
            (void)dup2(fd, STDOUT_FILENO);
            (void)dup2(fd, STDERR_FILENO);
            close(fd);
        }
        if (env_name1 && env_value1)
            (void)setenv(env_name1, env_value1, 1);
        if (env_name2 && env_value2)
            (void)setenv(env_name2, env_value2, 1);
        execl(script, script, (char *)NULL);
        _exit(127);
    }

    int rc = 0;
    while (waitpid(pid, &rc, 0) < 0) {
        if (errno == EINTR)
            continue;
        if (restore_chld)
            (void)sigaction(SIGCHLD, &old_chld, NULL);
        return -1;
    }
    if (restore_chld)
        (void)sigaction(SIGCHLD, &old_chld, NULL);
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    return -1;
}

/* Snapshot the 1/5/15-minute load average into `out`. Best effort: a machine
 * without /proc/loadavg reports "unknown" rather than failing anything. This
 * is DIAGNOSTIC ONLY — nothing in this file branches on it. */
void lint_gate_loadavg(char *out, size_t outsz)
{
    if (!out || outsz == 0) return;
    out[0] = '\0';
    FILE *fp = fopen("/proc/loadavg", "rb");
    if (!fp) { snprintf(out, outsz, "unknown"); return; }
    char buf[128] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    /* Keep the first three fields (1m 5m 15m); drop the rest. */
    int fields = 0;
    for (size_t i = 0; i < n; i++) {
        if (buf[i] == ' ' && ++fields == 3) { buf[i] = '\0'; break; }
        if (buf[i] == '\n') { buf[i] = '\0'; break; }
    }
    snprintf(out, outsz, "%s", buf[0] ? buf : "unknown");
}

/* ── run_gate_script_watched — a PROGRESS watchdog, not a stopwatch ────────
 *
 * WHY THIS IS NOT `timeout <N> <script>`.
 *
 * This helper used to exec the script under `timeout -k 5 180`. That grades
 * the MACHINE, not the script: a total-duration ceiling fires on a saturated
 * or slow-disk box running perfectly correct code, and the resulting failure
 * is indistinguishable from a real defect. It is the same defect class as a
 * systemd WatchdogSec that SIGABRTs a healthy node because concurrent builds
 * saturated the box — measured on this project's own fleet. A bigger ceiling
 * does not fix it; it only lengthens the fuse and delays a genuine hang.
 *
 * What actually distinguishes a wedged script from a slow one is PROGRESS. A
 * gate script under test emits a line per assertion, so:
 *
 *   * a slow box emits the same lines, further apart  -> keep waiting;
 *   * a wedged script emits nothing at all            -> kill and report.
 *
 * So the bound here is on SILENCE, not on elapsed time, and the parent resets
 * it every time the child's output file grows. A box that is 20x slower still
 * passes, which is the point: this project wants slow machines on the network
 * and in CI, because they are the only instrument that finds the places where
 * the code assumes fast storage.
 *
 * `max_silent_secs` must be derived from the LONGEST DELIBERATE SILENCE in
 * the script being run (its own poll windows), not from its total runtime;
 * the caller passes that derivation in `why_bound` and it is printed on every
 * timeout so the next reader can check the arithmetic.
 *
 * Returns the script's exit status, or GATE_SCRIPT_WEDGED when it was killed
 * for going silent (diagnosed on stderr, with the measured silence, the total
 * elapsed and the load average), or -1 on a harness error. GATE_SCRIPT_WEDGED
 * is deliberately NOT 1: a hang and a failed assertion are different findings
 * and must never share an exit code.
 *
 * No `/usr/bin/timeout` dependency remains; the watchdog is this loop. */
int run_gate_script_watched(const char *script_rel, int max_silent_secs,
                            const char *why_bound)
{
    char script[PATH_MAX];
    if (repo_path(script, sizeof(script), script_rel) != 0)
        return -1;

    char out_path[PATH_MAX];
    if (lint_gate_out_path(out_path, sizeof(out_path)) != 0)
        return -1;
    if (max_silent_secs <= 0)
        return -1;

    struct sigaction old_chld;
    struct sigaction dfl_chld;
    int restore_chld = 0;
    memset(&old_chld, 0, sizeof(old_chld));
    memset(&dfl_chld, 0, sizeof(dfl_chld));
    dfl_chld.sa_handler = SIG_DFL;
    sigemptyset(&dfl_chld.sa_mask);
    if (sigaction(SIGCHLD, NULL, &old_chld) == 0 &&
        sigaction(SIGCHLD, &dfl_chld, NULL) == 0) {
        restore_chld = 1;
    }

    pid_t pid = fork_with_retry();
    if (pid < 0) {
        if (restore_chld)
            (void)sigaction(SIGCHLD, &old_chld, NULL);
        return -1;
    }
    if (pid == 0) {
        /* Own process group, so a wedged script's grandchildren (a fixture
         * node left spinning) go down with it instead of outliving the run. */
        (void)setpgid(0, 0);
        int fd = open(out_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (fd >= 0) {
            (void)dup2(fd, STDOUT_FILENO);
            (void)dup2(fd, STDERR_FILENO);
            close(fd);
        }
        execl(script, script, (char *)NULL);
        _exit(127);
    }
    (void)setpgid(pid, pid);  /* race-free: both sides set it */

    const int64_t started_ns = clock_now_monotonic_ns();
    int64_t last_progress_ns = started_ns;
    off_t last_size = -1;
    int rc = 0;
    int wedged = 0;

    for (;;) {
        pid_t w = waitpid(pid, &rc, WNOHANG);
        if (w == pid) break;
        if (w < 0) {
            if (errno == EINTR) continue;
            if (restore_chld) (void)sigaction(SIGCHLD, &old_chld, NULL);
            return -1;
        }

        struct stat st;
        if (stat(out_path, &st) == 0 && st.st_size != last_size) {
            last_size = st.st_size;
            last_progress_ns = clock_now_monotonic_ns();
        }

        int64_t silent_ns = clock_now_monotonic_ns() - last_progress_ns;
        if (silent_ns > (int64_t)max_silent_secs * 1000000000LL) {
            char load[64];
            lint_gate_loadavg(load, sizeof(load));
            long long silent_s = (long long)(silent_ns / 1000000000LL);
            long long total_s =
                (long long)((clock_now_monotonic_ns() - started_ns) / 1000000000LL);
            fprintf(stderr,
                "\n[gate-watchdog] WEDGED: %s produced no output for %llds.\n"
                "[gate-watchdog]   measured: %llds of silence; %llds total elapsed;"
                " loadavg %s.\n"
                "[gate-watchdog]   bound: %ds of SILENCE (not of runtime). %s\n"
                "[gate-watchdog]   This is a HANG report, not a failed assertion."
                " A busy or slow-disk\n"
                "[gate-watchdog]   box does not land here: it still emits its"
                " progress lines, just\n"
                "[gate-watchdog]   further apart, and every line resets this"
                " bound. Silence for this\n"
                "[gate-watchdog]   long means the script stopped making progress"
                " altogether.\n"
                "[gate-watchdog]   Partial output: %s\n",
                script_rel, silent_s, silent_s, total_s, load,
                max_silent_secs, why_bound ? why_bound : "(no derivation given)",
                out_path);
            /* SIGTERM the group first so the script's own EXIT trap runs and
             * tears down its fixture processes; SIGKILL only as a backstop. */
            (void)kill(-pid, SIGTERM);
            for (int i = 0; i < 50; i++) {
                if (waitpid(pid, &rc, WNOHANG) == pid) { wedged = 1; goto done; }
                struct timespec ts = {0, 100 * 1000 * 1000};
                (void)nanosleep(&ts, NULL);
            }
            (void)kill(-pid, SIGKILL);
            while (waitpid(pid, &rc, 0) < 0 && errno == EINTR) { }
            wedged = 1;
            goto done;
        }

        struct timespec ts = {0, 250 * 1000 * 1000};  /* 250 ms poll */
        (void)nanosleep(&ts, NULL);
    }

done:
    if (restore_chld)
        (void)sigaction(SIGCHLD, &old_chld, NULL);
    if (wedged) return GATE_SCRIPT_WEDGED;
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    return -1;
}

int plant_oversized_file(const char *rel, int n_lines)
{
    char path[PATH_MAX];
    if (repo_path(path, sizeof(path), rel) != 0) return -1;
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    for (int i = 0; i < n_lines; i++)
        fputs("// fixture line\n", fp);
    fclose(fp);
    return 0;
}

void unlink_rel(const char *rel)
{
    char path[PATH_MAX];
    if (repo_path(path, sizeof(path), rel) == 0)
        (void)unlink(path);
}

/* Write a single-function .c fixture whose gate-measured length (closing
 * brace line minus signature line) is exactly `target_len`, optionally
 * tagged `// long-function-ok:<tag>` on the signature line. Mirrors
 * plant_oversized_file's direct-fopen approach (no giant string buffer). */
int plant_long_function_file(const char *rel, const char *func_name,
                                    int target_len, const char *tag)
{
    char path[PATH_MAX];
    if (repo_path(path, sizeof(path), rel) != 0) return -1;
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    if (tag)
        fprintf(fp, "void %s(void) // long-function-ok:%s\n", func_name, tag);
    else
        fprintf(fp, "void %s(void)\n", func_name);
    fprintf(fp, "{\n");
    int body_lines = target_len - 2;
    if (body_lines < 1) body_lines = 1;
    for (int i = 0; i < body_lines; i++)
        fprintf(fp, "    (void)0; /* fixture line %d */\n", i);
    fprintf(fp, "}\n");
    fclose(fp);
    return 0;
}

/* ── META-GATE: fail-silent gates are now fail-LOUD on an empty scan ──────────
 *
 * A hollow gate reports "clean" exit 0 while a real violation is present: its
 * scan set silently emptied (a renamed/moved dir) and the violation loop ran
 * zero times. The fix (docs/work/lint-gate-hollowness-audit.md) is a non-empty
 * scan-set preflight that aborts exit 2 when the scan set is below a known
 * floor. Each hardened gate exposes a ZCL_*_SCAN_* env override of its scan
 * root so this meta-gate can feed it a GUARANTEED-EMPTY dir and assert exit 2
 * — the direct proof that "scanned nothing" is no longer a quiet pass.
 *
 * For each gate: (1) point its scan override at an empty dir → assert exit 2;
 * (2) run it with NO override → assert exit 0 (the real tree still passes).
 * This is the "plant → assert trip → remove → assert green" pattern, with the
 * empty scan dir as the planted fixture. */
/* One gate's empty-scan check: feed the gate an empty scan dir via its
 * override env var → assert exit 2 (fail-LOUD); run with no override → assert
 * exit 0 (real tree still clean). One TEST block per call (the TEST macro
 * defines a function-scoped `_test_next` label, so it must not repeat in a
 * single function). Returns 0 on pass, nonzero on failure. */
int meta_gate_empty_scan_trips(const char *script_rel,
                                      const char *env_name,
                                      const char *empty_value)
{
    int failures = 0;
    int trip_rc = run_gate_script_with_env(script_rel, env_name, empty_value);
    int green_rc = run_gate_script(script_rel, NULL);
    TEST("[lint-gate] META: empty/drifted scan trips gate exit 2, real tree passes") {
        /* Empty scan set MUST be exit 2 (fail-LOUD), never 0 (hollow) and
         * never 1 (a violation it could not actually have seen). */
        if (trip_rc != 2) {
            fprintf(stderr,
                    "[lint-gate] %s with empty %s: expected exit 2, got %d "
                    "(hollow gate?)\n", script_rel, env_name, trip_rc);
        }
        ASSERT(trip_rc == 2);
        if (green_rc != 0) {
            fprintf(stderr,
                    "[lint-gate] %s with no override: expected exit 0, got %d\n",
                    script_rel, green_rc);
        }
        ASSERT(green_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

void unlink_lint_fixtures(void)
{
    const char *fixtures[] = {
        FIXTURE_DST_REL,
        NODE_DB_EXEC_FIXTURE_DST_REL,
        COINS_FIXTURE_DST_REL,
        OBS_FIXTURE_DST_REL,
        OBS_OK_FIXTURE_DST_REL,
        RAW_MALLOC_FIXTURE_DST_REL,
        RAW_MALLOC_OK_FIXTURE_DST_REL,
        E1_BUFFER_FIXTURE_DST,
        E1_OVER_LIMIT_FIXTURE_DST,
        E10_SHAPE_FIXTURE_DST,
        E10_SQL_FIXTURE_DST,
        E10_SQL_SERVICE_FIXTURE_DST,
        MODEL_AR_FIXTURE_DST,
        E2_FIXTURE_DST,
        E3_FIXTURE_DST,
        E4_FIXTURE_DST,
        DOMAIN_PURITY_FIXTURE_DST,
        E5_FIXTURE_DST,
        E6_FIXTURE_DST,
        E7_FIXTURE_DST,
        E12_FIXTURE_DST,
        SUPDOM_BAD_WORKER_REL,
        SUPDOM_OK_WORKER_REL,
        CONSENSUS_PARITY_FIXTURE_DST,
        SILENT_BOOL_FIXTURE_DST,
    };

    for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); i++) {
        char path[PATH_MAX];
        if (repo_path(path, sizeof(path), fixtures[i]) == 0)
            (void)unlink(path);
    }
}

#else  /* !ZCL_TESTING */

/* Without ZCL_TESTING the lint-gate self-tests compile to nothing; this
 * keeps the translation unit non-empty. */
typedef int zcl_lint_gate_hlp_unit;

#endif /* ZCL_TESTING */
