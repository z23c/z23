/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The fork+exec half of the lint-gate self-test plumbing: every wrapper that
 * runs a gate script (plain, with worker files, with one to three environment
 * overrides, or under the silence watchdog) and reports its exit status.
 *
 * Kept in its own translation unit, separate from lint_gate_helpers.c's pure
 * file/string utilities: the testcache exec rail scans a group's authored
 * harness files for exec call sites, and a group that links this file runs
 * repo scripts whose bytes its closure key never hashes — it must refuse
 * caching. Groups that only copy files or walk directories link the helpers
 * file and stay cacheable.
 *
 * Nothing here asserts. The checks that do live in the sibling
 * lint_gate_*.c files; see lint_gate_selftests.h for the map. */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

/* The lint-gate self-test family fork+execs POSIX bash gate scripts; on
 * _WIN32 every helper compiles out and the group entry points report a skip. */
#if defined(ZCL_TESTING) && !defined(_WIN32)

#include "lint_gate_selftests.h"
#include "platform/clock.h"

/* fork() can transiently fail with EAGAIN/ENOMEM under load. Every
 * gate-script runner forks once and treats fork() < 0 as harness failure
 * (-1), so retry up to 8 attempts with exponential backoff (20 ms doubling,
 * capped at 500 ms, ~1.6 s worst case) before giving up. Each retry is
 * logged with its errno. */
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
    /* Retries exhausted: distinguish from an ordinary gate failure (rc != 0). */
    fprintf(stderr,
            "[lint-gate] fork() failed all %d attempts (errno=%d %s) — "
            "harness failure under sustained resource pressure, not a gate "
            "failure\n",
            ZCL_FORK_RETRY_ATTEMPTS, errno, strerror(errno));
    return -1;
}

/* Keep real phase changes visible to the group runner while the epoch
 * selftest's ordinary output stays in the per-gate diagnostic file. */
static void epoch_selftest_progress_channel(const char *script_rel)
{
    if (strcmp(script_rel, "tools/dev/build-epoch-selftest.sh") != 0)
        return;
    int progress_fd = dup(STDOUT_FILENO);
    if (progress_fd < 0)
        return;
    char fd_text[24];
    (void)snprintf(fd_text, sizeof(fd_text), "%d", progress_fd);
    if (setenv("EPOCH_SELFTEST_PROGRESS_FD", fd_text, 1) != 0)
        close(progress_fd);
}

/* Runs a gate rel: a script path, or "<binary> <subcommand>" for a lintc gate
 * exec'd as `z23-lint check-X` (no shell shim). Splits the buffer in place;
 * only ever called in the forked child, so the parent copy is untouched. */
void gate_exec(char *rel, const char *arg)
{
    char *sub = strchr(rel, ' ');
    if (sub != NULL)
        *sub++ = '\0';
    if (sub != NULL && arg != NULL)
        execl(rel, rel, sub, arg, (char *)NULL);
    else if (sub != NULL)
        execl(rel, rel, sub, (char *)NULL);
    else if (arg != NULL)
        execl(rel, rel, arg, (char *)NULL);
    else
        execl(rel, rel, (char *)NULL);
}

/* Generalized gate-script runner: fork/exec the script at repo-relative
 * path `script_rel`, optionally with ZCL_LINT_MODE set to `mode` (NULL to
 * leave unset) and optionally one argv word `arg` (NULL for none).
 * Returns the script's exit status (0 = clean, non-zero = violations), or -1
 * on harness failure.
 *
 * `arg` serves gates that own their trip/recover matrix behind a `--selftest`
 * flag; the shell already builds and tears down the fixture sandbox. */
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
        epoch_selftest_progress_channel(script_rel);
        int fd = open(out_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (fd >= 0) {
            (void)dup2(fd, STDOUT_FILENO);
            (void)dup2(fd, STDERR_FILENO);
            close(fd);
        }
        if (mode)
            (void)setenv("ZCL_LINT_MODE", mode, 1);
        if (arg)
            gate_exec(script, arg);
        else
            gate_exec(script, NULL);
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
 * Gate #21 background-worker scan reads a planted fixture instead of
 * engine/composition/src/boot_background_workers.c. `worker_files` is a
 * space-separated repo-relative path list, resolved to absolute paths before
 * export. */
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
        gate_exec(script, NULL);
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

/* Like run_gate_script but exports ONE arbitrary env var (name=value). Used
 * by the META-GATE, which points each hardened gate at an empty scan dir and
 * asserts exit 2. */
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
        gate_exec(script, NULL);
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
 * service-result-convergence self-test to isolate both the scan dir and the
 * baseline file. */
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
        gate_exec(script, NULL);
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

/* Child side of run_gate_script_envv: redirect output, export the
 * overrides, exec the gate. Never returns. */
static void gate_envv_child(const char *script, const char *out_path,
                            const char *const *names,
                            const char *const *values, size_t n)
{
    int fd = open(out_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd >= 0) {
        (void)dup2(fd, STDOUT_FILENO);
        (void)dup2(fd, STDERR_FILENO);
        close(fd);
    }
    for (size_t i = 0; i < n; i++)
        if (names[i] && values[i])
            (void)setenv(names[i], values[i], 1);
    gate_exec(script, NULL);
    _exit(127);
}

/* Runs a gate script with `n` exported env overrides and returns its exit
 * status, or -1. SIGCHLD is held at SIG_DFL for the wait, as its siblings
 * do. */
static int run_gate_script_envv(const char *script_rel,
                                const char *const *names,
                                const char *const *values, size_t n)
{
    char script[PATH_MAX], out_path[PATH_MAX];
    if (repo_path(script, sizeof(script), script_rel) != 0 ||
        lint_gate_out_path(out_path, sizeof(out_path)) != 0)
        return -1;
    struct sigaction old_chld, dfl_chld;
    memset(&old_chld, 0, sizeof(old_chld));
    memset(&dfl_chld, 0, sizeof(dfl_chld));
    dfl_chld.sa_handler = SIG_DFL;
    sigemptyset(&dfl_chld.sa_mask);
    int restore_chld = sigaction(SIGCHLD, NULL, &old_chld) == 0 &&
                       sigaction(SIGCHLD, &dfl_chld, NULL) == 0;
    pid_t pid = fork_with_retry();
    if (pid == 0)
        gate_envv_child(script, out_path, names, values, n);
    int rc = 0;
    pid_t waited = -1;
    if (pid > 0)
        while ((waited = waitpid(pid, &rc, 0)) < 0 && errno == EINTR)
            ;
    if (restore_chld)
        (void)sigaction(SIGCHLD, &old_chld, NULL);
    return waited == pid && WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
}

/* Like run_gate_script_with_env2 but exports THREE env vars. Used by the
 * git-hooks-installed self-tests, which also point the gate at a hermetic
 * fixture root (ZCL_GIT_HOOK_ROOT) so the verdict does not depend on this
 * checkout's installed hooks. */
int run_gate_script_with_env3(const char *script_rel,
                              const char *env_name1, const char *env_value1,
                              const char *env_name2, const char *env_value2,
                              const char *env_name3, const char *env_value3)
{
    const char *const names[] = {env_name1, env_name2, env_name3};
    const char *const values[] = {env_value1, env_value2, env_value3};
    return run_gate_script_envv(script_rel, names, values, 3);
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

/* ── run_gate_script_watched: a progress watchdog, not a stopwatch ─────────
 *
 * The bound is on silence, not elapsed time: the parent resets it whenever
 * the child's output file grows, so a slow box still passes and a wedged
 * script (no output) is killed.
 *
 * `max_silent_secs` must be derived from the longest deliberate silence in
 * the script (its own poll windows); the caller passes that derivation in
 * `why_bound`, printed on every timeout.
 *
 * Returns the script's exit status, GATE_SCRIPT_WEDGED when killed for
 * silence (diagnosed on stderr), or -1 on a harness error.
 * GATE_SCRIPT_WEDGED is deliberately not 1: a hang and a failed assertion
 * never share an exit code. */
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
        gate_exec(script, NULL);
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
                (void)nanosleep(&ts, NULL); /* real-clock: pre-existing bounded poll loop, seeded when check_no_real_clock_test_deadline.sh was introduced */
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

#else  /* !ZCL_TESTING */

/* Without ZCL_TESTING the lint-gate self-tests compile to nothing; this
 * keeps the translation unit non-empty. */
typedef int zcl_lint_gate_exec_unit;

#endif /* ZCL_TESTING */
