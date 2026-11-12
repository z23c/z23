/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Signal contract of tools/agent/gate_receipt.c, the C23 receipt wrapper
 * behind build/bin/gate_receipt. Each case builds the wrapper into a
 * private fixture, starts it on a command that announces readiness through an
 * inherited pipe (never a pidfile), signals the wrapper, and checks that the
 * wrapper died of that signal, stopped and reaped its child, published no
 * receipt and left no temporary file. One case interrupts the helper build of
 * --selftest-helper and checks that its temporary directory is removed. */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#if defined(ZCL_TESTING) && !defined(_WIN32)

#include "lint_gate_selftests.h"

#include <poll.h>
#include <time.h>

#define RCPTSIG_READY_MS 60000
#define RCPTSIG_EXIT_MS 30000

struct rcptsig_proc {
    pid_t wrapper;
    pid_t child;
    int ready_fd;
};

static int rcptsig_run(char *const argv[])
{
    int status = 0;
    pid_t pid = fork();

    if (pid < 0)
        return -1;
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    if (waitpid(pid, &status, 0) != pid)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int rcptsig_build(const char *root, const char *fix)
{
    const char *cc = getenv("CC");
    char out[PATH_MAX], inc_a[PATH_MAX], inc_b[PATH_MAX], inc_c[PATH_MAX], inc_d[PATH_MAX];
    char s0[PATH_MAX], s1[PATH_MAX], s2[PATH_MAX], s3[PATH_MAX], s4[PATH_MAX], s5[PATH_MAX], dirs[PATH_MAX];

    snprintf(dirs, sizeof dirs, "%s/build/bin", fix);
    snprintf(out, sizeof out, "%s/gate_receipt", dirs);
    snprintf(inc_a, sizeof inc_a, "-I%s/platform/modules/sha3/include", root);
    snprintf(inc_b, sizeof inc_b, "-I%s/core/modules/crypto/include", root);
    snprintf(inc_c, sizeof inc_c, "-I%s/platform/modules/base/include", root);
    snprintf(inc_d, sizeof inc_d, "-I%s/platform/modules/support/include", root);
    snprintf(s0, sizeof s0, "%s/tools/agent/gate_receipt.c", root);
    snprintf(s1, sizeof s1, "%s/tools/agent/gate_receipt_proc.c", root);
    snprintf(s2, sizeof s2, "%s/tools/agent/gate_receipt_text.c", root);
    snprintf(s3, sizeof s3, "%s/platform/modules/sha3/src/sha3.c", root);
    snprintf(s4, sizeof s4, "%s/platform/modules/base/src/safe_alloc.c", root);
    char *const mk[] = {"mkdir", "-p", dirs, nullptr};
    char *const build[] = {(char *)(cc && *cc ? cc : "cc"), "-std=c23", "-O2", "-Wall", "-Wextra", "-Werror",
                           inc_a, inc_b, inc_c, inc_d, "-o", out, s0, s1, s2, s3, s4, nullptr};

    if (rcptsig_run(mk) != 0 || rcptsig_run(build) != 0)
        return -1;
    snprintf(out, sizeof out, "%s/agent_sha3", dirs);
    snprintf(s0, sizeof s0, "%s/tools/agent/agent_sha3.c", root);
    snprintf(s5, sizeof s5, "%s/platform/modules/sha3/src/sha3.c", root);
    char *const helper[] = {build[0], "-std=c23", "-O2", inc_a, inc_b, inc_c, inc_d, "-o", out, s0, s5, nullptr};

    return rcptsig_run(helper);
}

static int rcptsig_git_init(const char *fix)
{
    char *const init[] = {"git", "-C", (char *)fix, "init", "-q", nullptr};
    char *const commit[] = {"git", "-C", (char *)fix, "-c", "user.name=fixture", "-c",
                            "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit",
                            "-q", "--allow-empty", "-m", "fixture", nullptr};

    return rcptsig_run(init) != 0 || rcptsig_run(commit) != 0;
}

/* Starts the wrapper in `fix` with descriptor 3 connected to ready_fd. */
static int rcptsig_spawn(const char *fix, char *const args[], char *const env[], int out_fd,
                         struct rcptsig_proc *p)
{
    int rdy[2];
    char bin[PATH_MAX];
    size_t n = 0;
    char *argv[32];

    snprintf(bin, sizeof bin, "%s/build/bin/gate_receipt", fix);
    argv[n++] = bin;
    argv[n++] = (char *)fix;
    for (size_t i = 0; args[i] != nullptr && n < 30; i++)
        argv[n++] = args[i];
    argv[n] = nullptr;
    if (pipe(rdy) != 0)
        return -1;
    p->wrapper = fork();
    if (p->wrapper < 0)
        return -1;
    if (p->wrapper == 0) {
        signal(SIGINT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGHUP, SIG_DFL);
        sigset_t none;
        sigemptyset(&none);
        sigprocmask(SIG_SETMASK, &none, nullptr);
        dup2(rdy[1], 3);
        if (out_fd >= 0)
            dup2(out_fd, 1);
        for (size_t i = 0; env && env[i]; i++) {
            char *eq = strchr(env[i], '=');

            if (eq != nullptr) {
                *eq = '\0';
                setenv(env[i], eq + 1, 1);
            }
        }
        if (chdir(fix) == 0)
            execv(bin, argv);
        _exit(127);
    }
    close(rdy[1]);
    p->ready_fd = rdy[0];
    return 0;
}

/* The wrapped command writes "ready <pid>\n" once it is running. */
static int rcptsig_wait_ready(struct rcptsig_proc *p)
{
    struct pollfd pfd = {.fd = p->ready_fd, .events = POLLIN};
    char line[64] = {0};
    ssize_t n;
    int child;

    if (poll(&pfd, 1, RCPTSIG_READY_MS) != 1)
        return -1;
    n = read(p->ready_fd, line, sizeof line - 1);
    if (n <= 0 || sscanf(line, "ready %d", &child) != 1)
        return -1;
    p->child = (pid_t)child;
    return 0;
}

static int rcptsig_reap(struct rcptsig_proc *p, int *status)
{
    for (int waited = 0; waited < RCPTSIG_EXIT_MS; waited += 20) {
        pid_t r = waitpid(p->wrapper, status, WNOHANG);

        if (r == p->wrapper)
            return 0;
        if (r < 0)
            return -1;
        nanosleep(&(struct timespec){.tv_nsec = 20000000L}, nullptr);
    }
    kill(p->wrapper, SIGKILL);
    waitpid(p->wrapper, status, 0);
    return -1;
}

static int rcptsig_entries_with(const char *dir, const char *suffix)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    int n = 0;
    size_t sl = strlen(suffix);

    if (d == nullptr)
        return 0;
    while ((e = readdir(d)) != nullptr) {
        size_t l = strlen(e->d_name);

        n += l >= sl && strcmp(e->d_name + l - sl, suffix) == 0;
    }
    closedir(d);
    return n;
}

static int rcptsig_count_entries(const char *dir)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    int n = 0;

    if (d == nullptr)
        return -1;
    while ((e = readdir(d)) != nullptr)
        n += strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0;
    closedir(d);
    return n;
}

static void rcptsig_kill_leftover(struct rcptsig_proc *p)
{
    if (p->child > 0)
        kill(p->child, SIGKILL);
    if (p->ready_fd >= 0)
        close(p->ready_fd);
}

/* Signals the wrapper `count` times and reports whether it died of `sig`
 * with its child gone. */
static int rcptsig_signal_verdict(struct rcptsig_proc *p, int sig, int count)
{
    int status = 0;

    for (int i = 0; i < count; i++)
        kill(p->wrapper, sig);
    if (rcptsig_reap(p, &status) != 0 || !WIFSIGNALED(status) || WTERMSIG(status) != sig)
        return 1;
    return !(kill(p->child, 0) == -1 && errno == ESRCH);
}

static int rcptsig_signal_case(const char *fix, int sig, int count, const char *script)
{
    char receipts[PATH_MAX];
    char *const args[] = {"--gate", "sig", "--dir", "receipts", "--", "sh", "-c", (char *)script, nullptr};
    struct rcptsig_proc p = {.child = -1, .ready_fd = -1};
    int bad = 1;

    snprintf(receipts, sizeof receipts, "%s/receipts", fix);
    if (rcptsig_spawn(fix, args, nullptr, -1, &p) == 0 && rcptsig_wait_ready(&p) == 0)
        bad = rcptsig_signal_verdict(&p, sig, count);
    rcptsig_kill_leftover(&p);
    if (rcptsig_entries_with(receipts, ".receipt") != 0 || rcptsig_entries_with(receipts, ".tmp") != 0)
        bad = 1;
    if (bad)
        fprintf(stderr, "receipt signal case: signal %d x%d failed\n", sig, count);
    return bad;
}

/* Interrupts the compiler of --selftest-helper; the private directory the
 * selftest created must be gone. */
static int rcptsig_selftest_cleanup_case(const char *fix, int sig)
{
    char tmpdir[PATH_MAX], cc[PATH_MAX], env_tmp[PATH_MAX + 8], env_cc[PATH_MAX + 4];
    char *const args[] = {"--selftest-helper", nullptr};
    char *const env[] = {env_tmp, env_cc, nullptr};
    struct rcptsig_proc p = {.child = -1, .ready_fd = -1};
    FILE *f;
    int bad = 1;

    snprintf(tmpdir, sizeof tmpdir, "%s/tmp", fix);
    snprintf(cc, sizeof cc, "%s/slowcc", fix);
    snprintf(env_tmp, sizeof env_tmp, "TMPDIR=%s", tmpdir);
    snprintf(env_cc, sizeof env_cc, "CC=%s", cc);
    f = fopen(cc, "w");
    if (f == nullptr)
        return 1;
    fputs("#!/bin/sh\necho \"ready $$\" >&3\nexec sleep 60\n", f);
    fclose(f);
    chmod(cc, 0700);
    mkdir(tmpdir, 0700);
    if (rcptsig_spawn(fix, args, env, -1, &p) == 0 && rcptsig_wait_ready(&p) == 0 && rcptsig_count_entries(tmpdir) == 1)
        bad = rcptsig_signal_verdict(&p, sig, 1);
    rcptsig_kill_leftover(&p);
    if (rcptsig_count_entries(tmpdir) != 0)
        bad = 1;
    if (bad)
        fprintf(stderr, "receipt selftest cleanup: signal %d failed\n", sig);
    return bad;
}

/* The wrapper's stdout is a pipe nobody reads and the gate has filled it:
 * a signal must still stop the wrapper within the kill grace period. */
static int rcptsig_stalled_stdout_case(const char *fix)
{
    char *const args[] = {"--gate", "stall", "--dir", "receipts", "--", "sh", "-c",
                          "echo \"ready $$\" >&3; yes | head -c 4000000; exec sleep 60", nullptr};
    struct rcptsig_proc p = {.child = -1, .ready_fd = -1};
    int sink[2];
    int bad = 1;

    if (pipe(sink) != 0)
        return 1;
    if (rcptsig_spawn(fix, args, nullptr, sink[1], &p) == 0 && rcptsig_wait_ready(&p) == 0) {
        sleep(2);
        bad = rcptsig_signal_verdict(&p, SIGTERM, 1);
    }
    rcptsig_kill_leftover(&p);
    close(sink[0]);
    close(sink[1]);
    if (bad)
        fprintf(stderr, "receipt signal case: stalled stdout failed\n");
    return bad;
}

static const char rcptsig_plain[] = "echo \"ready $$\" >&3; exec sleep 60";
static const char rcptsig_stubborn[] = "trap '' INT TERM HUP; echo \"ready $$\" >&3; while :; do sleep 1; done";

int t_receipt_signals(void)
{
    char fix[PATH_MAX];
    int bad = 1;

    test_make_tmpdir(fix, sizeof fix, "receipt_signals", "wrapper");
    if (rcptsig_build(repo_root(), fix) == 0 && rcptsig_git_init(fix) == 0) {
        bad = rcptsig_signal_case(fix, SIGTERM, 1, rcptsig_plain);
        bad |= rcptsig_signal_case(fix, SIGINT, 1, rcptsig_plain);
        bad |= rcptsig_signal_case(fix, SIGHUP, 1, rcptsig_plain);
        bad |= rcptsig_signal_case(fix, SIGTERM, 2, rcptsig_plain);
        bad |= rcptsig_signal_case(fix, SIGTERM, 2, rcptsig_stubborn);
        bad |= rcptsig_stalled_stdout_case(fix);
        bad |= rcptsig_selftest_cleanup_case(fix, SIGTERM);
        bad |= rcptsig_selftest_cleanup_case(fix, SIGINT);
    } else {
        fprintf(stderr, "receipt signals: fixture build failed\n");
    }
    if (test_rm_rf_recursive(fix) != 0) {
        fprintf(stderr, "receipt signals: fixture cleanup failed\n");
        bad = 1;
    }
    return bad;
}

#endif /* ZCL_TESTING && !_WIN32 */
