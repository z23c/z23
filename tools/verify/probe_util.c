/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Helpers for the unprivileged verifier probes; see probe_util.h. */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#include "verify/probe_util.h"

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

void pu_argv_add(struct pu_argv *a, const char *arg)
{
    if (a->n >= PU_ARGV_MAX) {
        fputs("probe_util: argument vector full\n", stderr);
        exit(70);
    }
    a->v[a->n++] = arg;
    a->v[a->n] = nullptr;
}

void pu_argv_addv(struct pu_argv *a, const char *const *args)
{
    for (; *args; ++args) pu_argv_add(a, *args);
}

static bool redirect(posix_spawn_file_actions_t *fa, int fd, const char *path)
{
    if (!path) return true;
    return posix_spawn_file_actions_addopen(fa, fd, path,
               O_WRONLY | O_CREAT | O_TRUNC, 0666) == 0;
}

const char *pu_at(const char *dir, const char *name)
{
    static char slot[8][PU_PATH_MAX];
    static unsigned next;
    char *p = slot[next++ % 8u];
    pu_poll_signal();
    if (snprintf(p, PU_PATH_MAX, "%s/%s", dir, name) >= (int)PU_PATH_MAX) {
        fputs("probe_util: path too long\n", stderr);
        exit(70);
    }
    return p;
}

bool pu_read(const char *path, char *buf, size_t cap, size_t *len, bool trim)
{
    FILE *f = fopen(path, "rb");
    pu_poll_signal();
    if (!f) return false;
    size_t n = fread(buf, 1, cap - 1u, f);
    bool ok = !ferror(f) && fgetc(f) == EOF && !ferror(f);
    ok = fclose(f) == 0 && ok;
    while (trim && n > 0 && buf[n - 1u] == '\n') --n;
    buf[n] = '\0';
    if (len) *len = n;
    pu_poll_signal();
    return ok;
}

bool pu_has_line(const char *path, const char *line)
{
    FILE *f = fopen(path, "r");
    char *buf = nullptr;
    size_t cap = 0, want = strlen(line);
    ssize_t n;
    bool found = false;
    if (!f) return false;
    while (!found && (n = getline(&buf, &cap, f)) >= 0) {
        if (n > 0 && buf[n - 1] == '\n') --n;
        found = (size_t)n == want && memcmp(buf, line, want) == 0;
    }
    free(buf);
    fclose(f);
    pu_poll_signal();
    return found;
}

bool pu_same_file(const char *a, const char *b)
{
    FILE *fa = fopen(a, "rb");
    FILE *fb = fopen(b, "rb");
    bool same = fa && fb;
    while (same) {
        char x[8192], y[8192];
        size_t nx = fread(x, 1, sizeof x, fa);
        size_t ny = fread(y, 1, sizeof y, fb);
        same = nx == ny && memcmp(x, y, nx) == 0 && !ferror(fa) && !ferror(fb);
        if (nx < sizeof x) break;
    }
    if (fa) fclose(fa);
    if (fb) fclose(fb);
    pu_poll_signal();
    return same;
}

bool pu_copy(const char *src, const char *dst)
{
    FILE *in = fopen(src, "rb");
    FILE *out = in ? fopen(dst, "wb") : nullptr;
    bool ok = in && out;
    while (ok) {
        char buf[8192];
        size_t n = fread(buf, 1, sizeof buf, in);
        ok = fwrite(buf, 1, n, out) == n && !ferror(in);
        if (n < sizeof buf) break;
    }
    if (in) fclose(in);
    if (out) ok = fclose(out) == 0 && ok;
    pu_poll_signal();
    return ok;
}

static bool fmt_fits(int r, size_t cap) { return r >= 0 && (size_t)r < cap; }

bool pu_mkdirs(const char *path)
{
    char buf[PU_PATH_MAX];
    if (!fmt_fits(snprintf(buf, sizeof buf, "%s", path), sizeof buf))
        return false;
    for (char *p = buf + 1; *p; ++p) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(buf, 0777) != 0 && errno != EEXIST) return false;
        *p = '/';
    }
    return mkdir(buf, 0777) == 0 || errno == EEXIST;
}

#define SCRATCH_SLOTS 4u

static char g_dirs[SCRATCH_SLOTS][PU_PATH_MAX];
static volatile sig_atomic_t g_count;
static volatile sig_atomic_t g_cleaning;
static volatile sig_atomic_t g_sig;
static bool g_installed;

static void signal_set(sigset_t *set)
{
    sigemptyset(set);
    sigaddset(set, SIGINT);
    sigaddset(set, SIGTERM);
    sigaddset(set, SIGHUP);
}

static int remove_entry(const char *p, const struct stat *sb, int type,
                        struct FTW *ftw)
{
    (void)sb;
    (void)type;
    (void)ftw;
    return remove(p);
}

void pu_scratch_remove(const char *path)
{
    nftw(path, remove_entry, 16, FTW_DEPTH | FTW_PHYS);
}

static void cleanup(void)
{
    sigset_t set;
    signal_set(&set);
    sigprocmask(SIG_BLOCK, &set, nullptr);
    if (g_cleaning) return;
    g_cleaning = 1;
    for (sig_atomic_t i = 0; i < g_count; ++i) pu_scratch_remove(g_dirs[i]);
}

/* The handler only records the signal; the main path acts on it. */
static void on_signal(int sig)
{
    g_sig = sig;
}

static void on_child(int sig)
{
    (void)sig;
}

static void die_by_signal(int sig)
{
    struct sigaction sa;
    sigset_t set;
    cleanup();
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, nullptr);
    signal_set(&set);
    sigprocmask(SIG_UNBLOCK, &set, nullptr);
    raise(sig);
    _exit(128 + sig);
}

void pu_poll_signal(void)
{
    if (g_sig) die_by_signal(g_sig);
}

static void install_handlers(void)
{
    static const int sigs[] = {SIGINT, SIGTERM, SIGHUP, SIGCHLD};
    struct sigaction sa;
    if (g_installed) return;
    memset(&sa, 0, sizeof sa);
    sigemptyset(&sa.sa_mask);
    for (size_t i = 0; i < 4u; ++i) {
        sa.sa_handler = sigs[i] == SIGCHLD ? on_child : on_signal;
        sigaction(sigs[i], &sa, nullptr);
    }
    atexit(cleanup);
    g_installed = true;
}

bool pu_scratch_make(const char *templ, char *out, size_t cap)
{
    sigset_t set, old;
    bool ok = strlen(templ) < cap && strlen(templ) < PU_PATH_MAX &&
              (size_t)g_count < SCRATCH_SLOTS;
    if (!ok) return false;
    install_handlers();
    signal_set(&set);
    sigprocmask(SIG_BLOCK, &set, &old);
    ok = fmt_fits(snprintf(out, cap, "%s", templ), cap) &&
         mkdtemp(out) != nullptr;
    if (ok) {
        /* mkdtemp keeps the length, and strlen(templ) < PU_PATH_MAX above. */
        memcpy(g_dirs[g_count], out, strlen(out) + 1u);
        g_count = g_count + 1;
    }
    sigprocmask(SIG_SETMASK, &old, nullptr);
    pu_poll_signal();
    return ok;
}

/* Spawn with the cleanup signals blocked in the parent; the child starts
 * with default dispositions and an empty mask. */
static bool spawn_child(const struct pu_argv *a, posix_spawn_file_actions_t *fa,
                        pid_t *pid)
{
    posix_spawnattr_t attr;
    sigset_t cleanup_set, none;
    signal_set(&cleanup_set);
    sigemptyset(&none);
    if (posix_spawnattr_init(&attr) != 0) return false;
    bool ok = posix_spawnattr_setsigmask(&attr, &none) == 0 &&
              posix_spawnattr_setsigdefault(&attr, &cleanup_set) == 0 &&
              posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK |
                                              POSIX_SPAWN_SETSIGDEF) == 0 &&
              posix_spawnp(pid, a->v[0], fa, &attr, (char *const *)a->v,
                           environ) == 0;
    posix_spawnattr_destroy(&attr);
    return ok;
}

/* Wait for pid with the cleanup signals and SIGCHLD blocked except inside
 * sigsuspend, so a signal cannot slip between the check and the wait. A
 * recorded signal is forwarded to the child, which is reaped before exit. */
/* After forwarding a signal: give the child 5 s to exit, then kill it. */
static void reap_forwarded(pid_t pid, int sig)
{
    int status;
    kill(pid, sig);
    for (int i = 0; i < 500; ++i) {
        if (waitpid(pid, &status, WNOHANG) != 0) return;
        nanosleep(&(struct timespec){.tv_nsec = 10000000}, nullptr);
    }
    kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
}

static int wait_child(pid_t pid, const sigset_t *old)
{
    int status;
    for (;;) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) break;
        if (r < 0 && errno != EINTR) return -1;
        if (g_sig) {
            reap_forwarded(pid, g_sig);
            die_by_signal(g_sig);
        }
        sigsuspend(old);
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int pu_run(const struct pu_argv *a, const char *out_path, const char *err_path)
{
    posix_spawn_file_actions_t fa;
    sigset_t block, old;
    pid_t pid;
    pu_poll_signal();
    install_handlers();
    if (posix_spawn_file_actions_init(&fa) != 0) return -1;
    bool ok = redirect(&fa, 1, out_path) && redirect(&fa, 2, err_path);
    fflush(nullptr);
    signal_set(&block);
    sigaddset(&block, SIGCHLD);
    sigprocmask(SIG_BLOCK, &block, &old);
    ok = ok && spawn_child(a, &fa, &pid);
    posix_spawn_file_actions_destroy(&fa);
    int rc = ok ? wait_child(pid, &old) : -1;
    sigprocmask(SIG_SETMASK, &old, nullptr);
    pu_poll_signal();
    return rc;
}

bool pu_repo_root(char *out, size_t cap)
{
    char tmp[PU_PATH_MAX], file[PU_PATH_MAX + 8u];
    struct pu_argv a = {.n = 0};
    pu_argv_add(&a, "git");
    pu_argv_add(&a, "rev-parse");
    pu_argv_add(&a, "--show-toplevel");
    if (!pu_scratch_make("/tmp/z23-probe-root.XXXXXX", tmp, sizeof tmp))
        return false;
    snprintf(file, sizeof file, "%s/out", tmp);
    bool ok = pu_run(&a, file, nullptr) == 0 && pu_read(file, out, cap, nullptr, true);
    pu_scratch_remove(tmp);
    return ok;
}

long long pu_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts); // platform-ok:standalone probe has no platform clock link
    return (long long)ts.tv_sec * 1000000000ll + ts.tv_nsec;
}

static bool selftest_run(const char *dir)
{
    struct pu_argv ok = {.n = 0}, bad = {.n = 0}, none = {.n = 0};
    const char *out = pu_at(dir, "out");
    pu_argv_add(&ok, "sh");
    pu_argv_add(&ok, "-c");
    pu_argv_add(&ok, "echo hello; exit 0");
    pu_argv_add(&bad, "sh");
    pu_argv_add(&bad, "-c");
    pu_argv_add(&bad, "echo oops >&2; exit 7");
    pu_argv_add(&none, "z23-no-such-command");
    return pu_run(&ok, out, nullptr) == 0 && pu_has_line(out, "hello") &&
           pu_run(&bad, nullptr, out) == 7 && pu_has_line(out, "oops") &&
           !pu_has_line(out, "oo") && pu_run(&none, nullptr, nullptr) == -1;
}

static bool selftest_files(const char *dir)
{
    char buf[16];
    size_t n = 0;
    const char *a = pu_at(dir, "a");
    const char *b = pu_at(dir, "deep/er/b");
    FILE *f = fopen(a, "wb");
    if (!f || fputs("abc\n\n", f) == EOF || fclose(f) != 0) return false;
    if (!pu_mkdirs(pu_at(dir, "deep/er")) || !pu_copy(a, b)) return false;
    if (!pu_same_file(a, b) || !pu_read(b, buf, sizeof buf, &n, true) ||
        n != 3u || strcmp(buf, "abc") != 0) return false;
    f = fopen(b, "ab");
    if (!f || fputc('x', f) == EOF || fclose(f) != 0) return false;
    return !pu_same_file(a, b) && !pu_same_file(a, pu_at(dir, "missing"));
}

/* Child makes a scratch tree, then ends by signal (or exit when sig is 0);
 * the tree must be gone and the status must be the signal's. */
static bool end_case(int sig)
{
    int fd[2], status;
    char dir[PU_PATH_MAX] = "";
    struct stat st;
    if (pipe(fd) != 0) return false;
    fflush(nullptr);
    pid_t pid = fork();
    if (pid == 0) {
        char d[PU_PATH_MAX];
        if (!pu_scratch_make("/tmp/z23-probe-sig.XXXXXX", d, sizeof d) ||
            !pu_mkdirs(pu_at(d, "a/b")) || write(fd[1], d, strlen(d) + 1) < 0)
            _exit(1);
        if (sig) raise(sig);
        pu_poll_signal();
        exit(0);
    }
    close(fd[1]);
    ssize_t n = read(fd[0], dir, sizeof dir - 1u);
    close(fd[0]);
    if (pid < 0 || n <= 0 || waitpid(pid, &status, 0) != pid) return false;
    bool ended = sig ? WIFSIGNALED(status) && WTERMSIG(status) == sig
                     : WIFEXITED(status) && WEXITSTATUS(status) == 0;
    return ended && stat(dir, &st) != 0;
}

/* Child side: make a scratch tree and run a long helper inside it. */
static _Noreturn void long_helper_child(int wfd)
{
    char d[PU_PATH_MAX], cmd[2u * PU_PATH_MAX];
    struct pu_argv a = {.n = 0};
    if (!pu_scratch_make("/tmp/z23-probe-run.XXXXXX", d, sizeof d) ||
        write(wfd, d, strlen(d) + 1) < 0) _exit(1);
    snprintf(cmd, sizeof cmd, "echo $$ > %s/pid; exec sleep 30", d);
    pu_argv_add(&a, "sh");
    pu_argv_add(&a, "-c");
    pu_argv_add(&a, cmd);
    _exit(pu_run(&a, nullptr, nullptr) == 0 ? 0 : 1);
}

static long helper_pid(const char *dir)
{
    char pidfile[PU_PATH_MAX + 8u], text[32] = "";
    snprintf(pidfile, sizeof pidfile, "%s/pid", dir);
    for (int i = 0; i < 500; ++i) {
        if (pu_read(pidfile, text, sizeof text, nullptr, true) && atol(text) > 1)
            break;
        nanosleep(&(struct timespec){.tv_nsec = 10000000}, nullptr);
    }
    return atol(text);
}

/* The signal sent to the child must reach the helper, remove the tree and
 * give the child the signal's status; twice sends it again at once. */
static bool running_child_case(int sig, bool twice)
{
    int fd[2], status;
    char dir[PU_PATH_MAX] = "";
    struct stat st;
    if (pipe(fd) != 0) return false;
    fflush(nullptr);
    pid_t pid = fork();
    if (pid == 0) long_helper_child(fd[1]);
    close(fd[1]);
    ssize_t n = read(fd[0], dir, sizeof dir - 1u);
    close(fd[0]);
    if (pid < 0 || n <= 0) return false;
    long helper = helper_pid(dir);
    kill(pid, sig);
    if (twice) kill(pid, sig);
    if (helper <= 1 || waitpid(pid, &status, 0) != pid) return false;
    return WIFSIGNALED(status) && WTERMSIG(status) == sig &&
           stat(dir, &st) != 0 && kill((pid_t)helper, 0) != 0;
}

int pu_selftest(void)
{
    char dir[PU_PATH_MAX];
    bool ok = end_case(0) && end_case(SIGTERM) && end_case(SIGINT) &&
              end_case(SIGHUP) && running_child_case(SIGTERM, false) &&
              running_child_case(SIGINT, false) &&
              running_child_case(SIGHUP, false) &&
              running_child_case(SIGTERM, true) &&
              running_child_case(SIGINT, true);
    if (!ok || !pu_scratch_make("/tmp/z23-probe-selftest.XXXXXX", dir,
                                sizeof dir)) {
        puts("probe_util_selftest=FAIL");
        return 1;
    }
    ok = selftest_run(dir) && selftest_files(dir);
    pu_scratch_remove(dir);
    struct stat st;
    ok = ok && stat(dir, &st) != 0;
    puts(ok ? "probe_util_selftest=PASS" : "probe_util_selftest=FAIL");
    return ok ? 0 : 1;
}
