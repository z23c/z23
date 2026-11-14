/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: exercise live journey child status, timeout and capture ownership. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#define main app_journey_live_main
#include "app_journey_live.c"
#undef main
#include <limits.h>

static volatile sig_atomic_t aj_interrupted;
static void aj_test_interrupt(int sig) { (void)sig; aj_interrupted = 1; }

static int aj_test_child(const char *mode)
{
    if (!strcmp(mode, "held")) {
        pid_t p = fork();
        if (p < 0) return 99;
        if (p == 0) { sleep(2); _exit(0); }
        return 7;
    }
    if (!strcmp(mode, "signal")) { raise(SIGKILL); return 99; }
    /* Real delay lets the parent enter its wait before the interrupt. */
    if (!strcmp(mode, "interrupt")) { sleep(1); kill(getppid(), SIGUSR1); sleep(1); return 0; }
    if (!strcmp(mode, "timeout")) { sleep(5); return 0; }
    return 0;
}

static int aj_test_call(const char *mode, int timeout, int expected)
{
    char out[256];
    char *args[] = {(char *)"z23", (char *)"--child", (char *)mode, NULL};
    int got = aj_run("/", "/", timeout, out, sizeof out, args);
    if (got != expected) {
        fprintf(stderr, "%s: expected %d, got %d\n", mode, expected, got);
        return 1;
    }
    printf("%s: PASS\n", mode);
    return 0;
}

static int aj_test_setup(const char *self, const char *tmp)
{
    char path[PATH_MAX + 32];
    if (snprintf(g_repo, sizeof g_repo, "%s", tmp) >= (int)sizeof g_repo ||
        snprintf(path, sizeof path, "%s/build", tmp) >= (int)sizeof path || mkdir(path, 0700)) return 2;
    if (snprintf(path, sizeof path, "%s/build/bin", tmp) >= (int)sizeof path || mkdir(path, 0700)) return 2;
    if (snprintf(path, sizeof path, "%s/build/bin/z23", tmp) >= (int)sizeof path || symlink(self, path)) return 2;
    return 0;
}

static int aj_group_startup_test(void)
{
    int ready[2], gate[2];
    if (pipe(ready) || pipe(gate)) return 1;
    pid_t p = fork();
    if (p < 0) return 1;
    if (!p) {
        close(ready[0]); close(gate[1]);
        char b = 'r';
        if (write(ready[1], &b, 1) != 1) _exit(2);
        if (read(gate[0], &b, 1) < 0) _exit(2);
        _exit(0);
    }
    close(ready[1]); close(gate[0]);
    struct pollfd fd = {.fd = ready[0], .events = POLLIN};
    char b; bool ready_ok = poll(&fd, 1, 3000) > 0 && (fd.revents & POLLIN) && read(ready[0], &b, 1) == 1;
    bool stopped = ready_ok && aj_kill_group(p);
    close(ready[0]); close(gate[1]);
    if (!stopped && aj_observe_child(p, WNOHANG) >= 0) {
        (void)kill(p, SIGKILL); (void)waitpid(p, NULL, 0);
    }
    if (!stopped) fprintf(stderr, "group startup custody failed\n");
    else puts("group pre-setsid cleanup: PASS");
    return stopped ? 0 : 1;
}

static void aj_group_test_leader(int ready[2], int alive[2])
{
    close(ready[0]); close(alive[0]);
    if (setsid() < 0 || signal(SIGTERM, SIG_IGN) == SIG_ERR) _exit(2);
    pid_t child = fork();
    if (child < 0) _exit(2);
    if (!child) { close(ready[1]); for (;;) pause(); }
    if (signal(SIGTERM, SIG_DFL) == SIG_ERR) _exit(2);
    char b = 'r'; if (write(ready[1], &b, 1) != 1) _exit(2);
    for (;;) pause();
}

static bool aj_group_test_wait_other(pid_t other)
{
    int st; pid_t got; do { got = waitpid(other, &st, 0); } while (got < 0 && errno == EINTR);
    return got == other && WIFEXITED(st) && WEXITSTATUS(st) == 42 &&
        !aj_kill_group(other) && !aj_kill_group(getpid());
}

static bool aj_group_test_finish(pid_t p, int ready, int alive)
{
    struct pollfd ready_fd = {.fd = ready, .events = POLLIN};
    char b; bool ready_ok = p > 0 && poll(&ready_fd, 1, 3000) > 0 &&
        (ready_fd.revents & POLLIN) && read(ready, &b, 1) == 1;
    bool stopped = p > 0 && aj_kill_group(p);
    bool absent = stopped && kill(-p, 0) < 0 && errno == ESRCH;
    close(ready);
    struct pollfd fd = {.fd = alive, .events = POLLIN | POLLHUP};
    bool eof = poll(&fd, 1, 3000) > 0 && (fd.revents & POLLHUP) && read(alive, &b, 1) == 0;
    close(alive);
    return ready_ok && stopped && absent && eof;
}

static int aj_group_owned_test(void)
{
    int ready[2], alive[2];
    if (pipe(ready) || pipe(alive)) return 1;
    pid_t other = fork();
    if (!other) _exit(42);
    if (other < 0) return 1;
    pid_t p = fork();
    if (!p) aj_group_test_leader(ready, alive);
    close(ready[1]); close(alive[1]);
    bool ok = aj_group_test_finish(p, ready[0], alive[0]);
    ok = aj_group_test_wait_other(other) && ok;
    if (ok) puts("group descendant and unrelated custody: PASS");
    return ok ? 0 : 1;
}

static int aj_test_cases(void)
{
    struct sigaction action = {0}, old;
    action.sa_handler = aj_test_interrupt;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, &old) != 0) return 1;
    int failed = aj_test_call("held", 8, 7) | aj_test_call("ok", 8, 0) |
                 aj_test_call("signal", 8, -1) | aj_test_call("timeout", 1, -1) |
                 aj_test_call("interrupt", 8, 0);
    if (!aj_interrupted || sigaction(SIGUSR1, &old, NULL) != 0) failed = 1;
    pid_t p = fork();
    if (p == 0) _exit(0);
    int st;
    g_alarm_fired = 0;
    if (p < 0 || waitpid(p, &st, 0) != p || aj_finish_child(p, true) != -1) failed = 1;
    else puts("ECHILD: PASS");
    int fds[2]; char out[4] = "bad";
    if (pipe(fds) != 0) return 1;
    close(fds[0]); close(fds[1]);
    if (aj_capture_pipe(fds[0], getpid(), out, sizeof out) || out[0] != '\0') failed = 1;
    else puts("capture read failure: PASS");
    return failed;
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "--child")) return aj_test_child(argv[2]);
    char self[PATH_MAX], tmp[PATH_MAX], root[PATH_MAX];
    const char *base = getenv("TMPDIR"), *home = getenv("HOME");
    if (!base || !*base) {
        if (!home || snprintf(root, sizeof root, "%s/.cache/development-scratch/z23", home) >= (int)sizeof root || aj_mkdir_p(root)) return 2;
        base = root;
    }
    if (!realpath(argv[0], self) || snprintf(tmp, sizeof tmp, "%s/app-journey-test.XXXXXX", base) >= (int)sizeof tmp || !mkdtemp(tmp)) return 2;
    int failed = aj_test_setup(self, tmp);
    if (!failed) failed = aj_test_cases() | aj_group_startup_test() | aj_group_owned_test();
    if (!aj_rm_rf(tmp, 0)) failed = 1;
    if (!failed) puts("app journey child status selftest: PASS");
    return failed;
}
