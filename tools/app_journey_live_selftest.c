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

static int aj_test_cli(int argc, char **argv)
{
    for (int i = 0; i + 1 < argc; ++i) if (!strcmp(argv[i], "app") && !strcmp(argv[i + 1], "get")) {
        if (i + 2 == argc) {
            char path[PATH_MAX];
            const char *home = getenv("HOME");
            if (!home || snprintf(path, sizeof(path), "%s/catalog-error", home) >= (int)sizeof(path)) return 2;
            if (access(path, F_OK) == 0) return 7;
            if (snprintf(path, sizeof(path), "%s/catalog-absent", home) >= (int)sizeof(path)) return 2;
            puts(access(path, F_OK) == 0 ? "example/app-extra abc root 1s ago" : "example/app abc 0123456789abcdef 1s ago");
            return 0;
        }
        int fd = open("get-count", O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (fd < 0) return 2;
        char b = 'x'; bool ok = write(fd, &b, 1) == 1 && close(fd) == 0;
        if (!ok) return 2;
        if (access("get-success", F_OK) == 0) { puts("retrieval succeeded"); return 0; }
        puts("distinctive retrieval failure"); return 7;
    }
    return -1;
}

static bool aj_single_get_success(struct aj_node_ctx *c, const char *tmp, const char *path)
{
    char success[PATH_MAX], out[4096]; struct stat st;
    if (snprintf(success, sizeof(success), "%s/get-success", tmp) >= (int)sizeof(success)) return false;
    int fd = open(success, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0 || close(fd) != 0) return false;
    bool passed = aj_b_get_once(c, out, sizeof(out)) && strstr(out, "retrieval succeeded");
    bool once = stat(path, &st) == 0 && st.st_size == 1;
    bool cleaned = unlink(success) == 0 && unlink(path) == 0;
    return passed && once && cleaned;
}

static int aj_single_get_test(const char *tmp)
{
    struct aj_node_ctx c = {.rpc = 1};
    size_t len = strlen(tmp);
    if (len >= sizeof(c.datadir) || len >= sizeof(g_repo_app)) return 1;
    memcpy(c.datadir, tmp, len + 1); memcpy(c.home, tmp, len + 1);
    memcpy(g_repo_app, tmp, len + 1);
    snprintf(g_name, sizeof(g_name), "example/app");
    g_board_wait_s = 3;
    char out[4096], path[PATH_MAX];
    bool failed = !aj_b_get_once(&c, out, sizeof(out)) && strstr(out, "distinctive retrieval failure");
    if (snprintf(path, sizeof(path), "%s/get-count", tmp) >= (int)sizeof(path)) return 1;
    struct stat st;
    bool once = stat(path, &st) == 0 && st.st_size == 1;
    (void)unlink(path);
    g_board_wait_s = 1;
    bool passed = aj_single_get_success(&c, tmp, path);
    if (failed && once && passed) puts("single get failure and success: PASS");
    return failed && once && passed ? 0 : 1;
}

static int aj_catalog_test(const char *tmp)
{
    struct aj_node_ctx c = {.rpc = 1}; size_t len = strlen(tmp);
    if (len >= sizeof(c.datadir)) return 1;
    memcpy(c.datadir, tmp, len + 1); memcpy(c.home, tmp, len + 1);
    snprintf(g_name, sizeof(g_name), "example/app"); g_board_wait_s = 2;
    bool ok = !aj_catalog_has_name("example/app-extra abc\n", g_name) &&
        aj_catalog_has_name("other abc\nexample/app abc root\n", g_name);
    char path[PATH_MAX], out[1024];
    const char *modes[] = {"catalog-absent", "catalog-error"};
    for (size_t i = 0; i < 2; i++) {
        if (snprintf(path, sizeof(path), "%s/%s", tmp, modes[i]) >= (int)sizeof(path)) return 1;
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0 || close(fd) != 0) return 1;
        bool absent = !aj_wait_catalog(&c, out, sizeof(out));
        bool removed = unlink(path) == 0;
        ok = absent && removed && ok;
    }
    if (ok) puts("catalog matching and refusal: PASS");
    return ok ? 0 : 1;
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
    int cli = aj_test_cli(argc, argv);
    if (cli >= 0) return cli;
    char self[PATH_MAX], tmp[PATH_MAX], root[PATH_MAX];
    const char *base = getenv("TMPDIR"), *home = getenv("HOME");
    if (!base || !*base) {
        if (!home || snprintf(root, sizeof root, "%s/.cache/development-scratch/z23", home) >= (int)sizeof root || aj_mkdir_p(root)) return 2;
        base = root;
    }
    if (!realpath(argv[0], self) || snprintf(tmp, sizeof tmp, "%s/app-journey-test.XXXXXX", base) >= (int)sizeof tmp || !mkdtemp(tmp)) return 2;
    int failed = aj_test_setup(self, tmp);
    if (!failed) failed = aj_test_cases() | aj_group_startup_test() | aj_group_owned_test() | aj_single_get_test(tmp) | aj_catalog_test(tmp);
    if (!aj_rm_rf(tmp, 0)) failed = 1;
    if (!failed) puts("app journey child status selftest: PASS");
    return failed;
}
