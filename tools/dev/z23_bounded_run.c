/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Run one local proof executable under a bounded process-group rail.
 *
 * This deliberately small POSIX helper exists because macOS has no standard
 * timeout(1), and killing only a test's immediate PID can leave forked
 * descendants alive after a gate reports failure.  The child starts a new
 * session; timeout and cleanup signal the whole process group. */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { RUN_TIMEOUT = 124, RUN_INFRA = 125 };

static bool monotonic_ms(uint64_t *out)
{
    struct timespec now;
    if (!out || clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0)
        return false;
    uint64_t seconds = (uint64_t)now.tv_sec;
    if (seconds > UINT64_MAX / 1000u) return false;
    *out = seconds * 1000u + (uint64_t)now.tv_nsec / 1000000u;
    return true;
}

static void signal_group(pid_t leader, int signal_number)
{
    if (leader > 1 && kill(-leader, signal_number) != 0 && errno != ESRCH)
        fprintf(stderr, "z23_bounded_run: cannot signal process group %ld: %s\n",
                (long)leader, strerror(errno));
}

static void reap_group(pid_t leader)
{
    struct timespec grace = {.tv_nsec = 100000000L};
    signal_group(leader, SIGTERM);
    (void)nanosleep(&grace, NULL);
    signal_group(leader, SIGKILL);
}

static int child_status(int status)
{
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return RUN_INFRA;
}

static int run_bounded(uint64_t timeout_ms, char *const argv[])
{
    if (!argv || !argv[0] || timeout_ms == 0) return RUN_INFRA;
    pid_t leader = fork();
    if (leader < 0) {
        fprintf(stderr, "z23_bounded_run: fork failed: %s\n", strerror(errno));
        return RUN_INFRA;
    }
    if (leader == 0) {
        if (setsid() < 0) _exit(RUN_INFRA);
        execv(argv[0], argv);
        _exit(RUN_INFRA);
    }

    uint64_t started = 0;
    if (!monotonic_ms(&started)) {
        reap_group(leader);
        (void)waitpid(leader, NULL, 0);
        return RUN_INFRA;
    }
    for (;;) {
        int status = 0;
        pid_t got = waitpid(leader, &status, WNOHANG);
        if (got == leader) {
            /* A test is not allowed to daemonize proof work.  Clean any
             * surviving members even when the session leader exited first. */
            reap_group(leader);
            return child_status(status);
        }
        if (got < 0) {
            if (errno == EINTR) continue;
            reap_group(leader);
            return RUN_INFRA;
        }
        uint64_t now = 0;
        if (!monotonic_ms(&now) || now < started) {
            reap_group(leader);
            (void)waitpid(leader, NULL, 0);
            return RUN_INFRA;
        }
        if (now - started >= timeout_ms) {
            reap_group(leader);
            while (waitpid(leader, NULL, 0) < 0 && errno == EINTR) { }
            return RUN_TIMEOUT;
        }
        struct timespec tick = {.tv_nsec = 1000000L};
        (void)nanosleep(&tick, NULL);
    }
}

static volatile sig_atomic_t selftest_stop;

static void selftest_stop_handler(int signal_number)
{
    (void)signal_number;
    selftest_stop = 1;
}

static int selftest_tree(const char *pid_path)
{
    pid_t descendant = fork();
    if (descendant < 0) return 2;
    if (descendant == 0) {
        for (;;) pause();
    }
    FILE *pid_file = fopen(pid_path, "w");
    bool wrote_pid = pid_file &&
        fprintf(pid_file, "%ld\n", (long)descendant) > 0;
    if (pid_file && fclose(pid_file) != 0) wrote_pid = false;
    if (!wrote_pid) {
        (void)kill(descendant, SIGKILL);
        (void)waitpid(descendant, NULL, 0);
        return 2;
    }
    struct sigaction action = {0};
    action.sa_handler = selftest_stop_handler;
    (void)sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) != 0) return 2;
    while (!selftest_stop) pause();
    while (waitpid(descendant, NULL, 0) < 0 && errno == EINTR) { }
    return 0;
}

static int selftest(const char *self)
{
    char *const pass_argv[] = {(char *)self, "--selftest-pass", NULL};
    char *const fail_argv[] = {(char *)self, "--selftest-fail", NULL};
    char pid_path[] = "/tmp/z23-bounded-run-XXXXXX";
    int pid_fd = mkstemp(pid_path);
    if (pid_fd < 0 || close(pid_fd) != 0) {
        if (pid_fd >= 0) (void)unlink(pid_path);
        return 1;
    }
    char *const tree_argv[] = {
        (char *)self, "--selftest-tree", pid_path, NULL};
    if (run_bounded(1000u, pass_argv) != 0) return 1;
    if (run_bounded(1000u, fail_argv) != 23) return 1;
    if (run_bounded(250u, tree_argv) != RUN_TIMEOUT) {
        (void)unlink(pid_path);
        return 1;
    }
    FILE *pid_file = fopen(pid_path, "r");
    long descendant = 0;
    bool read_pid = pid_file && fscanf(pid_file, "%ld", &descendant) == 1;
    if (pid_file) (void)fclose(pid_file);
    (void)unlink(pid_path);
    if (!read_pid || descendant <= 1 || descendant > INT_MAX ||
        kill((pid_t)descendant, 0) == 0 || errno != ESRCH)
        return 1;
    puts("z23_bounded_run: selftest PASS");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0)
        return selftest(argv[0]);
    if (argc == 2 && strcmp(argv[1], "--selftest-pass") == 0) return 0;
    if (argc == 2 && strcmp(argv[1], "--selftest-fail") == 0) return 23;
    if (argc == 3 && strcmp(argv[1], "--selftest-tree") == 0)
        return selftest_tree(argv[2]);
    if (argc < 3) {
        fprintf(stderr, "usage: %s TIMEOUT_MS /absolute/program [arg ...]\n",
                argv[0]);
        return RUN_INFRA;
    }
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(argv[1], &end, 10);
    if (errno || !end || *end || parsed == 0 || parsed > UINT32_MAX ||
        argv[2][0] != '/') {
        fprintf(stderr, "z23_bounded_run: invalid timeout or non-absolute program\n");
        return RUN_INFRA;
    }
    return run_bounded((uint64_t)parsed, &argv[2]);
}
