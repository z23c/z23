/* Purpose: time a developer command with the native monotonic clock. */
#define _POSIX_C_SOURCE 200809L
#include "platform/clock.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static int timed_run(char *const argv[], int64_t *elapsed_ms)
{
    *elapsed_ms = -1;
    int64_t start = clock_now_monotonic_ns();
    if (start <= 0) return 125;
    pid_t child;
    int error = posix_spawnp(&child, argv[0], NULL, NULL, argv, environ);
    if (error != 0) {
        fprintf(stderr, "dev-loop-timer: launch failed: %s\n", strerror(error));
        return error == ENOENT ? 127 : 126;
    }
    int status;
    pid_t done;
    do {
        done = waitpid(child, &status, 0);
    } while (done < 0 && errno == EINTR);
    if (done != child) return 125;
    int rc = WIFEXITED(status) ? WEXITSTATUS(status)
           : WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 125;
    int64_t end = clock_now_monotonic_ns();
    if (end <= 0 || end < start) return rc ? rc : 125;
    int64_t ns = end - start;
    *elapsed_ms = ns / 1000000 + (ns % 1000000 != 0);
    return rc;
}

static int64_t test_tick(void *opaque)
{
    int64_t *tick = opaque;
    int64_t value = *tick;
    *tick += 123000001;
    return value;
}

static int self_test(void)
{
    int failures = 0;
    int64_t tick = 1000000000, elapsed;
    clock_iface_t clock = {.now_monotonic_ns = test_tick, .self = &tick};
    clock_set_default(&clock);
    char *ok[] = {"/bin/sh", "-c", "exit 0", NULL};
    char *bad[] = {"/bin/sh", "-c", "exit 7", NULL};
    char *signal[] = {"/bin/sh", "-c", "kill -TERM $$", NULL};
    failures += timed_run(ok, &elapsed) != 0 || elapsed != 124;
    failures += timed_run(bad, &elapsed) != 7 || elapsed != 124;
    failures += timed_run(signal, &elapsed) != 143 || elapsed != 124;
    tick = 0;
    failures += timed_run(ok, &elapsed) != 125 || elapsed != -1;
    clock_reset_default();
    printf("dev-loop-timer selftest: %s\n", failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) return self_test();
    if (argc < 3) {
        fputs("usage: dev-loop-timer SAMPLE_FILE COMMAND [ARG...]\n", stderr);
        return 2;
    }
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    FILE *sample = fd < 0 ? NULL : fdopen(fd, "w");
    if (!sample) {
        if (fd >= 0) close(fd);
        perror("dev-loop-timer: sample file");
        return 125;
    }
    int64_t elapsed;
    int rc = timed_run(argv + 2, &elapsed);
    bool written = elapsed >= 0 && fprintf(sample, "%" PRId64 "\n", elapsed) > 0;
    if (fclose(sample) != 0) written = false;
    if (!written) {
        fputs("dev-loop-timer: no trustworthy elapsed sample\n", stderr);
        if (rc == 0) rc = 125;
    }
    return rc;
}
