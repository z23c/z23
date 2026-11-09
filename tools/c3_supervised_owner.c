/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* purpose: Own one isolated stopwatch node and report proven descendant cleanup. */
#define _POSIX_C_SOURCE 200809L
#include "platform/supervised_process.h"
#include "sha3/sha3.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
extern char **environ;
static int64_t now_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return -1;
    return (int64_t)t.tv_sec * 1000000000LL + t.tv_nsec;
}
static int sealed_launcher(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd < 0) return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (uint64_t)st.st_size > PLATFORM_SUPERVISED_IMAGE_MAX) { close(fd); return -1; }
    size_t len = (size_t)st.st_size, used = 0;
    unsigned char *bytes = malloc(len);
    if (!bytes) { close(fd); return -1; }
    while (used < len) {
        ssize_t n = read(fd, bytes + used, len - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        used += (size_t)n;
    }
    close(fd);
    uint8_t digest[32];
    int sealed = -1;
    if (used == len) {
        zcl_sha3_256(bytes, len, digest);
        if (platform_supervised_image_capture(bytes, len, digest, &sealed) != PLATFORM_SUPERVISED_IMAGE_OK)
            sealed = -1;
    }
    free(bytes);
    return sealed;
}
static enum platform_supervised_state stop_until_reaped(struct platform_supervised_process *p)
{
    enum platform_supervised_state s;
    do {
        int64_t t = now_ns();
        if (t < 0) { (void)poll(NULL, 0, 100); continue; }
        s = platform_supervised_stop(p, t + 10000000000LL);
    } while (p->supervisor_pid >= 0);
    return s;
}
int main(int argc, char **argv)
{
    if (argc < 4 || argc > (int)PLATFORM_SUPERVISED_ARGV_DEFAULT_MAX) return 2;
    (void)signal(SIGPIPE, SIG_IGN);
    int image = sealed_launcher(argv[1]);
    int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int log = open(argv[2], O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (image < 0 || input < 0 || log < 0) return 3;
    char **args = calloc((size_t)argc, sizeof(*args));
    if (!args) return 3;
    args[0] = argv[1];
    for (int i = 3; i < argc; ++i) args[i - 2] = argv[i];
    size_t env_count = 0;
    while (environ[env_count]) ++env_count;
    struct platform_supervised_fd_map maps[] = {{input, 0}, {log, 1}, {log, 2}};
    int64_t t = now_ns();
    if (t < 0) return 3;
    struct platform_supervised_spec spec = {
        .executable_fd = image, .argv = (const char *const *)args,
        .env = (const char *const *)environ, .env_count = env_count,
        .env_policy = PLATFORM_SUPERVISED_ENV_COMPLETE, .maps = maps, .map_count = 3,
        .launch_deadline_ns = t + 10000000000LL, .cleanup_timeout_ms = 10000,
    };
    struct platform_supervised_process p;
    platform_supervised_init(&p);
    enum platform_supervised_state s = platform_supervised_start(&p, &spec);
    close(image); close(input); close(log); free(args);
    if (s != PLATFORM_SUPERVISED_RUNNING) {
        if (p.supervisor_pid >= 0) (void)stop_until_reaped(&p);
        return 4;
    }
    bool stop = printf("START\n") < 0 || fflush(stdout) != 0;
    bool observation_failed = false;
    while (p.supervisor_pid >= 0 && !stop) {
        s = platform_supervised_poll(&p);
        if (p.supervisor_pid < 0) break;
        if (s != PLATFORM_SUPERVISED_RUNNING) { observation_failed = true; break; }
        struct pollfd f = { .fd = STDIN_FILENO, .events = POLLIN | POLLHUP };
        int n = poll(&f, 1, 100);
        if (n < 0 && errno != EINTR) stop = true;
        if (n > 0) { char byte; ssize_t got = read(STDIN_FILENO, &byte, 1); if (got != 1 || byte == 'S') stop = true; }
    }
    if (p.supervisor_pid >= 0) s = stop_until_reaped(&p);
    if (observation_failed || s != PLATFORM_SUPERVISED_CLEAN || !p.observation.engine_exit_observed ||
        !p.observation.no_children || p.supervisor_pid >= 0) return 5;
    return printf("DONE CLEAN %d\n", p.observation.engine_wait_status) < 0 || fflush(stdout) != 0 ? 6 : 0;
}
#else
int main(void) { fputs("c3-supervised-owner: unsupported platform\n", stderr); return 2; }
#endif
