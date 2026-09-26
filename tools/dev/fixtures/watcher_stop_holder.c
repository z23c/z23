/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Isolated watcher-stop identity fixture: deliberately simple lock holder. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static volatile sig_atomic_t stopped;

static void stop_handler(int sig)
{
    (void)sig;
    stopped = 1;
}

static unsigned long long start_token(long pid)
{
    char path[64], line[4096];
    snprintf(path, sizeof(path), "/proc/%ld/stat", pid);
    FILE *file = fopen(path, "r");
    if (!file || !fgets(line, sizeof(line), file)) {
        if (file) fclose(file);
        return 0;
    }
    fclose(file);
    char *field = strrchr(line, ')');
    if (!field) return 0;
    field += 2;
    for (int i = 3; i < 22; i++) {
        field = strchr(field, ' ');
        if (!field) return 0;
        field++;
    }
    return strtoull(field, NULL, 10);
}

static int hold_start(const char *claimed_pid, int *lock_fd,
                      int *stop_fd, char stop_path[320], char nonce[65])
{
    *lock_fd = open(".cache/zcl-dev-watch.lock", O_RDWR | O_CREAT | O_CLOEXEC,
                    0600);
    if (*lock_fd < 0 || flock(*lock_fd, LOCK_EX | LOCK_NB) != 0 ||
        ftruncate(*lock_fd, 0) != 0) return 3;
    long record_pid = strcmp(claimed_pid, "self") == 0
        ? (long)getpid() : strtol(claimed_pid, NULL, 10);
    unsigned long long token = start_token(record_pid);
    if (record_pid <= 1 || token == 0) return 4;
    snprintf(nonce, 65, "%064lx", (unsigned long)getpid());
    snprintf(stop_path, 320, "/tmp/z23-watch-stop-%lu-%s",
             (unsigned long)geteuid(), nonce);
    if (mkfifo(stop_path, 0600) != 0) return 4;
    *stop_fd = open(stop_path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (*stop_fd < 0 ||
        dprintf(*lock_fd, "%ld verify ready proofq1 %llu %s\n",
                record_pid, token, nonce) <= 0) return 4;
    return 0;
}

static void stop_poll(int stop_fd, const char nonce[65])
{
    struct pollfd event = {.fd = stop_fd, .events = POLLIN};
    if (poll(&event, 1, 100) <= 0) return;
    char body[192], prefix[128];
    ssize_t got = read(stop_fd, body, sizeof(body));
    int n = snprintf(prefix, sizeof(prefix), "%ld %llu %s ",
                     (long)getpid(), start_token((long)getpid()), nonce);
    if (got >= n && n > 0 && n < (int)sizeof(prefix) &&
        memcmp(body, prefix, (size_t)n) == 0) stopped = 1;
}

static bool ready_write(const char *path)
{
    int ready = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    return ready >= 0 && write(ready, "r", 1) == 1 && close(ready) == 0;
}

int main(int argc, char **argv)
{
    if (argc != 5 || chdir(argv[2]) != 0) return 2;
    int fd = -1, stop_fd = -1;
    char stop_path[320] = {0}, nonce[65] = {0};
    if (strcmp(argv[1], "hold") == 0) {
        int rc = hold_start(argv[3], &fd, &stop_fd, stop_path, nonce);
        if (rc != 0) return rc;
    } else if (strcmp(argv[1], "idle") != 0) return 5;
    struct sigaction action = {0};
    action.sa_handler = stop_handler;
    if (sigaction(SIGTERM, &action, NULL) != 0) return 6;
    if (!ready_write(argv[4])) return 7;
    while (!stopped) {
        if (stop_fd < 0) { pause(); continue; }
        stop_poll(stop_fd, nonce);
    }
    if (stop_fd >= 0) close(stop_fd);
    if (stop_path[0]) unlink(stop_path);
    if (fd >= 0 && close(fd) != 0) return 8;
    return 0;
}
