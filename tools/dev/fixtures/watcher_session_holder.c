/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Isolated watcher-session fixture: a recorded watcher stand-in with one
 * proof-worker child, for the dev-binary stop and launch selftest.
 *
 *   z23-dev fifo   <root> <ready-file>   leaves on a bound stop request and
 *                                        leaks its worker, as a watcher
 *                                        that fails to join one would
 *   z23-dev orphan <root> <ready-file>   holds the lock until killed; its
 *                                        worker outlives it
 *
 * It records itself exactly as the launcher records a watcher and writes
 * "<pid> <worker> <start-token> <session>" to <ready-file>. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

struct holder {
    long pid;
    unsigned long long token;
    char nonce[65];
    char fifo[320];
    int lock_fd;
    int stop_fd;
    const char *image;
};

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

static bool boot_id(char out[64])
{
    FILE *file = fopen("/proc/sys/kernel/random/boot_id", "r");
    bool ok = file && fgets(out, 64, file);
    if (file) fclose(file);
    if (ok) out[strcspn(out, "\n")] = 0;
    return ok && out[0];
}

/* The launcher's record: pid, birth token, boot, image device and inode
 * (the selftest runs this fixture by its absolute path). */
static bool record_self(const struct holder *h)
{
    char boot[64], body[256];
    struct stat exe;
    if (!boot_id(boot) || h->image[0] != '/' || stat(h->image, &exe) != 0 ||
        (mkdir(".cache/zcl-dev-watch.d", 0700) != 0 && errno != EEXIST))
        return false;
    int n = snprintf(body, sizeof(body),
                     "zcl.dev_watch_session.v2 %ld %llu %s %llu %llu\n",
                     h->pid, h->token, boot,
                     (unsigned long long)exe.st_dev,
                     (unsigned long long)exe.st_ino);
    char path[96];
    snprintf(path, sizeof(path), ".cache/zcl-dev-watch.d/%ld", h->pid);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    bool ok = fd >= 0 && n > 0 && write(fd, body, (size_t)n) == n;
    return fd >= 0 && close(fd) == 0 && ok;
}

static bool hold(struct holder *h)
{
    h->pid = (long)getpid();
    h->token = start_token(h->pid);
    snprintf(h->nonce, sizeof(h->nonce), "%064lx", (unsigned long)h->pid);
    snprintf(h->fifo, sizeof(h->fifo), "/tmp/z23-watch-stop-%lu-%s",
             (unsigned long)geteuid(), h->nonce);
    h->lock_fd = open(".cache/zcl-dev-watch.lock",
                      O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (h->token == 0 || mkfifo(h->fifo, 0600) != 0) return false;
    h->stop_fd = open(h->fifo, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    return h->stop_fd >= 0 && h->lock_fd >= 0 &&
           flock(h->lock_fd, LOCK_EX | LOCK_NB) == 0 &&
           ftruncate(h->lock_fd, 0) == 0 &&
           dprintf(h->lock_fd, "%ld verify ready proofq1 %llu %s\n", h->pid,
                   h->token, h->nonce) > 0 &&
           record_self(h);
}

static bool ready_write(const char *path, const struct holder *h, long worker)
{
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *file = fopen(tmp, "w");
    bool ok = file && fprintf(file, "%ld %ld %llu %s\n", h->pid, worker,
                              h->token, h->nonce) > 0;
    if (file && fclose(file) != 0) ok = false;
    return ok && rename(tmp, path) == 0;
}

/* Until a request names exactly this pid, birth and session. */
static void stop_wait(const struct holder *h)
{
    char prefix[160];
    int n = snprintf(prefix, sizeof(prefix), "%ld %llu %s ", h->pid,
                     h->token, h->nonce);
    for (;;) {
        struct pollfd event = {.fd = h->stop_fd, .events = POLLIN};
        char body[192] = {0};
        if (poll(&event, 1, 100) <= 0) continue;
        ssize_t got = read(h->stop_fd, body, sizeof(body) - 1);
        if (got >= n && memcmp(body, prefix, (size_t)n) == 0) return;
    }
}

/* Lead a session of its own, as the launcher's child does: -1 on failure,
 * 1 in the parent that handed the session to its child, else 0. */
static int lead_session(void)
{
    if (setsid() >= 0) return 0;
    /* A process-group leader cannot lead a new session: its child can. */
    pid_t child = fork();
    if (child != 0) return child > 0 ? 1 : -1;
    return setsid() < 0 ? -1 : 0;
}

/* A proof worker: it holds neither the lock nor the endpoint. */
static pid_t spawn_worker(const struct holder *h)
{
    pid_t worker = fork();
    if (worker != 0) return worker;
    close(h->lock_fd);
    close(h->stop_fd);
    for (;;) pause();
}

int main(int argc, char **argv)
{
    struct holder h = {.lock_fd = -1, .stop_fd = -1, .image = argv[0]};
    bool fifo = argc == 4 && strcmp(argv[1], "fifo") == 0;
    bool orphan = argc == 4 && strcmp(argv[1], "orphan") == 0;
    if (!fifo && !orphan) return 2;
    int led = lead_session();
    if (led != 0) return led > 0 ? 0 : 2;
    if (chdir(argv[2]) != 0) return 2;
    if (!hold(&h)) return 3;
    pid_t worker = spawn_worker(&h);
    if (worker < 0 || !ready_write(argv[3], &h, (long)worker)) return 4;
    if (orphan) {
        for (;;) pause();
    }
    stop_wait(&h);
    close(h.stop_fd);
    unlink(h.fifo);
    close(h.lock_fd);
    return 0;
}
