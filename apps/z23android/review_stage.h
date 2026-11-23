/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_REVIEW_STAGE_H
#define ZAPP_REVIEW_STAGE_H
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

enum zapp_review_stage { ZAPP_STAGE_OK, ZAPP_STAGE_EMPTY, ZAPP_STAGE_TOO_LARGE,
                         ZAPP_STAGE_CANCELED, ZAPP_STAGE_UNAVAILABLE };

/* Remove only our reserved temporary files from a previous app process. */
static bool zapp_review_stage_cleanup(const char *directory)
{
    int fd = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat root;
    if (fd < 0) return false;
    if (fstat(fd, &root) || !S_ISDIR(root.st_mode) || root.st_uid != geteuid() || (root.st_mode & 077)) {
        close(fd);
        return false;
    }
    DIR *dir = fdopendir(fd);
    if (!dir) { close(fd); return false; }
    bool ok = true;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(dir))) {
        const char *name = entry->d_name;
        if (strlen(name) != 17 || strncmp(name, "z23-review-", 11)) continue;
        bool suffix = true;
        for (size_t i = 11; i < 17; ++i)
            if (!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'A' && name[i] <= 'Z') ||
                  (name[i] >= 'a' && name[i] <= 'z'))) suffix = false;
        struct stat item;
        if (!suffix) continue;
        if (fstatat(fd, name, &item, AT_SYMLINK_NOFOLLOW) || !S_ISREG(item.st_mode) ||
            item.st_uid != geteuid() || item.st_nlink != 1 || (item.st_mode & 077)) { ok = false; continue; }
        if (unlinkat(fd, name, 0)) ok = false;
        errno = 0;
    }
    if (errno) ok = false;
    if (closedir(dir)) ok = false;
    return ok;
}

/* The caller owns both descriptors and removes the private staging file on every failure. */
static enum zapp_review_stage zapp_review_stage_copy(int input, int output, uint64_t limit,
                                                    unsigned timeout_ms, const atomic_bool *cancel)
{
    int flags = fcntl(input, F_GETFL);
    struct timespec started;
    if (flags < 0 || fcntl(input, F_SETFL, flags | O_NONBLOCK) < 0 ||
        clock_gettime(CLOCK_MONOTONIC, &started)) return ZAPP_STAGE_UNAVAILABLE;
    uint64_t start = (uint64_t)started.tv_sec * 1000u + (uint64_t)started.tv_nsec / 1000000u;
    uint64_t total = 0;
    char buffer[16384];
    for (;;) {
        if (cancel && atomic_load(cancel)) return ZAPP_STAGE_CANCELED;
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now)) return ZAPP_STAGE_UNAVAILABLE;
        uint64_t current = (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
        if (current < start || current - start >= timeout_ms) return ZAPP_STAGE_UNAVAILABLE;
        uint64_t left = timeout_ms - (current - start);
        int wait = left < 100u ? (int)left : 100;
        struct pollfd p = {.fd = input, .events = POLLIN};
        int ready = poll(&p, 1, wait);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || (p.revents & (POLLERR | POLLNVAL))) return ZAPP_STAGE_UNAVAILABLE;
        if (!ready) continue;
        ssize_t n = read(input, buffer, sizeof(buffer));
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n < 0) return ZAPP_STAGE_UNAVAILABLE;
        if (!n) return total ? ZAPP_STAGE_OK : ZAPP_STAGE_EMPTY;
        if ((uint64_t)n > limit - total) return ZAPP_STAGE_TOO_LARGE;
        for (ssize_t done = 0; done < n;) {
            ssize_t wrote = write(output, buffer + done, (size_t)(n - done));
            if (wrote < 0 && errno == EINTR) continue;
            if (wrote <= 0) return ZAPP_STAGE_UNAVAILABLE;
            done += wrote;
        }
        total += (uint64_t)n;
    }
}
#endif
