/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: implementation of platform/ram_scratch.h.
 *
 * POSIX arm: Linux mounts a tmpfs at /dev/shm on every mainstream
 * distribution, and it is the one RAM-backed path a program may assume by
 * name. It is still checked rather than trusted — a container can mount it
 * tiny, read-only, or not at all — and the free-space guard is what keeps a
 * caller from spending the machine's memory on scratch files.
 *
 * The free-space guard alone lies under concurrency: every asker sees the
 * same free bytes, so N proofs asked at once all hear yes and then fill the
 * tmpfs together. Reservations close that window — each reserver, under one
 * flock, sums what live leases already hold and only then spends what is
 * left.
 *
 * Windows arm: there is no equivalent the OS guarantees, so the answer is
 * always no and the caller keeps its ordinary location. */
#include "platform/ram_scratch.h"

#include "platform/disk_space.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#define RAM_SCRATCH_DEFAULT "/dev/shm"
#define RAM_SCRATCH_LEASE_DIR ".z23-leases"
#define RAM_SCRATCH_LEASE_LOCK "lock"

#if !defined(_WIN32)

/* Lease files are named "<pid>-<counter>", plain decimals and nothing else,
 * so a lease can be attributed to a live or dead process by name alone. */
static bool lease_name_pid(const char *name, long long *pid_out)
{
    size_t i = 0;
    bool digits = false;
    while (name[i] >= '0' && name[i] <= '9') { i++; digits = true; }
    if (!digits || name[i] != '-') return false;
    i++;
    digits = false;
    while (name[i] >= '0' && name[i] <= '9') { i++; digits = true; }
    if (!digits || name[i] != '\0') return false;
    errno = 0;
    char *end = NULL;
    long long pid = strtoll(name, &end, 10);
    if (errno != 0 || pid <= 0 || end == name) return false;
    *pid_out = pid;
    return true;
}

/* Read one lease's reserved byte count from its decimal text. */
static bool lease_bytes_read(const char *path, uint64_t *out)
{
    char body[32];
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    ssize_t got = read(fd, body, sizeof(body) - 1);
    (void)close(fd);
    if (got <= 0) return false;
    body[got] = '\0';
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(body, &end, 10);
    if (errno != 0 || end == body) return false;
    while (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')
        end++;
    if (*end != '\0') return false;
    *out = (uint64_t)value;
    return true;
}

/* Sum what live leases hold, and drop the ones whose process is gone.
 * kill(pid, 0) asks only "does it exist": ESRCH says no, so the lease is
 * stale — skip its bytes and take its file along; EPERM says yes but not
 * ours, and any other failure is undecidable, and an undecidable lease still
 * counts. A lease whose count cannot be read counts as everything: fail
 * closed rather than under-reserve. */
static bool lease_sum_live(const char *dir, uint64_t *sum)
{
    DIR *d = opendir(dir);
    if (!d) return false;
    uint64_t total = 0;
    for (struct dirent *entry = readdir(d); entry; entry = readdir(d)) {
        long long pid = 0;
        if (strcmp(entry->d_name, RAM_SCRATCH_LEASE_LOCK) == 0 ||
            !lease_name_pid(entry->d_name, &pid))
            continue;
        char path[PLATFORM_RAM_SCRATCH_LEASE_PATH_MAX];
        if (snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name) >=
            (int)sizeof(path))
            continue;
        if (kill((pid_t)pid, 0) != 0 && errno == ESRCH) {
            (void)unlink(path);
            continue;
        }
        uint64_t bytes = 0;
        if (!lease_bytes_read(path, &bytes)) bytes = UINT64_MAX;
        if (bytes > UINT64_MAX - total) total = UINT64_MAX;
        else total += bytes;
    }
    (void)closedir(d);
    *sum = total;
    return true;
}

/* Create this caller's lease file: O_EXCL keeps even two threads of one pid
 * from sharing a name, and the counter walks until an unused name appears. */
static bool lease_create(const char *dir, uint64_t bytes,
                         struct platform_ram_scratch_lease *out)
{
    long long pid = (long long)getpid();
    char body[32];
    int body_len = snprintf(body, sizeof(body), "%llu",
                            (unsigned long long)bytes);
    if (body_len <= 0 || (size_t)body_len >= sizeof(body)) return false;
    for (unsigned counter = 1; counter != 0; counter++) {
        char path[PLATFORM_RAM_SCRATCH_LEASE_PATH_MAX];
        int path_len = snprintf(path, sizeof(path), "%s/%lld-%u", dir, pid,
                                counter);
        if (path_len <= 0 || (size_t)path_len >= sizeof(path)) return false;
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) {
            if (errno == EEXIST) continue;
            return false;
        }
        size_t written = 0;
        bool ok = true;
        while (written < (size_t)body_len) {
            ssize_t n = write(fd, body + written,
                              (size_t)body_len - written);
            if (n < 0) { ok = false; break; }
            written += (size_t)n;
        }
        (void)close(fd);
        if (!ok) {
            (void)unlink(path);
            return false;
        }
        snprintf(out->path, sizeof(out->path), "%s", path);
        out->held = true;
        return true;
    }
    return false;
}

#endif

bool platform_ram_scratch_root(char *out_path, size_t out_cap,
                               uint64_t min_free_bytes)
{
    if (!out_path || out_cap == 0) return false;
    out_path[0] = '\0';
    if (min_free_bytes == 0)
        min_free_bytes = PLATFORM_RAM_SCRATCH_MIN_FREE_BYTES;
#if defined(_WIN32)
    (void)min_free_bytes;
    return false;
#else
    /* An override that is empty, or not absolute, is a refusal — never a
     * silent fall back to the default, which would answer a question the
     * caller did not ask. */
    const char *candidate = getenv("ZCL_RAM_SCRATCH_ROOT");
    if (candidate && candidate[0] != '/') return false;
    if (!candidate) candidate = RAM_SCRATCH_DEFAULT;
    struct stat st;
    if (stat(candidate, &st) != 0 || !S_ISDIR(st.st_mode)) return false;
    if (access(candidate, W_OK | X_OK) != 0) return false;
    uint64_t available = 0;
    if (!platform_disk_space_available(candidate, &available) ||
        available < min_free_bytes)
        return false;
    size_t len = strlen(candidate);
    if (len == 0 || len + 1 > out_cap) return false;
    memcpy(out_path, candidate, len + 1);
    return true;
#endif
}

bool platform_ram_scratch_reserve(const char *root, uint64_t bytes,
                                  struct platform_ram_scratch_lease *out)
{
    if (!out) return false;
    out->held = false;
    out->path[0] = '\0';
#if defined(_WIN32)
    (void)root;
    (void)bytes;
    return false;
#else
    /* Only the root platform_ram_scratch_root() answered is resolvable:
     * absolute, and therefore unambiguous about which lease directory the
     * flock and the sum describe. */
    if (!root || root[0] != '/' || bytes == 0) return false;
    uint64_t free_bytes = 0;
    if (!platform_disk_space_available(root, &free_bytes) ||
        free_bytes < PLATFORM_RAM_SCRATCH_MIN_FREE_BYTES)
        return false;
    uint64_t admitted = free_bytes - PLATFORM_RAM_SCRATCH_MIN_FREE_BYTES;
    char dir[PLATFORM_RAM_SCRATCH_LEASE_PATH_MAX];
    char lock_path[PLATFORM_RAM_SCRATCH_LEASE_PATH_MAX];
    if (snprintf(dir, sizeof(dir), "%s/%s", root, RAM_SCRATCH_LEASE_DIR) >=
            (int)sizeof(dir) ||
        snprintf(lock_path, sizeof(lock_path), "%s/%s", dir,
                 RAM_SCRATCH_LEASE_LOCK) >= (int)sizeof(lock_path))
        return false;
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) return false;
    struct stat st;
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) return false;
    int lock_fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd < 0) return false;
    if (flock(lock_fd, LOCK_EX) != 0) {
        (void)close(lock_fd);
        return false;
    }
    /* One reserver at a time sums the live leases and adds its own; a second
     * arriving meanwhile waits here instead of re-spending the same free
     * bytes. */
    uint64_t held = 0;
    bool ok = lease_sum_live(dir, &held) &&
              held <= admitted && bytes <= admitted - held &&
              lease_create(dir, bytes, out);
    (void)flock(lock_fd, LOCK_UN);
    (void)close(lock_fd);
    return ok;
#endif
}

void platform_ram_scratch_release(struct platform_ram_scratch_lease *lease)
{
    if (!lease || !lease->held) return;
#if !defined(_WIN32)
    (void)unlink(lease->path);
#endif
    lease->path[0] = '\0';
    lease->held = false;
}
