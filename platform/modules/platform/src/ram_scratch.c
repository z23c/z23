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
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "platform/ram_scratch.h"

#include "platform/disk_space.h"
#include "platform/os_proc.h"
#if defined(__linux__)
#include <linux/magic.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#endif

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

static bool lease_bytes_parse(char *body, uint64_t *out)
{
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(body, &end, 10);
    if (errno != 0 || end == body || body[0] < '0' || body[0] > '9' || value == 0) return false;
    while (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')
        end++;
    if (*end != '\0') return false;
    *out = (uint64_t)value;
    return true;
}

/* Read one lease's reserved byte count from its decimal text. */
static bool lease_bytes_read(const char *path, uint64_t *out)
{
    char body[32];
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    ssize_t got = read(fd, body, sizeof(body) - 1);
    char extra;
    ssize_t trailing = got > 0 ? read(fd, &extra, 1) : -1;
    int close_rc = close(fd);
    if (got <= 0 || trailing != 0 || close_rc != 0) return false;
    body[got] = '\0';
    return lease_bytes_parse(body, out);
}

/* Sum what live leases hold, and drop the ones whose process is gone.
 * kill(pid, 0) asks only "does it exist": ESRCH says no, so the lease is
 * stale — skip its bytes and take its file along; EPERM says yes but not
 * ours, and any other failure is undecidable, and an undecidable lease still
 * counts. A lease whose count cannot be read counts as everything: fail
 * closed rather than under-reserve. */
static bool lease_sum_entry(const char *dir, const struct dirent *entry,
                            uint64_t *total)
{
    long long pid = 0;
    if (strcmp(entry->d_name, RAM_SCRATCH_LEASE_LOCK) == 0 ||
        !lease_name_pid(entry->d_name, &pid)) return true;
    char path[PLATFORM_RAM_SCRATCH_LEASE_PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name) >=
        (int)sizeof(path)) return false;
    if (kill((pid_t)pid, 0) != 0 && errno == ESRCH) {
        (void)unlink(path);
        return true;
    }
    uint64_t bytes = 0;
    if (!lease_bytes_read(path, &bytes)) bytes = UINT64_MAX;
    if (bytes > UINT64_MAX - *total) *total = UINT64_MAX;
    else *total += bytes;
    return true;
}

static bool lease_sum_live(const char *dir, uint64_t *sum)
{
    DIR *d = opendir(dir);
    if (!d) return false;
    uint64_t total = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(d);
        if (!entry) {
            bool ok = errno == 0;
            if (closedir(d) != 0) ok = false;
            *sum = total;
            return ok;
        }
        if (!lease_sum_entry(dir, entry, &total)) {
            (void)closedir(d);
            return false;
        }
    }
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

/* Admitted bytes are the free space above the standing guard. */
static bool reserve_root_admits(const char *root, uint64_t bytes,
                                uint64_t *admitted)
{
    /* Only the root platform_ram_scratch_root() answered is resolvable:
     * absolute, and therefore unambiguous about which lease directory the
     * flock and the sum describe. */
    if (!root || root[0] != '/' || bytes == 0) return false;
    uint64_t free_bytes = 0;
    if (!platform_disk_space_available(root, &free_bytes) ||
        free_bytes < PLATFORM_RAM_SCRATCH_MIN_FREE_BYTES)
        return false;
    *admitted = free_bytes - PLATFORM_RAM_SCRATCH_MIN_FREE_BYTES;
    return true;
}

/* A path that does not fit refuses, and so does any mkdir failure other
 * than EEXIST. What is there must be a directory before it is locked. */
static bool lease_dir_prepare(const char *root, char *dir, size_t dir_cap,
                              char *lock_path, size_t lock_cap, bool private)
{
    if (snprintf(dir, dir_cap, "%s/%s", root, RAM_SCRATCH_LEASE_DIR) >=
            (int)dir_cap ||
        snprintf(lock_path, lock_cap, "%s/%s", dir,
                 RAM_SCRATCH_LEASE_LOCK) >= (int)lock_cap)
        return false;
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) return false;
    struct stat st;
    if ((private ? lstat(dir, &st) : stat(dir, &st)) != 0 || !S_ISDIR(st.st_mode)) return false;
    if (private && (st.st_uid != geteuid() || (st.st_mode & 0077))) return false;
    return true;
}

static int lease_lock_open(const char *path, bool private)
{
    int flags = O_RDWR | O_CREAT | O_CLOEXEC | (private ? O_NOFOLLOW : 0);
    int fd = open(path, flags, 0600);
    if (fd < 0) return -1;
    struct stat st;
    if (private && (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != geteuid() || st.st_nlink != 1 || (st.st_mode & 0077))) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

#if defined(__linux__)
static bool ram_scratch_ancestors_safe(const char *root)
{
    char path[4096], canonical[4096];
    if (!realpath(root, canonical) || strcmp(root, canonical) != 0 ||
        snprintf(path, sizeof(path), "%s", root) >= (int)sizeof(path)) return false;
    for (;;) {
        char *slash = strrchr(path, '/');
        if (!slash) return false;
        if (slash == path) path[1] = '\0'; else *slash = '\0';
        struct stat st;
        if (lstat(path, &st) != 0 || !S_ISDIR(st.st_mode) ||
            (st.st_uid != 0 && st.st_uid != geteuid())) return false;
        if ((st.st_mode & 0022) &&
            (!(st.st_mode & S_ISVTX) || st.st_uid != 0)) return false;
        if (strcmp(path, "/") == 0) return true;
    }
}
#endif

static bool ram_scratch_private_root(const char *root)
{
#if defined(__linux__)
    struct stat st;
    struct statfs fs;
    struct statvfs vfs;
    if (lstat(root, &st) != 0 || statfs(root, &fs) != 0 ||
        statvfs(root, &vfs) != 0 || !ram_scratch_ancestors_safe(root)) return false;
    struct platform_ram_scratch_root_facts facts = {
        .directory = S_ISDIR(st.st_mode), .owner = st.st_uid == geteuid(),
        .owner_private = (st.st_mode & 0077) == 0,
        .tmpfs = (unsigned long)fs.f_type == TMPFS_MAGIC,
        .noexec = (vfs.f_flag & ST_NOEXEC) != 0,
        .readonly = (vfs.f_flag & ST_RDONLY) != 0,
        .free_inodes = vfs.f_favail > 0 && vfs.f_favail != (fsfilcnt_t)-1
    };
    return platform_ram_scratch_root_facts_admit(&facts);
#else
    (void)root;
    return false;
#endif
}

static bool ram_scratch_private_capacity(const char *root, uint64_t *admitted)
{
#if defined(__linux__)
    struct os_proc_mem mem;
    uint64_t cgroup;
    if (!ram_scratch_private_root(root) || !os_proc_mem_read(&mem) ||
        mem.sys_avail_bytes < 0 || !os_proc_cgroup_memory_headroom(&cgroup)) return false;
    uint64_t available = (uint64_t)mem.sys_avail_bytes;
    if (cgroup < available) available = cgroup;
    if (available < PLATFORM_RAM_SCRATCH_MIN_FREE_BYTES) return false;
    available -= PLATFORM_RAM_SCRATCH_MIN_FREE_BYTES;
    if (available < *admitted) *admitted = available;
    return true;
#else
    (void)root; (void)admitted;
    return false;
#endif
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

bool platform_ram_scratch_root_facts_admit(
    const struct platform_ram_scratch_root_facts *facts)
{
    return facts && facts->directory && facts->owner && facts->owner_private &&
           facts->tmpfs && !facts->noexec && !facts->readonly && facts->free_inodes;
}

bool platform_ram_scratch_private_root(char *out_path, size_t out_cap)
{
    if (!out_path || !out_cap) return false;
    out_path[0] = '\0';
#if defined(__linux__)
    char fallback[64];
    const char *override = getenv("ZCL_RAM_SCRATCH_ROOT");
    const char *root = override ? override : getenv("XDG_RUNTIME_DIR");
    if (!override && (!root || root[0] != '/' || !ram_scratch_private_root(root))) {
        int n = snprintf(fallback, sizeof(fallback), "/run/user/%lu", (unsigned long)geteuid());
        if (n < 0 || (size_t)n >= sizeof(fallback)) return false;
        root = fallback;
    }
    if (!root || root[0] != '/' || !ram_scratch_private_root(root)) return false;
    int n = snprintf(out_path, out_cap, "%s", root);
    if (n < 0 || (size_t)n >= out_cap) { out_path[0] = '\0'; return false; }
    return true;
#else
    return false;
#endif
}

#if !defined(_WIN32)
static bool lease_reserve_locked(const char *root, const char *dir,
                                 uint64_t bytes, bool private,
                                 struct platform_ram_scratch_lease *out)
{
    uint64_t admitted = 0, held = 0;
    return reserve_root_admits(root, bytes, &admitted) &&
           (!private || ram_scratch_private_capacity(root, &admitted)) &&
           lease_sum_live(dir, &held) && held <= admitted &&
           bytes <= admitted - held && lease_create(dir, bytes, out);
}
#endif

static bool ram_scratch_reserve(const char *root, uint64_t bytes,
                                struct platform_ram_scratch_lease *out, bool private)
{
    if (!out) return false;
    out->held = false;
    out->path[0] = '\0';
#if defined(_WIN32)
    (void)root;
    (void)bytes;
    (void)private;
    return false;
#else
    if (!root || root[0] != '/' || bytes == 0 ||
        (private && !ram_scratch_private_root(root))) return false;
    char dir[PLATFORM_RAM_SCRATCH_LEASE_PATH_MAX];
    char lock_path[PLATFORM_RAM_SCRATCH_LEASE_PATH_MAX];
    if (!lease_dir_prepare(root, dir, sizeof(dir), lock_path,
                           sizeof(lock_path), private))
        return false;
    int lock_fd = lease_lock_open(lock_path, private);
    if (lock_fd < 0) return false;
    if (flock(lock_fd, LOCK_EX | (private ? LOCK_NB : 0)) != 0) {
        (void)close(lock_fd);
        return false;
    }
    /* One reserver at a time sums live leases. The latency-sensitive private
     * caller refuses contention; generic callers continue to wait. */
    bool ok = lease_reserve_locked(root, dir, bytes, private, out);
    (void)flock(lock_fd, LOCK_UN);
    (void)close(lock_fd);
    return ok;
#endif
}

bool platform_ram_scratch_reserve(const char *root, uint64_t bytes,
                                  struct platform_ram_scratch_lease *out)
{
    return ram_scratch_reserve(root, bytes, out, false);
}

bool platform_ram_scratch_reserve_private(const char *root, uint64_t bytes,
                                          struct platform_ram_scratch_lease *out)
{
    return ram_scratch_reserve(root, bytes, out, true);
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
