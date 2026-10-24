/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: file helpers for the plugin store: bounded reads, hashing copies,
 * directory creation and generation link parsing. */

#include "plugin_internal.h"
#if defined(_WIN32)
#include "platform/directory_transaction.h"
#include "platform/directory_compat.h"
#include <io.h>
#endif

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "platform/private_directory.h"
#include "platform/time_compat.h"
#include "sha3/sha3.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

/* Hosts without these open flags (Windows) have no symbolic-link or
 * close-on-exec semantics to request; the store is a POSIX feature. */
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

bool plugin_join(char *out, size_t cap, const char *a, const char *b,
                 const char *c, const char *d)
{
    int n = snprintf(out, cap, "%s%s%s%s%s%s%s", a, b ? "/" : "", b ? b : "",
                     c ? "/" : "", c ? c : "", d ? "/" : "", d ? d : "");
    return n > 0 && (size_t)n < cap;
}

int plugin_open_read(const char *path, unsigned flags)
{
#if defined(_WIN32)
    return platform_directory_transaction_read_fd(path, (flags & PLUGIN_OPEN_OWNER_ONLY) != 0);
#else

    int oflags = O_RDONLY | O_CLOEXEC;
    struct stat st;
    if (flags & PLUGIN_OPEN_NOFOLLOW)
        oflags |= O_NOFOLLOW;
    int fd = open(path, oflags);
    if (fd < 0)
        return -1;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
    if (ok && (flags & PLUGIN_OPEN_OWNER_ONLY))
        ok = st.st_uid == geteuid() && (st.st_mode & 022) == 0;
    if (!ok) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    return fd;

#endif
}

enum plugin_status plugin_check_dir(const char *path)
{
#if defined(_WIN32)
    struct platform_directory_transaction directory;
    platform_directory_transaction_init(&directory);
    if (platform_directory_transaction_open(&directory, path)) {
        platform_directory_transaction_close(&directory);
        return PLUGIN_OK;
    }
    return platform_directory_probe_real(path) == PLATFORM_DIRECTORY_PROBE_MISSING
        ? PLUGIN_ERR_NOT_INSTALLED : PLUGIN_ERR_KEYS_INSECURE;
#else

    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT ? PLUGIN_ERR_NOT_INSTALLED : PLUGIN_ERR_IO;
    if (!S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 022) != 0)
        return PLUGIN_ERR_KEYS_INSECURE;
    return PLUGIN_OK;

#endif
}

bool plugin_fsync_dir(const char *path)
{
#if defined(_WIN32)
    struct platform_directory_transaction directory;
    platform_directory_transaction_init(&directory);
    bool ok = platform_directory_transaction_open(&directory, path) &&
        platform_directory_transaction_flush(&directory);
    platform_directory_transaction_close(&directory);
    return ok;
#else

    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return false;
    bool ok = fsync(fd) == 0 || errno == EINVAL;
    close(fd);
    return ok;

#endif
}

bool plugin_read_file(const char *path, size_t max, unsigned flags,
                      char **out, size_t *len)
{
    int fd = plugin_open_read(path, flags);
    FILE *f = fd >= 0 ? fdopen(fd, "rb") : NULL;
    if (!f) {
        if (fd >= 0)
            close(fd);
        return false;
    }
    char *buf = zcl_malloc(max + 1, "plugin_read_file");
    if (!buf) {
        fclose(f);
        errno = ENOMEM;
        return false;
    }
    size_t n = fread(buf, 1, max + 1, f);
    bool bad = ferror(f) || n > max;
    fclose(f);
    if (bad) {
        free(buf);
        errno = n > max ? EFBIG : EIO;
        return false;
    }
    buf[n] = '\0';
    *out = buf;
    *len = n;
    return true;
}

static enum plugin_status plugin_hash_stream(FILE *in, FILE *copy,
                                             char hex[PLUGIN_HEX_SHA3_512 + 1])
{
    unsigned char buf[16384], digest[PLUGIN_DIGEST_BYTES];
    struct sha3_512_ctx ctx;
    sha3_512_init(&ctx);
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        sha3_512_write(&ctx, buf, n);
        if (copy && fwrite(buf, 1, n, copy) != n)
            return PLUGIN_ERR_IO;
    }
    if (ferror(in))
        return PLUGIN_ERR_IO;
    sha3_512_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), hex);
    return PLUGIN_OK;
}

static enum plugin_status plugin_open_failure(void)
{
    if (errno == ENOENT)
        return PLUGIN_ERR_EXE_MISSING;
    return errno == EPERM || errno == ELOOP ? PLUGIN_ERR_KEYS_INSECURE
                                            : PLUGIN_ERR_IO;
}

enum plugin_status plugin_hash_path(const char *path, unsigned flags,
                                    char hex[PLUGIN_HEX_SHA3_512 + 1])
{
    int fd = path ? plugin_open_read(path, flags) : -1;
    if (fd < 0)
        return path ? plugin_open_failure() : PLUGIN_ERR_ARGUMENT;
    FILE *f = fdopen(fd, "rb");
    if (!f) {
        close(fd);
        return PLUGIN_ERR_IO;
    }
    enum plugin_status st = plugin_hash_stream(f, NULL, hex);
    fclose(f);
    return st;
}

enum plugin_status plugin_hash_file(const char *path,
                                    char hex[PLUGIN_HEX_SHA3_512 + 1])
{
    return plugin_hash_path(path, 0, hex);
}

static enum plugin_status plugin_copy_finish(FILE *out)
{
#if defined(_WIN32)
    bool ok = fflush(out) == 0 && _commit(fileno(out)) == 0;
    ok = fclose(out) == 0 && ok;
    return ok ? PLUGIN_OK : PLUGIN_ERR_IO;
#else

    bool ok = fflush(out) == 0 && fsync(fileno(out)) == 0;
    ok = (fclose(out) == 0) && ok;
    return ok ? PLUGIN_OK : PLUGIN_ERR_IO;

#endif
}

#if defined(_WIN32)
static FILE *
plugin_copy_windows_output(const char *destination,
                           struct platform_directory_transaction *parent,
                           struct platform_directory_child *child,
                           char leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u])
{
    char temporary[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    bool ok = platform_directory_transaction_parent(destination, parent, leaf);
    int n = ok ? snprintf(temporary, sizeof(temporary), "%s.copy.%lu", leaf,
                          (unsigned long)getpid())
               : -1;
    ok = ok && n > 0 && (size_t)n < sizeof(temporary) &&
         platform_directory_child_create(parent, temporary, child);
    int fd = ok ? platform_directory_child_duplicate_fd(child->native, _O_WRONLY) : -1;
    FILE *out = fd >= 0 ? fdopen(fd, "wb") : NULL;
    if (!out && fd >= 0)
        close(fd);
    return out;
}

static enum plugin_status plugin_copy_windows(const char *src, const char *dst,
                                              unsigned mode,
                                              char hex[PLUGIN_HEX_SHA3_512 + 1])
{
    (void)mode; /* Owner-private DACL; Windows executes PE, not mode bits. */
    int in_fd = plugin_open_read(src, 0);
    if (in_fd < 0)
        return plugin_open_failure();
    FILE *in = fdopen(in_fd, "rb");
    if (!in) {
        close(in_fd);
        return PLUGIN_ERR_IO;
    }
    struct platform_directory_transaction parent;
    struct platform_directory_child child;
    platform_directory_transaction_init(&parent);
    platform_directory_child_init(&child);
    char leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    FILE *out = plugin_copy_windows_output(dst, &parent, &child, leaf);
    enum plugin_status st = out ? plugin_hash_stream(in, out, hex) : PLUGIN_ERR_IO;
    if (out && plugin_copy_finish(out) != PLUGIN_OK)
        st = PLUGIN_ERR_IO;
    fclose(in);
    if (st == PLUGIN_OK && !platform_directory_child_flush(&child))
        st = PLUGIN_ERR_IO;
    if (st == PLUGIN_OK &&
        platform_directory_child_move_between(&parent, &child, &parent, leaf, true) !=
            PLATFORM_DIRECTORY_OK)
        st = PLUGIN_ERR_IO;
    platform_directory_child_close(&child);
    platform_directory_transaction_close(&parent);
    return st;
}
#endif

enum plugin_status plugin_copy_file(const char *src, const char *dst,
                                    unsigned mode,
                                    char hex[PLUGIN_HEX_SHA3_512 + 1])
{
#if defined(_WIN32)
    return plugin_copy_windows(src, dst, mode, hex);
#else

    int in_fd = plugin_open_read(src, 0);
    if (in_fd < 0)
        return plugin_open_failure();
    FILE *in = fdopen(in_fd, "rb");
    int out_fd = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                      (mode_t)mode);
    /* The mode must not depend on the process umask. */
    if (out_fd >= 0 && fchmod(out_fd, (mode_t)mode) != 0) {
        close(out_fd);
        out_fd = -1;
    }
    FILE *out = out_fd >= 0 ? fdopen(out_fd, "wb") : NULL;
    if (!in || !out) {
        if (in)
            fclose(in);
        else
            close(in_fd);
        if (out)
            fclose(out);
        else if (out_fd >= 0)
            close(out_fd);
        return PLUGIN_ERR_IO;
    }
    enum plugin_status st = plugin_hash_stream(in, out, hex);
    fclose(in);
    if (st != PLUGIN_OK) {
        fclose(out);
        return st;
    }
    return plugin_copy_finish(out);

#endif
}

#if defined(_WIN32)
static bool plugin_mkdirs_windows(const char *path)
{
    char tmp[PLUGIN_PATH_MAX];
    size_t len = path ? strlen(path) : 0;
    if (!len || len >= sizeof(tmp))
        return false;
    memcpy(tmp, path, len + 1u);
    for (size_t i = 1; i <= len; i++) {
        if (tmp[i] != '/' && tmp[i] != '\\' && tmp[i] != '\0')
            continue;
        /* A drive root is a parent, never a directory to create. */
        if (i == 2u && tmp[1] == ':')
            continue;
        char saved = tmp[i];
        tmp[i] = 0;
        enum platform_directory_probe_result probe = platform_directory_probe_real(tmp);
        if (probe == PLATFORM_DIRECTORY_PROBE_REFUSED)
            return false;
        /* A concurrent creator may win between the probe and the create. */
        if (probe == PLATFORM_DIRECTORY_PROBE_MISSING &&
            !platform_private_directory_create(tmp) &&
            platform_directory_probe_real(tmp) != PLATFORM_DIRECTORY_PROBE_OK)
            return false;
        char canonical[PLUGIN_PATH_MAX];
        if (!platform_directory_canonical_real(tmp, canonical, sizeof(canonical)))
            return false;
        tmp[i] = saved;
    }
    return true;
}
#endif

bool plugin_mkdirs(const char *path)
{
#if defined(_WIN32)
    return plugin_mkdirs_windows(path);
#else
    char tmp[PLUGIN_PATH_MAX];
    size_t len = strlen(path);
    struct stat st;
    if (len == 0 || len >= sizeof(tmp))
        return false;
    memcpy(tmp, path, len + 1);
    for (size_t i = 1; i <= len; i++) {
        if (tmp[i] != '/' && tmp[i] != '\0')
            continue;
        char saved = tmp[i];
        tmp[i] = '\0';
        bool present = stat(tmp, &st) == 0 && S_ISDIR(st.st_mode);
        /* Another thread or process may create it between the stat and the
         * mkdir: a directory that exists now is what we wanted. */
        if (!present && !platform_private_directory_create(tmp) &&
            !(errno == EEXIST && stat(tmp, &st) == 0 && S_ISDIR(st.st_mode)))
            return false;
        tmp[i] = saved;
    }
    return true;

#endif
}

bool plugin_mkdir_new(const char *path)
{
    return platform_private_directory_create(path);
}

bool plugin_remove_tree(const char *path)
{
#if defined(_WIN32)
    return platform_directory_transaction_remove_tree(path);
#else

    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT;
    if (!S_ISDIR(st.st_mode))
        return unlink(path) == 0;
    DIR *d = opendir(path);
    if (!d)
        return false;
    bool ok = true;
    struct dirent *e;
    while (ok && (e = readdir(d)) != NULL) {
        char child[PLUGIN_PATH_MAX];
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        ok = plugin_join(child, sizeof(child), path, e->d_name, NULL, NULL) &&
             plugin_remove_tree(child);
    }
    closedir(d);
    return ok && rmdir(path) == 0;

#endif
}

/* Why a readlink failed: nothing there, something there that is not a link,
 * or a read the process was not allowed or able to make. */
#if !defined(_WIN32)
static enum plugin_slot_state plugin_link_failure(int err)
{
    if (err == ENOENT)
        return PLUGIN_SLOT_MISSING;
    return err == EINVAL || err == ENOTDIR || err == ELOOP ? PLUGIN_SLOT_CORRUPT
                                                           : PLUGIN_SLOT_UNREADABLE;
}

#endif
enum plugin_slot_state plugin_link_slot(const char *dir, const char *link,
                                        char hex[PLUGIN_HEX_SHA3_512 + 1])
{
#if defined(_WIN32)
    /* Windows slot format: exactly "generations/" + 128 lowercase hex + LF.
     * Ordinary owner-private files replace POSIX symlinks on Windows only. */
    static const char prefix[] = "generations/";
    enum { POINTER_BYTES = sizeof(prefix) - 1u + PLUGIN_HEX_SHA3_512 + 1u };
    struct platform_directory_transaction parent;
    struct platform_directory_child child;
    struct platform_directory_child_info info;
    platform_directory_transaction_init(&parent);
    platform_directory_child_init(&child);
    if (!platform_directory_transaction_open(&parent, dir)) return PLUGIN_SLOT_UNREADABLE;
    enum platform_directory_result opened = platform_directory_child_open_result(
        &parent, link, false, false, &child, NULL);
    enum plugin_slot_state result = opened == PLATFORM_DIRECTORY_MISSING
        ? PLUGIN_SLOT_MISSING : opened == PLATFORM_DIRECTORY_REFUSED
        ? PLUGIN_SLOT_CORRUPT : PLUGIN_SLOT_UNREADABLE;
    char pointer[POINTER_BYTES + 1u];
    if (opened == PLATFORM_DIRECTORY_OK &&
        platform_directory_child_info(&child, &info)) {
        result = PLUGIN_SLOT_CORRUPT;
        if (info.size == POINTER_BYTES && platform_directory_child_read_exact(
                &child, pointer, POINTER_BYTES, 0)) {
            pointer[POINTER_BYTES] = '\0';
            if (pointer[POINTER_BYTES - 1u] == '\n') {
                pointer[POINTER_BYTES - 1u] = '\0';
                if (!memcmp(pointer, prefix, sizeof(prefix)-1u) &&
                    plugin_hex_valid(pointer + sizeof(prefix)-1u, PLUGIN_HEX_SHA3_512)) {
                    memcpy(hex, pointer + sizeof(prefix)-1u, PLUGIN_HEX_SHA3_512+1u);
                    result = PLUGIN_SLOT_OK;
                }
            }
        }
    }
    platform_directory_child_close(&child);
    platform_directory_transaction_close(&parent);
    return result;
#else

    static const char prefix[] = "generations/";
    char path[PLUGIN_PATH_MAX], target[PLUGIN_PATH_MAX];
    if (!plugin_join(path, sizeof(path), dir, link, NULL, NULL))
        return PLUGIN_SLOT_UNREADABLE;
    ssize_t n = readlink(path, target, sizeof(target) - 1);
    if (n < 0)
        return plugin_link_failure(errno);
    target[n] = '\0';
    if (strncmp(target, prefix, sizeof(prefix) - 1) != 0 ||
        !plugin_hex_valid(target + sizeof(prefix) - 1, PLUGIN_HEX_SHA3_512))
        return PLUGIN_SLOT_CORRUPT;
    memcpy(hex, target + sizeof(prefix) - 1, PLUGIN_HEX_SHA3_512 + 1);
    return PLUGIN_SLOT_OK;

#endif
}

bool plugin_link_generation(const char *dir, const char *link,
                            char hex[PLUGIN_HEX_SHA3_512 + 1])
{
    return plugin_link_slot(dir, link, hex) == PLUGIN_SLOT_OK;
}

enum plugin_status plugin_keys_load(const char *path, char **bytes, size_t *len)
{
    if (path && plugin_read_file(path, PLUGIN_FILE_MAX,
                                 PLUGIN_OPEN_NOFOLLOW | PLUGIN_OPEN_OWNER_ONLY, bytes, len))
        return PLUGIN_OK;
    if (!path)
        return PLUGIN_ERR_NO_KEYS;
    switch (errno) {
    case EPERM:
    case ELOOP:
        return PLUGIN_ERR_KEYS_INSECURE;
    case EFBIG:
        return PLUGIN_ERR_KEYS_MALFORMED;
    case EIO:
    case ENOMEM:
        return PLUGIN_ERR_IO;
    default:
        return PLUGIN_ERR_NO_KEYS;
    }
}


/* Per-plugin mutation lock. flock locks belong to the open file description,
 * so a crashed holder never leaves a stale lock behind.
 *
 * A bare poll of a non-blocking flock is unfair: a holder that releases and
 * re-takes ".lock" back to back wins every race against a poller, so under
 * load a waiter can starve for the whole budget. ".lock.q" is a waiter gate
 * that removes that race without any wake-up order from the kernel:
 *
 *   - An acquirer first tests the gate with a momentary exclusive flock. If a
 *     waiter holds the gate shared, the test fails and the newcomer yields
 *     (polls the gate, holding nothing) instead of racing for ".lock".
 *   - A newcomer that passes the gate tries ".lock" once. If it is held, the
 *     newcomer becomes a waiter: it holds the gate shared (announces itself)
 *     and polls ".lock" until the deadline.
 *
 * So once a waiter has announced itself, a holder that comes back around is
 * gated and cannot take ".lock" until every announced waiter has been served.
 * At most one acquirer that had already passed the gate before the
 * announcement can still win ".lock" once; the next release finds the waiter
 * alone with the lock. The waiter therefore wins within about two holds plus
 * one 1 ms step, not by luck. Waiters hold the gate shared, so they never
 * block each other, and only waiters that arrived within one hold of each
 * other race among themselves. Both locks are flocks, so a crashed process
 * releases them and a leftover (unlocked) ".lock.q" file is harmless.
 *
 * The budget is a monotonic-clock deadline, not a step count, and it bounds
 * time without progress: each new holder stamps a counter in ".lock", and a
 * waiter that sees the stamp change restarts its budget, because the lock is
 * moving and a loaded host only makes each hold longer. A lock that does not
 * change hands for a whole budget still answers PLUGIN_ERR_BUSY. */
enum { PLUGIN_LOCK_STEP_MS = 1 };

#ifdef ZCL_TESTING
static int64_t g_lock_budget_ms;
static int64_t g_lock_hold_pause_ms;

void plugin_lock_test_timing(int64_t budget_ms, int64_t hold_pause_ms)
{
    g_lock_budget_ms = budget_ms;
    g_lock_hold_pause_ms = hold_pause_ms;
}
#endif

#if !defined(_WIN32)
static int64_t plugin_lock_budget_ms(void)
{
#ifdef ZCL_TESTING
    if (g_lock_budget_ms > 0)
        return g_lock_budget_ms;
#endif
    return PLUGIN_LOCK_WAIT_MS;
}

/* Open one lock file and require a regular file owned by this user. */
static enum plugin_status plugin_lock_open(const char *plugdir, const char *name, int *fd_out)
{
    char path[PLUGIN_PATH_MAX];
    if (!plugin_join(path, sizeof(path), plugdir, name, NULL, NULL))
        return PLUGIN_ERR_ARGUMENT;
    int fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return errno == ELOOP ? PLUGIN_ERR_KEYS_INSECURE : PLUGIN_ERR_IO;
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return PLUGIN_ERR_IO;
    }
    if (!S_ISREG(st.st_mode) || st.st_uid != geteuid()) {
        close(fd);
        return PLUGIN_ERR_KEYS_INSECURE;
    }
    *fd_out = fd;
    return PLUGIN_OK;
}


/* One non-blocking flock attempt: 0 taken, 1 held elsewhere, -1 error. */
static int plugin_flock_try(int fd, int op)
{
    if (flock(fd, op | LOCK_NB) == 0)
        return 0;
    return (errno == EWOULDBLOCK || errno == EINTR) ? 1 : -1;
}

/* One acquirer's wait. The deadline is a no-progress bound: every time the
 * holder of ".lock" changes (the holder stamps a counter in the file on each
 * take) the deadline restarts, so a waiter is refused only after a full budget
 * in which the lock did not change hands. Under load holds get long and a
 * waiter may need many of them; that is the lock moving, not a stuck holder. */
struct plugin_wait {
    int fd;            /* ".lock", read for the stamp */
    int64_t deadline;  /* monotonic ms */
    uint64_t seen;     /* last stamp observed */
};

static uint64_t plugin_lock_stamp_read(int fd)
{
    uint64_t v = 0;
    return pread(fd, &v, sizeof(v), 0) == (ssize_t)sizeof(v) ? v : 0;
}

/* Called by the new holder, under the lock, so the read-modify-write is safe. */
static void plugin_lock_stamp(int fd)
{
    uint64_t v = plugin_lock_stamp_read(fd) + 1;
    if (pwrite(fd, &v, sizeof(v), 0) != (ssize_t)sizeof(v)) {
        /* best effort: without a stamp the wait degrades to a fixed deadline */
    }
}

/* True when the budget is spent with no handover since the last check. */
static bool plugin_wait_expired(struct plugin_wait *w)
{
    int64_t now = platform_time_monotonic_ms();
    uint64_t stamp = plugin_lock_stamp_read(w->fd);
    if (stamp != w->seen) {
        w->seen = stamp;
        w->deadline = now + plugin_lock_budget_ms();
        return false;
    }
    return now >= w->deadline;
}

/* Poll until the lock is taken; *st is BUSY on a spent budget, IO on error. */
static bool plugin_flock_poll(int fd, int op, struct plugin_wait *w, enum plugin_status *st)
{
    for (;;) {
        int r = plugin_flock_try(fd, op);
        if (r == 0)
            return true;
        if (r < 0) {
            *st = PLUGIN_ERR_IO;
            return false;
        }
        if (plugin_wait_expired(w)) {
            *st = PLUGIN_ERR_BUSY;
            return false;
        }
        platform_sleep_ms(PLUGIN_LOCK_STEP_MS);
    }
}

/* Pass the waiter gate: true when no waiter is announced. A newcomer yields
 * (holding nothing) while one is. */
static bool plugin_gate_pass(int qfd, struct plugin_wait *w, enum plugin_status *st)
{
    if (!plugin_flock_poll(qfd, LOCK_EX, w, st))
        return false;
    flock(qfd, LOCK_UN);
    return true;
}

/* Take ".lock" with qfd and fd open; see the comment above. */
static enum plugin_status plugin_lock_take(int qfd, int fd, int64_t deadline)
{
    struct plugin_wait w = { fd, deadline, plugin_lock_stamp_read(fd) };
    enum plugin_status st = PLUGIN_OK;
    if (!plugin_gate_pass(qfd, &w, &st))
        return st;
    int r = plugin_flock_try(fd, LOCK_EX);
    if (r == 0)
        return PLUGIN_OK;
    if (r < 0)
        return PLUGIN_ERR_IO;
    /* Held: announce as a waiter, then poll. Closing qfd later withdraws it. */
    if (!plugin_flock_poll(qfd, LOCK_SH, &w, &st))
        return st;
    if (!plugin_flock_poll(fd, LOCK_EX, &w, &st))
        return st;
    return PLUGIN_OK;
}
#endif

enum plugin_status plugin_lock_acquire(const char *plugdir, struct plugin_lock *lock)
{
    lock->fd = -1;
#if defined(_WIN32)
    /* Windows keeps its current behavior: no cross-process mutation lock yet;
     * the exclusive temp-file creates and atomic replaces remain the only
     * exclusion there. */
    (void)plugdir;
    return PLUGIN_OK;
#else

    int qfd = -1, fd = -1;
    int64_t deadline = platform_time_monotonic_ms() + plugin_lock_budget_ms();
    enum plugin_status st = plugin_lock_open(plugdir, ".lock.q", &qfd);
    if (st != PLUGIN_OK)
        return st;
    st = plugin_lock_open(plugdir, ".lock", &fd);
    if (st == PLUGIN_OK)
        st = plugin_lock_take(qfd, fd, deadline);
    close(qfd); /* withdraws the waiter announcement */
    if (st != PLUGIN_OK) {
        if (fd >= 0)
            close(fd);
        return st;
    }
    plugin_lock_stamp(fd); /* tell the waiters the lock changed hands */
#ifdef ZCL_TESTING
    if (g_lock_hold_pause_ms > 0)
        platform_sleep_ms((int)g_lock_hold_pause_ms);
#endif
    lock->fd = fd;
    return PLUGIN_OK;

#endif
}

void plugin_lock_release(struct plugin_lock *lock)
{
    if (lock->fd >= 0)
        close(lock->fd); /* closing drops the flock */
    lock->fd = -1;
}
