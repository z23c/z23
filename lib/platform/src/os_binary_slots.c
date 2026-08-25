/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Crash-durable binary A/B slot state and pinned executable selection.
 */
/* Purpose: select and pin crash-loop-safe executable slots without shell IO. */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "platform/os_binary_slots.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_NOFOLLOW
#error "os_binary_slots requires O_NOFOLLOW"
#endif

#ifdef O_PATH
#define SLOT_TRAVERSE_FLAGS (O_PATH | O_DIRECTORY | O_CLOEXEC)
#else
#define SLOT_TRAVERSE_FLAGS (O_RDONLY | O_DIRECTORY | O_CLOEXEC)
#endif

#define SLOT_LOCK_BASENAME ".binary-slots.lock"
#define STREAK_TEXT_MAX 32

#ifdef ZCL_TESTING
static bool g_fail_before_rename_once;

void os_binary_slots_test_fail_before_rename_once(void)
{
    g_fail_before_rename_once = true;
}
#endif

static void set_error(char *out, size_t out_size, const char *fmt, ...)
{
    if (!out || out_size == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(out, out_size, fmt, ap);
    va_end(ap);
}

static bool component_valid(const char *s)
{
    return s && s[0] && strcmp(s, ".") != 0 && strcmp(s, "..") != 0 &&
           strchr(s, '/') == NULL;
}

static bool join_slots_path(const char *slots_dir, const char *base,
                            char *out, size_t out_size,
                            char *error, size_t error_size)
{
    if (!slots_dir || !slots_dir[0] || !component_valid(base)) {
        set_error(error, error_size, "invalid slots path");
        return false;
    }
    int n = snprintf(out, out_size, "%s/%s", slots_dir, base);
    if (n < 0 || (size_t)n >= out_size) {
        set_error(error, error_size, "slots path is too long");
        return false;
    }
    return true;
}

bool os_binary_slots_parse_threshold(const char *text, uint32_t *out)
{
    if (!text || !text[0] || !out)
        return false;
    for (const char *p = text; *p; p++)
        if (*p < '0' || *p > '9')
            return false;
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno == ERANGE || !end || *end != '\0' || value == 0 ||
        value > UINT32_MAX)
        return false;
    *out = (uint32_t)value;
    return true;
}

bool os_binary_slots_ensure_directory(const char *slots_dir,
                                      char *error, size_t error_size)
{
    if (error && error_size) error[0] = '\0';
    if (!slots_dir || !slots_dir[0] || strlen(slots_dir) >= OS_BINARY_SLOTS_PATH_MAX) {
        set_error(error, error_size, "invalid slots directory");
        return false;
    }

    char copy[OS_BINARY_SLOTS_PATH_MAX];
    (void)snprintf(copy, sizeof(copy), "%s", slots_dir);
    int dirfd = open(copy[0] == '/' ? "/" : ".", SLOT_TRAVERSE_FLAGS);
    if (dirfd < 0) {
        set_error(error, error_size, "open path root failed: %s", strerror(errno));
        return false;
    }

    char *cursor = copy;
    if (*cursor == '/') cursor++;
    char *save = NULL;
    for (char *part = strtok_r(cursor, "/", &save); part;
         part = strtok_r(NULL, "/", &save)) {
        if (!component_valid(part)) {
            set_error(error, error_size, "unsafe path component");
            close(dirfd);
            return false;
        }
        if (mkdirat(dirfd, part, 0700) != 0 && errno != EEXIST) {
            set_error(error, error_size, "mkdirat(%s) failed: %s",
                      part, strerror(errno));
            close(dirfd);
            return false;
        }
        int next = openat(dirfd, part, SLOT_TRAVERSE_FLAGS | O_NOFOLLOW);
        if (next < 0) {
            set_error(error, error_size, "openat directory %s failed: %s",
                      part, strerror(errno));
            close(dirfd);
            return false;
        }
        close(dirfd);
        dirfd = next;
    }
    close(dirfd);
    return true;
}

static bool split_parent(const char *path, char *parent, size_t parent_size,
                         char *base, size_t base_size,
                         char *error, size_t error_size)
{
    if (!path || !path[0] || strlen(path) >= OS_BINARY_SLOTS_PATH_MAX) {
        set_error(error, error_size, "invalid streak path");
        return false;
    }
    const char *slash = strrchr(path, '/');
    if (!slash) {
        (void)snprintf(parent, parent_size, ".");
        (void)snprintf(base, base_size, "%s", path);
    } else if (slash == path) {
        (void)snprintf(parent, parent_size, "/");
        (void)snprintf(base, base_size, "%s", slash + 1);
    } else {
        size_t n = (size_t)(slash - path);
        if (n >= parent_size) {
            set_error(error, error_size, "streak parent path too long");
            return false;
        }
        memcpy(parent, path, n);
        parent[n] = '\0';
        (void)snprintf(base, base_size, "%s", slash + 1);
    }
    if (!component_valid(base)) {
        set_error(error, error_size, "invalid streak basename");
        return false;
    }
    return true;
}

static int lock_directory(int dirfd, char *error, size_t error_size)
{
    int fd = openat(dirfd, SLOT_LOCK_BASENAME,
                    O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        set_error(error, error_size, "open slot lock failed: %s", strerror(errno));
        return -1;
    }
    if (flock(fd, LOCK_EX) != 0) {
        set_error(error, error_size, "lock slot state failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

enum streak_read_result {
    STREAK_MISSING,
    STREAK_VALID,
    STREAK_CORRUPT
};

static enum streak_read_result read_streak_at(int dirfd, const char *base,
                                               uint32_t *value)
{
    int fd = openat(dirfd, base,
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0)
        return errno == ENOENT ? STREAK_MISSING : STREAK_CORRUPT;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        st.st_size >= STREAK_TEXT_MAX) {
        close(fd);
        return STREAK_CORRUPT;
    }
    char buf[STREAK_TEXT_MAX];
    size_t used = 0;
    while (used < sizeof(buf) - 1) {
        ssize_t n = read(fd, buf + used, sizeof(buf) - 1 - used);
        if (n > 0) {
            used += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            close(fd);
            return STREAK_CORRUPT;
        }
        break;
    }
    close(fd);
    buf[used] = '\0';
    if (used < 2 || buf[used - 1] != '\n')
        return STREAK_CORRUPT;
    buf[used - 1] = '\0';
    for (size_t i = 0; i + 1 < used; i++)
        if (buf[i] < '0' || buf[i] > '9')
            return STREAK_CORRUPT;
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(buf, &end, 10);
    if (errno == ERANGE || !end || *end != '\0' || parsed > UINT32_MAX)
        return STREAK_CORRUPT;
    *value = (uint32_t)parsed;
    return STREAK_VALID;
}

static bool write_all(int fd, const char *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        return false;
    }
    return true;
}

static bool store_streak_at(int dirfd, const char *base, uint32_t value,
                            char *error, size_t error_size)
{
    char tmp[96];
    int n = snprintf(tmp, sizeof(tmp), ".%s.tmp.%ld", base, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof(tmp)) {
        set_error(error, error_size, "streak temporary name too long");
        return false;
    }
    (void)unlinkat(dirfd, tmp, 0);
    int fd = openat(dirfd, tmp,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    0600);
    if (fd < 0) {
        set_error(error, error_size, "open streak temporary failed: %s",
                  strerror(errno));
        return false;
    }
    char text[STREAK_TEXT_MAX];
    int text_len = snprintf(text, sizeof(text), "%u\n", value);
    bool ok = text_len > 0 && (size_t)text_len < sizeof(text) &&
              write_all(fd, text, (size_t)text_len);
    if (!ok)
        set_error(error, error_size, "write streak temporary failed: %s",
                  strerror(errno));
    if (ok && fsync(fd) != 0) {
        set_error(error, error_size, "fsync streak temporary failed: %s",
                  strerror(errno));
        ok = false;
    }
    if (close(fd) != 0 && ok) {
        set_error(error, error_size, "close streak temporary failed: %s",
                  strerror(errno));
        ok = false;
    }
#ifdef ZCL_TESTING
    if (ok && g_fail_before_rename_once) {
        g_fail_before_rename_once = false;
        set_error(error, error_size, "injected failure before streak rename");
        ok = false;
    }
#endif
    if (ok && renameat(dirfd, tmp, dirfd, base) != 0) {
        set_error(error, error_size, "rename streak failed: %s", strerror(errno));
        ok = false;
    }
    if (ok && fsync(dirfd) != 0) {
        set_error(error, error_size, "fsync slots directory failed: %s",
                  strerror(errno));
        ok = false;
    }
    if (!ok)
        (void)unlinkat(dirfd, tmp, 0);
    return ok;
}

static int pin_executable_path(const char *path, char *error, size_t error_size)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        set_error(error, error_size, "open executable %s failed: %s",
                  path, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) {
        set_error(error, error_size, "%s is not a regular executable", path);
        close(fd);
        return -1;
    }
    return fd;
}

static int pin_lastgood_at(int dirfd, bool *invalid,
                           char *error, size_t error_size)
{
    if (invalid)
        *invalid = false;
    int fd = openat(dirfd, OS_BINARY_SLOTS_LASTGOOD_BASENAME,
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        if (invalid && errno != ENOENT)
            *invalid = true;
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) {
        if (invalid)
            *invalid = true;
        set_error(error, error_size, "last-good is not a regular executable");
        close(fd);
        return -1;
    }
    return fd;
}

bool os_binary_slots_prepare_launch(const char *slots_dir,
                                    const char *current_path,
                                    uint32_t fallback_threshold,
                                    struct os_binary_slots_launch *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    out->executable_fd = -1;
    if (!slots_dir || !slots_dir[0] || !current_path || !current_path[0] ||
        strlen(current_path) >= sizeof(out->target_path) ||
        fallback_threshold == 0) {
        set_error(out->error, sizeof(out->error), "invalid launch arguments");
        return false;
    }
    char lastgood_path[OS_BINARY_SLOTS_PATH_MAX];
    if (!join_slots_path(slots_dir, OS_BINARY_SLOTS_LASTGOOD_BASENAME,
                         lastgood_path, sizeof(lastgood_path), out->error,
                         sizeof(out->error)))
        return false;
    int dirfd = open(slots_dir,
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) {
        set_error(out->error, sizeof(out->error), "open slots directory failed: %s",
                  strerror(errno));
        return false;
    }
    int lockfd = lock_directory(dirfd, out->error, sizeof(out->error));
    if (lockfd < 0) {
        close(dirfd);
        return false;
    }

    uint32_t prior = 0;
    enum streak_read_result state = read_streak_at(
        dirfd, OS_BINARY_SLOTS_STREAK_BASENAME, &prior);
    bool corrupt = state == STREAK_CORRUPT ||
                   (state == STREAK_VALID && prior == UINT32_MAX);
    bool lastgood_invalid = false;
    int lastgood_fd = pin_lastgood_at(dirfd, &lastgood_invalid, NULL, 0);
    bool fallback_due = corrupt ||
                        (state == STREAK_VALID && prior >= fallback_threshold);
    if (fallback_due && lastgood_invalid) {
        set_error(out->error, sizeof(out->error),
                  "fallback required but last-good is not a regular executable");
        (void)flock(lockfd, LOCK_UN);
        close(lockfd);
        close(dirfd);
        return false;
    }
    bool use_fallback = lastgood_fd >= 0 && fallback_due;
    int selected_fd = -1;
    if (use_fallback) {
        selected_fd = lastgood_fd;
        lastgood_fd = -1;
        out->fallback_active = true;
        memcpy(out->target_path, lastgood_path, strlen(lastgood_path) + 1u);
    } else {
        selected_fd = pin_executable_path(current_path, out->error,
                                          sizeof(out->error));
        if (selected_fd < 0 && lastgood_fd >= 0) {
            selected_fd = lastgood_fd;
            lastgood_fd = -1;
            out->fallback_active = true;
            memcpy(out->target_path, lastgood_path,
                   strlen(lastgood_path) + 1u);
        } else {
            memcpy(out->target_path, current_path, strlen(current_path) + 1u);
        }
    }
    if (lastgood_fd >= 0)
        close(lastgood_fd);
    if (selected_fd < 0) {
        (void)flock(lockfd, LOCK_UN);
        close(lockfd);
        close(dirfd);
        return false;
    }

    out->streak_corrupt = corrupt;
    out->streak_before = prior;
    if (!corrupt) {
        uint32_t next = prior + 1;
        if (!store_streak_at(dirfd, OS_BINARY_SLOTS_STREAK_BASENAME, next,
                             out->error, sizeof(out->error))) {
            close(selected_fd);
            (void)flock(lockfd, LOCK_UN);
            close(lockfd);
            close(dirfd);
            return false;
        }
        out->streak_written = true;
        out->streak_after = next;
    }
    out->executable_fd = selected_fd;
    (void)flock(lockfd, LOCK_UN);
    close(lockfd);
    close(dirfd);
    return true;
}

void os_binary_slots_close_launch(struct os_binary_slots_launch *launch)
{
    if (!launch)
        return;
    if (launch->executable_fd >= 0)
        close(launch->executable_fd);
    launch->executable_fd = -1;
}

static bool streak_file_operation(const char *streak_file, bool reset,
                                  char *error, size_t error_size)
{
    if (error && error_size) error[0] = '\0';
    char parent[OS_BINARY_SLOTS_PATH_MAX];
    char base[OS_BINARY_SLOTS_PATH_MAX];
    if (!split_parent(streak_file, parent, sizeof(parent), base, sizeof(base),
                      error, error_size))
        return false;
    int dirfd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) {
        set_error(error, error_size, "open streak parent failed: %s", strerror(errno));
        return false;
    }
    int lockfd = lock_directory(dirfd, error, error_size);
    if (lockfd < 0) {
        close(dirfd);
        return false;
    }
    uint32_t next = 0;
    bool ok = true;
    if (!reset) {
        uint32_t prior = 0;
        enum streak_read_result state = read_streak_at(dirfd, base, &prior);
        if (state == STREAK_CORRUPT ||
            (state == STREAK_VALID && prior == UINT32_MAX)) {
            set_error(error, error_size,
                      "refusing to overwrite corrupt or overflowing streak");
            ok = false;
        } else {
            next = prior + 1;
        }
    }
    if (ok)
        ok = store_streak_at(dirfd, base, next, error, error_size);
    (void)flock(lockfd, LOCK_UN);
    close(lockfd);
    close(dirfd);
    return ok;
}

bool os_binary_slots_reset_streak_file(const char *streak_file,
                                       char *error, size_t error_size)
{
    return streak_file_operation(streak_file, true, error, error_size);
}

bool os_binary_slots_increment_streak_file(const char *streak_file,
                                           char *error, size_t error_size)
{
    return streak_file_operation(streak_file, false, error, error_size);
}
