/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * See storage/ldb_snapshot.h for the design rationale. */

#include "storage/ldb_snapshot.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

static void set_err(char *buf, size_t cap, const char *fmt, ...)
{
    if (!buf || cap == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, cap, fmt, ap);
    va_end(ap);
}

#if !defined(_WIN32)
/* Read up to `cap-1` bytes from `path` into `buf`, NUL-terminate.
 * Returns number of bytes read (>= 0), or -1 on error. */
static ssize_t slurp_small(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, cap > 0 ? cap - 1 : 0);
    close(fd);
    if (n < 0) return -1;
    if ((size_t)n < cap) buf[n] = '\0';
    else if (cap > 0) buf[cap - 1] = '\0';
    return n;
}

/* Copy a small file `src` → `dst`. Uses a simple read+write loop;
 * good enough for the few KB-MB metadata files in a LevelDB dir. */
static bool copy_file(const char *src, const char *dst,
                      char *err, size_t err_sz)
{
    int sfd = open(src, O_RDONLY);
    if (sfd < 0) {
        set_err(err, err_sz, "open(%s): %s", src, strerror(errno));
        return false;
    }
    int dfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (dfd < 0) {
        set_err(err, err_sz, "create(%s): %s", dst, strerror(errno));
        close(sfd);
        return false;
    }
    uint8_t *buf = zcl_malloc(64 * 1024, "ldb_snapshot.copybuf");
    if (!buf) {
        close(sfd); close(dfd);
        set_err(err, err_sz, "oom");
        return false;
    }
    ssize_t n;
    bool ok = true;
    while ((n = read(sfd, buf, 64 * 1024)) > 0) {
        ssize_t w = 0;
        while (w < n) {
            ssize_t k = write(dfd, buf + w, (size_t)(n - w));
            if (k <= 0) {
                ok = false;
                set_err(err, err_sz, "write(%s): %s",
                        dst, strerror(errno));
                break;
            }
            w += k;
        }
        if (!ok) break;
    }
    if (n < 0) {
        ok = false;
        set_err(err, err_sz, "read(%s): %s", src, strerror(errno));
    }
    free(buf);
    close(sfd);
    if (close(dfd) != 0 && ok) {
        ok = false;
        set_err(err, err_sz, "close(%s): %s", dst, strerror(errno));
    }
    return ok;
}

/* Try hardlink; on EXDEV fall back to copy. */
static bool link_or_copy(const char *src, const char *dst,
                        char *err, size_t err_sz)
{
    if (link(src, dst) == 0) return true;
    if (errno == EXDEV)
        return copy_file(src, dst, err, err_sz);
    if (errno == EEXIST) {
        /* Stale entry from earlier failed run — remove + retry. If the
         * unlink fails the file is still present, so a retried link()
         * would just hit EEXIST again; fail loudly instead. */
        if (unlink(dst) != 0) {
            int e = errno; /* preserve across LOG_WARN's fprintf */
            LOG_WARN("storage", "unlink(%s): %s", dst, strerror(e));
            set_err(err, err_sz, "unlink(%s): %s", dst, strerror(e));
            return false;
        }
        if (link(src, dst) == 0) return true;
    }
    set_err(err, err_sz, "link(%s,%s): %s", src, dst, strerror(errno));
    return false;
}

/* Heuristic: file name pattern matches a small metadata file we should
 * copy bytes-for-bytes (rather than hardlink). */
static bool is_metadata_name(const char *name)
{
    if (strcmp(name, "CURRENT") == 0) return true;
    if (strcmp(name, "LOG") == 0)     return true;
    if (strcmp(name, "LOG.old") == 0) return true;
    if (strncmp(name, "MANIFEST-", 9) == 0) return true;
    return false;
}

static bool name_is_ldb(const char *name)
{
    size_t n = strlen(name);
    return n >= 4 && strcmp(name + n - 4, ".ldb") == 0;
}
#endif

void ldb_snapshot_destroy(const char *dst_dir)
{
#if defined(_WIN32)
    /* Destruction is part of the same unqualified directory transaction as
     * creation; refuse without inspecting or mutating the supplied path. */
    (void)dst_dir;
    return;
#else
    if (!dst_dir) return;
    DIR *d = opendir(dst_dir);
    if (!d) return; /* nothing to clean */
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0) continue;
        if (strcmp(de->d_name, "..") == 0) continue;
        char p[2048];
        snprintf(p, sizeof(p), "%s/%s", dst_dir, de->d_name);
        (void)unlink(p);
    }
    closedir(d);
    (void)rmdir(dst_dir);
#endif
}

bool ldb_snapshot_make(const char *src_dir,
                       const char *dst_dir,
                       char *err_msg, size_t err_sz)
{
    if (!src_dir || !dst_dir) {
        set_err(err_msg, err_sz, "null args");
        LOG_FAIL("ldb_snapshot", "make: null args");
        return false;
    }

#if defined(_WIN32)
    set_err(err_msg, err_sz,
            "Windows LevelDB snapshots are disabled until retained directory "
            "capabilities provide no-clobber copy/link and rollback");
    return false;
#else
    /* Verify src exists. */
    struct stat st;
    if (stat(src_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        set_err(err_msg, err_sz,
                "src missing: %s", src_dir);
        LOG_FAIL("ldb_snapshot", "src missing");
        return false;
    }

    /* Wipe stale dst. */
    ldb_snapshot_destroy(dst_dir);

    if (mkdir(dst_dir, 0700) != 0 && errno != EEXIST) {
        set_err(err_msg, err_sz,
                "mkdir(%s): %s", dst_dir, strerror(errno));
        LOG_FAIL("ldb_snapshot", "mkdir");
        return false;
    }

    /* Read CURRENT before/after to detect MANIFEST rotation race. */
    char src_current_path[2048];
    snprintf(src_current_path, sizeof(src_current_path),
             "%s/CURRENT", src_dir);
    char current_before[256] = {0};
    if (slurp_small(src_current_path, current_before,
                    sizeof(current_before)) <= 0) {
        set_err(err_msg, err_sz,
                "read CURRENT: %s", strerror(errno));
        LOG_FAIL("ldb_snapshot", "read CURRENT");
        return false;
    }

    DIR *d = opendir(src_dir);
    if (!d) {
        set_err(err_msg, err_sz,
                "opendir(%s): %s", src_dir, strerror(errno));
        LOG_FAIL("ldb_snapshot", "opendir");
        return false;
    }

    bool ok = true;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0) continue;
        if (strcmp(de->d_name, "..") == 0) continue;
        if (strcmp(de->d_name, "LOCK") == 0) continue;

        char src_p[2048], dst_p[2048];
        snprintf(src_p, sizeof(src_p), "%s/%s", src_dir, de->d_name);
        snprintf(dst_p, sizeof(dst_p), "%s/%s", dst_dir, de->d_name);

        char sub_err[256] = {0};
        if (name_is_ldb(de->d_name)) {
            if (!link_or_copy(src_p, dst_p, sub_err, sizeof(sub_err))) {
                set_err(err_msg, err_sz, "link_or_copy(%s): %s",
                        de->d_name, sub_err);
                LOG_FAIL("ldb_snapshot", "link_or_copy");
                ok = false;
                break;
            }
        } else if (is_metadata_name(de->d_name)) {
            if (!copy_file(src_p, dst_p, sub_err, sizeof(sub_err))) {
                set_err(err_msg, err_sz, "copy(%s): %s",
                        de->d_name, sub_err);
                LOG_FAIL("ldb_snapshot", "copy");
                ok = false;
                break;
            }
        }
        /* Unknown files (extensions we don't recognize): skip
         * silently. LevelDB doesn't need them. */
    }
    closedir(d);

    if (!ok) {
        ldb_snapshot_destroy(dst_dir);
        return false;
    }

    /* Race detection: re-read CURRENT in src. If MANIFEST rotated
     * mid-copy, our MANIFEST file may now be stale. */
    char current_after[256] = {0};
    if (slurp_small(src_current_path, current_after,
                    sizeof(current_after)) <= 0) {
        set_err(err_msg, err_sz, "race recheck failed");
        LOG_FAIL("ldb_snapshot", "race recheck");
        ldb_snapshot_destroy(dst_dir);
        return false;
    }
    if (strcmp(current_before, current_after) != 0) {
        set_err(err_msg, err_sz, "manifest_changed");
        /* This is a retryable race, not a hard error — don't LOG_FAIL. */
        ldb_snapshot_destroy(dst_dir);
        return false;
    }

    return true;
#endif
}
