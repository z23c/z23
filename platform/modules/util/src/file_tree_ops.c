/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * file_tree_ops — the single fd-based recursive file-tree walker.
 *
 * See util/file_tree_ops.h for the contract. This is the one recursive
 * copy/remove implementation in the tree; it replaces every
 * `system("cp -a …")` / `system("rm -rf …")` shell-out (os-substrate-plan
 * §1). openat/fdopendir/fstatat with O_NOFOLLOW throughout so a symlink is
 * never followed; recursion is depth-bounded; every error return carries the
 * exact offending path in its struct zcl_result. */

#include "util/file_tree_ops.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#ifndef _WIN32
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#ifdef _WIN32

/* Recursive mutation remains disabled until the Win32 implementation walks
 * retained directory handles and validates every component against reparse
 * substitution. Refuse before probing or creating either tree. */
struct zcl_result zcl_tree_copy(const char *src, const char *dst,
                                unsigned flags, zcl_tree_filter_fn filter,
                                void *fctx)
{
    (void)src;
    (void)dst;
    (void)flags;
    (void)filter;
    (void)fctx;
    return ZCL_ERR(-1,
        "zcl_tree_copy: Windows recursive mutation is disabled pending "
        "handle-bound no-reparse qualification");
}

struct zcl_result zcl_tree_remove(const char *path)
{
    (void)path;
    return ZCL_ERR(-1,
        "zcl_tree_remove: Windows recursive mutation is disabled pending "
        "handle-bound no-reparse qualification");
}

struct zcl_result zcl_mkdir_p(const char *path, mode_t mode)
{
    (void)path;
    (void)mode;
    return ZCL_ERR(-1,
        "zcl_mkdir_p: Windows recursive mutation is disabled pending "
        "handle-bound no-reparse qualification");
}

#else

#define ZCL_TREE_IOBUF_SZ (256u * 1024u)

/* Copy every remaining byte of `in` into `out` through a 256 KB buffer that
 * the top-level call allocated once and threads down the recursion. */
static struct zcl_result copy_bytes(int in, int out, char *iobuf,
                                    const char *src_disp, const char *dst_disp)
{
    for (;;) {
        ssize_t r = read(in, iobuf, ZCL_TREE_IOBUF_SZ);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return ZCL_ERR(-1, "read failed: %s: errno=%d: %s; "
                           "inspect source readability before retrying",
                           src_disp, errno, strerror(errno));
        }
        if (r == 0)
            return ZCL_OK;
        size_t off = 0;
        while (off < (size_t)r) {
            ssize_t w = write(out, iobuf + off, (size_t)r - off);
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                return ZCL_ERR(-1, "write failed: %s: %s", dst_disp,
                               strerror(errno));
            }
            off += (size_t)w;
        }
    }
}

/* Compare the opened objects before any destructive destination operation. */
static struct zcl_result copy_prepare_destination(int in, int out,
                                                  const char *src_disp,
                                                  const char *dst_disp)
{
    struct stat src_st, dst_st;
    if (fstat(in, &src_st) != 0)
        return ZCL_ERR(-1, "fstat src failed: %s: %s", src_disp,
                       strerror(errno));
    if (fstat(out, &dst_st) != 0)
        return ZCL_ERR(-1, "fstat dst failed: %s: %s", dst_disp,
                       strerror(errno));
    if (src_st.st_dev == dst_st.st_dev && src_st.st_ino == dst_st.st_ino)
        return ZCL_ERR(-1, "refusing same-inode copy: %s -> %s",
                       src_disp, dst_disp);
    if (ftruncate(out, 0) != 0)
        return ZCL_ERR(-1, "truncate dst failed: %s: %s", dst_disp,
                       strerror(errno));
    return ZCL_OK;
}

/* Copy one regular file `s_dfd/sname` -> `d_dfd/dname`. `st` is the already
 * lstat'd source. Honors ZCL_COPY_UPDATE_ONLY (skip when dst mtime >= src)
 * and ZCL_COPY_PRESERVE_TIMES (futimens dst = src atime/mtime). */
static struct zcl_result copy_regular_at(int s_dfd, const char *sname,
                                         int d_dfd, const char *dname,
                                         const struct stat *st, unsigned flags,
                                         char *iobuf, const char *src_disp,
                                         const char *dst_disp)
{
    if (flags & ZCL_COPY_UPDATE_ONLY) {
        struct stat dst_st;
        if (fstatat(d_dfd, dname, &dst_st, AT_SYMLINK_NOFOLLOW) == 0 &&
            S_ISREG(dst_st.st_mode)) {
            /* Skip unless the source is strictly newer than the destination
             * (cp -u): dst mtime >= src mtime means keep the destination. */
            bool src_newer =
                (st->st_mtim.tv_sec > dst_st.st_mtim.tv_sec) ||
                (st->st_mtim.tv_sec == dst_st.st_mtim.tv_sec &&
                 st->st_mtim.tv_nsec > dst_st.st_mtim.tv_nsec);
            if (!src_newer)
                return ZCL_OK;
        }
    }

    int in = openat(s_dfd, sname, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (in < 0)
        return ZCL_ERR(-1, "open src failed: %s: %s", src_disp,
                       strerror(errno));

    mode_t mode = st->st_mode & 07777;
    int out = openat(d_dfd, dname,
                     O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
                     mode);
    if (out < 0) {
        int e = errno;
        close(in);
        return ZCL_ERR(-1, "open dst failed: %s: %s", dst_disp, strerror(e));
    }

    struct zcl_result r = copy_prepare_destination(in, out, src_disp, dst_disp);
    if (r.ok)
        r = copy_bytes(in, out, iobuf, src_disp, dst_disp);
    if (r.ok) {
        /* Set the exact mode even under a restrictive umask. */
        if (fchmod(out, mode) != 0)
            r = ZCL_ERR(-1, "fchmod failed: %s: %s", dst_disp,
                        strerror(errno));
    }
    if (r.ok && (flags & ZCL_COPY_PRESERVE_TIMES)) {
        struct timespec ts[2] = { st->st_atim, st->st_mtim };
        if (futimens(out, ts) != 0)
            r = ZCL_ERR(-1, "futimens failed: %s: %s", dst_disp,
                        strerror(errno));
    }

    close(in);
    close(out);
    return r;
}

/* Recursively copy the directory whose open handle is `sd` into the already
 * created destination directory fd `d_dfd`. `sd` is closed by the caller. */
static struct zcl_result copy_dir(DIR *sd, int d_dfd, unsigned flags,
                                  zcl_tree_filter_fn filter, void *fctx,
                                  int depth, char *iobuf,
                                  const char *src_disp, const char *dst_disp);

/* Copies one subdirectory. Directory mode/times are set AFTER its children
 * exist, since writing children bumps the directory's own mtime. */
static struct zcl_result copy_subdir(int s_dfd, int d_dfd, const char *name,
                                     const struct stat *st, unsigned flags,
                                     zcl_tree_filter_fn filter, void *fctx,
                                     int depth, char *iobuf, const char *cs,
                                     const char *cd)
{
    mode_t mode = st->st_mode & 07777;
    if (mkdirat(d_dfd, name, mode) != 0 && errno != EEXIST)
        return ZCL_ERR(-1, "mkdir failed: %s: %s", cd, strerror(errno));

    int child_s = openat(s_dfd, name,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (child_s < 0)
        return ZCL_ERR(-1, "open dir failed: %s: %s", cs, strerror(errno));
    int child_d = openat(d_dfd, name,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (child_d < 0) {
        int e = errno;
        close(child_s);
        return ZCL_ERR(-1, "open dir failed: %s: %s", cd, strerror(e));
    }
    DIR *child_sd = fdopendir(child_s);
    if (!child_sd) {
        int e = errno;
        close(child_s);
        close(child_d);
        return ZCL_ERR(-1, "fdopendir failed: %s: %s", cs, strerror(e));
    }

    struct zcl_result r = copy_dir(child_sd, child_d, flags, filter, fctx,
                                   depth + 1, iobuf, cs, cd);
    closedir(child_sd);   /* also closes child_s */

    if (r.ok && fchmod(child_d, mode) != 0)
        r = ZCL_ERR(-1, "fchmod failed: %s: %s", cd, strerror(errno));
    if (r.ok && (flags & ZCL_COPY_PRESERVE_TIMES)) {
        struct timespec ts[2] = { st->st_atim, st->st_mtim };
        if (futimens(child_d, ts) != 0)
            r = ZCL_ERR(-1, "futimens failed: %s: %s", cd, strerror(errno));
    }
    close(child_d);
    return r;
}

/* Copies one directory entry; a filtered-out entry is skipped. */
static struct zcl_result copy_entry(int s_dfd, int d_dfd, const char *name,
                                    unsigned flags, zcl_tree_filter_fn filter,
                                    void *fctx, int depth, char *iobuf,
                                    const char *src_disp, const char *dst_disp)
{
    struct stat st;
    if (fstatat(s_dfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return ZCL_ERR(-1, "stat failed: %s/%s: %s", src_disp, name,
                       strerror(errno));

    bool is_dir = S_ISDIR(st.st_mode);
    if (filter && !filter(name, is_dir, fctx))
        return ZCL_OK;

    if (S_ISLNK(st.st_mode))
        return ZCL_ERR(-1, "refusing to copy symlink entry: %s/%s",
                       src_disp, name);

    char cs[PATH_MAX], cd[PATH_MAX];
    int ns = snprintf(cs, sizeof(cs), "%s/%s", src_disp, name);
    int nd = snprintf(cd, sizeof(cd), "%s/%s", dst_disp, name);
    if (ns <= 0 || (size_t)ns >= sizeof(cs) ||
        nd <= 0 || (size_t)nd >= sizeof(cd))
        return ZCL_ERR(-1, "path too long under: %s", src_disp);

    if (is_dir)
        return copy_subdir(s_dfd, d_dfd, name, &st, flags, filter, fctx,
                           depth, iobuf, cs, cd);
    if (S_ISREG(st.st_mode))
        return copy_regular_at(s_dfd, name, d_dfd, name, &st, flags, iobuf,
                               cs, cd);
    return ZCL_ERR(-1, "refusing unsupported file type: %s/%s", src_disp,
                   name);
}

static struct zcl_result copy_dir(DIR *sd, int d_dfd, unsigned flags,
                                  zcl_tree_filter_fn filter, void *fctx,
                                  int depth, char *iobuf,
                                  const char *src_disp, const char *dst_disp)
{
    if (depth >= ZCL_TREE_MAX_DEPTH)
        return ZCL_ERR(-1, "max copy depth %d exceeded at: %s",
                       ZCL_TREE_MAX_DEPTH, src_disp);

    int s_dfd = dirfd(sd);
    for (;;) {
        errno = 0;
        struct dirent *ent = readdir(sd);
        if (!ent) {
            if (errno != 0)
                return ZCL_ERR(-1, "readdir failed: %s: %s", src_disp,
                               strerror(errno));
            break;
        }
        const char *name = ent->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
            continue;
        struct zcl_result r = copy_entry(s_dfd, d_dfd, name, flags, filter,
                                         fctx, depth, iobuf, src_disp,
                                         dst_disp);
        if (!r.ok)
            return r;
    }
    return ZCL_OK;
}

/* Copy a directory root after the caller has validated its type and allocated
 * the shared I/O buffer. */
static struct zcl_result copy_root_dir(const char *src, const char *dst,
                                       const struct stat *st, unsigned flags,
                                       zcl_tree_filter_fn filter, void *fctx,
                                       char *iobuf)
{
    int s = openat(AT_FDCWD, src,
                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (s < 0)
        return ZCL_ERR(-1, "open src dir failed: %s: %s", src,
                       strerror(errno));
    if (mkdir(dst, st->st_mode & 07777) != 0 && errno != EEXIST) {
        int e = errno;
        close(s);
        return ZCL_ERR(-1, "mkdir dst failed: %s: %s", dst, strerror(e));
    }
    int d = openat(AT_FDCWD, dst,
                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (d < 0) {
        int e = errno;
        close(s);
        return ZCL_ERR(-1, "open dst dir failed: %s: %s", dst, strerror(e));
    }
    DIR *sd = fdopendir(s);
    if (!sd) {
        int e = errno;
        close(s);
        close(d);
        return ZCL_ERR(-1, "fdopendir failed: %s: %s", src, strerror(e));
    }

    struct zcl_result r = copy_dir(sd, d, flags, filter, fctx, 0, iobuf,
                                   src, dst);
    closedir(sd);   /* also closes s */

    if (r.ok && fchmod(d, st->st_mode & 07777) != 0)
        r = ZCL_ERR(-1, "fchmod failed: %s: %s", dst, strerror(errno));
    if (r.ok && (flags & ZCL_COPY_PRESERVE_TIMES)) {
        struct timespec ts[2] = { st->st_atim, st->st_mtim };
        if (futimens(d, ts) != 0)
            r = ZCL_ERR(-1, "futimens failed: %s: %s", dst, strerror(errno));
    }
    close(d);
    return r;
}

struct zcl_result zcl_tree_copy(const char *src, const char *dst,
                                unsigned flags, zcl_tree_filter_fn filter,
                                void *fctx)
{
    if (!src)
        return ZCL_ERR(-1, "zcl_tree_copy: NULL src; supply a source path");
    if (!dst)
        return ZCL_ERR(-1, "zcl_tree_copy: NULL dst; supply a destination path");

    struct stat st;
    if (fstatat(AT_FDCWD, src, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return ZCL_ERR(-1, "stat src failed: %s: %s", src, strerror(errno));
    if (S_ISLNK(st.st_mode))
        return ZCL_ERR(-1, "refusing to copy symlink root: %s", src);

    char *iobuf = zcl_malloc(ZCL_TREE_IOBUF_SZ, "file_tree_copy.iobuf");
    if (!iobuf)
        return ZCL_ERR(-1, "iobuf alloc failed (%u bytes)", ZCL_TREE_IOBUF_SZ);

    struct zcl_result r;

    if (S_ISREG(st.st_mode)) {
        r = copy_regular_at(AT_FDCWD, src, AT_FDCWD, dst, &st, flags, iobuf,
                            src, dst);
        free(iobuf);
        return r;
    }

    if (!S_ISDIR(st.st_mode)) {
        free(iobuf);
        return ZCL_ERR(-1, "refusing unsupported root file type: %s", src);
    }

    r = copy_root_dir(src, dst, &st, flags, filter, fctx, iobuf);
    free(iobuf);
    return r;
}

static struct zcl_result remove_dir(DIR *d, int depth, const char *disp);

/* Remove one already-lstat'd entry without ever following a symlink. */
static struct zcl_result remove_entry(int dfd, const char *name,
                                      const struct stat *st, int depth,
                                      const char *disp)
{
    if (S_ISDIR(st->st_mode) && !S_ISLNK(st->st_mode)) {
        char child[PATH_MAX];
        int n = snprintf(child, sizeof(child), "%s/%s", disp, name);
        if (n <= 0 || (size_t)n >= sizeof(child))
            return ZCL_ERR(-1, "path too long under: %s", disp);

        int cfd = openat(dfd, name,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (cfd < 0) {
            if (errno == ENOENT)
                return ZCL_OK;
            return ZCL_ERR(-1, "open dir failed: %s: %s", child,
                           strerror(errno));
        }
        DIR *cd = fdopendir(cfd);
        if (!cd) {
            int e = errno;
            close(cfd);
            return ZCL_ERR(-1, "fdopendir failed: %s: %s", child,
                           strerror(e));
        }
        struct zcl_result r = remove_dir(cd, depth + 1, child);
        closedir(cd);   /* also closes cfd */
        if (!r.ok)
            return r;
        if (unlinkat(dfd, name, AT_REMOVEDIR) != 0 && errno != ENOENT)
            return ZCL_ERR(-1, "rmdir failed: %s: %s", child,
                           strerror(errno));
        return ZCL_OK;
    }

    if (unlinkat(dfd, name, 0) != 0 && errno != ENOENT)
        return ZCL_ERR(-1, "unlink failed: %s/%s: %s", disp, name,
                       strerror(errno));
    return ZCL_OK;
}

/* Empty and remove the directory whose open handle is `d`; `d` is closed by
 * the caller, the directory itself is rmdir'd by the caller. */
static struct zcl_result remove_dir(DIR *d, int depth, const char *disp)
{
    if (depth >= ZCL_TREE_MAX_DEPTH)
        return ZCL_ERR(-1, "max remove depth %d exceeded at: %s",
                       ZCL_TREE_MAX_DEPTH, disp);

    int dfd = dirfd(d);
    for (;;) {
        errno = 0;
        struct dirent *ent = readdir(d);
        if (!ent) {
            if (errno != 0)
                return ZCL_ERR(-1, "readdir failed: %s: %s", disp,
                               strerror(errno));
            break;
        }
        const char *name = ent->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
            continue;

        struct stat st;
        if (fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT)
                continue;
            return ZCL_ERR(-1, "stat failed: %s/%s: %s", disp, name,
                           strerror(errno));
        }

        /* A symlink is unlinked in place, never descended into. */
        struct zcl_result r = remove_entry(dfd, name, &st, depth, disp);
        if (!r.ok)
            return r;
    }
    return ZCL_OK;
}

struct zcl_result zcl_tree_remove(const char *path)
{
    if (!path)
        return ZCL_ERR(-1, "zcl_tree_remove: NULL path");

    struct stat st;
    if (fstatat(AT_FDCWD, path, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT)
            return ZCL_OK;   /* rm -rf: a missing path is success */
        return ZCL_ERR(-1, "stat failed: %s: %s", path, strerror(errno));
    }

    if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) {
        if (unlink(path) != 0 && errno != ENOENT)
            return ZCL_ERR(-1, "unlink failed: %s: %s", path, strerror(errno));
        return ZCL_OK;
    }

    int fd = openat(AT_FDCWD, path,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT)
            return ZCL_OK;
        return ZCL_ERR(-1, "open dir failed: %s: %s", path, strerror(errno));
    }
    DIR *d = fdopendir(fd);
    if (!d) {
        int e = errno;
        close(fd);
        return ZCL_ERR(-1, "fdopendir failed: %s: %s", path, strerror(e));
    }
    struct zcl_result r = remove_dir(d, 0, path);
    closedir(d);   /* also closes fd */
    if (!r.ok)
        return r;
    if (rmdir(path) != 0 && errno != ENOENT)
        return ZCL_ERR(-1, "rmdir failed: %s: %s", path, strerror(errno));
    return ZCL_OK;
}

struct zcl_result zcl_mkdir_p(const char *path, mode_t mode)
{
    if (!path || !*path)
        return ZCL_ERR(-1, "zcl_mkdir_p: empty path");

    char *copy = zcl_strdup(path, "mkdir_p.path");
    if (!copy)
        return ZCL_ERR(-1, "zcl_mkdir_p: strdup failed: %s", path);

    /* Create each intermediate component, tolerating an existing directory. */
    for (char *p = copy + (copy[0] == '/' ? 1 : 0); *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (copy[0] != '\0' && mkdir(copy, mode) != 0 && errno != EEXIST) {
            struct zcl_result r =
                ZCL_ERR(-1, "mkdir failed: %s: %s", copy, strerror(errno));
            free(copy);
            return r;
        }
        *p = '/';
    }
    if (mkdir(copy, mode) != 0 && errno != EEXIST) {
        struct zcl_result r =
            ZCL_ERR(-1, "mkdir failed: %s: %s", copy, strerror(errno));
        free(copy);
        return r;
    }
    free(copy);
    return ZCL_OK;
}

#endif
