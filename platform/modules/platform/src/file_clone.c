/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: descriptor-bound copy-on-write cloning. Linux fills the existing
 * destination inode with FICLONE and never reopens a path. Darwin has no
 * FICLONE into an existing inode; APFS clonefile creates a new inode, the
 * destination path is replaced with that clone, and the caller's descriptor
 * number is retargeted onto it. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "platform/file_clone.h"

#if defined(__linux__)
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

static enum platform_file_clone_result clone_refused(const char *reason,
                                                      int error)
{
    fprintf(stderr, /* obs-ok:platform-primitive */
            "[platform] file_clone_fd: %s errno=%d\n", reason, error);
    return PLATFORM_FILE_CLONE_REFUSED;
}

static bool clone_unavailable(int error)
{
    return error == EOPNOTSUPP || error == ENOTTY || error == EXDEV ||
           error == EINVAL || error == EPERM || error == EACCES ||
           error == ENOSYS || error == EBADF;
}

static bool same_file(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

/* Returns the inspection refusal reason and its error code, or NULL. */
static const char *descriptor_inspection_refusal(int source_fd,
                                                 int destination_fd,
                                                 struct stat *source,
                                                 struct stat *destination,
                                                 int *error)
{
    if (source_fd < 0 || destination_fd < 0) {
        *error = 0;
        return "invalid descriptor";
    }
    if (fstat(source_fd, source) != 0 ||
        fstat(destination_fd, destination) != 0) {
        *error = errno;
        return "descriptor inspection failed";
    }
    return NULL;
}

/* Returns which pre-clone rule refuses the request, or NULL if none. */
static const char *clone_request_refusal(int source_flags,
                                         int destination_flags,
                                         const struct stat *source,
                                         const struct stat *destination)
{
#if defined(O_PATH)
    if ((source_flags & O_PATH) != 0 || (destination_flags & O_PATH) != 0)
        return "O_PATH descriptor refused";
#endif
    if ((source_flags & O_ACCMODE) == O_WRONLY ||
        (destination_flags & O_ACCMODE) == O_RDONLY ||
        (destination_flags & O_APPEND) != 0)
        return "descriptor access mode refused";
    if (!S_ISREG(source->st_mode) ||
        !S_ISREG(destination->st_mode) ||
        destination->st_size != 0 ||
        destination->st_nlink > 1 ||
        same_file(source, destination))
        return "descriptor shape refused";
    return NULL;
}

/* Re-stats both descriptors after the clone; true when both calls succeed. */
static bool restat_cloned_descriptors(int source_fd, int destination_fd,
                                      struct stat *source,
                                      struct stat *destination)
{
    return fstat(source_fd, source) == 0 &&
           fstat(destination_fd, destination) == 0;
}

/* True when the cloned files fail the post-clone shape rules. */
static bool cloned_shape_refused(const struct stat *source,
                                 const struct stat *destination)
{
    return !S_ISREG(source->st_mode) ||
           !S_ISREG(destination->st_mode) ||
           destination->st_nlink > 1 ||
           same_file(source, destination) ||
           source->st_size != destination->st_size;
}

enum platform_file_clone_result platform_file_clone_fd(int source_fd,
                                                        int destination_fd)
{
    struct stat source_before, destination_before;
    int inspection_error = 0;
    const char *inspection_refusal = descriptor_inspection_refusal(
        source_fd, destination_fd, &source_before, &destination_before,
        &inspection_error);
    if (inspection_refusal != NULL)
        return clone_refused(inspection_refusal, inspection_error);
    int source_flags = fcntl(source_fd, F_GETFL);
    if (source_flags < 0)
        return clone_refused("source descriptor flags unavailable", errno);
    int destination_flags = fcntl(destination_fd, F_GETFL);
    if (destination_flags < 0)
        return clone_refused("destination descriptor flags unavailable",
                             errno);
    const char *request_refusal = clone_request_refusal(
        source_flags, destination_flags, &source_before, &destination_before);
    if (request_refusal != NULL)
        return clone_refused(request_refusal, 0);

    if (ioctl(destination_fd, FICLONE, source_fd) != 0) {
        int error = errno;
        struct stat destination_after;
        if (fstat(destination_fd, &destination_after) != 0)
            return clone_refused("destination reinspection failed", errno);
        if (destination_after.st_size != 0)
            return clone_refused("failed clone changed destination", error);
        if (clone_unavailable(error))
            return PLATFORM_FILE_CLONE_UNAVAILABLE;
        return clone_refused("clone I/O failed", error);
    }

    struct stat source_after, destination_after;
    if (!restat_cloned_descriptors(source_fd, destination_fd, &source_after,
                                   &destination_after))
        return clone_refused("cloned file inspection failed", errno);
    if (cloned_shape_refused(&source_after, &destination_after))
        return clone_refused("cloned file shape refused", 0);
    return PLATFORM_FILE_CLONE_CLONED;
}
#elif defined(__APPLE__)
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/clonefile.h>
#include <sys/stat.h>
#include <sys/stdio.h>
#include <sys/xattr.h>
#include <unistd.h>

struct apple_clone_req {
    struct stat source;
    struct stat destination;
    off_t source_off;
    off_t destination_off;
    int dest_fd_flags;
    int open_flags;
    char dir[PATH_MAX];
    char base[256];
};

static enum platform_file_clone_result apple_refused(const char *reason,
                                                      int error)
{
    fprintf(stderr, /* obs-ok:platform-primitive */
            "[platform] file_clone_fd: %s errno=%d\n", reason, error);
    return PLATFORM_FILE_CLONE_REFUSED;
}

static bool apple_unsupported_dev(int error)
{
    return error == ENOTSUP || error == EOPNOTSUPP || error == EXDEV ||
           error == EINVAL || error == EPERM || error == EACCES ||
           error == ENOSYS || error == EBADF;
}

static bool apple_unsupported_name(int error)
{
    return error == ENOENT || error == EEXIST || error == ENOTDIR ||
           error == EMLINK || error == EBUSY || error == EMFILE ||
           error == ENFILE || error == ENAMETOOLONG || error == EAGAIN;
}

static bool apple_unsupported(int error)
{
    return apple_unsupported_dev(error) || apple_unsupported_name(error);
}

static bool apple_mode_refused(int source_flags, int destination_flags)
{
    return (source_flags & O_ACCMODE) == O_WRONLY ||
           (destination_flags & O_ACCMODE) == O_RDONLY ||
           (destination_flags & O_APPEND) != 0;
}

static bool apple_shape_refused(const struct stat *source,
                                const struct stat *destination)
{
    return !S_ISREG(source->st_mode) || !S_ISREG(destination->st_mode) ||
           destination->st_size != 0 || destination->st_nlink > 1 ||
           (source->st_dev == destination->st_dev &&
            source->st_ino == destination->st_ino);
}

static bool apple_split(const char *full, char *dir, char *base)
{
    const char *slash = strrchr(full, '/');
    size_t dlen, blen;
    if (!slash || slash == full) return false;
    dlen = (size_t)(slash - full);
    blen = strlen(slash + 1);
    if (dlen == 0 || dlen >= PATH_MAX || blen == 0 || blen >= 256)
        return false;
    memcpy(dir, full, dlen);
    dir[dlen] = '\0';
    memcpy(base, slash + 1, blen + 1);
    return true;
}

static int apple_open_flags(int destination_flags)
{
    if ((destination_flags & O_ACCMODE) == O_WRONLY)
        return O_WRONLY | O_CLOEXEC | O_NOFOLLOW;
    return O_RDWR | O_CLOEXEC | O_NOFOLLOW;
}

static bool apple_prepare(int source_fd, int destination_fd,
                          struct apple_clone_req *req,
                          enum platform_file_clone_result *failure)
{
    int source_flags, destination_flags;
    char path[PATH_MAX];
    if (source_fd < 0 || destination_fd < 0) {
        *failure = apple_refused("invalid descriptor", 0);
        return false;
    }
    if (fstat(source_fd, &req->source) != 0 ||
        fstat(destination_fd, &req->destination) != 0) {
        *failure = apple_refused("descriptor inspection failed", errno);
        return false;
    }
    source_flags = fcntl(source_fd, F_GETFL);
    destination_flags = fcntl(destination_fd, F_GETFL);
    if (source_flags < 0 || destination_flags < 0) {
        *failure = apple_refused("descriptor flags unavailable", errno);
        return false;
    }
    if (apple_mode_refused(source_flags, destination_flags) ||
        apple_shape_refused(&req->source, &req->destination)) {
        *failure = apple_refused("descriptor shape refused", 0);
        return false;
    }
    req->source_off = lseek(source_fd, 0, SEEK_CUR);
    req->destination_off = lseek(destination_fd, 0, SEEK_CUR);
    req->dest_fd_flags = fcntl(destination_fd, F_GETFD);
    if (req->source_off < 0 || req->destination_off < 0 ||
        req->dest_fd_flags < 0) {
        *failure = apple_refused("descriptor offset unavailable", errno);
        return false;
    }
    if (fcntl(destination_fd, F_GETPATH, path) != 0 ||
        !apple_split(path, req->dir, req->base)) {
        *failure = PLATFORM_FILE_CLONE_UNAVAILABLE;
        return false;
    }
    req->open_flags = apple_open_flags(destination_flags);
    return true;
}

/* 0700 directory in dirfd. The clone stays here until its mode is the
 * destination's, so the source mode is never reachable from the parent. */
static bool apple_private_dir(int dirfd, char *name)
{
    char templ[] = ".z23d.XXXXXX";
    if (mkdtempat_np(dirfd, templ) == NULL) return false;
    memcpy(name, templ, sizeof templ);
    return true;
}

static int apple_clear_xattr(int fd)
{
    char names[4096];
    ssize_t n, at;
    n = flistxattr(fd, names, sizeof names, 0);
    if (n < 0) return errno == ENOTSUP ? 0 : -1;
    at = 0;
    while (at < n) {
        if (fremovexattr(fd, names + at, 0) != 0) return -1;
        at += (ssize_t)strlen(names + at) + 1;
    }
    return 0;
}

static int apple_clear_acl(int fd)
{
    acl_t acl, empty;
    int rc;
    acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    if (acl == NULL) return errno == ENOENT ? 0 : -1;
    acl_free(acl);
    empty = acl_init(0);
    if (empty == NULL) return -1;
    rc = acl_set_fd_np(fd, empty, ACL_TYPE_EXTENDED);
    acl_free(empty);
    return rc;
}

/* Copy the destination's attributes onto the clone. A value that does not
 * fit, or a name that cannot be set, declines the clone. */
static int apple_copy_xattr(int from, int to)
{
    char names[4096];
    char value[8192];
    ssize_t n, at, vlen;
    if (apple_clear_xattr(to) != 0) return -1;
    n = flistxattr(from, names, sizeof names, 0);
    if (n < 0) return errno == ENOTSUP ? 0 : -1;
    at = 0;
    while (at < n) {
        vlen = fgetxattr(from, names + at, value, sizeof value, 0, 0);
        if (vlen < 0 || fsetxattr(to, names + at, value, (size_t)vlen, 0, 0) != 0)
            return -1;
        at += (ssize_t)strlen(names + at) + 1;
    }
    return 0;
}

static int apple_copy_acl(int from, int to)
{
    acl_t acl;
    int rc;
    acl = acl_get_fd_np(from, ACL_TYPE_EXTENDED);
    if (acl == NULL) return errno == ENOENT ? apple_clear_acl(to) : -1;
    rc = acl_set_fd_np(to, acl, ACL_TYPE_EXTENDED);
    acl_free(acl);
    return rc;
}

/* Mode, flags, and access-control metadata of the destination, not the source. */
static int apple_match_dest(int clone, int dest_fd, const struct stat *dest)
{
    if (fchown(clone, dest->st_uid, dest->st_gid) != 0) {
        errno = ENOTSUP;
        return -1;
    }
    if (fchmod(clone, dest->st_mode & 07777) != 0) return -1;
    if (fchflags(clone, dest->st_flags) != 0 && dest->st_flags != 0) return -1;
    if (apple_copy_xattr(dest_fd, clone) != 0 || apple_copy_acl(dest_fd, clone) != 0) {
        errno = ENOTSUP;
        return -1;
    }
    return 0;
}

static void apple_drop_private(int dirfd, const char *priv, int clone)
{
    int privfd;
    if (clone >= 0) close(clone);
    if (dirfd < 0 || priv == NULL || priv[0] == '\0') return;
    privfd = openat(dirfd, priv, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (privfd >= 0) {
        (void)unlinkat(privfd, "c", 0);
        close(privfd);
    }
    (void)unlinkat(dirfd, priv, AT_REMOVEDIR);
}

static int apple_name_is_original(int dirfd, const char *name,
                                const struct stat *before)
{
    struct stat now;
    if (fstatat(dirfd, name, &now, AT_SYMLINK_NOFOLLOW) != 0) return 0;
    if (now.st_dev != before->st_dev || now.st_ino != before->st_ino) return 0;
    if (now.st_size != 0 || !S_ISREG(now.st_mode)) return 0;
    return 1;
}

static int apple_path_is(int dirfd, const char *base, dev_t dev, ino_t ino)
{
    struct stat now;
    if (fstatat(dirfd, base, &now, AT_SYMLINK_NOFOLLOW) != 0) return 0;
    return now.st_dev == dev && now.st_ino == ino && S_ISREG(now.st_mode);
}

/* Swap back only while the published name is still the clone we created.
 * A newer replacement at that name is left untouched. */
static int apple_restore_displaced(int dirfd, int privfd, const char *base,
                                  dev_t clone_dev, ino_t clone_ino)
{
    if (!apple_path_is(dirfd, base, clone_dev, clone_ino)) return -2;
    if (renameatx_np(privfd, "c", dirfd, base, RENAME_SWAP) != 0) return -2;
    return 0;
}

/* 0 published. -1 names unchanged. -2 a displaced name could not be restored. */
static int apple_publish_swap(int dirfd, int privfd, const char *base,
                             const struct stat *before, dev_t clone_dev,
                             ino_t clone_ino)
{
    if (!apple_name_is_original(dirfd, base, before)) {
        errno = EEXIST;
        return -1;
    }
    if (renameatx_np(privfd, "c", dirfd, base, RENAME_SWAP) != 0) return -1;
    if (!apple_name_is_original(privfd, "c", before)) {
        if (apple_restore_displaced(dirfd, privfd, base, clone_dev, clone_ino) != 0)
            return -2;
        errno = EEXIST;
        return -1;
    }
    if (unlinkat(privfd, "c", 0) != 0) {
        int error = errno;
        if (apple_restore_displaced(dirfd, privfd, base, clone_dev, clone_ino) != 0)
            return -2;
        errno = error;
        return -1;
    }
    return 0;
}

static int apple_hidden_clone(int source_fd, int dest_fd, int dirfd, char *priv,
                             int *privfd, int open_flags, const struct stat *dest,
                             off_t source_size, struct stat *cloned)
{
    int clone;
    *privfd = -1;
    priv[0] = '\0';
    if (!apple_private_dir(dirfd, priv)) return -1;
    *privfd = openat(dirfd, priv, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (*privfd < 0) return -1;
    if (fclonefileat(source_fd, *privfd, "c",
                     CLONE_NOFOLLOW | CLONE_NOOWNERCOPY) != 0)
        return -1;
    clone = openat(*privfd, "c", open_flags);
    if (clone < 0) return -1;
    if (apple_match_dest(clone, dest_fd, dest) != 0 || fstat(clone, cloned) != 0 ||
        !S_ISREG(cloned->st_mode) || cloned->st_size != source_size ||
        cloned->st_ino == dest->st_ino) {
        close(clone);
        return -1;
    }
    return clone;
}

static enum platform_file_clone_result apple_unchanged(
    int destination_fd, const struct stat *before, int error)
{
    struct stat now;
    if (fstat(destination_fd, &now) != 0)
        return apple_refused("destination reinspection failed", errno);
    if (now.st_ino != before->st_ino || now.st_size != before->st_size)
        return apple_refused("failed clone changed destination", error);
    if (apple_unsupported(error)) return PLATFORM_FILE_CLONE_UNAVAILABLE;
    return apple_refused("clone I/O failed", error);
}

static enum platform_file_clone_result apple_publish(
    int source_fd, int destination_fd, struct apple_clone_req *req)
{
    char priv[256];
    int dirfd, privfd = -1, clone, swapped, error;
    struct stat cloned;
    dirfd = open(req->dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0)
        return apple_unchanged(destination_fd, &req->destination, errno);
    clone = apple_hidden_clone(source_fd, destination_fd, dirfd, priv, &privfd,
                              req->open_flags, &req->destination,
                              req->source.st_size, &cloned);
    if (clone < 0) {
        error = errno;
        if (privfd >= 0) close(privfd);
        apple_drop_private(dirfd, priv, -1);
        close(dirfd);
        return apple_unchanged(destination_fd, &req->destination, error);
    }
    swapped = apple_publish_swap(dirfd, privfd, req->base, &req->destination,
                                cloned.st_dev, cloned.st_ino);
    error = errno;
    close(privfd);
    if (swapped != 0) {
        if (swapped == -1) apple_drop_private(dirfd, priv, clone);
        else close(clone);
        close(dirfd);
        if (swapped == -2)
            return apple_refused("destination changed during clone", error);
        return apple_unchanged(destination_fd, &req->destination, error);
    }
    (void)unlinkat(dirfd, priv, AT_REMOVEDIR);
    if (dup2(clone, destination_fd) < 0) {
        error = errno;
        close(clone);
        close(dirfd);
        return apple_refused("destination descriptor replace failed", error);
    }
    close(clone);
    close(dirfd);
    if ((req->dest_fd_flags & FD_CLOEXEC) != 0)
        (void)fcntl(destination_fd, F_SETFD, FD_CLOEXEC);
    if (lseek(source_fd, req->source_off, SEEK_SET) < 0 ||
        lseek(destination_fd, req->destination_off, SEEK_SET) < 0)
        return apple_refused("descriptor offset restore failed", errno);
    return PLATFORM_FILE_CLONE_CLONED;
}

enum platform_file_clone_result platform_file_clone_fd(int source_fd,
                                                        int destination_fd)
{
    struct apple_clone_req req;
    enum platform_file_clone_result failure = PLATFORM_FILE_CLONE_REFUSED;
    if (!apple_prepare(source_fd, destination_fd, &req, &failure))
        return failure;
    return apple_publish(source_fd, destination_fd, &req);
}
#else
enum platform_file_clone_result platform_file_clone_fd(int source_fd,
                                                        int destination_fd)
{
    (void)source_fd;
    (void)destination_fd;
    return PLATFORM_FILE_CLONE_UNAVAILABLE;
}
#endif
