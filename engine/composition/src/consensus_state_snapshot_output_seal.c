/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Retire writable anonymous-output descriptors and hash the exact
 * immutable inode used by consensus bundle/candidate publication. */

#define _GNU_SOURCE

#include "consensus_state_snapshot_export_internal.h"

#include "crypto/sha3.h"

#include <stdio.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#endif

#if defined(_WIN32)

bool consensus_export_descriptor_digest(int fd, uint8_t out[32])
{
    (void)fd;
    (void)out;
    /* Native export is disabled until immutable output generations and the
     * Windows sandbox are qualified. A descriptor alone cannot prove those
     * publication properties, so validation fails closed too. */
    return false;
}

bool consensus_export_seal_readonly(
    struct consensus_export_output_binding *output, struct stat *sealed)
{
    (void)output;
    (void)sealed;
    /* Do not close, chmod, duplicate, hash, or otherwise mutate caller state. */
    return false;
}

#else

/* True when the directory entry names an open descriptor other than
 * readonly_fd that has write access to the exact inode in identity. */
static bool fd_entry_is_writable_alias(const char *name, int readonly_fd,
                                       const struct stat *identity)
{
    char *end = NULL;
    errno = 0;
    long candidate = strtol(name, &end, 10);
    if (errno != 0 || !end || *end != '\0' || candidate < 0 ||
        candidate > INT_MAX || candidate == readonly_fd)
        return false;
    struct stat st;
    int flags = fcntl((int)candidate, F_GETFL);
    return flags >= 0 && (flags & O_ACCMODE) != O_RDONLY &&
        fstat((int)candidate, &st) == 0 &&
        st.st_dev == identity->st_dev && st.st_ino == identity->st_ino;
}

/* An O_TMPFILE is private by name, but a callback or another in-process
 * subsystem could retain a duplicate of its original O_RDWR descriptor.
 * chmod(0400) does not revoke that already-open authority.  Refuse the seal
 * unless the new read-only descriptor is the only remaining reference in
 * this process with write access to the exact inode. */
static bool descriptor_has_writable_alias(int readonly_fd,
                                          const struct stat *identity)
{
    DIR *dir = opendir("/proc/self/fd");
    if (!dir)
        return true;
    bool found = false;
    struct dirent *entry;
    while (!found && (entry = readdir(dir)) != NULL)
        found = fd_entry_is_writable_alias(entry->d_name, readonly_fd,
                                           identity);
    if (closedir(dir) != 0)
        found = true;
    return found;
}

/* Same inode, size, and modification/change times. */
static bool export_stat_same_snapshot(const struct stat *a,
                                      const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_size == b->st_size &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
        a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

/* Hash [0, size) of fd into ctx; false on short read or error. */
static bool export_hash_descriptor_range(int fd, off_t size,
                                         struct sha3_256_ctx *ctx)
{
    uint8_t buffer[64u * 1024u];
    off_t offset = 0;
    while (offset < size) {
        size_t want = sizeof(buffer);
        off_t left = size - offset;
        if (left < (off_t)want)
            want = (size_t)left;
        ssize_t got = pread(fd, buffer, want, offset);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            return false;
        sha3_256_write(ctx, buffer, (size_t)got);
        offset += got;
    }
    return true;
}

bool consensus_export_descriptor_digest(int fd, uint8_t out[32])
{
    struct stat before;
    if (fd < 0 || !out || fstat(fd, &before) != 0 ||
        !S_ISREG(before.st_mode) || before.st_size <= 0)
        return false;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    if (!export_hash_descriptor_range(fd, before.st_size, &ctx))
        return false;
    sha3_256_finalize(&ctx, out);
    struct stat after;
    return fstat(fd, &after) == 0 && export_stat_same_snapshot(&before, &after);
}

/* The writable temp descriptor must still be the unlinked, read-only-mode
 * regular file the output binding recorded. Fills before. */
static bool export_seal_source_valid(
    const struct consensus_export_output_binding *output, struct stat *before)
{
    int access = fcntl(output->temp_fd, F_GETFL);
    return access >= 0 && (access & O_ACCMODE) == O_RDWR &&
        fstat(output->temp_fd, before) == 0 && S_ISREG(before->st_mode) &&
        before->st_dev == output->temp_dev &&
        before->st_ino == output->temp_ino && before->st_nlink == 0 &&
        (before->st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) == 0;
}

/* readonly_fd must be a read-only descriptor for exactly the inode in before. */
static bool export_readonly_reopen_exact(int readonly_fd,
                                         const struct stat *before)
{
    struct stat reopened;
    int readonly_access = readonly_fd >= 0 ? fcntl(readonly_fd, F_GETFL) : -1;
    return readonly_fd >= 0 && readonly_access >= 0 &&
        (readonly_access & O_ACCMODE) == O_RDONLY &&
        fstat(readonly_fd, &reopened) == 0 && S_ISREG(reopened.st_mode) &&
        reopened.st_nlink == 0 && reopened.st_mode == before->st_mode &&
        export_stat_same_snapshot(&reopened, before);
}

/* The sealed stat must match the pre-seal inode and have no writable alias. */
static bool export_sealed_stat_refused(int readonly_fd,
                                       const struct stat *before,
                                       const struct stat *sealed)
{
    return sealed->st_nlink != 0 || sealed->st_mode != before->st_mode ||
        !export_stat_same_snapshot(sealed, before) ||
        descriptor_has_writable_alias(readonly_fd, sealed);
}

bool consensus_export_seal_readonly(
    struct consensus_export_output_binding *output, struct stat *sealed)
{
    if (!output || output->temp_fd < 0 || !sealed)
        return false;
    int writable_fd = output->temp_fd;
    struct stat before;
    if (!export_seal_source_valid(output, &before))
        return false;
    char path[64];
    int n = snprintf(path, sizeof(path), "/proc/self/fd/%d", writable_fd);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    int readonly_fd = open(path, O_RDONLY | O_CLOEXEC);
    bool exact = export_readonly_reopen_exact(readonly_fd, &before);
    output->temp_fd = -1;
    if (close(writable_fd) != 0)
        exact = false;
    if (!exact) {
        if (readonly_fd >= 0)
            (void)close(readonly_fd);
        return false;
    }
    output->temp_fd = readonly_fd;
    if (fstat(readonly_fd, sealed) != 0 ||
        export_sealed_stat_refused(readonly_fd, &before, sealed)) {
        (void)close(readonly_fd);
        output->temp_fd = -1;
        return false;
    }
    return true;
}

#endif
