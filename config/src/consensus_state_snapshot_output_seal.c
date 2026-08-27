/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Seal and hash the exact immutable staging inode used by consensus
 * bundle/candidate publication: retire the writable descriptor where the
 * platform can (Linux anonymous O_TMPFILE), and everywhere re-verify the
 * pinned inode identity through the reopened descriptor. */

#define _GNU_SOURCE

#include "consensus_state_snapshot_export_internal.h"

#include "crypto/sha3.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

/* fd-naming root for the descriptor scan: /proc/self/fd on Linux, /dev/fd on
 * Darwin (see platform/fd_path.h). */
static const char *descriptor_fd_root(void)
{
#if defined(__APPLE__)
    return "/dev/fd";
#else
    return "/proc/self/fd";
#endif
}

/* A sealed staging inode must have no other in-process descriptor with write
 * authority: a callback or another subsystem could retain a duplicate of the
 * original O_RDWR descriptor, and chmod(0400) does not revoke already-open
 * authority. Refuse the seal unless every remaining descriptor for the exact
 * inode other than `readonly_fd` is read-only. On Darwin the retained
 * descriptor itself keeps O_RDWR access (the /dev/fd/N reopen is a dup and
 * cannot downgrade the access mode) — the weaker recorded property of the
 * named-staging design — so this scan is the only in-process write-alias
 * proof either platform has. */
static bool descriptor_has_writable_alias(int readonly_fd,
                                          const struct stat *identity)
{
    DIR *dir = opendir(descriptor_fd_root());
    if (!dir)
        return true;
    bool found = false;
    struct dirent *entry;
    while (!found && (entry = readdir(dir)) != NULL) {
        char *end = NULL;
        errno = 0;
        long candidate = strtol(entry->d_name, &end, 10);
        if (errno != 0 || !end || *end != '\0' || candidate < 0 ||
            candidate > INT_MAX || candidate == readonly_fd)
            continue;
        struct stat st;
        int flags = fcntl((int)candidate, F_GETFL);
        if (flags >= 0 && (flags & O_ACCMODE) != O_RDONLY &&
            fstat((int)candidate, &st) == 0 &&
            st.st_dev == identity->st_dev && st.st_ino == identity->st_ino)
            found = true;
    }
    if (closedir(dir) != 0)
        found = true;
    return found;
}

bool consensus_export_descriptor_digest(int fd, uint8_t out[32])
{
    struct stat before;
    if (fd < 0 || !out || fstat(fd, &before) != 0 ||
        !S_ISREG(before.st_mode) || before.st_size <= 0)
        return false;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    uint8_t buffer[64u * 1024u];
    off_t offset = 0;
    while (offset < before.st_size) {
        size_t want = sizeof(buffer);
        off_t left = before.st_size - offset;
        if (left < (off_t)want)
            want = (size_t)left;
        ssize_t got = pread(fd, buffer, want, offset);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            return false;
        sha3_256_write(&ctx, buffer, (size_t)got);
        offset += got;
    }
    sha3_256_finalize(&ctx, out);
    struct stat after;
    return fstat(fd, &after) == 0 && before.st_dev == after.st_dev &&
        before.st_ino == after.st_ino && before.st_size == after.st_size &&
        before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
        before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
        before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
        before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}

bool consensus_export_seal_readonly(
    struct consensus_export_output_binding *output, struct stat *sealed)
{
    if (!output || output->temp_fd < 0 || !sealed)
        return false;
    int writable_fd = output->temp_fd;
    struct stat before;
    int access = fcntl(writable_fd, F_GETFL);
    if (access < 0 || (access & O_ACCMODE) != O_RDWR ||
        fstat(writable_fd, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_dev != output->temp_dev || before.st_ino != output->temp_ino ||
        !consensus_export_staging_nlink_valid(output, before.st_nlink) ||
        (before.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) != 0)
        return false;
    /* Reopen the staged inode through the platform fd-naming shim and require
     * the full identity (dev/ino/size/mtimes/ctimes) to survive: this is the
     * reopen the installer will later replay, and on Darwin it also proves the
     * staging name still resolves to the pinned inode. Linux asserts the
     * reopened descriptor is O_RDONLY (retiring the last writable one); the
     * Darwin /dev/fd/N reopen is a dup that cannot downgrade O_RDWR, so there
     * the seal only swaps descriptors and records the retained access. */
    char path[64];
    int n = snprintf(path, sizeof(path), "%s/%d", descriptor_fd_root(),
                     writable_fd);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    int readonly_fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat reopened;
    int readonly_access = readonly_fd >= 0 ? fcntl(readonly_fd, F_GETFL) : -1;
    bool exact = readonly_fd >= 0 && readonly_access >= 0 &&
#if !defined(__APPLE__)
        (readonly_access & O_ACCMODE) == O_RDONLY &&
#endif
        fstat(readonly_fd, &reopened) == 0 && S_ISREG(reopened.st_mode) &&
        reopened.st_dev == before.st_dev && reopened.st_ino == before.st_ino &&
        consensus_export_staging_nlink_valid(output, reopened.st_nlink) &&
        reopened.st_size == before.st_size &&
        reopened.st_mode == before.st_mode &&
        reopened.st_mtim.tv_sec == before.st_mtim.tv_sec &&
        reopened.st_mtim.tv_nsec == before.st_mtim.tv_nsec &&
        reopened.st_ctim.tv_sec == before.st_ctim.tv_sec &&
        reopened.st_ctim.tv_nsec == before.st_ctim.tv_nsec;
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
        sealed->st_dev != before.st_dev || sealed->st_ino != before.st_ino ||
        !consensus_export_staging_nlink_valid(output, sealed->st_nlink) ||
        sealed->st_size != before.st_size ||
        sealed->st_mode != before.st_mode ||
        sealed->st_mtim.tv_sec != before.st_mtim.tv_sec ||
        sealed->st_mtim.tv_nsec != before.st_mtim.tv_nsec ||
        sealed->st_ctim.tv_sec != before.st_ctim.tv_sec ||
        sealed->st_ctim.tv_nsec != before.st_ctim.tv_nsec ||
        descriptor_has_writable_alias(readonly_fd, sealed)) {
        (void)close(readonly_fd);
        output->temp_fd = -1;
        return false;
    }
    return true;
}
