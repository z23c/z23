/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Quiet block-file read-mapping helper for node_db catchup. */

#include "node_db_catchup_internal.h"

#include "services/node_db_catchup_service.h"
#include "util/log_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

void node_db_catchup_block_mapping_init(
    struct node_db_catchup_block_mapping *block_mapping)
{
    if (!block_mapping) return;
    platform_read_mapping_init(&block_mapping->mapping);
    block_mapping->fd = -1;
}

void node_db_catchup_block_mapping_close(
    struct node_db_catchup_block_mapping *block_mapping)
{
    if (!block_mapping) return;
    /* read_mapping keeps the descriptor alive as part of its contract. */
    platform_read_mapping_close(&block_mapping->mapping);
    if (block_mapping->fd >= 0) {
#if defined(_WIN32)
        (void)_close(block_mapping->fd);
#else
        (void)close(block_mapping->fd);
#endif
    }
    node_db_catchup_block_mapping_init(block_mapping);
}

static int catchup_open_readonly_binary(const char *path)
{
#if defined(_WIN32)
    if (!path) {
        errno = EINVAL;
        return -1;
    }
    int wide_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path,
                                       -1, NULL, 0);
    if (wide_len <= 0 || wide_len > 32768) {
        errno = EINVAL;
        return -1;
    }
    wchar_t *wide = malloc((size_t)wide_len * sizeof(*wide));
    if (!wide) {
        errno = ENOMEM;
        return -1;
    }
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                            wide, wide_len) != wide_len) {
        free(wide);
        errno = EINVAL;
        return -1;
    }
    int fd = _wopen(wide, _O_RDONLY | _O_BINARY | _O_NOINHERIT);
    free(wide);
    return fd;
#else
    return open(path, O_RDONLY | O_CLOEXEC);
#endif
}

bool node_db_catchup_block_mapping_open_quiet(
    struct node_db_catchup_block_mapping *block_mapping,
    const char *datadir, int file_num, int *out_errno)
{
    if (out_errno) *out_errno = 0;
    if (!block_mapping || !datadir || file_num < 0) {
        if (out_errno) *out_errno = EINVAL;
        return false;
    }
    node_db_catchup_block_mapping_close(block_mapping);

    char path[512];
    int path_len = snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat",
                            datadir, file_num);
    if (path_len < 0 || (size_t)path_len >= sizeof(path)) {
        if (out_errno) *out_errno = ENAMETOOLONG;
        return false;
    }
    int fd = catchup_open_readonly_binary(path);
    if (fd < 0) {
        if (out_errno) *out_errno = errno;
        return false;
    }

#if defined(_WIN32)
    struct _stati64 fst;
    int stat_result = _fstati64(fd, &fst);
#else
    struct stat fst;
    int stat_result = fstat(fd, &fst);
#endif
    if (stat_result != 0) {
        int e = errno;
#if defined(_WIN32)
        (void)_close(fd);
#else
        (void)close(fd);
#endif
        if (out_errno) *out_errno = e;
        LOG_WARN("sync", "catchup mapping: fstat failed for %s", path);
        return false;
    }
    if (fst.st_size <= 0 || (uintmax_t)fst.st_size > SIZE_MAX) {
#if defined(_WIN32)
        (void)_close(fd);
#else
        (void)close(fd);
#endif
        if (out_errno) *out_errno = EINVAL;
        return false;
    }

    block_mapping->fd = fd;
    if (!platform_read_mapping_open(&block_mapping->mapping, fd,
                                    (size_t)fst.st_size)) {
        int e = errno ? errno : EIO;
        node_db_catchup_block_mapping_close(block_mapping);
        if (out_errno) *out_errno = errno;
        LOG_WARN("sync", "catchup mapping: map failed for file %d", file_num);
        if (out_errno) *out_errno = e;
        return false;
    }
    platform_read_mapping_advise_sequential(&block_mapping->mapping);
    return true;
}
