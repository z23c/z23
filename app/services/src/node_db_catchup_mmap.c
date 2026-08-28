/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Quiet block-file read-mapping helper for node_db catchup. */

#include "node_db_catchup_internal.h"

#include "services/node_db_catchup_service.h"
#include "base/result.h"
#include "base/safe_alloc.h"
#include "util/log_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

/* The descriptor close is the only place this file needs the CRT/POSIX split,
 * so it lives here once instead of at each of its call sites. */
static void catchup_close_descriptor(int fd)
{
    if (fd < 0) return;
#if defined(_WIN32)
    (void)_close(fd);
#else
    (void)close(fd);
#endif
}

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
    catchup_close_descriptor(block_mapping->fd);
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
    wchar_t *wide = zcl_malloc((size_t)wide_len * sizeof(*wide),
                               "node_db_catchup_wide_path");
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

/* Quiet: a blk file that is simply absent is a normal outcome of the catchup
 * walk, not an incident. The refusal therefore travels as a zcl_result whose
 * `code` is the exact errno, so the caller can tell "this file was never
 * written" (ENOENT/ENOTDIR) from a real I/O problem, and the reason is carried
 * with the failure instead of being reduced to a bare false. */
struct zcl_result node_db_catchup_block_mapping_open_quiet(
    struct node_db_catchup_block_mapping *block_mapping,
    const char *datadir, int file_num)
{
    if (!block_mapping || !datadir || file_num < 0)
        return ZCL_ERR(EINVAL,
                       "catchup mapping: bad arguments (mapping=%p datadir=%p "
                       "file_num=%d)",
                       (const void *)block_mapping, (const void *)datadir,
                       file_num);
    node_db_catchup_block_mapping_close(block_mapping);

    char path[512];
    int path_len = snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat",
                            datadir, file_num);
    if (path_len < 0 || (size_t)path_len >= sizeof(path))
        return ZCL_ERR(ENAMETOOLONG,
                       "catchup mapping: path for blk%05d.dat does not fit in "
                       "%zu bytes", file_num, sizeof(path));
    int fd = catchup_open_readonly_binary(path);
    if (fd < 0)
        return ZCL_ERR(errno ? errno : EIO, "catchup mapping: open %s failed",
                       path);

#if defined(_WIN32)
    struct _stati64 fst;
    int stat_result = _fstati64(fd, &fst);
#else
    struct stat fst;
    int stat_result = fstat(fd, &fst);
#endif
    if (stat_result != 0) {
        int e = errno ? errno : EIO;
        catchup_close_descriptor(fd);
        LOG_WARN("sync", "catchup mapping: fstat failed for %s", path);
        return ZCL_ERR(e, "catchup mapping: fstat failed for %s", path);
    }
    if (fst.st_size <= 0 || (uintmax_t)fst.st_size > SIZE_MAX) {
        catchup_close_descriptor(fd);
        return ZCL_ERR(EINVAL, "catchup mapping: %s has unmappable size %jd",
                       path, (intmax_t)fst.st_size);
    }

    block_mapping->fd = fd;
    if (!platform_read_mapping_open(&block_mapping->mapping, fd,
                                    (size_t)fst.st_size)) {
        int e = errno ? errno : EIO;
        node_db_catchup_block_mapping_close(block_mapping);
        LOG_WARN("sync", "catchup mapping: map failed for file %d", file_num);
        return ZCL_ERR(e, "catchup mapping: map failed for %s", path);
    }
    platform_read_mapping_advise_sequential(&block_mapping->mapping);
    return ZCL_OK;
}
