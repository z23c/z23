/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Exact-descriptor SQLite I/O for the contained consensus-state
 * exporter; no pathname is ever accepted as database authority. */

#define _GNU_SOURCE

#include "consensus_state_snapshot_export_internal.h"
#include "platform/fd_path.h"
#include "platform/file_sync.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct output_sqlite_file {
    sqlite3_file base;
    int fd;
    int lock_level;
    bool readonly;
};

static int output_file_close(sqlite3_file *file)
{
    struct output_sqlite_file *out = (struct output_sqlite_file *)file;
    int rc = out->fd >= 0 && close(out->fd) != 0
        ? SQLITE_IOERR_CLOSE : SQLITE_OK;
    out->fd = -1;
    out->base.pMethods = NULL;
    return rc;
}

static int output_file_read(sqlite3_file *file, void *buffer, int amount,
                            sqlite3_int64 offset)
{
    struct output_sqlite_file *out = (struct output_sqlite_file *)file;
    unsigned char *cursor = buffer;
    int remaining = amount;
    while (remaining > 0) {
        ssize_t n = pread(out->fd, cursor, (size_t)remaining, (off_t)offset);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            return SQLITE_IOERR_READ;
        if (n == 0) {
            memset(cursor, 0, (size_t)remaining);
            return SQLITE_IOERR_SHORT_READ;
        }
        cursor += n;
        remaining -= (int)n;
        offset += n;
    }
    return SQLITE_OK;
}

static int output_file_write(sqlite3_file *file, const void *buffer,
                             int amount, sqlite3_int64 offset)
{
    struct output_sqlite_file *out = (struct output_sqlite_file *)file;
    if (out->readonly)
        return SQLITE_READONLY;
    const unsigned char *cursor = buffer;
    int remaining = amount;
    while (remaining > 0) {
        ssize_t n = pwrite(out->fd, cursor, (size_t)remaining, (off_t)offset);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return SQLITE_IOERR_WRITE;
        cursor += n;
        remaining -= (int)n;
        offset += n;
    }
    return SQLITE_OK;
}

static int output_file_truncate(sqlite3_file *file, sqlite3_int64 size)
{
    struct output_sqlite_file *out = (struct output_sqlite_file *)file;
    if (out->readonly)
        return SQLITE_READONLY;
    int rc;
    do {
        rc = ftruncate(out->fd, (off_t)size);
    } while (rc != 0 && errno == EINTR);
    return rc == 0 ? SQLITE_OK : SQLITE_IOERR_TRUNCATE;
}

static int output_file_sync(sqlite3_file *file, int flags)
{
    struct output_sqlite_file *out = (struct output_sqlite_file *)file;
    int rc;
    do {
        rc = (flags & SQLITE_SYNC_DATAONLY) != 0
            ? platform_data_sync(out->fd) : fsync(out->fd);
    } while (rc != 0 && errno == EINTR);
    return rc == 0 ? SQLITE_OK : SQLITE_IOERR_FSYNC;
}

static int output_file_size(sqlite3_file *file, sqlite3_int64 *size)
{
    struct output_sqlite_file *out = (struct output_sqlite_file *)file;
    struct stat st;
    if (fstat(out->fd, &st) != 0)
        return SQLITE_IOERR_FSTAT;
    *size = (sqlite3_int64)st.st_size;
    return SQLITE_OK;
}

static int output_file_lock(sqlite3_file *file, int level)
{
    struct output_sqlite_file *out = (struct output_sqlite_file *)file;
    if (level > out->lock_level)
        out->lock_level = level;
    return SQLITE_OK;
}

static int output_file_unlock(sqlite3_file *file, int level)
{
    struct output_sqlite_file *out = (struct output_sqlite_file *)file;
    out->lock_level = level;
    return SQLITE_OK;
}

static int output_file_reserved(sqlite3_file *file, int *reserved)
{
    struct output_sqlite_file *out = (struct output_sqlite_file *)file;
    *reserved = out->lock_level >= SQLITE_LOCK_RESERVED;
    return SQLITE_OK;
}

static int output_file_control(sqlite3_file *file, int operation, void *arg)
{
    struct output_sqlite_file *out = (struct output_sqlite_file *)file;
    switch (operation) {
    case SQLITE_FCNTL_LOCKSTATE:
        *(int *)arg = out->lock_level;
        return SQLITE_OK;
    case SQLITE_FCNTL_HAS_MOVED:
        *(int *)arg = 0;
        return SQLITE_OK;
    case SQLITE_FCNTL_VFSNAME:
        *(char **)arg = sqlite3_mprintf("zcl-output-fd");
        return *(char **)arg ? SQLITE_OK : SQLITE_NOMEM;
    case SQLITE_FCNTL_SIZE_HINT:
        return out->readonly ? SQLITE_READONLY : SQLITE_OK;
    default:
        return SQLITE_NOTFOUND;
    }
}

static int output_file_sector_size(sqlite3_file *file)
{
    (void)file;
    return 4096;
}

static int output_file_device_characteristics(sqlite3_file *file)
{
    (void)file;
    return 0;
}

static const sqlite3_io_methods g_output_file_methods = {
    .iVersion = 1,
    .xClose = output_file_close,
    .xRead = output_file_read,
    .xWrite = output_file_write,
    .xTruncate = output_file_truncate,
    .xSync = output_file_sync,
    .xFileSize = output_file_size,
    .xLock = output_file_lock,
    .xUnlock = output_file_unlock,
    .xCheckReservedLock = output_file_reserved,
    .xFileControl = output_file_control,
    .xSectorSize = output_file_sector_size,
    .xDeviceCharacteristics = output_file_device_characteristics,
};

int consensus_export_fd_file_size(void)
{
    return (int)sizeof(struct output_sqlite_file);
}

int consensus_export_fd_file_open(sqlite3_file *file, int retained_fd,
                                  int flags, int *out_flags)
{
    if (!file)
        return SQLITE_CANTOPEN;
    struct output_sqlite_file *out = (struct output_sqlite_file *)file;
    memset(out, 0, sizeof(*out));
    out->fd = -1;
    if (retained_fd < 0 || (flags & SQLITE_OPEN_MAIN_DB) == 0)
        return SQLITE_CANTOPEN;
    out->readonly = (flags & SQLITE_OPEN_READONLY) != 0;
    if (out->readonly) {
        char source[PATH_MAX];
        if (!platform_fd_path(source, sizeof(source), retained_fd, NULL))
            return SQLITE_CANTOPEN;
        out->fd = open(source, O_RDONLY | O_CLOEXEC);
    } else {
        out->fd = fcntl(retained_fd, F_DUPFD_CLOEXEC, 3);
    }
    if (out->fd < 0)
        return SQLITE_CANTOPEN;
    out->base.pMethods = &g_output_file_methods;
    if (out_flags)
        *out_flags = flags;
    return SQLITE_OK;
}
