/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Descriptor-pinned SQLite VFS for the contained consensus-state
 * exporter. Every database I/O goes through the retained staging descriptor —
 * no pathname is ever accepted as database authority — and the strict close
 * proves a handle is fully retired before the seal is trusted. Split from
 * consensus_state_snapshot_export.c along the file-size ceiling seam. */

#include "consensus_state_snapshot_export_internal.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static sqlite3_vfs *output_vfs_base(sqlite3_vfs *vfs)
{
    struct consensus_export_output_binding *output = vfs->pAppData;
    return output ? output->base_vfs : NULL;
}

static int output_vfs_open(sqlite3_vfs *vfs, const char *name,
                           sqlite3_file *file, int flags, int *out_flags)
{
    (void)name;
    struct consensus_export_output_binding *output = vfs->pAppData;
    return consensus_export_fd_file_open(
        file, output ? output->temp_fd : -1, flags, out_flags);
}

static int output_vfs_delete(sqlite3_vfs *vfs, const char *name,
                             int sync_dir)
{
    (void)vfs;
    (void)name;
    (void)sync_dir;
    return SQLITE_IOERR_DELETE;
}

static int output_vfs_access(sqlite3_vfs *vfs, const char *name, int flags,
                             int *result)
{
    (void)vfs;
    (void)flags;
    *result = name && strcmp(name, "zcl-export-main") == 0;
    return SQLITE_OK;
}

static int output_vfs_full_pathname(sqlite3_vfs *vfs, const char *name,
                                    int size, char *out)
{
    (void)vfs;
    if (!name || !out || size <= 0 || strlen(name) >= (size_t)size)
        return SQLITE_CANTOPEN;
    memcpy(out, name, strlen(name) + 1);
    return SQLITE_OK;
}

static void *output_vfs_dl_open(sqlite3_vfs *vfs, const char *name)
{
    sqlite3_vfs *base = output_vfs_base(vfs);
    return base && base->xDlOpen ? base->xDlOpen(base, name) : NULL;
}

static void output_vfs_dl_error(sqlite3_vfs *vfs, int size, char *message)
{
    sqlite3_vfs *base = output_vfs_base(vfs);
    if (base && base->xDlError)
        base->xDlError(base, size, message);
    else if (size > 0)
        message[0] = '\0';
}

static void (*output_vfs_dl_sym(sqlite3_vfs *vfs, void *handle,
                                const char *symbol))(void)
{
    sqlite3_vfs *base = output_vfs_base(vfs);
    return base && base->xDlSym ? base->xDlSym(base, handle, symbol) : NULL;
}

static void output_vfs_dl_close(sqlite3_vfs *vfs, void *handle)
{
    sqlite3_vfs *base = output_vfs_base(vfs);
    if (base && base->xDlClose)
        base->xDlClose(base, handle);
}

static int output_vfs_randomness(sqlite3_vfs *vfs, int size, char *out)
{
    sqlite3_vfs *base = output_vfs_base(vfs);
    return base->xRandomness(base, size, out);
}

static int output_vfs_sleep(sqlite3_vfs *vfs, int microseconds)
{
    sqlite3_vfs *base = output_vfs_base(vfs);
    return base->xSleep(base, microseconds);
}

static int output_vfs_current_time(sqlite3_vfs *vfs, double *time_out)
{
    sqlite3_vfs *base = output_vfs_base(vfs);
    return base->xCurrentTime(base, time_out);
}

static int output_vfs_last_error(sqlite3_vfs *vfs, int size, char *message)
{
    sqlite3_vfs *base = output_vfs_base(vfs);
    return base && base->xGetLastError
        ? base->xGetLastError(base, size, message) : 0;
}

static int output_vfs_current_time_i64(sqlite3_vfs *vfs,
                                       sqlite3_int64 *time_out)
{
    sqlite3_vfs *base = output_vfs_base(vfs);
    return base && base->iVersion >= 2 && base->xCurrentTimeInt64
        ? base->xCurrentTimeInt64(base, time_out) : SQLITE_ERROR;
}

static int output_vfs_set_system_call(sqlite3_vfs *vfs, const char *name,
                                      sqlite3_syscall_ptr call)
{
    sqlite3_vfs *base = output_vfs_base(vfs);
    return base && base->iVersion >= 3 && base->xSetSystemCall
        ? base->xSetSystemCall(base, name, call) : SQLITE_NOTFOUND;
}

static sqlite3_syscall_ptr output_vfs_get_system_call(sqlite3_vfs *vfs,
                                                      const char *name)
{
    sqlite3_vfs *base = output_vfs_base(vfs);
    return base && base->iVersion >= 3 && base->xGetSystemCall
        ? base->xGetSystemCall(base, name) : NULL;
}

static const char *output_vfs_next_system_call(sqlite3_vfs *vfs,
                                               const char *name)
{
    sqlite3_vfs *base = output_vfs_base(vfs);
    return base && base->iVersion >= 3 && base->xNextSystemCall
        ? base->xNextSystemCall(base, name) : NULL;
}

bool consensus_export_output_vfs_register(
    struct consensus_export_output_binding *output)
{
    static atomic_uint_fast64_t sequence = 0;
    output->base_vfs = sqlite3_vfs_find(NULL);
    if (!output->base_vfs)
        return false;
    uint64_t nonce = atomic_fetch_add(&sequence, 1) + 1;
    int n = snprintf(output->vfs_name, sizeof(output->vfs_name),
                     "zcl_export_fd_%ld_%llu", (long)getpid(),
                     (unsigned long long)nonce);
    if (n <= 0 || (size_t)n >= sizeof(output->vfs_name))
        return false;
    output->vfs = (sqlite3_vfs) {
        .iVersion = output->base_vfs->iVersion > 3
            ? 3 : output->base_vfs->iVersion,
        .szOsFile = consensus_export_fd_file_size(),
        .mxPathname = output->base_vfs->mxPathname,
        .zName = output->vfs_name,
        .pAppData = output,
        .xOpen = output_vfs_open,
        .xDelete = output_vfs_delete,
        .xAccess = output_vfs_access,
        .xFullPathname = output_vfs_full_pathname,
        .xDlOpen = output_vfs_dl_open,
        .xDlError = output_vfs_dl_error,
        .xDlSym = output_vfs_dl_sym,
        .xDlClose = output_vfs_dl_close,
        .xRandomness = output_vfs_randomness,
        .xSleep = output_vfs_sleep,
        .xCurrentTime = output_vfs_current_time,
        .xGetLastError = output_vfs_last_error,
        .xCurrentTimeInt64 = output_vfs_current_time_i64,
        .xSetSystemCall = output_vfs_set_system_call,
        .xGetSystemCall = output_vfs_get_system_call,
        .xNextSystemCall = output_vfs_next_system_call,
    };
    if (sqlite3_vfs_register(&output->vfs, 0) != SQLITE_OK)
        return false;
    output->vfs_registered = true;
    return true;
}

bool consensus_export_output_sqlite_close_strict(
    struct consensus_export_output_binding *output, sqlite3 **db)
{
    if (!db || !*db)
        return true;
    bool clean = true;
    sqlite3_stmt *stmt;
    while ((stmt = sqlite3_next_stmt(*db, NULL)) != NULL) {
        if (sqlite3_finalize(stmt) != SQLITE_OK)
            clean = false;
    }
    int rc = sqlite3_close(*db);
    if (rc != SQLITE_OK) {
        /* The VFS and pAppData are stack-external only while the binding is
         * retained. The caller intentionally leaks a heap binding on this
         * impossible-to-prove-close path rather than unregistering live
         * callbacks or manufacturing success. */
        if (output)
            output->abandon_on_close = true;
        return false;
    }
    *db = NULL;
    return clean;
}
