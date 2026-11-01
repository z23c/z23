/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sync-recording SQLite VFS wrapper; see test/test_sync_probe_vfs.h. */

#include "test/test_sync_probe_vfs.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <string.h>

#define SPV_EVENT_CAP 4096

struct spv_file {
    sqlite3_file base;
    sqlite3_file *real;
    bool wal;
    bool main_db;
};

static sqlite3_vfs g_spv_vfs;
static sqlite3_vfs *g_spv_real;
static atomic_int g_spv_events;
static atomic_int g_spv_log[SPV_EVENT_CAP];
static atomic_bool g_spv_fail;
static const sqlite3_io_methods g_spv_io;

#define SPV_REAL(f) (((struct spv_file *)(f))->real)

static void spv_record(enum spv_kind kind)
{
    int at = atomic_fetch_add(&g_spv_events, 1);
    if (at < SPV_EVENT_CAP)
        atomic_store(&g_spv_log[at], (int)kind);
}

static int spv_close(sqlite3_file *f)
{
    return SPV_REAL(f)->pMethods->xClose(SPV_REAL(f));
}
static int spv_read(sqlite3_file *f, void *p, int n, sqlite3_int64 o)
{
    return SPV_REAL(f)->pMethods->xRead(SPV_REAL(f), p, n, o);
}
static int spv_write(sqlite3_file *f, const void *p, int n, sqlite3_int64 o)
{
    return SPV_REAL(f)->pMethods->xWrite(SPV_REAL(f), p, n, o);
}
static int spv_truncate(sqlite3_file *f, sqlite3_int64 s)
{
    if (((struct spv_file *)f)->wal)
        spv_record(SPV_TRUNC_WAL);
    return SPV_REAL(f)->pMethods->xTruncate(SPV_REAL(f), s);
}
static int spv_sync(sqlite3_file *f, int flags)
{
    struct spv_file *w = (struct spv_file *)f;
    if (w->wal) {
        if (atomic_load(&g_spv_fail))
            return SQLITE_IOERR_FSYNC;
        spv_record(SPV_SYNC_WAL);
    } else if (w->main_db) {
        spv_record(SPV_SYNC_DB);
    }
    return SPV_REAL(f)->pMethods->xSync(SPV_REAL(f), flags);
}
static int spv_size(sqlite3_file *f, sqlite3_int64 *s)
{
    return SPV_REAL(f)->pMethods->xFileSize(SPV_REAL(f), s);
}
static int spv_lock(sqlite3_file *f, int l)
{
    return SPV_REAL(f)->pMethods->xLock(SPV_REAL(f), l);
}
static int spv_unlock(sqlite3_file *f, int l)
{
    return SPV_REAL(f)->pMethods->xUnlock(SPV_REAL(f), l);
}
static int spv_reserved(sqlite3_file *f, int *r)
{
    return SPV_REAL(f)->pMethods->xCheckReservedLock(SPV_REAL(f), r);
}
static int spv_control(sqlite3_file *f, int op, void *a)
{
    return SPV_REAL(f)->pMethods->xFileControl(SPV_REAL(f), op, a);
}
static int spv_sector(sqlite3_file *f)
{
    return SPV_REAL(f)->pMethods->xSectorSize(SPV_REAL(f));
}
static int spv_device(sqlite3_file *f)
{
    return SPV_REAL(f)->pMethods->xDeviceCharacteristics(SPV_REAL(f));
}
static int spv_shm_map(sqlite3_file *f, int pg, int sz, int ext,
                       void volatile **pp)
{
    return SPV_REAL(f)->pMethods->xShmMap(SPV_REAL(f), pg, sz, ext, pp);
}
static int spv_shm_lock(sqlite3_file *f, int off, int n, int flags)
{
    return SPV_REAL(f)->pMethods->xShmLock(SPV_REAL(f), off, n, flags);
}
static void spv_shm_barrier(sqlite3_file *f)
{
    SPV_REAL(f)->pMethods->xShmBarrier(SPV_REAL(f));
}
static int spv_shm_unmap(sqlite3_file *f, int del)
{
    return SPV_REAL(f)->pMethods->xShmUnmap(SPV_REAL(f), del);
}

static const sqlite3_io_methods g_spv_io = {
    2, spv_close, spv_read, spv_write, spv_truncate, spv_sync, spv_size,
    spv_lock, spv_unlock, spv_reserved, spv_control, spv_sector, spv_device,
    spv_shm_map, spv_shm_lock, spv_shm_barrier, spv_shm_unmap, NULL, NULL,
};

static int spv_open(sqlite3_vfs *v, const char *name, sqlite3_file *f,
                    int flags, int *out_flags)
{
    (void)v;
    struct spv_file *w = (struct spv_file *)f;
    w->base.pMethods = NULL;
    w->real = (sqlite3_file *)(w + 1);
    w->wal = (flags & SQLITE_OPEN_WAL) != 0;
    w->main_db = (flags & SQLITE_OPEN_MAIN_DB) != 0;
    int rc = g_spv_real->xOpen(g_spv_real, name, w->real, flags, out_flags);
    if (rc == SQLITE_OK)
        w->base.pMethods = &g_spv_io;
    return rc;
}

bool spv_install(void)
{
    g_spv_real = sqlite3_vfs_find(NULL);
    if (!g_spv_real)
        return false;
    g_spv_vfs = *g_spv_real;
    g_spv_vfs.zName = "test_sync_probe";
    g_spv_vfs.szOsFile = (int)sizeof(struct spv_file) + g_spv_real->szOsFile;
    g_spv_vfs.xOpen = spv_open;
    g_spv_vfs.pNext = NULL;
    spv_reset();
    atomic_store(&g_spv_fail, false);
    return sqlite3_vfs_register(&g_spv_vfs, 1) == SQLITE_OK;
}

void spv_uninstall(void)
{
    atomic_store(&g_spv_fail, false);
    (void)sqlite3_vfs_unregister(&g_spv_vfs);
}

void spv_reset(void)
{
    atomic_store(&g_spv_events, 0);
}

int spv_count(enum spv_kind kind)
{
    int n = atomic_load(&g_spv_events);
    if (n > SPV_EVENT_CAP)
        n = SPV_EVENT_CAP;
    int count = 0;
    for (int i = 0; i < n; i++)
        if (atomic_load(&g_spv_log[i]) == (int)kind)
            count++;
    return count;
}

int spv_first(enum spv_kind kind)
{
    int n = atomic_load(&g_spv_events);
    if (n > SPV_EVENT_CAP)
        n = SPV_EVENT_CAP;
    for (int i = 0; i < n; i++)
        if (atomic_load(&g_spv_log[i]) == (int)kind)
            return i;
    return -1;
}

void spv_fail_wal_sync(bool on)
{
    atomic_store(&g_spv_fail, on);
}
