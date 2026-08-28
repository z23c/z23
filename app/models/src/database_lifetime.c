/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: one process-wide ownership boundary for SQLite file lifetimes.
 * ar-validate-skip:sqlite-vfs-infrastructure-not-a-row */

#define _GNU_SOURCE
#include "models/database_lifetime.h"

#include "platform/path_compat.h"
#include "platform/time_compat.h"

#include <errno.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <execinfo.h>
#endif
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <sqlite3.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#include <unistd.h>

enum { DBLT_PATH_MAX = 1024, DBLT_OWNER_MAX = 80, DBLT_ENTRIES = 128 };

struct db_lifetime_entry {
    char path[DBLT_PATH_MAX];
    uint64_t generation;
    uint64_t last_sequence;
    unsigned main_refs;
    unsigned wal_refs;
    unsigned shm_refs;
    bool backing_owner_active;
};

struct db_lifetime_file {
    sqlite3_file base;
    max_align_t inner_alignment;
    sqlite3_file *inner;
    const sqlite3_io_methods *inner_methods;
    uint64_t handle_id;
    uint64_t generation;
    int flags;
    char path[DBLT_PATH_MAX];
    char owner[DBLT_OWNER_MAX];
};

static sqlite3_vfs g_lifetime_vfs;
static sqlite3_vfs *g_base_vfs;
static pthread_mutex_t g_registry_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct db_lifetime_entry g_entries[DBLT_ENTRIES];
static atomic_uint_fast64_t g_sequence;
static atomic_uint_fast64_t g_unauthorized;
static atomic_bool g_installed;
static atomic_bool g_installing;

static _Thread_local const char *g_scope_owner;
static _Thread_local enum db_lifetime_authority g_scope_authority;
static _Thread_local uint64_t g_scope_generation;

static int64_t lifetime_monotonic_us(void)
{
    return platform_time_monotonic_us();
}

static unsigned long long lifetime_tid(void)
{
#if defined(__APPLE__)
    uint64_t tid = 0;
    return pthread_threadid_np(NULL, &tid) == 0 ?
           (unsigned long long)tid : 0u;
#elif defined(__linux__)
    return (unsigned long long)syscall(SYS_gettid);
#elif defined(_WIN32)
    return (unsigned long long)GetCurrentThreadId();
#else
#error "lifetime_tid requires a native thread identifier"
#endif
}

static bool lifetime_trace_enabled(void)
{
    const char *value = getenv("ZCL_DB_LIFETIME_TRACE");
    return value && strcmp(value, "1") == 0;
}

static const char *lifetime_owner(void)
{
    return g_scope_owner && g_scope_owner[0] ? g_scope_owner : "unclaimed";
}

static const char *lifetime_authority_name(enum db_lifetime_authority authority)
{
    switch (authority) {
    case DB_LIFETIME_BACKING_OWNER: return "backing-owner";
    case DB_LIFETIME_HANDLE_OWNER: return "handle-owner";
    default: return "borrowed";
    }
}

static bool lifetime_node_db_path(const char *path)
{
    if (!path) return false;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    return strcmp(base, "node.db") == 0 ||
           strcmp(base, "node.db-wal") == 0 ||
           strcmp(base, "node.db-shm") == 0 ||
           strcmp(base, "node.db-journal") == 0;
}

static enum { DBLT_MAIN, DBLT_WAL, DBLT_SHM, DBLT_OTHER }
lifetime_kind_and_base(const char *path, char base[DBLT_PATH_MAX])
{
    char identity[DBLT_PATH_MAX];
    const char *source = path;
    if (path && platform_path_identity(identity, sizeof(identity), path))
        source = identity;
    size_t n = source ? strlen(source) : 0;
    if (n >= DBLT_PATH_MAX) n = DBLT_PATH_MAX - 1u;
    if (n) memcpy(base, source, n);
    base[n] = '\0';
    static const char wal[] = "-wal";
    static const char shm[] = "-shm";
    static const char journal[] = "-journal";
    if (n >= sizeof(wal) - 1u &&
        strcmp(base + n - (sizeof(wal) - 1u), wal) == 0) {
        base[n - (sizeof(wal) - 1u)] = '\0';
        return DBLT_WAL;
    }
    if (n >= sizeof(shm) - 1u &&
        strcmp(base + n - (sizeof(shm) - 1u), shm) == 0) {
        base[n - (sizeof(shm) - 1u)] = '\0';
        return DBLT_SHM;
    }
    if (n >= sizeof(journal) - 1u &&
        strcmp(base + n - (sizeof(journal) - 1u), journal) == 0) {
        base[n - (sizeof(journal) - 1u)] = '\0';
        return DBLT_OTHER;
    }
    return DBLT_MAIN;
}

static struct db_lifetime_entry *lifetime_entry_locked(const char *path,
                                                        bool create)
{
    struct db_lifetime_entry *free_entry = NULL;
    struct db_lifetime_entry *oldest = NULL;
    for (size_t i = 0; i < DBLT_ENTRIES; i++) {
        struct db_lifetime_entry *entry = &g_entries[i];
        if (entry->path[0] && strcmp(entry->path, path) == 0)
            return entry;
        if (!entry->path[0] && !free_entry)
            free_entry = entry;
        if (!entry->main_refs && !entry->wal_refs && !entry->shm_refs &&
            !entry->backing_owner_active &&
            (!oldest || entry->last_sequence < oldest->last_sequence))
            oldest = entry;
    }
    if (!create) return NULL;
    struct db_lifetime_entry *entry = free_entry ? free_entry : oldest;
    if (!entry) return NULL;
    memset(entry, 0, sizeof(*entry));
    (void)snprintf(entry->path, sizeof(entry->path), "%s", path);
    return entry;
}

static void lifetime_backtrace(char out[1024])
{
#if defined(_WIN32)
    snprintf(out, 1024, "%s", "unavailable-on-windows");
#else
    void *frames[12];
    int count = backtrace(frames, (int)(sizeof(frames) / sizeof(frames[0])));
    char **symbols = count > 0 ? backtrace_symbols(frames, count) : NULL;
    size_t used = 0;
    out[0] = '\0';
    for (int i = 2; symbols && i < count && used + 2u < 1024u; i++) {
        const char *symbol = symbols[i];
        size_t n = strlen(symbol);
        if (n > 180u) n = 180u;
        if (used) out[used++] = '|';
        if (n > 1023u - used) n = 1023u - used;
        memcpy(out + used, symbol, n);
        used += n;
        out[used] = '\0';
    }
    free(symbols);
#endif
}

static void lifetime_log(const char *event, const char *path,
                         uint64_t handle_id, uint64_t generation,
                         int flags, unsigned refs, bool unauthorized,
                         int rc)
{
    if (!lifetime_node_db_path(path))
        return;
    if (!lifetime_trace_enabled() && !unauthorized)
        return;
    char caller[1024];
    struct stat path_stat;
    bool path_present = path && stat(path, &path_stat) == 0;
    lifetime_backtrace(caller);
    fprintf(stderr,  // obs-ok:vfs-boundary-cannot-reenter-event-persistence
            "[db-lifetime] schema=zcl.db_lifetime.v1 event=%s "
            "mono_us=%lld pid=%ld tid=%llu sqlite_file=%llu generation=%llu "
            "owner=%s authority=%s path=%s path_present=%d "
            "path_dev=%llu path_ino=%llu flags=0x%x refs=%u "
            "unauthorized=%d rc=%d caller=%s\n",
            event ? event : "unknown", (long long)lifetime_monotonic_us(),
            (long)getpid(), lifetime_tid(),
            (unsigned long long)handle_id,
            (unsigned long long)generation, lifetime_owner(),
            lifetime_authority_name(g_scope_authority),
            path ? path : "(null)", path_present ? 1 : 0,
            path_present ? (unsigned long long)path_stat.st_dev : 0u,
            path_present ? (unsigned long long)path_stat.st_ino : 0u,
            flags, refs,
            unauthorized ? 1 : 0, rc, caller[0] ? caller : "unavailable");
    fflush(stderr);
}

static unsigned lifetime_open_record(struct db_lifetime_file *file)
{
    if (!lifetime_node_db_path(file->path)) return 0;
    char base[DBLT_PATH_MAX];
    int kind = lifetime_kind_and_base(file->path, base);
    unsigned refs = 0;
    pthread_mutex_lock(&g_registry_mutex);
    struct db_lifetime_entry *entry = lifetime_entry_locked(base, true);
    if (entry) {
        entry->last_sequence = file->handle_id;
        if (kind == DBLT_MAIN) {
            entry->main_refs++;
            if (g_scope_authority == DB_LIFETIME_BACKING_OWNER) {
                entry->generation = file->handle_id;
                entry->backing_owner_active = true;
                g_scope_generation = entry->generation;
            }
        } else if (kind == DBLT_WAL) {
            entry->wal_refs++;
        } else if (kind == DBLT_SHM) {
            entry->shm_refs++;
        }
        if (!g_scope_generation)
            g_scope_generation = entry->generation;
        file->generation = g_scope_generation
            ? g_scope_generation : entry->generation;
        refs = entry->main_refs + entry->wal_refs + entry->shm_refs;
    }
    pthread_mutex_unlock(&g_registry_mutex);
    return refs;
}

static unsigned lifetime_close_record(struct db_lifetime_file *file)
{
    if (!lifetime_node_db_path(file->path)) return 0;
    char base[DBLT_PATH_MAX];
    int kind = lifetime_kind_and_base(file->path, base);
    unsigned refs = 0;
    pthread_mutex_lock(&g_registry_mutex);
    struct db_lifetime_entry *entry = lifetime_entry_locked(base, false);
    if (entry) {
        if (kind == DBLT_MAIN && entry->main_refs) entry->main_refs--;
        else if (kind == DBLT_WAL && entry->wal_refs) entry->wal_refs--;
        else if (kind == DBLT_SHM && entry->shm_refs) entry->shm_refs--;
        if (kind == DBLT_MAIN &&
            file->generation == entry->generation &&
            strcmp(file->owner, "node_db.canonical") == 0)
            entry->backing_owner_active = false;
        refs = entry->main_refs + entry->wal_refs + entry->shm_refs;
    }
    pthread_mutex_unlock(&g_registry_mutex);
    return refs;
}

static bool lifetime_delete_unauthorized(const char *path,
                                         uint64_t *generation,
                                         unsigned *refs)
{
    *generation = 0;
    *refs = 0;
    if (!lifetime_node_db_path(path)) return false;
    char base[DBLT_PATH_MAX];
    int kind = lifetime_kind_and_base(path, base);
    if (kind != DBLT_WAL && kind != DBLT_SHM && kind != DBLT_MAIN)
        return false;
    bool unauthorized = false;
    pthread_mutex_lock(&g_registry_mutex);
    struct db_lifetime_entry *entry = lifetime_entry_locked(base, false);
    if (entry) {
        *generation = entry->generation;
        *refs = entry->main_refs + entry->wal_refs + entry->shm_refs;
        unauthorized = entry->backing_owner_active &&
            g_scope_authority != DB_LIFETIME_BACKING_OWNER;
    }
    pthread_mutex_unlock(&g_registry_mutex);
    return unauthorized;
}

/* SQLite's unix VFS performs some WAL/SHM retirement with direct unlink(2)
 * calls below xDelete (notably xShmUnmap).  Interpose the process filesystem
 * calls as the final ownership boundary so no raw SQLite caller or helper can
 * evade the same generation/refcount audit.  The syscall forms avoid calling
 * back through libc and therefore cannot recurse into these wrappers. */
#if !defined(_WIN32)
static int lifetime_os_remove(const char *event, int dirfd, const char *path,
                              int flags)
{
    uint64_t generation = 0;
    unsigned refs = 0;
    bool tracked = dirfd == AT_FDCWD && lifetime_node_db_path(path);
    bool unauthorized = tracked && lifetime_delete_unauthorized(
        path, &generation, &refs);
    int rc;
    if (unauthorized) {
        /* The canonical backing owner is still live. A borrowed/helper close
         * may release its own handle, but it cannot retire the shared path. */
        atomic_fetch_add(&g_unauthorized, 1);
        errno = EPERM;
        rc = -1;
    } else {
        rc = (int)syscall(SYS_unlinkat, dirfd, path, flags);
    }
    if (tracked)
        lifetime_log(unauthorized ? "os_unlink_refused" : event,
                     path, 0, generation, flags, refs, unauthorized,
                     rc == 0 ? SQLITE_OK : SQLITE_ERROR);
    return rc;
}

int unlink(const char *path)
{
    return lifetime_os_remove("os_unlink", AT_FDCWD, path, 0);
}

int unlinkat(int dirfd, const char *path, int flags)
{
    return lifetime_os_remove("os_unlinkat", dirfd, path, flags);
}

static int lifetime_os_rename(const char *event,
                              int olddirfd, const char *oldpath,
                              int newdirfd, const char *newpath)
{
    uint64_t generation = 0;
    unsigned refs = 0;
    bool tracked = olddirfd == AT_FDCWD && lifetime_node_db_path(oldpath);
    bool unauthorized = tracked && lifetime_delete_unauthorized(
        oldpath, &generation, &refs);
    int rc;
    if (unauthorized) {
        atomic_fetch_add(&g_unauthorized, 1);
        errno = EPERM;
        rc = -1;
    } else {
        rc = (int)syscall(SYS_renameat, olddirfd, oldpath, newdirfd, newpath);
    }
    if (tracked)
        lifetime_log(unauthorized ? "os_rename_refused" : event,
                     oldpath, 0, generation, 0, refs, unauthorized,
                     rc == 0 ? SQLITE_OK : SQLITE_ERROR);
    return rc;
}

int rename(const char *oldpath, const char *newpath)
{
    return lifetime_os_rename("os_rename", AT_FDCWD, oldpath,
                              AT_FDCWD, newpath);
}

int renameat(int olddirfd, const char *oldpath,
             int newdirfd, const char *newpath)
{
    return lifetime_os_rename("os_renameat", olddirfd, oldpath,
                              newdirfd, newpath);
}
#else
/* SQLite's Win32 VFS does not call the Unix unlink/rename symbols. Native
 * Windows lifecycle enforcement belongs in the Win32 VFS wrapper; package
 * and canonical runtime acceptance remain blocked until that hook is wired. */
#endif

static struct db_lifetime_file *lifetime_file(sqlite3_file *file)
{
    return (struct db_lifetime_file *)file;
}

static int lifetime_io_close(sqlite3_file *file)
{
    struct db_lifetime_file *tracked = lifetime_file(file);
    lifetime_log("close_begin", tracked->path, tracked->handle_id,
                 tracked->generation, tracked->flags, 0, false, SQLITE_OK);
    int rc = tracked->inner_methods->xClose(tracked->inner);
    unsigned refs = lifetime_close_record(tracked);
    lifetime_log("close", tracked->path, tracked->handle_id,
                 tracked->generation, tracked->flags, refs, false, rc);
    tracked->base.pMethods = NULL;
    return rc;
}

#define DBLT_DELEGATE(name, args, callargs) \
    static int lifetime_io_##name args { \
        struct db_lifetime_file *f = lifetime_file(file); \
        return f->inner_methods->x##name callargs; \
    }

DBLT_DELEGATE(Read,
    (sqlite3_file *file, void *buf, int amount, sqlite3_int64 offset),
    (f->inner, buf, amount, offset))
DBLT_DELEGATE(Write,
    (sqlite3_file *file, const void *buf, int amount, sqlite3_int64 offset),
    (f->inner, buf, amount, offset))
DBLT_DELEGATE(Sync, (sqlite3_file *file, int flags), (f->inner, flags))
DBLT_DELEGATE(FileSize,
    (sqlite3_file *file, sqlite3_int64 *size), (f->inner, size))
DBLT_DELEGATE(Lock, (sqlite3_file *file, int lock), (f->inner, lock))
DBLT_DELEGATE(Unlock, (sqlite3_file *file, int lock), (f->inner, lock))
DBLT_DELEGATE(CheckReservedLock,
    (sqlite3_file *file, int *reserved), (f->inner, reserved))
DBLT_DELEGATE(FileControl,
    (sqlite3_file *file, int op, void *arg), (f->inner, op, arg))

static int lifetime_io_truncate(sqlite3_file *file, sqlite3_int64 size)
{
    struct db_lifetime_file *tracked = lifetime_file(file);
    int rc = tracked->inner_methods->xTruncate(tracked->inner, size);
    if (lifetime_node_db_path(tracked->path) && size == 0)
        lifetime_log("truncate", tracked->path, tracked->handle_id,
                     tracked->generation, tracked->flags, 0, false, rc);
    return rc;
}

static int lifetime_io_sector_size(sqlite3_file *file)
{
    struct db_lifetime_file *f = lifetime_file(file);
    return f->inner_methods->xSectorSize(f->inner);
}

static int lifetime_io_device_characteristics(sqlite3_file *file)
{
    struct db_lifetime_file *f = lifetime_file(file);
    return f->inner_methods->xDeviceCharacteristics(f->inner);
}

static int lifetime_io_shm_map(sqlite3_file *file, int page, int size,
                               int extend, void volatile **out)
{
    struct db_lifetime_file *f = lifetime_file(file);
    return f->inner_methods->xShmMap
        ? f->inner_methods->xShmMap(f->inner, page, size, extend, out)
        : SQLITE_IOERR_SHMMAP;
}

static int lifetime_io_shm_lock(sqlite3_file *file, int offset, int n,
                                int flags)
{
    struct db_lifetime_file *f = lifetime_file(file);
    return f->inner_methods->xShmLock
        ? f->inner_methods->xShmLock(f->inner, offset, n, flags)
        : SQLITE_IOERR_SHMLOCK;
}

static void lifetime_io_shm_barrier(sqlite3_file *file)
{
    struct db_lifetime_file *f = lifetime_file(file);
    if (f->inner_methods->xShmBarrier)
        f->inner_methods->xShmBarrier(f->inner);
}

static int lifetime_io_shm_unmap(sqlite3_file *file, int delete_flag)
{
    struct db_lifetime_file *f = lifetime_file(file);
    char shm_path[DBLT_PATH_MAX];
    uint64_t generation = 0;
    unsigned refs = 0;
    int n = snprintf(shm_path, sizeof(shm_path), "%s-shm", f->path);
    bool refuse_delete = delete_flag && n > 0 &&
        (size_t)n < sizeof(shm_path) &&
        lifetime_delete_unauthorized(shm_path, &generation, &refs);
    if (refuse_delete) {
        atomic_fetch_add(&g_unauthorized, 1);
        lifetime_log("shm_delete_refused", shm_path, f->handle_id,
                     generation, delete_flag, refs, true, SQLITE_OK);
    }
    lifetime_log("shm_unmap_begin", shm_path, f->handle_id,
                 f->generation, delete_flag, refs, false, SQLITE_OK);
    int rc = f->inner_methods->xShmUnmap
        ? f->inner_methods->xShmUnmap(f->inner,
                                     refuse_delete ? 0 : delete_flag)
        : SQLITE_OK;
    lifetime_log("shm_unmap_end", shm_path, f->handle_id,
                 f->generation, delete_flag, refs, false, rc);
    return rc;
}

static int lifetime_io_fetch(sqlite3_file *file, sqlite3_int64 offset,
                             int amount, void **out)
{
    struct db_lifetime_file *f = lifetime_file(file);
    if (!f->inner_methods->xFetch) { *out = NULL; return SQLITE_OK; }
    return f->inner_methods->xFetch(f->inner, offset, amount, out);
}

static int lifetime_io_unfetch(sqlite3_file *file, sqlite3_int64 offset,
                               void *ptr)
{
    struct db_lifetime_file *f = lifetime_file(file);
    return f->inner_methods->xUnfetch
        ? f->inner_methods->xUnfetch(f->inner, offset, ptr) : SQLITE_OK;
}

static const sqlite3_io_methods g_lifetime_io = {
    .iVersion = 3,
    .xClose = lifetime_io_close,
    .xRead = lifetime_io_Read,
    .xWrite = lifetime_io_Write,
    .xTruncate = lifetime_io_truncate,
    .xSync = lifetime_io_Sync,
    .xFileSize = lifetime_io_FileSize,
    .xLock = lifetime_io_Lock,
    .xUnlock = lifetime_io_Unlock,
    .xCheckReservedLock = lifetime_io_CheckReservedLock,
    .xFileControl = lifetime_io_FileControl,
    .xSectorSize = lifetime_io_sector_size,
    .xDeviceCharacteristics = lifetime_io_device_characteristics,
    .xShmMap = lifetime_io_shm_map,
    .xShmLock = lifetime_io_shm_lock,
    .xShmBarrier = lifetime_io_shm_barrier,
    .xShmUnmap = lifetime_io_shm_unmap,
    .xFetch = lifetime_io_fetch,
    .xUnfetch = lifetime_io_unfetch,
};

static int lifetime_vfs_open(sqlite3_vfs *vfs, const char *name,
                             sqlite3_file *file, int flags, int *out_flags)
{
    (void)vfs;
    struct db_lifetime_file *tracked = (struct db_lifetime_file *)file;
    memset(tracked, 0, sizeof(*tracked));
    tracked->inner = (sqlite3_file *)((unsigned char *)file +
                                      sizeof(*tracked));
    memset(tracked->inner, 0, (size_t)g_base_vfs->szOsFile);
    int rc = g_base_vfs->xOpen(g_base_vfs, name, tracked->inner,
                               flags, out_flags);
    if (rc != SQLITE_OK)
        return rc;
    tracked->inner_methods = tracked->inner->pMethods;
    tracked->handle_id = atomic_fetch_add(&g_sequence, 1) + 1u;
    tracked->flags = out_flags ? *out_flags : flags;
    (void)snprintf(tracked->path, sizeof(tracked->path), "%s",
                   name ? name : "(temporary)");
    (void)snprintf(tracked->owner, sizeof(tracked->owner), "%s",
                   lifetime_owner());
    tracked->base.pMethods = &g_lifetime_io;
    unsigned refs = lifetime_open_record(tracked);
    lifetime_log("open", tracked->path, tracked->handle_id,
                 tracked->generation, tracked->flags, refs, false, rc);
    return SQLITE_OK;
}

static int lifetime_vfs_delete(sqlite3_vfs *vfs, const char *name,
                               int sync_dir)
{
    (void)vfs;
    uint64_t generation = 0;
    unsigned refs = 0;
    bool unauthorized = lifetime_delete_unauthorized(name, &generation, &refs);
    if (unauthorized) atomic_fetch_add(&g_unauthorized, 1);
    int rc = unauthorized ? SQLITE_IOERR_DELETE
                          : g_base_vfs->xDelete(g_base_vfs, name, sync_dir);
    if (lifetime_node_db_path(name))
        lifetime_log(unauthorized ? "delete_refused" : "delete",
                     name, 0, generation, 0, refs, unauthorized, rc);
    return rc;
}

static int lifetime_vfs_access(sqlite3_vfs *vfs, const char *name, int flags,
                               int *result)
{
    (void)vfs;
    return g_base_vfs->xAccess(g_base_vfs, name, flags, result);
}

static int lifetime_vfs_full_pathname(sqlite3_vfs *vfs, const char *name,
                                      int size, char *out)
{
    (void)vfs;
    return g_base_vfs->xFullPathname(g_base_vfs, name, size, out);
}

#define DBLT_VFS_FORWARD(ret, name, args, callargs, fallback) \
    static ret lifetime_vfs_##name args { \
        (void)vfs; \
        return g_base_vfs->x##name \
            ? g_base_vfs->x##name callargs : (fallback); \
    }

DBLT_VFS_FORWARD(void *, DlOpen,
    (sqlite3_vfs *vfs, const char *name), (g_base_vfs, name), NULL)
static void lifetime_vfs_dl_error(sqlite3_vfs *vfs, int size, char *message)
{
    (void)vfs;
    if (g_base_vfs->xDlError) g_base_vfs->xDlError(g_base_vfs, size, message);
    else if (size > 0) message[0] = '\0';
}
static void (*lifetime_vfs_dl_sym(sqlite3_vfs *vfs, void *handle,
                                  const char *symbol))(void)
{
    (void)vfs;
    return g_base_vfs->xDlSym
        ? g_base_vfs->xDlSym(g_base_vfs, handle, symbol) : NULL;
}
static void lifetime_vfs_dl_close(sqlite3_vfs *vfs, void *handle)
{
    (void)vfs;
    if (g_base_vfs->xDlClose) g_base_vfs->xDlClose(g_base_vfs, handle);
}
DBLT_VFS_FORWARD(int, Randomness,
    (sqlite3_vfs *vfs, int size, char *out), (g_base_vfs, size, out), 0)
DBLT_VFS_FORWARD(int, Sleep,
    (sqlite3_vfs *vfs, int us), (g_base_vfs, us), 0)
DBLT_VFS_FORWARD(int, CurrentTime,
    (sqlite3_vfs *vfs, double *out), (g_base_vfs, out), SQLITE_ERROR)
DBLT_VFS_FORWARD(int, GetLastError,
    (sqlite3_vfs *vfs, int size, char *out), (g_base_vfs, size, out), 0)
DBLT_VFS_FORWARD(int, CurrentTimeInt64,
    (sqlite3_vfs *vfs, sqlite3_int64 *out), (g_base_vfs, out), SQLITE_ERROR)
DBLT_VFS_FORWARD(int, SetSystemCall,
    (sqlite3_vfs *vfs, const char *name, sqlite3_syscall_ptr call),
    (g_base_vfs, name, call), SQLITE_NOTFOUND)
DBLT_VFS_FORWARD(sqlite3_syscall_ptr, GetSystemCall,
    (sqlite3_vfs *vfs, const char *name), (g_base_vfs, name), NULL)
DBLT_VFS_FORWARD(const char *, NextSystemCall,
    (sqlite3_vfs *vfs, const char *name), (g_base_vfs, name), NULL)

bool db_lifetime_install(void)
{
    if (atomic_load(&g_installed)) return true;
    bool expected = false;
    if (!atomic_compare_exchange_strong(&g_installing, &expected, true)) {
        while (atomic_load(&g_installing) && !atomic_load(&g_installed))
            sched_yield();
        return atomic_load(&g_installed);
    }
    g_base_vfs = sqlite3_vfs_find(NULL);
    bool ok = g_base_vfs != NULL;
    if (ok) {
        g_lifetime_vfs = (sqlite3_vfs) {
            .iVersion = g_base_vfs->iVersion > 3 ? 3 : g_base_vfs->iVersion,
            .szOsFile = (int)(sizeof(struct db_lifetime_file) +
                             (size_t)g_base_vfs->szOsFile),
            .mxPathname = g_base_vfs->mxPathname,
            .zName = "zcl-db-lifetime-v1",
            .xOpen = lifetime_vfs_open,
            .xDelete = lifetime_vfs_delete,
            .xAccess = lifetime_vfs_access,
            .xFullPathname = lifetime_vfs_full_pathname,
            .xDlOpen = lifetime_vfs_DlOpen,
            .xDlError = lifetime_vfs_dl_error,
            .xDlSym = lifetime_vfs_dl_sym,
            .xDlClose = lifetime_vfs_dl_close,
            .xRandomness = lifetime_vfs_Randomness,
            .xSleep = lifetime_vfs_Sleep,
            .xCurrentTime = lifetime_vfs_CurrentTime,
            .xGetLastError = lifetime_vfs_GetLastError,
            .xCurrentTimeInt64 = lifetime_vfs_CurrentTimeInt64,
            .xSetSystemCall = lifetime_vfs_SetSystemCall,
            .xGetSystemCall = lifetime_vfs_GetSystemCall,
            .xNextSystemCall = lifetime_vfs_NextSystemCall,
        };
        ok = sqlite3_vfs_register(&g_lifetime_vfs, 1) == SQLITE_OK;
    }
    atomic_store(&g_installed, ok);
    atomic_store(&g_installing, false);
    return ok;
}

void db_lifetime_scope_enter(struct db_lifetime_scope *scope,
                             const char *owner,
                             enum db_lifetime_authority authority,
                             uint64_t generation)
{
    if (!scope) return;
    scope->previous_owner = g_scope_owner;
    scope->previous_authority = g_scope_authority;
    scope->previous_generation = g_scope_generation;
    g_scope_owner = owner;
    g_scope_authority = authority;
    g_scope_generation = generation;
}

void db_lifetime_scope_leave(struct db_lifetime_scope *scope)
{
    if (!scope) return;
    g_scope_owner = scope->previous_owner;
    g_scope_authority = scope->previous_authority;
    g_scope_generation = scope->previous_generation;
}

uint64_t db_lifetime_scope_generation(void)
{
    return g_scope_generation;
}

uint64_t db_lifetime_unauthorized_count(void)
{
    return atomic_load(&g_unauthorized);
}

static int lifetime_explicit_fs(const char *event, const char *from,
                                const char *to, const char *owner,
                                enum db_lifetime_authority authority,
                                uint64_t generation, bool rename_op)
{
    struct db_lifetime_scope scope;
    db_lifetime_scope_enter(&scope, owner, authority, generation);
    uint64_t current_generation = 0;
    unsigned refs = 0;
    bool unauthorized = lifetime_delete_unauthorized(
        from, &current_generation, &refs);
    int rc = rename_op ? rename(from, to) : unlink(from);
    lifetime_log(event, from, 0,
                 current_generation ? current_generation : generation,
                 0, refs, unauthorized, rc == 0 ? SQLITE_OK : SQLITE_ERROR);
    db_lifetime_scope_leave(&scope);
    return rc;
}

int db_lifetime_rename(const char *from, const char *to, const char *owner,
                       enum db_lifetime_authority authority,
                       uint64_t generation)
{
    return lifetime_explicit_fs("rename", from, to, owner, authority,
                                generation, true);
}

int db_lifetime_unlink(const char *path, const char *owner,
                       enum db_lifetime_authority authority,
                       uint64_t generation)
{
    return lifetime_explicit_fs("unlink", path, NULL, owner, authority,
                                generation, false);
}
