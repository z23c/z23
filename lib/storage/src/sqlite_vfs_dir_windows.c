/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: implementation of storage/sqlite_vfs_dir.h — a retained-directory
 * SQLite VFS for native Windows. Every namespace operation (xOpen, xDelete,
 * xAccess, xFullPathname) is capability-bound to the validated, owner-private
 * directory HANDLE carried in the binding's pAppData: leaf names are
 * validated and allowlisted to the bound database basename, the sibling
 * suffixes SQLite actually requests (-wal, -shm, -journal, -mjXXXXXXXXX), and
 * a VFS-minted nameless temporary file, then resolved relative to the retained
 * handle via NtCreateFile with FILE_OPEN_REPARSE_POINT (the child_open idiom
 * of lib/platform/src/directory_transaction.c), with post-open refusal of
 * directories and reparse points and an owner-private ACL check. Renaming or
 * replacing the directory path after registration cannot redirect I/O.
 *
 * The sqlite3_file methods are a full read/write implementation over the
 * HANDLE: positioned I/O through OVERLAPPED on synchronous handles, and the
 * PENDING/SHARED/RESERVED/EXCLUSIVE byte-range lock protocol plus the
 * shared-memory WAL-index (xShm*) semantics mirrored from the vendored
 * os_win.c (vendor/sqlite3.c), which is what WAL mode with a concurrent
 * independent reader requires. os_win.c behavior is mirrored deliberately
 * where SQLite core depends on it (lock byte offsets, zero-length xAccess
 * EXISTS reporting, DELETE_NOENT, IOERR_SHORT_READ zero-fill, DMS
 * dead-man-switch truncate-and-downgrade); deliberate divergences are
 * commented at the site.
 *
 * Compiles to an empty translation unit off Windows. */

#include "storage/sqlite_vfs_dir.h"

#if defined(_WIN32)

#include "sqlite_vfs_dir_windows_internal.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>

#include "../../platform/src/private_acl_internal.h" /* bind the source-local
                                                       * private platform header
                                                       * without a broad src
                                                       * include path */

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

/* ── Lock layout, identical to os_win.c (vendor/sqlite3.c) ─────────────── */
#define VFS_DIR_PENDING_BYTE  0x40000000u
#define VFS_DIR_RESERVED_BYTE (VFS_DIR_PENDING_BYTE + 1u)
#define VFS_DIR_SHARED_FIRST  (VFS_DIR_PENDING_BYTE + 2u)
#define VFS_DIR_SHARED_SIZE   510u
#define VFS_DIR_LOCKFILE_FLAGS (LOCKFILE_FAIL_IMMEDIATELY | LOCKFILE_EXCLUSIVE_LOCK)

/* Shared-memory lock window, identical to os_win.c WIN_SHM_BASE/WIN_SHM_DMS. */
#define VFS_DIR_SHM_BASE ((22 + SQLITE_SHM_NLOCK) * 4)
#define VFS_DIR_SHM_DMS  (VFS_DIR_SHM_BASE + SQLITE_SHM_NLOCK)

/* Transient-error retry, mirroring os_win.c winIoerrCanRetry1 /
 * SQLITE_WIN32_IOERR_RETRY{,_DELAY}. */
#define VFS_DIR_IOERR_RETRY       10
#define VFS_DIR_IOERR_RETRY_DELAY 25

#ifndef FILE_OPEN
#define FILE_OPEN 1u
#define FILE_CREATE 2u
#define FILE_OPEN_IF 3u
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x40u
#define FILE_OPEN_REPARSE_POINT 0x00200000u
#define FILE_SYNCHRONOUS_IO_NONALERT 0x20u
#define FILE_DELETE_ON_CLOSE 0x00001000u
#endif

typedef NTSTATUS (NTAPI *vfs_dir_nt_create_file_fn)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *vfs_dir_nt_set_information_file_fn)(
    HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);

static INIT_ONCE vfs_dir_create_once = INIT_ONCE_STATIC_INIT;
static INIT_ONCE vfs_dir_set_once = INIT_ONCE_STATIC_INIT;
static vfs_dir_nt_create_file_fn vfs_dir_create_cached;
static vfs_dir_nt_set_information_file_fn vfs_dir_set_cached;

static BOOL CALLBACK vfs_dir_resolve_nt_symbols(PINIT_ONCE once,
                                                PVOID parameter,
                                                PVOID *context)
{
    (void)once; (void)context;
    HMODULE module = GetModuleHandleW(L"ntdll.dll");
    FARPROC symbol = module ? GetProcAddress(module, (const char *)parameter)
                            : NULL;
    if (!strcmp((const char *)parameter, "NtCreateFile"))
        memcpy(&vfs_dir_create_cached, &symbol, sizeof(vfs_dir_create_cached));
    else
        memcpy(&vfs_dir_set_cached, &symbol, sizeof(vfs_dir_set_cached));
    return TRUE;
}

static vfs_dir_nt_create_file_fn vfs_dir_nt_create_file(void)
{
    (void)InitOnceExecuteOnce(&vfs_dir_create_once, vfs_dir_resolve_nt_symbols,
                              (PVOID)"NtCreateFile", NULL);
    return vfs_dir_create_cached;
}
static vfs_dir_nt_set_information_file_fn vfs_dir_nt_set_information_file(void)
{
    (void)InitOnceExecuteOnce(&vfs_dir_set_once, vfs_dir_resolve_nt_symbols,
                              (PVOID)"NtSetInformationFile", NULL);
    return vfs_dir_set_cached;
}

#define VFS_DIR_CTRL_PSOW        0x01u
#define VFS_DIR_CTRL_PERSIST_WAL 0x02u

/* ── Logging ───────────────────────────────────────────────────────────── */

static int vfs_dir_log_ioerr(int rc, const char *op, const char *leaf,
                             DWORD error)
{
    sqlite3_log(rc, "sqlite_vfs_dir: %s(%s) failed: win32=%lu",
                op, leaf ? leaf : "?", (unsigned long)error);
    return rc;
}

static int vfs_dir_log_refusal(const char *op, const char *name,
                               const char *why)
{
    sqlite3_log(SQLITE_CANTOPEN, "sqlite_vfs_dir: %s(%s) refused: %s",
                op, name ? name : "(null)", why);
    return SQLITE_CANTOPEN;
}

/* Transient-error retry, mirroring os_win.c winRetryIoerr (bounded, with
 * backoff; only the transient error classes retry). */
static bool vfs_dir_retry_ioerr(int *retries, DWORD *error)
{
    DWORD e = GetLastError();
    if (*retries >= VFS_DIR_IOERR_RETRY) {
        *error = e;
        return false;
    }
    if (e == ERROR_ACCESS_DENIED || e == ERROR_SHARING_VIOLATION ||
        e == ERROR_LOCK_VIOLATION || e == ERROR_DEV_NOT_EXIST ||
        e == ERROR_NETNAME_DELETED || e == ERROR_SEM_TIMEOUT ||
        e == ERROR_NETWORK_UNREACHABLE) {
        Sleep(VFS_DIR_IOERR_RETRY_DELAY * (DWORD)(1 + *retries));
        ++*retries;
        return true;
    }
    *error = e;
    return false;
}

/* ── Leaf validation and allowlist ─────────────────────────────────────── */

/* Plain-basename rules, mirroring valid_leaf() in
 * lib/platform/src/directory_transaction.c: no separators or drive/stream
 * syntax, no dot-relative names, no trailing dot/space, no reserved device
 * stems. */
bool vfs_dir_valid_leaf(const char *leaf)
{
    if (!leaf || !leaf[0] || strlen(leaf) > VFS_DIR_LEAF_MAX ||
        !strcmp(leaf, ".") || !strcmp(leaf, "..") || strchr(leaf, '/') ||
        strchr(leaf, '\\') || strchr(leaf, ':'))
        return false;
    size_t n = strlen(leaf);
    if (leaf[n - 1] == '.' || leaf[n - 1] == ' ')
        return false;
    char stem[16];
    size_t stem_len = strcspn(leaf, ".");
    if (stem_len >= sizeof(stem)) stem_len = sizeof(stem) - 1;
    for (size_t i = 0; i < stem_len; ++i) {
        unsigned char c = (unsigned char)leaf[i];
        stem[i] = (char)(c >= 'a' && c <= 'z' ? c - ('a' - 'A') : c);
    }
    stem[stem_len] = 0;
    if (!strcmp(stem, "CON") || !strcmp(stem, "PRN") || !strcmp(stem, "AUX") ||
        !strcmp(stem, "NUL") ||
        (stem_len == 4 && (!memcmp(stem, "COM", 3) || !memcmp(stem, "LPT", 3)) &&
         stem[3] >= '1' && stem[3] <= '9'))
        return false;
    return true;
}

static bool vfs_dir_is_hex9(const char *tail)
{
    /* Master-journal tail from pager.c: "-mj" + %06X + '9' + %02X. */
    if (tail[0] != '-' || tail[1] != 'm' || tail[2] != 'j')
        return false;
    for (int i = 3; i < 12; ++i) {
        char c = tail[i];
        bool hex = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F');
        if (i == 9 ? c != '9' : !hex)
            return false;
    }
    return tail[12] == '\0';
}

bool vfs_dir_is_temp_name(const char *leaf)
{
    size_t prefix = sizeof(VFS_DIR_TEMP_PREFIX) - 1u;
    if (strncmp(leaf, VFS_DIR_TEMP_PREFIX, prefix) != 0)
        return false;
    for (size_t i = prefix; i < prefix + VFS_DIR_TEMP_HEX; ++i) {
        char c = leaf[i];
        if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f'))
            return false;
    }
    return leaf[prefix + VFS_DIR_TEMP_HEX] == '\0';
}

/* The whole named namespace this VFS will serve: the bound basename and the
 * sibling suffixes SQLite derives from it. Nameless temp xOpen calls mint an
 * exclusive delete-on-close child directly; a caller-supplied temp-looking
 * name is never authority to open, probe, or delete a preexisting file. */
static bool vfs_dir_name_allowed(const struct sqlite_vfs_dir_binding *b,
                                 const char *leaf)
{
    size_t base = strlen(b->basename);
    if (strcmp(leaf, b->basename) == 0)
        return true;
    if (strncmp(leaf, b->basename, base) == 0) {
        const char *suffix = leaf + base;
        if (!strcmp(suffix, "-journal") || !strcmp(suffix, "-wal") ||
            !strcmp(suffix, "-shm") || vfs_dir_is_hex9(suffix))
            return true;
    }
    return false;
}

/* ── Handle-relative NT operations ─────────────────────────────────────── */

static bool vfs_dir_wide_leaf(const char *leaf, wchar_t out[260],
                              UNICODE_STRING *name)
{
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, leaf, -1,
                                out, 260);
    if (n <= 1)
        return false;
    name->Buffer = out;
    name->Length = (USHORT)((n - 1) * sizeof(wchar_t));
    name->MaximumLength = (USHORT)(n * sizeof(wchar_t));
    return true;
}

/* Open/create a child relative to the retained directory handle, following
 * the child_open idiom: reparse points surfaced rather than followed,
 * directories refused by disposition, post-open identity validation. Returns
 * INVALID_HANDLE_VALUE on any failure with the NTSTATUS in *status_out. */
static HANDLE vfs_dir_open_child(struct sqlite_vfs_dir_binding *b,
                                 const char *leaf, ACCESS_MASK access,
                                 ULONG disposition, ULONG options,
                                 NTSTATUS *status_out)
{
    vfs_dir_nt_create_file_fn create_file = vfs_dir_nt_create_file();
    wchar_t wide[260];
    UNICODE_STRING name;
    *status_out = 0xC000000FL; /* STATUS_INVALID_PARAMETER-ish sentinel */
    if (!create_file || !vfs_dir_wide_leaf(leaf, wide, &name))
        return INVALID_HANDLE_VALUE;
    OBJECT_ATTRIBUTES attributes;
    struct platform_private_acl acl;
    platform_private_acl_init_empty(&acl);
    if (!platform_private_acl_create(&acl))
        return INVALID_HANDLE_VALUE;
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE,
                               b->dir, platform_private_acl_descriptor(&acl));
    IO_STATUS_BLOCK status;
    HANDLE child = INVALID_HANDLE_VALUE;
    NTSTATUS result = create_file(
        &child, access, &attributes, &status, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, disposition,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT |
            FILE_SYNCHRONOUS_IO_NONALERT | options,
        NULL, 0);
    platform_private_acl_destroy(&acl);
    *status_out = result;
    if (result < 0 || child == INVALID_HANDLE_VALUE)
        return INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(child, &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY |
                                  FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        !platform_private_acl_validate_handle(child, false)) {
        CloseHandle(child);
        *status_out = (NTSTATUS)0xC0000022L; /* STATUS_ACCESS_DENIED */
        return INVALID_HANDLE_VALUE;
    }
    return child;
}

/* Delete a leaf relative to the retained handle: open with DELETE, then
 * FileDispositionInformationEx (class 64) with POSIX semantics so the
 * directory entry leaves the namespace while sharing handles remain open —
 * the same proven pattern as platform_directory_child_unlink_result. */
static bool vfs_dir_unlink_child(struct sqlite_vfs_dir_binding *b,
                                 const char *leaf, NTSTATUS *status_out)
{
    vfs_dir_nt_set_information_file_fn set_info =
        vfs_dir_nt_set_information_file();
    HANDLE child = vfs_dir_open_child(b, leaf,
        GENERIC_READ | DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
        FILE_OPEN, 0, status_out);
    if (child == INVALID_HANDLE_VALUE)
        return false;
    struct disposition_ex { ULONG flags; } disposition = { .flags = 1u | 2u };
    IO_STATUS_BLOCK status = { 0 };
    bool ok = set_info && set_info(child, &status, &disposition,
                                   sizeof(disposition),
                                   (FILE_INFORMATION_CLASS)64) >= 0;
    if (!ok)
        *status_out = status.Status ? status.Status
                                    : (NTSTATUS)0xC0000001L;
    CloseHandle(child);
    return ok;
}

/* ── sqlite3_file methods ──────────────────────────────────────────────── */

static int vfs_dir_shm_unmap(sqlite3_file *fd, int delete_flag);

static int vfs_dir_xclose(sqlite3_file *fd)
{
    struct vfs_dir_file *f = (struct vfs_dir_file *)fd;
    struct sqlite_vfs_dir_binding *b = f->binding;
    if (f->shm)
        (void)vfs_dir_shm_unmap(fd, 0); /* core unmaps first; defensive */
    BOOL ok = FALSE;
    int attempts = 0;
    while (!(ok = CloseHandle(f->h)) && ++attempts < 3)
        Sleep(100); /* os_win.c MX_CLOSE_ATTEMPT */
    DWORD error = ok ? NO_ERROR : GetLastError();
    f->h = INVALID_HANDLE_VALUE;
    f->base.pMethods = NULL;
    vfs_dir_binding_file_closed(b);
    return ok ? SQLITE_OK
              : vfs_dir_log_ioerr(SQLITE_IOERR_CLOSE, "xClose", f->leaf,
                                  error);
}

static int vfs_dir_xread(sqlite3_file *fd, void *buffer, int amount,
                         sqlite3_int64 offset)
{
    struct vfs_dir_file *f = (struct vfs_dir_file *)fd;
    OVERLAPPED overlapped;
    DWORD got = 0;
    int retries = 0;
    DWORD error = NO_ERROR;
    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.Offset = (DWORD)((uint64_t)offset & 0xffffffffu);
    overlapped.OffsetHigh = (DWORD)(((uint64_t)offset >> 32) & 0x7fffffffu);
    while (!ReadFile(f->h, buffer, (DWORD)amount, &got, &overlapped) &&
           GetLastError() != ERROR_HANDLE_EOF) {
        if (vfs_dir_retry_ioerr(&retries, &error))
            continue;
        f->last_errno = error;
        return vfs_dir_log_ioerr(SQLITE_IOERR_READ, "xRead", f->leaf, error);
    }
    if (got < (DWORD)amount) {
        /* Unread parts of the buffer must be zero-filled (os_win.c). */
        memset((char *)buffer + got, 0, (size_t)(amount - (int)got));
        return SQLITE_IOERR_SHORT_READ;
    }
    return SQLITE_OK;
}

static int vfs_dir_xwrite(sqlite3_file *fd, const void *buffer, int amount,
                          sqlite3_int64 offset)
{
    struct vfs_dir_file *f = (struct vfs_dir_file *)fd;
    const unsigned char *remaining = buffer;
    int left = amount;
    uint64_t at = (uint64_t)offset;
    int retries = 0;
    DWORD error = NO_ERROR;
    while (left > 0) {
        OVERLAPPED overlapped;
        DWORD wrote = 0;
        memset(&overlapped, 0, sizeof(overlapped));
        overlapped.Offset = (DWORD)(at & 0xffffffffu);
        overlapped.OffsetHigh = (DWORD)((at >> 32) & 0x7fffffffu);
        if (!WriteFile(f->h, remaining, (DWORD)left, &wrote, &overlapped)) {
            if (vfs_dir_retry_ioerr(&retries, &error))
                continue;
            f->last_errno = error;
            break;
        }
        if (wrote == 0 || wrote > (DWORD)left) {
            error = GetLastError();
            f->last_errno = error;
            break;
        }
        at += wrote;
        remaining += wrote;
        left -= (int)wrote;
    }
    if (left > 0) {
        int rc = error == ERROR_HANDLE_DISK_FULL || error == ERROR_DISK_FULL
                     ? SQLITE_FULL : SQLITE_IOERR_WRITE;
        return vfs_dir_log_ioerr(rc, "xWrite", f->leaf, error);
    }
    return SQLITE_OK;
}

static int vfs_dir_xtruncate(sqlite3_file *fd, sqlite3_int64 size)
{
    struct vfs_dir_file *f = (struct vfs_dir_file *)fd;
    if (f->sector_chunk > 0)
        size = ((size + f->sector_chunk - 1) / f->sector_chunk) *
               f->sector_chunk;
    FILE_END_OF_FILE_INFO end = { .EndOfFile = { .QuadPart = size } };
    if (!SetFileInformationByHandle(f->h, FileEndOfFileInfo, &end,
                                    sizeof(end)) &&
        GetLastError() != ERROR_USER_MAPPED_FILE) {
        f->last_errno = GetLastError();
        return vfs_dir_log_ioerr(SQLITE_IOERR_TRUNCATE, "xTruncate", f->leaf,
                                 f->last_errno);
    }
    return SQLITE_OK;
}

static int vfs_dir_xsync(sqlite3_file *fd, int flags)
{
    struct vfs_dir_file *f = (struct vfs_dir_file *)fd;
    (void)flags; /* Windows exposes no data-only sync; FlushFileBuffers covers
                    both SQLITE_SYNC_NORMAL and FULL (os_win.c winSync). */
    if (!FlushFileBuffers(f->h)) {
        f->last_errno = GetLastError();
        return vfs_dir_log_ioerr(SQLITE_IOERR_FSYNC, "xSync", f->leaf,
                                 f->last_errno);
    }
    return SQLITE_OK;
}

static int vfs_dir_xfilesize(sqlite3_file *fd, sqlite3_int64 *size)
{
    struct vfs_dir_file *f = (struct vfs_dir_file *)fd;
    LARGE_INTEGER end;
    if (!GetFileSizeEx(f->h, &end)) {
        f->last_errno = GetLastError();
        return vfs_dir_log_ioerr(SQLITE_IOERR_FSTAT, "xFileSize", f->leaf,
                                 f->last_errno);
    }
    *size = end.QuadPart;
    return SQLITE_OK;
}

static BOOL vfs_dir_lock_range(HANDLE h, DWORD flags, DWORD offset,
                               DWORD bytes)
{
    OVERLAPPED overlapped;
    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.Offset = offset;
    return LockFileEx(h, flags, 0, bytes, 0, &overlapped);
}

static BOOL vfs_dir_unlock_range(HANDLE h, DWORD offset, DWORD bytes)
{
    OVERLAPPED overlapped;
    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.Offset = offset;
    return UnlockFileEx(h, 0, bytes, 0, &overlapped);
}

static BOOL vfs_dir_get_read_lock(struct vfs_dir_file *f)
{
    return vfs_dir_lock_range(f->h, LOCKFILE_FAIL_IMMEDIATELY,
                              VFS_DIR_SHARED_FIRST, VFS_DIR_SHARED_SIZE);
}

static void vfs_dir_unlock_read_lock(struct vfs_dir_file *f)
{
    /* ERROR_NOT_LOCKED (already unlocked) is not an error (os_win.c). */
    (void)vfs_dir_unlock_range(f->h, VFS_DIR_SHARED_FIRST,
                               VFS_DIR_SHARED_SIZE);
}

/* The PENDING/SHARED/RESERVED/EXCLUSIVE state machine, mirrored transition
 * for transition from os_win.c winLock (byte layout at the top of this
 * file), including the bounded 3-try PENDING-byte acquisition that works
 * around indexing/anti-virus interference. */
static int vfs_dir_xlock(sqlite3_file *fd, int locktype)
{
    struct vfs_dir_file *f = (struct vfs_dir_file *)fd;
    int rc = SQLITE_OK;
    BOOL res = TRUE;
    BOOL got_pending = FALSE;
    DWORD last_err = NO_ERROR;

    if (f->lock_type >= locktype)
        return SQLITE_OK;
    /* No write lock on a read-only file (os_win.c WINFILE_RDONLY rule). */
    if (f->readonly && locktype >= SQLITE_LOCK_RESERVED)
        return SQLITE_IOERR_LOCK;

    int new_locktype = f->lock_type;
    if (f->lock_type == SQLITE_LOCK_NONE ||
        (locktype == SQLITE_LOCK_EXCLUSIVE &&
         f->lock_type <= SQLITE_LOCK_RESERVED)) {
        int count = 3;
        while (count-- > 0 &&
               !(res = vfs_dir_lock_range(f->h, VFS_DIR_LOCKFILE_FLAGS,
                                          VFS_DIR_PENDING_BYTE, 1))) {
            last_err = GetLastError();
            if (last_err == ERROR_INVALID_HANDLE) {
                f->last_errno = last_err;
                return vfs_dir_log_ioerr(SQLITE_IOERR_LOCK, "xLock", f->leaf,
                                         last_err);
            }
            if (count)
                Sleep(1);
        }
        got_pending = res;
        if (!res)
            last_err = GetLastError();
    }

    if (locktype == SQLITE_LOCK_SHARED && res) {
        res = vfs_dir_get_read_lock(f);
        if (res)
            new_locktype = SQLITE_LOCK_SHARED;
        else
            last_err = GetLastError();
    }

    if (locktype == SQLITE_LOCK_RESERVED && res) {
        res = vfs_dir_lock_range(f->h, VFS_DIR_LOCKFILE_FLAGS,
                                 VFS_DIR_RESERVED_BYTE, 1);
        if (res)
            new_locktype = SQLITE_LOCK_RESERVED;
        else
            last_err = GetLastError();
    }

    if (locktype == SQLITE_LOCK_EXCLUSIVE && res) {
        new_locktype = SQLITE_LOCK_PENDING;
        got_pending = FALSE; /* the PENDING byte stays held on this path */
    }

    if (locktype == SQLITE_LOCK_EXCLUSIVE && res) {
        (void)vfs_dir_unlock_read_lock(f);
        res = vfs_dir_lock_range(f->h, VFS_DIR_LOCKFILE_FLAGS,
                                 VFS_DIR_SHARED_FIRST, VFS_DIR_SHARED_SIZE);
        if (res) {
            new_locktype = SQLITE_LOCK_EXCLUSIVE;
        } else {
            last_err = GetLastError();
            (void)vfs_dir_get_read_lock(f);
        }
    }

    if (got_pending && locktype == SQLITE_LOCK_SHARED)
        (void)vfs_dir_unlock_range(f->h, VFS_DIR_PENDING_BYTE, 1);

    if (!res) {
        /* Contention is normal operation, not an error to log. */
        f->last_errno = last_err;
        rc = SQLITE_BUSY;
    }
    f->lock_type = new_locktype;
    return rc;
}

/* Mirrored from os_win.c winUnlock. */
static int vfs_dir_xunlock(sqlite3_file *fd, int locktype)
{
    struct vfs_dir_file *f = (struct vfs_dir_file *)fd;
    int rc = SQLITE_OK;
    int type = f->lock_type;
    if (type >= SQLITE_LOCK_EXCLUSIVE) {
        (void)vfs_dir_unlock_range(f->h, VFS_DIR_SHARED_FIRST,
                                   VFS_DIR_SHARED_SIZE);
        if (locktype == SQLITE_LOCK_SHARED && !vfs_dir_get_read_lock(f)) {
            f->last_errno = GetLastError();
            rc = vfs_dir_log_ioerr(SQLITE_IOERR_UNLOCK, "xUnlock", f->leaf,
                                   f->last_errno);
        }
    }
    if (type >= SQLITE_LOCK_RESERVED)
        (void)vfs_dir_unlock_range(f->h, VFS_DIR_RESERVED_BYTE, 1);
    if (locktype == SQLITE_LOCK_NONE && type >= SQLITE_LOCK_SHARED)
        vfs_dir_unlock_read_lock(f);
    if (type >= SQLITE_LOCK_PENDING)
        (void)vfs_dir_unlock_range(f->h, VFS_DIR_PENDING_BYTE, 1);
    f->lock_type = locktype;
    return rc;
}

/* Mirrored from os_win.c winCheckReservedLock. */
static int vfs_dir_xcheck_reserved(sqlite3_file *fd, int *out)
{
    struct vfs_dir_file *f = (struct vfs_dir_file *)fd;
    int res;
    if (f->lock_type >= SQLITE_LOCK_RESERVED) {
        res = 1;
    } else {
        BOOL locked = vfs_dir_lock_range(f->h, LOCKFILE_FAIL_IMMEDIATELY,
                                         VFS_DIR_RESERVED_BYTE, 1);
        if (locked)
            (void)vfs_dir_unlock_range(f->h, VFS_DIR_RESERVED_BYTE, 1);
        res = !locked;
    }
    *out = res;
    return SQLITE_OK;
}

static void vfs_dir_mode_bit(struct vfs_dir_file *f, unsigned char mask,
                             int *arg)
{
    if (*arg < 0) {
        *arg = (f->ctrl_flags & mask) != 0;
    } else if (*arg == 0) {
        f->ctrl_flags &= (unsigned char)~mask;
    } else {
        f->ctrl_flags |= mask;
    }
}

static int vfs_dir_xfilecontrol(sqlite3_file *fd, int operation, void *arg)
{
    struct vfs_dir_file *f = (struct vfs_dir_file *)fd;
    switch (operation) {
    case SQLITE_FCNTL_LOCKSTATE:
        *(int *)arg = f->lock_type;
        return SQLITE_OK;
    case SQLITE_FCNTL_LAST_ERRNO:
        *(int *)arg = (int)f->last_errno;
        return SQLITE_OK;
    case SQLITE_FCNTL_CHUNK_SIZE:
        f->sector_chunk = *(int *)arg;
        return SQLITE_OK;
    case SQLITE_FCNTL_SIZE_HINT:
        return SQLITE_OK; /* advisory; truncation on close is core's job */
    case SQLITE_FCNTL_PERSIST_WAL:
        vfs_dir_mode_bit(f, VFS_DIR_CTRL_PERSIST_WAL, (int *)arg);
        return SQLITE_OK;
    case SQLITE_FCNTL_POWERSAFE_OVERWRITE:
        vfs_dir_mode_bit(f, VFS_DIR_CTRL_PSOW, (int *)arg);
        return SQLITE_OK;
    case SQLITE_FCNTL_VFSNAME:
        *(char **)arg = sqlite3_mprintf("%s", f->binding->name);
        return *(char **)arg ? SQLITE_OK : SQLITE_NOMEM;
    case SQLITE_FCNTL_HAS_MOVED:
        *(int *)arg = 0; /* handle-bound: the file cannot have "moved" */
        return SQLITE_OK;
    default:
        return SQLITE_NOTFOUND;
    }
}

static int vfs_dir_xsector_size(sqlite3_file *fd)
{
    (void)fd;
    return 4096; /* SQLITE_DEFAULT_SECTOR_SIZE, os_win.c winSectorSize */
}

static int vfs_dir_xdevice_characteristics(sqlite3_file *fd)
{
    struct vfs_dir_file *f = (struct vfs_dir_file *)fd;
    /* Child handles deliberately share DELETE and xDelete uses POSIX delete
     * semantics. Advertising UNDELETABLE_WHEN_OPEN would let SQLite retain a
     * rollback journal across unlock even though another connection can
     * delete it underneath that open handle. */
    return SQLITE_IOCAP_SUBPAGE_READ |
           ((f->ctrl_flags & VFS_DIR_CTRL_PSOW)
                ? SQLITE_IOCAP_POWERSAFE_OVERWRITE : 0);
}

/* ── Shared memory (WAL-index), mirrored from os_win.c winShm* ─────────── */

#define VFS_DIR_SHM_UNLCK 1
#define VFS_DIR_SHM_RDLCK 2
#define VFS_DIR_SHM_WRLCK 3

static int vfs_dir_shm_system_lock(struct vfs_dir_shm_node *node, int how,
                                   int offset, int bytes)
{
    int rc;
    if (how == VFS_DIR_SHM_UNLCK) {
        rc = vfs_dir_unlock_range(node->file, (DWORD)offset, (DWORD)bytes)
                 ? SQLITE_OK : SQLITE_BUSY;
    } else {
        DWORD flags = LOCKFILE_FAIL_IMMEDIATELY;
        if (how == VFS_DIR_SHM_WRLCK)
            flags |= LOCKFILE_EXCLUSIVE_LOCK;
        rc = vfs_dir_lock_range(node->file, flags, (DWORD)offset,
                                (DWORD)bytes) ? SQLITE_OK : SQLITE_BUSY;
    }
    return rc; /* lock contention here is protocol, not an error to log */
}

/* The dead-man-switch dance, mirrored from os_win.c winLockSharedMemory:
 * win the exclusive DMS byte → this process is the first/only owner →
 * truncate the wal-index to zero; then drop to a shared DMS hold. A busy
 * exclusive attempt means another process already initialized it. */
static int vfs_dir_shm_lock_dms(struct vfs_dir_shm_node *node)
{
    int rc = vfs_dir_shm_system_lock(node, VFS_DIR_SHM_WRLCK, VFS_DIR_SHM_DMS,
                                     1);
    if (rc == SQLITE_OK) {
        FILE_END_OF_FILE_INFO end = { .EndOfFile = { .QuadPart = 0 } };
        if (!SetFileInformationByHandle(node->file, FileEndOfFileInfo, &end,
                                        sizeof(end))) {
            DWORD error = GetLastError();
            (void)vfs_dir_shm_system_lock(node, VFS_DIR_SHM_UNLCK,
                                          VFS_DIR_SHM_DMS, 1);
            return vfs_dir_log_ioerr(SQLITE_IOERR_SHMOPEN, "xShmOpen(dms)",
                                     "-shm", error);
        }
        (void)vfs_dir_shm_system_lock(node, VFS_DIR_SHM_UNLCK,
                                      VFS_DIR_SHM_DMS, 1);
    }
    return vfs_dir_shm_system_lock(node, VFS_DIR_SHM_RDLCK, VFS_DIR_SHM_DMS, 1);
}

/* Attach this connection to the binding's shm node, opening the -shm file
 * handle-relative on first use. os_win.c opens the node readonly only under
 * the readonly_shm URI parameter; this VFS never accepts URI names, so the
 * node is always READWRITE|CREATE here. Call with binding->mutex held. */
static int vfs_dir_shm_open_locked(struct sqlite_vfs_dir_binding *b,
                                   struct vfs_dir_file *f)
{
    struct vfs_dir_shm_conn *conn = sqlite3_malloc(sizeof(*conn));
    if (!conn)
        return SQLITE_IOERR_NOMEM;
    conn->next = NULL;
    conn->shared_mask = 0;
    conn->excl_mask = 0;
    struct vfs_dir_shm_node *node = &b->shm;
    int rc = SQLITE_OK;
    if (node->file == INVALID_HANDLE_VALUE) {
        char shm_leaf[VFS_DIR_LEAF_MAX + 1u];
        int n = snprintf(shm_leaf, sizeof(shm_leaf), "%s-shm", b->basename);
        if (n <= 0 || (size_t)n >= sizeof(shm_leaf)) {
            sqlite3_free(conn);
            return vfs_dir_log_refusal("xShmOpen", b->basename,
                                       "shm leaf overflow");
        }
        NTSTATUS status = 0;
        HANDLE file = vfs_dir_open_child(b, shm_leaf,
            GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE |
                FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
            FILE_OPEN_IF, 0, &status);
        if (file == INVALID_HANDLE_VALUE) {
            sqlite3_free(conn);
            return vfs_dir_log_ioerr(SQLITE_IOERR_SHMOPEN, "xShmOpen",
                                     shm_leaf, (DWORD)(status & 0xffff));
        }
        node->file = file;
        node->region_size = 0;
        node->region_count = 0;
        node->regions = NULL;
        node->first = NULL;
        node->ref = 0;
        rc = vfs_dir_shm_lock_dms(node);
        if (rc != SQLITE_OK) {
            (void)CloseHandle(node->file);
            node->file = INVALID_HANDLE_VALUE;
            sqlite3_free(conn);
            return rc;
        }
    }
    conn->next = node->first;
    node->first = conn;
    node->ref++;
    f->shm = conn;
    return rc;
}

static int vfs_dir_xshm_map(sqlite3_file *fd, int region, int size,
                            int is_write, void volatile **out)
{
    struct vfs_dir_file *f = (struct vfs_dir_file *)fd;
    struct sqlite_vfs_dir_binding *b = f->binding;
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    const DWORD granularity = info.dwAllocationGranularity;
    *out = NULL;
    int rc = SQLITE_OK;
    sqlite3_mutex_enter(b->mutex);
    if (!f->shm)
        rc = vfs_dir_shm_open_locked(b, f);
    struct vfs_dir_shm_node *node = &b->shm;
    if (rc == SQLITE_OK && node->region_count <= region) {
        node->region_size = size;
        sqlite3_int64 need = (sqlite3_int64)(region + 1) * size;
        LARGE_INTEGER current;
        if (!GetFileSizeEx(node->file, &current)) {
            rc = vfs_dir_log_ioerr(SQLITE_IOERR_SHMSIZE, "xShmMap(size)",
                                   f->leaf, GetLastError());
            goto out;
        }
        if (current.QuadPart < need) {
            if (!is_write)
                goto out; /* *out stays NULL with SQLITE_OK (os_win.c) */
            FILE_END_OF_FILE_INFO end = { .EndOfFile = { .QuadPart = need } };
            if (!SetFileInformationByHandle(node->file, FileEndOfFileInfo,
                                            &end, sizeof(end))) {
                rc = vfs_dir_log_ioerr(SQLITE_IOERR_SHMSIZE,
                                       "xShmMap(extend)", f->leaf,
                                       GetLastError());
                goto out;
            }
        }
        struct vfs_dir_shm_region *grown = sqlite3_realloc64(
            node->regions, (sqlite3_uint64)(region + 1) * sizeof(*grown));
        if (!grown) {
            rc = SQLITE_IOERR_NOMEM;
            goto out;
        }
        node->regions = grown;
        while (node->region_count <= region) {
            HANDLE map = CreateFileMappingW(node->file, NULL, PAGE_READWRITE,
                (DWORD)((uint64_t)need >> 32), (DWORD)(uint64_t)need, NULL);
            void *view = NULL;
            if (map) {
                int offset = node->region_count * size;
                int shift = (int)((uint32_t)offset % granularity);
                view = MapViewOfFile(map, FILE_MAP_WRITE | FILE_MAP_READ, 0,
                                     (DWORD)(offset - shift),
                                     (SIZE_T)(size + shift));
            }
            if (!view) {
                DWORD error = GetLastError();
                if (map)
                    (void)CloseHandle(map);
                rc = vfs_dir_log_ioerr(SQLITE_IOERR_SHMMAP, "xShmMap(map)",
                                       f->leaf, error);
                goto out;
            }
            node->regions[node->region_count].map = map;
            node->regions[node->region_count].view = view;
            node->region_count++;
        }
    }
out:
    if (rc == SQLITE_OK && node->region_count > region) {
        int offset = region * size;
        int shift = (int)((uint32_t)offset % granularity);
        *out = (void *)((char *)node->regions[region].view + shift);
    }
    sqlite3_mutex_leave(b->mutex);
    return rc;
}

/* Mirrored from os_win.c winShmLock, including the sibling-mask bookkeeping
 * that keeps same-process connections from fighting their own OS locks. */
static int vfs_dir_xshm_lock(sqlite3_file *fd, int offset, int count,
                             int flags)
{
    struct vfs_dir_file *f = (struct vfs_dir_file *)fd;
    struct vfs_dir_shm_conn *conn = f->shm;
    if (!conn)
        return SQLITE_IOERR_SHMLOCK;
    struct sqlite_vfs_dir_binding *b = f->binding;
    struct vfs_dir_shm_node *node = &b->shm;
    if (offset < 0 || count < 1 || offset + count > SQLITE_SHM_NLOCK)
        return vfs_dir_log_refusal("xShmLock", f->leaf, "lock window range");
    int rc = SQLITE_OK;
    uint16_t mask = (uint16_t)((1u << (offset + count)) - (1u << offset));
    sqlite3_mutex_enter(b->mutex);
    if (flags & SQLITE_SHM_UNLOCK) {
        uint16_t all = 0;
        for (struct vfs_dir_shm_conn *x = node->first; x; x = x->next) {
            if (x != conn)
                all |= x->shared_mask;
        }
        if ((mask & all) == 0)
            rc = vfs_dir_shm_system_lock(node, VFS_DIR_SHM_UNLCK,
                                         offset + VFS_DIR_SHM_BASE, count);
        if (rc == SQLITE_OK) {
            conn->excl_mask &= (uint16_t)~mask;
            conn->shared_mask &= (uint16_t)~mask;
        }
    } else if (flags & SQLITE_SHM_SHARED) {
        uint16_t all_shared = 0;
        for (struct vfs_dir_shm_conn *x = node->first; x; x = x->next) {
            if ((x->excl_mask & mask) != 0) {
                rc = SQLITE_BUSY;
                break;
            }
            all_shared |= x->shared_mask;
        }
        if (rc == SQLITE_OK) {
            if ((all_shared & mask) == 0)
                rc = vfs_dir_shm_system_lock(node, VFS_DIR_SHM_RDLCK,
                                             offset + VFS_DIR_SHM_BASE,
                                             count);
            if (rc == SQLITE_OK)
                conn->shared_mask |= mask;
        }
    } else {
        for (struct vfs_dir_shm_conn *x = node->first; x; x = x->next) {
            if (x != conn &&
                ((x->excl_mask | x->shared_mask) & mask) != 0) {
                rc = SQLITE_BUSY;
                break;
            }
        }
        if (rc == SQLITE_OK) {
            rc = vfs_dir_shm_system_lock(node, VFS_DIR_SHM_WRLCK,
                                         offset + VFS_DIR_SHM_BASE, count);
            if (rc == SQLITE_OK)
                conn->excl_mask |= mask;
        }
    }
    sqlite3_mutex_leave(b->mutex);
    return rc;
}

static void vfs_dir_xshm_barrier(sqlite3_file *fd)
{
    struct vfs_dir_file *f = (struct vfs_dir_file *)fd;
    MemoryBarrier();
    sqlite3_mutex_enter(f->binding->mutex); /* os_win.c: also mutex, for
                                               redundancy */
    sqlite3_mutex_leave(f->binding->mutex);
}

static int vfs_dir_shm_unmap(sqlite3_file *fd, int delete_flag)
{
    struct vfs_dir_file *f = (struct vfs_dir_file *)fd;
    struct vfs_dir_shm_conn *conn = f->shm;
    if (!conn)
        return SQLITE_OK;
    struct sqlite_vfs_dir_binding *b = f->binding;
    struct vfs_dir_shm_node *node = &b->shm;
    sqlite3_mutex_enter(b->mutex);
    struct vfs_dir_shm_conn **link = &node->first;
    while (*link && *link != conn)
        link = &(*link)->next;
    if (*link)
        *link = conn->next;
    f->shm = NULL;
    if (node->ref > 0)
        node->ref--;
    if (node->ref == 0) {
        for (int i = 0; i < node->region_count; ++i) {
            (void)UnmapViewOfFile(node->regions[i].view);
            (void)CloseHandle(node->regions[i].map);
        }
        sqlite3_free(node->regions);
        node->regions = NULL;
        node->region_count = 0;
        (void)CloseHandle(node->file);
        node->file = INVALID_HANDLE_VALUE;
        if (delete_flag) {
            char shm_leaf[VFS_DIR_LEAF_MAX + 1u];
            int n = snprintf(shm_leaf, sizeof(shm_leaf), "%s-shm",
                             b->basename);
            NTSTATUS status = 0;
            if (n > 0 && (size_t)n < sizeof(shm_leaf) &&
                !vfs_dir_unlink_child(b, shm_leaf, &status))
                sqlite3_log(SQLITE_IOERR_DELETE,
                            "sqlite_vfs_dir: xShmUnmap delete(%s) failed: "
                            "NTSTATUS=0x%08lx", shm_leaf,
                            (unsigned long)status);
        }
    }
    sqlite3_mutex_leave(b->mutex);
    sqlite3_free(conn);
    return SQLITE_OK;
}

const sqlite3_io_methods vfs_dir_io_methods = {
    .iVersion = 2,
    .xClose = vfs_dir_xclose,
    .xRead = vfs_dir_xread,
    .xWrite = vfs_dir_xwrite,
    .xTruncate = vfs_dir_xtruncate,
    .xSync = vfs_dir_xsync,
    .xFileSize = vfs_dir_xfilesize,
    .xLock = vfs_dir_xlock,
    .xUnlock = vfs_dir_xunlock,
    .xCheckReservedLock = vfs_dir_xcheck_reserved,
    .xFileControl = vfs_dir_xfilecontrol,
    .xSectorSize = vfs_dir_xsector_size,
    .xDeviceCharacteristics = vfs_dir_xdevice_characteristics,
    .xShmMap = vfs_dir_xshm_map,
    .xShmLock = vfs_dir_xshm_lock,
    .xShmBarrier = vfs_dir_xshm_barrier,
    .xShmUnmap = vfs_dir_shm_unmap,
};

/* ── sqlite3_vfs methods ───────────────────────────────────────────────── */

static int vfs_dir_open_impl(struct sqlite_vfs_dir_binding *b,
                             const char *name, sqlite3_file *file, int flags,
                             int *out_flags, bool readonly_fallback);

static int vfs_dir_xopen(sqlite3_vfs *vfs, const char *name,
                         sqlite3_file *file, int flags, int *out_flags)
{
    struct sqlite_vfs_dir_binding *b =
        (struct sqlite_vfs_dir_binding *)vfs->pAppData;
    if (!b || !vfs_dir_binding_open_begin(b, flags)) {
        sqlite3_log(SQLITE_CANTOPEN,
                    "sqlite_vfs_dir: xOpen(%s) refused: binding retired",
                    name ? name : "(null)");
        return SQLITE_CANTOPEN;
    }
    int rc = vfs_dir_open_impl(b, name, file, flags, out_flags, false);
    vfs_dir_binding_open_end(b, rc == SQLITE_OK);
    return rc;
}

static int vfs_dir_open_impl(struct sqlite_vfs_dir_binding *b,
                             const char *name, sqlite3_file *file, int flags,
                             int *out_flags, bool readonly_fallback)
{
    struct vfs_dir_file *f = (struct vfs_dir_file *)file;
    memset(f, 0, sizeof(*f));
    f->h = INVALID_HANDLE_VALUE;

    bool is_readonly = (flags & SQLITE_OPEN_READONLY) != 0;
    bool is_create = (flags & SQLITE_OPEN_CREATE) != 0;
    bool is_exclusive = (flags & SQLITE_OPEN_EXCLUSIVE) != 0;
    bool is_delete_on_close = (flags & SQLITE_OPEN_DELETEONCLOSE) != 0;

    char leaf[VFS_DIR_LEAF_MAX + 1u];
    ULONG disposition;
    if (!name) {
        /* Temp file: SQLite hands the VFS no name, so mint one inside the
         * bound directory. Temp files are always delete-on-close. */
        if (!is_delete_on_close)
            return vfs_dir_log_refusal("xOpen", name,
                                       "nameless open without DELETEONCLOSE");
        bool minted = false;
        for (int attempt = 0; attempt < 16 && !minted; ++attempt) {
            uint64_t nonce = 0;
            sqlite3_randomness((int)sizeof(nonce), &nonce);
            int n = snprintf(leaf, sizeof(leaf), VFS_DIR_TEMP_PREFIX "%016llx",
                             (unsigned long long)nonce);
            minted = n > 0 && (size_t)n < sizeof(leaf);
        }
        if (!minted)
            return vfs_dir_log_refusal("xOpen", name,
                                       "temp leaf mint failed");
        disposition = FILE_CREATE; /* fail on the astronomically unlikely
                                      collision; NtCreateFile says so */
    } else {
        if (!vfs_dir_valid_leaf(name))
            return vfs_dir_log_refusal("xOpen", name, "not a plain basename");
        if (!vfs_dir_name_allowed(b, name))
            return vfs_dir_log_refusal("xOpen", name,
                                       "outside the bound database family");
        memcpy(leaf, name, strlen(name) + 1u);
        disposition = is_exclusive ? FILE_CREATE
                      : is_create  ? FILE_OPEN_IF : FILE_OPEN;
    }

    ACCESS_MASK access = GENERIC_READ | SYNCHRONIZE | FILE_READ_ATTRIBUTES |
                         FILE_WRITE_ATTRIBUTES;
    if (!is_readonly)
        access |= GENERIC_WRITE;
    if (is_delete_on_close || !is_readonly)
        access |= DELETE;
    ULONG options = is_delete_on_close ? FILE_DELETE_ON_CLOSE : 0;

    NTSTATUS status = 0;
    HANDLE child = INVALID_HANDLE_VALUE;
    int retries = 0;
    for (;;) {
        child = vfs_dir_open_child(b, leaf, access, disposition, options,
                                   &status);
        if (child != INVALID_HANDLE_VALUE)
            break;
        if ((ULONG)status == 0xC0000035u) /* collision on exclusive create */
            break;
        SetLastError((ULONG)status == 0xC0000022u ? ERROR_ACCESS_DENIED
                     : (ULONG)status == 0xC0000043u ? ERROR_SHARING_VIOLATION
                     : ERROR_PATH_NOT_FOUND);
        DWORD error = NO_ERROR;
        if (vfs_dir_retry_ioerr(&retries, &error))
            continue;
        break;
    }
    if (child == INVALID_HANDLE_VALUE) {
        /* os_win.c winOpen fallback: a failing READWRITE open is retried as
         * READONLY (never widened, never for temp files). */
        if (!is_readonly && !is_exclusive && name && !is_delete_on_close &&
            !readonly_fallback) {
            return vfs_dir_open_impl(b, name, file,
                (flags | SQLITE_OPEN_READONLY) &
                    ~(SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE),
                out_flags, true);
        }
        return vfs_dir_log_ioerr(SQLITE_CANTOPEN, "xOpen", leaf,
                                 (DWORD)(status & 0xffff));
    }

    f->binding = b;
    f->h = child;
    f->lock_type = SQLITE_LOCK_NONE;
    f->readonly = is_readonly;
    f->last_errno = NO_ERROR;
    f->shm = NULL;
    memcpy(f->leaf, leaf, strlen(leaf) + 1u);
    /* os_win.c: powersafe-overwrite defaults on for the main database. */
    if (name && (flags & SQLITE_OPEN_MAIN_DB) != 0 &&
        sqlite3_uri_boolean(name, "psow", 1))
        f->ctrl_flags |= VFS_DIR_CTRL_PSOW;

    f->base.pMethods = &vfs_dir_io_methods;
    if (out_flags)
        *out_flags = is_readonly ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE;
    return SQLITE_OK;
}

static int vfs_dir_xdelete(sqlite3_vfs *vfs, const char *name, int sync_dir)
{
    struct sqlite_vfs_dir_binding *b =
        (struct sqlite_vfs_dir_binding *)vfs->pAppData;
    (void)sync_dir; /* Win32 exposes no directory fsync; the retained handle
                       is revalidated below instead (the
                       platform_directory_transaction_flush pattern). */
    if (!b || !vfs_dir_binding_aux_begin(b))
        return vfs_dir_log_refusal("xDelete", name, "binding retired");
    int rc = SQLITE_OK;
    if (!name || !vfs_dir_valid_leaf(name)) {
        rc = vfs_dir_log_refusal("xDelete", name, "not a plain basename");
        goto out;
    }
    if (!vfs_dir_name_allowed(b, name)) {
        rc = vfs_dir_log_refusal("xDelete", name,
                                 "outside the bound database family");
        goto out;
    }
    NTSTATUS status = 0;
    int retries = 0;
    for (;;) {
        if (vfs_dir_unlink_child(b, name, &status))
            break;
        if ((ULONG)status == 0xC0000034u || (ULONG)status == 0xC000003Au) {
            rc = SQLITE_IOERR_DELETE_NOENT; /* already gone (os_win.c) */
            goto out;
        }
        SetLastError((ULONG)status == 0xC0000043u ? ERROR_SHARING_VIOLATION
                     : (ULONG)status == 0xC0000022u ? ERROR_ACCESS_DENIED
                     : ERROR_ARENA_TRASHED);
        DWORD error = NO_ERROR;
        if (vfs_dir_retry_ioerr(&retries, &error))
            continue;
        rc = vfs_dir_log_ioerr(SQLITE_IOERR_DELETE, "xDelete", name,
                               (DWORD)(status & 0xffff));
        goto out;
    }
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(b->dir, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        rc = vfs_dir_log_ioerr(SQLITE_IOERR_DELETE, "xDelete(dir)", name,
                               GetLastError());
    }
out:
    vfs_dir_binding_aux_end(b);
    return rc;
}

static int vfs_dir_xaccess(sqlite3_vfs *vfs, const char *name, int flags,
                           int *result)
{
    struct sqlite_vfs_dir_binding *b =
        (struct sqlite_vfs_dir_binding *)vfs->pAppData;
    if (!result)
        return vfs_dir_log_refusal("xAccess", name, "missing result output");
    *result = 0;
    if (!name) {
        return SQLITE_OK;
    }
    if (!b || !vfs_dir_binding_aux_begin(b))
        return vfs_dir_log_refusal("xAccess", name, "binding retired");
    int rc = SQLITE_OK;
    if (!vfs_dir_valid_leaf(name)) {
        rc = vfs_dir_log_refusal("xAccess", name, "not a plain basename");
        goto out;
    }
    if (!vfs_dir_name_allowed(b, name)) {
        rc = vfs_dir_log_refusal("xAccess", name,
                                 "outside the bound database family");
        goto out;
    }
    NTSTATUS status = 0;
    HANDLE child = vfs_dir_open_child(b, name,
        GENERIC_READ | SYNCHRONIZE | FILE_READ_ATTRIBUTES, FILE_OPEN, 0,
        &status);
    if (child == INVALID_HANDLE_VALUE) {
        if ((ULONG)status == 0xC0000034u || (ULONG)status == 0xC000003Au) {
            *result = 0;
            goto out;
        }
        rc = vfs_dir_log_ioerr(SQLITE_IOERR_ACCESS, "xAccess", name,
                               (DWORD)(status & 0xffff));
        goto out;
    }
    BY_HANDLE_FILE_INFORMATION info;
    bool got = GetFileInformationByHandle(child, &info) != 0;
    DWORD error = got ? NO_ERROR : GetLastError();
    CloseHandle(child);
    if (!got) {
        rc = vfs_dir_log_ioerr(SQLITE_IOERR_ACCESS, "xAccess(info)", name,
                               error);
        goto out;
    }
    uint64_t size = ((uint64_t)info.nFileSizeHigh << 32) | info.nFileSizeLow;
    switch (flags) {
    case SQLITE_ACCESS_EXISTS:
        /* os_win.c: a zero-length file reports as nonexistent for EXISTS. */
        *result = size != 0;
        break;
    case SQLITE_ACCESS_READ:
        *result = 1;
        break;
    case SQLITE_ACCESS_READWRITE:
        *result = (info.dwFileAttributes & FILE_ATTRIBUTE_READONLY) == 0;
        break;
    default:
        rc = vfs_dir_log_refusal("xAccess", name, "unknown access flags");
        break;
    }
out:
    vfs_dir_binding_aux_end(b);
    return rc;
}

static int vfs_dir_xfull_pathname(sqlite3_vfs *vfs, const char *name,
                                  int size, char *out)
{
    struct sqlite_vfs_dir_binding *b =
        (struct sqlite_vfs_dir_binding *)vfs->pAppData;
    /* The leaf is the full name: the retained handle is the directory, so no
     * path ever materializes. SQLite derives -wal/-journal/etc. by appending
     * to this string, which keeps every sibling a leaf too. */
    if (!b || !vfs_dir_binding_aux_begin(b))
        return vfs_dir_log_refusal("xFullPathname", name,
                                   "binding retired");
    int rc = SQLITE_OK;
    if (!name || !out || size <= 0 || strlen(name) >= (size_t)size ||
        !vfs_dir_valid_leaf(name))
        rc = vfs_dir_log_refusal("xFullPathname", name,
                                 "not a plain basename or too long");
    else if (!vfs_dir_name_allowed(b, name))
        rc = vfs_dir_log_refusal("xFullPathname", name,
                                 "outside the bound database family");
    else
        memcpy(out, name, strlen(name) + 1u);
    vfs_dir_binding_aux_end(b);
    return rc;
}

static void *vfs_dir_xdlopen(sqlite3_vfs *vfs, const char *name)
{
    struct sqlite_vfs_dir_binding *b = vfs->pAppData;
    return b->base && b->base->xDlOpen ? b->base->xDlOpen(b->base, name)
                                       : NULL;
}

static void vfs_dir_xdlerror(sqlite3_vfs *vfs, int size, char *message)
{
    struct sqlite_vfs_dir_binding *b = vfs->pAppData;
    if (b->base && b->base->xDlError)
        b->base->xDlError(b->base, size, message);
    else if (size > 0)
        message[0] = '\0';
}

static void (*vfs_dir_xdlsym(sqlite3_vfs *vfs, void *handle,
                             const char *symbol))(void)
{
    struct sqlite_vfs_dir_binding *b = vfs->pAppData;
    return b->base && b->base->xDlSym ? b->base->xDlSym(b->base, handle,
                                                        symbol) : NULL;
}

static void vfs_dir_xdlclose(sqlite3_vfs *vfs, void *handle)
{
    struct sqlite_vfs_dir_binding *b = vfs->pAppData;
    if (b->base && b->base->xDlClose)
        b->base->xDlClose(b->base, handle);
}

static int vfs_dir_xrandomness(sqlite3_vfs *vfs, int size, char *out)
{
    struct sqlite_vfs_dir_binding *b = vfs->pAppData;
    return b->base->xRandomness(b->base, size, out);
}

static int vfs_dir_xsleep(sqlite3_vfs *vfs, int microseconds)
{
    struct sqlite_vfs_dir_binding *b = vfs->pAppData;
    return b->base->xSleep(b->base, microseconds);
}

static int vfs_dir_xcurrent_time(sqlite3_vfs *vfs, double *time_out)
{
    struct sqlite_vfs_dir_binding *b = vfs->pAppData;
    return b->base->xCurrentTime(b->base, time_out);
}

static int vfs_dir_xlast_error(sqlite3_vfs *vfs, int size, char *message)
{
    struct sqlite_vfs_dir_binding *b = vfs->pAppData;
    return b->base && b->base->xGetLastError
               ? b->base->xGetLastError(b->base, size, message) : 0;
}

static int vfs_dir_xcurrent_time_i64(sqlite3_vfs *vfs,
                                     sqlite3_int64 *time_out)
{
    struct sqlite_vfs_dir_binding *b = vfs->pAppData;
    return b->base && b->base->iVersion >= 2 && b->base->xCurrentTimeInt64
               ? b->base->xCurrentTimeInt64(b->base, time_out) : SQLITE_ERROR;
}

static int vfs_dir_xset_system_call(sqlite3_vfs *vfs, const char *name,
                                    sqlite3_syscall_ptr call)
{
    struct sqlite_vfs_dir_binding *b = vfs->pAppData;
    return b->base && b->base->iVersion >= 3 && b->base->xSetSystemCall
               ? b->base->xSetSystemCall(b->base, name, call)
               : SQLITE_NOTFOUND;
}

static sqlite3_syscall_ptr vfs_dir_xget_system_call(sqlite3_vfs *vfs,
                                                    const char *name)
{
    struct sqlite_vfs_dir_binding *b = vfs->pAppData;
    return b->base && b->base->iVersion >= 3 && b->base->xGetSystemCall
               ? b->base->xGetSystemCall(b->base, name) : NULL;
}

static const char *vfs_dir_xnext_system_call(sqlite3_vfs *vfs,
                                             const char *name)
{
    struct sqlite_vfs_dir_binding *b = vfs->pAppData;
    return b->base && b->base->iVersion >= 3 && b->base->xNextSystemCall
               ? b->base->xNextSystemCall(b->base, name) : NULL;
}

/* Registration owns allocation and lifetime. This file owns the method table
 * because every callback below is deliberately translation-unit private. */
void vfs_dir_binding_initialize_vfs(struct sqlite_vfs_dir_binding *b)
{
    b->vfs = (sqlite3_vfs) {
        .iVersion = b->base->iVersion > 3 ? 3 : b->base->iVersion,
        .szOsFile = (int)sizeof(struct vfs_dir_file),
        .mxPathname = VFS_DIR_MX_PATHNAME,
        .pNext = NULL,
        .zName = b->name,
        .pAppData = b,
        .xOpen = vfs_dir_xopen,
        .xDelete = vfs_dir_xdelete,
        .xAccess = vfs_dir_xaccess,
        .xFullPathname = vfs_dir_xfull_pathname,
        .xDlOpen = vfs_dir_xdlopen,
        .xDlError = vfs_dir_xdlerror,
        .xDlSym = vfs_dir_xdlsym,
        .xDlClose = vfs_dir_xdlclose,
        .xRandomness = vfs_dir_xrandomness,
        .xSleep = vfs_dir_xsleep,
        .xCurrentTime = vfs_dir_xcurrent_time,
        .xGetLastError = vfs_dir_xlast_error,
        .xCurrentTimeInt64 = vfs_dir_xcurrent_time_i64,
        .xSetSystemCall = vfs_dir_xset_system_call,
        .xGetSystemCall = vfs_dir_xget_system_call,
        .xNextSystemCall = vfs_dir_xnext_system_call,
    };
}

#else
typedef int sqlite_vfs_dir_windows_nonempty_translation_unit;
#endif /* _WIN32 */
