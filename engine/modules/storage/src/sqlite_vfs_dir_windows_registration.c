/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: registration, retained lifetime, filesystem qualification, and
 * main-file identity audit for the native Windows directory-bound SQLite VFS. */
#include "storage/sqlite_vfs_dir.h"

#if defined(_WIN32)

#include "sqlite_vfs_dir_windows_internal.h"
#include "../../platform/src/private_acl_internal.h"

#include <winternl.h>

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#ifndef FILE_REMOTE_DEVICE
#define FILE_REMOTE_DEVICE 0x00000010u
#endif

typedef NTSTATUS (NTAPI *vfs_dir_nt_query_volume_fn)(
    HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FS_INFORMATION_CLASS);

static INIT_ONCE vfs_dir_query_volume_once = INIT_ONCE_STATIC_INIT;
static vfs_dir_nt_query_volume_fn vfs_dir_query_volume_cached;

static BOOL CALLBACK vfs_dir_resolve_query_volume(PINIT_ONCE once,
                                                   PVOID parameter,
                                                   PVOID *context)
{
    (void)once;
    (void)parameter;
    (void)context;
    HMODULE module = GetModuleHandleW(L"ntdll.dll");
    FARPROC symbol = module
        ? GetProcAddress(module, "NtQueryVolumeInformationFile") : NULL;
    memcpy(&vfs_dir_query_volume_cached, &symbol,
           sizeof(vfs_dir_query_volume_cached));
    return TRUE;
}

static vfs_dir_nt_query_volume_fn vfs_dir_nt_query_volume(void)
{
    (void)InitOnceExecuteOnce(&vfs_dir_query_volume_once,
                              vfs_dir_resolve_query_volume, NULL, NULL);
    return vfs_dir_query_volume_cached;
}

/* Qualify from the retained handle only. A remote server may report its
 * backing filesystem as NTFS, so the filesystem-name check alone is not an
 * admission boundary. */
static bool vfs_dir_volume_is_local_ntfs(HANDLE directory, const char *op)
{
    wchar_t filesystem[32];
    DWORD serial = 0;
    DWORD maximum_component = 0;
    DWORD flags = 0;
    if (!GetVolumeInformationByHandleW(
            directory, NULL, 0, &serial, &maximum_component, &flags,
            filesystem, (DWORD)(sizeof(filesystem) / sizeof(filesystem[0])))) {
        DWORD error = GetLastError();
        fprintf(stderr,  // obs-ok:sqlite-vfs-dir-register
                "[sqlite_vfs_dir] %s: volume query failed: win32=%lu\n",
                op, (unsigned long)error);
        return false;
    }
    if (_wcsicmp(filesystem, L"NTFS") != 0) {
        fprintf(stderr,  // obs-ok:sqlite-vfs-dir-register
                "[sqlite_vfs_dir] %s: filesystem is not qualified NTFS\n",
                op);
        return false;
    }

    vfs_dir_nt_query_volume_fn query_volume = vfs_dir_nt_query_volume();
    if (!query_volume) {
        fprintf(stderr,  // obs-ok:sqlite-vfs-dir-register
                "[sqlite_vfs_dir] %s: native volume-device query unavailable\n",
                op);
        return false;
    }
    IO_STATUS_BLOCK status = {0};
    FILE_FS_DEVICE_INFORMATION device = {0};
    NTSTATUS result = query_volume(directory, &status, &device,
                                   sizeof(device), FileFsDeviceInformation);
    if (result < 0) {
        fprintf(stderr,  // obs-ok:sqlite-vfs-dir-register
                "[sqlite_vfs_dir] %s: volume-device query failed: "
                "NTSTATUS=0x%08lx\n", op, (unsigned long)result);
        return false;
    }
    if ((device.Characteristics & FILE_REMOTE_DEVICE) != 0) {
        fprintf(stderr,  // obs-ok:sqlite-vfs-dir-register
                "[sqlite_vfs_dir] %s: remote NTFS is not qualified\n", op);
        return false;
    }
    return true;
}

/* The registry lock protects both name membership and lifetime counters. A
 * closing binding stays in this private list so a late xOpen can establish a
 * reservation without dereferencing memory that unregister just freed. */
static INIT_ONCE vfs_dir_registry_once = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION vfs_dir_registry_lock;
static struct sqlite_vfs_dir_binding *vfs_dir_registry;
static unsigned vfs_dir_registry_reservations;

static BOOL CALLBACK vfs_dir_registry_init(PINIT_ONCE once, PVOID parameter,
                                           PVOID *context)
{
    (void)once;
    (void)parameter;
    (void)context;
    InitializeCriticalSection(&vfs_dir_registry_lock);
    return TRUE;
}

static void vfs_dir_registry_enter(void)
{
    (void)InitOnceExecuteOnce(&vfs_dir_registry_once, vfs_dir_registry_init,
                              NULL, NULL);
    EnterCriticalSection(&vfs_dir_registry_lock);
}

static void vfs_dir_registry_leave(void)
{
    LeaveCriticalSection(&vfs_dir_registry_lock);
}

static bool vfs_dir_registry_reserve(void)
{
    vfs_dir_registry_enter();
    bool reserved =
        vfs_dir_registry_reservations < SQLITE_VFS_DIR_REGISTRATION_LIMIT;
    if (reserved)
        vfs_dir_registry_reservations++;
    vfs_dir_registry_leave();
    return reserved;
}

static void vfs_dir_registry_release_reservation(void)
{
    vfs_dir_registry_enter();
    if (vfs_dir_registry_reservations > 0)
        vfs_dir_registry_reservations--;
    vfs_dir_registry_leave();
}

static bool vfs_dir_registry_contains(
    const struct sqlite_vfs_dir_binding *binding)
{
    for (const struct sqlite_vfs_dir_binding *item = vfs_dir_registry;
         item; item = item->next) {
        if (item == binding)
            return true;
    }
    return false;
}

static bool vfs_dir_binding_should_retire(
    const struct sqlite_vfs_dir_binding *binding)
{
    return binding->closing && binding->open_files == 0 &&
           binding->active_ops == 0 && !binding->resources_retired;
}

static void vfs_dir_close_handle(HANDLE handle, const char *resource)
{
    if (handle && handle != INVALID_HANDLE_VALUE && !CloseHandle(handle)) {
        DWORD error = GetLastError();
        fprintf(stderr,  // obs-ok:sqlite-vfs-dir-retire
                "[sqlite_vfs_dir] retire: CloseHandle(%s) failed: "
                "win32=%lu\n", resource, (unsigned long)error);
    }
}

static void vfs_dir_unmap_view(void *view, int region)
{
    if (view && !UnmapViewOfFile(view)) {
        DWORD error = GetLastError();
        fprintf(stderr,  // obs-ok:sqlite-vfs-dir-retire
                "[sqlite_vfs_dir] retire: UnmapViewOfFile(region=%d) "
                "failed: win32=%lu\n", region, (unsigned long)error);
    }
}

static void vfs_dir_binding_retire_resources(
    struct sqlite_vfs_dir_binding *binding)
{
    for (int i = 0; i < binding->shm.region_count; ++i) {
        vfs_dir_unmap_view(binding->shm.regions[i].view, i);
        vfs_dir_close_handle(binding->shm.regions[i].map, "shm-region");
    }
    sqlite3_free(binding->shm.regions);
    vfs_dir_close_handle(binding->shm.file, "shm-file");
    binding->shm.regions = NULL;
    binding->shm.region_count = 0;
    binding->shm.file = INVALID_HANDLE_VALUE;
    sqlite3_mutex_free(binding->mutex);
    binding->mutex = NULL;
    vfs_dir_close_handle(binding->dir, "directory");
    binding->dir = INVALID_HANDLE_VALUE;
}

static void vfs_dir_binding_destroy_unpublished(
    struct sqlite_vfs_dir_binding *binding)
{
    vfs_dir_binding_retire_resources(binding);
    sqlite3_free(binding);
}

bool vfs_dir_binding_open_begin(struct sqlite_vfs_dir_binding *binding,
                                int flags)
{
    if (!binding)
        return false;
    vfs_dir_registry_enter();
    bool continuation = binding->open_files > 0 &&
                        (flags & SQLITE_OPEN_MAIN_DB) == 0;
    bool allowed = vfs_dir_registry_contains(binding) &&
                   !binding->resources_retired &&
                   (!binding->closing || continuation);
    if (allowed)
        binding->active_ops++;
    vfs_dir_registry_leave();
    return allowed;
}

void vfs_dir_binding_open_end(struct sqlite_vfs_dir_binding *binding,
                              bool success)
{
    bool destroy = false;
    vfs_dir_registry_enter();
    if (vfs_dir_registry_contains(binding) && binding->active_ops > 0) {
        binding->active_ops--;
        if (success)
            binding->open_files++;
        destroy = vfs_dir_binding_should_retire(binding);
        if (destroy)
            binding->resources_retired = true;
    }
    vfs_dir_registry_leave();
    if (destroy)
        vfs_dir_binding_retire_resources(binding);
}

bool vfs_dir_binding_aux_begin(struct sqlite_vfs_dir_binding *binding)
{
    if (!binding)
        return false;
    vfs_dir_registry_enter();
    /* An already-open connection may still need xDelete/xAccess for its
     * journal and WAL family after the public VFS name is unregistered.
     * With no open file, a cached stale vtable has no continuation authority. */
    bool continuation = binding->open_files > 0;
    bool allowed = vfs_dir_registry_contains(binding) &&
                   !binding->resources_retired &&
                   (!binding->closing || continuation);
    if (allowed)
        binding->active_ops++;
    vfs_dir_registry_leave();
    return allowed;
}

void vfs_dir_binding_aux_end(struct sqlite_vfs_dir_binding *binding)
{
    bool destroy = false;
    vfs_dir_registry_enter();
    if (vfs_dir_registry_contains(binding) && binding->active_ops > 0) {
        binding->active_ops--;
        destroy = vfs_dir_binding_should_retire(binding);
        if (destroy)
            binding->resources_retired = true;
    }
    vfs_dir_registry_leave();
    if (destroy)
        vfs_dir_binding_retire_resources(binding);
}

void vfs_dir_binding_file_closed(struct sqlite_vfs_dir_binding *binding)
{
    bool destroy = false;
    vfs_dir_registry_enter();
    if (vfs_dir_registry_contains(binding) && binding->open_files > 0) {
        binding->open_files--;
        destroy = vfs_dir_binding_should_retire(binding);
        if (destroy)
            binding->resources_retired = true;
    }
    vfs_dir_registry_leave();
    if (destroy)
        vfs_dir_binding_retire_resources(binding);
}

bool sqlite_vfs_dir_register(uintptr_t retained_dir, const char *db_basename,
                             char vfs_name_out[SQLITE_VFS_DIR_NAME_MAX])
{
    static atomic_uint_fast64_t sequence = 0;
    HANDLE dir = (HANDLE)retained_dir;
    if (!vfs_name_out || !db_basename ||
        dir == INVALID_HANDLE_VALUE || !dir) {
        fprintf(stderr,  // obs-ok:sqlite-vfs-dir-register
                "[sqlite_vfs_dir] register: null argument\n");
        return false;
    }
    if (!vfs_dir_registry_reserve()) {
        fprintf(stderr,  // obs-ok:sqlite-vfs-dir-register
                "[sqlite_vfs_dir] register: process registration limit "
                "(%u) reached\n", SQLITE_VFS_DIR_REGISTRATION_LIMIT);
        return false;
    }
    if (!vfs_dir_volume_is_local_ntfs(dir, "register"))
        goto refuse_reserved;
    if (strlen(db_basename) > VFS_DIR_BASENAME_MAX ||
        !vfs_dir_valid_leaf(db_basename) ||
        vfs_dir_is_temp_name(db_basename)) {
        fprintf(stderr,  // obs-ok:sqlite-vfs-dir-register
                "[sqlite_vfs_dir] register: refused db basename '%s'\n",
                db_basename);
        goto refuse_reserved;
    }
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(dir, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        !platform_private_acl_validate_handle(dir, true)) {
        fprintf(stderr,  // obs-ok:sqlite-vfs-dir-register
                "[sqlite_vfs_dir] register: retained handle failed "
                "directory validation (win32=%lu)\n",
                (unsigned long)GetLastError());
        goto refuse_reserved;
    }

    struct sqlite_vfs_dir_binding *binding = sqlite3_malloc(sizeof(*binding));
    HANDLE duplicated = INVALID_HANDLE_VALUE;
    if (binding)
        memset(binding, 0, sizeof(*binding));
    if (!binding || !DuplicateHandle(GetCurrentProcess(), dir,
                                     GetCurrentProcess(), &duplicated,
                                     0, FALSE, DUPLICATE_SAME_ACCESS)) {
        fprintf(stderr,  // obs-ok:sqlite-vfs-dir-register
                "[sqlite_vfs_dir] register: allocation/duplication failed "
                "(win32=%lu)\n", (unsigned long)GetLastError());
        sqlite3_free(binding);
        goto refuse_reserved;
    }
    binding->dir = duplicated;
    memcpy(binding->basename, db_basename, strlen(db_basename) + 1u);
    binding->shm.file = INVALID_HANDLE_VALUE;
    binding->base = sqlite3_vfs_find(NULL);
    binding->mutex = binding->base
        ? sqlite3_mutex_alloc(SQLITE_MUTEX_FAST) : NULL;
    if (!binding->base || !binding->mutex) {
        fprintf(stderr,  // obs-ok:sqlite-vfs-dir-register
                "[sqlite_vfs_dir] register: no default VFS or no mutex\n");
        (void)CloseHandle(binding->dir);
        sqlite3_free(binding);
        goto refuse_reserved;
    }
    uint64_t nonce = atomic_fetch_add(&sequence, 1) + 1;
    int n = snprintf(binding->name, sizeof(binding->name),
                     "zclvfsdir_%lu_%llu",
                     (unsigned long)GetCurrentProcessId(),
                     (unsigned long long)nonce);
    if (n <= 0 || (size_t)n >= sizeof(binding->name)) {
        fprintf(stderr,  // obs-ok:sqlite-vfs-dir-register
                "[sqlite_vfs_dir] register: VFS name overflow\n");
        vfs_dir_binding_destroy_unpublished(binding);
        goto refuse_reserved;
    }
    vfs_dir_binding_initialize_vfs(binding);
    if (sqlite3_vfs_register(&binding->vfs, 0) != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:sqlite-vfs-dir-register
                "[sqlite_vfs_dir] register: sqlite3_vfs_register failed\n");
        vfs_dir_binding_destroy_unpublished(binding);
        goto refuse_reserved;
    }
    vfs_dir_registry_enter();
    binding->next = vfs_dir_registry;
    vfs_dir_registry = binding;
    vfs_dir_registry_leave();
    memcpy(vfs_name_out, binding->name, strlen(binding->name) + 1u);
    return true;

refuse_reserved:
    vfs_dir_registry_release_reservation();
    return false;
}

bool sqlite_vfs_dir_unregister(const char *vfs_name)
{
    if (!vfs_name) {
        fprintf(stderr,  // obs-ok:sqlite-vfs-dir-register
                "[sqlite_vfs_dir] unregister: null name\n");
        return false;
    }
    vfs_dir_registry_enter();
    struct sqlite_vfs_dir_binding *binding = vfs_dir_registry;
    while (binding &&
           (binding->closing || strcmp(binding->name, vfs_name) != 0))
        binding = binding->next;
    if (binding)
        binding->closing = true;
    vfs_dir_registry_leave();
    if (!binding) {
        fprintf(stderr,  // obs-ok:sqlite-vfs-dir-register
                "[sqlite_vfs_dir] unregister: no live binding named '%s'\n",
                vfs_name);
        return false;
    }

    int rc = sqlite3_vfs_unregister(&binding->vfs);
    bool destroy = false;
    vfs_dir_registry_enter();
    if (rc == SQLITE_OK) {
        destroy = vfs_dir_binding_should_retire(binding);
        if (destroy)
            binding->resources_retired = true;
    } else {
        binding->closing = false;
    }
    vfs_dir_registry_leave();
    if (destroy)
        vfs_dir_binding_retire_resources(binding);
    if (rc != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:sqlite-vfs-dir-register
                "[sqlite_vfs_dir] unregister: sqlite registry failed: "
                "rc=%d (%s)\n", rc, sqlite3_errstr(rc));
        return false;
    }
    return true;
}

bool sqlite_vfs_dir_main_file_info(sqlite3 *db, uintptr_t expected_directory,
                                   const char *expected_leaf,
                                   uint64_t *volume_serial_out,
                                   uint64_t *file_index_out,
                                   uint64_t *file_size_out)
{
    if (!db || expected_directory == UINTPTR_MAX || expected_directory == 0 ||
        !expected_leaf || !vfs_dir_valid_leaf(expected_leaf) ||
        !volume_serial_out || !file_index_out || !file_size_out) {
        fprintf(stderr,
                "[sqlite_vfs_dir] main_file_info: invalid argument\n");
        return false;
    }

    sqlite3_file *base = NULL;
    int rc = sqlite3_file_control(db, "main", SQLITE_FCNTL_FILE_POINTER,
                                  &base);
    if (rc != SQLITE_OK || !base || base->pMethods != &vfs_dir_io_methods) {
        fprintf(stderr,
                "[sqlite_vfs_dir] main_file_info: main database is not "
                "owned by sqlite_vfs_dir\n");
        return false;
    }

    struct vfs_dir_file *file = (struct vfs_dir_file *)base;
    BY_HANDLE_FILE_INFORMATION bound_directory;
    BY_HANDLE_FILE_INFORMATION expected;
    bool same_directory = file->binding &&
        GetFileInformationByHandle(file->binding->dir, &bound_directory) != 0 &&
        GetFileInformationByHandle((HANDLE)expected_directory, &expected) != 0 &&
        bound_directory.dwVolumeSerialNumber == expected.dwVolumeSerialNumber &&
        bound_directory.nFileIndexHigh == expected.nFileIndexHigh &&
        bound_directory.nFileIndexLow == expected.nFileIndexLow;
    if (!same_directory || file->h == INVALID_HANDLE_VALUE ||
        (expected.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (expected.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        !platform_private_acl_validate_handle((HANDLE)expected_directory,
                                              true) ||
        !vfs_dir_volume_is_local_ntfs((HANDLE)expected_directory,
                                      "main_file_info") ||
        strcmp(file->leaf, expected_leaf) != 0 ||
        strcmp(file->binding->basename, expected_leaf) != 0) {
        fprintf(stderr,
                "[sqlite_vfs_dir] main_file_info: retained directory "
                "identity mismatch\n");
        return false;
    }

    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(file->h, &info)) {
        fprintf(stderr,
                "[sqlite_vfs_dir] main_file_info: file identity read failed: "
                "win32=%lu\n", (unsigned long)GetLastError());
        return false;
    }
    *volume_serial_out = (uint64_t)info.dwVolumeSerialNumber;
    *file_index_out = ((uint64_t)info.nFileIndexHigh << 32) |
                      (uint64_t)info.nFileIndexLow;
    *file_size_out = ((uint64_t)info.nFileSizeHigh << 32) |
                     (uint64_t)info.nFileSizeLow;
    return true;
}

#else
typedef int sqlite_vfs_dir_windows_registration_nonempty_translation_unit;
#endif /* _WIN32 */
