/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Retained directory identity and child-path construction for progress_store. */
#include "progress_store_directory.h"
#include "platform/directory_transaction.h"
#include "platform/fd_path.h"
#include "platform/private_directory.h"
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(_WIN32)
#include <io.h>
#include <wchar.h>
#include <windows.h>

static bool progress_directory_wide_to_utf8(const wchar_t *wide, char *out,
                                            size_t out_size)
{
    int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1,
                                NULL, 0, NULL, NULL);
    return n > 0 && (size_t)n <= out_size &&
           WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1,
                               out, (int)out_size, NULL, NULL) > 0;
}

/* Derive a canonical path from an open directory handle and prove the path
 * resolves to the same directory object at this instant. This supports
 * identity diagnostics and snapshot activation. SQLite authority does not
 * rely on the returned pathname: progress_store binds main/WAL/SHM opens to
 * the retained handle through sqlite_vfs_dir. */
static bool progress_directory_canonical_from_handle(HANDLE dir, char *out,
                                                     size_t out_size)
{
    wchar_t canonical[32768];
    DWORD n = GetFinalPathNameByHandleW(
        dir, canonical, sizeof(canonical) / sizeof(canonical[0]),
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!n || n >= sizeof(canonical) / sizeof(canonical[0]))
        return false;
    const wchar_t *plain = wcsncmp(canonical, L"\\\\?\\", 4) == 0
                               ? canonical + 4 : canonical;
    HANDLE probe = CreateFileW(
        plain, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (probe == INVALID_HANDLE_VALUE)
        return false;
    BY_HANDLE_FILE_INFORMATION retained, resolved;
    bool same = GetFileInformationByHandle(dir, &retained) != 0 &&
                GetFileInformationByHandle(probe, &resolved) != 0 &&
                retained.dwVolumeSerialNumber == resolved.dwVolumeSerialNumber &&
                retained.nFileIndexHigh == resolved.nFileIndexHigh &&
                retained.nFileIndexLow == resolved.nFileIndexLow;
    CloseHandle(probe);
    if (!same)
        return false;
    return progress_directory_wide_to_utf8(canonical, out, out_size);
}
#endif

bool progress_directory_open(const char *directory, const char *child,
                             char *path, size_t path_size, uintptr_t *handle)
{
#if defined(_WIN32)
    if (!platform_private_directory_open_validated(directory, handle))
        return false;
    char canonical[32768];
    if (!progress_directory_canonical_from_handle((HANDLE)*handle, canonical,
                                                  sizeof(canonical))) {
        platform_private_directory_close(*handle);
        *handle = UINTPTR_MAX;
        return false;
    }
    int length = snprintf(path, path_size, "%s\\%s", canonical, child);
    if (length > 0 && (size_t)length < path_size)
        return true;
    platform_private_directory_close(*handle);
    *handle = UINTPTR_MAX;
    return false;
#else
    int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return false;
    if (!platform_dirfd_child_path(path, path_size, fd, child)) {
        close(fd);
        return false;
    }
    *handle = (uintptr_t)fd;
    return true;
#endif
}

void progress_directory_close(uintptr_t handle)
{
    if (handle != UINTPTR_MAX)
        platform_private_directory_close(handle);
}

bool progress_directory_same(uintptr_t left, uintptr_t right)
{
    if (left == UINTPTR_MAX || right == UINTPTR_MAX)
        return false;
#if defined(_WIN32)
    BY_HANDLE_FILE_INFORMATION a;
    BY_HANDLE_FILE_INFORMATION b;
    return GetFileInformationByHandle((HANDLE)left, &a) != 0 &&
           GetFileInformationByHandle((HANDLE)right, &b) != 0 &&
           a.dwVolumeSerialNumber == b.dwVolumeSerialNumber &&
           a.nFileIndexHigh == b.nFileIndexHigh &&
           a.nFileIndexLow == b.nFileIndexLow;
#else
    struct stat a;
    struct stat b;
    return fstat((int)left, &a) == 0 && fstat((int)right, &b) == 0 &&
           a.st_dev == b.st_dev && a.st_ino == b.st_ino;
#endif
}

bool progress_directory_child_exists(uintptr_t handle, const char *child,
                                     bool *exists)
{
    if (handle == UINTPTR_MAX || !child || !child[0] || !exists) {
        fprintf(stderr,
                "[progress_directory] child_exists: invalid argument\n");
        return false;
    }

    struct platform_directory_transaction directory = {.native = handle};
    struct platform_directory_child opened;
    platform_directory_child_init(&opened);
    enum platform_directory_result result =
        platform_directory_child_open_result(&directory, child, false, false,
                                             &opened, NULL);
    if (result == PLATFORM_DIRECTORY_OK) {
        platform_directory_child_close(&opened);
        *exists = true;
        return true;
    }
    if (result == PLATFORM_DIRECTORY_MISSING) {
        *exists = false;
        return true;
    }
    /* Refusal still proves that the retained namespace contains something at
     * this leaf (for example a legacy file whose inherited ACL is not strict
     * enough to open as an authority-bearing child). Treat it as occupied so
     * callers refuse migration instead of mistaking hostile bytes for absence. */
    if (result == PLATFORM_DIRECTORY_REFUSED) {
        *exists = true;
        return true;
    }
    fprintf(stderr,
            "[progress_directory] child_exists: retained open failed "
            "child=%s result=%d\n", child, (int)result);
    return false;
}

bool progress_directory_matches_fd(uintptr_t handle, int fd)
{
#if defined(_WIN32)
    if (handle == UINTPTR_MAX || fd < 0)
        return false;
    HANDLE retained = (HANDLE)handle;
    HANDLE candidate = (HANDLE)_get_osfhandle(fd);
    if (candidate == INVALID_HANDLE_VALUE)
        return false;
    BY_HANDLE_FILE_INFORMATION a, b;
    FILE_ATTRIBUTE_TAG_INFO tag;
    return GetFileInformationByHandle(retained, &a) != 0 &&
           GetFileInformationByHandle(candidate, &b) != 0 &&
           a.dwVolumeSerialNumber == b.dwVolumeSerialNumber &&
           a.nFileIndexHigh == b.nFileIndexHigh &&
           a.nFileIndexLow == b.nFileIndexLow &&
           GetFileInformationByHandleEx(candidate, FileAttributeTagInfo,
                                        &tag, sizeof(tag)) != 0 &&
           (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
           (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
#else
    struct stat retained;
    struct stat candidate;
    return handle != UINTPTR_MAX && fd >= 0 &&
           fstat((int)handle, &retained) == 0 &&
           fstat(fd, &candidate) == 0 && S_ISDIR(retained.st_mode) &&
           S_ISDIR(candidate.st_mode) && retained.st_dev == candidate.st_dev &&
           retained.st_ino == candidate.st_ino;
#endif
}
