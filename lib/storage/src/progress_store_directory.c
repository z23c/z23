/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Retained directory identity and child-path construction for progress_store. */
#include "progress_store_directory.h"
#include "platform/fd_path.h"
#include "platform/private_directory.h"
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(_WIN32)
#include <windows.h>
#endif

bool progress_directory_open(const char *directory, const char *child,
                             char *path, size_t path_size, uintptr_t *handle)
{
#if defined(_WIN32)
    if (!platform_private_directory_open_validated(directory, handle))
        return false;
    int length = snprintf(path, path_size, "%s/%s", directory, child);
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

bool progress_directory_matches_fd(uintptr_t handle, int fd)
{
#if defined(_WIN32)
    (void)handle;
    (void)fd;
    return false;
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
