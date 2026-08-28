/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: safe file opens, positioned reads, and owner locks across hosts. */

#ifndef ZCL_PLATFORM_FILE_COMPAT_H
#define ZCL_PLATFORM_FILE_COMPAT_H

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#if defined(_WIN32)
#include <windows.h>
#include <io.h>

struct platform_file_identity {
    uint64_t volume;
    uint64_t file;
    uint64_t size;
    uint64_t write_time;
};

static inline bool platform_file_identity_read(
    int fd, struct platform_file_identity *out)
{
    if (!out) return false;
    intptr_t raw = _get_osfhandle(fd);
    BY_HANDLE_FILE_INFORMATION info;
    if (raw == -1 || !GetFileInformationByHandle((HANDLE)raw, &info))
        return false;
    out->volume = info.dwVolumeSerialNumber;
    out->file = ((uint64_t)info.nFileIndexHigh << 32) | info.nFileIndexLow;
    out->size = ((uint64_t)info.nFileSizeHigh << 32) | info.nFileSizeLow;
    out->write_time = ((uint64_t)info.ftLastWriteTime.dwHighDateTime << 32) |
                      info.ftLastWriteTime.dwLowDateTime;
    return true;
}

static inline bool platform_file_utf8_path(const char *path,
                                           wchar_t out[32768])
{
    if (!path || !path[0]) {
        errno = EINVAL;
        return false;
    }
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                                    out, 32768);
    if (count <= 0) {
        errno = EINVAL;
        return false;
    }
    return true;
}

static inline int platform_file_open_nofollow(const char *path, int flags,
                                               int mode)
{
    wchar_t wide[32768];
    if (!platform_file_utf8_path(path, wide))
        return -1;
    DWORD access = (flags & O_RDWR) ? (GENERIC_READ | GENERIC_WRITE) :
                   (flags & O_WRONLY) ? GENERIC_WRITE : GENERIC_READ;
    DWORD creation = OPEN_EXISTING;
    if ((flags & O_CREAT) && (flags & O_EXCL)) creation = CREATE_NEW;
    else if (flags & O_TRUNC) creation = CREATE_ALWAYS;
    else if (flags & O_CREAT) creation = OPEN_ALWAYS;
    HANDLE handle = CreateFileW(wide, access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, creation,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        errno = GetLastError() == ERROR_FILE_NOT_FOUND ? ENOENT : EACCES;
        return -1;
    }
    FILE_ATTRIBUTE_TAG_INFO tag;
    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag,
                                      sizeof(tag)) ||
        (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        CloseHandle(handle);
        errno = ELOOP;
        return -1;
    }
    int crt_flags = (flags & O_RDWR) ? O_RDWR :
                    (flags & O_WRONLY) ? O_WRONLY : O_RDONLY;
    crt_flags |= O_BINARY;
    int fd = _open_osfhandle((intptr_t)handle, crt_flags);
    if (fd < 0) {
        CloseHandle(handle);
        return -1;
    }
    (void)mode;
    return fd;
}

static inline int platform_file_replace_atomic(const char *source,
                                               const char *destination)
{
    wchar_t source_wide[32768];
    wchar_t destination_wide[32768];
    if (!platform_file_utf8_path(source, source_wide) ||
        !platform_file_utf8_path(destination, destination_wide))
        return -1;
    if (MoveFileExW(source_wide, destination_wide,
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        return 0;
    errno = GetLastError() == ERROR_ACCESS_DENIED ? EACCES : EIO;
    return -1;
}

static inline int platform_file_lock_exclusive(int fd)
{
    intptr_t raw = _get_osfhandle(fd);
    if (raw == -1) {
        errno = EBADF;
        return -1;
    }
    OVERLAPPED overlap = { 0 };
    if (LockFileEx((HANDLE)raw,
                   LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                   0, 1, 0, &overlap))
        return 0;
    DWORD error = GetLastError();
    errno = error == ERROR_LOCK_VIOLATION ? EWOULDBLOCK : EIO;
    return -1;
}

static inline int platform_file_unlock(int fd)
{
    intptr_t raw = _get_osfhandle(fd);
    if (raw == -1) {
        errno = EBADF;
        return -1;
    }
    OVERLAPPED overlap = { 0 };
    if (UnlockFileEx((HANDLE)raw, 0, 1, 0, &overlap))
        return 0;
    errno = EIO;
    return -1;
}

static inline ssize_t platform_file_pread(int fd, void *buffer, size_t count,
                                          int64_t offset)
{
    intptr_t raw = _get_osfhandle(fd);
    if (raw == -1 || count > UINT32_MAX || offset < 0) {
        errno = EINVAL;
        return -1;
    }
    LARGE_INTEGER position;
    position.QuadPart = offset;
    if (!SetFilePointerEx((HANDLE)raw, position, NULL, FILE_BEGIN)) {
        errno = EIO;
        return -1;
    }
    DWORD read_count = 0;
    if (!ReadFile((HANDLE)raw, buffer, (DWORD)count, &read_count, NULL)) {
        errno = EIO;
        return -1;
    }
    return (ssize_t)read_count;
}
#else
#include <sys/file.h>
#include <unistd.h>

struct platform_file_identity {
    uint64_t volume;
    uint64_t file;
    uint64_t size;
    uint64_t write_time;
};

static inline bool platform_file_identity_read(
    int fd, struct platform_file_identity *out)
{
    struct stat st;
    if (!out || fstat(fd, &st) != 0)
        return false;
    out->volume = (uint64_t)st.st_dev;
    out->file = (uint64_t)st.st_ino;
    out->size = (uint64_t)st.st_size;
    out->write_time = ((uint64_t)st.st_mtim.tv_sec << 32) ^
                      (uint32_t)st.st_mtim.tv_nsec;
    return true;
}

static inline int platform_file_open_nofollow(const char *path, int flags,
                                               int mode)
{
    return open(path, flags | O_CLOEXEC | O_NOFOLLOW, (mode_t)mode);
}

static inline int platform_file_replace_atomic(const char *source,
                                               const char *destination)
{
    return rename(source, destination);
}

static inline int platform_file_lock_exclusive(int fd)
{
    return flock(fd, LOCK_EX | LOCK_NB);
}

static inline int platform_file_unlock(int fd)
{
    return flock(fd, LOCK_UN);
}

static inline ssize_t platform_file_pread(int fd, void *buffer, size_t count,
                                          int64_t offset)
{
    return pread(fd, buffer, count, (off_t)offset);
}
#endif

#endif
