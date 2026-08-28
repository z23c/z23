/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "platform/positioned_file.h"

#include <errno.h>
#include <limits.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wchar.h>

static HANDLE positioned_handle(const struct platform_positioned_file *file)
{
    return file ? (HANDLE)file->native : INVALID_HANDLE_VALUE;
}

static bool positioned_wide(const char *utf8, wchar_t out[32768])
{
    if (!utf8 || !utf8[0]) return false;
    wchar_t plain[32768];
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1,
                                plain, 32768);
    if (n <= 0) return false;
    if (wcsncmp(plain, L"\\\\?\\", 4) == 0) {
        wmemcpy(out, plain, (size_t)n);
        return true;
    }
    if (plain[0] == L'\\' && plain[1] == L'\\') {
        if ((size_t)n + 6 >= 32768) return false;
        wmemcpy(out, L"\\\\?\\UNC\\", 8);
        wmemcpy(out + 8, plain + 2, (size_t)n - 2);
        return true;
    }
    if (plain[0] && plain[1] == L':' &&
        (plain[2] == L'\\' || plain[2] == L'/')) {
        if ((size_t)n + 4 >= 32768) return false;
        wmemcpy(out, L"\\\\?\\", 4);
        wmemcpy(out + 4, plain, (size_t)n);
        return true;
    }
    wmemcpy(out, plain, (size_t)n);
    return true;
}

void platform_positioned_file_init(struct platform_positioned_file *file)
{
    if (file) file->native = (uintptr_t)INVALID_HANDLE_VALUE;
}

bool platform_positioned_file_open(struct platform_positioned_file *file,
                                   const char *path)
{
    wchar_t wide[32768];
    if (!file || !positioned_wide(path, wide)) return false;
    platform_positioned_file_close(file);
    HANDLE handle = CreateFileW(
        wide, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT |
            FILE_FLAG_OVERLAPPED,
        NULL);
    if (handle == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION info = {0};
    if (!GetFileInformationByHandle(handle, &info) ||
        (info.dwFileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        CloseHandle(handle);
        return false;
    }
    file->native = (uintptr_t)handle;
    return true;
}

void platform_positioned_file_close(struct platform_positioned_file *file)
{
    if (!file) return;
    HANDLE handle = positioned_handle(file);
    if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
    platform_positioned_file_init(file);
}

bool platform_positioned_file_size(const struct platform_positioned_file *file,
                                   uint64_t *size)
{
    LARGE_INTEGER value;
    HANDLE handle = positioned_handle(file);
    if (!size || handle == INVALID_HANDLE_VALUE ||
        !GetFileSizeEx(handle, &value) || value.QuadPart < 0)
        return false;
    *size = (uint64_t)value.QuadPart;
    return true;
}

int64_t platform_positioned_file_read(
    const struct platform_positioned_file *file, void *data, size_t size,
    uint64_t offset)
{
    HANDLE handle = positioned_handle(file);
    if (handle == INVALID_HANDLE_VALUE || (!data && size) ||
        size > UINT32_MAX || offset > INT64_MAX)
        return -1;
    if (!size) return 0;
    OVERLAPPED operation = {0};
    operation.Offset = (DWORD)offset;
    operation.OffsetHigh = (DWORD)(offset >> 32);
    operation.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!operation.hEvent) return -1;
    DWORD read = 0;
    BOOL ok = ReadFile(handle, data, (DWORD)size, &read, &operation);
    if (!ok && GetLastError() == ERROR_IO_PENDING)
        ok = GetOverlappedResult(handle, &operation, &read, TRUE);
    else if (!ok && GetLastError() == ERROR_HANDLE_EOF)
        ok = TRUE;
    CloseHandle(operation.hEvent);
    return ok ? (int64_t)read : -1;
}

#else

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void platform_positioned_file_init(struct platform_positioned_file *file)
{
    if (file) file->native = (uintptr_t)-1;
}

bool platform_positioned_file_open(struct platform_positioned_file *file,
                                   const char *path)
{
    if (!file || !path || !path[0]) return false;
    platform_positioned_file_close(file);
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return false;
    }
    file->native = (uintptr_t)fd;
    return true;
}

void platform_positioned_file_close(struct platform_positioned_file *file)
{
    if (!file) return;
    int fd = (int)file->native;
    if (fd >= 0) close(fd);
    platform_positioned_file_init(file);
}

bool platform_positioned_file_size(const struct platform_positioned_file *file,
                                   uint64_t *size)
{
    struct stat st;
    int fd = file ? (int)file->native : -1;
    if (!size || fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size < 0)
        return false;
    *size = (uint64_t)st.st_size;
    return true;
}

int64_t platform_positioned_file_read(
    const struct platform_positioned_file *file, void *data, size_t size,
    uint64_t offset)
{
    int fd = file ? (int)file->native : -1;
    if (fd < 0 || (!data && size) || offset > INT64_MAX || size > SSIZE_MAX)
        return -1;
    ssize_t result;
    do {
        result = pread(fd, data, size, (off_t)offset);
    } while (result < 0 && errno == EINTR);
    return (int64_t)result;
}

#endif
