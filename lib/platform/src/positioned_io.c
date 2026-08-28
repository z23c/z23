/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Implement cursor-independent writes on supported host platforms. */
#include "platform/positioned_io.h"

#include <limits.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <io.h>

int64_t platform_positioned_write(int fd, const void *data, size_t size,
                                  uint64_t offset)
{
    if (fd < 0 || (!data && size) || size > UINT32_MAX || offset > INT64_MAX)
        return -1;
    if (!size) return 0;
    intptr_t native = _get_osfhandle(fd);
    if (native == -1) return -1;
    HANDLE positioned = ReOpenFile((HANDLE)native, GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_FLAG_OVERLAPPED);
    if (positioned == INVALID_HANDLE_VALUE) return -1;
    OVERLAPPED operation = {0};
    operation.Offset = (DWORD)offset;
    operation.OffsetHigh = (DWORD)(offset >> 32);
    operation.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!operation.hEvent) { CloseHandle(positioned); return -1; }
    DWORD wrote = 0;
    BOOL ok = WriteFile(positioned, data, (DWORD)size, &wrote, &operation);
    if (!ok && GetLastError() == ERROR_IO_PENDING)
        ok = GetOverlappedResult(positioned, &operation, &wrote, TRUE);
    CloseHandle(operation.hEvent);
    CloseHandle(positioned);
    return ok ? (int64_t)wrote : -1;
}

#else
#include <sys/types.h>
#include <unistd.h>

int64_t platform_positioned_write(int fd, const void *data, size_t size,
                                  uint64_t offset)
{
    if (fd < 0 || (!data && size) || offset > INT64_MAX ||
        size > (size_t)SSIZE_MAX)
        return -1;
    ssize_t wrote = pwrite(fd, data, size, (off_t)offset);
    return wrote < 0 ? -1 : (int64_t)wrote;
}
#endif
