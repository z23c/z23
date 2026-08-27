/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Win32 file mappings behind the project's existing mmap contract. */

#ifndef ZCL_PLATFORM_SYS_MMAN_H
#define ZCL_PLATFORM_SYS_MMAN_H

#if !defined(_WIN32)
#if defined(__GNUC__)
#pragma GCC system_header
#endif
#include_next <sys/mman.h>
#else

#include <errno.h>
#include <io.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <windows.h>

#define PROT_NONE  0x0
#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

#define MAP_SHARED    0x01
#define MAP_PRIVATE   0x02
#define MAP_FIXED     0x10
#define MAP_ANONYMOUS 0x20
#define MAP_ANON MAP_ANONYMOUS
#define MAP_FAILED ((void *)-1)

#define MS_ASYNC      0x01
#define MS_INVALIDATE 0x02
#define MS_SYNC       0x04

#define MADV_NORMAL     0
#define MADV_RANDOM     1
#define MADV_SEQUENTIAL 2
#define MADV_WILLNEED   3
#define MADV_DONTNEED   4

struct platform_mmap_view {
    void *address;
    void *base;
    size_t length;
};

static SRWLOCK platform_mmap_lock = SRWLOCK_INIT;
static struct platform_mmap_view platform_mmap_views[256];

static inline DWORD platform_mmap_protection(int protection, int flags)
{
    bool write = (protection & PROT_WRITE) != 0;
    bool execute = (protection & PROT_EXEC) != 0;
    bool copy = (flags & MAP_PRIVATE) != 0 && write;
    if (execute)
        return copy ? PAGE_EXECUTE_WRITECOPY
                    : (write ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ);
    return copy ? PAGE_WRITECOPY : (write ? PAGE_READWRITE : PAGE_READONLY);
}

static inline DWORD platform_mmap_access(int protection, int flags)
{
    DWORD access = (protection & PROT_WRITE) != 0
        ? ((flags & MAP_PRIVATE) != 0 ? FILE_MAP_COPY : FILE_MAP_WRITE)
        : FILE_MAP_READ;
    if ((protection & PROT_EXEC) != 0)
        access |= FILE_MAP_EXECUTE;
    return access;
}

static inline void *mmap(void *requested, size_t length, int protection,
                         int flags, int fd, off_t offset)
{
    if (length == 0 || offset < 0 || (flags & MAP_FIXED) != 0) {
        errno = EINVAL;
        return MAP_FAILED;
    }
    SYSTEM_INFO system_info;
    GetSystemInfo(&system_info);
    uint64_t granularity = system_info.dwAllocationGranularity;
    uint64_t requested_offset = (uint64_t)offset;
    uint64_t aligned_offset = requested_offset - requested_offset % granularity;
    size_t delta = (size_t)(requested_offset - aligned_offset);
    if (length > SIZE_MAX - delta) {
        errno = EOVERFLOW;
        return MAP_FAILED;
    }
    size_t mapped_length = length + delta;
    HANDLE file = INVALID_HANDLE_VALUE;
    if ((flags & MAP_ANONYMOUS) == 0) {
        intptr_t raw = _get_osfhandle(fd);
        if (raw == -1) {
            errno = EBADF;
            return MAP_FAILED;
        }
        file = (HANDLE)raw;
    }
    uint64_t maximum = (flags & MAP_ANONYMOUS) != 0 ? mapped_length : 0;
    HANDLE mapping = CreateFileMappingW(
        file, NULL, platform_mmap_protection(protection, flags),
        (DWORD)(maximum >> 32), (DWORD)maximum, NULL);
    if (!mapping) {
        errno = EIO;
        return MAP_FAILED;
    }
    void *base = MapViewOfFileEx(
        mapping, platform_mmap_access(protection, flags),
        (DWORD)(aligned_offset >> 32), (DWORD)aligned_offset, mapped_length,
        requested);
    CloseHandle(mapping);
    if (!base) {
        errno = ENOMEM;
        return MAP_FAILED;
    }
    void *address = (unsigned char *)base + delta;
    bool stored = false;
    AcquireSRWLockExclusive(&platform_mmap_lock);
    for (size_t i = 0; i < sizeof(platform_mmap_views) /
                            sizeof(platform_mmap_views[0]); i++) {
        if (!platform_mmap_views[i].address) {
            platform_mmap_views[i] = (struct platform_mmap_view) {
                .address = address, .base = base, .length = mapped_length,
            };
            stored = true;
            break;
        }
    }
    ReleaseSRWLockExclusive(&platform_mmap_lock);
    if (!stored) {
        UnmapViewOfFile(base);
        errno = EMFILE;
        return MAP_FAILED;
    }
    return address;
}

static inline int munmap(void *address, size_t length)
{
    (void)length;
    void *base = NULL;
    AcquireSRWLockExclusive(&platform_mmap_lock);
    for (size_t i = 0; i < sizeof(platform_mmap_views) /
                            sizeof(platform_mmap_views[0]); i++) {
        if (platform_mmap_views[i].address == address) {
            base = platform_mmap_views[i].base;
            platform_mmap_views[i] = (struct platform_mmap_view) { 0 };
            break;
        }
    }
    ReleaseSRWLockExclusive(&platform_mmap_lock);
    if (!base || !UnmapViewOfFile(base)) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static inline int msync(void *address, size_t length, int flags)
{
    (void)flags;
    if (FlushViewOfFile(address, length))
        return 0;
    errno = EIO;
    return -1;
}

static inline int mprotect(void *address, size_t length, int protection)
{
    DWORD old_protection = 0;
    if (VirtualProtect(address, length,
                       platform_mmap_protection(protection, MAP_SHARED),
                       &old_protection))
        return 0;
    errno = EACCES;
    return -1;
}

static inline int mlock(const void *address, size_t length)
{
    if (VirtualLock((void *)address, length))
        return 0;
    errno = ENOMEM;
    return -1;
}

static inline int munlock(const void *address, size_t length)
{
    if (VirtualUnlock((void *)address, length))
        return 0;
    errno = EINVAL;
    return -1;
}

static inline int madvise(void *address, size_t length, int advice)
{
    (void)address;
    (void)length;
    (void)advice;
    return 0;
}

#endif
#endif
