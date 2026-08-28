/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Read-only mappings backed by an already-open descriptor. */

#include "platform/read_mapping.h"
#include "platform/positioned_file.h"

#include <limits.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <io.h>

#else
#include <sys/mman.h>
#endif

void platform_read_mapping_init(struct platform_read_mapping *mapping)
{
    if (!mapping) return;
    mapping->data = NULL;
    mapping->size = 0;
    mapping->native_mapping = NULL;
}

bool platform_read_mapping_open(struct platform_read_mapping *mapping,
                                int fd, size_t size)
{
    if (!mapping || fd < 0 || size == 0) return false;
    platform_read_mapping_close(mapping);

#if defined(_WIN32)
    intptr_t raw_handle = _get_osfhandle(fd);
    if (raw_handle == -1) return false;
    HANDLE section = CreateFileMappingW((HANDLE)raw_handle, NULL,
                                        PAGE_READONLY, 0, 0, NULL);
    if (!section) return false;
    const uint8_t *view = (const uint8_t *)MapViewOfFile(
        section, FILE_MAP_READ, 0, 0, size);
    if (!view) {
        CloseHandle(section);
        return false;
    }
    mapping->native_mapping = section;
    mapping->data = view;
#else
    void *view = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (view == MAP_FAILED) return false;
    mapping->data = (const uint8_t *)view;
#endif
    mapping->size = size;
    return true;
}

bool platform_read_mapping_open_positioned(
    struct platform_read_mapping *mapping,
    const struct platform_positioned_file *file, size_t size)
{
    if (!file) return false;
#if defined(_WIN32)
    if (!mapping || file->native == (uintptr_t)INVALID_HANDLE_VALUE ||
        size == 0)
        return false;
    platform_read_mapping_close(mapping);
    HANDLE section = CreateFileMappingW((HANDLE)file->native, NULL,
                                        PAGE_READONLY, 0, 0, NULL);
    if (!section) return false;
    const uint8_t *view = MapViewOfFile(section, FILE_MAP_READ, 0, 0, size);
    if (!view) {
        CloseHandle(section);
        return false;
    }
    mapping->native_mapping = section;
    mapping->data = view;
    mapping->size = size;
    return true;
#else
    return platform_read_mapping_open(mapping, (int)file->native, size);
#endif
}

void platform_read_mapping_advise_sequential(
    const struct platform_read_mapping *mapping)
{
    if (!mapping || !mapping->data || mapping->size == 0) return;
#if defined(_WIN32)
    /* Resolve this Windows 8+ API dynamically so older MinGW header feature
     * levels do not decide whether this implementation compiles. */
    struct platform_win_memory_range_entry {
        PVOID virtual_address;
        SIZE_T number_of_bytes;
    };
    typedef BOOL (WINAPI *prefetch_virtual_memory_fn)(
        HANDLE, ULONG_PTR,
        const struct platform_win_memory_range_entry *, ULONG);
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    FARPROC symbol = kernel ? GetProcAddress(kernel, "PrefetchVirtualMemory")
                            : NULL;
    prefetch_virtual_memory_fn prefetch = NULL;
    static_assert(sizeof(prefetch) == sizeof(symbol),
                  "Windows function pointer representations must match");
    memcpy(&prefetch, &symbol, sizeof(prefetch));
    if (prefetch) {
        struct platform_win_memory_range_entry range = {
            .virtual_address = (PVOID)mapping->data,
            .number_of_bytes = mapping->size,
        };
        (void)prefetch(GetCurrentProcess(), 1, &range, 0);
    }
#else
    (void)posix_madvise((void *)mapping->data, mapping->size,
                        POSIX_MADV_SEQUENTIAL);
    (void)posix_madvise((void *)mapping->data, mapping->size,
                        POSIX_MADV_WILLNEED);
#endif
}

void platform_read_mapping_close(struct platform_read_mapping *mapping)
{
    if (!mapping) return;
    if (mapping->data) {
#if defined(_WIN32)
        (void)UnmapViewOfFile(mapping->data);
#else
        (void)munmap((void *)mapping->data, mapping->size);
#endif
    }
#if defined(_WIN32)
    if (mapping->native_mapping)
        (void)CloseHandle((HANDLE)mapping->native_mapping);
#endif
    platform_read_mapping_init(mapping);
}
