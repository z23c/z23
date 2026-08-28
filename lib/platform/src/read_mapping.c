/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "platform/read_mapping.h"

#include <limits.h>

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
