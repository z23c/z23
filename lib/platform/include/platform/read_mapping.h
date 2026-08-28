/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Read-only whole-file mappings backed by an already-open file descriptor. */

#ifndef ZCL_PLATFORM_READ_MAPPING_H
#define ZCL_PLATFORM_READ_MAPPING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct platform_read_mapping {
    const uint8_t *data;
    size_t size;
    void *native_mapping;
};

void platform_read_mapping_init(struct platform_read_mapping *mapping);

/* Map exactly size bytes from offset zero.  The caller must keep fd open until
 * platform_read_mapping_close().  A zero-byte mapping is rejected. */
bool platform_read_mapping_open(struct platform_read_mapping *mapping,
                                int fd, size_t size);

void platform_read_mapping_close(struct platform_read_mapping *mapping);

#endif
