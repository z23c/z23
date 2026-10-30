/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Read-only mappings backed by an already-open descriptor. */

#ifndef ZCL_PLATFORM_READ_MAPPING_H
#define ZCL_PLATFORM_READ_MAPPING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct platform_positioned_file;

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
bool platform_read_mapping_open_positioned(
    struct platform_read_mapping *mapping,
    const struct platform_positioned_file *file, size_t size);

/* Hint that the whole mapping will be consumed in ascending address order.
 * This is advisory only: unsupported platforms and transient hint failures
 * leave the mapping valid and readable. */
void platform_read_mapping_advise_sequential(
    const struct platform_read_mapping *mapping);

/* Drop the resident pages of a consumed prefix.  `released` is the byte
 * boundary a previous call returned (zero first); the pages wholly below
 * `consumed` and at or above `released` are returned to the kernel and the
 * new page-aligned boundary is returned.  The mapping stays valid: a later
 * read of a dropped page faults it back in from the file.  The release runs
 * on Linux, including Android, and is a no-op elsewhere. */
size_t platform_read_mapping_release_below(
    const struct platform_read_mapping *mapping, size_t released,
    size_t consumed);

void platform_read_mapping_close(struct platform_read_mapping *mapping);

#endif
