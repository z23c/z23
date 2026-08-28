/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Bounded descriptor-relative reads beneath a trusted root. */
#ifndef ZCL_PLATFORM_SAFE_ROOT_READ_H
#define ZCL_PLATFORM_SAFE_ROOT_READ_H

#include <stddef.h>
#include <stdint.h>

enum platform_safe_root_read_result {
    PLATFORM_SAFE_ROOT_READ_OK = 0,
    PLATFORM_SAFE_ROOT_READ_NOT_FOUND,
    PLATFORM_SAFE_ROOT_READ_FORBIDDEN,
    PLATFORM_SAFE_ROOT_READ_TOO_LARGE,
    PLATFORM_SAFE_ROOT_READ_IO_ERROR
};

/* Read one regular file beneath root without following symlinks or Windows
 * reparse points. rel_utf8 must be a slash-separated relative UTF-8 path.
 * On success *data is malloc-owned (also for an empty file) and *size is set.
 */
enum platform_safe_root_read_result platform_safe_root_read(
    const char *root_utf8, const char *rel_utf8, size_t maximum,
    uint8_t **data, size_t *size);

#endif
