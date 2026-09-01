/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: caller-available filesystem capacity for UTF-8 paths. */
#ifndef ZCL_PLATFORM_DISK_SPACE_H
#define ZCL_PLATFORM_DISK_SPACE_H

#include <stdbool.h>
#include <stdint.h>

/* Report bytes available to the current user, not total volume free bytes.
 * Returns false for invalid, missing, or inaccessible paths and on arithmetic
 * overflow. */
bool platform_disk_space_available(const char *utf8_path,
                                   uint64_t *available_bytes);

#endif
