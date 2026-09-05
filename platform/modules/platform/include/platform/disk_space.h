/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: caller-available filesystem capacity for UTF-8 paths. */
#ifndef ZCL_PLATFORM_DISK_SPACE_H
#define ZCL_PLATFORM_DISK_SPACE_H

#include <stdbool.h>
#include <stdint.h>

/* Available bytes, and volume size when `total_bytes` is non-NULL. Either
 * out pointer may be NULL. False on invalid path or overflow. */
bool platform_disk_space(const char *utf8_path, uint64_t *available_bytes,
                         uint64_t *total_bytes);

/* Available bytes to the current user. False on invalid path or overflow. */
bool platform_disk_space_available(const char *utf8_path,
                                   uint64_t *available_bytes);

#endif
