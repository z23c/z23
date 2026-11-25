/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: expose a boot-scoped invalidation identity. */
#ifndef ZCL_PLATFORM_OS_BOOT_H
#define ZCL_PLATFORM_OS_BOOT_H

#include <stdbool.h>
#include <stddef.h>

/* Normalize exactly 36 nonzero boot UUID bytes into 37 bytes, in place if
 * needed; syntax alone does not establish identity. Both clear out on failure.
 * The boot identity is unavailable on unsupported platforms; it is an
 * invalidation token, not authentication. */
bool os_proc_boot_id_normalize(const char *text, size_t len, char out[37]);
bool os_proc_boot_id(char out[37]);

#endif
