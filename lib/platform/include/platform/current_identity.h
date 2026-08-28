/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef ZCL_PLATFORM_CURRENT_IDENTITY_H
#define ZCL_PLATFORM_CURRENT_IDENTITY_H

#include <stdbool.h>
#include <stddef.h>

/* Stable, diagnostic-only identity for the account running this process.
 * Windows returns its SID; POSIX returns its numeric effective UID. */
bool platform_current_identity(char *out, size_t out_size);

#endif
