/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: name the OS account running this process as one printable string --
 * "sid:S-1-5-…" on Windows, "uid:1000" on POSIX -- so a refusal can report
 * WHO was refused. Diagnostic only; never an authorization input. */
#ifndef ZCL_PLATFORM_CURRENT_IDENTITY_H
#define ZCL_PLATFORM_CURRENT_IDENTITY_H

#include <stdbool.h>
#include <stddef.h>

/* Stable, diagnostic-only identity for the account running this process.
 * Windows returns its SID; POSIX returns its numeric effective UID. */
bool platform_current_identity(char *out, size_t out_size);

#endif
