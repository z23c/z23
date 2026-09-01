/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: atomic publication of a staged file over an existing pathname,
 * with UTF-8 and long-path support on Windows. */

#ifndef ZCL_PLATFORM_PATH_REPLACE_H
#define ZCL_PLATFORM_PATH_REPLACE_H

/* Atomically rename staged_path onto destination_path, replacing an existing
 * destination. Both paths name files in the same filesystem. Returns zero on
 * success and -1 with errno set on failure. The staged path is consumed only
 * on success. */
int platform_path_replace(const char *staged_path,
                          const char *destination_path);

#endif
