/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Small path and text checks shared by command units, so each unit does not
 * carry its own copy. Every function refuses rather than truncates.
 */
#ifndef ZCL_UTIL_PATH_UTIL_H
#define ZCL_UTIL_PATH_UTIL_H

#include <stddef.h>

/* Write "a/b" into out. False when an argument is NULL or the joined path
 * does not fit in cap bytes. */
bool zcl_path_join(char *out, size_t cap, const char *a, const char *b);

/* True when path names a directory; stat(2) follows symlinks. */
bool zcl_path_is_dir(const char *path);

/* True when s is exactly len characters of lowercase hexadecimal. */
bool zcl_is_lower_hex(const char *s, size_t len);

#endif
