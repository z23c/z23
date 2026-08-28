/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: UTF-8 directory operations across POSIX and Win32. */

#ifndef ZCL_PLATFORM_DIRECTORY_COMPAT_H
#define ZCL_PLATFORM_DIRECTORY_COMPAT_H

#include <stdbool.h>
#include <stddef.h>

struct platform_directory_entry {
    char *name;
};

struct platform_directory_list {
    struct platform_directory_entry *entries;
    size_t count;
};

enum platform_directory_probe_result {
    PLATFORM_DIRECTORY_PROBE_OK = 0,
    PLATFORM_DIRECTORY_PROBE_MISSING,
    PLATFORM_DIRECTORY_PROBE_REFUSED,
};

/* Classify an existing real directory without creating it. Symlinks and
 * reparse points are refused. */
enum platform_directory_probe_result platform_directory_probe_real(
    const char *path);

/* Resolve an existing real directory to a canonical UTF-8 absolute path.
 * Windows rejects reparse points at every traversed component. */
bool platform_directory_canonical_real(const char *path, char *out,
                                       size_t out_size);

int platform_directory_create(const char *path, int mode);

/* Create path if absent and prove the resulting object is a real directory.
 * Symbolic links and Windows reparse points are refused. */
bool platform_directory_ensure(const char *path, int mode);

/* Return real, immediate child directories in bytewise name order. Dot
 * entries, symbolic links, and Windows reparse points are omitted. */
bool platform_directory_list_real_sorted(const char *path,
                                         struct platform_directory_list *out);

/* Return real, immediate child regular files in bytewise name order.
 * Symbolic links and Windows reparse points are omitted. */
bool platform_directory_list_regular_sorted(
    const char *path, struct platform_directory_list *out);
void platform_directory_list_free(struct platform_directory_list *list);

#endif
