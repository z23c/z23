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

int platform_directory_create(const char *path, int mode);

/* Create path if absent and prove the resulting object is a real directory.
 * Symbolic links and Windows reparse points are refused. */
bool platform_directory_ensure(const char *path, int mode);

/* Return real, immediate child directories in bytewise name order. Dot
 * entries, symbolic links, and Windows reparse points are omitted. */
bool platform_directory_list_real_sorted(const char *path,
                                         struct platform_directory_list *out);
void platform_directory_list_free(struct platform_directory_list *list);

#endif
