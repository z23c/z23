/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: UTF-8 directory operations across POSIX and Win32. */

#ifndef ZCL_PLATFORM_DIRECTORY_COMPAT_H
#define ZCL_PLATFORM_DIRECTORY_COMPAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct platform_directory_entry {
    char *name;
    /* Handle-bound directory enumeration metadata.  Windows obtains these
     * fields from FILE_ID_BOTH_DIR_INFORMATION on one retained directory
     * handle; POSIX obtains them with fstatat() on the opened directory.
     * Callers that need an exact freshness key must require snapshot_valid. */
    bool snapshot_valid;
    uint64_t size;
    int64_t modified_seconds;
    uint32_t modified_nanoseconds;
    int64_t changed_seconds;
    uint32_t changed_nanoseconds;
    uint64_t volume;
    uint64_t file_low;
    uint64_t file_high;
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

/* Return real, immediate child regular files in bytewise name order with a
 * valid metadata snapshot for every entry. Symbolic links and Windows reparse
 * points are omitted. */
bool platform_directory_list_regular_sorted(
    const char *path, struct platform_directory_list *out);

/* Return real immediate directories and regular files from one retained
 * directory enumeration.  This is the freshness-scan path: opening and
 * walking a large tree twice on Windows is observable latency, while one
 * handle-bound FILE_ID_BOTH_DIR_INFORMATION stream already carries both the
 * child kind and the exact regular-file metadata.  Both lists are sorted
 * independently and own their entries. */
bool platform_directory_list_children_sorted(
    const char *path, struct platform_directory_list *directories,
    struct platform_directory_list *files);
void platform_directory_list_free(struct platform_directory_list *list);

#endif
