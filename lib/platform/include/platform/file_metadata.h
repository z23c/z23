/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Race-aware UTF-8 pathname metadata for regular files. */
#ifndef ZCL_PLATFORM_FILE_METADATA_H
#define ZCL_PLATFORM_FILE_METADATA_H

#include <stdint.h>

enum platform_file_metadata_result {
    PLATFORM_FILE_METADATA_OK = 0,
    PLATFORM_FILE_METADATA_MISSING,
    PLATFORM_FILE_METADATA_REPARSE,
    PLATFORM_FILE_METADATA_NOT_REGULAR,
    PLATFORM_FILE_METADATA_REFUSED,
};

struct platform_file_metadata {
    uint64_t size;
    int64_t modified_seconds;
};

/* Open the named object without following a final symlink/reparse point and
 * report metadata only when it is a regular file. Missing, reparse points,
 * other object shapes, and unreadable paths retain distinct verdicts. */
enum platform_file_metadata_result platform_file_metadata_read(
    const char *utf8_path, struct platform_file_metadata *out);

#endif
