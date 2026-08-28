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

/* What kind of object a pathname names, without following a final
 * symlink/reparse point. */
enum platform_file_shape {
    PLATFORM_FILE_SHAPE_MISSING = 0,
    PLATFORM_FILE_SHAPE_REGULAR,
    PLATFORM_FILE_SHAPE_SYMLINK,
    /* Exists and is neither a regular file nor a symlink: a directory,
     * device, FIFO, or socket. */
    PLATFORM_FILE_SHAPE_OTHER,
    /* Exists (or may exist) but could not be classified — a permission or
     * I/O failure. Never reported as MISSING: "nobody put anything here" and
     * "something is here that we could not look at" are different facts and
     * a caller that conflates them publishes a wrong observation. */
    PLATFORM_FILE_SHAPE_UNREADABLE,
};

/* Classify utf8_path. This answers WHY a handle-based open refused, for
 * reporting only: the refusal itself must already have been taken on the
 * handle, because a pathname re-probe is inherently racy. */
enum platform_file_shape platform_file_shape_read(const char *utf8_path);

#endif
