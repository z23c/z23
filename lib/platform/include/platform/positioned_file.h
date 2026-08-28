/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef ZCL_PLATFORM_POSITIONED_FILE_H
#define ZCL_PLATFORM_POSITIONED_FILE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A read-only regular file whose reads carry their own byte offset.  Multiple
 * threads may read one instance concurrently without sharing or changing a
 * seek cursor. */
struct platform_positioned_file {
    uintptr_t native;
};

/* Handle-bound metadata used to prove that content and metadata came from
 * one regular file, even when its pathname is concurrently replaced. */
struct platform_positioned_file_snapshot {
    uint64_t size;
    int64_t modified_seconds;
    uint32_t modified_nanoseconds;
    int64_t changed_seconds;
    uint32_t changed_nanoseconds;
    uint64_t volume;
    uint64_t file_low;
    uint64_t file_high;
};

void platform_positioned_file_init(struct platform_positioned_file *file);
bool platform_positioned_file_open(struct platform_positioned_file *file,
                                   const char *utf8_path);
/* Open one leaf relative to a trusted real directory without following a
 * symlink/reparse point at either boundary. */
bool platform_positioned_file_open_beneath(
    struct platform_positioned_file *file, const char *root_utf8,
    const char *leaf_utf8);
void platform_positioned_file_close(struct platform_positioned_file *file);
bool platform_positioned_file_size(const struct platform_positioned_file *file,
                                   uint64_t *size);
bool platform_positioned_file_snapshot(
    const struct platform_positioned_file *file,
    struct platform_positioned_file_snapshot *snapshot);
/* Return the canonical path of the opened object, bound to its handle. */
bool platform_positioned_file_path(
    const struct platform_positioned_file *file, char *utf8_path,
    size_t path_size);
/* True for a regular executable image. Windows validates the PE image magic;
 * POSIX additionally requires at least one execute permission bit. */
bool platform_positioned_file_is_executable(
    const struct platform_positioned_file *file);

/* Return bytes read (zero at EOF), or -1 on invalid input/I/O failure.  A
 * successful short read is preserved for callers that deliberately race an
 * appending or truncating producer. */
int64_t platform_positioned_file_read(
    const struct platform_positioned_file *file, void *data, size_t size,
    uint64_t offset);

#endif
