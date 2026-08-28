/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Concurrent cursor-free reads from one verified regular file. */
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

void platform_positioned_file_init(struct platform_positioned_file *file);
bool platform_positioned_file_open(struct platform_positioned_file *file,
                                   const char *utf8_path);
void platform_positioned_file_close(struct platform_positioned_file *file);
bool platform_positioned_file_size(const struct platform_positioned_file *file,
                                   uint64_t *size);

/* Return bytes read (zero at EOF), or -1 on invalid input/I/O failure.  A
 * successful short read is preserved for callers that deliberately race an
 * appending or truncating producer. */
int64_t platform_positioned_file_read(
    const struct platform_positioned_file *file, void *data, size_t size,
    uint64_t offset);

#endif
