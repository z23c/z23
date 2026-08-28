/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: exclusive-create, lock, and durable-retire operations on a
 * single private file, portable across POSIX and Windows. */
#ifndef ZCL_PLATFORM_PRIVATE_FILE_H
#define ZCL_PLATFORM_PRIVATE_FILE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct platform_private_file {
  uintptr_t native;
  bool locked;
};

struct platform_private_file_identity {
  uint64_t volume;
  uint64_t file;
};

void platform_private_file_init(struct platform_private_file *file);
bool platform_private_file_create(const char *path,
                                  struct platform_private_file *file);
bool platform_private_file_open_locked(const char *path,
                                       struct platform_private_file *file);
void platform_private_file_close(struct platform_private_file *file);
bool platform_private_file_size(struct platform_private_file *file,
                                uint64_t *size);
bool platform_private_file_truncate(struct platform_private_file *file,
                                    uint64_t size);
bool platform_private_file_read_at(struct platform_private_file *file,
                                   void *data, size_t size, uint64_t offset);
bool platform_private_file_write_at(struct platform_private_file *file,
                                    const void *data, size_t size,
                                    uint64_t offset);
bool platform_private_file_flush(struct platform_private_file *file);
bool platform_private_file_replace(struct platform_private_file *file,
                                   const char *staging_path,
                                   const char *destination_path);
bool platform_private_file_retire(struct platform_private_file *file,
                                  const char *path);
bool platform_private_file_identity(struct platform_private_file *file,
                                    struct platform_private_file_identity *id);

/* Resolve an existing absolute parent and append the original leaf. */
bool platform_private_path_resolve(const char *path, char *resolved,
                                   size_t resolved_size, char *parent,
                                   size_t parent_size);
bool platform_private_path_absent(const char *path);
bool platform_private_file_link_no_clobber(
    const char *source, const char *destination,
    const struct platform_private_file_identity *source_identity,
    bool *already_same);
bool platform_private_file_unlink_missing_ok(const char *path);
bool platform_private_parent_flush(const char *parent);

#endif
