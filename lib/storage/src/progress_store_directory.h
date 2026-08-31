/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private retained-directory capability operations for progress_store. */
#ifndef ZCL_STORAGE_PROGRESS_STORE_DIRECTORY_H
#define ZCL_STORAGE_PROGRESS_STORE_DIRECTORY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool progress_directory_open(const char *directory, const char *child,
                             char *path, size_t path_size, uintptr_t *handle);
void progress_directory_close(uintptr_t handle);
bool progress_directory_same(uintptr_t left, uintptr_t right);
bool progress_directory_child_exists(uintptr_t handle, const char *child,
                                     bool *exists);
bool progress_directory_matches_fd(uintptr_t handle, int fd);

#endif
