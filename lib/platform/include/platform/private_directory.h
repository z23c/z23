/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private, no-link directory creation and validation. */
#ifndef ZCL_PLATFORM_PRIVATE_DIRECTORY_H
#define ZCL_PLATFORM_PRIVATE_DIRECTORY_H

#include <stdbool.h>
#include <stdint.h>

/* Create path if absent and prove it is owned by the current user, is not a
 * symlink/reparse point, and grants access only to that user and SYSTEM.
 * POSIX enforces an equivalent owner-only mode 0700 directory. */
bool platform_private_directory_ensure(const char *utf8_path);
/* Create a new owner-private directory, refusing an existing path. */
bool platform_private_directory_create(const char *utf8_path);
/* Atomically publish a private staged directory without replacing anything
 * already present at destination. */
bool platform_private_directory_publish_no_clobber(
    const char *staging_utf8, const char *destination_utf8);
bool platform_private_directory_remove_empty(const char *utf8_path);

/* Open, validate, and return the exact owner-private no-link directory object.
 * The caller retains this capability until platform_private_directory_close. */
bool platform_private_directory_open_validated(const char *utf8_path,
                                               uintptr_t *native_handle);
/* Open the same validated object with traverse/read authority only.  This is
 * the retained RootDirectory form required by Windows relative namespace
 * operations; callers that flush the directory must use the full form. */
bool platform_private_directory_open_validated_traverse(
    const char *utf8_path, uintptr_t *native_handle);
void platform_private_directory_close(uintptr_t native_handle);

#endif
