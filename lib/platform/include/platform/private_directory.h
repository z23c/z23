/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private, no-link directory creation and validation. */
#ifndef ZCL_PLATFORM_PRIVATE_DIRECTORY_H
#define ZCL_PLATFORM_PRIVATE_DIRECTORY_H

#include <stdbool.h>

/* Create path if absent and prove it is owned by the current user, is not a
 * symlink/reparse point, and grants access only to that user and SYSTEM.
 * POSIX enforces an equivalent owner-only mode 0700 directory. */
bool platform_private_directory_ensure(const char *utf8_path);

#endif
