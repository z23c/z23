/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: share portable package-store path and file-identity operations. */

#ifndef ZCL_VCS_PACKAGE_FILE_IO_H
#define ZCL_VCS_PACKAGE_FILE_IO_H

#include "platform/positioned_file.h"

#include <stdbool.h>
#include <stddef.h>

bool vcs_package_file_exists(const char *path);
bool vcs_package_name_is_hex64(const char *name);
bool vcs_package_child_path(char *out, size_t out_size,
                            const char *root, const char *child);

#endif
