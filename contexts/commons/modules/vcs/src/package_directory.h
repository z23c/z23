/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: expose deterministic portable package-directory iteration. */

#ifndef ZCL_VCS_PACKAGE_DIRECTORY_H
#define ZCL_VCS_PACKAGE_DIRECTORY_H

#include "platform/directory_compat.h"

struct vcs_package_directory {
    struct platform_directory_list list;
    size_t next;
};

bool vcs_package_directory_open(struct vcs_package_directory *dir,
                                const char *path);
const char *vcs_package_directory_next(struct vcs_package_directory *dir);
void vcs_package_directory_close(struct vcs_package_directory *dir);

#endif
