/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: implement deterministic portable package-directory iteration. */

#include "package_directory.h"

#include <string.h>

bool vcs_package_directory_open(struct vcs_package_directory *dir,
                                const char *path)
{
    if (!dir)
        return false;
    memset(dir, 0, sizeof(*dir));
    return platform_directory_list_regular_sorted(path, &dir->list);
}

const char *vcs_package_directory_next(struct vcs_package_directory *dir)
{
    if (!dir || dir->next >= dir->list.count)
        return NULL;
    return dir->list.entries[dir->next++].name;
}

void vcs_package_directory_close(struct vcs_package_directory *dir)
{
    if (!dir)
        return;
    platform_directory_list_free(&dir->list);
    memset(dir, 0, sizeof(*dir));
}
