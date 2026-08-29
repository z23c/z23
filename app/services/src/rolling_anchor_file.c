/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bind rolling-anchor snapshots and durable parent publication. */
// one-result-type-ok:internal-file-identity-helpers

#include "rolling_anchor_file_internal.h"
#include "platform/private_file.h"

#include <stdio.h>
#include <string.h>


bool rolling_anchor_parent_flush(const char *path)
{
    char parent[1024];
    int written = snprintf(parent, sizeof(parent), "%s", path);
    if (written <= 0 || (size_t)written >= sizeof(parent)) return false;
    char *slash = strrchr(parent, '/');
#if defined(_WIN32)
    char *backslash = strrchr(parent, '\\');
    if (!slash || (backslash && backslash > slash)) slash = backslash;
#endif
    if (!slash) return false;
    *slash = '\0';
    return platform_private_parent_flush(parent);
}
