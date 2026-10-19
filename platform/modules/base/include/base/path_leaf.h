/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: last path component of a POSIX path. */
#ifndef ZCL_BASE_PATH_LEAF_H
#define ZCL_BASE_PATH_LEAF_H

#include <string.h>

/* Pointer into `path` just past its last '/', or `path` itself when it has
 * none. A trailing '/' yields the empty string. `path` must not be NULL. */
static inline const char *zcl_path_leaf(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

#endif /* ZCL_BASE_PATH_LEAF_H */
