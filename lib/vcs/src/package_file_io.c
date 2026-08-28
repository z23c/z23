/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: implement portable package-store path and file-identity operations. */

#include "package_file_io.h"

#include "base/hex.h"

#include <string.h>

bool vcs_package_file_snapshot_equal(
    const struct platform_positioned_file_snapshot *a,
    const struct platform_positioned_file_snapshot *b)
{
    return a->size == b->size && a->volume == b->volume &&
           a->file_low == b->file_low && a->file_high == b->file_high &&
           a->modified_seconds == b->modified_seconds &&
           a->modified_nanoseconds == b->modified_nanoseconds &&
           a->changed_seconds == b->changed_seconds &&
           a->changed_nanoseconds == b->changed_nanoseconds;
}

bool vcs_package_file_exists(const char *path)
{
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    bool exists = platform_positioned_file_open(&file, path);
    platform_positioned_file_close(&file);
    return exists;
}

bool vcs_package_name_is_hex64(const char *name)
{
    uint8_t scratch[32];
    return zcl_hex_decode_lower(name, scratch, sizeof(scratch));
}

bool vcs_package_child_path(char *out, size_t out_size,
                            const char *root, const char *child)
{
    size_t root_len = strlen(root), child_len = strlen(child);
    if (root_len + 1u + child_len + 1u > out_size)
        return false;
    memcpy(out, root, root_len);
    out[root_len] = '/';
    memcpy(out + root_len + 1u, child, child_len + 1u);
    return true;
}
