/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * File operations for data import/export.
 * Always byte-copy. Never hardlink or symlink. */

#ifndef ZCL_FILE_OPS_H
#define ZCL_FILE_OPS_H

#include <stdbool.h>

/* Copy a single file (byte copy). Overwrites dst if it exists. */
bool file_copy(const char *src, const char *dst);

/* Copy all files in a directory (byte copy, skips LOCK files).
 * Removes dst contents first. */
bool dir_copy(const char *src_dir, const char *dst_dir);

/* Copy all blk*.dat and rev*.dat from src_dir to dst_dir.
 * Returns count of blk*.dat files copied, or -1 on any copy failure. */
int block_files_copy(const char *src_dir, const char *dst_dir);

/* Remove all blk*.dat and rev*.dat from a directory. */
void block_files_clean(const char *dir);

/* Remove a directory tree recursively. */
void dir_remove_tree(const char *dir);

#endif
