/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Report the size of one built binary. */

#ifndef ZCL_BINARY_SIZE_H
#define ZCL_BINARY_SIZE_H

/* 0 and a size line when path (or default_path) is a regular file.
 * 1 when that file is absent. 2 on an unknown flag. */
int zcl_binary_size(int argc, char **argv, const char *default_path);

#endif
