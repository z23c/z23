/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Copy generated vendor/include headers from one checkout into
 *          another. Extra files already at the destination stay. */

#ifndef ZCL_COPY_VENDOR_INCLUDE_H
#define ZCL_COPY_VENDOR_INCLUDE_H

/* 0 when the headers are copied. 1 when the source tree is missing or the
 * copy fails. 2 when an argument is missing. The missing-source line is
 * written to err_fd. */
int zcl_copy_vendor_include(const char *source_root, const char *dest_root,
                            int err_fd);

#endif
