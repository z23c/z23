/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Locate this checkout's tools/dev from a host tool installed at
 *          build/bin. Shared by the acceptance launchers so each one does
 *          not carry its own copy. */

#ifndef ZCL_DEV_SCRIPT_DIR_H
#define ZCL_DEV_SCRIPT_DIR_H

#include <stddef.h>

/* Writes the checkout root of a host tool installed at build/bin/<tool>.
 * 0 on success, -1 when the path does not have that shape. */
int zcl_dev_checkout_root(char *out, size_t cap);

/* Writes "<checkout>/tools/dev" to out. 0 on success, -1 when the running
 * executable path does not have the build/bin/<tool> shape. */
int zcl_dev_script_dir(char *out, size_t cap);

/* Strips trailing '\n' and '\r' bytes from a line in place. */
void zcl_dev_chomp(char *text);

#endif
