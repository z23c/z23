/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Build and run the depfile-scope selftest in a private directory,
 *          then remove that directory. */

#ifndef ZCL_DEPFILE_SCOPE_LAUNCH_H
#define ZCL_DEPFILE_SCOPE_LAUNCH_H

/* 0 when make and the selftest both exit 0. The failing command's status
 * otherwise. 2 when root is missing or the private directory cannot be
 * created. 1 when a caught signal stops the run. The private directory is
 * removed before return. */
int zcl_depfile_scope_launch(const char *root);

#endif
