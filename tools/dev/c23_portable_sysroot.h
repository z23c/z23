/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Prepare and verify the pinned glibc 2.31 portable sysroot. */

#ifndef ZCL_C23_PORTABLE_SYSROOT_H
#define ZCL_C23_PORTABLE_SYSROOT_H

/* mode NULL or empty is prepare. prepare and cc-path print the compiler
 * wrapper path. root-path prints the sysroot. verify checks the ISA floor
 * and the GLIBC_2.31 ceiling. Returns 0 on success. */
int zcl_c23_portable_sysroot(const char *repo, const char *mode);

#endif
