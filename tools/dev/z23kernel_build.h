/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Build and inspect the bounded RV64 z23kernel image. */

#ifndef ZCL_Z23KERNEL_BUILD_H
#define ZCL_Z23KERNEL_BUILD_H

/* Compile, link, and publish the flat kernel. A NULL tool name uses the
 * Z23KERNEL_* environment value, or the historical default command.
 * 0 when kernel.bin and kernel.identity are published. 1 on refusal. */
int zcl_z23kernel_build(const char *source_dir, const char *output_dir,
                        const char *bin_dir, const char *cc, const char *ld,
                        const char *objcopy, const char *readelf,
                        const char *nm);

#endif
