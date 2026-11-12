/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the z23kernel image build. */

#include "z23kernel_build.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: z23kernel-build SOURCE OUTPUT BIN\n");
        return 2;
    }
    return zcl_z23kernel_build(argv[1], argv[2], argv[3],
                               getenv("Z23KERNEL_CC"), getenv("Z23KERNEL_LD"),
                               getenv("Z23KERNEL_OBJCOPY"),
                               getenv("Z23KERNEL_READELF"),
                               getenv("Z23KERNEL_NM"));
}
