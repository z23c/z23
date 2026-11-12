/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the portable glibc 2.31 sysroot. */

#include "c23_portable_sysroot.h"
#include "dev_script_dir.h"

#include <stdio.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(int argc, char **argv)
{
    char root[PATH_MAX];
    const char *mode = argc > 1 ? argv[1] : NULL;
    if (zcl_dev_checkout_root(root, sizeof root) != 0) {
        fprintf(stderr, "c23-portable-sysroot: cannot locate the checkout\n");
        return 1;
    }
    return zcl_c23_portable_sysroot(root, mode);
}
