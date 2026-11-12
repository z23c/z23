/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the cached build-epoch integrity probes. */

#include "build_epoch_integrity.h"
#include "dev_script_dir.h"

#include <stdio.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(int argc, char **argv)
{
    char root[PATH_MAX];
    (void)argc;
    (void)argv;
    if (zcl_dev_checkout_root(root, sizeof root) != 0) {
        fprintf(stderr, "build-epoch-integrity: cannot locate the checkout\n");
        return 2;
    }
    return zcl_build_epoch_integrity(root);
}
