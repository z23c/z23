/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for ROM bundle replication. */

#include "dev_script_dir.h"
#include "rom_bundle_replicate.h"

#include <stdio.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(int argc, char **argv)
{
    char root[PATH_MAX];
    if (zcl_dev_checkout_root(root, sizeof root) != 0) {
        fprintf(stderr, "rom-bundle-replicate: cannot locate the checkout\n");
        return 2;
    }
    return zcl_rom_bundle_replicate(root, argc - 1, argv + 1);
}
