/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the fleet source status selftest. */

#include "dev_script_dir.h"
#include "fleet_source_status_selftest.h"

#include <stdio.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(int argc, char **argv)
{
    char root[PATH_MAX];
    char library[PATH_MAX];
    int n;
    (void)argc;
    (void)argv;
    if (zcl_dev_checkout_root(root, sizeof root) != 0) {
        fprintf(stderr, "check_fleet_source_status: FAIL\n");
        return 1;
    }
    n = snprintf(library, sizeof library, "%s/%s", root,
                 "tools/scripts/fleet_source_status.sh");
    if (n < 0 || (size_t)n >= sizeof library) {
        fprintf(stderr, "check_fleet_source_status: FAIL\n");
        return 1;
    }
    return zcl_fleet_source_status_selftest(library);
}
