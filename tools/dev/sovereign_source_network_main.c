/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for `make sovereign-source-network-acceptance`. */

#include "dev_script_dir.h"
#include "sovereign_source_network.h"

#include <stdio.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(void)
{
#if defined(_WIN32)
    fprintf(stderr,
            "sovereign-source-network-acceptance: unavailable on Windows\n");
    return 2;
#else
    char dir[PATH_MAX];
    if (zcl_dev_script_dir(dir, sizeof dir) != 0) {
        fprintf(stderr,
                "sovereign-source-network-acceptance: cannot locate tools/dev\n");
        return 2;
    }
    return zcl_sovereign_source_network_launch(dir);
#endif
}
