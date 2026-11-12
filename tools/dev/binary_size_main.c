/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the derived binary-size report. */

#include "binary_size.h"
#include "dev_script_dir.h"

#include <stdio.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(int argc, char **argv)
{
    char root[PATH_MAX];
    char fallback[PATH_MAX];
    const char *def = "";
    if (zcl_dev_checkout_root(root, sizeof root) == 0 &&
        snprintf(fallback, sizeof fallback, "%s/build/bin/zclassic23", root) <
            (int)sizeof fallback)
        def = fallback;
    return zcl_binary_size(argc, argv, def);
}
