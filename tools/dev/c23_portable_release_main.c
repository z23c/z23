/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the portable C23 release build. */

#include "c23_portable_release.h"
#include "dev_script_dir.h"

#include <stdio.h>
#include <string.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(int argc, char **argv)
{
    char root[PATH_MAX];
    if (argc > 1 && strcmp(argv[1], "--selftest") == 0)
        return zcl_c23_portable_release(NULL, 1);
    if (zcl_dev_checkout_root(root, sizeof root) != 0) {
        fprintf(stderr, "c23-portable-release: cannot locate the checkout\n");
        return 1;
    }
    return zcl_c23_portable_release(root, 0);
}
