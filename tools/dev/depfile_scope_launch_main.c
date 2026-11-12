/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the depfile-scope selftest driver. */

#include "depfile_scope_launch.h"
#include "dev_script_dir.h"

#include <stdio.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(void)
{
#if defined(_WIN32)
    fprintf(stderr, "depfile-scope-launch: unavailable on Windows\n");
    return 2;
#else
    char root[PATH_MAX];
    if (zcl_dev_checkout_root(root, sizeof root) != 0) {
        fprintf(stderr, "depfile-scope-launch: cannot locate the checkout\n");
        return 2;
    }
    return zcl_depfile_scope_launch(root);
#endif
}
