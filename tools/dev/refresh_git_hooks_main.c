/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the armed git-hook refresh. */

#include "refresh_git_hooks.h"
#include "dev_script_dir.h"

#include <stdio.h>
#include <stdlib.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(void)
{
#if defined(_WIN32)
    return 0;
#else
    char root[PATH_MAX];
    const char *source = getenv("ZCL_GIT_HOOK_SOURCE_ROOT");
    if (!source || !source[0]) {
        if (zcl_dev_checkout_root(root, sizeof root) != 0 ||
            setenv("ZCL_GIT_HOOK_SOURCE_ROOT", root, 0) != 0) {
            fprintf(stderr, "refresh-git-hooks: cannot locate the checkout\n");
            return 2;
        }
    }
    return zcl_refresh_git_hooks_if_armed();
#endif
}
