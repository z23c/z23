/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The arena-product-journey wrapper. It contributes no node,
 *          transport, or cleanup authority; it only selects the hook and
 *          execs the Commons beta acceptance. */

#include "arena_product_journey.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <unistd.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int zcl_arena_product_journey_launch(const char *script_dir)
{
#if defined(_WIN32)
    (void)script_dir;
    return 2;
#else
    char hook[PATH_MAX];
    char root[PATH_MAX];
    if (!script_dir || !script_dir[0])
        return 2;
    if (snprintf(hook, sizeof hook, "%s/arena_product_journey_hook.sh",
                 script_dir) >= (int)sizeof hook)
        return 2;
    char bin[PATH_MAX];
    const char *alt;
    char *argv[2];
    if (setenv("C23_BETA_LABEL", "arena-product-journey", 1) != 0 ||
        setenv("C23_BETA_HOOK", hook, 1) != 0 ||
        setenv("C23_BETA_INSTALL_ARENA_RUNNER", "1", 1) != 0)
        return 2;
    alt = getenv("C23_BETA_ACCEPTANCE_BIN");
    if (alt != NULL && alt[0] != '\0') {
        argv[0] = (char *)alt;
        argv[1] = NULL;
        execv(alt, argv);
        return 127;
    }
    if (snprintf(root, sizeof root, "%s/../..", script_dir) >= (int)sizeof root)
        return 2;
    if (snprintf(bin, sizeof bin, "%s/build/bin/c23-commons-beta", root) >=
        (int)sizeof bin)
        return 2;
    argv[0] = bin;
    argv[1] = NULL;
    execv(bin, argv);
    return 127;
#endif
}
