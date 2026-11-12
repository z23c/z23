/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the secure-release regression group check. */

#include "secure_release_regressions.h"
#include "dev_script_dir.h"

#include <stdio.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(int argc, char **argv)
{
    char root[PATH_MAX];
    char manifest[PATH_MAX];
    char catalog[PATH_MAX];
    if (argc != 2 || !argv[1] || !argv[1][0]) {
        fprintf(stderr,
                "secure-release-regressions-selftest: FAIL: expected the Makefile exact group set\n");
        return 1;
    }
    if (zcl_dev_checkout_root(root, sizeof root) != 0 ||
        snprintf(manifest, sizeof manifest,
                 "%s/contexts/commons/modules/vcs/src/build_release_regressions.c",
                 root) >= (int)sizeof manifest ||
        snprintf(catalog, sizeof catalog, "%s/tools/dev/test_group_catalog.def",
                 root) >= (int)sizeof catalog) {
        fprintf(stderr,
                "secure-release-regressions-selftest: FAIL: canonical manifest group set is empty\n");
        return 1;
    }
    return zcl_secure_release_regressions_check(argv[1], manifest, catalog);
}
