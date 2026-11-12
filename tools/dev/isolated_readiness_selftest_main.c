/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the isolated readiness selftest. */

#include "isolated_readiness_selftest.h"
#include "dev_script_dir.h"

#include <stdio.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(void)
{
    char root[PATH_MAX];
    char env_sh[PATH_MAX];
    char jsonq[PATH_MAX];
    if (zcl_dev_checkout_root(root, sizeof root) != 0 ||
        snprintf(env_sh, sizeof env_sh,
                 "%s/tools/scripts/isolated_node_env.sh", root) >=
            (int)sizeof env_sh ||
        snprintf(jsonq, sizeof jsonq, "%s/build/bin/jsonq", root) >=
            (int)sizeof jsonq) {
        fprintf(stderr, "isolated-readiness selftest: FAIL: "
                        "checkout root is unavailable\n");
        return 1;
    }
    return zcl_isolated_readiness_selftest(env_sh, jsonq);
}
