/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the sovereign source-identity selftest. */

#include "sovereign_source_identity_selftest.h"
#include "dev_script_dir.h"

#include <stdio.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(void)
{
    char root[PATH_MAX];
    char script[PATH_MAX];
    if (zcl_dev_checkout_root(root, sizeof root) != 0 ||
        snprintf(script, sizeof script, "%s/tools/dev/source-identity.sh",
                 root) >= (int)sizeof script) {
        fprintf(stderr, "sovereign-source-identity-selftest: FAIL: "
                        "checkout root is unavailable\n");
        return 1;
    }
    return zcl_sovereign_source_identity_selftest(script);
}
