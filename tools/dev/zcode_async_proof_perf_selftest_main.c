/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the async proof performance selftest. */

#include "zcode_async_proof_perf_selftest.h"
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
        snprintf(script, sizeof script,
                 "%s/tools/dev/zcode_async_proof_perf_report.sh", root) >=
            (int)sizeof script) {
        fprintf(stderr, "proof-perf selftest: checkout root is unavailable\n");
        return 1;
    }
    return zcl_zcode_async_proof_perf_selftest(script);
}
