/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the dev-lane stale reindex clear. */

#include "agent_clear_stale_reindex.h"
#include "dev_script_dir.h"

#include <stdio.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(int argc, char **argv)
{
    char root[PATH_MAX];
    if (zcl_dev_checkout_root(root, sizeof root) != 0) {
        fprintf(stderr, "agent-clear-stale-reindex: cannot locate the checkout\n");
        return 1;
    }
    return zcl_agent_clear_stale_reindex(root, argc - 1, argv + 1);
}
