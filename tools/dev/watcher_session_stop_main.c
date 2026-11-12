/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the watcher-session stop selftest. */

#include "dev_script_dir.h"
#include "watcher_session_stop.h"

#include <stdio.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(int argc, char **argv)
{
    char root[PATH_MAX];
    const char *bin = argc > 1 ? argv[1] : NULL;
    const char *fixture = argc > 2 ? argv[2] : NULL;
    if (zcl_dev_checkout_root(root, sizeof root) != 0) {
        fprintf(stderr, "watcher session selftest: cannot locate the checkout\n");
        return 1;
    }
    return zcl_watcher_session_stop(root, bin, fixture);
}
