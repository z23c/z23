/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Sets the package-host flag and one DHT hook, then execs
 *          zcode_dht_acceptance.sh. No node or transport authority. */

#include "dht_acceptance_launch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <unistd.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int zcl_dht_acceptance_launch(const char *script_dir, const char *hook_file)
{
#if defined(_WIN32)
    (void)script_dir;
    (void)hook_file;
    return 2;
#else
    char hook[PATH_MAX];
    char target[PATH_MAX];
    if (!script_dir || !script_dir[0] || !hook_file || !hook_file[0])
        return 2;
    if (snprintf(hook, sizeof hook, "%s/%s", script_dir, hook_file) >=
        (int)sizeof hook)
        return 2;
    if (snprintf(target, sizeof target, "%s/zcode_dht_acceptance.sh",
                 script_dir) >= (int)sizeof target)
        return 2;
    if (setenv("DHT_PACKAGEHOST", "1", 1) != 0 ||
        setenv("DHT_AFTER_SPARSE_HOOK", hook, 1) != 0)
        return 2;
    execlp("bash", "bash", target, (char *)NULL);
    return 127;
#endif
}
