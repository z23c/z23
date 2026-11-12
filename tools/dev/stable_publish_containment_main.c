/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Exec z23-lint for `make check-stable-publish-contained`. */

#include "stable_publish_containment.h"

#include "platform/os_proc.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int spc_lint_path(char *out, size_t cap)
{
    char exe[PATH_MAX];
    char *slash;
    if (!os_proc_exe_path(exe, sizeof exe))
        return -1;
    slash = strrchr(exe, '/');
    if (!slash)
        return -1;
    *slash = '\0';
    if (snprintf(out, cap, "%s/z23-lint", exe) >= (int)cap)
        return -1;
    return 0;
}

int main(int argc, char **argv)
{
    char lint[PATH_MAX];
    const char *args[64];
    int n;
    if (spc_lint_path(lint, sizeof lint) != 0) {
        fprintf(stderr, "check-stable-publish-contained: z23-lint not found\n");
        return 127;
    }
    n = zcl_stable_publish_exec_args(lint, argc, argv, args, 64);
    if (n < 0) {
        fprintf(stderr, "check-stable-publish-contained: too many arguments\n");
        return 2;
    }
    execv(args[0], (char *const *)args);
    fprintf(stderr, "check-stable-publish-contained: cannot exec %s\n", lint);
    return 127;
}
