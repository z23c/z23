/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Standalone host tool build/bin/test-group-list: the former
 *          tools/dev/test-group-list.sh and test-registry-report.sh. Make
 *          runs it at parse time (ONLY= validation, t-list, t-fast-exact), so
 *          it needs neither the node nor a test binary. The same body is the
 *          `z23-dev dev test groups` leaf (tools/command/native_dev_test_groups.c).
 *          The sources default to the repository root; when the current
 *          directory is not one, the root is found from this binary's own
 *          path (<root>/build/bin/test-group-list). */

#include "test_group_list.h"

#include "platform/os_proc.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* chdir to <exe>/../.. when the registry is not under the current directory. */
static void enter_repo_root(const struct tgl_sources *s)
{
    char exe[PATH_MAX];
    char *slash;
    if (access(s->registry, R_OK) == 0 || !os_proc_exe_path(exe, sizeof(exe)))
        return;
    for (int up = 0; up < 3; up++) {
        slash = strrchr(exe, '/');
        if (!slash)
            return;
        *slash = '\0';
    }
    if (exe[0])
        if (chdir(exe) != 0)
            return;
}

int main(int argc, char **argv)
{
    struct tgl_sources s;
    tgl_sources_from_env(&s);
    enter_repo_root(&s);
    return tgl_run(&s, argc - 1, (const char *const *)argv + 1, stdout, stderr);
}
