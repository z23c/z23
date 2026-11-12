/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: One path walk from a build/bin host tool up to tools/dev. */

#include "dev_script_dir.h"

#include "platform/os_proc.h"

#include <stdio.h>
#include <string.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

void zcl_dev_chomp(char *text)
{
    size_t n = strlen(text);
    while (n > 0 && (text[n - 1] == '\n' || text[n - 1] == '\r'))
        text[--n] = '\0';
}

int zcl_dev_checkout_root(char *out, size_t cap)
{
    char exe[PATH_MAX];
    int i;
    if (!out || cap == 0)
        return -1;
    if (!os_proc_exe_path(exe, sizeof exe))
        return -1;
    for (i = 0; i < 3; i++) {
        char *slash = strrchr(exe, '/');
        if (!slash)
            return -1;
        *slash = '\0';
    }
    if (strlen(exe) + 1 > cap)
        return -1;
    memcpy(out, exe, strlen(exe) + 1);
    return 0;
}

int zcl_dev_script_dir(char *out, size_t cap)
{
    char root[PATH_MAX];
    if (zcl_dev_checkout_root(root, sizeof root) != 0)
        return -1;
    if (snprintf(out, cap, "%s/tools/dev", root) >= (int)cap)
        return -1;
    return 0;
}
