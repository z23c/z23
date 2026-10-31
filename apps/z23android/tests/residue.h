/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_TEST_RESIDUE_H
#define ZAPP_TEST_RESIDUE_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* Whether the text appears in this process's writable program data or its heap:
 * the places a copy of wallet data could survive after the screens that held it are gone. Stacks,
 * mappings of libraries and read-only data are not searched: the fixtures live in read-only data, and a
 * stack is reused by every call. Run on one thread, so that every allocation is in the main heap. */
static inline bool process_holds(const char *needle)
{
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[600];
    bool found = false;
    if (!maps) return true;
    while (!found && fgets(line, sizeof(line), maps)) {
        unsigned long low = 0, high = 0;
        char perms[8] = "", path[400] = "";
        if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %399[^\n]", &low, &high, perms, path) < 3) continue;
        if (perms[0] != 'r' || perms[1] != 'w' || perms[3] != 'p') continue;
        if (strstr(path, "[stack") || strstr(path, ".so") || strstr(path, "[vvar") || strstr(path, "[vsyscall")) continue;
        found = memmem((const void *)low, high - low, needle, strlen(needle)) != NULL;
    }
    fclose(maps);
    return found;
}
#endif
