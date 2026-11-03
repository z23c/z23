/* loop_tick_gate.c - see loop_tick_gate.h. Linux /proc/<pid>/fd scan. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "loop_tick_gate.h"

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool all_digits(const char *s)
{
    if (!*s)
        return false;
    for (; *s; s++)
        if (*s < '0' || *s > '9')
            return false;
    return true;
}

/* True when process `pid` has `want` open on any descriptor. */
static bool pid_holds(const char *pid, const char *want, size_t want_len)
{
    char dir[64];
    if (snprintf(dir, sizeof(dir), "/proc/%s/fd", pid) >= (int)sizeof(dir))
        return false;
    DIR *d = opendir(dir);
    if (!d)
        return false;
    bool held = false;
    const struct dirent *e;
    while (!held && (e = readdir(d)) != NULL) {
        char link[96], target[PATH_MAX];
        if (e->d_name[0] == '.' ||
            snprintf(link, sizeof(link), "%s/%s", dir, e->d_name) >= (int)sizeof(link))
            continue;
        const ssize_t n = readlink(link, target, sizeof(target) - 1);
        held = n == (ssize_t)want_len && memcmp(target, want, want_len) == 0;
    }
    closedir(d);
    return held;
}

bool lt_log_orphaned(const char *log)
{
    char want[PATH_MAX];
    struct stat st;
    if (stat(log, &st) != 0 || !realpath(log, want))
        return false;
    DIR *proc = opendir("/proc");
    if (!proc)
        return false; /* no /proc: cannot tell, so never call a run dead */
    bool held = false;
    const struct dirent *e;
    while (!held && (e = readdir(proc)) != NULL)
        held = all_digits(e->d_name) && pid_holds(e->d_name, want, strlen(want));
    closedir(proc);
    return !held;
}
