/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Report one binary's size. The default path is this checkout's
 *          build/bin/zclassic23. */

#include "binary_size.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static const char *bs_choose(int argc, char **argv, int *bytes_only, int *rc)
{
    const char *bin = NULL;
    int i;
    *bytes_only = 0;
    *rc = 0;
    if (argv == NULL)
        return NULL;
    for (i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (arg == NULL)
            continue;
        if (strcmp(arg, "--bytes") == 0) {
            *bytes_only = 1;
            continue;
        }
        if (arg[0] == '-') {
            fprintf(stderr, "binary_size.sh: unknown flag '%s'\n", arg);
            *rc = 2;
            return NULL;
        }
        bin = arg;
    }
    return bin;
}

static int bs_measure(const char *path, unsigned long long *size)
{
    struct stat st;
    if (path == NULL || path[0] == '\0')
        return 0;
    if (stat(path, &st) != 0)
        return 0;
    if (!S_ISREG(st.st_mode) || st.st_size < 0)
        return 0;
    *size = (unsigned long long)st.st_size;
    return 1;
}

static void bs_print(unsigned long long size, const char *path, int bytes_only)
{
    char mb[32];
    if (bytes_only) {
        fprintf(stdout, "%llu\n", size);
        return;
    }
    snprintf(mb, sizeof mb, "%.1f", (double)size / 1048576.0);
    fprintf(stdout, "%llu bytes (~%s MB)  %s\n", size, mb, path);
}

static void bs_missing(const char *path)
{
    fprintf(stderr,
            "binary_size.sh: '%s' not built yet — run 'make -j$(nproc)' "
            "(or 'make build-only').\n",
            path);
}

int zcl_binary_size(int argc, char **argv, const char *default_path)
{
    int bytes_only = 0;
    int rc = 0;
    unsigned long long size = 0;
    const char *chosen = bs_choose(argc, argv, &bytes_only, &rc);
    const char *path;
    if (rc != 0)
        return rc;
    path = (chosen != NULL && chosen[0] != '\0') ? chosen : default_path;
    if (path == NULL)
        path = "";
    if (!bs_measure(path, &size)) {
        bs_missing(path);
        return 1;
    }
    bs_print(size, path, bytes_only);
    return 0;
}
