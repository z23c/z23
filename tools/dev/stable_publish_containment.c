/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Translate the Makefile's --self-test spelling into the
 *          z23-lint flag and pass every other argument through. */

#include "stable_publish_containment.h"

#include <string.h>

static const char k_gate[] = "check-stable-publish-contained";
static const char k_selftest[] = "--selftest";
static const char k_make_self[] = "--self-test";

int zcl_stable_publish_exec_args(const char *lint_bin, int argc, char **argv,
                                 const char **out, int cap)
{
    int src = 1;
    int n = 0;
    int rewrite;
    if (!lint_bin || !lint_bin[0] || !out || cap < 3 || !argv)
        return -1;
    rewrite = argc > 1 && argv[1] && strcmp(argv[1], k_make_self) == 0;
    out[n++] = lint_bin;
    out[n++] = k_gate;
    if (rewrite) {
        if (n >= cap)
            return -1;
        out[n++] = k_selftest;
        src = 2;
    }
    while (src < argc) {
        if (n + 1 >= cap)
            return -1;
        out[n++] = argv[src++];
    }
    if (n >= cap)
        return -1;
    out[n++] = NULL;
    return n;
}
