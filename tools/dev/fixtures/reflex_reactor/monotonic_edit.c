/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Monotonic benchmark clock; optional rename timestamps the edit start. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(int argc, char **argv)
{
    if (argc != 1 && argc != 3) {
        fprintf(stderr, "usage: monotonic_edit [STAGED TARGET]\n");
        return 2;
    }
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) { // platform-ok: standalone timing helper does not link node platform.clock
        fprintf(stderr, "monotonic_edit: clock: %s\n", strerror(errno));
        return 1;
    }
    int64_t us = (int64_t)now.tv_sec * INT64_C(1000000) +
                 now.tv_nsec / 1000;
    if (argc == 3 && rename(argv[1], argv[2]) != 0) {
        fprintf(stderr, "monotonic_edit: rename: %s\n", strerror(errno));
        return 1;
    }
    if (printf("%" PRId64 "\n", us) < 0 || fflush(stdout) != 0)
        return 1;
    return 0;
}
