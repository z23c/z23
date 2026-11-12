/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host tool the epoch shell drivers exec. The lock fd is inherited.
 *          Exit leaves it held on that open file description. */

#include "build_epoch_lock_wait.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char *end = NULL;
    long fd;
    if (argc != 5) {
        fprintf(stderr,
                "build-epoch-lock-wait: usage: build-epoch-lock-wait "
                "TAG FD LOCK_FILE KIND\n");
        return 2;
    }
    fd = strtol(argv[2], &end, 10);
    if (!end || *end || fd < 0 || fd > 1023)
        return zcl_build_epoch_flock_bounded(argv[1], -1, argv[3], argv[4],
                                             STDERR_FILENO);
    return zcl_build_epoch_flock_bounded(argv[1], (int)fd, argv[3], argv[4],
                                         STDERR_FILENO);
}
