/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Start one command as the leader of a private process group.  This is the
 * portable syscall-level equivalent of the Linux util-linux setsid(1) tool;
 * macOS provides setsid(2), but does not ship that command-line wrapper. */

#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "process-group-exec: usage: process-group-exec COMMAND [ARG ...]\n");
        return 2;
    }

    if (setsid() < 0 && setpgid(0, 0) < 0) {
        fprintf(stderr, "process-group-exec: cannot create process group: %s\n",
                strerror(errno));
        return 126;
    }

    execvp(argv[1], &argv[1]);
    fprintf(stderr, "process-group-exec: cannot execute %s: %s\n", argv[1],
            strerror(errno));
    return 127;
}
