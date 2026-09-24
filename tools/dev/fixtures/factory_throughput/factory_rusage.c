/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * purpose: Account for a bounded local command and its waited children. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static double seconds(const struct timeval *value)
{
    return (double)value->tv_sec + (double)value->tv_usec / 1000000.0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: factory-rusage OUTPUT COMMAND [ARG ...]\n");
        return 2;
    }
    pid_t child = fork();
    if (child < 0) {
        perror("factory-rusage fork");
        return 1;
    }
    if (child == 0) {
        execvp(argv[2], &argv[2]);
        perror("factory-rusage exec");
        _exit(127);
    }
    struct rusage usage = {0};
    int status = 0;
    while (wait4(child, &status, 0, &usage) < 0) {
        if (errno == EINTR) continue;
        perror("factory-rusage wait4");
        return 1;
    }
    FILE *result = fopen(argv[1], "w");
    if (!result) {
        perror("factory-rusage result");
        return 1;
    }
    int wrote = fprintf(result, "%.6f\t%.6f\t%ld\t%ld\t%ld\n",
                        seconds(&usage.ru_utime), seconds(&usage.ru_stime),
                        usage.ru_maxrss, usage.ru_inblock, usage.ru_oublock);
    int closed = fclose(result);
    if (wrote < 0 || closed != 0) {
        fprintf(stderr, "factory-rusage: cannot write result\n");
        return 1;
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}
