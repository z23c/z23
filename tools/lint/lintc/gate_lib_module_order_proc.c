/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: process spawn for the lib module link graph: runs nm over a
 * batch of objects and hands each output line to a callback, reporting
 * every pipe, fork, read, wait and signal failure distinctly so the gate
 * can fail closed (see gate_lib_module_order_graph.c).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "gate_lib_module_order_priv.h"

static const char k_lmo_gate[] = "check_lib_module_order";

/* Child side: stdout to wfd, stderr to /dev/null, then exec. */
static void lmo_child(char *const argv[], int rfd, int wfd)
{
    close(rfd);
    dup2(wfd, 1);
    close(wfd);
    int dn = open("/dev/null", O_WRONLY);
    if (dn >= 0) {
        dup2(dn, 2);
        close(dn);
    }
    execvp(argv[0], argv);
    _exit(127);
}

/* Waits for pid, retrying EINTR. 0 and *st filled, or -1. */
static int lmo_reap(pid_t pid, int *st)
{
    pid_t w;
    do {
        w = waitpid(pid, st, 0);
    } while (w < 0 && errno == EINTR);
    return w == pid ? 0 : -1;
}

/* Feeds every line of f (newline stripped) to cb. Keeps draining after a
 * callback refusal so the child never blocks on a full pipe. */
static int lmo_lines(FILE *f, int (*cb)(void *, char *), void *ctx)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int bad = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (!bad && cb(ctx, line) != 0)
            bad = 1;
    }
    int rerr = ferror(f);
    free(line);
    return bad || rerr ? LMO_CAP_FAIL : 0;
}

/* fork+execvp argv with stderr discarded; each stdout line goes to cb. A
 * non-zero cb return stops the processing and fails the call. Returns the
 * child's exit status (>= 0), or LMO_CAP_FAIL (pipe, fork, read, wait,
 * abnormal exit or callback refusal: message printed). */
int lmo_nm_stream(char *const argv[], int (*cb)(void *ctx, char *line),
                  void *ctx)
{
    int pfd[2];
    if (pipe(pfd) != 0) {
        fprintf(stderr, "%s: pipe failed\n", k_lmo_gate);
        return LMO_CAP_FAIL;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        fprintf(stderr, "%s: fork failed\n", k_lmo_gate);
        return LMO_CAP_FAIL;
    }
    if (pid == 0)
        lmo_child(argv, pfd[0], pfd[1]);
    close(pfd[1]);
    FILE *f = fdopen(pfd[0], "r");
    int pr = f ? lmo_lines(f, cb, ctx) : LMO_CAP_FAIL;
    if (f)
        fclose(f);
    else
        close(pfd[0]);
    int st = 0;
    if (lmo_reap(pid, &st) != 0 || pr == LMO_CAP_FAIL) {
        fprintf(stderr, "%s: cannot read or reap %s\n", k_lmo_gate, argv[0]);
        return LMO_CAP_FAIL;
    }
    if (!WIFEXITED(st)) {
        fprintf(stderr, "%s: %s terminated abnormally\n", k_lmo_gate,
                argv[0]);
        return LMO_CAP_FAIL;
    }
    return WEXITSTATUS(st);
}
