/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: process capture for the check-lib-module-order gate: runs the
 * link-graph tool, collects its stdout in a fixed buffer and reports every
 * pipe, fork, read, wait, signal and overflow failure distinctly so the
 * gate can fail closed (see gate_lib_module_order.c).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "gate_lib_module_order_priv.h"

static const char k_lmo_gate[] = "check_lib_module_order";

/* Child side: stdout to wfd, stderr to /dev/null when quiet, then exec. */
static void lmo_child(char *const argv[], int rfd, int wfd, int quiet_err)
{
    close(rfd);
    dup2(wfd, 1);
    close(wfd);
    if (quiet_err) {
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) {
            dup2(dn, 2);
            close(dn);
        }
    }
    execvp(argv[0], argv);
    _exit(127);
}

/* Drains fd. With out set, keeps up to cap-1 bytes in out and reports
 * LMO_CAP_OVF when more arrives; with out NULL, discards. EINTR retries;
 * any other read error is LMO_CAP_FAIL. */
static int lmo_pump(int fd, char *out, size_t cap, size_t *n)
{
    char spare[512];
    *n = 0;
    for (;;) {
        char *dst = spare;
        size_t room = sizeof spare;
        if (out && *n < cap - 1) {
            dst = out + *n;
            room = cap - 1 - *n;
        }
        ssize_t r = read(fd, dst, room);
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0)
            return LMO_CAP_FAIL;
        if (r == 0)
            return 0;
        if (out && dst == spare)
            return LMO_CAP_OVF;
        if (out)
            *n += (size_t)r;
    }
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

/* fork+execvp; stdout captured into out (discarded when out is NULL),
 * stderr to /dev/null when quiet. Returns the exit status (>= 0), or
 * LMO_CAP_FAIL (pipe, fork, read, wait or abnormal exit: message printed)
 * or LMO_CAP_OVF (more than cap-1 bytes: message printed). */
int lmo_capture(char *const argv[], char *out, size_t cap,
                       size_t *outn, int quiet_err)
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
        lmo_child(argv, pfd[0], pfd[1], quiet_err);
    close(pfd[1]);
    int pr = lmo_pump(pfd[0], out, cap, outn);
    close(pfd[0]);
    int st = 0;
    if (lmo_reap(pid, &st) != 0 || pr == LMO_CAP_FAIL) {
        fprintf(stderr, "%s: cannot read or reap %s\n", k_lmo_gate, argv[0]);
        return LMO_CAP_FAIL;
    }
    if (pr == LMO_CAP_OVF) {
        fprintf(stderr, "%s: graph output exceeds %zu bytes\n", k_lmo_gate,
                cap - 1);
        return LMO_CAP_OVF;
    }
    if (!WIFEXITED(st)) {
        fprintf(stderr, "%s: %s terminated abnormally\n", k_lmo_gate,
                argv[0]);
        return LMO_CAP_FAIL;
    }
    return WEXITSTATUS(st);
}

