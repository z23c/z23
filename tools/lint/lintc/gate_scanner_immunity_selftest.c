/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-scanner-immunity
 * (gate_scanner_immunity.c). Runs the full ported selftest with its stdout
 * and stderr captured (it must answer 0 — that is the passing case: all
 * five scanner-immunity assertions hold against the real built binary),
 * and proves the stray-marker matcher both accepts annotated output and
 * fails closed when the "untracked stray file" marker is absent.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <unistd.h>
#include "lintc.h"

extern int check_scanner_immunity_run(int argc, char **argv);
extern int si_stray_output_names(const char *out, const char *path);

/* Runs the full gate with fds 1 and 2 captured by a tmpfile; returns its
 * exit code, or -1 when the capture could not be set up. */
static int si_st_captured_run(void)
{
    if (fflush(stdout) != 0 || fflush(stderr) != 0)
        return -1;
    int out = dup(1), err = dup(2);
    FILE *tf = tmpfile();
    if (out < 0 || err < 0 || !tf) {
        if (out >= 0)
            close(out);
        if (err >= 0)
            close(err);
        if (tf)
            fclose(tf);
        return -1;
    }
    dup2(fileno(tf), 1);
    dup2(fileno(tf), 2);
    int got = check_scanner_immunity_run(0, NULL);
    fflush(stdout);
    fflush(stderr);
    dup2(out, 1);
    dup2(err, 2);
    close(out);
    close(err);
    fclose(tf);
    return got;
}

int check_scanner_immunity_selftest(void)
{
    int bad = 0;
    int got = si_st_captured_run();
    if (got == 0)
        printf("  selftest ok: full scanner-immunity run passes (rc=0)\n");
    else {
        fprintf(stderr, "check-scanner-immunity selftest: "
                "full run: want rc=0 got rc=%d\n", got);
        bad = 1;
    }
    if (si_stray_output_names("a/b.c [untracked stray file -- delete it]",
                              "a/b.c") == 1)
        printf("  selftest ok: stray marker matcher accepts annotated "
               "output\n");
    else {
        fprintf(stderr, "check-scanner-immunity selftest: "
                "stray marker matcher rejected annotated output\n");
        bad = 1;
    }
    if (si_stray_output_names("a/b.c ordinary violation text", "a/b.c") == 0)
        printf("  selftest ok: stray marker matcher fails closed without "
               "the marker\n");
    else {
        fprintf(stderr, "check-scanner-immunity selftest: "
                "stray marker matcher passed output lacking the marker\n");
        bad = 1;
    }
    return st_ok(bad, "check-scanner-immunity selftest: OK\n");
}
