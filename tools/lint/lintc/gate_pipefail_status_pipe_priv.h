/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared declaration for the check-pipefail-status-pipe gate: the driver
 * entry used by the selftest to run the full gate logic against fixture
 * trees with overridden env (scan glob, baseline, ceiling, floor, mode).
 */
#ifndef GATE_PIPEFAIL_STATUS_PIPE_PRIV_H
#define GATE_PIPEFAIL_STATUS_PIPE_PRIV_H

#include <stdio.h>

#define PSP_GATE "check_pipefail_status_pipe"
#define PSP_SEP '\001'

enum { PSP_LINE = 8192, PSP_STMT = 65536, PSP_STAGE = 8192,
       PSP_PATH = 1024, PSP_FILES = 4096, PSP_BASE = 1024,
       PSP_ROWS = 1024, PSP_ROW = 512, PSP_VAL = 32 };

int psp_main(FILE *out, FILE *err);
int psp_err2(const char *what, const char *arg, long n);
int psp_each_line(const char *path, int (*cb)(void *, const char *, size_t),
                  void *ctx);
int psp_scan_file(const char *path, long *count, long *first);

#endif
