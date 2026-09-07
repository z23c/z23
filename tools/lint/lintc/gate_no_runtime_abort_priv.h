/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations for the check-no-runtime-abort C23 lint
 * family (gate_no_runtime_abort.c and its _selftest.c sibling). Private to
 * this family — never included outside tools/lint/lintc/.
 */
#ifndef GATE_NO_RUNTIME_ABORT_PRIV_H
#define GATE_NO_RUNTIME_ABORT_PRIV_H

#include <stdio.h>

enum { NRA_PATH = 512, NRA_ROOTS_MAX = 32, NRA_ROOT_LEN = 256 };

enum nra_mode { NRA_MODE_FAIL, NRA_MODE_WARN, NRA_MODE_UPDATE };

struct nra_ctx {
    const char *baseline;
    const char *const *roots;
    int nroots;
    int file_floor;
    int site_floor;
    enum nra_mode mode;
};

/* Runs the full gate (scan, ratchet against the baseline, report) exactly
 * as check_no_runtime_abort.sh does, writing to out/err and returning its
 * exit code (0 clean/WARN, 1 FAIL-mode violation, 2 hollow scan). Shared by
 * the production entry point (env-derived ctx) and the selftest (fixture
 * ctx), so both paths run the identical logic. */
int nra_run_gate(const struct nra_ctx *c, FILE *out, FILE *err);

#endif
