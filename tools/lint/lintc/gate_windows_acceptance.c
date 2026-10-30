/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-windows-acceptance — the platform-seam acceptance
 * gate, in two steps, in this order: RECONCILE the catalog against the
 * tree, then COMPILE. Ported from tools/lint/check_windows_acceptance.sh
 * (deleted). The reconcile step fails closed on any acceptance program on
 * disk that nothing accounts for (catalog row, registered suite group, or
 * a reasoned EXEMPT row), because a test file existing proves nothing runs
 * it. The compile step runs `make windows-acceptance-compile` when mingw
 * is present and prints UNOBSERVED otherwise. Selftest:
 * gate_windows_acceptance_selftest.c.
 *
 * Usage (argv after the gate name):
 *   check-windows-acceptance             the gate
 *   check-windows-acceptance --self-test prove it can go red
 *   check-windows-acceptance --global    reconcile + make plan
 *   check-windows-acceptance --row=ID... cross-link these rows
 *
 * Env: ZCL_WINDOWS_ACCEPTANCE_ROOT (tree to reconcile, default repo root),
 * ZCL_WINDOWS_ACCEPTANCE_CC (cross-compiler probe), ZCL_REQUIRE_MINGW=1
 * (missing compiler is a hard failure). Exit: 0 clean or UNOBSERVED, 1 on
 * any violation or malformed tree, 2 on refusal or internal error.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_windows_acceptance_priv.h"

int check_windows_acceptance_run(int argc, char **argv)
{
    if (argc >= 1 && (!strcmp(argv[0], "--self-test") ||
                      !strcmp(argv[0], "--selftest")))
        return check_windows_acceptance_selftest();
    if (argc >= 1 && !strcmp(argv[0], "--global"))
        return wa_global_main_io(stdout);
    if (argc >= 1 && !strncmp(argv[0], "--row=", 6))
        return wa_rows_main_io(argc, argv, stdout, stderr);
    if (argc >= 1) {
        fprintf(stderr,
                "usage: check-windows-acceptance"
                " [--self-test | --global | --row=ID...]\n");
        return 2;
    }
    const char *env = getenv("ZCL_WINDOWS_ACCEPTANCE_ROOT");
    char root[WA_PATH];
    const char *use = root;
    if (env && env[0]) {
        use = env;
    } else if (wa_repo_root(root, sizeof root)) {
        return 2;
    }
    if (wa_reconcile_root(use, stdout))
        return 1;
    return wa_compile_step_io(stdout, stderr, 0);
}
