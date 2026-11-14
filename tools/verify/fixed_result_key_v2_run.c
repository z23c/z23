/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Builds fixed_result_key_v2_probe.c in a private scratch directory
 *          under $TMPDIR and runs it from the repository root; the exit status
 *          is the compiler's or the probe's. Started through
 *          fixed_result_key_v2_probe.sh; --selftest checks that every compile
 *          input exists and the scratch and signal helpers. */
#define _POSIX_C_SOURCE 200809L
#include "verify/probe_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *const frk_cc[] = {
    "/usr/bin/cc", "-std=c23", "-Wall", "-Wextra", "-Werror", "-pedantic",
    "-Itools", "-Iplatform/modules/base/include",
    "-Iplatform/modules/sha3/include", "-Iplatform/modules/platform/include",
    "-Iplatform/modules/codec/include",
    nullptr};
static const char *const frk_sources[] = {
    "tools/verify/fixed_result_key_v2.c", "tools/verify/fixed_result_contract.c",
    "tools/verify/fixed_result_key_v2_probe.c", "platform/modules/sha3/src/sha3.c",
    "platform/modules/codec/src/cursor.c",
    nullptr};

static int frk_status(int rc)
{
    return rc > 0 ? rc : 1;
}

static int frk_selftest(void)
{
    bool ok = true;
    for (const char *const *s = frk_sources; *s; ++s)
        if (access(*s, R_OK) != 0) {
            fprintf(stderr, "missing compile input: %s\n", *s);
            ok = false;
        }
    puts(ok ? "fixed_result_key_v2_run_selftest=PASS"
            : "fixed_result_key_v2_run_selftest=FAIL");
    return ok && frk_status(0) == 1 && frk_status(7) == 7 &&
           pu_selftest() == 0 ? 0 : 1;
}

static int frk_run(void)
{
    struct pu_argv cc = {.n = 0}, probe = {.n = 0};
    char templ[PU_PATH_MAX], work[PU_PATH_MAX];
    const char *scratch = getenv("TMPDIR");
    int rc;
    if (!scratch || scratch[0] != '/') {
        fputs("usage: run from the repository root through devbuild\n", stderr);
        return 2;
    }
    if (snprintf(templ, sizeof templ, "%s/z23-fixed-key-v2.XXXXXX", scratch) >=
            (int)sizeof templ || !pu_scratch_make(templ, work, sizeof work))
        return 1;
    pu_argv_addv(&cc, frk_cc);
    pu_argv_addv(&cc, frk_sources);
    pu_argv_add(&cc, "-o");
    pu_argv_add(&cc, pu_at(work, "probe"));
    rc = pu_run(&cc, nullptr, nullptr);
    if (rc != 0) return frk_status(rc);
    pu_argv_add(&probe, pu_at(work, "probe"));
    rc = pu_run(&probe, nullptr, nullptr);
    return rc == 0 ? 0 : frk_status(rc);
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[2], "--selftest") == 0) return frk_selftest();
    return frk_run();
}
