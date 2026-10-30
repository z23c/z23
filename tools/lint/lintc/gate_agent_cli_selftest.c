/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-agent-cli (gate_agent_cli.c). Exercises the
 * knob-driven fail-closed paths of check_agent_cli_run: a non-executable
 * node binary (FAIL rc 1), ZCL_NODE_BIN=/bin/false (allow case exits 1 ->
 * FAIL rc 1), ZCL_NODE_BIN=/bin/true (rc 0 but no schema field -> FAIL
 * rc 1), and, when build/bin/zclassic23 is executable, the real binary
 * passing rc 0 (otherwise that case is reported as skipped).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

static const char k_ags_gate[] = "check_agentdeployguard_cli_exit";
static const char k_ags_knob[] = "ZCL_NODE_BIN";
static const char k_ags_real[] = "build/bin/zclassic23";

/* Runs the gate with ZCL_NODE_BIN forced to bin; restores the knob after.
 * Prints a selftest line on match, a mismatch on stderr, returns 0/1. */
static int ags_case(const char *name, const char *bin, int want)
{
    const char *old = getenv(k_ags_knob);
    if (setenv(k_ags_knob, bin, 1) != 0) {
        fprintf(stderr, "%s selftest: setenv %s failed\n", k_ags_gate,
                k_ags_knob);
        return 1;
    }
    int got = check_agent_cli_run(0, NULL);
    if (old)
        setenv(k_ags_knob, old, 1);
    else
        unsetenv(k_ags_knob);
    if (got != want) {
        fprintf(stderr, "%s selftest: %s: want rc=%d got rc=%d\n", k_ags_gate,
                name, want, got);
        return 1;
    }
    printf("  selftest ok: %s (rc=%d)\n", name, got);
    return 0;
}


/* ZCL_DATADIR set to an empty directory of its own must not move the real
 * binary off the fixture: the refuse case still needs HOME's datadir. */
static int ags_env_case(void)
{
    char dir[256];
    const char *old = getenv("ZCL_DATADIR");
    int got;

    if (lint_mkdtemp(dir, sizeof dir, "agent-cli-env")) {
        fprintf(stderr, "%s selftest: cannot create ZCL_DATADIR fixture\n",
                k_ags_gate);
        return 1;
    }
    if (setenv("ZCL_DATADIR", dir, 1) != 0) {
        rap_rm_rf(dir);
        fprintf(stderr, "%s selftest: setenv ZCL_DATADIR failed\n", k_ags_gate);
        return 1;
    }
    got = check_agent_cli_run(0, NULL);
    if (old)
        setenv("ZCL_DATADIR", old, 1);
    else
        unsetenv("ZCL_DATADIR");
    rap_rm_rf(dir);
    if (got != 0) {
        fprintf(stderr, "%s selftest: ZCL_DATADIR set: want rc=0 got rc=%d\n",
                k_ags_gate, got);
        return 1;
    }
    printf("  selftest ok: ZCL_DATADIR does not redirect the cases (rc=0)\n");
    return 0;
}

int check_agent_cli_selftest(void)
{
    int bad = 0;
    bad |= ags_case("non-executable node binary fails closed", "/etc/hostname",
                    1) != 0;
    bad |= ags_case("/bin/false allow case exits 1", "/bin/false", 1) != 0;
    bad |= ags_case("/bin/true exits 0 without schema field", "/bin/true",
                    1) != 0;
    if (access(k_ags_real, X_OK) == 0) {
        bad |= ags_case("real node binary passes", k_ags_real, 0) != 0;
    } else {
        printf("  selftest skipped: %s not executable\n", k_ags_real);
    }
    if (access(k_ags_real, X_OK) == 0)
        bad |= ags_env_case() != 0;
    if (bad)
        fprintf(stderr, "FAIL: check_agent_cli selftest\n");
    return st_ok(bad, "check_agentdeployguard_cli_exit selftest: OK\n");
}
