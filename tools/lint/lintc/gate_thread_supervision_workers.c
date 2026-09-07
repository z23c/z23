/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-thread-supervision
 * Third file of the check-thread-supervision family (the 700-line family
 * ceiling split): the gate's --selftest probes. The find mirror, the
 * git-oracle coverage check, the gate entry, and the family's parity notes
 * live in gate_thread_supervision.c; the baseline loader, the spawn-site
 * scan, and the verdict report live in gate_thread_supervision_scan.c.
 */

/* ── --selftest ────────────────────────────────────────────────────────────
 * Byte-parity port of the original script's --selftest block: the COVERAGE
 * check's three answers, exercised on every `make lint` before the real run
 * follows in the same `--selftest && <gate>` command. Each cov_case
 * re-invokes the gate FOR REAL with ZCL_THREADSUP_COVERAGE_ONLY=1, so the
 * inner run stops the moment the coverage verdict is in: a full scan clears
 * its own expectation (exit 0), a scan set deliberately reduced below the
 * expectation (the override roots "app lib" track nothing) is UNPROVEN
 * (exit 2 — never 0, never 1), and an allowance above the true shortfall
 * is a stale-ratchet (exit 1). Here the shell's `env VAR=VAL... "$self"` is
 * setenv + the runtime's self-exec helper, with the four relevant ZCL_*
 * vars snapshotted at entry and restored before each case, so every inner
 * run sees exactly what `env VAR=VAL... "$self"` would have seen,
 * including operator-set leftovers the case doesn't override. The inner
 * run's merged output is discarded (>/dev/null 2>&1); only its exit code
 * is graded. The SELFTEST FAILED text and the PASS line are the shell's
 * byte-for-byte.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

static const char k_tsw_name[] = "check_thread_supervision";
static const char k_tsw_gate[] = "check-thread-supervision";

enum { TSW_SINK = 65536 };

struct tsw_snap { char val[4096]; int set; };
static struct tsw_snap g_tsw_snap[4];
static const char *const k_tsw_vars[] = {
    "ZCL_LINT_PRODUCTION_SCAN", "ZCL_THREADSUP_COVERAGE_ONLY",
    "ZCL_THREADSUP_SCAN_ROOTS", "ZCL_THREADSUP_COVERAGE_ALLOWANCE",
};

static int tsw_snap_save(void)
{
    for (int i = 0; i < 4; i++) {
        const char *e = getenv(k_tsw_vars[i]);
        g_tsw_snap[i].set = e != NULL;
        if (e && ovf(snprintf(g_tsw_snap[i].val, sizeof g_tsw_snap[i].val,
                              "%s", e), sizeof g_tsw_snap[i].val))
            return 2;
    }
    return 0;
}

static int tsw_snap_restore(void)
{
    for (int i = 0; i < 4; i++) {
        int rc = g_tsw_snap[i].set
            ? setenv(k_tsw_vars[i], g_tsw_snap[i].val, 1)
            : unsetenv(k_tsw_vars[i]);
        if (rc != 0)
            return die("z23-lint: setenv failed\n", "");
    }
    return 0;
}

static int tsw_apply(const char *const *assigns)
{
    for (; *assigns; assigns++) {
        char buf[4096];
        if (ovf(snprintf(buf, sizeof buf, "%s", *assigns), sizeof buf))
            return 2;
        char *eq = strchr(buf, '=');
        if (!eq)
            return die("z23-lint: setenv failed\n", "");
        *eq = '\0';
        if (setenv(buf, eq + 1, 1) != 0)
            return die("z23-lint: setenv failed\n", "");
    }
    return 0;
}

/* cov_case: restore the entry snapshot, apply this case's assignments, run
 * the gate for real, grade only the exit code. */
static int tsw_cov_case(int want, const char *msg, const char *const *assigns)
{
    int rc = tsw_snap_restore();
    if (rc == 0)
        rc = tsw_apply(assigns);
    if (rc)
        return rc;
    static char sink[TSW_SINK];
    int code = 0;
    rc = cic_invoke(k_tsw_gate, 1, sink, sizeof sink, &code);
    if (rc)
        return rc;
    if (code != want) {
        fprintf(stderr, "%s: SELFTEST FAILED — %s (wanted exit %d, got %d)\n",
                k_tsw_name, msg, want, code);
        return 2;
    }
    return 0;
}

int check_thread_supervision_selftest(void)
{
    static const char *const case1[] = {
        "ZCL_LINT_PRODUCTION_SCAN=1", "ZCL_THREADSUP_COVERAGE_ONLY=1", NULL
    };
    static const char *const case2[] = {
        "ZCL_LINT_PRODUCTION_SCAN=1", "ZCL_THREADSUP_COVERAGE_ONLY=1",
        "ZCL_THREADSUP_SCAN_ROOTS=app lib", NULL
    };
    static const char *const case3[] = {
        "ZCL_LINT_PRODUCTION_SCAN=1", "ZCL_THREADSUP_COVERAGE_ONLY=1",
        "ZCL_THREADSUP_COVERAGE_ALLOWANCE=1", NULL
    };
    char root[4096];
    int rc = cic_repo_root(root, sizeof root);
    if (rc == 0 && chdir(root) != 0)
        rc = 2;
    if (rc == 0)
        rc = tsw_snap_save();
    if (rc == 0)
        rc = tsw_cov_case(0, "the complete scan did not pass its coverage "
                             "expectation", case1);
    if (rc == 0)
        rc = tsw_cov_case(2, "a scan missing a whole declared root was not "
                             "UNPROVEN", case2);
    if (rc == 0)
        rc = tsw_cov_case(1, "an allowance above the true shortfall was "
                             "silently tolerated", case3);
    if (rc == 0)
        fputs("[check_thread_supervision] SELFTEST PASS (a full scan "
              "passes coverage, a scan short one declared root is UNPROVEN "
              "exit 2, and an allowance above the true shortfall is a "
              "stale-ratchet exit 1)\n", stdout);
    return rc;
}
