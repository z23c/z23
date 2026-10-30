/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check_blocker_handoff_declared
 * (gate_blocker_handoff_declared.c). Builds a fixture tree under
 * $HOME/.local/state/zclassic23/scratch (never a bare temp path) with its
 * own scan root, remedy and decision tables and baseline, drives it through
 * env overrides, and proves each case: clean pass, a new unbaselined
 * violation fails, a stale baseline entry fails, an escape-armed raise is
 * out of scope, a wrapper file that assigns escape_action aborts, a missing
 * table fails closed, and UPDATE mode rewrites the baseline.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "lintc_text.h"
#include "gate_blocker_handoff_declared_priv.h"

enum { BHX_PATH = 1024, BHX_TEXT = 4096 };
enum { BHX_CLEAN, BHX_VIOLATION, BHX_STALE, BHX_WRAPPER, BHX_MISSING,
       BHX_UPDATE };

static const char k_bhx_src[] =
    "#define AUTO_BLOCKER_ID \"auto.heal\"\n"
    "void a_work(struct zcl_blocker *b)\n"
    "{\n"
    "    blocker_init(b, AUTO_BLOCKER_ID, 0);\n"
    "    blocker_init(b, \"own.nodecision\", 0);\n"
    "%s"
    "}\n"
    "\n"
    "void a_arm(struct zcl_blocker *b)\n"
    "{\n"
    "    blocker_init(b, \"armed.id\", 0);\n"
    "    b->escape_action = \"go.now\";\n"
    "}\n";

static void bhx_env(const char *name, const char *val)
{
    setenv(name, val, 1);
}

static int bhx_write_table(const char *root)
{
    char path[BHX_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/tables/remedy.def", root),
             sizeof path))
        return 2;
    int rc = csr_write(path,
                       "ZCL_BLOCKER_REMEDY(auto.heal, condition_engine_healer)\n"
                       "ZCL_BLOCKER_REMEDY(own.nodecision, OWNER)\n"
                       "ZCL_BLOCKER_REMEDY(armed.id, OWNER)\n");
    if (rc)
        return rc;
    if (ovf(snprintf(path, sizeof path, "%s/tables/decisions.def", root),
             sizeof path))
        return 2;
    return csr_write(path,
                     "ZCL_BLOCKER_DECISION(decided.id, choose between X and Y)\n");
}

static int bhx_write_src(const char *root, int stuck)
{
    char path[BHX_PATH], text[BHX_TEXT];
    if (ovf(snprintf(path, sizeof path, "%s/fsrc/a.c", root), sizeof path))
        return 2;
    const char *extra = stuck ? "    blocker_init(b, \"stuck.horn\", 0);\n" : "";
    if (ovf(snprintf(text, sizeof text, k_bhx_src, extra), sizeof text))
        return 2;
    return csr_write(path, text);
}

static int bhx_write_baseline(const char *root, const char *body)
{
    char path[BHX_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/base.txt", root), sizeof path))
        return 2;
    return csr_write(path, body);
}

static int bhx_fixture(const char *root, int kind)
{
    char path[BHX_PATH];
    /* The wrapper case plants a poisoned wrapper that the gate re-checks on
     * every later run. Clear it first so only the wrapper case sees it. */
    if (ovf(snprintf(path, sizeof path, "%s/engine/services/src/"
                     "invariant_sentinel.c", root), sizeof path))
        return 2;
    unlink(path);
    int rc = bhx_write_src(root, kind == BHX_VIOLATION || kind == BHX_UPDATE);
    if (rc == 0)
        rc = bhx_write_table(root);
    if (rc)
        return rc;
    if (kind == BHX_STALE)
        rc = bhx_write_baseline(root, "own.nodecision\ngui.stale\n");
    else
        rc = bhx_write_baseline(root, "own.nodecision\n");
    if (rc == 0 && kind == BHX_WRAPPER) {
        if (ovf(snprintf(path, sizeof path, "%s/engine/services/src/"
                         "invariant_sentinel.c", root), sizeof path))
            return 2;
        rc = csr_write(path, "void sentinel_raise_blocker_fixture(void)\n"
                             "{\n    rec.escape_action = \"x\";\n}\n");
    }
    return rc;
}

static void bhx_set_env(int kind)
{
    bhx_env("ZCL_BLOCKER_HANDOFF_SCAN_ROOTS", "fsrc");
    bhx_env("ZCL_BLOCKER_HANDOFF_REMEDY_TABLE",
            kind == BHX_MISSING ? "tables/absent.def" : "tables/remedy.def");
    bhx_env("ZCL_BLOCKER_HANDOFF_DECISION_TABLE", "tables/decisions.def");
    bhx_env("ZCL_BLOCKER_HANDOFF_BASELINE", "base.txt");
    bhx_env("ZCL_BLOCKER_HANDOFF_FILE_FLOOR", "1");
    bhx_env("ZCL_BLOCKER_HANDOFF_SITE_FLOOR", "1");
    bhx_env("ZCL_BLOCKER_HANDOFF_REMEDY_FLOOR", "1");
    bhx_env("ZCL_BLOCKER_HANDOFF_DECISION_FLOOR", "1");
    bhx_env("ZCL_LINT_MODE", kind == BHX_UPDATE ? "UPDATE" : "FAIL");
}

static int bhx_baseline_has(const char *root, const char *needle)
{
    char path[BHX_PATH], line[512];
    if (ovf(snprintf(path, sizeof path, "%s/base.txt", root), sizeof path))
        return -1;
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    int found = 0;
    while (!found && fgets(line, sizeof line, f))
        if (strstr(line, needle))
            found = 1;
    fclose(f);
    return found;
}

static const struct { const char *name; int kind; int want; } k_bhx_cases[] = {
    { "clean fixture passes", BHX_CLEAN, 0 },
    { "new unbaselined empty-escape id fails", BHX_VIOLATION, 1 },
    { "stale baseline entry fails", BHX_STALE, 1 },
    { "wrapper assigning escape_action aborts", BHX_WRAPPER, 2 },
    { "missing remedy table fails closed", BHX_MISSING, 2 },
    { "UPDATE mode rewrites the baseline", BHX_UPDATE, 0 },
};

static int bhx_run_case(const char *root, int i)
{
    if (bhx_fixture(root, k_bhx_cases[i].kind))
        return 2;
    bhx_set_env(k_bhx_cases[i].kind);
    FILE *sink = tmpfile();
    if (!sink)
        return die("z23-lint: tmpfile failed\n", "");
    FILE *errk = tmpfile();
    if (!errk) {
        fclose(sink);
        return die("z23-lint: tmpfile failed\n", "");
    }
    int got = bhd_run_gate(root, sink, errk);
    fclose(sink);
    fclose(errk);
    if (k_bhx_cases[i].kind == BHX_UPDATE) {
        int has = bhx_baseline_has(root, "stuck.horn");
        if (has != 1)
            got = -9; /* force mismatch: UPDATE must record the id */
    }
    if (got != k_bhx_cases[i].want) {
        fprintf(stderr, "check_blocker_handoff_declared selftest: %s: "
                "want rc=%d got rc=%d\n", k_bhx_cases[i].name,
                k_bhx_cases[i].want, got);
        return 1;
    }
    printf("  selftest ok: %s (rc=%d)\n", k_bhx_cases[i].name, got);
    return 0;
}

int check_blocker_handoff_declared_selftest(void)
{
    char root[BHX_PATH];
    int rc = lct_scratch_dir(root, sizeof root, "blocker-handoff-declared");
    if (rc)
        return rc;
    char dirs[3][BHX_PATH];
    const char *leaves[] = { "/fsrc", "/tables", "/engine/services/src" };
    for (int i = 0; i < 3; i++) {
        if (ovf(snprintf(dirs[i], sizeof dirs[i], "%s%s", root, leaves[i]),
                 sizeof dirs[i]))
            return 2;
        rc = csr_mkdirs(dirs[i]);
        if (rc)
            return rc;
    }
    int bad = 0;
    size_t n = sizeof k_bhx_cases / sizeof k_bhx_cases[0];
    for (size_t i = 0; i < n; i++)
        bad |= bhx_run_case(root, (int)i) != 0;
    rap_rm_rf(root);
    unsetenv("ZCL_BLOCKER_HANDOFF_SCAN_ROOTS");
    unsetenv("ZCL_BLOCKER_HANDOFF_REMEDY_TABLE");
    unsetenv("ZCL_BLOCKER_HANDOFF_DECISION_TABLE");
    unsetenv("ZCL_BLOCKER_HANDOFF_BASELINE");
    unsetenv("ZCL_BLOCKER_HANDOFF_FILE_FLOOR");
    unsetenv("ZCL_BLOCKER_HANDOFF_SITE_FLOOR");
    unsetenv("ZCL_BLOCKER_HANDOFF_REMEDY_FLOOR");
    unsetenv("ZCL_BLOCKER_HANDOFF_DECISION_FLOOR");
    unsetenv("ZCL_LINT_MODE");
    if (bad)
        fputs("FAIL: check_blocker_handoff_declared selftest\n", stderr);
    return st_ok(bad, "check_blocker_handoff_declared selftest: OK\n");
}
