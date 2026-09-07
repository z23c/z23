/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-supervisor-progress-declared, split out of
 * gate_supervisor_progress_declared.c to keep that file well under the
 * family line-count ceiling. Plants a fresh sandbox child registration
 * under a sandbox scan root and asserts the gate distinguishes undeclared /
 * zero-window / zero-store (FAIL) from armed / raw-armed / exempt (PASS) —
 * the same six cases the replaced script's own --selftest names. The shell
 * script's own --selftest was found broken on the tree this gate was
 * ported from (ZCL_SUPERVISOR_PROGRESS_SCAN_ROOTS pointed at "$tmp/app",
 * a directory the fixture never created — the fixture always lived under
 * "$tmp/engine/..."), so this C selftest fixes the sandbox layout rather
 * than reproducing that bug, and tests the documented contract instead.
 * check-supervisor-progress-declared's Makefile target never invokes
 * --selftest either way (the shell script's was never wired in), so this
 * is new coverage, not a parity requirement.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

int spd_run_for_selftest(FILE *out, int file_floor, int child_floor);

static int spd_st_plant(const char *root, const char *decl)
{
    char path[4096], body[4096];
    if (ovf(snprintf(path, sizeof path,
                     "%s/engine/services/src/selftest_service.c", root),
            sizeof path))
        return 1;
    if (ovf(snprintf(body, sizeof body,
                     "#include \"util/supervisor.h\"\n"
                     "static struct liveness_contract g_c;\n"
                     "void selftest_register(void)\n"
                     "{\n"
                     "    liveness_contract_init(&g_c, \"selftest.child\");\n"
                     "    supervisor_child_id id = supervisor_register"
                     "(&g_c);\n"
                     "    %s\n"
                     "}\n", decl ? decl : ""),
            sizeof body))
        return 1;
    return csr_write(path, body);
}

static int spd_st_setenv(const char *root, const char *baseline)
{
    return setenv("ZCL_SUPERVISOR_PROGRESS_SCAN_ROOTS", root, 1) != 0
        || setenv("ZCL_SUPERVISOR_PROGRESS_BASELINE", baseline, 1) != 0
        || setenv("ZCL_LINT_MODE", "FAIL", 1) != 0;
}

static int spd_st_expect(const char *root, const char *baseline, int decl_ix,
                         const char *decl, int want_fail, const char *msg)
{
    (void)decl_ix;
    if (spd_st_plant(root, decl))
        return 1;
    if (spd_st_setenv(root, baseline))
        return die("z23-lint: setenv failed\n", "");
    FILE *out = tmpfile();
    if (!out)
        return die("z23-lint: tmpfile failed\n", "");
    int rc = spd_run_for_selftest(out, 1, 1);
    fclose(out);
    if (want_fail && rc == 0) {
        fprintf(stderr, "check_supervisor_progress_declared selftest: "
                "SELFTEST FAILED — %s\n", msg);
        return 1;
    }
    if (!want_fail && rc != 0) {
        fprintf(stderr, "check_supervisor_progress_declared selftest: "
                "SELFTEST FAILED — %s (rc=%d)\n", msg, rc);
        return 1;
    }
    return 0;
}

int check_supervisor_progress_declared_selftest(void)
{
    const char *td = env_or("TMPDIR", "test-tmp");
    (void)csr_mkdirs("test-tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-spd-XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdtemp failed: %s\n", tmpl);
    char baseline[4096];
    int bad = ovf(snprintf(baseline, sizeof baseline,
                          "%s/empty_baseline.txt", root), sizeof baseline)
        || csr_write(baseline, "");
    if (!bad) {
        bad |= spd_st_expect(root, baseline, 0, "", 1,
                             "an undeclared child did not fail the gate");
        bad |= spd_st_expect(root, baseline, 1,
                             "supervisor_set_progress_max_quiet(id, "
                             "900000000);", 0,
                             "an ARMED child was still reported "
                             "undeclared");
        bad |= spd_st_expect(root, baseline, 2,
                             "supervisor_set_progress_exempt(id, \"pure "
                             "sampler, no work units\");", 0,
                             "an EXEMPT child was still reported "
                             "undeclared");
        bad |= spd_st_expect(root, baseline, 3,
                             "supervisor_set_progress_max_quiet(id, 0);", 1,
                             "a literal-zero window counted as a policy");
        bad |= spd_st_expect(root, baseline, 4,
                             "atomic_store(&g_c.progress_max_quiet_us, "
                             "(int64_t)0);", 1,
                             "a raw zero store counted as a policy");
        bad |= spd_st_expect(root, baseline, 5,
                             "atomic_store(&g_c.progress_max_quiet_us, "
                             "(int64_t)900000000);", 0,
                             "a raw NON-zero store was not recognised as "
                             "armed");
    }
    (void)rap_rm_rf(root);
    unsetenv("ZCL_SUPERVISOR_PROGRESS_SCAN_ROOTS");
    unsetenv("ZCL_SUPERVISOR_PROGRESS_BASELINE");
    unsetenv("ZCL_LINT_MODE");
    return st_ok(bad, "[check_supervisor_progress_declared] SELFTEST PASS "
                 "(undeclared/zero-window/zero-store fail; armed, "
                 "raw-armed and exempt pass)\n");
}
