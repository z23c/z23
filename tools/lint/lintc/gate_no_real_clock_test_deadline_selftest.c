/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-no-real-clock-test-deadline, split out of
 * gate_no_real_clock_test_deadline.c to keep that file well under the
 * family line-count ceiling. Reuses the gate's own ZCL_REAL_CLOCK_GATE_*
 * env-var sandbox seam (nrc_run_for_selftest), mirroring the shell
 * original's --selftest exactly: a fresh sandbox directory, one planted
 * fixture at a time, run the gate against it via the same override knobs.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

int nrc_run_for_selftest(FILE *out, FILE *err);

struct nrc_st_env {
    char root[4096];
    char srcdir[4096];
    char glob[4096];
};

static int nrc_st_setenv(const struct nrc_st_env *e, const char *glob_pat,
                         const char *floor)
{
    (void)e;
    return setenv("ZCL_REAL_CLOCK_GATE_SCAN_GLOB", glob_pat, 1) != 0
        || setenv("ZCL_REAL_CLOCK_GATE_FILE_FLOOR", floor, 1) != 0
        || setenv("ZCL_LINT_MODE", "FAIL", 1) != 0;
}

static int nrc_st_run(const struct nrc_st_env *e, int *rc_out, char *both,
                      size_t cap)
{
    if (nrc_st_setenv(e, e->glob, "1"))
        return die("z23-lint: setenv failed\n", "");
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out)
            fclose(out);
        if (err)
            fclose(err);
        return die("z23-lint: tmpfile failed\n", "");
    }
    *rc_out = nrc_run_for_selftest(out, err);
    char bo[8192], be[8192];
    int rc = csr_slurp(out, bo, sizeof bo) | csr_slurp(err, be, sizeof be);
    fclose(out);
    fclose(err);
    if (rc)
        return rc;
    return ovf(snprintf(both, cap, "%s%s", bo, be), cap);
}

static int nrc_st_plant(const struct nrc_st_env *e, const char *body)
{
    char path[4096];
    return ovf(snprintf(path, sizeof path, "%s/sandbox_probe.c", e->srcdir),
              sizeof path)
        || csr_write(path, body);
}

static int nrc_st_expect(const struct nrc_st_env *e, int want_fail,
                         const char *msg, const char *body)
{
    if (nrc_st_plant(e, body))
        return 1;
    int rc = 0;
    char both[16384];
    if (nrc_st_run(e, &rc, both, sizeof both))
        return 1;
    if (want_fail && rc == 0) {
        fprintf(stderr, "check_no_real_clock_test_deadline selftest: "
                "SELFTEST FAILED — %s\n", msg);
        return 1;
    }
    if (!want_fail && rc != 0) {
        fprintf(stderr, "check_no_real_clock_test_deadline selftest: "
                "SELFTEST FAILED — %s (rc=%d)\n%s\n", msg, rc, both);
        return 1;
    }
    return 0;
}

static const char k_nrc_st_bare_assert[] =
    "int t_probe(void) {\n"
    "    int64_t started = clock_gettime_stub();\n"
    "    ASSERT(clock_gettime(CLOCK_MONOTONIC, &ts) == 0 && ts.tv_sec - " // platform-ok: fixture text the gate must trip on, never compiled
    "started < 1);\n"
    "    return 0;\n"
    "}\n";
static const char k_nrc_st_bare_poll[] =
    "static bool probe(void) {\n"
    "    bool done = false;\n"
    "    for (unsigned i = 0; i < 250; i++) {\n"
    "        if (check_done()) { done = true; break; }\n"
    "        platform_sleep_ms(1);\n"
    "    }\n"
    "    return done;\n"
    "}\n";
static const char k_nrc_st_marked_assert[] =
    "int t_probe(void) {\n"
    "    ASSERT(clock_gettime(CLOCK_MONOTONIC, &ts) == 0); /* real-clock: " // platform-ok: fixture text the gate must trip on, never compiled
    "selftest fixture */\n"
    "    return 0;\n"
    "}\n";
static const char k_nrc_st_marked_poll[] =
    "static bool probe(void) {\n"
    "    bool done = false;\n"
    "    for (unsigned i = 0; i < 250; i++) {\n"
    "        if (check_done()) { done = true; break; }\n"
    "        platform_sleep_ms(1); /* real-clock: selftest fixture */\n"
    "    }\n"
    "    return done;\n"
    "}\n";
static const char k_nrc_st_virtual[] =
    "int t_probe(void) {\n"
    "    int64_t now = 1000;\n"
    "    ASSERT(check_timeouts(&dm, now + 3600) == 1);\n"
    "    for (unsigned i = 0; i < 250; i++) { do_work(i); }\n"
    "    return 0;\n"
    "}\n";

static int nrc_st_hollow(const struct nrc_st_env *e)
{
    char nomatch[4096];
    if (ovf(snprintf(nomatch, sizeof nomatch,
                     "%s/nothing-matches-this-*.c", e->srcdir),
            sizeof nomatch))
        return 1;
    struct nrc_st_env h = *e;
    if (ovf(snprintf(h.glob, sizeof h.glob, "%s", nomatch), sizeof h.glob))
        return 1;
    int rc = 0;
    char both[16384];
    if (nrc_st_run(&h, &rc, both, sizeof both))
        return 1;
    if (rc != 2) {
        fprintf(stderr, "check_no_real_clock_test_deadline selftest: an "
                "EMPTY scan set exited %d, not 2\n", rc);
        return 1;
    }
    return 0;
}

int check_no_real_clock_test_deadline_selftest(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-nrc-XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdtemp failed: %s\n", tmpl);
    struct nrc_st_env e;
    memset(&e, 0, sizeof e);
    int bad = ovf(snprintf(e.root, sizeof e.root, "%s", root), sizeof e.root)
        || ovf(snprintf(e.srcdir, sizeof e.srcdir, "%s/src", root),
              sizeof e.srcdir)
        || csr_mkdirs(e.srcdir)
        || ovf(snprintf(e.glob, sizeof e.glob, "%s/*.c", e.srcdir),
              sizeof e.glob);
    if (!bad) {
        bad |= nrc_st_expect(&e, 1,
                             "a real clock read inside an ASSERT was "
                             "reported clean", k_nrc_st_bare_assert);
        bad |= nrc_st_expect(&e, 1,
                             "a fixed-iteration poll loop sleeping toward "
                             "a deadline was reported clean",
                             k_nrc_st_bare_poll);
        bad |= nrc_st_expect(&e, 0,
                             "a marked real-clock assertion was still "
                             "reported as a violation", k_nrc_st_marked_assert);
        bad |= nrc_st_expect(&e, 0,
                             "a marked fixed-iteration poll loop was still "
                             "reported as a violation", k_nrc_st_marked_poll);
        bad |= nrc_st_expect(&e, 0,
                             "virtual time (an injected now, no real clock "
                             "read) was reported as a violation",
                             k_nrc_st_virtual);
        bad |= nrc_st_hollow(&e);
    }
    (void)rap_rm_rf(root);
    unsetenv("ZCL_REAL_CLOCK_GATE_SCAN_GLOB");
    unsetenv("ZCL_REAL_CLOCK_GATE_FILE_FLOOR");
    unsetenv("ZCL_LINT_MODE");
    return st_ok(bad, "[check_no_real_clock_test_deadline] SELFTEST PASSED "
                 "(bare assertion, bare poll loop, marked assertion, "
                 "marked poll loop, virtual-time clean file, hollow "
                 "scan)\n");
}
