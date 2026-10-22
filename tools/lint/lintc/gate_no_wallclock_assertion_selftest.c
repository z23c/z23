/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest of check-no-wallclock-assertion, the port of the shell
 * gate's selftest case for case. A fresh sandbox directory receives one
 * planted fixture at a time; wca_run_cfg() grades it with an empty allowlist,
 * ceiling 0 and a floor of 1, exactly the knobs the shell selftest set through
 * ZCL_WALLCLOCK_GATE_*. Proves: plain, wrapped, helper and out-parameter
 * violations are caught; function boundaries, local names and member arrows
 * do not leak taint; the clean idioms stay clean; an empty scan is exit 2;
 * an allowlisted file passes at its recorded count, fails when it grows and
 * fails when the row goes stale. The fixtures are guarded against going
 * hollow (a fixture that stopped carrying its shape proves nothing).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "gate_no_wallclock_assertion_priv.h"
#include "lintc.h"

enum { WCS_PATH = 4096 };

/* A violation written the way the two real ones in this tree were. */
static const char k_wcs_plain[] =
    "#include \"test/test_core.h\"\n"
    "#include \"platform/clock.h\"\n"
    "int t_probe(void)\n"
    "{\n"
    "    int failures = 0;\n"
    "    int64_t started = clock_now_monotonic_ns();\n"
    "    do_the_thing();\n"
    "    int64_t elapsed = clock_now_monotonic_ns() - started;\n"
    "    ASSERT(elapsed < 250000000LL);\n"
    "    return failures;\n"
    "}\n";
/* The SAME violation, wrapped across lines, reindented, and behind an
 * out-parameter clock read plus a local helper — the three shapes a
 * line-anchored matcher misses. */
static const char k_wcs_wrapped[] =
    "#include \"test/test_core.h\"\n"
    "static int64_t probe_now_us(void)\n"
    "{\n"
    "    struct timespec ts;\n"
    "    clock_gettime(CLOCK_MONOTONIC, &ts);\n" // platform-ok: fixture text the gate must trip on, never compiled
    "    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;\n"
    "}\n"
    "int t_probe(void)\n"
    "{\n"
    "    int failures = 0;\n"
    "    int64_t t0 = probe_now_us();\n"
    "    do_the_thing();\n"
    "    int64_t spent = probe_now_us() - t0;\n"
    "    PROBE_CHECK(\"finished promptly\",\n"
    "                spent\n"
    "                    <\n"
    "                        250000);\n"
    "    return failures;\n"
    "}\n";
/* Clean, and every line of it is an idiom this tree uses and must keep:
 * virtual time passed into the subject, CPU time, a reported duration, an
 * assertion MESSAGE mentioning elapsed, and a comment about wall clocks. */
static const char k_wcs_clean[] =
    "#include \"test/test_core.h\"\n"
    "/* elapsed wall-clock time is deliberately not asserted on here. */\n"
    "int t_probe(void)\n"
    "{\n"
    "    int failures = 0;\n"
    "    int64_t now = 1000;                       /* virtual time, injected */\n"
    "    ASSERT(check_timeouts(&dm, now + DL_REQUEST_TIMEOUT_SECS + 1) == 1);\n"
    "    ASSERT(dl_get_request_timeout_secs() == DL_REQUEST_TIMEOUT_SECS);\n"
    "    struct timespec cpu;\n"
    "    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu);\n" // platform-ok: fixture text the gate must trip on, never compiled
    "    int64_t started = clock_now_monotonic_ns();\n"
    "    int ops = do_the_thing();\n"
    "    printf(\"took %.3f ms\\n\", (double)(clock_now_monotonic_ns() - started) / 1e6);\n"
    "    ASSERT(ops == 2);\n"
    "    ASSERT_EQ(strcmp(msg, \"elapsed\"), 0);\n"
    "    return failures;\n"
    "}\n";
static const char k_wcs_probe2[] =
    "int t_probe2(void)\n"
    "{\n"
    "    int failures = 0;\n"
    "    int64_t s2 = clock_now_monotonic_ns();\n"
    "    do_the_thing();\n"
    "    ASSERT(clock_now_monotonic_ns() - s2 < 250000000LL);\n"
    "    return failures;\n"
    "}\n";

#define WCS_CAPTURE \
    "static struct timespec shared;\n" \
    "static void capture(void)\n" \
    "{\n" \
    "    clock_gettime" \
    "(CLOCK_MONOTONIC, &shared);\n" \
    "}\n"

struct wcs_case { int want_fail; const char *msg; const char *body; };

static const struct wcs_case k_wcs_cases[] = {
    { 1, "a plain 'elapsed < literal' assertion was reported CLEAN",
      k_wcs_plain },
    { 1, "the same violation wrapped across lines, behind a local helper "
         "and an out-parameter clock read, escaped the gate", k_wcs_wrapped },
    { 0, "a clean file (virtual time, CPU time, a REPORTED duration, an "
         "'elapsed' message) was reported as a violation", k_wcs_clean },
    { 0, "a multiline clock reader contaminated the preceding helper or a "
         "member arrow became subtraction",
      "static int ordinary_result(void) { return 7; }\n"
      "static int64_t actual_clock(\n"
      "    void)\n"
      "{\n"
      "    return clock_now_monotonic_ns();\n"
      "}\n"
      "int probe(struct row *row)\n"
      "{\n"
      "    int value = ordinary_result();\n"
      "    ASSERT(value - 1 == 6);\n"
      "    int64_t base = actual_clock();\n"
      "    ASSERT(row->ready && base > 0);\n"
      "}\n" },
    { 0, "a clock output name leaked into another function body",
      "static void report_clock(void)\n"
      "{\n"
      "    struct timespec out;\n"
      "    clock_gettime(CLOCK_MONOTONIC, &out);\n" // platform-ok: fixture text the gate must trip on, never compiled
      "}\n"
      "static int ordinary_result(int out)\n"
      "{\n"
      "    return out;\n"
      "}\n"
      "int probe(void)\n"
      "{\n"
      "    int value = ordinary_result(7);\n"
      "    ASSERT(value - 1 == 6);\n"
      "}\n" },
    { 1, "another function's constant shadowed a genuine multiline-reader "
         "interval",
      "static void virtual_fixture(void)\n"
      "{\n"
      "    int64_t elapsed = 7;\n"
      "    ASSERT(elapsed == 7);\n"
      "}\n"
      "static int64_t actual_clock(\n"
      "    void)\n"
      "{\n"
      "    return clock_now_monotonic_ns();\n"
      "}\n"
      "int probe(void)\n"
      "{\n"
      "    int64_t start = actual_clock();\n"
      "    int64_t elapsed = actual_clock() - start;\n"
      "    ASSERT(elapsed < 250000000);\n"
      "}\n" },
    { 1, "a genuine clock-output wrapper interval escaped function scoping",
      "static int observed_clock(struct timespec *output)\n"
      "{\n"
      "    return clock_gettime(CLOCK_MONOTONIC, output);\n" // platform-ok: fixture text the gate must trip on, never compiled
      "}\n"
      "int probe(void)\n"
      "{\n"
      "    struct timespec start, finish;\n"
      "    observed_clock(&start);\n"
      "    observed_clock(&finish);\n"
      "    int64_t elapsed = finish.tv_sec - start.tv_sec;\n"
      "    ASSERT(elapsed < 2);\n"
      "}\n" },
    { 1, "a formal timestamp escaped interval detection",
      "int probe(int64_t started)\n"
      "{\n"
      "    ASSERT(clock_now_monotonic_ns() - started < 250000000);\n"
      "}\n" },
    { 1, "a global timestamp escaped interval detection",
      "static int64_t started;\n"
      "int probe(void)\n"
      "{\n"
      "    ASSERT(clock_now_monotonic_ns() - started < 250000000);\n"
      "}\n" },
    { 1, "a member timestamp escaped interval detection",
      "int probe(struct record *record)\n"
      "{\n"
      "    ASSERT(clock_now_monotonic_ns() - record->started < 250000000);\n"
      "}\n" },
    { 1, "two clock readings in the same aggregate escaped detection",
      "int probe(void)\n"
      "{\n"
      "    struct record record;\n"
      "    clock_gettime(CLOCK_MONOTONIC, &record.started);\n" // platform-ok: fixture text the gate must trip on, never compiled
      "    clock_gettime(CLOCK_MONOTONIC, &record.finished);\n" // platform-ok: fixture text the gate must trip on, never compiled
      "    ASSERT(record.finished.tv_sec - record.started.tv_sec < 2);\n"
      "}\n" },
    { 1, "a numeric prefix hid an unknown timestamp operand",
      "int probe(int64_t started)\n"
      "{\n"
      "    ASSERT(clock_now_monotonic_ns() - (1 * started) < 250000000);\n"
      "}\n" },
    { 1, "a fixed offset hid a comparison of two real timestamps",
      "int probe(void)\n"
      "{\n"
      "    int64_t started = clock_now_monotonic_ns();\n"
      "    int64_t finished = clock_now_monotonic_ns();\n"
      "    ASSERT(started < finished - 10);\n"
      "}\n" },
    { 1, "a fixed offset hid two timestamps in the same aggregate",
      "int probe(void)\n"
      "{\n"
      "    struct record record;\n"
      "    clock_gettime(CLOCK_MONOTONIC, &record.started);\n" // platform-ok: fixture text the gate must trip on, never compiled
      "    clock_gettime(CLOCK_MONOTONIC, &record.finished);\n" // platform-ok: fixture text the gate must trip on, never compiled
      "    ASSERT(record.started.tv_sec < record.finished.tv_sec - 10);\n"
      "}\n" },
    { 1, "a declared global timestamp lost its capture-to-getter flow",
      WCS_CAPTURE
      "static long getter(void)\n"
      "{\n"
      "    return shared.tv_sec;\n"
      "}\n"
      "int probe(void)\n"
      "{\n"
      "    capture();\n"
      "    long first = getter();\n"
      "    capture();\n"
      "    long second = getter();\n"
      "    ASSERT(second - first < 2);\n"
      "}\n" },
    { 0, "a declared global timestamp contaminated a local or formal shadow",
      WCS_CAPTURE
      "static void parameter(struct timespec shared)\n"
      "{\n"
      "    ASSERT(shared.tv_sec - 1 == 6);\n"
      "}\n"
      "int probe(void)\n"
      "{\n"
      "    struct timespec shared = {7, 0};\n"
      "    ASSERT(shared.tv_sec - 1 == 6);\n"
      "}\n" },
    { 1, "an unresolved global declarator lost cross-helper flow",
      "static struct timespec unused, shared;\n"
      "static void capture(void)\n"
      "{\n"
      "    clock_gettime(CLOCK_MONOTONIC, &shared);\n" // platform-ok: fixture text the gate must trip on, never compiled
      "}\n"
      "static long getter(struct shared *other)\n"
      "{\n"
      "    return shared.tv_sec;\n"
      "}\n"
      "int probe(void)\n"
      "{\n"
      "    capture();\n"
      "    long first = getter(NULL);\n"
      "    capture();\n"
      "    long second = getter(NULL);\n"
      "    ASSERT(second - first < 2);\n"
      "}\n" },
    { 1, "a later local declaration hid an earlier global timestamp",
      WCS_CAPTURE
      "int probe(void)\n"
      "{\n"
      "    ASSERT(shared.tv_sec - 1 < 2);\n"
      "    struct timespec shared = {7, 0};\n"
      "    ASSERT(shared.tv_sec - 1 == 6);\n"
      "}\n" },
    { 1, "a closed nested shadow hid a subsequent global timestamp",
      WCS_CAPTURE
      "int probe(void)\n"
      "{\n"
      "    {\n"
      "        struct timespec shared = {7, 0};\n"
      "        ASSERT(shared.tv_sec - 1 == 6);\n"
      "    }\n"
      "    ASSERT(shared.tv_sec - 1 < 2);\n"
      "}\n" },
    { 1, "a multiplication expression hid a global clock observation",
      "static long multiplier, other;\n"
      "static void observed_clock(long *output)\n"
      "{\n"
      "    struct timespec stamp;\n"
      "    clock_gettime(CLOCK_MONOTONIC, &stamp);\n" // platform-ok: fixture text the gate must trip on, never compiled
      "    *output = stamp.tv_sec;\n"
      "}\n"
      "static void capture(void)\n"
      "{\n"
      "    observed_clock(&multiplier);\n"
      "}\n"
      "static long getter(void)\n"
      "{\n"
      "    other * multiplier;\n"
      "    return multiplier;\n"
      "}\n"
      "int probe(void)\n"
      "{\n"
      "    capture();\n"
      "    long first = getter();\n"
      "    capture();\n"
      "    long second = getter();\n"
      "    ASSERT(second - first < 2);\n"
      "}\n" },
};

struct wcs_env {
    char root[WCS_PATH], src[WCS_PATH], probe[WCS_PATH], glob[WCS_PATH],
        nothing[WCS_PATH], empty[WCS_PATH], allow1[WCS_PATH];
};

static int wcs_fail(const char *msg)
{
    fprintf(stderr, WCA_GATE ": SELFTEST FAILED — %s\n", msg);
    return 2;
}

/* Runs the gate with its report silenced, the way the shell selftest sent
 * both streams to /dev/null. */
static int wcs_grade(const char *glob, const char *allow, long ceiling)
{
    FILE *nul = fopen("/dev/null", "w");
    if (!nul)
        return -1;
    fflush(stderr);
    int saved = dup(STDERR_FILENO);
    if (saved < 0 || dup2(fileno(nul), STDERR_FILENO) < 0) {
        fclose(nul);
        return -1;
    }
    struct wca_cfg c = { glob, allow, ceiling, 1, "FAIL", nul, nul };
    int rc = wca_run_cfg(&c);
    fflush(stderr);
    dup2(saved, STDERR_FILENO);
    close(saved);
    fclose(nul);
    return rc;
}

static int wcs_expect(const struct wcs_env *e, int want_fail, const char *msg,
                      const char *body)
{
    if (csr_write(e->probe, body))
        return 2;
    int rc = wcs_grade(e->glob, e->empty, 0);
    if (rc < 0)
        return die("z23-lint: selftest cannot silence its report\n", "");
    if ((want_fail && rc == 0) || (!want_fail && rc != 0))
        return wcs_fail(msg);
    return 0;
}

static int wcs_guards(void)
{
    if (strcmp(k_wcs_wrapped, k_wcs_plain) == 0)
        return wcs_fail("the wrapped fixture is byte-identical to the plain "
                        "one; the wrap-dodge assertion is hollow");
    if (!strstr(k_wcs_plain, "clock_"))
        return wcs_fail("the plain fixture no longer reads a clock; it "
                        "cannot carry the violation it claims");
    if (!strstr(k_wcs_wrapped, "clock_"))
        return wcs_fail("the wrapped fixture no longer reads a clock; it "
                        "cannot carry the violation it claims");
    if (!strstr(k_wcs_wrapped, "clock_gettime(CLOCK_MONOTONIC, &ts)")) // platform-ok: fixture text the gate must trip on, never compiled
        return wcs_fail("the wrapped fixture lost its out-parameter clock "
                        "read; it is not testing that shape");
    if (!strstr(k_wcs_clean, "CLOCK_THREAD_CPUTIME_ID"))
        return wcs_fail("the clean fixture lost its CPU-time line; the 'CPU "
                        "time is not wall time' exemption is untested");
    if (!strstr(k_wcs_clean, "clock_now_monotonic_ns"))
        return wcs_fail("the clean fixture no longer READS a clock at all, "
                        "so proving it clean proves nothing about "
                        "reporting-vs-asserting");
    if (!strstr(k_wcs_clean, "ASSERT_EQ(strcmp(msg, \"elapsed\"), 0)"))
        return wcs_fail("the clean fixture lost the assertion whose MESSAGE "
                        "says 'elapsed'; the string-stripping exemption is "
                        "untested");
    return 0;
}

/* The allowlist half: a row tolerates exactly what it names. */
static int wcs_allowlist(const struct wcs_env *e)
{
    if (csr_write(e->probe, k_wcs_plain))
        return 2;
    int rc = wcs_grade(e->nothing, e->empty, 0);
    if (rc != 2)
        return wcs_fail("an EMPTY scan set did not exit 2; the gate can "
                        "pass by scanning nothing");
    if (wcs_grade(e->glob, e->allow1, 1) != 0)
        return wcs_fail("an allowlisted file at its recorded count was "
                        "still reported as a violation");
    char grown[sizeof k_wcs_plain + sizeof k_wcs_probe2];
    snprintf(grown, sizeof grown, "%s%s", k_wcs_plain, k_wcs_probe2);
    if (csr_write(e->probe, grown))
        return 2;
    if (wcs_grade(e->glob, e->allow1, 1) == 0)
        return wcs_fail("an allowlisted file that GREW a new clock-graded "
                        "assertion still passed; the ratchet does not "
                        "ratchet");
    if (csr_write(e->probe, k_wcs_clean))
        return 2;
    if (wcs_grade(e->glob, e->allow1, 1) == 0)
        return wcs_fail("a STALE allowlist row (file now clean) was "
                        "accepted");
    return 0;
}

static int wcs_prepare(struct wcs_env *e, char *root)
{
    int bad = ovf(snprintf(e->root, sizeof e->root, "%s", root), sizeof e->root)
        || ovf(snprintf(e->src, sizeof e->src, "%s/src", root), sizeof e->src)
        || csr_mkdirs(e->src)
        || ovf(snprintf(e->probe, sizeof e->probe, "%s/sandbox_probe.c",
                        e->src), sizeof e->probe)
        || ovf(snprintf(e->glob, sizeof e->glob, "%s/*.c", e->src),
               sizeof e->glob)
        || ovf(snprintf(e->nothing, sizeof e->nothing,
                        "%s/nothing-matches-this-*.c", e->src),
               sizeof e->nothing)
        || ovf(snprintf(e->empty, sizeof e->empty, "%s/empty_allowlist.txt",
                        root), sizeof e->empty)
        || ovf(snprintf(e->allow1, sizeof e->allow1, "%s/allow1.txt", root),
               sizeof e->allow1);
    if (bad || csr_write(e->empty, ""))
        return 2;
    char row[WCS_PATH + 4];
    if (ovf(snprintf(row, sizeof row, "%s 1\n", e->probe), sizeof row))
        return 2;
    return csr_write(e->allow1, row) ? 2 : 0;
}

int check_no_wallclock_assertion_selftest(void)
{
    int rc = wcs_guards();
    if (rc)
        return rc;
    const char *td = env_or("TMPDIR", "test-tmp");
    (void)csr_mkdirs("test-tmp");
    char tmpl[WCS_PATH];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-wca-XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdtemp failed: %s\n", tmpl);
    struct wcs_env e;
    memset(&e, 0, sizeof e);
    rc = wcs_prepare(&e, root);
    for (size_t i = 0; rc == 0 && i < sizeof k_wcs_cases / sizeof *k_wcs_cases;
         i++)
        rc = wcs_expect(&e, k_wcs_cases[i].want_fail, k_wcs_cases[i].msg,
                        k_wcs_cases[i].body);
    if (rc == 0)
        rc = wcs_allowlist(&e);
    (void)rap_rm_rf(root);
    if (rc)
        return rc;
    return fputs("[" WCA_GATE "] SELFTEST PASSED (plain/wrapped/helper/"
                 "out-param violations, function boundaries and local "
                 "names, member arrows, clean idioms, hollow scan, "
                 "allowlist honoured, growth and stale rows refused)\n",
                 stdout) == EOF
        ? die("z23-lint: write failed\n", "")
        : 0;
}
