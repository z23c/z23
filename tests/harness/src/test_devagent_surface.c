/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Coverage for the pure primitives behind the dev.agent.* command surface
 * (tools/command/native_devagent.c).
 *
 * Two of these primitives decide whether an agent is told the truth:
 *
 *   - zcl_devagent_verdict_parse() reads test_parallel's SUITE VERDICT line.
 *     A MISSING field must read back as -1, never 0, so a run that executed
 *     nothing cannot serialize like one that said so.
 *
 *   - zcl_devagent_mutate_line() decides what dev.agent.mutate writes into a
 *     source file. A rule must not match inside a string literal or a
 *     comment, or the check would report on a mutation that never happened.
 *
 * Pure and deterministic: no clock, no RNG, no spawn, no I/O except the
 * filesystem probe in the checkout-root leg, which uses only paths the suite
 * creates under its own temp directory. */

/* realpath() is declared by glibc only through the fortify inline unless a
 * feature-test macro asks for it; the macro is a hard requirement at -O0 or
 * on another libc. Must precede the first #include (<features.h>). */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"

#include "command/native_devagent.h"
#include "platform/directory_compat.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Exercise the production admission predicate without spawning. */
#define zcl_native_handle_dev_agent_ready tds_ready
#define zcl_native_handle_dev_agent_test tds_test
#define zcl_devagent_run_make tds_run_make
#define zcl_devagent_run_group tds_run_group
#include "../../../tools/command/native_devagent_command.c"
#undef zcl_devagent_run_group
#undef zcl_devagent_run_make
#undef zcl_native_handle_dev_agent_test
#undef zcl_native_handle_dev_agent_ready

static int tds_runner_status(int code, bool present, long long ran, long long failed,
                              const char *error)
{
    int failures = 0;
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.agent_test_run.v1");
    TEST("agent test: footer cannot override runner failure") {
        struct dva_run run = {.exit_code = code};
        struct zcl_devagent_verdict v = {
            .present = present, .mode = "cold", .groups_total = 1,
            .groups_ran = ran, .groups_failed = failed, .groups_gated = ran == 0,
        };
        char line[256];
        bool proven = dva_test_verdict_proven(&reply, &run, &v, line, sizeof(line));
        if (proven != (error == NULL))
            printf("  runner status=%d accepted=%d\n", code, proven);
        ASSERT_EQ(proven, error == NULL);
        if (error) {
            ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_FAILED);
            ASSERT_STR_EQ(reply.error.code, error);
        }
        PASS();
    }
_test_next:;
    zcl_command_reply_free(&reply);
    return failures;
}

static int tds_runner_status_tests(void)
{
    int failures = 0;
    failures += tds_runner_status(0, true, 1, 0, NULL);
    failures += tds_runner_status(23, true, 1, 0, "RUNNER_EXIT_NONZERO");
    failures += tds_runner_status(143, true, 1, 0, "RUNNER_EXIT_NONZERO");
    failures += tds_runner_status(137, true, 1, 0, "RUNNER_EXIT_NONZERO");
    failures += tds_runner_status(-1, true, 1, 0, "RUNNER_EXIT_NONZERO");
    failures += tds_runner_status(23, true, 1, 1, "TEST_GROUP_FAILED");
    failures += tds_runner_status(23, false, 1, 0, "NO_SUITE_VERDICT");
    failures += tds_runner_status(23, true, 0, 0, "NO_GROUP_RAN");
    return failures;
}

/* Write an empty file at <dir>/<rel>, creating parent directories. */
static bool tds_touch(const char *dir, const char *rel)
{
    char path[1024];
    if (snprintf(path, sizeof(path), "%s/%s", dir, rel) < 0)
        return false;
    if (!platform_directory_ensure(dir, 0700))
        return false;
    for (char *p = path + strlen(dir) + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        bool made = platform_directory_ensure(path, 0700);
        *p = '/';
        if (!made)
            return false;
    }
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    return fclose(f) == 0;
}

int test_devagent_surface(void);
int test_devagent_surface(void)
{
    int failures = tds_runner_status_tests();

    /* ─────────────────────── SUITE VERDICT parsing ─────────────────────── */

    TEST("verdict: a complete cold line parses every field") {
        struct zcl_devagent_verdict v;
        const char *line =
            "\nSUITE VERDICT mode=cold groups_total=1016 groups_ran=1 "
            "groups_cached=0 groups_gated=1015 groups_failed=0 self_skips=0 "
            "env_unobserved=0 toolkey=f455dfbfbf7c\n";
        ASSERT(zcl_devagent_verdict_parse(line, &v));
        ASSERT(v.present);
        ASSERT_STR_EQ(v.mode, "cold");
        ASSERT_EQ(v.groups_total, 1016);
        ASSERT_EQ(v.groups_ran, 1);
        ASSERT_EQ(v.groups_cached, 0);
        ASSERT_EQ(v.groups_gated, 1015);
        ASSERT_EQ(v.groups_failed, 0);
        ASSERT_EQ(v.self_skips, 0);
        ASSERT_EQ(v.env_unobserved, 0);
        ASSERT_STR_EQ(v.toolkey, "f455dfbfbf7c");
        ASSERT(!v.hotswap);
        PASS();
    }

    /* A field the runner did not print must never read back as 0, which
     * downstream means "measured, and it was none". */
    TEST("verdict: a MISSING numeric field reads -1, never 0") {
        struct zcl_devagent_verdict v;
        const char *line = "SUITE VERDICT mode=cold groups_total=5\n";
        ASSERT(zcl_devagent_verdict_parse(line, &v));
        ASSERT_EQ(v.groups_total, 5);
        ASSERT_EQ(v.groups_ran, -1);
        ASSERT_EQ(v.groups_failed, -1);
        ASSERT_EQ(v.groups_cached, -1);
        PASS();
    }

    TEST("verdict: a zero groups_ran is preserved as zero, not as missing") {
        struct zcl_devagent_verdict v;
        const char *line =
            "SUITE VERDICT mode=cached groups_total=9 groups_ran=0 "
            "groups_cached=9 groups_failed=0\n";
        ASSERT(zcl_devagent_verdict_parse(line, &v));
        ASSERT_EQ(v.groups_ran, 0);
        ASSERT_EQ(v.groups_cached, 9);
        ASSERT_STR_EQ(v.mode, "cached");
        PASS();
    }

    TEST("verdict: no SUITE VERDICT line means present=false, not a zero run") {
        struct zcl_devagent_verdict v;
        ASSERT(!zcl_devagent_verdict_parse("ALL TESTS PASSED\n", &v));
        ASSERT(!v.present);
        ASSERT_EQ(v.groups_ran, -1);
        PASS();
    }

    TEST("verdict: NULL text initializes the struct instead of leaving it") {
        struct zcl_devagent_verdict v;
        memset(&v, 0x5a, sizeof(v));
        ASSERT(!zcl_devagent_verdict_parse(NULL, &v));
        ASSERT(!v.present);
        ASSERT_EQ(v.groups_failed, -1);
        PASS();
    }

    /* A transcript can quote the verdict line in prose before printing it;
     * the real one is last. */
    TEST("verdict: the LAST verdict line in a transcript wins") {
        struct zcl_devagent_verdict v;
        const char *text =
            "the gate greps for SUITE VERDICT mode=cold groups_ran=999\n"
            "...\n"
            "SUITE VERDICT mode=cold groups_ran=2 groups_failed=1\n";
        ASSERT(zcl_devagent_verdict_parse(text, &v));
        ASSERT_EQ(v.groups_ran, 2);
        ASSERT_EQ(v.groups_failed, 1);
        PASS();
    }

    TEST("verdict: a hot-swapped run is flagged, never read as an ordinary one") {
        struct zcl_devagent_verdict v;
        const char *line =
            "SUITE VERDICT mode=cold groups_ran=1 groups_failed=0 "
            "toolkey=aaaa hotswap_module=0123456789ab hotswap_source=x\n";
        ASSERT(zcl_devagent_verdict_parse(line, &v));
        ASSERT(v.hotswap);
        PASS();
    }

    /* ───────────────────────── mutation rules ─────────────────────────── */

    TEST("mutate: == becomes != and reports the rule and column") {
        struct zcl_devagent_mutation m;
        char out[256];
        ASSERT(zcl_devagent_mutate_line("    if (a == b) return 1;", &m, out,
                                        sizeof(out)));
        ASSERT_STR_EQ(out, "    if (a != b) return 1;");
        ASSERT_STR_EQ(m.rule, "eq_to_ne");
        ASSERT_STR_EQ(m.before, "==");
        ASSERT_STR_EQ(m.after, "!=");
        ASSERT_EQ(m.column, 11);
        PASS();
    }

    TEST("mutate: != becomes ==") {
        struct zcl_devagent_mutation m;
        char out[256];
        ASSERT(zcl_devagent_mutate_line("  return x != 0;", &m, out,
                                        sizeof(out)));
        ASSERT_STR_EQ(out, "  return x == 0;");
        ASSERT_STR_EQ(m.rule, "ne_to_eq");
        PASS();
    }

    TEST("mutate: && becomes || and || becomes &&") {
        struct zcl_devagent_mutation m;
        char out[256];
        ASSERT(zcl_devagent_mutate_line("  ok = a && b;", &m, out, sizeof(out)));
        ASSERT_STR_EQ(out, "  ok = a || b;");
        ASSERT_STR_EQ(m.rule, "and_to_or");
        ASSERT(zcl_devagent_mutate_line("  ok = a || b;", &m, out, sizeof(out)));
        ASSERT_STR_EQ(out, "  ok = a && b;");
        ASSERT_STR_EQ(m.rule, "or_to_and");
        PASS();
    }

    TEST("mutate: <= loses its equality and >= loses its equality") {
        struct zcl_devagent_mutation m;
        char out[256];
        ASSERT(zcl_devagent_mutate_line("  if (n <= cap) {", &m, out,
                                        sizeof(out)));
        ASSERT_STR_EQ(out, "  if (n < cap) {");
        ASSERT_STR_EQ(m.rule, "le_to_lt");
        ASSERT(zcl_devagent_mutate_line("  if (n >= cap) {", &m, out,
                                        sizeof(out)));
        ASSERT_STR_EQ(out, "  if (n > cap) {");
        ASSERT_STR_EQ(m.rule, "ge_to_gt");
        PASS();
    }

    /* `x <<= 1` carries a `<=` at offset 1; flipping it yields the syntax
     * error `x << 1`, which teaches nothing about the test's coverage. */
    TEST("mutate: a compound shift-assign is not read as a comparison") {
        struct zcl_devagent_mutation m;
        char out[256];
        ASSERT(zcl_devagent_mutate_line("  x <<= 1;", &m, out, sizeof(out)));
        ASSERT_STR_EQ(m.rule, "int_bump");
        ASSERT_STR_EQ(out, "  x <<= 2;");
        PASS();
    }

    TEST("mutate: true and false flip, as whole words only") {
        struct zcl_devagent_mutation m;
        char out[256];
        ASSERT(zcl_devagent_mutate_line("  return true;", &m, out, sizeof(out)));
        ASSERT_STR_EQ(out, "  return false;");
        ASSERT_STR_EQ(m.rule, "true_to_false");
        ASSERT(zcl_devagent_mutate_line("  return false;", &m, out,
                                        sizeof(out)));
        ASSERT_STR_EQ(out, "  return true;");
        ASSERT_STR_EQ(m.rule, "false_to_true");
        /* `truest` is not `true`: with no other rule the mutation is
         * refused, not applied to part of an identifier. */
        ASSERT(!zcl_devagent_mutate_line("  truest_value;", &m, out,
                                         sizeof(out)));
        PASS();
    }

    TEST("mutate: an integer literal is bumped by exactly one") {
        struct zcl_devagent_mutation m;
        char out[256];
        ASSERT(zcl_devagent_mutate_line("  size_t cap = 4096;", &m, out,
                                        sizeof(out)));
        ASSERT_STR_EQ(out, "  size_t cap = 4097;");
        ASSERT_STR_EQ(m.rule, "int_bump");
        ASSERT_STR_EQ(m.before, "4096");
        ASSERT_STR_EQ(m.after, "4097");
        PASS();
    }

    /* Editing inside a string literal cannot fail a test, so it would
     * report a meaningless "noticed=false" verdict. */
    TEST("mutate: an operator inside a string literal is not a candidate") {
        struct zcl_devagent_mutation m;
        char out[256];
        ASSERT(!zcl_devagent_mutate_line("  puts(\"a == b\");", &m, out,
                                         sizeof(out)));
        ASSERT_STR_EQ(m.rule, "");
        ASSERT_STR_EQ(out, "");
        PASS();
    }

    TEST("mutate: an escaped quote does not end the literal early") {
        struct zcl_devagent_mutation m;
        char out[256];
        ASSERT(!zcl_devagent_mutate_line("  puts(\"\\\" a == b\");", &m, out,
                                         sizeof(out)));
        PASS();
    }

    TEST("mutate: a trailing // comment is not a candidate") {
        struct zcl_devagent_mutation m;
        char out[256];
        ASSERT(!zcl_devagent_mutate_line("  step(); // a == b, or 42", &m, out,
                                         sizeof(out)));
        PASS();
    }

    /* Code before a trailing comment is still code. */
    TEST("mutate: code preceding a trailing comment is still mutated") {
        struct zcl_devagent_mutation m;
        char out[256];
        ASSERT(zcl_devagent_mutate_line("  if (a == b) x(); // note", &m, out,
                                        sizeof(out)));
        ASSERT_STR_EQ(out, "  if (a != b) x(); // note");
        PASS();
    }

    TEST("mutate: a line with no rule refuses instead of silently no-op'ing") {
        struct zcl_devagent_mutation m;
        char out[256];
        ASSERT(!zcl_devagent_mutate_line("  do_something(arg);", &m, out,
                                         sizeof(out)));
        ASSERT_STR_EQ(out, "");
        ASSERT_EQ(m.column, 0);
        PASS();
    }

    TEST("mutate: an empty line and a NULL line both refuse") {
        struct zcl_devagent_mutation m;
        char out[256];
        ASSERT(!zcl_devagent_mutate_line("", &m, out, sizeof(out)));
        ASSERT(!zcl_devagent_mutate_line(NULL, &m, out, sizeof(out)));
        PASS();
    }

    /* A buffer too small for the rewrite must refuse, not truncate the
     * line. */
    TEST("mutate: an undersized output buffer refuses rather than truncating") {
        struct zcl_devagent_mutation m;
        char out[8];
        ASSERT(!zcl_devagent_mutate_line("  if (a == b) return 1;", &m, out,
                                         sizeof(out)));
        PASS();
    }

    /* ──────────────────────── checkout-root walk ───────────────────────── */

    TEST("checkout root: found by walking up from a nested directory") {
        char dir[1024], nested[1200], found[1024], here[PATH_MAX];
        test_make_tmpdir(dir, sizeof(dir), "devagent", "root");
        ASSERT(tds_touch(dir, "Makefile"));
        ASSERT(tds_touch(dir, "engine/composition/commands/root.def"));
        ASSERT(tds_touch(dir, "tools/dev/test_group_catalog.def"));
        (void)snprintf(nested, sizeof(nested), "%s/engine/composition/commands", dir);
        ASSERT(zcl_devagent_checkout_root(nested, found, sizeof(found)));
        /* The answer is canonical; compare against the canonical fixture
         * path so a symlinked TMPDIR cannot flake the walk. */
        ASSERT(realpath(dir, here) != NULL);
        ASSERT_STR_EQ(found, here);
        test_cleanup_tmpdir(dir);
        PASS();
    }

    /* Two of three markers is not a checkout: the walk passes over the
     * inner directory and settles on the complete one above it, so
     * dev.agent.mutate cannot write into a partial checkout. Both
     * candidates live inside the fixture. */
    TEST("checkout root: a partial marker set is walked past, not accepted") {
        char outer[1024], inner[1200], deep[1400], found[1024], here[PATH_MAX];
        test_make_tmpdir(outer, sizeof(outer), "devagent", "partial");
        ASSERT(tds_touch(outer, "Makefile"));
        ASSERT(tds_touch(outer, "engine/composition/commands/root.def"));
        ASSERT(tds_touch(outer, "tools/dev/test_group_catalog.def"));
        (void)snprintf(inner, sizeof(inner), "%s/inner", outer);
        ASSERT(tds_touch(inner, "Makefile"));
        ASSERT(tds_touch(inner, "engine/composition/commands/root.def"));
        (void)snprintf(deep, sizeof(deep), "%s/inner/engine/composition/commands", outer);
        ASSERT(zcl_devagent_checkout_root(deep, found, sizeof(found)));
        ASSERT(realpath(outer, here) != NULL);
        ASSERT_STR_EQ(found, here);
        test_cleanup_tmpdir(outer);
        PASS();
    }

    TEST("checkout root: the filesystem root terminates the walk") {
        char found[1024];
        ASSERT(!zcl_devagent_checkout_root("/", found, sizeof(found)));
        PASS();
    }

    /* A symlinked route to a checkout answers the canonical path: dev.land
     * stores the string in a queue row that must read back. Proven through
     * a symlink, not a chdir (the parallel runner shares one cwd). */
    TEST("checkout root: a symlinked start answers the canonical path") {
        char dir[1024], alias[1100], found[1024], here[PATH_MAX];
        test_make_tmpdir(dir, sizeof(dir), "devagent", "canon");
        ASSERT(tds_touch(dir, "Makefile"));
        ASSERT(tds_touch(dir, "engine/composition/commands/root.def"));
        ASSERT(tds_touch(dir, "tools/dev/test_group_catalog.def"));
        (void)snprintf(alias, sizeof(alias), "%s/alias", dir);
        ASSERT(symlink(dir, alias) == 0);
        ASSERT(realpath(dir, here) != NULL);
        ASSERT(zcl_devagent_checkout_root(alias, found, sizeof(found)));
        ASSERT_STR_EQ(found, here);
        remove(alias);
        test_cleanup_tmpdir(dir);
        PASS();
    }

_test_next:;
    if (failures == 0)
        printf("test_devagent_surface: all passed\n");
    else
        printf("test_devagent_surface: %d FAILED\n", failures);
    return failures;
}
