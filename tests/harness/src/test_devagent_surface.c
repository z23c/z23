/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Coverage for the pure primitives behind the dev.agent.* command surface
 * (tools/command/native_devagent.c).
 *
 * Two of these primitives decide whether an agent is told the truth:
 *
 *   - zcl_devagent_verdict_parse() reads test_parallel's own SUITE VERDICT
 *     line. If it returned 0 for a MISSING field, a run that executed nothing
 *     and a run that executed nothing-and-said-so would serialize identically
 *     — which is the exact failure dev.agent.test exists to make impossible.
 *     So a missing field must read back as -1, and that is asserted here.
 *
 *   - zcl_devagent_mutate_line() decides what dev.agent.mutate writes into a
 *     source file. A rule that silently matched inside a string literal or a
 *     comment would edit text the compiler never reads, and the check would
 *     report "the test did not notice" about a mutation that never happened.
 *
 * Pure and deterministic: no clock, no RNG, no spawn, no I/O except the
 * filesystem probe in the checkout-root leg, which uses only paths the suite
 * creates under its own temp directory. */

#include "test/test_core.h"

#include "command/native_devagent.h"
#include "platform/directory_compat.h"

#include <stdio.h>
#include <string.h>

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
    int failures = 0;

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

    /* The whole point of the -1 sentinel: a field the runner did not print
     * must never read back as the number zero, which downstream means
     * "measured, and it was none". */
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

    /* `x <<= 1` carries a `<=` at offset 1. Flipping it produces `x << 1` —
     * a syntax error, which the check would report as "the compiler noticed"
     * and teach nothing about the test's coverage. */
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
        /* `truest` is not `true`. With no other rule on the line the mutation
         * must be refused, not applied to a substring of an identifier. */
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

    /* Editing inside a string literal changes bytes the compiler emits but
     * not the logic a test group is asleep on; worse, it would report a
     * "noticed=false" verdict about a mutation that could never fail. */
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

    /* A buffer too small for the rewrite must refuse, not truncate the line
     * — a truncated line is a corrupted source file. */
    TEST("mutate: an undersized output buffer refuses rather than truncating") {
        struct zcl_devagent_mutation m;
        char out[8];
        ASSERT(!zcl_devagent_mutate_line("  if (a == b) return 1;", &m, out,
                                         sizeof(out)));
        PASS();
    }

    /* ──────────────────────── checkout-root walk ───────────────────────── */

    TEST("checkout root: found by walking up from a nested directory") {
        char dir[1024], nested[1200], found[1024];
        test_make_tmpdir(dir, sizeof(dir), "devagent", "root");
        ASSERT(tds_touch(dir, "Makefile"));
        ASSERT(tds_touch(dir, "engine/composition/commands/root.def"));
        ASSERT(tds_touch(dir, "tools/dev/test_group_catalog.def"));
        (void)snprintf(nested, sizeof(nested), "%s/engine/composition/commands", dir);
        ASSERT(zcl_devagent_checkout_root(nested, found, sizeof(found)));
        ASSERT_STR_EQ(found, dir);
        test_cleanup_tmpdir(dir);
        PASS();
    }

    /* Two of three markers is not a checkout: the walk must pass straight
     * over the inner directory and settle on the complete one above it.
     * Accepting a partial set would let dev.agent.mutate write into a
     * directory that is not the checkout the agent meant. Both candidates
     * live inside the fixture, so the assertion does not depend on where the
     * suite happens to be running. */
    TEST("checkout root: a partial marker set is walked past, not accepted") {
        char outer[1024], inner[1200], deep[1400], found[1024];
        test_make_tmpdir(outer, sizeof(outer), "devagent", "partial");
        ASSERT(tds_touch(outer, "Makefile"));
        ASSERT(tds_touch(outer, "engine/composition/commands/root.def"));
        ASSERT(tds_touch(outer, "tools/dev/test_group_catalog.def"));
        (void)snprintf(inner, sizeof(inner), "%s/inner", outer);
        ASSERT(tds_touch(inner, "Makefile"));
        ASSERT(tds_touch(inner, "engine/composition/commands/root.def"));
        (void)snprintf(deep, sizeof(deep), "%s/inner/engine/composition/commands", outer);
        ASSERT(zcl_devagent_checkout_root(deep, found, sizeof(found)));
        ASSERT_STR_EQ(found, outer);
        test_cleanup_tmpdir(outer);
        PASS();
    }

    TEST("checkout root: the filesystem root terminates the walk") {
        char found[1024];
        ASSERT(!zcl_devagent_checkout_root("/", found, sizeof(found)));
        PASS();
    }

_test_next:;
    if (failures == 0)
        printf("test_devagent_surface: all passed\n");
    else
        printf("test_devagent_surface: %d FAILED\n", failures);
    return failures;
}
