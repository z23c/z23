/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for util/parse_num.h — zcl_parse_i64, the shared base-10
 * int64_t string parser that folds the two near-identical local
 * parsers that used to live in the chaos simulator and the
 * recovery-policy service.
 *
 * Pure: deterministic, no I/O, no global state, no clock. Table-driven. */

#include "test/test_core.h"

#include "util/parse_num.h"

#include <stdio.h>
#include <string.h>

#define PN_CHECK(name, expr) do {                                   \
    printf("parse_num: %s... ", (name));                            \
    if (expr) { printf("OK\n"); }                                   \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

int test_parse_num(void)
{
    printf("\n=== parse_num tests ===\n");
    int failures = 0;
    int64_t v;

    /* ── valid inputs ─────────────────────────────────────────── */
    v = -1;
    PN_CHECK("\"0\" parses to 0", zcl_parse_i64("0", &v) && v == 0);

    v = 0;
    PN_CHECK("\"42\" parses to 42", zcl_parse_i64("42", &v) && v == 42);

    v = 0;
    PN_CHECK("\"-42\" parses to -42", zcl_parse_i64("-42", &v) && v == -42);

    v = 0;
    PN_CHECK("\"+42\" parses to 42 (strtoll accepts leading +)",
             zcl_parse_i64("+42", &v) && v == 42);

    v = 0;
    PN_CHECK("INT64_MAX round-trips",
             zcl_parse_i64("9223372036854775807", &v) &&
             v == INT64_MAX);

    v = 0;
    PN_CHECK("INT64_MIN round-trips",
             zcl_parse_i64("-9223372036854775808", &v) &&
             v == INT64_MIN);

    v = 0;
    PN_CHECK("leading zeros accepted (\"007\" -> 7)",
             zcl_parse_i64("007", &v) && v == 7);

    /* ── invalid inputs: rejected, *out untouched policy is "false" ── */
    PN_CHECK("NULL string rejected", !zcl_parse_i64(NULL, &v));
    PN_CHECK("empty string rejected", !zcl_parse_i64("", &v));
    PN_CHECK("NULL out pointer rejected", !zcl_parse_i64("42", NULL));

    PN_CHECK("trailing garbage rejected (\"42abc\")",
             !zcl_parse_i64("42abc", &v));
    PN_CHECK("trailing space rejected (\"42 \")",
             !zcl_parse_i64("42 ", &v));
    /* strtoll(3) skips LEADING whitespace per POSIX, so a leading-space
     * input still parses cleanly (end lands on '\0'); documents actual
     * behavior rather than asserting a stricter contract this parser
     * doesn't implement. */
    v = 0;
    PN_CHECK("leading space tolerated like strtoll (\" 42\" -> 42)",
             zcl_parse_i64(" 42", &v) && v == 42);

    PN_CHECK("bare sign rejected (\"-\")", !zcl_parse_i64("-", &v));
    PN_CHECK("bare sign rejected (\"+\")", !zcl_parse_i64("+", &v));
    PN_CHECK("non-numeric string rejected (\"abc\")",
             !zcl_parse_i64("abc", &v));
    PN_CHECK("hex-looking string parsed as decimal prefix rejected "
             "(\"0x10\" has trailing garbage after \"0\")",
             !zcl_parse_i64("0x10", &v));

    /* Overflow: strtoll clamps to LLONG_MAX/MIN and sets errno=ERANGE;
     * the wrapper must reject it rather than silently returning the
     * clamped value. */
    PN_CHECK("overflow beyond INT64_MAX rejected",
             !zcl_parse_i64("99999999999999999999", &v));
    PN_CHECK("underflow beyond INT64_MIN rejected",
             !zcl_parse_i64("-99999999999999999999", &v));

    /* A failed parse must not silently succeed with garbage output —
     * spot check that a rejected call leaves the caller free to treat
     * *out as unspecified (the contract only promises *out is set on
     * success); this call must still return false. */
    v = 777;
    PN_CHECK("rejected parse still returns false regardless of *out",
             !zcl_parse_i64("not-a-number", &v));

    return failures;
}
