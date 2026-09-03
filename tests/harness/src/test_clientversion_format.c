/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Extensive, focused coverage for the pure logic in
 * platform/modules/util/src/clientversion.c: FormatVersion().
 *
 * test_encoding.c has exactly one FormatVersion assertion, and it only
 * drives the LIVE CLIENT_VERSION constant (build suffix 50 today, e.g.
 * "0.1.0"), so it never independently exercises the four build-suffix
 * branches:
 *
 *   build < 25   -> "-betaN"   where N = build+1        (1..25)
 *   25<=build<50 -> "-rcN"     where N = build-24        (1..25)
 *   build == 50  -> plain "major.minor.rev", no suffix
 *   build  > 50  -> "-N"       where N = build-50
 *
 * A boundary regression at 24/25/49/50/51 (off-by-one in either the
 * comparison operators or the offset arithmetic) would NOT be caught by
 * the existing single assertion. This file pins every named boundary
 * from the task brief, plus the major/minor/rev digit-extraction
 * arithmetic and out_size truncation safety.
 *
 * Pure, deterministic, no I/O / node / network / time / RNG. FormatVersion
 * is a plain snprintf-based formatter over an int, safe to drive directly
 * with synthetic nVersion values -- it does not have to be CLIENT_VERSION. */

#include "test/test_core.h"

#include "config/bundle_exporter.h"
#include "util/clientversion.h"

#include <string.h>
#include <stdio.h>

#define CVF_CHECK(name, expr) do { \
    printf("clientversion_format: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Build a synthetic nVersion from major/minor/rev/build the same way
 * CLIENT_VERSION is assembled in clientversion.h, so every case below
 * is driven through the real encoding, not a hand-picked magic number. */
static int cvf_make_version(int major, int minor, int rev, int build)
{
    return 1000000 * major + 10000 * minor + 100 * rev + build;
}

static bool cvf_source_id_shape_valid(const char *source_id)
{
    if (!source_id)
        return false;
    if (strnlen(source_id, 65) != 64)
        return false;
    for (size_t i = 0; i < 64; i++) {
        char c = source_id[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

/* One function per TEST, as the harness's hardcoded `goto _test_next`
 * requires. */
static int t_commit_getter_exact(void)
{
    int failures = 0;
    TEST("zcl_build_commit_full: returns exactly \"external\", NUL-terminated") {
        const char *full = zcl_build_commit_full();
        ASSERT(full != NULL);
        ASSERT_STR_EQ(full, "external");
        ASSERT_EQ(strlen(full), 8);
        PASS();
    } _test_next:;
    return failures;
}

static int t_commit_getter_stable(void)
{
    int failures = 0;
    TEST("zcl_build_commit_full: answer is stable across calls") {
        const char *a = zcl_build_commit_full();
        const char *b = zcl_build_commit_full();
        ASSERT(a != NULL && b != NULL);
        ASSERT_STR_EQ(a, b);
        PASS();
    } _test_next:;
    return failures;
}

int test_clientversion_format(void)
{
    int failures = 0;

    CVF_CHECK("canonical build bakes exact lowercase SHA-256 source authority",
              cvf_source_id_shape_valid(zcl_build_source_id_sha256()));
    CVF_CHECK("dev/test build bakes exact lowercase ABA receipt",
              cvf_source_id_shape_valid(
                  zcl_build_source_mutation_sha256()));
    CVF_CHECK("ordinary build does not claim resident source-CAS authority",
              strcmp(zcl_build_source_cas_sha3(), "unknown") == 0);
    CVF_CHECK("bundle exporter accepts canonical SHA-256 source authority",
              bundle_exporter_source_identity_is_exact_for_test(
                  zcl_build_source_id_sha256()));
    CVF_CHECK("bundle exporter rejects external Git trace sentinel",
              !bundle_exporter_source_identity_is_exact_for_test("external"));
    CVF_CHECK("bundle exporter rejects legacy 40-hex Git object id",
              !bundle_exporter_source_identity_is_exact_for_test(
                  "0123456789abcdef0123456789abcdef01234567"));
    CVF_CHECK("bundle exporter rejects uppercase source identity",
              !bundle_exporter_source_identity_is_exact_for_test(
                  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeF"));
    CVF_CHECK("unstamped standalone fallback is not canonical authority",
              !cvf_source_id_shape_valid("unknown"));

    /* ===================================================================
     * Part 1 -- beta branch (build < 25). Offset is build+1, so the
     * FIRST beta build (build==0) is "-beta1", not "-beta0", and the
     * LAST beta build (build==24) is "-beta25", not "-beta24". Pinning
     * both ends catches an off-by-one in the +1 offset itself.
     * =================================================================== */
    {
        char out[64];
        FormatVersion(cvf_make_version(0, 1, 0, 0), out, sizeof(out));
        CVF_CHECK("build=0 -> 0.1.0-beta1", strcmp(out, "0.1.0-beta1") == 0);
    }
    {
        char out[64];
        FormatVersion(cvf_make_version(0, 1, 0, 1), out, sizeof(out));
        CVF_CHECK("build=1 -> 0.1.0-beta2", strcmp(out, "0.1.0-beta2") == 0);
    }
    {
        char out[64];
        FormatVersion(cvf_make_version(0, 1, 0, 23), out, sizeof(out));
        CVF_CHECK("build=23 -> 0.1.0-beta24 (one below beta upper edge)",
                  strcmp(out, "0.1.0-beta24") == 0);
    }
    {
        /* The task brief's canonical boundary case: build==24 is the LAST
         * beta build (still < 25), and must map to beta25 via the +1
         * offset -- not roll over into the rc branch. */
        char out[64];
        FormatVersion(cvf_make_version(0, 1, 0, 24), out, sizeof(out));
        CVF_CHECK("build=24 -> 0.1.0-beta25 (last beta, +1 offset)",
                  strcmp(out, "0.1.0-beta25") == 0);
    }

    /* ===================================================================
     * Part 2 -- rc branch (25 <= build < 50). Offset is build-24, so the
     * FIRST rc build (build==25) is "-rc1" (first rc boundary) and the
     * LAST rc build (build==49) is "-rc25".
     * =================================================================== */
    {
        char out[64];
        FormatVersion(cvf_make_version(0, 1, 0, 25), out, sizeof(out));
        CVF_CHECK("build=25 -> 0.1.0-rc1 (first rc boundary)",
                  strcmp(out, "0.1.0-rc1") == 0);
    }
    {
        char out[64];
        FormatVersion(cvf_make_version(0, 1, 0, 26), out, sizeof(out));
        CVF_CHECK("build=26 -> 0.1.0-rc2", strcmp(out, "0.1.0-rc2") == 0);
    }
    {
        char out[64];
        FormatVersion(cvf_make_version(0, 1, 0, 48), out, sizeof(out));
        CVF_CHECK("build=48 -> 0.1.0-rc24 (one below rc upper edge)",
                  strcmp(out, "0.1.0-rc24") == 0);
    }
    {
        /* Task brief's canonical case: build==49 is the LAST rc build
         * (still < 50) -> rc25. A regression that used <= instead of <
         * for this branch's guard would push 49 into the plain-release
         * branch instead; this pins it stays "-rc25". */
        char out[64];
        FormatVersion(cvf_make_version(0, 1, 0, 49), out, sizeof(out));
        CVF_CHECK("build=49 -> 0.1.0-rc25 (last rc)",
                  strcmp(out, "0.1.0-rc25") == 0);
    }

    /* ===================================================================
     * Part 3 -- exact release (build == 50). Plain "major.minor.rev", NO
     * suffix at all. This is the ONLY case test_encoding.c exercises
     * today (via the live CLIENT_VERSION_BUILD==50), so we also assert a
     * NEGATIVE: the string must not contain a trailing '-' anywhere,
     * proving no beta/rc/build suffix leaked in.
     * =================================================================== */
    {
        char out[64];
        FormatVersion(cvf_make_version(0, 1, 0, 50), out, sizeof(out));
        CVF_CHECK("build=50 -> 0.1.0 (exact release, no suffix)",
                  strcmp(out, "0.1.0") == 0);
        CVF_CHECK("build=50 output has no '-' suffix character",
                  strchr(out, '-') == NULL);
    }

    /* ===================================================================
     * Part 4 -- post-release build suffix (build > 50). Offset is
     * build-50, so the FIRST post-release build (build==51) is "-1" (the
     * task brief's canonical case) and build==99 is "-49" (the highest
     * build value representable in the build field, since build is
     * `nVersion % 100`).
     * =================================================================== */
    {
        char out[64];
        FormatVersion(cvf_make_version(0, 1, 0, 51), out, sizeof(out));
        CVF_CHECK("build=51 -> 0.1.0-1 (first post-release build)",
                  strcmp(out, "0.1.0-1") == 0);
    }
    {
        char out[64];
        FormatVersion(cvf_make_version(0, 1, 0, 52), out, sizeof(out));
        CVF_CHECK("build=52 -> 0.1.0-2", strcmp(out, "0.1.0-2") == 0);
    }
    {
        char out[64];
        FormatVersion(cvf_make_version(0, 1, 0, 99), out, sizeof(out));
        CVF_CHECK("build=99 -> 0.1.0-49 (max build%100 value)",
                  strcmp(out, "0.1.0-49") == 0);
    }

    /* ===================================================================
     * Part 5 -- major/minor/rev digit extraction. FormatVersion decodes
     * nVersion via integer division/modulo:
     *   major = n / 1000000
     *   minor = (n / 10000) % 100
     *   rev   = (n / 100) % 100
     *   build = n % 100
     * Pin a version number that rolls EACH field simultaneously so a
     * wrong divisor/modulus in any one field (not just build) is caught,
     * and cross an explicit minor/rev boundary (minor 1->2, rev 99->0).
     * =================================================================== */
    {
        /* major=3, minor=7, rev=21, build=50 (plain release form so the
         * suffix branch doesn't interfere with reading the digits). */
        char out[64];
        FormatVersion(cvf_make_version(3, 7, 21, 50), out, sizeof(out));
        CVF_CHECK("major/minor/rev decode: 3.7.21 (build=50, no suffix)",
                  strcmp(out, "3.7.21") == 0);
    }
    {
        /* nVersion = 1020150 -> major=1, minor=1, rev=1, build=50
         * (1*1000000 + 1*10000 + 1*100 + 50 = 1010150, see below);
         * cross a minor-field boundary by comparing two adjacent
         * constructed versions that differ ONLY in minor: 1 vs 2. */
        char out_minor1[64], out_minor2[64];
        FormatVersion(cvf_make_version(1, 1, 50, 50), out_minor1, sizeof(out_minor1));
        FormatVersion(cvf_make_version(1, 2, 50, 50), out_minor2, sizeof(out_minor2));
        CVF_CHECK("minor field rolls 1->2 independently of major/rev/build",
                  strcmp(out_minor1, "1.1.50") == 0 &&
                  strcmp(out_minor2, "1.2.50") == 0);
    }
    {
        /* Cross a rev-field boundary (99 -> 0 with minor bumping) using
         * raw nVersion arithmetic directly, matching the task brief's
         * "1020150 vs 1010150" style rollover: 1010199 (minor=1, rev=99)
         * vs 1020100 (minor=2, rev=1) -- rev wraps, minor increments,
         * major/build held fixed at 0/... to isolate the two fields. */
        int n_before = cvf_make_version(0, 1, 99, 50); /* 1019950 */
        int n_after  = cvf_make_version(0, 2, 1, 50);  /* 1020150 */
        char out_before[64], out_after[64];
        FormatVersion(n_before, out_before, sizeof(out_before));
        FormatVersion(n_after, out_after, sizeof(out_after));
        CVF_CHECK("rev=99 (minor=1) -> 0.1.99",
                  strcmp(out_before, "0.1.99") == 0);
        CVF_CHECK("rev rolls to 1 with minor bumped to 2 -> 0.2.1",
                  strcmp(out_after, "0.2.1") == 0);
    }
    {
        /* major field itself: a large major must appear verbatim (no
         * truncation / masking to a byte-sized field). */
        char out[64];
        FormatVersion(cvf_make_version(255, 0, 0, 50), out, sizeof(out));
        CVF_CHECK("major=255 decodes verbatim -> 255.0.0",
                  strcmp(out, "255.0.0") == 0);
    }

    /* ===================================================================
     * Part 6 -- nVersion == 0 (every field zero). build==0 takes the
     * beta branch (build < 25), so this also cross-checks Part 1's
     * build==0 case still holds at an all-zero version, not just when
     * major/minor/rev happen to be 0/1/0.
     * =================================================================== */
    {
        char out[64];
        FormatVersion(0, out, sizeof(out));
        CVF_CHECK("nVersion=0 -> 0.0.0-beta1", strcmp(out, "0.0.0-beta1") == 0);
    }

    /* ===================================================================
     * Part 7 -- negative nVersion. C's `%` and `/` on a negative dividend
     * truncate toward zero (round-to-zero division per C99/C23), so
     * negative fields propagate their sign into major/minor/rev/build.
     * This does not have to be "pretty", but it MUST be deterministic and
     * must not corrupt memory (snprintf handles arbitrary ints safely).
     * We pin the exact C integer-arithmetic result rather than merely
     * "does not crash", so a change in FormatVersion's field arithmetic
     * that alters negative-input behavior is caught. */
    {
        char out[64];
        /* -50 / 1000000 == 0; (-50/10000)%100 == 0; (-50/100)%100 == 0;
         * -50 % 100 == -50 (round-to-zero). build=-50 < 25 -> beta branch,
         * offset build+1 == -49. */
        FormatVersion(-50, out, sizeof(out));
        CVF_CHECK("nVersion=-50 -> 0.0.0-beta-49 (round-to-zero division)",
                  strcmp(out, "0.0.0-beta-49") == 0);
    }

    /* ===================================================================
     * Part 8 -- out_size truncation safety. snprintf must never write
     * past out_size, and the byte immediately after the buffer must be
     * left untouched (a canary), even when the formatted string would
     * overflow a too-small buffer. Also confirm snprintf's C99/C23
     * contract: the string is always NUL-terminated within out_size when
     * out_size > 0, and truncation still round-trips the exact PREFIX of
     * the full-size result (no corrupted/garbled partial output).
     * =================================================================== */
    {
        /* Reference full-size output to compare truncation against. */
        char full[64];
        FormatVersion(cvf_make_version(1, 2, 3, 51), full, sizeof(full));
        CVF_CHECK("reference full output is 1.2.3-1 (sanity for Part 8)",
                  strcmp(full, "1.2.3-1") == 0);

        /* A canary-guarded buffer: out_size deliberately too small to
         * hold the full "1.2.3-1" (8 bytes incl NUL); give it only 4
         * bytes so the result must be truncated to "1.2" + NUL. */
        struct { char buf[4]; unsigned char canary; } guarded;
        guarded.canary = 0xAB;
        FormatVersion(cvf_make_version(1, 2, 3, 51), guarded.buf, sizeof(guarded.buf));
        CVF_CHECK("truncated out_size=4 -> NUL-terminated prefix \"1.2\"",
                  strlen(guarded.buf) == 3 && strncmp(guarded.buf, "1.2", 3) == 0);
        CVF_CHECK("truncated write does not clobber adjacent canary byte",
                  guarded.canary == 0xAB);
    }
    {
        /* out_size == 1: snprintf must still only write the NUL
         * terminator, nothing else -- the strictest truncation case. */
        struct { char buf[1]; unsigned char canary; } guarded;
        guarded.canary = 0xCD;
        FormatVersion(cvf_make_version(9, 9, 9, 50), guarded.buf, sizeof(guarded.buf));
        CVF_CHECK("out_size=1 -> empty NUL-terminated string",
                  guarded.buf[0] == '\0');
        CVF_CHECK("out_size=1 does not clobber adjacent canary byte",
                  guarded.canary == 0xCD);
    }

    /* ── zcl_build_commit_full ──────────────────────────────────────────
     *
     * The sovereign executable deliberately carries no baked Git commit:
     * its exact bytes are the receipt authority, so the display getter
     * answers "external" — and must keep answering exactly that, since
     * version reporters compare it verbatim. */
    failures += t_commit_getter_exact();
    failures += t_commit_getter_stable();

    return failures;
}
