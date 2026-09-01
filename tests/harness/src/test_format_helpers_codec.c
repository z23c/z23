/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hermetic coverage for the pure formatting/classification/naive-JSON
 * primitives in contexts/explorer/views/src/format_helpers.c. Only zcl_format_zcl had
 * any dedicated coverage before this file (3 smoke-test lines inside
 * test_explorer.c) — the other 8 functions were completely untested:
 *
 *   zcl_format_time            gmtime_r wrapping + timestamp<=0/buf/max guards
 *   zcl_format_zcl_trimmed     trailing-zero trim down to a min_decimals floor
 *   zcl_format_zcl_short       zcl_format_zcl_trimmed(..., 4)
 *   zcl_is_all_hex/_hex_string length-gated hex classifier
 *   zcl_is_all_digits          non-empty all-decimal-digit classifier
 *   zcl_json_extract_str/_int/_real   linear strstr-based JSON scalar pulls
 *
 * Every exact expectation below (in particular the zcl_format_zcl_trimmed
 * decimal-point-survives-at-min_decimals=0 behavior, and the naive JSON
 * extractors' exact-quote-and-colon framing that happens to make a
 * short-key-is-a-substring-of-a-longer-key collision safe) was
 * cross-checked by compiling format_helpers.c's logic standalone and
 * printing its real output before being baked in here — not hand-derived
 * from the header comment.
 *
 * Pure and deterministic: no clock, no RNG, no network, no live DB.
 * (zcl_format_time calls gmtime_r, but only on caller-supplied timestamps
 * with UTC output — no wall-clock read.) */

#include "test/test_core.h"

#include "views/format_helpers.h"

#include <string.h>

int test_format_helpers_codec(void);
int test_format_helpers_codec(void)
{
    int failures = 0;

    /* ───────────────────────── zcl_format_time ───────────────────────── */

    TEST("zcl_format_time: formats a known UTC timestamp") {
        char buf[64];
        /* 2021-01-01 00:00:00 UTC */
        zcl_format_time(buf, sizeof(buf), 1609459200LL);
        ASSERT_STR_EQ(buf, "2021-01-01 00:00:00 UTC");
        PASS();
    }

    TEST("zcl_format_time: timestamp == 0 yields the empty string "
         "(explicit <= 0 guard, not just an epoch format)") {
        char buf[64] = "untouched";
        zcl_format_time(buf, sizeof(buf), 0);
        ASSERT_STR_EQ(buf, "");
        PASS();
    }

    TEST("zcl_format_time: a negative timestamp yields the empty string") {
        char buf[64] = "untouched";
        zcl_format_time(buf, sizeof(buf), -1LL);
        ASSERT_STR_EQ(buf, "");
        PASS();
    }

    TEST("zcl_format_time: NULL buf is a safe no-op (does not crash)") {
        zcl_format_time(NULL, 64, 1609459200LL);
        PASS();
    }

    TEST("zcl_format_time: max == 0 is a safe no-op (does not touch buf)") {
        char buf[8];
        memset(buf, 'X', sizeof(buf));
        zcl_format_time(buf, 0, 1609459200LL);
        ASSERT_EQ(buf[0], 'X');
        PASS();
    }

    TEST("zcl_format_time: a timestamp gmtime_r cannot represent "
         "(INT64_MAX, far outside any representable calendar date) makes "
         "gmtime_r fail, so the function returns early and buf stays the "
         "empty string it was set to before the conversion") {
        char buf[64] = "untouched";
        zcl_format_time(buf, sizeof(buf), INT64_MAX);
        ASSERT_STR_EQ(buf, "");
        PASS();
    }

    /* ───────────────────────── zcl_format_zcl (baseline) ───────────────────────── */

    TEST("zcl_format_zcl: one satoshi keeps all 8 decimals") {
        char buf[64];
        zcl_format_zcl(buf, sizeof(buf), 1);
        ASSERT_STR_EQ(buf, "0.00000001");
        PASS();
    }

    TEST("zcl_format_zcl: negative amount keeps the sign") {
        char buf[64];
        zcl_format_zcl(buf, sizeof(buf), -1);
        ASSERT_STR_EQ(buf, "-0.00000001");
        PASS();
    }

    /* ───────────────────────── zcl_format_zcl_trimmed ───────────────────────── */

    TEST("zcl_format_zcl_trimmed: min_decimals=0 on an all-zero fraction "
         "trims every fractional digit but leaves the bare decimal point "
         "(the loop never finds a nonzero digit, so last_nonzero stays at "
         "min_decimals=0 and only dot[1] is truncated to NUL)") {
        char buf[64];
        zcl_format_zcl_trimmed(buf, sizeof(buf), 0, 0);
        ASSERT_STR_EQ(buf, "0.");
        PASS();
    }

    TEST("zcl_format_zcl_trimmed: min_decimals=0 trims a clean 1.5 down to "
         "one fractional digit") {
        char buf[64];
        zcl_format_zcl_trimmed(buf, sizeof(buf), 150000000LL, 0);
        ASSERT_STR_EQ(buf, "1.5");
        PASS();
    }

    TEST("zcl_format_zcl_trimmed: min_decimals=8 never trims — the "
         "strlen(dot) > min_decimals+1 guard is false at the full width, "
         "so a whole-ZCL amount keeps all 8 zero decimals") {
        char buf[64];
        zcl_format_zcl_trimmed(buf, sizeof(buf), 100000000LL, 8);
        ASSERT_STR_EQ(buf, "1.00000000");
        PASS();
    }

    TEST("zcl_format_zcl_trimmed: the last nonzero digit sits exactly at "
         "the min_decimals boundary (1.0001 with min_decimals=4) — the "
         "boundary digit is kept, nothing past it survives") {
        char buf[64];
        zcl_format_zcl_trimmed(buf, sizeof(buf), 100010000LL, 4);
        ASSERT_STR_EQ(buf, "1.0001");
        PASS();
    }

    TEST("zcl_format_zcl_trimmed: a nonzero digit past min_decimals keeps "
         "the full fraction (1.00000001 with min_decimals=4)") {
        char buf[64];
        zcl_format_zcl_trimmed(buf, sizeof(buf), 100000001LL, 4);
        ASSERT_STR_EQ(buf, "1.00000001");
        PASS();
    }

    TEST("zcl_format_zcl_trimmed: negative amounts trim the same way, "
         "sign preserved") {
        char buf[64];
        zcl_format_zcl_trimmed(buf, sizeof(buf), -150000000LL, 0);
        ASSERT_STR_EQ(buf, "-1.5");
        PASS();
    }

    TEST("zcl_format_zcl_trimmed: min_decimals=2 on zero keeps exactly "
         "2 decimal places") {
        char buf[64];
        zcl_format_zcl_trimmed(buf, sizeof(buf), 0, 2);
        ASSERT_STR_EQ(buf, "0.00");
        PASS();
    }

    /* ───────────────────────── zcl_format_zcl_short ───────────────────────── */

    TEST("zcl_format_zcl_short: is zcl_format_zcl_trimmed with min_decimals=4 "
         "— an exact-4-decimal value trims to nothing extra") {
        char buf[64];
        zcl_format_zcl_short(buf, sizeof(buf), 100010000LL);
        ASSERT_STR_EQ(buf, "1.0001");
        PASS();
    }

    TEST("zcl_format_zcl_short: a whole-ZCL amount keeps the 4-decimal floor") {
        char buf[64];
        zcl_format_zcl_short(buf, sizeof(buf), 100000000LL);
        ASSERT_STR_EQ(buf, "1.0000");
        PASS();
    }

    TEST("zcl_format_zcl_short: full 8-decimal precision survives when the "
         "8th digit is nonzero") {
        char buf[64];
        zcl_format_zcl_short(buf, sizeof(buf), 123456789LL);
        ASSERT_STR_EQ(buf, "1.23456789");
        PASS();
    }

    /* ───────────────────────── zcl_is_all_hex / zcl_is_hex_string ───────────────────────── */

    TEST("zcl_is_all_hex: accepts a mixed-case hex run of the given length") {
        ASSERT(zcl_is_all_hex("deadBEEF01", 10));
        PASS();
    }

    TEST("zcl_is_all_hex: zero length is vacuously true (the loop never runs)") {
        ASSERT(zcl_is_all_hex("whatever-not-hex", 0));
        PASS();
    }

    TEST("zcl_is_all_hex: rejects a non-hex byte within the given length") {
        ASSERT(!zcl_is_all_hex("dead-beef", 9));
        PASS();
    }

    TEST("zcl_is_all_hex: only inspects the first `len` bytes — trailing "
         "garbage past len is never looked at") {
        ASSERT(zcl_is_all_hex("deadbeefZZZZ", 8));
        PASS();
    }

    TEST("zcl_is_hex_string: accepts a NUL-terminated string whose length "
         "exactly matches expected_len") {
        ASSERT(zcl_is_hex_string("deadbeef", 8));
        PASS();
    }

    TEST("zcl_is_hex_string: NULL string is rejected without dereferencing") {
        ASSERT(!zcl_is_hex_string(NULL, 8));
        PASS();
    }

    TEST("zcl_is_hex_string: rejects when strlen is one shorter than "
         "expected_len (off-by-one, too short)") {
        ASSERT(!zcl_is_hex_string("deadbef", 8));
        PASS();
    }

    TEST("zcl_is_hex_string: rejects when strlen is one longer than "
         "expected_len (off-by-one, too long) even though the first "
         "expected_len bytes are all valid hex") {
        ASSERT(!zcl_is_hex_string("deadbeef0", 8));
        PASS();
    }

    TEST("zcl_is_hex_string: a 64-hex-char sha3/blockhash-shaped string "
         "matches expected_len=64") {
        char buf65[65];
        memset(buf65, '0', 64);
        buf65[64] = '\0';
        ASSERT(zcl_is_hex_string(buf65, 64));
        PASS();
    }

    /* ───────────────────────── zcl_is_all_digits ───────────────────────── */

    TEST("zcl_is_all_digits: accepts a plain positive integer string") {
        ASSERT(zcl_is_all_digits("1234567890"));
        PASS();
    }

    TEST("zcl_is_all_digits: rejects the empty string (explicit !*s guard)") {
        ASSERT(!zcl_is_all_digits(""));
        PASS();
    }

    TEST("zcl_is_all_digits: rejects NULL without dereferencing") {
        ASSERT(!zcl_is_all_digits(NULL));
        PASS();
    }

    TEST("zcl_is_all_digits: rejects a leading minus sign (no sign chars "
         "accepted at all)") {
        ASSERT(!zcl_is_all_digits("-42"));
        PASS();
    }

    TEST("zcl_is_all_digits: rejects an embedded non-digit anywhere in "
         "the string") {
        ASSERT(!zcl_is_all_digits("123a456"));
        PASS();
    }

    TEST("zcl_is_all_digits: rejects a decimal point") {
        ASSERT(!zcl_is_all_digits("1.5"));
        PASS();
    }

    /* ───────────────────────── zcl_json_extract_str ───────────────────────── */

    TEST("zcl_json_extract_str: extracts a simple quoted string value") {
        char out[32];
        ASSERT(zcl_json_extract_str("{\"foo\":\"bar\"}", "foo", out, sizeof(out)));
        ASSERT_STR_EQ(out, "bar");
        PASS();
    }

    TEST("zcl_json_extract_str: tolerates spaces between the colon and "
         "the opening quote") {
        char out[32];
        ASSERT(zcl_json_extract_str("{\"foo\":   \"bar\"}", "foo", out, sizeof(out)));
        ASSERT_STR_EQ(out, "bar");
        PASS();
    }

    TEST("zcl_json_extract_str: a missing key returns false") {
        char out[32] = "untouched";
        ASSERT(!zcl_json_extract_str("{\"foo\":\"bar\"}", "missing", out, sizeof(out)));
        PASS();
    }

    TEST("zcl_json_extract_str: a key whose value is not quoted (a bare "
         "number) is rejected by the explicit *p != '\"' check") {
        char out[32] = "untouched";
        ASSERT(!zcl_json_extract_str("{\"foo\":123}", "foo", out, sizeof(out)));
        PASS();
    }

    TEST("zcl_json_extract_str: an empty-string value (\"\") returns false "
         "— the trailing `return i > 0` requires at least one copied byte "
         "even though the quotes themselves are well-formed") {
        char out[32] = "untouched";
        bool ok = zcl_json_extract_str("{\"foo\":\"\"}", "foo", out, sizeof(out));
        ASSERT(!ok);
        ASSERT_STR_EQ(out, "");
        PASS();
    }

    TEST("zcl_json_extract_str: an unterminated quote (no closing \") "
         "returns false but still copies what it saw before hitting NUL") {
        char out[32] = "untouched";
        bool ok = zcl_json_extract_str("{\"foo\":\"bar", "foo", out, sizeof(out));
        ASSERT(!ok);
        ASSERT_STR_EQ(out, "bar");
        PASS();
    }

    TEST("zcl_json_extract_str: an output buffer shorter than the value "
         "silently truncates and, because the closing quote is not at the "
         "truncated position, still fails") {
        char out[5];
        bool ok = zcl_json_extract_str("{\"foo\":\"abcdefgh\"}", "foo", out, sizeof(out));
        ASSERT(!ok);
        ASSERT_STR_EQ(out, "abcd");
        PASS();
    }

    TEST("zcl_json_extract_str: truncation succeeds when the output "
         "buffer capacity exactly matches the value length plus NUL — "
         "the closing quote lands exactly at the truncated position") {
        char out[5];
        bool ok = zcl_json_extract_str("{\"foo\":\"abcd\"}", "foo", out, sizeof(out));
        ASSERT(ok);
        ASSERT_STR_EQ(out, "abcd");
        PASS();
    }

    TEST("zcl_json_extract_str: NULL json/key/out or outmax==0 are all "
         "safe no-ops that return false") {
        char out[32];
        ASSERT(!zcl_json_extract_str(NULL, "foo", out, sizeof(out)));
        ASSERT(!zcl_json_extract_str("{\"foo\":\"bar\"}", NULL, out, sizeof(out)));
        ASSERT(!zcl_json_extract_str("{\"foo\":\"bar\"}", "foo", NULL, sizeof(out)));
        ASSERT(!zcl_json_extract_str("{\"foo\":\"bar\"}", "foo", out, 0));
        PASS();
    }

    TEST("zcl_json_extract_str: a short key is not spuriously matched "
         "inside a longer key that shares it as a substring — the exact "
         "\"key\": framing (leading quote + trailing quote+colon) is a "
         "full delimiter, so searching \"h\" against a document whose "
         "only other key is \"height\" finds nothing") {
        char out[32] = "untouched";
        ASSERT(!zcl_json_extract_str("{\"height\":\"tall\"}", "h", out, sizeof(out)));
        PASS();
    }

    /* ───────────────────────── zcl_json_extract_int ───────────────────────── */

    TEST("zcl_json_extract_int: extracts a positive integer value") {
        int64_t v = -999;
        ASSERT(zcl_json_extract_int("{\"height\":12345}", "height", &v));
        ASSERT_EQ(v, (int64_t)12345);
        PASS();
    }

    TEST("zcl_json_extract_int: extracts a negative integer value") {
        int64_t v = 0;
        ASSERT(zcl_json_extract_int("{\"n\":-42}", "n", &v));
        ASSERT_EQ(v, (int64_t)-42);
        PASS();
    }

    TEST("zcl_json_extract_int: a missing key returns false and leaves "
         "*out untouched") {
        int64_t v = -777;
        ASSERT(!zcl_json_extract_int("{\"height\":1}", "missing", &v));
        ASSERT_EQ(v, (int64_t)-777);
        PASS();
    }

    TEST("zcl_json_extract_int: a short key that is a prefix of a longer "
         "key is NOT spuriously matched — the search pattern \"h\": "
         "requires a literal quote+colon immediately after the 'h', which "
         "never appears inside \"height\":123 (the colon there follows "
         "the full word)") {
        int64_t v = -999;
        ASSERT(!zcl_json_extract_int("{\"height\":123}", "h", &v));
        PASS();
    }

    TEST("zcl_json_extract_int: the exact short key still resolves "
         "correctly even when a longer key sharing its name as a prefix "
         "appears earlier in the same document") {
        int64_t v = -1;
        ASSERT(zcl_json_extract_int("{\"height\":999,\"h\":42}", "h", &v));
        ASSERT_EQ(v, (int64_t)42);
        PASS();
    }

    TEST("zcl_json_extract_int: trailing garbage after a valid number is "
         "NOT rejected — the return predicate is only `end != p` (some "
         "digit was consumed), it never checks what follows the number") {
        int64_t v = -1;
        ASSERT(zcl_json_extract_int("{\"n\":123abc}", "n", &v));
        ASSERT_EQ(v, (int64_t)123);
        PASS();
    }

    TEST("zcl_json_extract_int: a value with no leading digits at all "
         "fails (`end == p`, strtoll consumed nothing)") {
        int64_t v = -1;
        ASSERT(!zcl_json_extract_int("{\"n\":abc}", "n", &v));
        PASS();
    }

    TEST("zcl_json_extract_int: skips spaces between the colon and the "
         "number") {
        int64_t v = -1;
        ASSERT(zcl_json_extract_int("{\"n\":   99}", "n", &v));
        ASSERT_EQ(v, (int64_t)99);
        PASS();
    }

    TEST("zcl_json_extract_int: NULL json/key/out are all safe no-ops "
         "that return false") {
        int64_t v = 0;
        ASSERT(!zcl_json_extract_int(NULL, "n", &v));
        ASSERT(!zcl_json_extract_int("{\"n\":1}", NULL, &v));
        ASSERT(!zcl_json_extract_int("{\"n\":1}", "n", NULL));
        PASS();
    }

    /* ───────────────────────── zcl_json_extract_real ───────────────────────── */

    TEST("zcl_json_extract_real: extracts a fractional value") {
        double v = -1.0;
        ASSERT(zcl_json_extract_real("{\"price\":1.5}", "price", &v));
        ASSERT(v > 1.4999 && v < 1.5001);
        PASS();
    }

    TEST("zcl_json_extract_real: extracts a negative fractional value") {
        double v = 0.0;
        ASSERT(zcl_json_extract_real("{\"delta\":-0.25}", "delta", &v));
        ASSERT(v > -0.2501 && v < -0.2499);
        PASS();
    }

    TEST("zcl_json_extract_real: a missing key returns false") {
        double v = -1.0;
        ASSERT(!zcl_json_extract_real("{\"price\":1.5}", "missing", &v));
        PASS();
    }

    TEST("zcl_json_extract_real: a short key that prefixes a longer key "
         "is not spuriously matched (same quote+colon framing as the int "
         "extractor)") {
        double v = -1.0;
        ASSERT(!zcl_json_extract_real("{\"height\":1.5}", "h", &v));
        PASS();
    }

    TEST("zcl_json_extract_real: trailing garbage after a valid number "
         "is not rejected — only `end != p` is checked") {
        double v = -1.0;
        ASSERT(zcl_json_extract_real("{\"x\":1.5abc}", "x", &v));
        ASSERT(v > 1.4999 && v < 1.5001);
        PASS();
    }

    TEST("zcl_json_extract_real: a value with no parseable number fails") {
        double v = -1.0;
        ASSERT(!zcl_json_extract_real("{\"x\":abc}", "x", &v));
        PASS();
    }

    TEST("zcl_json_extract_real: NULL json/key/out are all safe no-ops "
         "that return false") {
        double v = 0.0;
        ASSERT(!zcl_json_extract_real(NULL, "x", &v));
        ASSERT(!zcl_json_extract_real("{\"x\":1}", NULL, &v));
        ASSERT(!zcl_json_extract_real("{\"x\":1}", "x", NULL));
        PASS();
    }

    /* ───────────────────── zcl_json_int / zcl_json_real (inline wrappers) ───────────────────── */

    TEST("zcl_json_int: returns -1 (the documented miss default) when "
         "the key is absent") {
        ASSERT_EQ(zcl_json_int("{\"height\":5}", "missing"), (int64_t)-1);
        PASS();
    }

    TEST("zcl_json_int: returns the parsed value when the key is present") {
        ASSERT_EQ(zcl_json_int("{\"height\":5}", "height"), (int64_t)5);
        PASS();
    }

    TEST("zcl_json_real: returns 0.0 (the documented miss default) when "
         "the key is absent") {
        double v = zcl_json_real("{\"price\":5}", "missing");
        ASSERT(v > -0.0001 && v < 0.0001);
        PASS();
    }

    TEST("zcl_json_real: returns the parsed value when the key is present") {
        double v = zcl_json_real("{\"price\":2.5}", "price");
        ASSERT(v > 2.4999 && v < 2.5001);
        PASS();
    }

    /* ───────────────────────── zcl_pow10 (inline helper) ───────────────────────── */

    TEST("zcl_pow10: 10^0 == 1") {
        ASSERT_EQ(zcl_pow10(0), (int64_t)1);
        PASS();
    }

    TEST("zcl_pow10: 10^8 matches ZATOSHI_PER_ZCL") {
        ASSERT_EQ(zcl_pow10(8), (int64_t)ZATOSHI_PER_ZCL);
        PASS();
    }

_test_next:;
    if (failures == 0)
        printf("test_format_helpers_codec: all passed\n");
    else
        printf("test_format_helpers_codec: %d FAILED\n", failures);
    return failures;
}
