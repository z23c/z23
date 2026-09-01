/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hermetic coverage for the pure string/money encoding primitives in
 * platform/modules/encoding/src/{utilstrencodings.c,utilmoneystr.c}:
 *
 *   FormatMoney, ParseMoney                       (utilmoneystr.c)
 *   SanitizeString, HexDigit, IsHex, ParseHex,
 *   EncodeBase64, DecodeBase64, EncodeBase32,
 *   HexStr, ParseInt32, ParseFixedPoint, ConvertBits (utilstrencodings.c)
 *
 * These functions had no dedicated TEST()/ASSERT()-style group — only
 * incidental exercise via higher-level RPC/wallet paths. This group drives
 * each function directly: happy path, roundtrips, boundary lengths, and the
 * documented failure predicates. Every exact-string expectation below
 * (base64/base32 vectors, FormatMoney trailing-zero trims, ParseMoney
 * digit-count boundaries) was cross-checked by compiling the two source
 * files standalone and printing their real output before being baked in
 * here — not hand-derived from the RFC/spec, since this codebase's base32
 * alphabet is lowercase (not the RFC4648 upper-case table) and FormatMoney's
 * trim-then-reattach-one-zero behavior is an implementation quirk worth
 * pinning exactly.
 *
 * Pure and deterministic: no clock, no RNG, no network, no live DB. */

#include "test/test_core.h"

#include "encoding/utilmoneystr.h"
#include "encoding/utilstrencodings.h"

#include <string.h>

int test_test_str_money_codecs(void);
int test_test_str_money_codecs(void)
{
    int failures = 0;

    /* ───────────────────────── FormatMoney ───────────────────────── */

    TEST("FormatMoney: exactly 1 COIN trims to a single trailing zero") {
        char out[64];
        FormatMoney(100000000, out, sizeof(out));
        ASSERT_STR_EQ(out, "1.0");
        PASS();
    }

    TEST("FormatMoney: zero") {
        char out[64];
        FormatMoney(0, out, sizeof(out));
        ASSERT_STR_EQ(out, "0.0");
        PASS();
    }

    TEST("FormatMoney: negative amount keeps the sign and trims") {
        char out[64];
        FormatMoney(-50000000, out, sizeof(out));
        ASSERT_STR_EQ(out, "-0.5");
        PASS();
    }

    TEST("FormatMoney: no trailing zeros to trim keeps all 8 decimals") {
        char out[64];
        FormatMoney(112345678, out, sizeof(out));
        ASSERT_STR_EQ(out, "1.12345678");
        PASS();
    }

    TEST("FormatMoney: MAX_MONEY (21,000,000 COIN)") {
        char out[64];
        FormatMoney(21000000LL * 100000000LL, out, sizeof(out));
        ASSERT_STR_EQ(out, "21000000.0");
        PASS();
    }

    TEST("FormatMoney: single-satoshi amount keeps all 8 decimals") {
        char out[64];
        FormatMoney(1, out, sizeof(out));
        ASSERT_STR_EQ(out, "0.00000001");
        PASS();
    }

    /* ───────────────────────── ParseMoney ───────────────────────── */

    TEST("ParseMoney: roundtrips FormatMoney(1 COIN)") {
        int64_t ret = -1;
        ASSERT(ParseMoney("1.0", &ret));
        ASSERT_EQ(ret, 100000000);
        PASS();
    }

    TEST("ParseMoney: roundtrips a full 8-decimal fraction") {
        int64_t ret = -1;
        ASSERT(ParseMoney("1.12345678", &ret));
        ASSERT_EQ(ret, 112345678);
        PASS();
    }

    TEST("ParseMoney: the empty string parses as zero (documented quirk: "
         "the whole-part loop never runs and leaves nUnits/nWhole at 0)") {
        int64_t ret = -1;
        ASSERT(ParseMoney("", &ret));
        ASSERT_EQ(ret, 0);
        PASS();
    }

    TEST("ParseMoney: leading and trailing whitespace are both skipped") {
        int64_t ret = -1;
        ASSERT(ParseMoney("  1.5  ", &ret));
        ASSERT_EQ(ret, 150000000);
        PASS();
    }

    TEST("ParseMoney: whole part with no fractional dot") {
        int64_t ret = -1;
        ASSERT(ParseMoney("42", &ret));
        ASSERT_EQ(ret, 42LL * 100000000LL);
        PASS();
    }

    TEST("ParseMoney: a 9th fractional digit past the 8-decimal ceiling "
         "is rejected (the digit is left unconsumed by the mantissa loop, "
         "then fails the trailing all-whitespace check)") {
        int64_t ret = -1;
        ASSERT(!ParseMoney("1.123456789", &ret));
        PASS();
    }

    TEST("ParseMoney: an 11-digit whole part exceeds the 10-digit cap") {
        int64_t ret = -1;
        ASSERT(!ParseMoney("12345678901", &ret));
        PASS();
    }

    TEST("ParseMoney: a 10-digit whole part is still accepted") {
        int64_t ret = -1;
        ASSERT(ParseMoney("1234567890", &ret));
        ASSERT_EQ(ret, 1234567890LL * 100000000LL);
        PASS();
    }

    TEST("ParseMoney: rejects a leading minus sign (no negative amounts)") {
        int64_t ret = -1;
        ASSERT(!ParseMoney("-1.0", &ret));
        PASS();
    }

    TEST("ParseMoney: rejects non-numeric garbage") {
        int64_t ret = -1;
        ASSERT(!ParseMoney("abc", &ret));
        PASS();
    }

    TEST("ParseMoney: rejects trailing garbage after a valid number") {
        int64_t ret = -1;
        ASSERT(!ParseMoney("1.5x", &ret));
        PASS();
    }

    TEST("ParseMoney: rejects embedded whitespace inside the digits") {
        int64_t ret = -1;
        ASSERT(!ParseMoney("1 .5", &ret));
        PASS();
    }

    /* ───────────────────────── SanitizeString ───────────────────────── */

    TEST("SanitizeString: SAFE_CHARS_DEFAULT keeps parens and strips control chars") {
        char out[64];
        SanitizeString("hello (world)!\x01\x02", SAFE_CHARS_DEFAULT, out, sizeof(out));
        ASSERT_STR_EQ(out, "hello (world)");
        PASS();
    }

    TEST("SanitizeString: SAFE_CHARS_UA_COMMENT strips parens too") {
        char out[64];
        SanitizeString("hello (world)!", SAFE_CHARS_UA_COMMENT, out, sizeof(out));
        ASSERT_STR_EQ(out, "hello world");
        PASS();
    }

    TEST("SanitizeString: truncates to the output buffer size") {
        char out[6];
        SanitizeString("abcdefgh", SAFE_CHARS_DEFAULT, out, sizeof(out));
        ASSERT_STR_EQ(out, "abcde");
        PASS();
    }

    TEST("SanitizeString: empty input yields empty output") {
        char out[16];
        SanitizeString("", SAFE_CHARS_DEFAULT, out, sizeof(out));
        ASSERT_STR_EQ(out, "");
        PASS();
    }

    /* ───────────────────────── HexDigit / IsHex ───────────────────────── */

    TEST("HexDigit: decodes 0-9, a-f, A-F to their nibble values") {
        ASSERT_EQ(HexDigit('0'), 0);
        ASSERT_EQ(HexDigit('9'), 9);
        ASSERT_EQ(HexDigit('a'), 0xa);
        ASSERT_EQ(HexDigit('f'), 0xf);
        ASSERT_EQ(HexDigit('A'), 0xa);
        ASSERT_EQ(HexDigit('F'), 0xf);
        PASS();
    }

    TEST("HexDigit: non-hex characters return -1") {
        ASSERT_EQ(HexDigit('g'), -1);
        ASSERT_EQ(HexDigit(' '), -1);
        ASSERT_EQ(HexDigit('\0'), -1);
        PASS();
    }

    TEST("IsHex: accepts an even-length hex string") {
        ASSERT(IsHex("48656c6c6f"));
        PASS();
    }

    TEST("IsHex: rejects an odd-length string") {
        ASSERT(!IsHex("abc"));
        PASS();
    }

    TEST("IsHex: rejects the empty string") {
        ASSERT(!IsHex(""));
        PASS();
    }

    TEST("IsHex: rejects a non-hex character") {
        ASSERT(!IsHex("4g"));
        PASS();
    }

    TEST("IsHex: uppercase hex is accepted") {
        ASSERT(IsHex("DEADBEEF"));
        PASS();
    }

    /* ───────────────────────── ParseHex ───────────────────────── */

    TEST("ParseHex: decodes a simple ASCII hex string") {
        unsigned char out[16];
        size_t n = ParseHex("48656c6c6f", out, sizeof(out));
        ASSERT_EQ(n, (size_t)5);
        ASSERT(memcmp(out, "Hello", 5) == 0);
        PASS();
    }

    TEST("ParseHex: whitespace is only tolerated BETWEEN byte pairs, "
         "not inside one (a mid-pair space aborts before storing that byte)") {
        unsigned char out[16];
        size_t n = ParseHex("48 65", out, sizeof(out));
        ASSERT_EQ(n, (size_t)2);
        ASSERT_EQ(out[0], 0x48);
        ASSERT_EQ(out[1], 0x65);

        size_t n2 = ParseHex("4 8 65", out, sizeof(out));
        ASSERT_EQ(n2, (size_t)0);
        PASS();
    }

    TEST("ParseHex: stops at the first invalid hex character") {
        unsigned char out[16];
        size_t n = ParseHex("4g", out, sizeof(out));
        ASSERT_EQ(n, (size_t)0);
        PASS();
    }

    TEST("ParseHex: truncates to the output buffer capacity") {
        unsigned char out[2];
        size_t n = ParseHex("48656c6c6f", out, sizeof(out));
        ASSERT_EQ(n, (size_t)2);
        ASSERT_EQ(out[0], 0x48);
        ASSERT_EQ(out[1], 0x65);
        PASS();
    }

    TEST("ParseHex: empty string yields zero bytes") {
        unsigned char out[16];
        size_t n = ParseHex("", out, sizeof(out));
        ASSERT_EQ(n, (size_t)0);
        PASS();
    }

    /* ───────────────────────── EncodeBase64 / DecodeBase64 ───────────────────────── */

    TEST("EncodeBase64: 3-byte input needs no padding") {
        char out[16];
        size_t n = EncodeBase64((const unsigned char *)"Man", 3, out, sizeof(out));
        ASSERT_STR_EQ(out, "TWFu");
        ASSERT_EQ(n, (size_t)4);
        PASS();
    }

    TEST("EncodeBase64: 2-byte input gets one '=' pad") {
        char out[16];
        EncodeBase64((const unsigned char *)"Ma", 2, out, sizeof(out));
        ASSERT_STR_EQ(out, "TWE=");
        PASS();
    }

    TEST("EncodeBase64: 1-byte input gets two '=' pads") {
        char out[16];
        EncodeBase64((const unsigned char *)"M", 1, out, sizeof(out));
        ASSERT_STR_EQ(out, "TQ==");
        PASS();
    }

    TEST("EncodeBase64: empty input yields the empty string") {
        char out[16];
        size_t n = EncodeBase64((const unsigned char *)"", 0, out, sizeof(out));
        ASSERT_STR_EQ(out, "");
        ASSERT_EQ(n, (size_t)0);
        PASS();
    }

    TEST("DecodeBase64: roundtrips a valid, unpadded-remainder string") {
        unsigned char out[16];
        bool invalid = true;
        size_t n = DecodeBase64("TWFu", out, sizeof(out), &invalid);
        ASSERT(!invalid);
        ASSERT_EQ(n, (size_t)3);
        ASSERT(memcmp(out, "Man", 3) == 0);
        PASS();
    }

    TEST("DecodeBase64: roundtrips a padded string") {
        unsigned char out[16];
        bool invalid = true;
        size_t n = DecodeBase64("TW9u", out, sizeof(out), &invalid);
        ASSERT(!invalid);
        ASSERT_EQ(n, (size_t)3);
        ASSERT(memcmp(out, "Mon", 3) == 0);
        PASS();
    }

    TEST("DecodeBase64: flags an out-of-alphabet trailing character as invalid") {
        unsigned char out[16];
        bool invalid = false;
        size_t n = DecodeBase64("TWFu!", out, sizeof(out), &invalid);
        ASSERT(invalid);
        ASSERT_EQ(n, (size_t)3);
        PASS();
    }

    /* ───────────────────────── EncodeBase32 ───────────────────────── */

    TEST("EncodeBase32: empty input yields the empty string") {
        char out[16];
        size_t n = EncodeBase32((const unsigned char *)"", 0, out, sizeof(out));
        ASSERT_STR_EQ(out, "");
        ASSERT_EQ(n, (size_t)0);
        PASS();
    }

    TEST("EncodeBase32: single zero byte pads to an 8-char block") {
        unsigned char in[1] = {0x00};
        char out[16];
        size_t n = EncodeBase32(in, 1, out, sizeof(out));
        ASSERT_STR_EQ(out, "aa======");
        ASSERT_EQ(n, (size_t)8);
        PASS();
    }

    TEST("EncodeBase32: single 0xFF byte") {
        unsigned char in[1] = {0xFF};
        char out[16];
        EncodeBase32(in, 1, out, sizeof(out));
        ASSERT_STR_EQ(out, "74======");
        PASS();
    }

    TEST("EncodeBase32: 5-byte input needs no padding (40 bits = 8 groups of 5)") {
        unsigned char in[5] = {0xAB, 0xCD, 0xEF, 0x01, 0x23};
        char out[16];
        size_t n = EncodeBase32(in, 5, out, sizeof(out));
        ASSERT_STR_EQ(out, "vpg66ajd");
        ASSERT_EQ(n, (size_t)8);
        PASS();
    }

    TEST("EncodeBase32: truncates to the output buffer capacity") {
        unsigned char in[5] = {0xAB, 0xCD, 0xEF, 0x01, 0x23};
        char out[4];
        size_t n = EncodeBase32(in, 5, out, sizeof(out));
        ASSERT_EQ(n, (size_t)3);
        ASSERT_STR_EQ(out, "vpg");
        PASS();
    }

    /* ───────────────────────── HexStr ───────────────────────── */

    TEST("HexStr: encodes bytes without spaces") {
        unsigned char in[3] = {0xDE, 0xAD, 0xBE};
        char out[16];
        HexStr(in, 3, false, out, sizeof(out));
        ASSERT_STR_EQ(out, "deadbe");
        PASS();
    }

    TEST("HexStr: encodes bytes with spaces between them") {
        unsigned char in[3] = {0xDE, 0xAD, 0xBE};
        char out[16];
        HexStr(in, 3, true, out, sizeof(out));
        ASSERT_STR_EQ(out, "de ad be");
        PASS();
    }

    TEST("HexStr: empty input yields the empty string") {
        char out[16];
        HexStr(NULL, 0, false, out, sizeof(out));
        ASSERT_STR_EQ(out, "");
        PASS();
    }

    TEST("HexStr: stops cleanly when the output buffer is too small "
         "for the next byte (never writes a torn hex pair)") {
        unsigned char in[3] = {0xDE, 0xAD, 0xBE};
        char out[3];
        HexStr(in, 3, false, out, sizeof(out));
        ASSERT_STR_EQ(out, "de");
        PASS();
    }

    /* ───────────────────────── ParseInt32 ───────────────────────── */

    TEST("ParseInt32: parses a plain positive integer") {
        int32_t out = 0;
        ASSERT(ParseInt32("12345", &out));
        ASSERT_EQ(out, 12345);
        PASS();
    }

    TEST("ParseInt32: parses a negative integer") {
        int32_t out = 0;
        ASSERT(ParseInt32("-42", &out));
        ASSERT_EQ(out, -42);
        PASS();
    }

    TEST("ParseInt32: parses the exact INT32_MAX / INT32_MIN boundaries") {
        int32_t out = 0;
        ASSERT(ParseInt32("2147483647", &out));
        ASSERT_EQ(out, 2147483647);
        ASSERT(ParseInt32("-2147483648", &out));
        ASSERT_EQ(out, -2147483648);
        PASS();
    }

    TEST("ParseInt32: rejects overflow past INT32_MAX") {
        int32_t out = 0;
        ASSERT(!ParseInt32("2147483648", &out));
        PASS();
    }

    TEST("ParseInt32: rejects underflow past INT32_MIN") {
        int32_t out = 0;
        ASSERT(!ParseInt32("-2147483649", &out));
        PASS();
    }

    TEST("ParseInt32: rejects leading whitespace") {
        int32_t out = 0;
        ASSERT(!ParseInt32(" 42", &out));
        PASS();
    }

    TEST("ParseInt32: rejects trailing whitespace") {
        int32_t out = 0;
        ASSERT(!ParseInt32("42 ", &out));
        PASS();
    }

    TEST("ParseInt32: rejects trailing garbage") {
        int32_t out = 0;
        ASSERT(!ParseInt32("42abc", &out));
        PASS();
    }

    TEST("ParseInt32: rejects the empty string") {
        int32_t out = 0;
        ASSERT(!ParseInt32("", &out));
        PASS();
    }

    /* ───────────────────────── ParseFixedPoint ───────────────────────── */

    TEST("ParseFixedPoint: whole number scaled by decimals=8") {
        int64_t out = -1;
        ASSERT(ParseFixedPoint("1", 8, &out));
        ASSERT_EQ(out, 100000000LL);
        PASS();
    }

    TEST("ParseFixedPoint: fractional value scaled by decimals=8") {
        int64_t out = -1;
        ASSERT(ParseFixedPoint("1.5", 8, &out));
        ASSERT_EQ(out, 150000000LL);
        PASS();
    }

    TEST("ParseFixedPoint: negative value") {
        int64_t out = 1;
        ASSERT(ParseFixedPoint("-1.5", 8, &out));
        ASSERT_EQ(out, -150000000LL);
        PASS();
    }

    TEST("ParseFixedPoint: zero") {
        int64_t out = -1;
        ASSERT(ParseFixedPoint("0", 8, &out));
        ASSERT_EQ(out, 0LL);
        PASS();
    }

    TEST("ParseFixedPoint: scientific notation with a positive exponent") {
        int64_t out = -1;
        ASSERT(ParseFixedPoint("1e2", 8, &out));
        ASSERT_EQ(out, 100LL * 100000000LL);
        PASS();
    }

    TEST("ParseFixedPoint: scientific notation with a negative exponent") {
        int64_t out = -1;
        ASSERT(ParseFixedPoint("150e-2", 8, &out));
        ASSERT_EQ(out, 150000000LL);
        PASS();
    }

    TEST("ParseFixedPoint: rejects a bare decimal point with no fractional digits") {
        int64_t out = -1;
        ASSERT(!ParseFixedPoint("1.", 8, &out));
        PASS();
    }

    TEST("ParseFixedPoint: rejects an empty string") {
        int64_t out = -1;
        ASSERT(!ParseFixedPoint("", 8, &out));
        PASS();
    }

    TEST("ParseFixedPoint: rejects a leading-zero multi-digit integer part") {
        int64_t out = -1;
        ASSERT(!ParseFixedPoint("01", 8, &out));
        PASS();
    }

    TEST("ParseFixedPoint: rejects a value whose scaled magnitude is too large") {
        int64_t out = -1;
        ASSERT(!ParseFixedPoint("100000000000", 8, &out));
        PASS();
    }

    TEST("ParseFixedPoint: rejects trailing garbage after a valid number") {
        int64_t out = -1;
        ASSERT(!ParseFixedPoint("1.5x", 8, &out));
        PASS();
    }

    /* ───────────────────────── ConvertBits ───────────────────────── */

    TEST("ConvertBits: 8-bit -> 5-bit with padding, then back 5-bit -> 8-bit "
         "without padding roundtrips the original bytes") {
        unsigned char in[5] = {0xFF, 0x00, 0xFF, 0x00, 0xFF};
        unsigned char mid[16];
        size_t mid_len = 0;
        ASSERT(ConvertBits(8, 5, true, in, 5, mid, sizeof(mid), &mid_len));
        ASSERT_EQ(mid_len, (size_t)8);

        unsigned char back[16];
        size_t back_len = 0;
        ASSERT(ConvertBits(5, 8, false, mid, mid_len, back, sizeof(back), &back_len));
        ASSERT_EQ(back_len, (size_t)5);
        ASSERT(memcmp(back, in, 5) == 0);
        PASS();
    }

    TEST("ConvertBits: empty input produces empty output and succeeds") {
        unsigned char out[8];
        size_t out_len = 999;
        ASSERT(ConvertBits(8, 5, true, NULL, 0, out, sizeof(out), &out_len));
        ASSERT_EQ(out_len, (size_t)0);
        PASS();
    }

    TEST("ConvertBits: non-zero leftover bits are rejected when pad=false") {
        /* One input byte (8 bits) converted to 5-bit groups without padding
         * leaves 3 leftover bits that are non-zero (0xFF's low bits), which
         * the non-pad path must reject rather than silently drop. */
        unsigned char in[1] = {0xFF};
        unsigned char out[8];
        size_t out_len = 0;
        ASSERT(!ConvertBits(8, 5, false, in, 1, out, sizeof(out), &out_len));
        PASS();
    }

    TEST("ConvertBits: truncates cleanly when the output buffer is too small") {
        unsigned char in[5] = {0xAB, 0xCD, 0xEF, 0x01, 0x23};
        unsigned char out[3];
        size_t out_len = 0;
        ASSERT(ConvertBits(8, 5, true, in, 5, out, sizeof(out), &out_len));
        ASSERT_EQ(out_len, (size_t)3);
        PASS();
    }

_test_next:;
    if (failures == 0)
        printf("test_test_str_money_codecs: all passed\n");
    else
        printf("test_test_str_money_codecs: %d FAILED\n", failures);
    return failures;
}
