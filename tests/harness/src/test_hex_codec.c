/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hermetic coverage for the one hex codec, platform/modules/base/include/base/hex.h.
 *
 * This file deliberately hand-writes every expected hex string instead of
 * deriving it — checking zcl_hex_decode() against zcl_hex_encode() would
 * pass just as happily if both were wrong in the same direction. The same
 * reason lib/test is excluded from the check-hex-codec-single scan.
 *
 * What is pinned here is the reconciliation of the twelve private codecs
 * this header replaced, which disagreed with each other:
 *
 *   - encode is LOWERCASE and always NUL-terminates (all twelve agreed;
 *     this is what is on disk and in the database, so it must not move);
 *   - decode is EXACT-LENGTH — an odd length, a short string and a long
 *     string are all rejected, where several copies never looked;
 *   - decode rejects any character outside its alphabet;
 *   - zcl_hex_decode() accepts A-F, zcl_hex_decode_lower() does not, so a
 *     value stored as a filename has exactly one spelling;
 *   - a FAILED decode zeroes the caller's buffer and writes nothing past
 *     `want`, because at least one caller ignored the return value and read
 *     the buffer anyway.
 *
 * Pure and deterministic: no clock, no RNG, no I/O, no live DB. */

#include "test/test_core.h"

#include "base/hex.h"

#include <string.h>

int test_hex_codec(void);
int test_hex_codec(void)
{
    int failures = 0;

    /* ───────────────────────── zcl_hex_encode ───────────────────────── */

    TEST("zcl_hex_encode: known vector encodes lowercase") {
        const uint8_t in[4] = { 0xde, 0xad, 0xbe, 0xef };
        char out[9];
        zcl_hex_encode(in, sizeof(in), out);
        ASSERT_STR_EQ(out, "deadbeef");
        PASS();
    }

    TEST("zcl_hex_encode: high nibbles and low nibbles are not swapped") {
        const uint8_t in[3] = { 0x01, 0x10, 0xa0 };
        char out[7];
        zcl_hex_encode(in, sizeof(in), out);
        ASSERT_STR_EQ(out, "0110a0");
        PASS();
    }

    TEST("zcl_hex_encode: NUL-terminates at exactly 2*len and writes no "
         "further") {
        const uint8_t in[4] = { 0xde, 0xad, 0xbe, 0xef };
        char out[12];
        memset(out, 'X', sizeof(out));
        zcl_hex_encode(in, sizeof(in), out);
        ASSERT_EQ(out[8], '\0');
        /* Byte 9 onward belongs to the caller and must be untouched. */
        ASSERT_EQ(out[9], 'X');
        ASSERT_EQ(out[10], 'X');
        PASS();
    }

    TEST("zcl_hex_encode: empty input writes just the NUL") {
        const uint8_t in[1] = { 0xff };
        char out[4];
        memset(out, 'X', sizeof(out));
        zcl_hex_encode(in, 0, out);
        ASSERT_EQ(out[0], '\0');
        ASSERT_EQ(out[1], 'X');
        PASS();
    }

    TEST("zcl_hex_encode: NULL input writes the empty string rather than "
         "reading it") {
        char out[8];
        memset(out, 'X', sizeof(out));
        zcl_hex_encode(NULL, 4, out);
        ASSERT_STR_EQ(out, "");
        PASS();
    }

    TEST("zcl_hex_encode: every byte value round-trips through "
         "zcl_hex_decode") {
        uint8_t in[256];
        for (size_t i = 0; i < sizeof(in); i++)
            in[i] = (uint8_t)i;
        char hex[513];
        zcl_hex_encode(in, sizeof(in), hex);
        ASSERT_EQ(strlen(hex), (size_t)512);
        uint8_t back[256];
        ASSERT(zcl_hex_decode(hex, back, sizeof(back)));
        ASSERT_EQ(memcmp(in, back, sizeof(in)), 0);
        PASS();
    }

    TEST("zcl_hex_encode: its own output is accepted by the canonical "
         "(lowercase-only) decoder") {
        uint8_t in[32];
        for (size_t i = 0; i < sizeof(in); i++)
            in[i] = (uint8_t)(i * 7u + 3u);
        char hex[65];
        zcl_hex_encode(in, sizeof(in), hex);
        uint8_t back[32];
        ASSERT(zcl_hex_decode_lower(hex, back, sizeof(back)));
        ASSERT_EQ(memcmp(in, back, sizeof(in)), 0);
        PASS();
    }

    /* ───────────────────────── zcl_hex_decode ───────────────────────── */

    TEST("zcl_hex_decode: known vector decodes to the right bytes") {
        uint8_t out[4];
        ASSERT(zcl_hex_decode("deadbeef", out, sizeof(out)));
        ASSERT_EQ(out[0], 0xde);
        ASSERT_EQ(out[1], 0xad);
        ASSERT_EQ(out[2], 0xbe);
        ASSERT_EQ(out[3], 0xef);
        PASS();
    }

    TEST("zcl_hex_decode: an odd-length string is rejected") {
        uint8_t out[4];
        ASSERT(!zcl_hex_decode("abc", out, 2));
        ASSERT(!zcl_hex_decode("deadbee", out, 4));
        ASSERT(!zcl_hex_decode("d", out, 1));
        PASS();
    }

    TEST("zcl_hex_decode: a non-hex character is rejected wherever it sits") {
        uint8_t out[4];
        ASSERT(!zcl_hex_decode("deadbeeg", out, 4));  /* last  */
        ASSERT(!zcl_hex_decode("geadbeef", out, 4));  /* first */
        ASSERT(!zcl_hex_decode("dead beef", out, 4)); /* space (also longer) */
        ASSERT(!zcl_hex_decode("dead-eef", out, 4));  /* punctuation */
        PASS();
    }

    TEST("zcl_hex_decode: sscanf-style leading whitespace and a sign are "
         "NOT accepted (one replaced copy took both)") {
        uint8_t out[2];
        ASSERT(!zcl_hex_decode(" 1 2", out, 2));
        ASSERT(!zcl_hex_decode("+1+2", out, 2));
        PASS();
    }

    TEST("zcl_hex_decode: empty input decodes zero bytes and nothing else") {
        uint8_t out[4];
        memset(out, 0xaa, sizeof(out));
        ASSERT(zcl_hex_decode("", out, 0));
        /* want == 0 means no byte was claimed, so none was written. */
        ASSERT_EQ(out[0], 0xaa);
        /* and the empty string is not a valid encoding of any byte. */
        ASSERT(!zcl_hex_decode("", out, 1));
        PASS();
    }

    TEST("zcl_hex_decode: a string one byte LONGER than wanted is rejected") {
        uint8_t out[8];
        ASSERT(!zcl_hex_decode("deadbeef", out, 3));
        PASS();
    }

    TEST("zcl_hex_decode: an output buffer exactly one byte short is refused "
         "and nothing is written past `want`") {
        uint8_t out[8];
        memset(out, 0xaa, sizeof(out));
        /* "deadbeef" is 4 bytes; asking for 3 must fail, not truncate. */
        ASSERT(!zcl_hex_decode("deadbeef", out, 3));
        /* The refusal zeroes the claimed region ... */
        ASSERT_EQ(out[0], 0x00);
        ASSERT_EQ(out[2], 0x00);
        /* ... and does not touch the byte just past it. */
        ASSERT_EQ(out[3], 0xaa);
        ASSERT_EQ(out[4], 0xaa);
        PASS();
    }

    TEST("zcl_hex_decode: a failed decode zeroes the buffer, so a caller "
         "that ignores the return value cannot read stale bytes") {
        uint8_t out[4];
        memset(out, 0xaa, sizeof(out));
        ASSERT(!zcl_hex_decode("deadbeez", out, 4));
        for (size_t i = 0; i < sizeof(out); i++)
            ASSERT_EQ(out[i], 0x00);
        PASS();
    }

    TEST("zcl_hex_decode: NULL input is rejected without dereferencing") {
        uint8_t out[4];
        memset(out, 0xaa, sizeof(out));
        ASSERT(!zcl_hex_decode(NULL, out, 4));
        ASSERT_EQ(out[0], 0x00);
        ASSERT(!zcl_hex_decode("deadbeef", NULL, 4));
        PASS();
    }

    /* ──────────────────── case policy: the two decoders ──────────────── */

    TEST("zcl_hex_decode: uppercase A-F is accepted (operator-supplied hex)") {
        uint8_t out[4];
        ASSERT(zcl_hex_decode("DEADBEEF", out, sizeof(out)));
        ASSERT_EQ(out[0], 0xde);
        ASSERT_EQ(out[3], 0xef);
        ASSERT(zcl_hex_decode("DeAdBeEf", out, sizeof(out)));
        ASSERT_EQ(out[1], 0xad);
        PASS();
    }

    TEST("zcl_hex_decode_lower: uppercase A-F is REJECTED, so an on-disk "
         "name has exactly one spelling") {
        uint8_t out[4];
        memset(out, 0xaa, sizeof(out));
        ASSERT(!zcl_hex_decode_lower("DEADBEEF", out, sizeof(out)));
        ASSERT_EQ(out[0], 0x00);
        ASSERT(!zcl_hex_decode_lower("deadbeeF", out, sizeof(out)));
        ASSERT(zcl_hex_decode_lower("deadbeef", out, sizeof(out)));
        ASSERT_EQ(out[0], 0xde);
        PASS();
    }

    TEST("zcl_hex_decode_lower: digits and a-f both work; length is still "
         "exact") {
        uint8_t out[3];
        ASSERT(zcl_hex_decode_lower("0123ab", out, sizeof(out)));
        ASSERT_EQ(out[0], 0x01);
        ASSERT_EQ(out[1], 0x23);
        ASSERT_EQ(out[2], 0xab);
        ASSERT(!zcl_hex_decode_lower("0123ab00", out, sizeof(out)));
        PASS();
    }

    /* ──────────────────────── zcl_hex_decode_n ──────────────────────── */

    TEST("zcl_hex_decode_n: decodes a variable length and reports it") {
        uint8_t out[16];
        size_t n = 999;
        ASSERT(zcl_hex_decode_n("deadbeef", out, sizeof(out), &n));
        ASSERT_EQ(n, (size_t)4);
        ASSERT_EQ(out[0], 0xde);
        ASSERT_EQ(out[3], 0xef);
        /* Bytes past the decoded length stay zero, not stale. */
        ASSERT_EQ(out[4], 0x00);
        PASS();
    }

    TEST("zcl_hex_decode_n: a payload exactly filling the cap is accepted; "
         "one byte more is refused") {
        uint8_t out[4];
        size_t n = 0;
        ASSERT(zcl_hex_decode_n("deadbeef", out, sizeof(out), &n));
        ASSERT_EQ(n, (size_t)4);
        memset(out, 0xaa, sizeof(out));
        ASSERT(!zcl_hex_decode_n("deadbeef00", out, sizeof(out), &n));
        ASSERT_EQ(n, (size_t)0);
        ASSERT_EQ(out[0], 0x00);
        PASS();
    }

    TEST("zcl_hex_decode_n: empty and odd-length inputs are rejected") {
        uint8_t out[8];
        size_t n = 7;
        ASSERT(!zcl_hex_decode_n("", out, sizeof(out), &n));
        ASSERT_EQ(n, (size_t)0);
        ASSERT(!zcl_hex_decode_n("abc", out, sizeof(out), &n));
        ASSERT(!zcl_hex_decode_n(NULL, out, sizeof(out), &n));
        PASS();
    }

    TEST("zcl_hex_decode_n: a non-hex character is rejected and the whole "
         "cap is zeroed") {
        uint8_t out[8];
        size_t n = 0;
        memset(out, 0xaa, sizeof(out));
        ASSERT(!zcl_hex_decode_n("deadbeez", out, sizeof(out), &n));
        for (size_t i = 0; i < sizeof(out); i++)
            ASSERT_EQ(out[i], 0x00);
        PASS();
    }

    TEST("zcl_hex_decode_n: uppercase is accepted and out_len may be NULL") {
        uint8_t out[8];
        ASSERT(zcl_hex_decode_n("ABCD", out, sizeof(out), NULL));
        ASSERT_EQ(out[0], 0xab);
        ASSERT_EQ(out[1], 0xcd);
        PASS();
    }

    /* ───────────────────────── zcl_hex_nibble ───────────────────────── */

    TEST("zcl_hex_nibble: maps digits and letters, rejects everything else") {
        ASSERT_EQ(zcl_hex_nibble('0', true), 0);
        ASSERT_EQ(zcl_hex_nibble('9', true), 9);
        ASSERT_EQ(zcl_hex_nibble('a', true), 10);
        ASSERT_EQ(zcl_hex_nibble('f', true), 15);
        ASSERT_EQ(zcl_hex_nibble('A', true), 10);
        ASSERT_EQ(zcl_hex_nibble('F', true), 15);
        ASSERT_EQ(zcl_hex_nibble('A', false), -1);
        ASSERT_EQ(zcl_hex_nibble('g', true), -1);
        ASSERT_EQ(zcl_hex_nibble('/', true), -1);
        ASSERT_EQ(zcl_hex_nibble(':', true), -1);
        ASSERT_EQ(zcl_hex_nibble('\0', true), -1);
        PASS();
    }

_test_next:;
    if (failures == 0)
        printf("test_hex_codec: all passed\n");
    else
        printf("test_hex_codec: %d FAILED\n", failures);
    return failures;
}
