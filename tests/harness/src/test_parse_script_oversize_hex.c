/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression test: parse_script() must bound-check a "0x..." token's byte_len
 * against MAX_SCRIPT_SIZE before ParseHex writes into the stack buffer
 * `raw[MAX_SCRIPT_SIZE]` (core/math/src/core_io.c).
 *
 * A "0x" token of 30000 'a' chars (byte_len 15000) must return false with
 * out->size within bounds; a valid "0xdeadbeef" still parses to 4 bytes.
 */

#include "test/test_core.h"
#include "coins/undo.h"
#include "core/core_io.h"
#include "script/script.h"
#include <stdlib.h>
#include <string.h>

/* Characterization of parse_script() and script_to_asm_str() (core_io.c):
 * the expected values below were derived from the current code, one row per
 * branch. Byte sequences used by the sighash rows: a DER signature
 * 30 06 02 01 01 02 01 01 followed by a one-byte hashtype. */
#define ASM_SIG8 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01

struct parse_row {
    const char *in;
    bool ok;
    size_t n;
    unsigned char b[4];
};

static int pin_parse_script_tokens(void)
{
    int failures = 0;
    TEST_CASE("parse_script pins the token grammar, one row per branch") {
        static const struct parse_row rows[] = {
            {"", true, 0, {0}},
            {" \t\n", true, 0, {0}},
            {"OP_DUP OP_HASH160 OP_EQUAL", true, 3, {OP_DUP, OP_HASH160, OP_EQUAL}},
            {"DUP HASH160 EQUAL", true, 3, {OP_DUP, OP_HASH160, OP_EQUAL}},
            {"OP_DUP\tOP_EQUAL\nOP_CHECKSIG", true, 3, {OP_DUP, OP_EQUAL, OP_CHECKSIG}},
            {"OP_RESERVED", true, 1, {OP_RESERVED}},
            {"OP_1", false, 0, {0}},
            {"OP_FOO", false, 0, {0}},
            {"OP_DUP OP_FOO", false, 0, {0}},
            {"0", true, 1, {OP_0}},
            {"-0", true, 1, {OP_0}},
            {"1", true, 1, {OP_1}},
            {"16", true, 1, {OP_16}},
            {"-1", true, 1, {OP_1NEGATE}},
            {"17", true, 2, {0x01, 0x11}},
            {"1 2 OP_ADD", true, 3, {OP_1, OP_2, OP_ADD}},
            {"-", false, 0, {0}},
            {"+1", false, 0, {0}},
            {"0xdeadbeef", true, 4, {0xde, 0xad, 0xbe, 0xef}},
            {"0xDEADBEEF", true, 4, {0xde, 0xad, 0xbe, 0xef}},
            {"0x", false, 0, {0}},
            {"0xabc", false, 0, {0}},
            {"0xzz", false, 0, {0}},
            {"'abc'", true, 4, {0x03, 'a', 'b', 'c'}},
            {"''", true, 1, {0x00}},
            {"'", false, 0, {0}},
        };
        for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
            struct script s;
            bool ok = parse_script(rows[i].in, &s);
            ASSERT(ok == rows[i].ok);
            if (!ok) continue;
            ASSERT(s.size == rows[i].n);
            ASSERT(memcmp(s.data, rows[i].b, rows[i].n) == 0);
        }
    } TEST_END
    return failures;
}

static int pin_parse_script_hex_cap(void)
{
    int failures = 0;
    TEST_CASE("parse_script accepts exactly MAX_SCRIPT_SIZE hex bytes, refuses one more") {
        size_t cap = MAX_SCRIPT_SIZE;
        char *tok = zcl_malloc(2 * cap + 16, "test_parse_script_cap");
        ASSERT(tok != NULL);
        tok[0] = '0';
        tok[1] = 'x';
        memset(tok + 2, '0', 2 * cap);
        tok[2 + 2 * cap] = '\0';

        struct script s;
        bool ok = parse_script(tok, &s);
        ASSERT(ok == true);
        ASSERT(s.size == cap);

        /* One more byte in a second token overflows the script: refused. */
        tok[2 + 2 * cap] = ' ';
        memcpy(tok + 3 + 2 * cap, "0x00", 5);
        bool ok2 = parse_script(tok, &s);
        free(tok);
        ASSERT(ok2 == false);
        ASSERT(s.size == cap);
    } TEST_END
    return failures;
}

struct asm_row {
    unsigned char b[12];
    size_t n;
    bool decode;
    const char *text;
};

static int pin_script_to_asm_str_rows(void)
{
    int failures = 0;
    TEST_CASE("script_to_asm_str pins names, numbers, data and error rendering") {
        static const struct asm_row rows[] = {
            {{0}, 0, false, ""},
            {{OP_DUP, OP_HASH160, OP_EQUAL}, 3, false, "OP_DUP OP_HASH160 OP_EQUAL"},
            {{OP_0}, 1, false, "0"},
            {{OP_1}, 1, false, "1"},
            {{OP_16}, 1, false, "16"},
            {{OP_1NEGATE}, 1, false, "-1"},
            {{0x01, 0x81}, 2, false, "-1"},
            {{0x04, 0x01, 0x02, 0x03, 0x04}, 5, false, "67305985"},
            {{0x05, 0x01, 0x02, 0x03, 0x04, 0x05}, 6, false, "0102030405"},
            {{0x05, 0x01}, 2, false, "[error]"},
            {{OP_PUSHDATA1}, 1, false, "[error]"},
            {{0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}, 10, true,
             "010203040506070809"},
            {{0x09, ASM_SIG8, 0x01}, 10, false, "300602010102010101"},
            {{0x09, ASM_SIG8, 0x01}, 10, true, "3006020101020101[ALL]"},
            {{0x09, ASM_SIG8, 0x02}, 10, true, "3006020101020101[NONE]"},
            {{0x09, ASM_SIG8, 0x03}, 10, true, "3006020101020101[SINGLE]"},
            {{0x09, ASM_SIG8, 0x81}, 10, true, "3006020101020101[ALL|ANYONECANPAY]"},
            {{0x09, ASM_SIG8, 0x82}, 10, true, "3006020101020101[NONE|ANYONECANPAY]"},
            {{0x09, ASM_SIG8, 0x83}, 10, true, "3006020101020101[SINGLE|ANYONECANPAY]"},
            {{0x09, ASM_SIG8, 0x04}, 10, true, "300602010102010104"},
            {{0x09, ASM_SIG8, 0x00}, 10, true, "300602010102010100"},
            {{OP_RETURN, 0x09, ASM_SIG8, 0x01}, 11, true, "OP_RETURN 300602010102010101"},
        };
        for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
            struct script s;
            script_init(&s);
            script_set(&s, rows[i].b, rows[i].n);
            char buf[128];
            size_t n = script_to_asm_str(&s, rows[i].decode, buf, sizeof(buf));
            ASSERT(n == strlen(rows[i].text));
            ASSERT_STR_EQ(buf, rows[i].text);
        }
    } TEST_END
    return failures;
}

static int pin_script_to_asm_str_small_buffer(void)
{
    int failures = 0;
    TEST_CASE("script_to_asm_str truncates into a small buffer and reports full length") {
        struct script s;
        script_init(&s);
        script_push_op(&s, OP_DUP);
        script_push_op(&s, OP_HASH160);
        char buf[4];
        memset(buf, 'x', sizeof(buf));
        size_t n = script_to_asm_str(&s, false, buf, sizeof(buf));
        ASSERT(n == 17);
        ASSERT_STR_EQ(buf, "OP_");
    } TEST_END
    return failures;
}

int test_parse_script_oversize_hex(void)
{
    int failures = 0;
    failures += pin_parse_script_tokens();
    failures += pin_parse_script_hex_cap();
    failures += pin_script_to_asm_str_rows();
    failures += pin_script_to_asm_str_small_buffer();
    TEST_CASE("parse_script rejects oversize 0x hex without overflow") {
        /* "0x" + 30000 'a' -> byte_len 15000 > MAX_SCRIPT_SIZE (10000). */
        size_t hex_chars = 30000;
        char *big = zcl_malloc(hex_chars + 3, "test_oversize_hex");
        ASSERT(big != NULL);
        big[0] = '0';
        big[1] = 'x';
        memset(big + 2, 'a', hex_chars);
        big[hex_chars + 2] = '\0';

        struct script s;
        bool ok = parse_script(big, &s);
        free(big);

        /* Returns false with no overflow. */
        ASSERT(ok == false);
        /* Output never advanced past the fixed-size script buffer. */
        ASSERT(s.size <= MAX_SCRIPT_SIZE);

        /* A valid short hex token still parses to its exact byte length. */
        struct script v;
        bool ok2 = parse_script("0xdeadbeef", &v);
        ASSERT(ok2 == true);
        ASSERT(v.size == 4);
        ASSERT(v.data[0] == 0xde);
        ASSERT(v.data[1] == 0xad);
        ASSERT(v.data[2] == 0xbe);
        ASSERT(v.data[3] == 0xef);
    } TEST_END
    return failures;
}
