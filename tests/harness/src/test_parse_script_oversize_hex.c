/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression test for the parse_script() stack buffer overflow in
 * core/math/src/core_io.c.
 *
 * For a "0x..." hex token, parse_script derives byte_len = strlen(token+2)/2
 * from an UNBOUNDED token length, then formerly called
 * ParseHex(token+2, raw, byte_len) into `unsigned char raw[MAX_SCRIPT_SIZE]`
 * (10000) BEFORE checking byte_len against MAX_SCRIPT_SIZE. A token with
 * more than 20000 hex chars made byte_len > 10000, so ParseHex wrote past
 * the end of the stack array `raw` -> stack buffer overflow (under ASan the
 * old code traps here).
 *
 * The fix reorders the bound check ahead of the write:
 *   if (byte_len > MAX_SCRIPT_SIZE || out->size + byte_len > MAX_SCRIPT_SIZE)
 *       { ok = false; break; }
 * so an oversize token cleanly returns false with no overflow.
 *
 * This test feeds a "0x" token of 30000 'a' chars (byte_len = 15000 > 10000)
 * and asserts parse_script returns false and out->size stays within bounds
 * (no overflow / no partial advance). It also asserts a valid short
 * "0xdeadbeef" token still parses to a 4-byte script.
 */

#include "test/test_core.h"
#include "coins/undo.h"
#include "core/core_io.h"
#include "script/script.h"
#include <stdlib.h>
#include <string.h>

int test_parse_script_oversize_hex(void)
{
    int failures = 0;
    TEST_CASE("parse_script rejects oversize 0x hex without overflow") {
        /* "0x" + 30000 'a' -> hex_len 30000, byte_len 15000 > MAX_SCRIPT_SIZE
         * (10000). The old code wrote 15000 bytes into raw[10000]. */
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

        /* Fixed code returns false; old code overflowed the stack first. */
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
