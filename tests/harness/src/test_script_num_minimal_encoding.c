/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure table test for script_num_from_bytes (script/script.h) — the
 * consensus minimal-encoding rejection branch, the len>max_size bound,
 * the negative sign-bit decode, and a script_num_serialize round-trip.
 *
 * script_num_from_bytes is an inline used by every numeric opcode in
 * eval_script; the require_minimal rejection path and the size bound
 * are exercised by no other test today. Fully deterministic, no fixtures.
 *
 * One TEST_CASE per function: TEST_END emits the _test_next label, so a
 * second pair would be a duplicate-label compile error. All sub-checks
 * live in this single block and short-circuit via ASSERT -> _test_next. */

#include "test/test_core.h"
#include "chain/pow.h"

int test_script_num_minimal_encoding(void);
int test_script_num_minimal_encoding(void)
{
    printf("\n=== script_num minimal encoding tests ===\n");
    int failures = 0;

    TEST_CASE("script_num_from_bytes minimal/size/negative table") {
        struct script_num out;

        /* ── Minimal-encoding REJECTION (consensus rule, never hit
         * today): require_minimal=true rejects redundant padding. ── */
        const unsigned char redundant_zero[]   = { 0x00 };
        const unsigned char trailing_zero[]    = { 0x01, 0x00 };
        const unsigned char negative_zero[]    = { 0x80 };
        ASSERT(!script_num_from_bytes(&out, redundant_zero, 1, true,
                                      SCRIPT_NUM_DEFAULT_MAX_SIZE));
        ASSERT(!script_num_from_bytes(&out, trailing_zero, 2, true,
                                      SCRIPT_NUM_DEFAULT_MAX_SIZE));
        ASSERT(!script_num_from_bytes(&out, negative_zero, 1, true,
                                      SCRIPT_NUM_DEFAULT_MAX_SIZE));

        /* ── Same buffers ACCEPTED when minimality is not required. ── */
        ASSERT(script_num_from_bytes(&out, redundant_zero, 1, false,
                                     SCRIPT_NUM_DEFAULT_MAX_SIZE));
        ASSERT(out.value == 0);
        ASSERT(script_num_from_bytes(&out, negative_zero, 1, false,
                                     SCRIPT_NUM_DEFAULT_MAX_SIZE));
        ASSERT(out.value == 0);                 /* negative zero == 0 */
        ASSERT(script_num_from_bytes(&out, trailing_zero, 2, false,
                                     SCRIPT_NUM_DEFAULT_MAX_SIZE));
        ASSERT(out.value == 1);

        /* ── Size REJECTION: len > max_size. ── */
        const unsigned char five[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        ASSERT(!script_num_from_bytes(&out, five, 5, false,
                                      SCRIPT_NUM_DEFAULT_MAX_SIZE));   /* max 4 */
        ASSERT(script_num_from_bytes(&out, five, 5, false,
                                     SCRIPT_NUM_MAX_SIZE));            /* max 8 */

        /* ── Negative sign-bit decode. {0x81} is the minimal encoding
         * of -1; {0x01,0x80} also decodes to -1 (sign bit in the top
         * byte) but is NON-minimal, so it is rejected under
         * require_minimal=true and only decodes with it cleared. ── */
        const unsigned char neg_one_min[] = { 0x81 };
        const unsigned char neg_one_pad[] = { 0x01, 0x80 };
        ASSERT(script_num_from_bytes(&out, neg_one_min, 1, true,
                                     SCRIPT_NUM_DEFAULT_MAX_SIZE));
        ASSERT(out.value == -1);
        ASSERT(!script_num_from_bytes(&out, neg_one_pad, 2, true,
                                      SCRIPT_NUM_DEFAULT_MAX_SIZE));
        ASSERT(script_num_from_bytes(&out, neg_one_pad, 2, false,
                                     SCRIPT_NUM_DEFAULT_MAX_SIZE));
        ASSERT(out.value == -1);

        /* ── Empty buffer -> 0, accepted even under require_minimal. ── */
        ASSERT(script_num_from_bytes(&out, NULL, 0, true,
                                     SCRIPT_NUM_DEFAULT_MAX_SIZE));
        ASSERT(out.value == 0);

        /* ── Positive minimal decode. ── */
        const unsigned char pos_127[] = { 0x7f };
        ASSERT(script_num_from_bytes(&out, pos_127, 1, true,
                                     SCRIPT_NUM_DEFAULT_MAX_SIZE));
        ASSERT(out.value == 127);

        /* ── serialize -> minimal re-parse round-trips. ── */
        struct script_num sn_neg = script_num_from_int(-1);
        unsigned char buf[SCRIPT_NUM_MAX_SIZE];
        size_t n = script_num_serialize(&sn_neg, buf, sizeof(buf));
        ASSERT(n > 0);
        ASSERT(script_num_from_bytes(&out, buf, n, true, SCRIPT_NUM_MAX_SIZE));
        ASSERT(out.value == -1);

        struct script_num sn_pos = script_num_from_int(127);
        n = script_num_serialize(&sn_pos, buf, sizeof(buf));
        ASSERT(n > 0);
        ASSERT(script_num_from_bytes(&out, buf, n, true, SCRIPT_NUM_MAX_SIZE));
        ASSERT(out.value == 127);
    } TEST_END

    return failures;
}
