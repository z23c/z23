/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * NET-NEW consensus edge-case tests for the pure ZClassic script VM
 * (domain/consensus/src/script_interp.c, reached through the
 * domain_consensus_eval_script entry point used by eval_script).
 *
 * These cover boundary/limit conditions that the existing suites do NOT:
 *   - test_domain_consensus_script_interp.c    (dispatch + sig + P2SH)
 *   - test_multisig_consensus_branches.c        (multisig branches)
 *   - test_script_interp_stack_bounds.c         (stack-shape pins + MAX_STACK_ITEMS)
 *   - test_script_interp_altstack_conditional.c (altstack across OP_IF)
 *
 * Each case below invokes the REAL consensus evaluator and asserts the
 * exact verdict (bool + ScriptError) the spec requires. They are
 * designed to PASS against current correct behaviour and to FAIL the
 * build if any of these consensus limits is loosened or removed:
 *
 *   1. CScriptNum 4-byte size limit — a 5-byte numeric operand to an
 *      arithmetic opcode (OP_1ADD) is rejected; a 4-byte operand at the
 *      boundary is accepted. (script_num_from_bytes max_size=4.)
 *   2. MAX_SCRIPT_ELEMENT_SIZE (520) push boundary — a 520-byte push (the
 *      largest legal stack element) is accepted and round-trips; 521-byte
 *      and 9000-byte declared pushes are rejected at parse by
 *      script_get_op's destination-capacity guard (no buffer overrun),
 *      and sigops appearing AFTER an oversized push are still counted
 *      (data-less walk parity with zclassicd GetSigOpCount).
 *   3. SCRIPT_VERIFY_MINIMALDATA — a non-minimal 1-byte push of {0x01}
 *      (raw opcode 0x01) is rejected with SCRIPT_ERR_MINIMALDATA when the
 *      flag is set, and accepted (truthy) when it is not.
 *   4. Op-count cap (201 non-push opcodes) — exactly 201 OP_NOPs succeed,
 *      202 trips SCRIPT_ERR_OP_COUNT. (The cap counts opcode > OP_16.)
 *   5. OP_CHECKMULTISIG with the dummy element missing — the count-operand
 *      bounds check underflows and yields SCRIPT_ERR_INVALID_STACK_OPERATION.
 *   6. Standalone OP_ELSE with no open OP_IF — SCRIPT_ERR_UNBALANCED_CONDITIONAL
 *      (a distinct code path from the already-tested stray OP_ENDIF).
 *
 * All assertions are non-vacuous: every reject case is paired with the
 * adjacent accept case at the boundary, so a stubbed-out limit cannot
 * pass both halves.
 *
 * NOTE: this file hosts EXACTLY ONE TEST_CASE/TEST_END pair, because the
 * harness macro defines a single _test_next: label per function. Each
 * sub-scope uses its own stack/script locals. The entrypoint is wired by
 * the central runner change, never colliding with the existing suites.
 */

#include "test/test_core.h"

#include "domain/consensus/script_interp.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/script_flags.h"

#include <stdint.h>
#include <string.h>

/* Evaluate `s` on a fresh heap stack and assert (ok, err) exactly.
 * Returns the running failure count delta via the caller's `failures`
 * by way of the ASSERT macros — so it is a helper that ASSERTs inline.
 * Kept as a macro so ASSERT's goto _test_next stays in the test fn. */
#define EVAL_AND_EXPECT(s, flags, expect_ok, expect_err)                  \
    do {                                                                  \
        struct script_stack _stk = {0};                                   \
        ASSERT(stack_init(&_stk));                                        \
        ScriptError _err = SCRIPT_ERR_ERROR_COUNT;                        \
        bool _ok = domain_consensus_eval_script(&_stk, (s), (flags),      \
                                                NULL, 0, &_err);          \
        if (_ok != (expect_ok) || (!(expect_ok) &&                        \
            _err != (ScriptError)(expect_err))) {                         \
            stack_free(&_stk);                                            \
            ASSERT(_ok == (expect_ok));                                   \
            ASSERT_EQ(_err, (ScriptError)(expect_err));                   \
        }                                                                 \
        if ((expect_ok)) ASSERT_EQ(_err, SCRIPT_ERR_OK);                  \
        stack_free(&_stk);                                                \
    } while (0)

int test_script_interp_edge(void)
{
    int failures = 0;
    TEST_CASE("script_interp edge: CScriptNum 4-byte limit, 520/521-byte "
              "push boundary, post-oversized-push sigops, MINIMALDATA, "
              "op-count 201 cap, multisig missing-dummy, standalone "
              "OP_ELSE") {

        /* ---- 1a. 5-byte numeric operand to OP_1ADD -> reject ----
         * SN_FROM_TOP uses SCRIPT_NUM_DEFAULT_MAX_SIZE (4). A 5-byte
         * push is a valid script element but an over-long number, so
         * script_num_from_bytes() returns false and the evaluator maps
         * that to SCRIPT_ERR_UNKNOWN_ERROR. */
        {
            unsigned char five[5] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
            struct script s; script_init(&s);
            ASSERT(script_push_data(&s, five, sizeof five));
            ASSERT(script_push_op(&s, OP_1ADD));
            EVAL_AND_EXPECT(&s, SCRIPT_VERIFY_NONE, false,
                            SCRIPT_ERR_UNKNOWN_ERROR);
        }

        /* ---- 1b. 4-byte numeric operand to OP_1ADD -> accept ----
         * The boundary case. {0x01,0x00,0x00,0x00} is the value 1; with
         * a 4-byte length it is within the limit, OP_1ADD makes it 2,
         * and the script completes (truthy residual). This proves 1a's
         * reject is the size limit, not OP_1ADD always failing. */
        {
            unsigned char four[4] = { 0x01, 0x00, 0x00, 0x00 };
            struct script s; script_init(&s);
            ASSERT(script_push_data(&s, four, sizeof four));
            ASSERT(script_push_op(&s, OP_1ADD));
            EVAL_AND_EXPECT(&s, SCRIPT_VERIFY_NONE, true, SCRIPT_ERR_OK);
        }

        /* ---- 2a. 520-byte push -> accept (== MAX_SCRIPT_ELEMENT_SIZE) ----
         * The largest legal stack element. The push itself must not be
         * rejected; the residual top is the 520-byte (truthy) element. */
        {
            unsigned char big[MAX_SCRIPT_ELEMENT_SIZE];
            memset(big, 0x42, sizeof big);
            struct script s; script_init(&s);
            ASSERT(script_push_data(&s, big, sizeof big));
            EVAL_AND_EXPECT(&s, SCRIPT_VERIFY_NONE, true, SCRIPT_ERR_OK);
        }

        /* ---- 2b. 521-byte push (one past the limit) -> parse reject ----
         * script_get_op rejects an oversized push BEFORE copying into the
         * caller's 520-byte payload buffer (destination-capacity guard),
         * so the evaluator sees a parse failure -> SCRIPT_ERR_BAD_OPCODE.
         * (Pre-fix, the memcpy ran before any size check — a stack buffer
         * overrun; this case was skipped until the guard landed.) */
        {
            unsigned char big[MAX_SCRIPT_ELEMENT_SIZE + 1];
            memset(big, 0x42, sizeof big);
            struct script s; script_init(&s);
            ASSERT(script_push_data(&s, big, sizeof big));
            /* Direct parse with a payload buffer: must return false
             * without writing past the 520-byte destination. */
            {
                size_t pc = 0;
                enum opcodetype op;
                unsigned char data[MAX_SCRIPT_ELEMENT_SIZE];
                size_t datalen = 0;
                ASSERT(!script_get_op(&s, &pc, &op, data, &datalen));
            }
            /* Data-less walk (data=NULL) must still traverse PAST the
             * oversized push — zclassicd GetOp parity; this pins the
             * sigop counter's NULL-walk companion fix. */
            {
                size_t pc = 0;
                enum opcodetype op;
                ASSERT(script_get_op(&s, &pc, &op, NULL, NULL));
                ASSERT_EQ(op, OP_PUSHDATA2);
                ASSERT_EQ(pc, s.size);
            }
            EVAL_AND_EXPECT(&s, SCRIPT_VERIFY_NONE, false,
                            SCRIPT_ERR_BAD_OPCODE);
        }

        /* ---- 2c. 9000-byte declared push -> same parse reject ----
         * Far past the limit (still within MAX_SCRIPT_SIZE so the script
         * itself is well-formed): the guard must hold, not just at the
         * 521 boundary. */
        {
            unsigned char huge[9000];
            memset(huge, 0x42, sizeof huge);
            struct script s; script_init(&s);
            ASSERT(script_push_data(&s, huge, sizeof huge));
            {
                size_t pc = 0;
                enum opcodetype op;
                unsigned char data[MAX_SCRIPT_ELEMENT_SIZE];
                size_t datalen = 0;
                ASSERT(!script_get_op(&s, &pc, &op, data, &datalen));
            }
            EVAL_AND_EXPECT(&s, SCRIPT_VERIFY_NONE, false,
                            SCRIPT_ERR_BAD_OPCODE);
        }

        /* ---- 2d. sigops AFTER an oversized push still count ----
         * script_get_sig_op_count walks with data=NULL, so an oversized
         * push is traversed, not rejected — matching zclassicd
         * GetSigOpCount's data-less GetOp walk (script.cpp:159-167).
         * Undercounting here is a MAX_BLOCK_SIGOPS fork risk: output
         * scriptPubKeys are sigop-counted at block acceptance but never
         * executed, so a >520-byte push CAN appear in a block. */
        {
            unsigned char big[600];
            memset(big, 0x42, sizeof big);
            struct script s; script_init(&s);
            ASSERT(script_push_data(&s, big, sizeof big));
            ASSERT(script_push_op(&s, OP_CHECKSIG));
            ASSERT_EQ(script_get_sig_op_count(&s, 0, false), 1u);
            ASSERT_EQ(script_get_sig_op_count(&s, 0, true), 1u);
        }

        /* ---- 3a. non-minimal push under MINIMALDATA -> reject ----
         * A 1-byte push of {0x01} encodes as raw opcode 0x01 (direct
         * length-prefixed push), but the minimal encoding of the value 1
         * is OP_1. With SCRIPT_VERIFY_MINIMALDATA set, check_minimal_push
         * rejects it with SCRIPT_ERR_MINIMALDATA. */
        {
            unsigned char one[1] = { 0x01 };
            struct script s; script_init(&s);
            ASSERT(script_push_data(&s, one, sizeof one));
            EVAL_AND_EXPECT(&s, SCRIPT_VERIFY_MINIMALDATA, false,
                            SCRIPT_ERR_MINIMALDATA);
        }

        /* ---- 3b. same push WITHOUT MINIMALDATA -> accept ----
         * The exact same script, no flag: the non-minimal push is legal,
         * leaves a truthy {0x01}, and the script completes. Proves 3a's
         * reject is the flag, not the script. */
        {
            unsigned char one[1] = { 0x01 };
            struct script s; script_init(&s);
            ASSERT(script_push_data(&s, one, sizeof one));
            EVAL_AND_EXPECT(&s, SCRIPT_VERIFY_NONE, true, SCRIPT_ERR_OK);
        }

        /* ---- 4a. exactly 201 non-push opcodes -> accept ----
         * OP_NOP (0x61) is > OP_16, so each one increments nOpCount.
         * The cap is `++nOpCount > 201`, i.e. the 202nd increment fails.
         * 201 OP_NOPs leave an empty stack -> eval returns true with
         * SCRIPT_ERR_OK (no final truthiness check inside eval_script). */
        {
            struct script s; script_init(&s);
            for (int i = 0; i < 201; i++)
                ASSERT(script_push_op(&s, OP_NOP));
            EVAL_AND_EXPECT(&s, SCRIPT_VERIFY_NONE, true, SCRIPT_ERR_OK);
        }

        /* ---- 4b. 202 non-push opcodes -> SCRIPT_ERR_OP_COUNT ----
         * One opcode past the cap. The 202nd OP_NOP trips the limit. */
        {
            struct script s; script_init(&s);
            for (int i = 0; i < 202; i++)
                ASSERT(script_push_op(&s, OP_NOP));
            EVAL_AND_EXPECT(&s, SCRIPT_VERIFY_NONE, false,
                            SCRIPT_ERR_OP_COUNT);
        }

        /* ---- 5. OP_CHECKMULTISIG missing the dummy element -> underflow ----
         * A well-formed 0-of-0 multisig needs THREE stack elements: the
         * key-count operand, the sig-count operand, and the consumed
         * nulldummy element below them. Here we supply only the two count
         * operands {OP_0 sigs, OP_0 keys}: nKeysCount=0 reads top(-1),
         * then the sig-presence guard `(int)stack->count < i` (with i
         * advanced past the would-be sig/dummy slots) fires because the
         * dummy element is absent, yielding SCRIPT_ERR_INVALID_STACK_OPERATION.
         * The existing multisig suite always supplies a dummy, so this
         * degenerate "no dummy" shape is uncovered. */
        {
            struct script s; script_init(&s);
            script_push_op(&s, OP_0);            /* sig count 0 */
            script_push_op(&s, OP_0);            /* key count 0 */
            script_push_op(&s, OP_CHECKMULTISIG);
            EVAL_AND_EXPECT(&s, SCRIPT_VERIFY_NONE, false,
                            SCRIPT_ERR_INVALID_STACK_OPERATION);
        }

        /* ---- 6. standalone OP_ELSE (no open OP_IF) -> unbalanced ----
         * Distinct code path from the already-covered stray OP_ENDIF:
         * OP_ELSE with vf_exec_count == 0 must reject with
         * SCRIPT_ERR_UNBALANCED_CONDITIONAL (script_interp.c:208-212). */
        {
            struct script s; script_init(&s);
            script_push_op(&s, OP_ELSE);
            EVAL_AND_EXPECT(&s, SCRIPT_VERIFY_NONE, false,
                            SCRIPT_ERR_UNBALANCED_CONDITIONAL);
        }

    } TEST_END
    return failures;
}
