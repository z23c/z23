/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Regression test for domain_consensus_eval_script() altstack <-> conditional
 * interaction (domain/consensus/src/script_interp.c).
 *
 * PIN: a value moved onto the altstack with OP_TOALTSTACK *inside* a taken
 * OP_IF branch MUST survive the surrounding conditional and be recoverable
 * byte-exactly with OP_FROMALTSTACK AFTER the matching OP_ENDIF.
 *
 * This is load-bearing because the altstack is a SINGLE buffer that lives
 * across the whole eval_script() invocation (script_interp.c:106) — it is NOT
 * scoped per OP_IF frame. The conditional machinery only tracks vf_exec[]
 * (the taken/not-taken flag stack at script_interp.c:102-103); OP_ENDIF merely
 * decrements vf_exec_count (script_interp.c:214-218) and does nothing to the
 * altstack. OP_TOALTSTACK pops the main stack and pushes the altstack
 * (script_interp.c:233-239); OP_FROMALTSTACK does the reverse
 * (script_interp.c:241-247). So a regression that reset/cleared the altstack
 * on OP_ENDIF, or that scoped the altstack to the IF body, would make
 * OP_FROMALTSTACK after the conditional either fail with
 * SCRIPT_ERR_INVALID_ALTSTACK_OPERATION or recover the wrong bytes.
 *
 * The assertions are deliberately non-vacuous:
 *   - taken branch: the recovered main-stack item is asserted byte-exact
 *     against the 4-byte sentinel that was pushed, the main stack count is
 *     pinned, and the call returns true with SCRIPT_ERR_OK.
 *   - control (not-taken branch): the SAME script shape with a false
 *     condition must leave the altstack EMPTY, so the trailing
 *     OP_FROMALTSTACK fails with SCRIPT_ERR_INVALID_ALTSTACK_OPERATION.
 *     This proves the taken-branch success is real (the move only happened
 *     because the branch actually executed), not an artifact of the opcode
 *     unconditionally touching the altstack.
 */

#include "test/test_core.h"

#include "domain/consensus/script_interp.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/script_flags.h"

#include <stdint.h>
#include <string.h>

int test_script_interp_altstack_conditional(void)
{
    int failures = 0;
    TEST_CASE("OP_TOALTSTACK inside a taken OP_IF survives OP_ENDIF and "
              "OP_FROMALTSTACK recovers it byte-exactly; not-taken branch "
              "leaves the altstack empty") {
        /* 4-byte sentinel chosen so it is NOT a minimal/small-int push and so
         * a one-off byte corruption is visible. */
        static const unsigned char SENTINEL[4] = { 0xDE, 0xAD, 0xBE, 0xEF };

        /* ---- taken-branch script ----
         * push SENTINEL ; OP_1 (truthy) ; OP_IF ; OP_TOALTSTACK ; OP_ENDIF ;
         * OP_FROMALTSTACK
         *
         * After execution the main stack must hold exactly one item == SENTINEL
         * (moved out to the altstack inside the branch, then moved back after
         * the conditional). */
        struct script taken;
        script_init(&taken);
        ASSERT(script_push_data(&taken, SENTINEL, sizeof SENTINEL));
        ASSERT(script_push_op(&taken, OP_1));   /* condition: true */
        ASSERT(script_push_op(&taken, OP_IF));
        ASSERT(script_push_op(&taken, OP_TOALTSTACK));
        ASSERT(script_push_op(&taken, OP_ENDIF));
        ASSERT(script_push_op(&taken, OP_FROMALTSTACK));

        struct script_stack stack __attribute__((cleanup(stack_free))) = {0};
        ASSERT(stack_init(&stack));

        ScriptError serr = (ScriptError)-1;
        bool ok = domain_consensus_eval_script(&stack, &taken,
                                               SCRIPT_VERIFY_NONE, NULL,
                                               0, &serr);

        /* The conditional must NOT have wedged the altstack, and the value must
         * have round-tripped. */
        ASSERT(ok);
        ASSERT_EQ(serr, SCRIPT_ERR_OK);
        ASSERT_EQ(stack.count, (size_t)1);

        struct stack_item *top = stack_top(&stack, -1);
        ASSERT_EQ(top->size, sizeof SENTINEL);
        /* byte-exact: a corruption-on-move regression fails here */
        ASSERT(memcmp(top->data, SENTINEL, sizeof SENTINEL) == 0);

        /* ---- control: same shape, NOT-taken branch ----
         * push SENTINEL ; OP_0 (falsy) ; OP_IF ; OP_TOALTSTACK ; OP_ENDIF ;
         * OP_FROMALTSTACK
         *
         * Because the IF body does not execute, nothing is moved to the
         * altstack, so the trailing OP_FROMALTSTACK must fail with
         * SCRIPT_ERR_INVALID_ALTSTACK_OPERATION (script_interp.c:242-243). This
         * is the non-vacuous half: it proves the taken-branch success above is
         * a real consequence of the branch executing, not of OP_TOALTSTACK /
         * OP_FROMALTSTACK touching the altstack unconditionally. */
        struct script not_taken;
        script_init(&not_taken);
        ASSERT(script_push_data(&not_taken, SENTINEL, sizeof SENTINEL));
        ASSERT(script_push_op(&not_taken, OP_0));   /* condition: false */
        ASSERT(script_push_op(&not_taken, OP_IF));
        ASSERT(script_push_op(&not_taken, OP_TOALTSTACK));
        ASSERT(script_push_op(&not_taken, OP_ENDIF));
        ASSERT(script_push_op(&not_taken, OP_FROMALTSTACK));

        struct script_stack stack2 __attribute__((cleanup(stack_free))) = {0};
        ASSERT(stack_init(&stack2));

        ScriptError serr2 = (ScriptError)-1;
        bool ok2 = domain_consensus_eval_script(&stack2, &not_taken,
                                                SCRIPT_VERIFY_NONE, NULL,
                                                0, &serr2);

        ASSERT(!ok2);
        ASSERT_EQ(serr2, SCRIPT_ERR_INVALID_ALTSTACK_OPERATION);
    } TEST_END
    return failures;
}
