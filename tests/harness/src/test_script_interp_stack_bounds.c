/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Pinning tests for domain/consensus/script_interp.c —
 * domain_consensus_eval_script() stack-manipulation opcodes with
 * their exact post-execution shape and their bounds behaviour.
 *
 * These are byte-exact regression seals. They do NOT re-derive the
 * intended semantics from a spec — they assert the precise residual
 * stack that the real evaluator produces today, so any change in
 * ordering, in remove-vs-push sequencing, or in the MAX_STACK_ITEMS
 * overflow boundary will fail the build.
 *
 * Each int test_*(void) entry hosts EXACTLY ONE TEST_CASE/TEST_END
 * pair (the harness macro defines a single _test_next: label per
 * function). The entrypoints are intentionally unregistered — they
 * pin behaviour at compile/inspection time and are wired by a later
 * runner change, never colliding with the existing
 * test_domain_consensus_script_interp() suite.
 *
 * Pins:
 *   1. OP_2ROT   : {1,2,3,4,5,6} -> {3,4,5,6,1,2}, order exact.
 *   2. OP_PICK   : n=0 (top), n=count-1 (bottom), n=count (reject).
 *   3. OP_ROLL   : same indices, remove-after-capture semantics.
 *   4. OP_TUCK   : {A,B} -> {B,A,B}.
 *   5. Overflow  : (MAX_STACK_ITEMS-2) items + OP_2DUP reaches exactly
 *                  MAX_STACK_ITEMS without STACK_SIZE, the next OP_DUP
 *                  fails with SCRIPT_ERR_STACK_SIZE. */

#include "test/test_core.h"

#include "domain/consensus/script_interp.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/script_flags.h"

#include <stdio.h>
#include <string.h>

/* Push the small integer opcode that materialises `n` onto the script.
 * n==0 -> OP_0 (empty array, script_num 0); 1..16 -> OP_1..OP_16
 * (single byte {n}). These are the exact encodings the evaluator's
 * numeric/push paths produce, which keeps stack-item byte assertions
 * deterministic. */
static bool si_push_small(struct script *s, int n)
{
    if (n == 0)
        return script_push_op(s, OP_0);
    if (n >= 1 && n <= 16)
        return script_push_op(s, (enum opcodetype)(OP_1 + (n - 1)));
    return false;
}

/* True iff stack item at absolute index `idx` is exactly the single
 * byte {val}. OP_1..OP_16 push exactly this shape, so a residual stack
 * of small integers can be pinned byte-for-byte. */
static bool si_item_is_byte(const struct script_stack *stk, size_t idx,
                            unsigned char val)
{
    if (idx >= stk->count)
        return false;
    const struct stack_item *it = &stk->items[idx];
    return it->size == 1 && it->data[0] == val;
}

/* PIN 1 — OP_2ROT moves the bottom pair of the top six to the top,
 * preserving their relative order. {1,2,3,4,5,6} -> {3,4,5,6,1,2}. */
int test_script_interp_op2rot_order(void)
{
    int failures = 0;
    TEST_CASE("script_interp: OP_2ROT {1..6} -> {3,4,5,6,1,2}") {
        struct script_stack stk = {0};
        ASSERT(stack_init(&stk));

        struct script s;
        script_init(&s);
        for (int n = 1; n <= 6; n++)
            ASSERT(si_push_small(&s, n));
        ASSERT(script_push_op(&s, OP_2ROT));

        ScriptError err = SCRIPT_ERR_ERROR_COUNT;
        bool ok = domain_consensus_eval_script(&stk, &s, 0, NULL, 0, &err);

        ASSERT(ok);
        ASSERT_EQ(err, SCRIPT_ERR_OK);
        /* Six items in, six items out — 2ROT is a permutation. */
        ASSERT_EQ(stk.count, (size_t)6);
        /* bottom -> top must be exactly 3,4,5,6,1,2. */
        ASSERT(si_item_is_byte(&stk, 0, 3));
        ASSERT(si_item_is_byte(&stk, 1, 4));
        ASSERT(si_item_is_byte(&stk, 2, 5));
        ASSERT(si_item_is_byte(&stk, 3, 6));
        ASSERT(si_item_is_byte(&stk, 4, 1));
        ASSERT(si_item_is_byte(&stk, 5, 2));

        stack_free(&stk);
    } TEST_END
    return failures;
}

/* PIN 2 — OP_PICK with n=0 copies the post-operand top; n=count-1
 * copies the bottom; n==count is out of range and rejects with
 * SCRIPT_ERR_INVALID_STACK_OPERATION. The operand index is taken
 * AFTER the operand itself is popped, so the data stack here is
 * {1,2,3} (count 3) for every sub-case. */
int test_script_interp_oppick_bounds(void)
{
    int failures = 0;
    TEST_CASE("script_interp: OP_PICK n=0 / n=count-1 / n=count") {
        ScriptError err;

        /* n=0 -> copy top of {1,2,3} -> push 3 -> {1,2,3,3}. */
        {
            struct script_stack stk = {0};
            ASSERT(stack_init(&stk));
            struct script s;
            script_init(&s);
            for (int n = 1; n <= 3; n++)
                ASSERT(si_push_small(&s, n));
            ASSERT(si_push_small(&s, 0));       /* operand n=0 */
            ASSERT(script_push_op(&s, OP_PICK));

            err = SCRIPT_ERR_ERROR_COUNT;
            bool ok = domain_consensus_eval_script(&stk, &s, 0, NULL, 0, &err);
            ASSERT(ok);
            ASSERT_EQ(err, SCRIPT_ERR_OK);
            ASSERT_EQ(stk.count, (size_t)4);
            ASSERT(si_item_is_byte(&stk, 0, 1));
            ASSERT(si_item_is_byte(&stk, 1, 2));
            ASSERT(si_item_is_byte(&stk, 2, 3));
            ASSERT(si_item_is_byte(&stk, 3, 3)); /* duplicated top */
            stack_free(&stk);
        }

        /* n=count-1=2 -> copy bottom of {1,2,3} -> push 1 -> {1,2,3,1}. */
        {
            struct script_stack stk = {0};
            ASSERT(stack_init(&stk));
            struct script s;
            script_init(&s);
            for (int n = 1; n <= 3; n++)
                ASSERT(si_push_small(&s, n));
            ASSERT(si_push_small(&s, 2));       /* operand n=count-1 */
            ASSERT(script_push_op(&s, OP_PICK));

            err = SCRIPT_ERR_ERROR_COUNT;
            bool ok = domain_consensus_eval_script(&stk, &s, 0, NULL, 0, &err);
            ASSERT(ok);
            ASSERT_EQ(err, SCRIPT_ERR_OK);
            ASSERT_EQ(stk.count, (size_t)4);
            ASSERT(si_item_is_byte(&stk, 0, 1));
            ASSERT(si_item_is_byte(&stk, 1, 2));
            ASSERT(si_item_is_byte(&stk, 2, 3));
            ASSERT(si_item_is_byte(&stk, 3, 1)); /* duplicated bottom */
            stack_free(&stk);
        }

        /* n=count=3 -> out of range -> reject, stack-shape untouched
         * semantics (eval returns false, precise error code). */
        {
            struct script_stack stk = {0};
            ASSERT(stack_init(&stk));
            struct script s;
            script_init(&s);
            for (int n = 1; n <= 3; n++)
                ASSERT(si_push_small(&s, n));
            ASSERT(si_push_small(&s, 3));       /* operand n==count */
            ASSERT(script_push_op(&s, OP_PICK));

            err = SCRIPT_ERR_ERROR_COUNT;
            bool ok = domain_consensus_eval_script(&stk, &s, 0, NULL, 0, &err);
            ASSERT(!ok);
            ASSERT_EQ(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
            stack_free(&stk);
        }
    } TEST_END
    return failures;
}

/* PIN 3 — OP_ROLL is OP_PICK plus an erase of the source slot taken
 * BEFORE the push (remove-after-capture). n=0 is a no-op permutation
 * of {1,2,3}; n=count-1 rotates the bottom to the top -> {2,3,1}. */
int test_script_interp_oproll_semantics(void)
{
    int failures = 0;
    TEST_CASE("script_interp: OP_ROLL n=0 noop / n=count-1 rotate") {
        ScriptError err;

        /* n=0 -> capture top 3, erase it, push it back -> {1,2,3}. */
        {
            struct script_stack stk = {0};
            ASSERT(stack_init(&stk));
            struct script s;
            script_init(&s);
            for (int n = 1; n <= 3; n++)
                ASSERT(si_push_small(&s, n));
            ASSERT(si_push_small(&s, 0));       /* operand n=0 */
            ASSERT(script_push_op(&s, OP_ROLL));

            err = SCRIPT_ERR_ERROR_COUNT;
            bool ok = domain_consensus_eval_script(&stk, &s, 0, NULL, 0, &err);
            ASSERT(ok);
            ASSERT_EQ(err, SCRIPT_ERR_OK);
            ASSERT_EQ(stk.count, (size_t)3); /* roll removes then pushes */
            ASSERT(si_item_is_byte(&stk, 0, 1));
            ASSERT(si_item_is_byte(&stk, 1, 2));
            ASSERT(si_item_is_byte(&stk, 2, 3));
            stack_free(&stk);
        }

        /* n=count-1=2 -> capture bottom 1, erase index 0, push 1
         * -> {2,3,1}: remove happens before push so 1 leaves the
         * bottom and reappears only at the top. */
        {
            struct script_stack stk = {0};
            ASSERT(stack_init(&stk));
            struct script s;
            script_init(&s);
            for (int n = 1; n <= 3; n++)
                ASSERT(si_push_small(&s, n));
            ASSERT(si_push_small(&s, 2));       /* operand n=count-1 */
            ASSERT(script_push_op(&s, OP_ROLL));

            err = SCRIPT_ERR_ERROR_COUNT;
            bool ok = domain_consensus_eval_script(&stk, &s, 0, NULL, 0, &err);
            ASSERT(ok);
            ASSERT_EQ(err, SCRIPT_ERR_OK);
            ASSERT_EQ(stk.count, (size_t)3);
            ASSERT(si_item_is_byte(&stk, 0, 2));
            ASSERT(si_item_is_byte(&stk, 1, 3));
            ASSERT(si_item_is_byte(&stk, 2, 1)); /* old bottom now top */
            stack_free(&stk);
        }
    } TEST_END
    return failures;
}

/* PIN 4 — OP_TUCK inserts a copy of the top item below the second
 * item: {A,B} -> {B,A,B}. Uses distinct byte values (A=5,B=7) so the
 * inserted slot is unambiguous. */
int test_script_interp_optuck_insert(void)
{
    int failures = 0;
    TEST_CASE("script_interp: OP_TUCK {5,7} -> {7,5,7}") {
        struct script_stack stk = {0};
        ASSERT(stack_init(&stk));

        struct script s;
        script_init(&s);
        ASSERT(si_push_small(&s, 5));   /* A */
        ASSERT(si_push_small(&s, 7));   /* B */
        ASSERT(script_push_op(&s, OP_TUCK));

        ScriptError err = SCRIPT_ERR_ERROR_COUNT;
        bool ok = domain_consensus_eval_script(&stk, &s, 0, NULL, 0, &err);

        ASSERT(ok);
        ASSERT_EQ(err, SCRIPT_ERR_OK);
        ASSERT_EQ(stk.count, (size_t)3); /* two in, three out */
        ASSERT(si_item_is_byte(&stk, 0, 7)); /* B inserted at bottom */
        ASSERT(si_item_is_byte(&stk, 1, 5)); /* original A */
        ASSERT(si_item_is_byte(&stk, 2, 7)); /* original top B */

        stack_free(&stk);
    } TEST_END
    return failures;
}

/* PIN 5 — overflow boundary. Building exactly (MAX_STACK_ITEMS-2)
 * items and applying OP_2DUP reaches MAX_STACK_ITEMS exactly without
 * tripping SCRIPT_ERR_STACK_SIZE; a subsequent OP_DUP — the item that
 * would be number MAX_STACK_ITEMS+1 — fails with STACK_SIZE. The two
 * evals share the same stack, exactly as verify_script chains evals. */
int test_script_interp_overflow_boundary(void)
{
    int failures = 0;
    TEST_CASE("script_interp: 2DUP fills to MAX_STACK_ITEMS, next DUP STACK_SIZE") {
        struct script_stack stk = {0};
        ASSERT(stack_init(&stk));

        /* Phase A: push (MAX_STACK_ITEMS - 2) ones, then OP_2DUP.
         * OP_1 is <= OP_16, so it never increments the 201 op-count
         * cap, and the script stays well under MAX_SCRIPT_SIZE. */
        struct script fill;
        script_init(&fill);
        for (int i = 0; i < MAX_STACK_ITEMS - 2; i++)
            ASSERT(si_push_small(&fill, 1));
        ASSERT(script_push_op(&fill, OP_2DUP));

        ScriptError err = SCRIPT_ERR_ERROR_COUNT;
        bool ok_a = domain_consensus_eval_script(&stk, &fill, 0, NULL, 0, &err);
        ASSERT(ok_a);                                  /* boundary NOT hit */
        ASSERT_EQ(err, SCRIPT_ERR_OK);
        ASSERT_EQ(stk.count, (size_t)MAX_STACK_ITEMS); /* exactly full */

        /* Phase B: one more push (OP_DUP) on the full stack must fail
         * with SCRIPT_ERR_STACK_SIZE — stack_push refuses at capacity
         * and PUSH_OR_FAIL maps that to STACK_SIZE. */
        struct script over;
        script_init(&over);
        ASSERT(script_push_op(&over, OP_DUP));

        err = SCRIPT_ERR_ERROR_COUNT;
        bool ok_b = domain_consensus_eval_script(&stk, &over, 0, NULL, 0, &err);
        ASSERT(!ok_b);
        ASSERT_EQ(err, SCRIPT_ERR_STACK_SIZE);
        /* count is unchanged: the failing push left the stack full. */
        ASSERT_EQ(stk.count, (size_t)MAX_STACK_ITEMS);

        stack_free(&stk);
    } TEST_END
    return failures;
}
