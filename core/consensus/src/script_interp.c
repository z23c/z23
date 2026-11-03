/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure ZClassic script VM. Extracted byte-exactly from
 * core/modules/script/src/interpreter.c (the historic EvalScript / VerifyScript
 * orchestrator). The lib wrapper now forwards `eval_script` and
 * `verify_script` to these domain entry points; impure surfaces
 * (sigcache, ECDSA verifier) live entirely in core/modules/script and are
 * supplied via the `struct sig_checker` callback table.
 *
 * No I/O, no clock, no RNG, no global-state reads. Allocator use is
 * limited to the altstack scratch buffer inside `eval_script` and to
 * the two stacks in `verify_script` (via stack_init in core/modules/script).
 *
 * The stack helper functions (stack_init/stack_free/stack_copy_active)
 * remain in core/modules/script because they call zcl_calloc, which is
 * allocator-side glue rather than consensus logic; they are pure too,
 * but they are also part of the existing public API used by external
 * callers like fuzz_script.c. */

#include "domain/consensus/script_interp.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "core/hash.h"
#include "crypto/ripemd160.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "script/sigencoding.h"

static bool check_minimal_push(const unsigned char *data, size_t len,
                                enum opcodetype opcode)
{
    if (len == 0)
        return opcode == OP_0;
    if (len == 1 && data[0] >= 1 && data[0] <= 16)
        return (int)opcode == (int)OP_1 + ((int)data[0] - 1);
    if (len == 1 && data[0] == 0x81)
        return opcode == OP_1NEGATE;
    if (len <= 75)
        return opcode == (enum opcodetype)len;
    if (len <= 255)
        return opcode == OP_PUSHDATA1;
    if (len <= 65535)
        return opcode == OP_PUSHDATA2;
    return true;
}

static bool sn_serialize_push(struct script_stack *stack,
                               const struct script_num *sn)
{
    unsigned char buf[SCRIPT_NUM_MAX_SIZE];
    size_t len = script_num_serialize(sn, buf, sizeof(buf));
    return stack_push(stack, buf, len);
}

#define SN_FROM_TOP(var, stk, idx, minimal) \
    struct script_num var; \
    if (!script_num_from_bytes(&var, stack_top(stk, idx)->data, \
        stack_top(stk, idx)->size, minimal, SCRIPT_NUM_DEFAULT_MAX_SIZE)) \
        return set_script_error(serror, SCRIPT_ERR_UNKNOWN_ERROR)

#define SN_FROM_TOP_N(var, stk, idx, minimal, maxsz) \
    struct script_num var; \
    if (!script_num_from_bytes(&var, stack_top(stk, idx)->data, \
        stack_top(stk, idx)->size, minimal, maxsz)) \
        return set_script_error(serror, SCRIPT_ERR_UNKNOWN_ERROR)

/* every stack mutation that can overflow MAX_STACK_ITEMS must be
 * propagated as SCRIPT_ERR_STACK_SIZE. Without this, OP_PICK/OP_ROLL and
 * other post-push reads could operate on an inconsistent stack shape. */
#define PUSH_OR_FAIL(stk, data, len) \
    do { \
        if (!stack_push((stk), (data), (len))) \
            return set_script_error(serror, SCRIPT_ERR_STACK_SIZE); \
    } while (0)

#define SN_PUSH_OR_FAIL(stk, sn_ptr) \
    do { \
        if (!sn_serialize_push((stk), (sn_ptr))) \
            return set_script_error(serror, SCRIPT_ERR_STACK_SIZE); \
    } while (0)

#define INSERT_OR_FAIL(stk, idx, item_ptr) \
    do { \
        if (!stack_insert_at((stk), (idx), (item_ptr))) \
            return set_script_error(serror, SCRIPT_ERR_STACK_SIZE); \
    } while (0)

/* Mutable interpreter state shared by the per-opcode handlers. Every handler
 * returns true to continue with the next opcode (the old `break`) or false
 * when it has already recorded the error in *serror (the old `return`). */
struct script_eval_ctx {
    struct script_stack *stack;
    struct script_stack *altstack;
    const struct script *script;
    unsigned int flags;
    const struct sig_checker *checker;
    uint32_t consensus_branch_id;
    ScriptError *serror;
    bool fRequireMinimal;
    bool fExec;
    int nOpCount;
    size_t pc;
    size_t vf_exec_count;
    bool vf_exec[MAX_STACK_ITEMS];
};

typedef bool (*script_eval_op_fn)(struct script_eval_ctx *c,
                                  enum opcodetype opcode);

static const unsigned char vch_true[] = {1};

/* Push the boolean result the way the original inline code did. */
static bool evalop_push_bool(struct script_eval_ctx *c, bool fSuccess)
{
    ScriptError *serror = c->serror;
    PUSH_OR_FAIL(c->stack, fSuccess ? vch_true : NULL, fSuccess ? 1 : 0);
    return true;
}

/* The *VERIFY tail: pop the pushed true, or fail with `code`. */
static bool evalop_verify_tail(struct script_eval_ctx *c, bool fSuccess,
                               ScriptError code)
{
    if (fSuccess)
        stack_pop(c->stack);
    else
        return set_script_error(c->serror, code);
    return true;
}

static bool evalop_push_small_int(struct script_eval_ctx *c,
                                  enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    struct script_num bn = script_num_from_int(
        (int)opcode - (int)(OP_1 - 1));
    SN_PUSH_OR_FAIL(stack, &bn);
    return true;
}

static bool evalop_nop(struct script_eval_ctx *c, enum opcodetype opcode)
{
    (void)c;
    (void)opcode;
    return true;
}

static bool evalop_checklocktimeverify(struct script_eval_ctx *c,
                                       [[maybe_unused]] enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    unsigned int flags = c->flags;
    const struct sig_checker *checker = c->checker;
    if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) {
        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
            return set_script_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
        return true;
    }
    if (stack->count < 1)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    SN_FROM_TOP_N(nLockTime, stack, -1, c->fRequireMinimal, 5);
    if (nLockTime.value < 0)
        return set_script_error(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);
    if (checker && checker->check_lock_time &&
        !checker->check_lock_time(checker, nLockTime.value))
        return set_script_error(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    return true;
}

static bool evalop_upgradable_nop(struct script_eval_ctx *c,
                                  [[maybe_unused]] enum opcodetype opcode)
{
    if (c->flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
        return set_script_error(c->serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
    return true;
}

static bool evalop_if_notif(struct script_eval_ctx *c, enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    bool fValue = false;
    if (c->fExec) {
        if (stack->count < 1)
            return set_script_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
        fValue = cast_to_bool(stack_top(stack, -1));
        if (opcode == OP_NOTIF) fValue = !fValue;
        stack_pop(stack);
    }
    if (c->vf_exec_count >= MAX_STACK_ITEMS)
        return set_script_error(serror, SCRIPT_ERR_STACK_SIZE);
    c->vf_exec[c->vf_exec_count++] = fValue;
    return true;
}

static bool evalop_else(struct script_eval_ctx *c,
                        [[maybe_unused]] enum opcodetype opcode)
{
    if (c->vf_exec_count == 0)
        return set_script_error(c->serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
    c->vf_exec[c->vf_exec_count - 1] = !c->vf_exec[c->vf_exec_count - 1];
    return true;
}

static bool evalop_endif(struct script_eval_ctx *c,
                         [[maybe_unused]] enum opcodetype opcode)
{
    if (c->vf_exec_count == 0)
        return set_script_error(c->serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
    c->vf_exec_count--;
    return true;
}

static bool evalop_verify(struct script_eval_ctx *c,
                          [[maybe_unused]] enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    if (stack->count < 1)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    if (cast_to_bool(stack_top(stack, -1)))
        stack_pop(stack);
    else
        return set_script_error(serror, SCRIPT_ERR_VERIFY);
    return true;
}

static bool evalop_return(struct script_eval_ctx *c,
                          [[maybe_unused]] enum opcodetype opcode)
{
    return set_script_error(c->serror, SCRIPT_ERR_OP_RETURN);
}

static bool evalop_toaltstack(struct script_eval_ctx *c,
                              [[maybe_unused]] enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    if (stack->count < 1)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    PUSH_OR_FAIL(c->altstack, stack_top(stack, -1)->data,
                 stack_top(stack, -1)->size);
    stack_pop(stack);
    return true;
}

static bool evalop_fromaltstack(struct script_eval_ctx *c,
                                [[maybe_unused]] enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    struct script_stack *altstack = c->altstack;
    ScriptError *serror = c->serror;
    if (altstack->count < 1)
        return set_script_error(serror, SCRIPT_ERR_INVALID_ALTSTACK_OPERATION);
    PUSH_OR_FAIL(stack, stack_top(altstack, -1)->data,
                 stack_top(altstack, -1)->size);
    stack_pop(altstack);
    return true;
}

static bool evalop_2drop(struct script_eval_ctx *c,
                         [[maybe_unused]] enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    if (stack->count < 2)
        return set_script_error(c->serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    stack_pop(stack); stack_pop(stack);
    return true;
}

/* OP_2DUP copies the top two items, OP_2OVER the two below them. */
static bool evalop_dup_over_pair(struct script_eval_ctx *c,
                                 enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    int depth = (opcode == OP_2DUP) ? 2 : 4;
    if (stack->count < (size_t)depth)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    struct stack_item v1 = *stack_top(stack, -depth);
    struct stack_item v2 = *stack_top(stack, 1 - depth);
    PUSH_OR_FAIL(stack, v1.data, v1.size);
    PUSH_OR_FAIL(stack, v2.data, v2.size);
    return true;
}

static bool evalop_3dup(struct script_eval_ctx *c,
                        [[maybe_unused]] enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    if (stack->count < 3)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    struct stack_item v1 = *stack_top(stack, -3);
    struct stack_item v2 = *stack_top(stack, -2);
    struct stack_item v3 = *stack_top(stack, -1);
    PUSH_OR_FAIL(stack, v1.data, v1.size);
    PUSH_OR_FAIL(stack, v2.data, v2.size);
    PUSH_OR_FAIL(stack, v3.data, v3.size);
    return true;
}

static bool evalop_2rot(struct script_eval_ctx *c,
                        [[maybe_unused]] enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    if (stack->count < 6)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    struct stack_item v1 = *stack_top(stack, -6);
    struct stack_item v2 = *stack_top(stack, -5);
    stack_erase_range(stack, stack->count - 6, stack->count - 4);
    PUSH_OR_FAIL(stack, v1.data, v1.size);
    PUSH_OR_FAIL(stack, v2.data, v2.size);
    return true;
}

static bool evalop_2swap(struct script_eval_ctx *c,
                         [[maybe_unused]] enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    if (stack->count < 4)
        return set_script_error(c->serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    stack_swap_items(stack_top(stack, -4), stack_top(stack, -2));
    stack_swap_items(stack_top(stack, -3), stack_top(stack, -1));
    return true;
}

static bool evalop_ifdup(struct script_eval_ctx *c,
                         [[maybe_unused]] enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    if (stack->count < 1)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    if (cast_to_bool(stack_top(stack, -1))) {
        struct stack_item v = *stack_top(stack, -1);
        PUSH_OR_FAIL(stack, v.data, v.size);
    }
    return true;
}

static bool evalop_depth(struct script_eval_ctx *c,
                         [[maybe_unused]] enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    struct script_num bn = script_num_from_int((int64_t)stack->count);
    SN_PUSH_OR_FAIL(stack, &bn);
    return true;
}

static bool evalop_drop(struct script_eval_ctx *c,
                        [[maybe_unused]] enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    if (stack->count < 1)
        return set_script_error(c->serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    stack_pop(stack);
    return true;
}

/* OP_DUP copies the top item, OP_OVER the one below it. */
static bool evalop_dup_over(struct script_eval_ctx *c, enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    int depth = (opcode == OP_DUP) ? 1 : 2;
    if (stack->count < (size_t)depth)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    struct stack_item v = *stack_top(stack, -depth);
    PUSH_OR_FAIL(stack, v.data, v.size);
    return true;
}

static bool evalop_nip(struct script_eval_ctx *c,
                       [[maybe_unused]] enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    if (stack->count < 2)
        return set_script_error(c->serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    stack_erase_at(stack, stack->count - 2);
    return true;
}

static bool evalop_pick_roll(struct script_eval_ctx *c, enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    if (stack->count < 2)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    SN_FROM_TOP(bn, stack, -1, c->fRequireMinimal);
    int n = script_num_get_int(&bn);
    stack_pop(stack);
    if (n < 0 || n >= (int)stack->count)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    struct stack_item v = *stack_top(stack, -n - 1);
    if (opcode == OP_ROLL)
        stack_erase_at(stack, stack->count - n - 1);
    PUSH_OR_FAIL(stack, v.data, v.size);
    return true;
}

static bool evalop_rot(struct script_eval_ctx *c,
                       [[maybe_unused]] enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    if (stack->count < 3)
        return set_script_error(c->serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    struct stack_item *third = stack_top(stack, -3);
    struct stack_item *second = stack_top(stack, -2);
    struct stack_item *first = stack_top(stack, -1);
    stack_swap_items(third, second);
    stack_swap_items(second, first);
    return true;
}

static bool evalop_swap(struct script_eval_ctx *c,
                        [[maybe_unused]] enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    if (stack->count < 2)
        return set_script_error(c->serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    stack_swap_items(stack_top(stack, -2), stack_top(stack, -1));
    return true;
}

static bool evalop_tuck(struct script_eval_ctx *c,
                        [[maybe_unused]] enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    if (stack->count < 2)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    struct stack_item v = *stack_top(stack, -1);
    INSERT_OR_FAIL(stack, stack->count - 2, &v);
    return true;
}

static bool evalop_size(struct script_eval_ctx *c,
                        [[maybe_unused]] enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    if (stack->count < 1)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    struct script_num bn = script_num_from_int(
        (int64_t)stack_top(stack, -1)->size);
    SN_PUSH_OR_FAIL(stack, &bn);
    return true;
}

static bool evalop_equal(struct script_eval_ctx *c, enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    if (stack->count < 2)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    struct stack_item *v1 = stack_top(stack, -2);
    struct stack_item *v2 = stack_top(stack, -1);
    bool fEqual = (v1->size == v2->size &&
                   (v1->size == 0 ||
                    memcmp(v1->data, v2->data, v1->size) == 0));
    stack_pop(stack); stack_pop(stack);
    if (!evalop_push_bool(c, fEqual))
        return false;
    if (opcode == OP_EQUALVERIFY)
        return evalop_verify_tail(c, fEqual, SCRIPT_ERR_EQUALVERIFY);
    return true;
}

static bool evalop_unary_arith(struct script_eval_ctx *c,
                               enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    if (stack->count < 1)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    SN_FROM_TOP(bn, stack, -1, c->fRequireMinimal);
    switch (opcode) {
    case OP_1ADD:      bn.value += 1; break;
    case OP_1SUB:      bn.value -= 1; break;
    case OP_NEGATE:    bn.value = -bn.value; break;
    case OP_ABS:       if (bn.value < 0) bn.value = -bn.value; break;
    case OP_NOT:       bn.value = (bn.value == 0); break;
    case OP_0NOTEQUAL: bn.value = (bn.value != 0); break;
    default: break;
    }
    stack_pop(stack);
    SN_PUSH_OR_FAIL(stack, &bn);
    return true;
}

/* Comparison half of the binary arithmetic group. */
static int64_t binary_compare_value(enum opcodetype opcode, int64_t a, int64_t b)
{
    switch (opcode) {
    case OP_NUMEQUAL: case OP_NUMEQUALVERIFY: return (a == b);
    case OP_NUMNOTEQUAL: return (a != b);
    case OP_LESSTHAN: return (a < b);
    case OP_GREATERTHAN: return (a > b);
    case OP_LESSTHANOREQUAL: return (a <= b);
    case OP_GREATERTHANOREQUAL: return (a >= b);
    default: return 0;
    }
}

static int64_t binary_arith_value(enum opcodetype opcode, int64_t a, int64_t b)
{
    switch (opcode) {
    case OP_ADD: return a + b;
    case OP_SUB: return a - b;
    case OP_BOOLAND: return (a != 0 && b != 0);
    case OP_BOOLOR:  return (a != 0 || b != 0);
    case OP_MIN: return (a < b) ? a : b;
    case OP_MAX: return (a > b) ? a : b;
    default: return binary_compare_value(opcode, a, b);
    }
}

static bool evalop_binary_arith(struct script_eval_ctx *c,
                                enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    if (stack->count < 2)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    SN_FROM_TOP(bn1, stack, -2, c->fRequireMinimal);
    SN_FROM_TOP(bn2, stack, -1, c->fRequireMinimal);
    struct script_num bn = script_num_from_int(0);
    bn.value = binary_arith_value(opcode, bn1.value, bn2.value);
    stack_pop(stack); stack_pop(stack);
    SN_PUSH_OR_FAIL(stack, &bn);
    if (opcode == OP_NUMEQUALVERIFY)
        return evalop_verify_tail(c, cast_to_bool(stack_top(stack, -1)),
                                  SCRIPT_ERR_NUMEQUALVERIFY);
    return true;
}

static bool evalop_within(struct script_eval_ctx *c,
                          [[maybe_unused]] enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    if (stack->count < 3)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    SN_FROM_TOP(bn1, stack, -3, c->fRequireMinimal);
    SN_FROM_TOP(bn2, stack, -2, c->fRequireMinimal);
    SN_FROM_TOP(bn3, stack, -1, c->fRequireMinimal);
    bool fValue = (bn2.value <= bn1.value && bn1.value < bn3.value);
    stack_pop(stack); stack_pop(stack); stack_pop(stack);
    return evalop_push_bool(c, fValue);
}

/* Hash `top` with the hash opcode; returns the digest length. */
static size_t evalop_hash_digest(enum opcodetype opcode,
                                 const struct stack_item *top,
                                 unsigned char hash_out[32])
{
    if (opcode == OP_RIPEMD160) {
        struct ripemd160_ctx ctx;
        ripemd160_init(&ctx);
        ripemd160_write(&ctx, top->data, top->size);
        ripemd160_finalize(&ctx, hash_out);
        return 20;
    } else if (opcode == OP_SHA1) {
        struct sha1_ctx ctx;
        sha1_init(&ctx);
        sha1_write(&ctx, top->data, top->size);
        sha1_finalize(&ctx, hash_out);
        return 20;
    } else if (opcode == OP_SHA256) {
        struct sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_write(&ctx, top->data, top->size);
        sha256_finalize(&ctx, hash_out);
        return 32;
    } else if (opcode == OP_HASH160) {
        hash160(top->data, top->size, hash_out);
        return 20;
    }
    hash256(top->data, top->size, hash_out);
    return 32;
}

static bool evalop_hash(struct script_eval_ctx *c, enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    if (stack->count < 1)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    struct stack_item *top = stack_top(stack, -1);
    unsigned char hash_out[32];
    size_t hash_len = evalop_hash_digest(opcode, top, hash_out);
    stack_pop(stack);
    PUSH_OR_FAIL(stack, hash_out, hash_len);
    return true;
}

static bool evalop_checksig(struct script_eval_ctx *c, enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    unsigned int flags = c->flags;
    const struct sig_checker *checker = c->checker;
    if (stack->count < 2)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    struct stack_item *sig_item = stack_top(stack, -2);
    struct stack_item *pk_item = stack_top(stack, -1);
    if (!check_transaction_signature_encoding(
            sig_item->data, sig_item->size, flags, serror) ||
        !check_pubkey_encoding(
            pk_item->data, pk_item->size, flags, serror))
        return false;
    bool fSuccess = false;
    if (checker && checker->check_sig)
        fSuccess = checker->check_sig(checker,
            sig_item->data, sig_item->size,
            pk_item->data, pk_item->size,
            c->script, c->consensus_branch_id);
    if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) &&
        sig_item->size > 0)
        return set_script_error(serror, SCRIPT_ERR_SIG_NULLFAIL);
    stack_pop(stack); stack_pop(stack);
    if (!evalop_push_bool(c, fSuccess))
        return false;
    if (opcode == OP_CHECKSIGVERIFY)
        return evalop_verify_tail(c, fSuccess, SCRIPT_ERR_CHECKSIGVERIFY);
    return true;
}

/* Verify the message-hash signature of OP_CHECKDATASIG; false = not valid. */
static bool evalop_checkdatasig_verify(struct script_eval_ctx *c,
                                       const struct stack_item *sig_item,
                                       const struct stack_item *msg_item,
                                       const struct stack_item *pk_item)
{
    const struct sig_checker *checker = c->checker;
    bool fSuccess = false;
    if (sig_item->size > 0 && checker && checker->verify_signature) {
        unsigned char msg_hash[32];
        struct sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_write(&ctx, msg_item->data, msg_item->size);
        sha256_finalize(&ctx, msg_hash);
        struct uint256 sighash;
        memcpy(sighash.data, msg_hash, 32);
        fSuccess = checker->verify_signature(checker,
            sig_item->data, sig_item->size,
            pk_item->data, pk_item->size, &sighash);
    }
    return fSuccess;
}

static bool evalop_checkdatasig(struct script_eval_ctx *c,
                                enum opcodetype opcode)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    unsigned int flags = c->flags;
    if (stack->count < 3)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    struct stack_item *sig_item = stack_top(stack, -3);
    struct stack_item *msg_item = stack_top(stack, -2);
    struct stack_item *pk_item = stack_top(stack, -1);
    if (!check_data_signature_encoding(
            sig_item->data, sig_item->size, flags, serror) ||
        !check_pubkey_encoding(
            pk_item->data, pk_item->size, flags, serror))
        return false;
    bool fSuccess = evalop_checkdatasig_verify(c, sig_item, msg_item, pk_item);
    if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) &&
        sig_item->size > 0)
        return set_script_error(serror, SCRIPT_ERR_SIG_NULLFAIL);
    stack_pop(stack); stack_pop(stack); stack_pop(stack);
    if (!evalop_push_bool(c, fSuccess))
        return false;
    if (opcode == OP_CHECKDATASIGVERIFY)
        return evalop_verify_tail(c, fSuccess, SCRIPT_ERR_CHECKDATASIGVERIFY);
    return true;
}

/* Stack offsets and counts of an OP_CHECKMULTISIG call. */
struct multisig_layout {
    int i;
    int ikey;
    int ikey2;
    int isig;
    int nKeysCount;
    int nSigsCount;
};

/* Read and validate the key and signature counts; false = error recorded. */
static bool evalop_multisig_layout(struct script_eval_ctx *c,
                                   struct multisig_layout *m)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    m->i = 1;
    if ((int)stack->count < m->i)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    SN_FROM_TOP(bnKeys, stack, -m->i, c->fRequireMinimal);
    m->nKeysCount = script_num_get_int(&bnKeys);
    if (m->nKeysCount < 0 || m->nKeysCount > 20)
        return set_script_error(serror, SCRIPT_ERR_PUBKEY_COUNT);
    c->nOpCount += m->nKeysCount;
    if (c->nOpCount > 201)
        return set_script_error(serror, SCRIPT_ERR_OP_COUNT);
    m->ikey = ++m->i;
    m->ikey2 = m->nKeysCount + 2;
    m->i += m->nKeysCount;
    if ((int)stack->count < m->i)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    SN_FROM_TOP(bnSigs, stack, -m->i, c->fRequireMinimal);
    m->nSigsCount = script_num_get_int(&bnSigs);
    if (m->nSigsCount < 0 || m->nSigsCount > m->nKeysCount)
        return set_script_error(serror, SCRIPT_ERR_SIG_COUNT);
    m->isig = ++m->i;
    m->i += m->nSigsCount;
    if ((int)stack->count < m->i)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    return true;
}

/* Match the signatures against the keys; false = encoding error recorded,
 * otherwise *fSuccess is the multisig result. */
static bool evalop_multisig_match(struct script_eval_ctx *c,
                                  struct multisig_layout *m, bool *fSuccess)
{
    struct script_stack *stack = c->stack;
    const struct sig_checker *checker = c->checker;
    *fSuccess = true;
    while (*fSuccess && m->nSigsCount > 0) {
        struct stack_item *sig_item = stack_top(stack, -m->isig);
        struct stack_item *pk_item = stack_top(stack, -m->ikey);
        if (!check_transaction_signature_encoding(
                sig_item->data, sig_item->size, c->flags, c->serror) ||
            !check_pubkey_encoding(
                pk_item->data, pk_item->size, c->flags, c->serror))
            return false;
        bool fOk = false;
        if (checker && checker->check_sig)
            fOk = checker->check_sig(checker,
                sig_item->data, sig_item->size,
                pk_item->data, pk_item->size,
                c->script, c->consensus_branch_id);
        if (fOk) { m->isig++; m->nSigsCount--; }
        m->ikey++; m->nKeysCount--;
        if (m->nSigsCount > m->nKeysCount) *fSuccess = false;
    }
    return true;
}

/* Clean the arguments off the stack, enforcing NULLFAIL and NULLDUMMY. */
static bool evalop_multisig_cleanup(struct script_eval_ctx *c,
                                    struct multisig_layout *m, bool fSuccess)
{
    struct script_stack *stack = c->stack;
    ScriptError *serror = c->serror;
    unsigned int flags = c->flags;
    while (m->i-- > 1) {
        if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) &&
            !m->ikey2 && stack_top(stack, -1)->size > 0)
            return set_script_error(serror, SCRIPT_ERR_SIG_NULLFAIL);
        if (m->ikey2 > 0) m->ikey2--;
        stack_pop(stack);
    }

    if (stack->count < 1)
        return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    if ((flags & SCRIPT_VERIFY_NULLDUMMY) &&
        stack_top(stack, -1)->size > 0)
        return set_script_error(serror, SCRIPT_ERR_SIG_NULLDUMMY);
    stack_pop(stack);
    return true;
}

static bool evalop_checkmultisig(struct script_eval_ctx *c,
                                 enum opcodetype opcode)
{
    struct multisig_layout m;
    bool fSuccess;
    if (!evalop_multisig_layout(c, &m))
        return false;
    if (!evalop_multisig_match(c, &m, &fSuccess))
        return false;
    if (!evalop_multisig_cleanup(c, &m, fSuccess))
        return false;
    if (!evalop_push_bool(c, fSuccess))
        return false;
    if (opcode == OP_CHECKMULTISIGVERIFY)
        return evalop_verify_tail(c, fSuccess, SCRIPT_ERR_CHECKMULTISIGVERIFY);
    return true;
}

/* Opcode -> handler. A NULL slot is an opcode the interpreter does not run
 * (the old `default:` arm), which fails with SCRIPT_ERR_BAD_OPCODE. */
static const script_eval_op_fn script_eval_op_table[256] = {
    [OP_1NEGATE] = evalop_push_small_int,
    [OP_1] = evalop_push_small_int, [OP_2] = evalop_push_small_int,
    [OP_3] = evalop_push_small_int, [OP_4] = evalop_push_small_int,
    [OP_5] = evalop_push_small_int, [OP_6] = evalop_push_small_int,
    [OP_7] = evalop_push_small_int, [OP_8] = evalop_push_small_int,
    [OP_9] = evalop_push_small_int, [OP_10] = evalop_push_small_int,
    [OP_11] = evalop_push_small_int, [OP_12] = evalop_push_small_int,
    [OP_13] = evalop_push_small_int, [OP_14] = evalop_push_small_int,
    [OP_15] = evalop_push_small_int, [OP_16] = evalop_push_small_int,
    [OP_NOP] = evalop_nop,
    [OP_CHECKLOCKTIMEVERIFY] = evalop_checklocktimeverify,
    [OP_NOP1] = evalop_upgradable_nop, [OP_NOP3] = evalop_upgradable_nop,
    [OP_NOP4] = evalop_upgradable_nop, [OP_NOP5] = evalop_upgradable_nop,
    [OP_NOP6] = evalop_upgradable_nop, [OP_NOP7] = evalop_upgradable_nop,
    [OP_NOP8] = evalop_upgradable_nop, [OP_NOP9] = evalop_upgradable_nop,
    [OP_NOP10] = evalop_upgradable_nop,
    [OP_IF] = evalop_if_notif, [OP_NOTIF] = evalop_if_notif,
    [OP_ELSE] = evalop_else, [OP_ENDIF] = evalop_endif,
    [OP_VERIFY] = evalop_verify, [OP_RETURN] = evalop_return,
    [OP_TOALTSTACK] = evalop_toaltstack,
    [OP_FROMALTSTACK] = evalop_fromaltstack,
    [OP_2DROP] = evalop_2drop, [OP_2DUP] = evalop_dup_over_pair,
    [OP_3DUP] = evalop_3dup, [OP_2OVER] = evalop_dup_over_pair,
    [OP_2ROT] = evalop_2rot, [OP_2SWAP] = evalop_2swap,
    [OP_IFDUP] = evalop_ifdup, [OP_DEPTH] = evalop_depth,
    [OP_DROP] = evalop_drop, [OP_DUP] = evalop_dup_over,
    [OP_NIP] = evalop_nip, [OP_OVER] = evalop_dup_over,
    [OP_PICK] = evalop_pick_roll, [OP_ROLL] = evalop_pick_roll,
    [OP_ROT] = evalop_rot, [OP_SWAP] = evalop_swap,
    [OP_TUCK] = evalop_tuck, [OP_SIZE] = evalop_size,
    [OP_EQUAL] = evalop_equal, [OP_EQUALVERIFY] = evalop_equal,
    [OP_1ADD] = evalop_unary_arith, [OP_1SUB] = evalop_unary_arith,
    [OP_NEGATE] = evalop_unary_arith, [OP_ABS] = evalop_unary_arith,
    [OP_NOT] = evalop_unary_arith, [OP_0NOTEQUAL] = evalop_unary_arith,
    [OP_ADD] = evalop_binary_arith, [OP_SUB] = evalop_binary_arith,
    [OP_BOOLAND] = evalop_binary_arith, [OP_BOOLOR] = evalop_binary_arith,
    [OP_NUMEQUAL] = evalop_binary_arith,
    [OP_NUMEQUALVERIFY] = evalop_binary_arith,
    [OP_NUMNOTEQUAL] = evalop_binary_arith,
    [OP_LESSTHAN] = evalop_binary_arith,
    [OP_GREATERTHAN] = evalop_binary_arith,
    [OP_LESSTHANOREQUAL] = evalop_binary_arith,
    [OP_GREATERTHANOREQUAL] = evalop_binary_arith,
    [OP_MIN] = evalop_binary_arith, [OP_MAX] = evalop_binary_arith,
    [OP_WITHIN] = evalop_within,
    [OP_RIPEMD160] = evalop_hash, [OP_SHA1] = evalop_hash,
    [OP_SHA256] = evalop_hash, [OP_HASH160] = evalop_hash,
    [OP_HASH256] = evalop_hash,
    [OP_CHECKSIG] = evalop_checksig, [OP_CHECKSIGVERIFY] = evalop_checksig,
    [OP_CHECKDATASIG] = evalop_checkdatasig,
    [OP_CHECKDATASIGVERIFY] = evalop_checkdatasig,
    [OP_CHECKMULTISIG] = evalop_checkmultisig,
    [OP_CHECKMULTISIGVERIFY] = evalop_checkmultisig,
};

/* Run the handler for `opcode`; unknown opcodes are SCRIPT_ERR_BAD_OPCODE. */
static bool evalop_dispatch(struct script_eval_ctx *c, enum opcodetype opcode)
{
    script_eval_op_fn fn = NULL;
    if ((unsigned int)opcode < 256)
        fn = script_eval_op_table[(unsigned int)opcode];
    if (!fn)
        return set_script_error(c->serror, SCRIPT_ERR_BAD_OPCODE);
    return fn(c, opcode);
}

/* True when every enclosing IF/ELSE branch is being executed. */
static bool evalop_branch_executing(const struct script_eval_ctx *c)
{
    for (size_t j = 0; j < c->vf_exec_count; j++) {
        if (!c->vf_exec[j])
            return false;
    }
    return true;
}

/* Opcodes that are disabled in every branch, executed or not. */
static bool evalop_is_disabled(enum opcodetype opcode)
{
    static const enum opcodetype disabled[] = {
        OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_INVERT, OP_AND, OP_OR,
        OP_XOR, OP_2MUL, OP_2DIV, OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT,
        OP_RSHIFT, OP_CODESEPARATOR,
    };
    for (size_t k = 0; k < sizeof(disabled) / sizeof(disabled[0]); k++) {
        if (opcode == disabled[k])
            return true;
    }
    return false;
}

/* Push the data operand of a push opcode, enforcing MINIMALDATA. */
static bool evalop_push_data(struct script_eval_ctx *c, enum opcodetype opcode,
                             const unsigned char *push_data, size_t push_len)
{
    ScriptError *serror = c->serror;
    if (c->fRequireMinimal && !check_minimal_push(push_data, push_len, opcode))
        return set_script_error(serror, SCRIPT_ERR_MINIMALDATA);
    PUSH_OR_FAIL(c->stack, push_data, push_len);
    return true;
}

/* Fetch, check and execute the next opcode of the script. */
static bool evalop_step(struct script_eval_ctx *c)
{
    ScriptError *serror = c->serror;
    c->fExec = evalop_branch_executing(c);

    enum opcodetype opcode;
    unsigned char push_data[MAX_SCRIPT_ELEMENT_SIZE];
    size_t push_len = 0;

    if (!script_get_op(c->script, &c->pc, &opcode, push_data, &push_len))
        return set_script_error(serror, SCRIPT_ERR_BAD_OPCODE);
    if (push_len > MAX_SCRIPT_ELEMENT_SIZE)
        return set_script_error(serror, SCRIPT_ERR_PUSH_SIZE);

    if (opcode > OP_16 && ++c->nOpCount > 201)
        return set_script_error(serror, SCRIPT_ERR_OP_COUNT);

    if (evalop_is_disabled(opcode))
        return set_script_error(serror, SCRIPT_ERR_DISABLED_OPCODE);

    if (c->fExec && opcode >= 0 && opcode <= OP_PUSHDATA4) {
        if (!evalop_push_data(c, opcode, push_data, push_len))
            return false;
    } else if (c->fExec || (OP_IF <= opcode && opcode <= OP_ENDIF)) {
        if (!evalop_dispatch(c, opcode))
            return false;
    }

    if (c->stack->count + c->altstack->count > 1000)
        return set_script_error(serror, SCRIPT_ERR_STACK_SIZE);
    return true;
}

bool domain_consensus_eval_script(struct script_stack *stack,
                                  const struct script *script,
                                  unsigned int flags,
                                  const struct sig_checker *checker,
                                  uint32_t consensus_branch_id,
                                  ScriptError *serror)
{
    /* altstack backing buffer on the heap (~520 KB). The cleanup
     * attribute frees it on every return path, including early errors. */
    struct script_stack altstack __attribute__((cleanup(stack_free))) = {0};
    if (!stack_init(&altstack))
        return set_script_error(serror, SCRIPT_ERR_STACK_SIZE);
    if (!stack->items)
        return set_script_error(serror, SCRIPT_ERR_STACK_SIZE);

    set_script_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);

    if (script->size > MAX_SCRIPT_SIZE)
        return set_script_error(serror, SCRIPT_ERR_SCRIPT_SIZE);

    struct script_eval_ctx ctx = {
        .stack = stack,
        .altstack = &altstack,
        .script = script,
        .flags = flags,
        .checker = checker,
        .consensus_branch_id = consensus_branch_id,
        .serror = serror,
        .fRequireMinimal = (flags & SCRIPT_VERIFY_MINIMALDATA) != 0,
    };

    while (ctx.pc < script->size) {
        if (!evalop_step(&ctx))
            return false;
    }

    if (ctx.vf_exec_count != 0)
        return set_script_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);

    return set_script_success(serror);
}

/* True when the stack top is a true script value; SCRIPT_ERR_EVAL_FALSE otherwise. */
static bool script_stack_top_is_true(struct script_stack *stack,
                                     ScriptError *serror)
{
    if (stack->count == 0)
        return set_script_error(serror, SCRIPT_ERR_EVAL_FALSE);
    if (!cast_to_bool(stack_top(stack, -1)))
        return set_script_error(serror, SCRIPT_ERR_EVAL_FALSE);
    return true;
}

/* P2SH redeem-script execution when required, then the clean-stack rule. */
static bool verify_p2sh_redeem_and_cleanstack(struct script_stack *stack,
                                              struct script_stack *stack_copy,
                                              const struct script *script_sig,
                                              const struct script *script_pub_key,
                                              unsigned int flags,
                                              const struct sig_checker *checker,
                                              uint32_t consensus_branch_id,
                                              ScriptError *serror)
{
    if ((flags & SCRIPT_VERIFY_P2SH) &&
        script_is_p2sh(script_pub_key)) {
        if (!script_is_push_only(script_sig))
            return set_script_error(serror, SCRIPT_ERR_SIG_PUSHONLY);
        if (!stack_copy_active(stack, stack_copy))
            return set_script_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
        assert(stack->count > 0);
        struct stack_item *serialized = stack_top(stack, -1);
        struct script pubkey2;
        script_set(&pubkey2, serialized->data, serialized->size);
        stack_pop(stack);
        bool eval_ok = domain_consensus_eval_script(
            stack, &pubkey2, flags, checker, consensus_branch_id, serror);
        if (!eval_ok)
            return eval_ok;
        bool top_true = script_stack_top_is_true(stack, serror);
        if (!top_true)
            return top_true;
    }

    if ((flags & SCRIPT_VERIFY_CLEANSTACK) != 0) {
        assert((flags & SCRIPT_VERIFY_P2SH) != 0);
        if (stack->count != 1)
            return set_script_error(serror, SCRIPT_ERR_CLEANSTACK);
    }

    return set_script_success(serror);
}

bool domain_consensus_verify_script(const struct script *script_sig,
                                    const struct script *script_pub_key,
                                    unsigned int flags,
                                    const struct sig_checker *checker,
                                    uint32_t consensus_branch_id,
                                    ScriptError *serror)
{
    set_script_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);

    if ((flags & SCRIPT_VERIFY_SIGPUSHONLY) != 0 &&
        !script_is_push_only(script_sig))
        return set_script_error(serror, SCRIPT_ERR_SIG_PUSHONLY);

    /* both stacks have their ~520 KB item buffer on the heap.
     * cleanup(stack_free) frees them on every return path. */
    struct script_stack stack __attribute__((cleanup(stack_free))) = {0};
    struct script_stack stack_copy __attribute__((cleanup(stack_free))) = {0};
    if (!stack_init(&stack) || !stack_init(&stack_copy))
        return set_script_error(serror, SCRIPT_ERR_STACK_SIZE);

    if (!domain_consensus_eval_script(&stack, script_sig, flags, checker,
                                       consensus_branch_id, serror))
        return false;

    if (flags & SCRIPT_VERIFY_P2SH) {
        if (!stack_copy_active(&stack_copy, &stack))
            return set_script_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    }

    if (!domain_consensus_eval_script(&stack, script_pub_key, flags, checker,
                                       consensus_branch_id, serror))
        return false;

    bool top_true = script_stack_top_is_true(&stack, serror);
    if (!top_true)
        return false;

    return verify_p2sh_redeem_and_cleanstack(
        &stack, &stack_copy, script_sig, script_pub_key, flags, checker,
        consensus_branch_id, serror);
}
