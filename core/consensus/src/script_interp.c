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

bool domain_consensus_eval_script(struct script_stack *stack,
                                  const struct script *script,
                                  unsigned int flags,
                                  const struct sig_checker *checker,
                                  uint32_t consensus_branch_id,
                                  ScriptError *serror)
{
    static const unsigned char vch_true[] = {1};
    bool vf_exec[MAX_STACK_ITEMS];
    size_t vf_exec_count = 0;
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

    int nOpCount = 0;
    bool fRequireMinimal = (flags & SCRIPT_VERIFY_MINIMALDATA) != 0;

    size_t pc = 0;
    while (pc < script->size) {
        bool fExec = true;
        for (size_t j = 0; j < vf_exec_count; j++) {
            if (!vf_exec[j]) { fExec = false; break; }
        }

        enum opcodetype opcode;
        unsigned char push_data[MAX_SCRIPT_ELEMENT_SIZE];
        size_t push_len = 0;

        if (!script_get_op(script, &pc, &opcode, push_data, &push_len))
            return set_script_error(serror, SCRIPT_ERR_BAD_OPCODE);
        if (push_len > MAX_SCRIPT_ELEMENT_SIZE)
            return set_script_error(serror, SCRIPT_ERR_PUSH_SIZE);

        if (opcode > OP_16 && ++nOpCount > 201)
            return set_script_error(serror, SCRIPT_ERR_OP_COUNT);

        if (opcode == OP_CAT || opcode == OP_SUBSTR || opcode == OP_LEFT ||
            opcode == OP_RIGHT || opcode == OP_INVERT || opcode == OP_AND ||
            opcode == OP_OR || opcode == OP_XOR || opcode == OP_2MUL ||
            opcode == OP_2DIV || opcode == OP_MUL || opcode == OP_DIV ||
            opcode == OP_MOD || opcode == OP_LSHIFT || opcode == OP_RSHIFT ||
            opcode == OP_CODESEPARATOR)
            return set_script_error(serror, SCRIPT_ERR_DISABLED_OPCODE);

        if (fExec && opcode >= 0 && opcode <= OP_PUSHDATA4) {
            if (fRequireMinimal && !check_minimal_push(push_data, push_len, opcode))
                return set_script_error(serror, SCRIPT_ERR_MINIMALDATA);
            PUSH_OR_FAIL(stack, push_data, push_len);
        } else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF)) {
            switch (opcode) {

            case OP_1NEGATE:
            case OP_1: case OP_2: case OP_3: case OP_4: case OP_5:
            case OP_6: case OP_7: case OP_8: case OP_9: case OP_10:
            case OP_11: case OP_12: case OP_13: case OP_14: case OP_15:
            case OP_16:
            {
                struct script_num bn = script_num_from_int(
                    (int)opcode - (int)(OP_1 - 1));
                SN_PUSH_OR_FAIL(stack, &bn);
            } break;

            case OP_NOP:
                break;

            case OP_CHECKLOCKTIMEVERIFY:
            {
                if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) {
                    if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                        return set_script_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                    break;
                }
                if (stack->count < 1)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                SN_FROM_TOP_N(nLockTime, stack, -1, fRequireMinimal, 5);
                if (nLockTime.value < 0)
                    return set_script_error(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);
                if (checker && checker->check_lock_time &&
                    !checker->check_lock_time(checker, nLockTime.value))
                    return set_script_error(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
            } break;

            case OP_NOP1: case OP_NOP3: case OP_NOP4: case OP_NOP5:
            case OP_NOP6: case OP_NOP7: case OP_NOP8: case OP_NOP9:
            case OP_NOP10:
                if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                    return set_script_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                break;

            case OP_IF:
            case OP_NOTIF:
            {
                bool fValue = false;
                if (fExec) {
                    if (stack->count < 1)
                        return set_script_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                    fValue = cast_to_bool(stack_top(stack, -1));
                    if (opcode == OP_NOTIF) fValue = !fValue;
                    stack_pop(stack);
                }
                if (vf_exec_count >= MAX_STACK_ITEMS)
                    return set_script_error(serror, SCRIPT_ERR_STACK_SIZE);
                vf_exec[vf_exec_count++] = fValue;
            } break;

            case OP_ELSE:
                if (vf_exec_count == 0)
                    return set_script_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                vf_exec[vf_exec_count - 1] = !vf_exec[vf_exec_count - 1];
                break;

            case OP_ENDIF:
                if (vf_exec_count == 0)
                    return set_script_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                vf_exec_count--;
                break;

            case OP_VERIFY:
            {
                if (stack->count < 1)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                if (cast_to_bool(stack_top(stack, -1)))
                    stack_pop(stack);
                else
                    return set_script_error(serror, SCRIPT_ERR_VERIFY);
            } break;

            case OP_RETURN:
                return set_script_error(serror, SCRIPT_ERR_OP_RETURN);

            case OP_TOALTSTACK:
                if (stack->count < 1)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                PUSH_OR_FAIL(&altstack, stack_top(stack, -1)->data,
                             stack_top(stack, -1)->size);
                stack_pop(stack);
                break;

            case OP_FROMALTSTACK:
                if (altstack.count < 1)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_ALTSTACK_OPERATION);
                PUSH_OR_FAIL(stack, stack_top(&altstack, -1)->data,
                             stack_top(&altstack, -1)->size);
                stack_pop(&altstack);
                break;

            case OP_2DROP:
                if (stack->count < 2)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                stack_pop(stack); stack_pop(stack);
                break;

            case OP_2DUP:
            {
                if (stack->count < 2)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                struct stack_item v1 = *stack_top(stack, -2);
                struct stack_item v2 = *stack_top(stack, -1);
                PUSH_OR_FAIL(stack, v1.data, v1.size);
                PUSH_OR_FAIL(stack, v2.data, v2.size);
            } break;

            case OP_3DUP:
            {
                if (stack->count < 3)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                struct stack_item v1 = *stack_top(stack, -3);
                struct stack_item v2 = *stack_top(stack, -2);
                struct stack_item v3 = *stack_top(stack, -1);
                PUSH_OR_FAIL(stack, v1.data, v1.size);
                PUSH_OR_FAIL(stack, v2.data, v2.size);
                PUSH_OR_FAIL(stack, v3.data, v3.size);
            } break;

            case OP_2OVER:
            {
                if (stack->count < 4)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                struct stack_item v1 = *stack_top(stack, -4);
                struct stack_item v2 = *stack_top(stack, -3);
                PUSH_OR_FAIL(stack, v1.data, v1.size);
                PUSH_OR_FAIL(stack, v2.data, v2.size);
            } break;

            case OP_2ROT:
            {
                if (stack->count < 6)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                struct stack_item v1 = *stack_top(stack, -6);
                struct stack_item v2 = *stack_top(stack, -5);
                stack_erase_range(stack, stack->count - 6, stack->count - 4);
                PUSH_OR_FAIL(stack, v1.data, v1.size);
                PUSH_OR_FAIL(stack, v2.data, v2.size);
            } break;

            case OP_2SWAP:
                if (stack->count < 4)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                stack_swap_items(stack_top(stack, -4), stack_top(stack, -2));
                stack_swap_items(stack_top(stack, -3), stack_top(stack, -1));
                break;

            case OP_IFDUP:
                if (stack->count < 1)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                if (cast_to_bool(stack_top(stack, -1))) {
                    struct stack_item v = *stack_top(stack, -1);
                    PUSH_OR_FAIL(stack, v.data, v.size);
                }
                break;

            case OP_DEPTH:
            {
                struct script_num bn = script_num_from_int((int64_t)stack->count);
                SN_PUSH_OR_FAIL(stack, &bn);
            } break;

            case OP_DROP:
                if (stack->count < 1)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                stack_pop(stack);
                break;

            case OP_DUP:
            {
                if (stack->count < 1)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                struct stack_item v = *stack_top(stack, -1);
                PUSH_OR_FAIL(stack, v.data, v.size);
            } break;

            case OP_NIP:
                if (stack->count < 2)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                stack_erase_at(stack, stack->count - 2);
                break;

            case OP_OVER:
            {
                if (stack->count < 2)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                struct stack_item v = *stack_top(stack, -2);
                PUSH_OR_FAIL(stack, v.data, v.size);
            } break;

            case OP_PICK:
            case OP_ROLL:
            {
                if (stack->count < 2)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                SN_FROM_TOP(bn, stack, -1, fRequireMinimal);
                int n = script_num_get_int(&bn);
                stack_pop(stack);
                if (n < 0 || n >= (int)stack->count)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                struct stack_item v = *stack_top(stack, -n - 1);
                if (opcode == OP_ROLL)
                    stack_erase_at(stack, stack->count - n - 1);
                PUSH_OR_FAIL(stack, v.data, v.size);
            } break;

            case OP_ROT:
                if (stack->count < 3)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                stack_swap_items(stack_top(stack, -3), stack_top(stack, -2));
                stack_swap_items(stack_top(stack, -2), stack_top(stack, -1));
                break;

            case OP_SWAP:
                if (stack->count < 2)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                stack_swap_items(stack_top(stack, -2), stack_top(stack, -1));
                break;

            case OP_TUCK:
            {
                if (stack->count < 2)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                struct stack_item v = *stack_top(stack, -1);
                INSERT_OR_FAIL(stack, stack->count - 2, &v);
            } break;

            case OP_SIZE:
            {
                if (stack->count < 1)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                struct script_num bn = script_num_from_int(
                    (int64_t)stack_top(stack, -1)->size);
                SN_PUSH_OR_FAIL(stack, &bn);
            } break;

            case OP_EQUAL:
            case OP_EQUALVERIFY:
            {
                if (stack->count < 2)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                struct stack_item *v1 = stack_top(stack, -2);
                struct stack_item *v2 = stack_top(stack, -1);
                bool fEqual = (v1->size == v2->size &&
                               (v1->size == 0 ||
                                memcmp(v1->data, v2->data, v1->size) == 0));
                stack_pop(stack); stack_pop(stack);
                PUSH_OR_FAIL(stack, fEqual ? vch_true : NULL,
                             fEqual ? 1 : 0);
                if (opcode == OP_EQUALVERIFY) {
                    if (fEqual) stack_pop(stack);
                    else return set_script_error(serror, SCRIPT_ERR_EQUALVERIFY);
                }
            } break;

            case OP_1ADD: case OP_1SUB: case OP_NEGATE: case OP_ABS:
            case OP_NOT: case OP_0NOTEQUAL:
            {
                if (stack->count < 1)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                SN_FROM_TOP(bn, stack, -1, fRequireMinimal);
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
            } break;

            case OP_ADD: case OP_SUB: case OP_BOOLAND: case OP_BOOLOR:
            case OP_NUMEQUAL: case OP_NUMEQUALVERIFY: case OP_NUMNOTEQUAL:
            case OP_LESSTHAN: case OP_GREATERTHAN:
            case OP_LESSTHANOREQUAL: case OP_GREATERTHANOREQUAL:
            case OP_MIN: case OP_MAX:
            {
                if (stack->count < 2)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                SN_FROM_TOP(bn1, stack, -2, fRequireMinimal);
                SN_FROM_TOP(bn2, stack, -1, fRequireMinimal);
                struct script_num bn = script_num_from_int(0);
                switch (opcode) {
                case OP_ADD: bn.value = bn1.value + bn2.value; break;
                case OP_SUB: bn.value = bn1.value - bn2.value; break;
                case OP_BOOLAND: bn.value = (bn1.value != 0 && bn2.value != 0); break;
                case OP_BOOLOR:  bn.value = (bn1.value != 0 || bn2.value != 0); break;
                case OP_NUMEQUAL: case OP_NUMEQUALVERIFY:
                    bn.value = (bn1.value == bn2.value); break;
                case OP_NUMNOTEQUAL: bn.value = (bn1.value != bn2.value); break;
                case OP_LESSTHAN: bn.value = (bn1.value < bn2.value); break;
                case OP_GREATERTHAN: bn.value = (bn1.value > bn2.value); break;
                case OP_LESSTHANOREQUAL: bn.value = (bn1.value <= bn2.value); break;
                case OP_GREATERTHANOREQUAL: bn.value = (bn1.value >= bn2.value); break;
                case OP_MIN: bn.value = (bn1.value < bn2.value) ? bn1.value : bn2.value; break;
                case OP_MAX: bn.value = (bn1.value > bn2.value) ? bn1.value : bn2.value; break;
                default: break;
                }
                stack_pop(stack); stack_pop(stack);
                SN_PUSH_OR_FAIL(stack, &bn);
                if (opcode == OP_NUMEQUALVERIFY) {
                    if (cast_to_bool(stack_top(stack, -1)))
                        stack_pop(stack);
                    else
                        return set_script_error(serror, SCRIPT_ERR_NUMEQUALVERIFY);
                }
            } break;

            case OP_WITHIN:
            {
                if (stack->count < 3)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                SN_FROM_TOP(bn1, stack, -3, fRequireMinimal);
                SN_FROM_TOP(bn2, stack, -2, fRequireMinimal);
                SN_FROM_TOP(bn3, stack, -1, fRequireMinimal);
                bool fValue = (bn2.value <= bn1.value && bn1.value < bn3.value);
                stack_pop(stack); stack_pop(stack); stack_pop(stack);
                PUSH_OR_FAIL(stack, fValue ? vch_true : NULL, fValue ? 1 : 0);
            } break;

            case OP_RIPEMD160:
            case OP_SHA1:
            case OP_SHA256:
            case OP_HASH160:
            case OP_HASH256:
            {
                if (stack->count < 1)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                struct stack_item *top = stack_top(stack, -1);
                unsigned char hash_out[32];
                size_t hash_len;
                if (opcode == OP_RIPEMD160) {
                    struct ripemd160_ctx ctx;
                    ripemd160_init(&ctx);
                    ripemd160_write(&ctx, top->data, top->size);
                    ripemd160_finalize(&ctx, hash_out);
                    hash_len = 20;
                } else if (opcode == OP_SHA1) {
                    struct sha1_ctx ctx;
                    sha1_init(&ctx);
                    sha1_write(&ctx, top->data, top->size);
                    sha1_finalize(&ctx, hash_out);
                    hash_len = 20;
                } else if (opcode == OP_SHA256) {
                    struct sha256_ctx ctx;
                    sha256_init(&ctx);
                    sha256_write(&ctx, top->data, top->size);
                    sha256_finalize(&ctx, hash_out);
                    hash_len = 32;
                } else if (opcode == OP_HASH160) {
                    hash160(top->data, top->size, hash_out);
                    hash_len = 20;
                } else {
                    hash256(top->data, top->size, hash_out);
                    hash_len = 32;
                }
                stack_pop(stack);
                PUSH_OR_FAIL(stack, hash_out, hash_len);
            } break;

            case OP_CHECKSIG:
            case OP_CHECKSIGVERIFY:
            {
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
                        script, consensus_branch_id);
                if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) &&
                    sig_item->size > 0)
                    return set_script_error(serror, SCRIPT_ERR_SIG_NULLFAIL);
                stack_pop(stack); stack_pop(stack);
                PUSH_OR_FAIL(stack, fSuccess ? vch_true : NULL,
                             fSuccess ? 1 : 0);
                if (opcode == OP_CHECKSIGVERIFY) {
                    if (fSuccess) stack_pop(stack);
                    else return set_script_error(serror, SCRIPT_ERR_CHECKSIGVERIFY);
                }
            } break;

            case OP_CHECKDATASIG:
            case OP_CHECKDATASIGVERIFY:
            {
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
                if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) &&
                    sig_item->size > 0)
                    return set_script_error(serror, SCRIPT_ERR_SIG_NULLFAIL);
                stack_pop(stack); stack_pop(stack); stack_pop(stack);
                PUSH_OR_FAIL(stack, fSuccess ? vch_true : NULL,
                             fSuccess ? 1 : 0);
                if (opcode == OP_CHECKDATASIGVERIFY) {
                    if (fSuccess) stack_pop(stack);
                    else return set_script_error(serror, SCRIPT_ERR_CHECKDATASIGVERIFY);
                }
            } break;

            case OP_CHECKMULTISIG:
            case OP_CHECKMULTISIGVERIFY:
            {
                int i = 1;
                if ((int)stack->count < i)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                SN_FROM_TOP(bnKeys, stack, -i, fRequireMinimal);
                int nKeysCount = script_num_get_int(&bnKeys);
                if (nKeysCount < 0 || nKeysCount > 20)
                    return set_script_error(serror, SCRIPT_ERR_PUBKEY_COUNT);
                nOpCount += nKeysCount;
                if (nOpCount > 201)
                    return set_script_error(serror, SCRIPT_ERR_OP_COUNT);
                int ikey = ++i;
                int ikey2 = nKeysCount + 2;
                i += nKeysCount;
                if ((int)stack->count < i)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                SN_FROM_TOP(bnSigs, stack, -i, fRequireMinimal);
                int nSigsCount = script_num_get_int(&bnSigs);
                if (nSigsCount < 0 || nSigsCount > nKeysCount)
                    return set_script_error(serror, SCRIPT_ERR_SIG_COUNT);
                int isig = ++i;
                i += nSigsCount;
                if ((int)stack->count < i)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                bool fSuccess = true;
                while (fSuccess && nSigsCount > 0) {
                    struct stack_item *sig_item = stack_top(stack, -isig);
                    struct stack_item *pk_item = stack_top(stack, -ikey);
                    if (!check_transaction_signature_encoding(
                            sig_item->data, sig_item->size, flags, serror) ||
                        !check_pubkey_encoding(
                            pk_item->data, pk_item->size, flags, serror))
                        return false;
                    bool fOk = false;
                    if (checker && checker->check_sig)
                        fOk = checker->check_sig(checker,
                            sig_item->data, sig_item->size,
                            pk_item->data, pk_item->size,
                            script, consensus_branch_id);
                    if (fOk) { isig++; nSigsCount--; }
                    ikey++; nKeysCount--;
                    if (nSigsCount > nKeysCount) fSuccess = false;
                }

                while (i-- > 1) {
                    if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) &&
                        !ikey2 && stack_top(stack, -1)->size > 0)
                        return set_script_error(serror, SCRIPT_ERR_SIG_NULLFAIL);
                    if (ikey2 > 0) ikey2--;
                    stack_pop(stack);
                }

                if (stack->count < 1)
                    return set_script_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                if ((flags & SCRIPT_VERIFY_NULLDUMMY) &&
                    stack_top(stack, -1)->size > 0)
                    return set_script_error(serror, SCRIPT_ERR_SIG_NULLDUMMY);
                stack_pop(stack);

                PUSH_OR_FAIL(stack, fSuccess ? vch_true : NULL,
                             fSuccess ? 1 : 0);
                if (opcode == OP_CHECKMULTISIGVERIFY) {
                    if (fSuccess) stack_pop(stack);
                    else return set_script_error(serror, SCRIPT_ERR_CHECKMULTISIGVERIFY);
                }
            } break;

            default:
                return set_script_error(serror, SCRIPT_ERR_BAD_OPCODE);
            }
        }

        if (stack->count + altstack.count > 1000)
            return set_script_error(serror, SCRIPT_ERR_STACK_SIZE);
    }

    if (vf_exec_count != 0)
        return set_script_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);

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

    if (stack.count == 0)
        return set_script_error(serror, SCRIPT_ERR_EVAL_FALSE);
    if (!cast_to_bool(stack_top(&stack, -1)))
        return set_script_error(serror, SCRIPT_ERR_EVAL_FALSE);

    if ((flags & SCRIPT_VERIFY_P2SH) &&
        script_is_p2sh(script_pub_key)) {
        if (!script_is_push_only(script_sig))
            return set_script_error(serror, SCRIPT_ERR_SIG_PUSHONLY);
        if (!stack_copy_active(&stack, &stack_copy))
            return set_script_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
        assert(stack.count > 0);
        struct stack_item *serialized = stack_top(&stack, -1);
        struct script pubkey2;
        script_set(&pubkey2, serialized->data, serialized->size);
        stack_pop(&stack);
        if (!domain_consensus_eval_script(&stack, &pubkey2, flags, checker,
                                           consensus_branch_id, serror))
            return false;
        if (stack.count == 0)
            return set_script_error(serror, SCRIPT_ERR_EVAL_FALSE);
        if (!cast_to_bool(stack_top(&stack, -1)))
            return set_script_error(serror, SCRIPT_ERR_EVAL_FALSE);
    }

    if ((flags & SCRIPT_VERIFY_CLEANSTACK) != 0) {
        assert((flags & SCRIPT_VERIFY_P2SH) != 0);
        if (stack.count != 1)
            return set_script_error(serror, SCRIPT_ERR_CLEANSTACK);
    }

    return set_script_success(serror);
}
