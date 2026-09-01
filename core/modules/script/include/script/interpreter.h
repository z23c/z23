/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_SCRIPT_INTERPRETER_H
#define ZCL_SCRIPT_INTERPRETER_H

#include "script/script_error.h"
#include "script/script.h"
#include "script/script_flags.h"
#include "script/sighashtype.h"
#include "core/uint256.h"
#include "core/amount.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define MAX_STACK_ITEMS 1000
#define MAX_STACK_ELEMENT_SIZE MAX_SCRIPT_ELEMENT_SIZE

struct stack_item {
    unsigned char data[MAX_STACK_ELEMENT_SIZE];
    size_t size;
};

/* Heap-owned backing buffer for script execution stacks.
 *
 * The array of items (~520 KB at MAX_STACK_ITEMS=1000) is heap-allocated
 * by stack_init() so the interpreter's C stack frame stays small — a
 * nest of OP_IF frames, verify_script's two stacks, or parallel
 * script-check workers can no longer blow the thread stack.
 *
 * Ownership rules:
 *   - stack_init() allocates .items; every success pairs with stack_free()
 *   - stack_free() tolerates all-zero or partially-initialized stacks,
 *     so __attribute__((cleanup(stack_free))) is safe even if init failed
 *   - stack_top/push/pop/etc. fail closed if .items is NULL */
struct script_stack {
    struct stack_item *items;  /* heap-owned, capacity = MAX_STACK_ITEMS */
    size_t count;
};

/* Allocate .items. Returns true on success, false on OOM (items stays NULL).
 * Callers must either pair init with stack_free() or decorate the local
 * with __attribute__((cleanup(stack_free))). */
bool stack_init(struct script_stack *s);

/* Free .items and zero the stack. Safe on all-zero or NULL-items stacks
 * so it works as a cleanup handler without conditional guards. */
void stack_free(struct script_stack *s);

/* Deep-copy active items from src to dst. dst must already be stack_init'd
 * (items non-NULL); returns false on internal inconsistency. Used by
 * verify_script to snapshot/restore around P2SH rebuild. */
bool stack_copy_active(struct script_stack *dst,
                       const struct script_stack *src);

static inline bool stack_push(struct script_stack *s,
                              const unsigned char *data, size_t len)
{
    if (!s->items) return false;
    if (s->count >= MAX_STACK_ITEMS || len > MAX_STACK_ELEMENT_SIZE)
        return false;
    if (len > 0) memcpy(s->items[s->count].data, data, len);
    s->items[s->count].size = len;
    s->count++;
    return true;
}

static inline bool stack_push_empty(struct script_stack *s)
{
    return stack_push(s, NULL, 0);
}

static inline struct stack_item *stack_top(struct script_stack *s, int i)
{
    return &s->items[(int)s->count + i];
}

static inline bool stack_pop(struct script_stack *s)
{
    if (s->count == 0) return false;
    s->count--;
    return true;
}

static inline bool stack_erase_at(struct script_stack *s, size_t idx)
{
    if (!s->items || idx >= s->count) return false;
    for (size_t i = idx; i < s->count - 1; i++)
        s->items[i] = s->items[i + 1];
    s->count--;
    return true;
}

static inline bool stack_erase_range(struct script_stack *s,
                                     size_t from, size_t to)
{
    if (!s->items || from > to || to > s->count) return false;
    size_t n = to - from;
    for (size_t i = from; i < s->count - n; i++)
        s->items[i] = s->items[i + n];
    s->count -= n;
    return true;
}

static inline bool stack_insert_at(struct script_stack *s, size_t idx,
                                   const struct stack_item *item)
{
    if (!s->items || s->count >= MAX_STACK_ITEMS || idx > s->count)
        return false;
    for (size_t i = s->count; i > idx; i--)
        s->items[i] = s->items[i - 1];
    s->items[idx] = *item;
    s->count++;
    return true;
}

static inline void stack_swap_items(struct stack_item *a, struct stack_item *b)
{
    struct stack_item tmp = *a;
    *a = *b;
    *b = tmp;
}

static inline bool cast_to_bool(const struct stack_item *item)
{
    for (size_t i = 0; i < item->size; i++) {
        if (item->data[i] != 0) {
            if (i == item->size - 1 && item->data[i] == 0x80)
                return false;
            return true;
        }
    }
    return false;
}

/* Caller-supplied signature/locktime oracle — the ONLY impure surface of
 * the otherwise pure script VM (see core/modules/script/src/interpreter.c header).
 * The interpreter never verifies a signature or reads a clock itself; it
 * calls back through this table. core/modules/validation typically pairs it with
 * the sigcache + the ECDSA verifier.
 *
 * Each callback may be NULL. When a hook the interpreter needs is NULL,
 * the corresponding check is treated as FAILING, never as passing:
 *   - check_sig NULL    -> OP_CHECKSIG / OP_CHECKMULTISIG see fSuccess=false
 *                          (the signature is treated as invalid, not skipped)
 *   - check_lock_time NULL -> an enabled OP_CHECKLOCKTIMEVERIFY does NOT call
 *                          back and the locktime constraint is not enforced;
 *                          only pass a NULL check_lock_time when CLTV is not a
 *                          concern for the caller
 *   - verify_signature NULL -> OP_CHECKDATASIG(VERIFY) sees fSuccess=false
 * This fail-closed convention is verified in
 * domain/consensus/src/script_interp.c — do not assume a missing hook means
 * "skip the check".
 *
 * check_sig: verify `sig` (DER + 1 trailing hashtype byte) against `pubkey`
 *   over `script_code` (the subscript being executed) for the network
 *   identified by `consensus_branch_id`. Returns true iff valid.
 * check_lock_time: return true iff the transaction's nLockTime/sequence
 *   permits spending at the BIP65 threshold `lock_time` (used by CLTV).
 * verify_signature: raw "message + sig + pubkey" verify against a precomputed
 *   `sighash` (used by OP_CHECKDATASIG, which hashes the message itself).
 * ctx: opaque per-checker state owned by the caller. */
struct sig_checker {
    bool (*check_sig)(const struct sig_checker *self,
                      const unsigned char *sig, size_t siglen,
                      const unsigned char *pubkey, size_t pklen,
                      const struct script *script_code,
                      uint32_t consensus_branch_id);
    bool (*check_lock_time)(const struct sig_checker *self, int64_t lock_time);
    bool (*verify_signature)(const struct sig_checker *self,
                             const unsigned char *sig, size_t siglen,
                             const unsigned char *pubkey, size_t pklen,
                             const struct uint256 *sighash);
    void *ctx;
};

/* Execute one script against `stack` (the OP_* dispatch loop). CONSENSUS
 * surface — must never fork. Forwards to domain_consensus_eval_script
 * (domain/consensus/src/script_interp.c), where the byte-exact behavior is
 * defined.
 *
 * `stack` must already be stack_init'd (.items non-NULL) and carries the
 * running stack across script_sig -> script_pub_key when called by
 * verify_script; eval_script does NOT clear it on entry. The altstack is
 * allocated/freed internally.
 *
 * `flags` is a bitmask of SCRIPT_VERIFY_* (see script/script_flags.h). It
 * only ever ADDS checks: SCRIPT_VERIFY_NONE (0) runs the base consensus
 * rules, and each bit set tightens acceptance. A bit that is CLEAR disables
 * exactly that one rule (e.g. clearing SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
 * makes OP_CLTV a no-op NOP; clearing SCRIPT_VERIFY_MINIMALDATA accepts
 * non-minimal pushes; clearing SCRIPT_VERIFY_NULLFAIL accepts a non-empty
 * signature on a failed checksig). Never relax a flag on the block-validation
 * path to "make a block connect" — that is a consensus split.
 *
 * `consensus_branch_id` selects the network upgrade epoch and is passed
 * verbatim to checker->check_sig (it changes the sighash). `serror` (may be
 * NULL) receives a SCRIPT_ERR_* code; it is reset before evaluation.
 *
 * Returns true iff the script ran to completion without error. true does
 * NOT mean the top stack item is truthy — that final-result test is applied
 * only by verify_script. A few opcodes are always-fail regardless of flags:
 * the disabled opcodes (OP_CAT, OP_SUBSTR, OP_2MUL, OP_LSHIFT,
 * OP_CODESEPARATOR, ...) -> SCRIPT_ERR_DISABLED_OPCODE, executed OP_RETURN
 * -> SCRIPT_ERR_OP_RETURN, >201 non-push opcodes -> SCRIPT_ERR_OP_COUNT,
 * and stack+altstack > 1000 items -> SCRIPT_ERR_STACK_SIZE. */
bool eval_script(struct script_stack *stack,
                 const struct script *script,
                 unsigned int flags,
                 const struct sig_checker *checker,
                 uint32_t consensus_branch_id,
                 ScriptError *serror);

/* Verify that `script_sig` satisfies `script_pub_key` — the per-input
 * consensus entry point. CONSENSUS surface — must never fork. Forwards to
 * domain_consensus_verify_script (domain/consensus/src/script_interp.c).
 *
 * Pipeline (verified against the implementation):
 *   1. If SCRIPT_VERIFY_SIGPUSHONLY is set and script_sig is not push-only,
 *      fail SCRIPT_ERR_SIG_PUSHONLY up front.
 *   2. eval_script(script_sig) into a fresh stack. If SCRIPT_VERIFY_P2SH is
 *      set, snapshot the post-scriptSig stack for the redeem-script step.
 *   3. eval_script(script_pub_key) continuing on the SAME stack.
 *   4. Require a non-empty stack whose top item is truthy
 *      (cast_to_bool), else SCRIPT_ERR_EVAL_FALSE.
 *   5. P2SH (only when SCRIPT_VERIFY_P2SH is set AND script_pub_key is the
 *      23-byte HASH160 template): re-require script_sig push-only, pop the
 *      serialized redeem script from the snapshot, eval it, and again require
 *      a truthy top item.
 *   6. SCRIPT_VERIFY_CLEANSTACK (asserts P2SH is also set): require EXACTLY
 *      one item remains, else SCRIPT_ERR_CLEANSTACK.
 *
 * Clearing SCRIPT_VERIFY_P2SH disables BIP16 redeem-script execution
 * entirely (the P2SH output is then satisfied by the bare HASH160 EQUAL,
 * which is a hard consensus difference). `flags`, `consensus_branch_id`,
 * `checker`, and `serror` carry the same meaning as in eval_script.
 *
 * Returns true iff the input is fully satisfied; on false, `serror` (if
 * non-NULL) holds the first SCRIPT_ERR_* reason. */
bool verify_script(const struct script *script_sig,
                   const struct script *script_pub_key,
                   unsigned int flags,
                   const struct sig_checker *checker,
                   uint32_t consensus_branch_id,
                   ScriptError *serror);

#endif
