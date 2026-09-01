/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Unit tests for the OP_CHECKMULTISIG branch of the ZClassic script VM
 * (domain/consensus/src/script_interp.c:589-657), the surface left
 * UNTESTED by test_domain_consensus_script_interp.c (which only hits
 * the 0-of-1 structural accept and a non-DER early reject):
 *
 *   - HAPPY PATH       : a 2-of-3 multisig where the synthetic checker
 *                        accepts -> fSuccess pushes vch_true {1}.
 *   - keys-exhaust     : sigs outnumber the keys the checker accepts
 *                        -> fSuccess=false, residual empty, no error.
 *   - SIG_COUNT bound  : nSigsCount > nKeysCount.
 *   - PUBKEY_COUNT     : nKeysCount > 20.
 *   - NULLDUMMY rule   : SCRIPT_VERIFY_NULLDUMMY + non-empty dummy.
 *   - NULLFAIL rule    : SCRIPT_VERIFY_NULLFAIL + non-empty failing sig.
 *
 * IMPLEMENTATION NOTE (the encoding-gate fact): inside the multisig
 * loop, check_transaction_signature_encoding runs BEFORE the checker
 * callback (script_interp.c:620). It validates sig[0..len-2] as raw
 * DER and treats the last byte as a hashtype; a raw DER sig starts
 * with 0x30. So for the checker to be REACHED and ACCEPT, the test sig
 * must be DER-shaped and fake_checker.accept_byte must be 0x30 (the
 * checker keys on sig[0]). Empty sigs (len==0) bypass the gate but can
 * never match accept_byte==0x30, so they take the fail branch.
 *
 * Every case runs through seal_eval, which cross-checks the domain
 * entry point against the lib wrapper byte-for-byte (same bool, same
 * ScriptError, same residual stack) — so each case gets the parity
 * seal for free. fake_checker / fc_init / seal_eval are copied verbatim
 * from test_domain_consensus_script_interp.c. */

#include "test/test_core.h"

#include "domain/consensus/script_interp.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/script_flags.h"

#include <stdio.h>
#include <string.h>

#define MCB_CHECK(name, expr) do { \
    printf("multisig_consensus_branches: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Synthetic sig checker — counts invocations, lets tests control
 * acceptance per (sig, pubkey) prefix without touching ECDSA.
 * Copied verbatim from test_domain_consensus_script_interp.c. */
struct fake_checker {
    struct sig_checker base;
    int sig_calls;
    int lock_calls;
    /* If first byte of sig matches accept_byte, return true. */
    unsigned char accept_byte;
    /* OP_CHECKLOCKTIMEVERIFY result — tests can toggle. */
    bool lock_ok;
};

static bool fc_check_sig(const struct sig_checker *self,
                         const unsigned char *sig, size_t siglen,
                         const unsigned char *pubkey, size_t pklen,
                         const struct script *script_code,
                         uint32_t consensus_branch_id)
{
    (void)pubkey; (void)pklen; (void)script_code; (void)consensus_branch_id;
    struct fake_checker *fc = (struct fake_checker *)(uintptr_t)self;
    fc->sig_calls++;
    return siglen > 0 && sig[0] == fc->accept_byte;
}

static bool fc_check_lock_time(const struct sig_checker *self, int64_t lt)
{
    (void)lt;
    struct fake_checker *fc = (struct fake_checker *)(uintptr_t)self;
    fc->lock_calls++;
    return fc->lock_ok;
}

static void fc_init(struct fake_checker *fc, unsigned char accept_byte,
                    bool lock_ok)
{
    memset(fc, 0, sizeof(*fc));
    fc->base.check_sig         = fc_check_sig;
    fc->base.check_lock_time   = fc_check_lock_time;
    fc->base.verify_signature  = NULL;
    fc->accept_byte = accept_byte;
    fc->lock_ok     = lock_ok;
}

/* Run the same input through both paths and verify byte-exact result.
 * Copied verbatim from test_domain_consensus_script_interp.c. */
static bool seal_eval(const struct script *s, unsigned int flags,
                      const struct sig_checker *checker,
                      uint32_t branch_id,
                      bool expect_ok, int expect_err)
{
    struct script_stack stk_dom __attribute__((cleanup(stack_free))) = {0};
    struct script_stack stk_lib __attribute__((cleanup(stack_free))) = {0};
    if (!stack_init(&stk_dom) || !stack_init(&stk_lib)) return false;

    ScriptError err_dom = SCRIPT_ERR_OK, err_lib = SCRIPT_ERR_OK;
    bool ok_dom = domain_consensus_eval_script(&stk_dom, s, flags, checker,
                                               branch_id, &err_dom);
    bool ok_lib = eval_script(&stk_lib, s, flags, checker, branch_id, &err_lib);

    if (ok_dom != ok_lib) {
        fprintf(stderr, "[seal] divergence ok dom=%d lib=%d ", ok_dom, ok_lib);
        return false;
    }
    if (err_dom != err_lib) {
        fprintf(stderr, "[seal] divergence err dom=%d lib=%d ",
                err_dom, err_lib);
        return false;
    }
    if (stk_dom.count != stk_lib.count) {
        fprintf(stderr, "[seal] divergence stack count dom=%zu lib=%zu ",
                stk_dom.count, stk_lib.count);
        return false;
    }
    for (size_t i = 0; i < stk_dom.count; i++) {
        if (stk_dom.items[i].size != stk_lib.items[i].size) return false;
        if (stk_dom.items[i].size > 0 &&
            memcmp(stk_dom.items[i].data, stk_lib.items[i].data,
                   stk_dom.items[i].size) != 0)
            return false;
    }
    if (ok_dom != expect_ok) {
        fprintf(stderr, "[seal] expected ok=%d got %d (err=%d) ",
                expect_ok, ok_dom, err_dom);
        return false;
    }
    if (!expect_ok && expect_err != -1 && err_dom != (ScriptError)expect_err) {
        fprintf(stderr, "[seal] expected err=%d got %d ",
                expect_err, err_dom);
        return false;
    }
    return true;
}

/* Minimal valid-DER signature buffer: an 8-byte minimal DER body
 * {0x30,0x06,0x02,0x01,0x01,0x02,0x01,0x01} followed by a 1-byte
 * hashtype (0x01). is_valid_signature_encoding accepts this shape,
 * and sig[0]==0x30 so a checker with accept_byte==0x30 accepts it. */
static const unsigned char DER_SIG[9] =
    { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01 };

/* A standard 33-byte compressed-pubkey shape (0x02 prefix). */
static void make_pk(unsigned char pk[33])
{
    memset(pk, 0, 33);
    pk[0] = 0x02;
}

int test_multisig_consensus_branches(void)
{
    int failures = 0;
    unsigned char pk[33];
    make_pk(pk);

    /* ---- HAPPY PATH: 2-of-3 multisig, checker accepts both sigs ----
     * <OP_0 dummy> <sigA> <sigB> OP_2 <pkX> <pkY> <pkZ> OP_3 CHECKMULTISIG
     * accept_byte=0x30 matches the DER sig prefix, so the checker
     * accepts; fSuccess stays true and the op pushes vch_true {1}. */
    {
        struct fake_checker fc;
        fc_init(&fc, 0x30, true);
        struct script s; script_init(&s);
        script_push_op(&s, OP_0);                 /* nulldummy */
        script_push_data(&s, DER_SIG, sizeof(DER_SIG));
        script_push_data(&s, DER_SIG, sizeof(DER_SIG));
        script_push_op(&s, OP_2);                 /* 2 sigs */
        script_push_data(&s, pk, 33);
        script_push_data(&s, pk, 33);
        script_push_data(&s, pk, 33);
        script_push_op(&s, OP_3);                 /* 3 keys */
        script_push_op(&s, OP_CHECKMULTISIG);
        MCB_CHECK("2-of-3 success pushes {1}",
                  seal_eval(&s, 0, &fc.base, 0, true, SCRIPT_ERR_OK));
    }

    /* ---- (a) keys exhaust before sigs match -> fSuccess=false ----
     * 1-of-2 with a single EMPTY sig: the empty sig bypasses the
     * encoding gate but never matches accept_byte, so the checker
     * rejects it against both keys. Keys run out -> fSuccess=false,
     * structurally completes pushing an empty (false) element. ok=true,
     * SCRIPT_ERR_OK, residual {} — and domain==lib. */
    {
        struct fake_checker fc;
        fc_init(&fc, 0x30, true);
        struct script s; script_init(&s);
        script_push_op(&s, OP_0);                 /* nulldummy */
        script_push_op(&s, OP_0);                 /* empty sig */
        script_push_op(&s, OP_1);                 /* 1 sig */
        script_push_data(&s, pk, 33);
        script_push_data(&s, pk, 33);
        script_push_op(&s, OP_2);                 /* 2 keys */
        script_push_op(&s, OP_CHECKMULTISIG);
        MCB_CHECK("keys exhaust -> fSuccess=false, residual false",
                  seal_eval(&s, 0, &fc.base, 0, true, SCRIPT_ERR_OK));
    }

    /* ---- (b) nSigsCount > nKeysCount -> SCRIPT_ERR_SIG_COUNT ----
     * Declare 2 sigs over only 1 key. The SIG_COUNT bound check fires
     * before any sig is read. */
    {
        struct fake_checker fc;
        fc_init(&fc, 0x30, true);
        struct script s; script_init(&s);
        script_push_op(&s, OP_0);                 /* nulldummy */
        script_push_data(&s, DER_SIG, sizeof(DER_SIG));
        script_push_data(&s, DER_SIG, sizeof(DER_SIG));
        script_push_op(&s, OP_2);                 /* 2 sigs */
        script_push_data(&s, pk, 33);
        script_push_op(&s, OP_1);                 /* 1 key  */
        script_push_op(&s, OP_CHECKMULTISIG);
        MCB_CHECK("nSigs>nKeys -> SCRIPT_ERR_SIG_COUNT",
                  seal_eval(&s, 0, &fc.base, 0, false, SCRIPT_ERR_SIG_COUNT));
    }

    /* ---- (c) nKeysCount=21 -> SCRIPT_ERR_PUBKEY_COUNT ----
     * Push the key count 21 (minimal-encoded {0x15}); the bound check
     * (nKeysCount > 20) rejects it before reading any keys/sigs. */
    {
        struct fake_checker fc;
        fc_init(&fc, 0x30, true);
        unsigned char n21[1] = { 21 };
        struct script s; script_init(&s);
        script_push_data(&s, n21, 1);             /* 21 keys */
        script_push_op(&s, OP_CHECKMULTISIG);
        MCB_CHECK("nKeys=21 -> SCRIPT_ERR_PUBKEY_COUNT",
                  seal_eval(&s, 0, &fc.base, 0, false,
                            SCRIPT_ERR_PUBKEY_COUNT));
    }

    /* ---- (d) NULLDUMMY + non-empty dummy -> SCRIPT_ERR_SIG_NULLDUMMY -
     * An otherwise-valid 1-of-1 (checker accepts the DER sig) but the
     * dummy element is a non-empty 1-byte push. With NULLDUMMY set, the
     * non-zero-length dummy is rejected after the sig loop succeeds. */
    {
        struct fake_checker fc;
        fc_init(&fc, 0x30, true);
        unsigned char dummy[1] = { 0x01 };
        struct script s; script_init(&s);
        script_push_data(&s, dummy, 1);           /* NON-empty dummy */
        script_push_data(&s, DER_SIG, sizeof(DER_SIG));
        script_push_op(&s, OP_1);                 /* 1 sig */
        script_push_data(&s, pk, 33);
        script_push_op(&s, OP_1);                 /* 1 key */
        script_push_op(&s, OP_CHECKMULTISIG);
        MCB_CHECK("NULLDUMMY non-empty dummy -> SCRIPT_ERR_SIG_NULLDUMMY",
                  seal_eval(&s, SCRIPT_VERIFY_NULLDUMMY, &fc.base, 0,
                            false, SCRIPT_ERR_SIG_NULLDUMMY));
    }

    /* ---- (e) NULLFAIL + non-empty failing sig -> SIG_NULLFAIL ----
     * 1-of-1 where the checker REJECTS the (DER, non-empty) sig because
     * accept_byte (0xAA) != sig[0] (0x30). The sig still passes the
     * encoding gate, so the checker is reached and returns false ->
     * fSuccess=false. With NULLFAIL set, a non-empty failing sig is a
     * hard error. */
    {
        struct fake_checker fc;
        fc_init(&fc, 0xAA, true);                 /* rejects 0x30 sig */
        struct script s; script_init(&s);
        script_push_op(&s, OP_0);                 /* empty dummy */
        script_push_data(&s, DER_SIG, sizeof(DER_SIG));
        script_push_op(&s, OP_1);                 /* 1 sig */
        script_push_data(&s, pk, 33);
        script_push_op(&s, OP_1);                 /* 1 key */
        script_push_op(&s, OP_CHECKMULTISIG);
        MCB_CHECK("NULLFAIL non-empty failing sig -> SCRIPT_ERR_SIG_NULLFAIL",
                  seal_eval(&s, SCRIPT_VERIFY_NULLFAIL, &fc.base, 0,
                            false, SCRIPT_ERR_SIG_NULLFAIL));
    }

    return failures;
}
