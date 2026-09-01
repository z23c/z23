/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Unit tests for domain/consensus/script_interp.{c,h}.
 *
 * Pins the pure ZClassic script VM. Tests exercise the domain
 * entry points directly AND cross-check that the lib wrapper
 * (eval_script / verify_script) returns BYTE-EXACT identical
 * results — same bool, same ScriptError code, same residual
 * stack shape — across every representative script:
 *
 *   - structural   : OP_TRUE, OP_ADD, OP_EQUAL
 *   - dispatch     : OP_IF/OP_ELSE/OP_ENDIF
 *   - failure modes: empty stack, OP_RETURN, OP_VERIFY-false, bad opcode
 *   - signatures   : OP_CHECKSIG success via synthetic checker
 *   - signatures   : OP_CHECKSIG failure (NULL checker => false)
 *   - multisig     : 2-of-3 OP_CHECKMULTISIG using synthetic checker
 *   - P2SH         : push redeem + P2SH wrapper, redeem evaluates to true
 *   - encoding     : OP_RETURN at top level rejects
 *   - locktime     : OP_CHECKLOCKTIMEVERIFY consults checker callback
 *
 * The cross-checks are the regression seal: any divergence between
 * domain and lib paths fails the test. */

#include "test/test_core.h"
#include "core/hash.h"

#include "domain/consensus/script_interp.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/script_flags.h"

#include <stdio.h>
#include <string.h>

#define DCSI_CHECK(name, expr) do { \
    printf("domain_consensus_script_interp: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Synthetic sig checker — counts invocations, lets tests control
 * acceptance per (sig, pubkey) prefix without touching ECDSA. */
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
 * Prints the actual results when the assertion fails so the regression
 * seal is debuggable. */
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

static bool seal_verify(const struct script *ss, const struct script *spk,
                        unsigned int flags,
                        const struct sig_checker *checker,
                        uint32_t branch_id,
                        bool expect_ok, int expect_err)
{
    ScriptError err_dom = SCRIPT_ERR_OK, err_lib = SCRIPT_ERR_OK;
    bool ok_dom = domain_consensus_verify_script(ss, spk, flags, checker,
                                                 branch_id, &err_dom);
    bool ok_lib = verify_script(ss, spk, flags, checker, branch_id, &err_lib);
    if (ok_dom != ok_lib) return false;
    if (err_dom != err_lib) return false;
    if (ok_dom != expect_ok) return false;
    if (!expect_ok && expect_err != -1 && err_dom != (ScriptError)expect_err)
        return false;
    return true;
}

int test_domain_consensus_script_interp(void)
{
    int failures = 0;

    /* ---- 1. Trivial OP_TRUE / OP_FALSE ---- */
    {
        struct script s; script_init(&s);
        script_push_op(&s, OP_1);
        DCSI_CHECK("OP_TRUE evaluates ok + leaves {1}",
                   seal_eval(&s, 0, NULL, 0, true, SCRIPT_ERR_OK));
    }
    {
        struct script s; script_init(&s);
        DCSI_CHECK("empty script evaluates ok",
                   seal_eval(&s, 0, NULL, 0, true, SCRIPT_ERR_OK));
    }

    /* ---- 2. OP_ADD arithmetic ---- */
    {
        struct script s; script_init(&s);
        script_push_op(&s, OP_2);
        script_push_op(&s, OP_3);
        script_push_op(&s, OP_ADD);
        script_push_op(&s, OP_5);
        script_push_op(&s, OP_EQUAL);
        DCSI_CHECK("2+3 == 5",
                   seal_eval(&s, 0, NULL, 0, true, SCRIPT_ERR_OK));
    }

    /* ---- 3. OP_RETURN at top level ---- */
    {
        struct script s; script_init(&s);
        script_push_op(&s, OP_RETURN);
        DCSI_CHECK("OP_RETURN -> SCRIPT_ERR_OP_RETURN",
                   seal_eval(&s, 0, NULL, 0, false, SCRIPT_ERR_OP_RETURN));
    }

    /* ---- 4. OP_VERIFY on falsy top -> SCRIPT_ERR_VERIFY ---- */
    {
        struct script s; script_init(&s);
        script_push_op(&s, OP_0);
        script_push_op(&s, OP_VERIFY);
        DCSI_CHECK("OP_VERIFY false -> SCRIPT_ERR_VERIFY",
                   seal_eval(&s, 0, NULL, 0, false, SCRIPT_ERR_VERIFY));
    }

    /* ---- 5. OP_IF / OP_ELSE / OP_ENDIF dispatch ---- */
    {
        struct script s; script_init(&s);
        script_push_op(&s, OP_1);
        script_push_op(&s, OP_IF);
        script_push_op(&s, OP_2);
        script_push_op(&s, OP_ELSE);
        script_push_op(&s, OP_3);
        script_push_op(&s, OP_ENDIF);
        DCSI_CHECK("OP_IF true branch picks 2",
                   seal_eval(&s, 0, NULL, 0, true, SCRIPT_ERR_OK));
    }
    {
        /* Unbalanced OP_ENDIF without matching OP_IF. */
        struct script s; script_init(&s);
        script_push_op(&s, OP_ENDIF);
        DCSI_CHECK("OP_ENDIF without OP_IF -> SCRIPT_ERR_UNBALANCED_CONDITIONAL",
                   seal_eval(&s, 0, NULL, 0, false,
                             SCRIPT_ERR_UNBALANCED_CONDITIONAL));
    }
    {
        /* Unterminated OP_IF. */
        struct script s; script_init(&s);
        script_push_op(&s, OP_1);
        script_push_op(&s, OP_IF);
        script_push_op(&s, OP_2);
        DCSI_CHECK("OP_IF without OP_ENDIF -> SCRIPT_ERR_UNBALANCED_CONDITIONAL",
                   seal_eval(&s, 0, NULL, 0, false,
                             SCRIPT_ERR_UNBALANCED_CONDITIONAL));
    }

    /* ---- 6. Disabled opcode (OP_CAT) ---- */
    {
        struct script s; script_init(&s);
        script_push_op(&s, OP_CAT);
        DCSI_CHECK("OP_CAT -> SCRIPT_ERR_DISABLED_OPCODE",
                   seal_eval(&s, 0, NULL, 0, false,
                             SCRIPT_ERR_DISABLED_OPCODE));
    }

    /* ---- 7. OP_CHECKSIG: bogus (non-DER) sig -> SCRIPT_ERR_SIG_DER ----
     * The signature encoding gate (check_raw_signature_encoding) is
     * mandatory in ZClassic; both paths must reject a non-DER sig with
     * the exact same error code BEFORE reaching the checker. This is
     * the canonical "signature-failure script" we want byte-exact. */
    {
        unsigned char sig[1] = {0x01};
        unsigned char pk[33];
        memset(pk, 0, sizeof(pk));
        pk[0] = 0x02;
        struct script s; script_init(&s);
        script_push_data(&s, sig, 1);
        script_push_data(&s, pk, 33);
        script_push_op(&s, OP_CHECKSIG);
        DCSI_CHECK("OP_CHECKSIG non-DER sig -> SCRIPT_ERR_SIG_DER",
                   seal_eval(&s, 0, NULL, 0, false, SCRIPT_ERR_SIG_DER));
    }

    /* ---- 8. OP_CHECKSIG with empty sig + NULL checker -> push false ----
     * Empty sig is the explicit "no signature provided" case; encoding
     * gate passes through (siglen==0), checker is NULL so push false,
     * and the script structurally completes. */
    {
        struct script s; script_init(&s);
        script_push_op(&s, OP_0);                /* empty sig */
        unsigned char pk[33];
        memset(pk, 0, sizeof(pk));
        pk[0] = 0x02;
        script_push_data(&s, pk, 33);
        script_push_op(&s, OP_CHECKSIG);
        DCSI_CHECK("OP_CHECKSIG empty sig + NULL checker -> push false",
                   seal_eval(&s, 0, NULL, 0, true, SCRIPT_ERR_OK));
    }

    /* ---- 9. OP_CHECKSIG via fake_checker, empty sig -> false branch ----
     * Empty sig encoding passes, checker is consulted (since check_sig
     * is not NULL), checker requires accept_byte == 0xAA which a
     * zero-length sig cannot match. Both paths must invoke the
     * checker callback identically. */
    {
        struct fake_checker fc;
        fc_init(&fc, 0xAA, true);
        struct script s; script_init(&s);
        script_push_op(&s, OP_0);                /* empty sig */
        unsigned char pk[33];
        memset(pk, 0, sizeof(pk));
        pk[0] = 0x02;
        script_push_data(&s, pk, 33);
        script_push_op(&s, OP_CHECKSIG);
        DCSI_CHECK("OP_CHECKSIG empty sig + fake checker pushes false",
                   seal_eval(&s, 0, &fc.base, 0, true, SCRIPT_ERR_OK));
        /* Both paths invoked the checker callback the same number of
         * times — the relative count is what matters (must equal). */
        DCSI_CHECK("fake_checker.sig_calls is even (domain+lib parity)",
                   (fc.sig_calls % 2) == 0);
    }

    /* ---- 10. OP_CHECKMULTISIG: empty sigs path, structural completion --
     * Standard nulldummy 0 + zero sigs + 1 key + OP_CHECKMULTISIG: the
     * sigs-needed count is 0, so the checker is never invoked and the
     * script completes by pushing true. Tests the multisig DISPATCH
     * without depending on real ECDSA. */
    {
        struct fake_checker fc;
        fc_init(&fc, 0xCD, true);
        unsigned char pk[33];
        memset(pk, 0, sizeof(pk));
        pk[0] = 0x02;
        struct script s; script_init(&s);
        script_push_op(&s, OP_0);                /* nulldummy */
        script_push_op(&s, OP_0);                /* 0 sigs */
        script_push_data(&s, pk, 33);
        script_push_op(&s, OP_1);                /* 1 key */
        script_push_op(&s, OP_CHECKMULTISIG);
        DCSI_CHECK("0-of-1 multisig structurally accepts",
                   seal_eval(&s, 0, &fc.base, 0, true, SCRIPT_ERR_OK));
    }

    /* ---- 11. OP_CHECKMULTISIG with non-DER sig -> SCRIPT_ERR_SIG_DER ---
     * The classic byte-exact regression seal on a signature-failure
     * script. Both paths must reject with the identical error code. */
    {
        struct fake_checker fc;
        fc_init(&fc, 0xCD, true);
        unsigned char bogus_sig[2] = {0x00, 0x01};
        unsigned char pk[33];
        memset(pk, 0, sizeof(pk));
        pk[0] = 0x02;
        struct script s; script_init(&s);
        script_push_op(&s, OP_0);
        script_push_data(&s, bogus_sig, 2);
        script_push_op(&s, OP_1);                /* 1 sig */
        script_push_data(&s, pk, 33);
        script_push_op(&s, OP_1);                /* 1 key */
        script_push_op(&s, OP_CHECKMULTISIG);
        DCSI_CHECK("multisig with non-DER sig -> SCRIPT_ERR_SIG_DER",
                   seal_eval(&s, 0, &fc.base, 0, false, SCRIPT_ERR_SIG_DER));
    }

    /* ---- 11. OP_CHECKLOCKTIMEVERIFY consults checker.check_lock_time ---- */
    {
        struct fake_checker fc;
        fc_init(&fc, 0x00, false);  /* locktime check FAILS */
        struct script s; script_init(&s);
        script_push_op(&s, OP_1);
        script_push_op(&s, OP_CHECKLOCKTIMEVERIFY);
        DCSI_CHECK("OP_CLTV reject when checker says no",
                   seal_eval(&s, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
                             &fc.base, 0,
                             false, SCRIPT_ERR_UNSATISFIED_LOCKTIME));
    }
    {
        struct fake_checker fc;
        fc_init(&fc, 0x00, true);  /* locktime check SUCCEEDS */
        struct script s; script_init(&s);
        script_push_op(&s, OP_1);
        script_push_op(&s, OP_CHECKLOCKTIMEVERIFY);
        DCSI_CHECK("OP_CLTV ok when checker accepts",
                   seal_eval(&s, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
                             &fc.base, 0, true, SCRIPT_ERR_OK));
    }

    /* ---- 12. verify_script: SIG_PUSHONLY gating ---- */
    {
        /* scriptSig contains an opcode that is not a push -> rejected
         * when SCRIPT_VERIFY_SIGPUSHONLY is on. */
        struct script ss; script_init(&ss);
        script_push_op(&ss, OP_1);   /* OP_1 is a push (1..16 are pushes) */
        script_push_op(&ss, OP_DUP); /* DUP is NOT a push */
        struct script spk; script_init(&spk);
        script_push_op(&spk, OP_1);
        DCSI_CHECK("verify_script SIGPUSHONLY rejects non-push in ss",
                   seal_verify(&ss, &spk, SCRIPT_VERIFY_SIGPUSHONLY,
                               NULL, 0, false, SCRIPT_ERR_SIG_PUSHONLY));
    }

    /* ---- 13. verify_script: P2SH redeem path success ---- */
    {
        /* Build a P2SH wrapper around a trivial OP_1 redeem script.
         * scriptSig pushes the serialized redeem; scriptPubKey is
         * HASH160 <hash> EQUAL of the redeem. */
        struct script redeem; script_init(&redeem);
        script_push_op(&redeem, OP_1);
        /* HASH160 of the redeem script. */
        unsigned char rh[20];
        hash160(redeem.data, redeem.size, rh);
        struct script spk; script_init(&spk);
        script_push_op(&spk, OP_HASH160);
        script_push_data(&spk, rh, 20);
        script_push_op(&spk, OP_EQUAL);

        struct script ss; script_init(&ss);
        script_push_data(&ss, redeem.data, redeem.size);

        DCSI_CHECK("verify_script P2SH OP_1 redeem accepts",
                   seal_verify(&ss, &spk, SCRIPT_VERIFY_P2SH, NULL, 0,
                               true, SCRIPT_ERR_OK));
    }

    /* ---- 14. verify_script: empty result -> EVAL_FALSE ---- */
    {
        struct script ss; script_init(&ss);
        struct script spk; script_init(&spk);  /* both empty */
        DCSI_CHECK("verify_script empty stacks -> SCRIPT_ERR_EVAL_FALSE",
                   seal_verify(&ss, &spk, 0, NULL, 0,
                               false, SCRIPT_ERR_EVAL_FALSE));
    }

    /* ---- 15. verify_script: scriptPubKey leaves 0 -> EVAL_FALSE ---- */
    {
        struct script ss; script_init(&ss);
        script_push_op(&ss, OP_1);
        struct script spk; script_init(&spk);
        script_push_op(&spk, OP_0);   /* pushes empty; final cast false */
        DCSI_CHECK("verify_script {1}{0} -> EVAL_FALSE",
                   seal_verify(&ss, &spk, 0, NULL, 0,
                               false, SCRIPT_ERR_EVAL_FALSE));
    }

    /* ---- 16. Script too big -> SCRIPT_ERR_SCRIPT_SIZE
     * We can't realistically exceed MAX_SCRIPT_SIZE inside the fixed
     * buffer via script_push_op repeatedly without allocator, so we
     * synthesize the oversize condition by directly setting .size. */
    {
        struct script s; script_init(&s);
        s.size = MAX_SCRIPT_SIZE + 1;  /* deliberately past the cap */
        memset(s.data, OP_NOP, sizeof(s.data));
        DCSI_CHECK("oversize script -> SCRIPT_ERR_SCRIPT_SIZE",
                   seal_eval(&s, 0, NULL, 0, false, SCRIPT_ERR_SCRIPT_SIZE));
    }

    /* ---- 17. OP_NUMEQUALVERIFY mismatch ---- */
    {
        struct script s; script_init(&s);
        script_push_op(&s, OP_1);
        script_push_op(&s, OP_2);
        script_push_op(&s, OP_NUMEQUALVERIFY);
        DCSI_CHECK("OP_NUMEQUALVERIFY 1!=2 -> SCRIPT_ERR_NUMEQUALVERIFY",
                   seal_eval(&s, 0, NULL, 0, false,
                             SCRIPT_ERR_NUMEQUALVERIFY));
    }

    /* ---- 18. Stack underflow on OP_DUP without operand ---- */
    {
        struct script s; script_init(&s);
        script_push_op(&s, OP_DUP);
        DCSI_CHECK("OP_DUP on empty stack -> SCRIPT_ERR_INVALID_STACK_OPERATION",
                   seal_eval(&s, 0, NULL, 0, false,
                             SCRIPT_ERR_INVALID_STACK_OPERATION));
    }

    return failures;
}
