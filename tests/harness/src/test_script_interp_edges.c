/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Adversarial edge-case coverage of the transparent script interpreter
 * (domain/consensus/src/script_interp.c, reached through the
 * domain_consensus_eval_script entry point that eval_script forwards to)
 * and the sigop/opcode limits it enforces.
 *
 * This file adds GAPS left uncovered by the substantial existing script
 * suites — it does NOT duplicate:
 *   - test_bip113_bip65.c                       (CLTV negative/mixed-domain,
 *                                                  MTP, ContextualCheckBlock)
 *   - test_domain_consensus_script_interp.c      (dispatch + sig + P2SH +
 *                                                  basic CLTV checker-consult)
 *   - test_script_interp_edge.c                  (CScriptNum 4-byte limit,
 *                                                  520/521 push boundary,
 *                                                  MINIMALDATA 1-byte case,
 *                                                  201/202 op-count cap,
 *                                                  multisig missing-dummy,
 *                                                  standalone OP_ELSE)
 * - test_script_interp_stack_bounds.c            (OP_2ROT/PICK/ROLL/TUCK,
 *                                                  MAX_STACK_ITEMS overflow)
 * - test_multisig_consensus_branches.c           (multisig branches:
 *                                                  SIG_COUNT/PUBKEY_COUNT/
 *                                                  NULLDUMMY/NULLFAIL)
 *   - test_sigops_edge.c / test_domain_consensus_sigops.c
 *                                                 (sigop counting incl. the
 *                                                  MAX_BLOCK_SIGOPS=20000
 *                                                  exact boundary and P2SH
 *                                                  accurate-mode edge cases)
 *
 * NET-NEW cases here:
 *
 *   1. OP_CHECKLOCKTIMEVERIFY when SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY is
 *      CLEAR: (a) with SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS set, the
 *      op rejects with SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS even on an
 *      EMPTY stack (the op never inspects the stack in the disabled path);
 *      (b) with that flag also clear, CLTV is a pure no-op (OP_NOP2
 *      semantics) and never touches the stack or the checker callback.
 *   2. OP_CHECKLOCKTIMEVERIFY enabled + empty stack ->
 *      SCRIPT_ERR_INVALID_STACK_OPERATION (existing CLTV coverage always
 *      pre-pushes an operand).
 *   3. OP_CHECKLOCKTIMEVERIFY's stack-top encoding limit: SN_FROM_TOP_N
 *      passes max_size=5 (wider than the ordinary arithmetic 4-byte cap).
 *      A 5-byte positive operand is accepted (and reaches the checker); a
 *      6-byte operand is rejected by script_num_from_bytes's length gate
 *      BEFORE the checker is consulted — proved with a checker that would
 *      have accepted, isolating the reject to the encoding limit.
 *   4. Disabled opcodes (OP_CAT, OP_MUL) reject even INSIDE an unexecuted
 *      (false) OP_IF branch — Bitcoin semantics: the disabled-opcode gate
 *      in domain_consensus_eval_script runs unconditionally, before the
 *      fExec gate, so branch-skipping cannot smuggle a disabled opcode
 *      through.
 *   5. SCRIPT_VERIFY_MINIMALDATA push-encoding boundaries not covered by
 *      the existing 1-byte case: the 75/76-byte direct-push vs
 *      OP_PUSHDATA1 boundary, and the 255/256-byte OP_PUSHDATA1 vs
 *      OP_PUSHDATA2 boundary. Each non-minimal encoding is rejected only
 *      when the flag is set, and accepted verbatim when it is clear.
 *   6. MAX_SCRIPT_SIZE (10000) exact-boundary ACCEPT: paired with the
 *      existing MAX_SCRIPT_SIZE+1 reject (test_domain_consensus_script_
 *      interp.c #16), a script of exactly 10000 bytes must NOT be rejected
 *      by the size gate — proved by running it into a *different*, later
 *      failure (SCRIPT_ERR_STACK_SIZE at the MAX_STACK_ITEMS boundary)
 *      rather than the immediate SCRIPT_ERR_SCRIPT_SIZE a regression would
 *      produce.
 *   7. OP_CHECKMULTISIG's accurate op-count contribution
 *      (`nOpCount += nKeysCount`) at the exact 201-op consensus boundary —
 *      distinct from the generic +1-per-opcode cap already pinned by
 *      test_script_interp_edge.c. 199 leading OP_NOPs + a 1-key multisig
 *      lands exactly on 201 (accept); 200 leading OP_NOPs overflows to 202
 *      (SCRIPT_ERR_OP_COUNT).
 *   8. Stack-underflow on stack-consuming opcode families with NO existing
 *      coverage anywhere in the test tree: OP_2OVER, OP_2SWAP, OP_ROT,
 *      OP_SWAP, OP_NIP, OP_WITHIN, OP_RIPEMD160 (representative of the
 *      RIPEMD160/SHA1/SHA256/HASH160/HASH256 family, which share one
 *      `stack->count < 1` guard), OP_CHECKDATASIG, OP_IFDUP, OP_2DROP,
 *      OP_3DUP.
 *
 * Every accept/reject pair is non-vacuous — the accept half proves the
 * script shape is otherwise well-formed, so the paired reject is
 * attributable to the specific limit under test, not some other defect.
 * No consensus predicate is touched; this file only reads through the
 * existing eval_script entry point. */

#include "test/test_core.h"

#include "domain/consensus/script_interp.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/script_flags.h"

#include <stdio.h>
#include <string.h>

#define SIE_CHECK(name, expr) do { \
    printf("script_interp_edges: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Synthetic sig checker — only check_lock_time is exercised in this file.
 * Copied verbatim (pattern established by test_domain_consensus_script_
 * interp.c / test_multisig_consensus_branches.c). */
struct sie_fake_checker {
    struct sig_checker base;
    int lock_calls;
    bool lock_ok;
};

static bool sie_check_lock_time(const struct sig_checker *self, int64_t lt)
{
    (void)lt;
    struct sie_fake_checker *fc = (struct sie_fake_checker *)(uintptr_t)self;
    fc->lock_calls++;
    return fc->lock_ok;
}

static void sie_fc_init(struct sie_fake_checker *fc, bool lock_ok)
{
    memset(fc, 0, sizeof(*fc));
    fc->base.check_sig        = NULL;
    fc->base.check_lock_time  = sie_check_lock_time;
    fc->base.verify_signature = NULL;
    fc->lock_ok = lock_ok;
}

/* Run domain_consensus_eval_script on a fresh heap stack and compare the
 * exact (bool, ScriptError) verdict. Returns true iff it matches. */
static bool sie_run(const struct script *s, unsigned int flags,
                    const struct sig_checker *checker,
                    bool expect_ok, ScriptError expect_err)
{
    struct script_stack stk __attribute__((cleanup(stack_free))) = {0};
    if (!stack_init(&stk)) return false;

    ScriptError err = SCRIPT_ERR_ERROR_COUNT;
    bool ok = domain_consensus_eval_script(&stk, s, flags, checker, 0, &err);

    if (ok != expect_ok) {
        fprintf(stderr, "[sie] expected ok=%d got %d (err=%d) ",
                expect_ok, ok, err);
        return false;
    }
    if (!expect_ok && err != expect_err) {
        fprintf(stderr, "[sie] expected err=%d got %d ", expect_err, err);
        return false;
    }
    if (expect_ok && err != SCRIPT_ERR_OK) {
        fprintf(stderr, "[sie] expected SCRIPT_ERR_OK on success, got %d ", err);
        return false;
    }
    return true;
}

int test_script_interp_edges(void)
{
    int failures = 0;

    /* ==== 1. CLTV disabled-flag paths ==== */

    /* 1a. CLTV flag clear + DISCOURAGE_UPGRADABLE_NOPS set -> reject, even
     * with a completely empty stack (the op never reaches a stack check). */
    {
        struct script s; script_init(&s);
        script_push_op(&s, OP_CHECKLOCKTIMEVERIFY);
        SIE_CHECK("CLTV flag off + DISCOURAGE_UPGRADABLE_NOPS -> reject on empty stack",
                  sie_run(&s, SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS, NULL,
                          false, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS));
    }

    /* 1b. CLTV flag clear + DISCOURAGE also clear -> pure no-op (OP_NOP2
     * semantics): empty stack, NULL checker, still succeeds. */
    {
        struct script s; script_init(&s);
        script_push_op(&s, OP_CHECKLOCKTIMEVERIFY);
        SIE_CHECK("CLTV flag off + no DISCOURAGE -> plain no-op, empty stack ok",
                  sie_run(&s, SCRIPT_VERIFY_NONE, NULL, true, SCRIPT_ERR_OK));
    }

    /* ==== 2. CLTV enabled + empty stack ==== */
    {
        struct script s; script_init(&s);
        script_push_op(&s, OP_CHECKLOCKTIMEVERIFY);
        SIE_CHECK("CLTV enabled + empty stack -> SCRIPT_ERR_INVALID_STACK_OPERATION",
                  sie_run(&s, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, NULL,
                          false, SCRIPT_ERR_INVALID_STACK_OPERATION));
    }

    /* ==== 3. CLTV stack-top encoding limit: 5-byte accept / 6-byte reject ==== */
    {
        /* 5-byte positive operand ({0x01,0,0,0,0} = value 1): within the
         * SN_FROM_TOP_N max_size=5 cap, checker accepts -> success. */
        unsigned char five[5] = { 0x01, 0x00, 0x00, 0x00, 0x00 };
        struct script s; script_init(&s);
        script_push_data(&s, five, sizeof five);
        script_push_op(&s, OP_CHECKLOCKTIMEVERIFY);
        struct sie_fake_checker fc;
        sie_fc_init(&fc, true);
        bool ok = sie_run(&s, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, &fc.base,
                          true, SCRIPT_ERR_OK);
        SIE_CHECK("CLTV 5-byte operand accepted (within max_size=5)",
                  ok && fc.lock_calls == 1);
    }
    {
        /* 6-byte positive operand: one byte past the CLTV-specific cap.
         * script_num_from_bytes rejects on length alone (SN_FROM_TOP_N ->
         * SCRIPT_ERR_UNKNOWN_ERROR) BEFORE the checker is ever consulted.
         * The checker is wired to ACCEPT, isolating the reject to the
         * encoding limit rather than checker refusal. */
        unsigned char six[6] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
        struct script s; script_init(&s);
        script_push_data(&s, six, sizeof six);
        script_push_op(&s, OP_CHECKLOCKTIMEVERIFY);
        struct sie_fake_checker fc;
        sie_fc_init(&fc, true);
        bool ok = sie_run(&s, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, &fc.base,
                          false, SCRIPT_ERR_UNKNOWN_ERROR);
        SIE_CHECK("CLTV 6-byte operand rejected before checker is consulted",
                  ok && fc.lock_calls == 0);
    }

    /* ==== 4. Disabled opcodes reject inside an UNEXECUTED IF branch ==== */
    {
        /* push 0 (false) ; OP_IF ; OP_CAT ; [never reached: OP_ENDIF] —
         * the disabled-opcode gate fires while scanning OP_CAT regardless
         * of fExec, so the script never even gets to the missing OP_ENDIF. */
        struct script s; script_init(&s);
        script_push_op(&s, OP_0);
        script_push_op(&s, OP_IF);
        script_push_op(&s, OP_CAT);
        SIE_CHECK("OP_CAT rejects inside an unexecuted (false) IF branch",
                  sie_run(&s, SCRIPT_VERIFY_NONE, NULL,
                          false, SCRIPT_ERR_DISABLED_OPCODE));
    }
    {
        struct script s; script_init(&s);
        script_push_op(&s, OP_0);
        script_push_op(&s, OP_IF);
        script_push_op(&s, OP_MUL);
        SIE_CHECK("OP_MUL rejects inside an unexecuted (false) IF branch",
                  sie_run(&s, SCRIPT_VERIFY_NONE, NULL,
                          false, SCRIPT_ERR_DISABLED_OPCODE));
    }

    /* ==== 5. MINIMALDATA push-encoding boundaries ==== */

    /* 5a. 75-byte direct push (opcode==75) is the minimal encoding -> ok. */
    {
        unsigned char buf[75];
        memset(buf, 0x42, sizeof buf);
        struct script s; script_init(&s);
        script_push_data(&s, buf, sizeof buf);
        SIE_CHECK("75-byte direct push is minimal -> accepted under MINIMALDATA",
                  sie_run(&s, SCRIPT_VERIFY_MINIMALDATA, NULL, true, SCRIPT_ERR_OK));
    }
    /* 5b. Same 75-byte payload re-encoded via OP_PUSHDATA1 (non-minimal:
     * check_minimal_push requires opcode==len for len<=75) -> reject under
     * MINIMALDATA, accept without it. */
    {
        unsigned char raw[2 + 75];
        raw[0] = OP_PUSHDATA1;
        raw[1] = 75;
        memset(raw + 2, 0x42, 75);
        struct script s; script_set(&s, raw, sizeof raw);
        SIE_CHECK("75-byte payload via OP_PUSHDATA1 -> SCRIPT_ERR_MINIMALDATA",
                  sie_run(&s, SCRIPT_VERIFY_MINIMALDATA, NULL,
                          false, SCRIPT_ERR_MINIMALDATA));
        SIE_CHECK("same non-minimal push accepted without MINIMALDATA",
                  sie_run(&s, SCRIPT_VERIFY_NONE, NULL, true, SCRIPT_ERR_OK));
    }
    /* 5c. 255-byte payload via native OP_PUSHDATA1 (minimal for len<=255)
     * -> ok. */
    {
        unsigned char buf[255];
        memset(buf, 0x43, sizeof buf);
        struct script s; script_init(&s);
        script_push_data(&s, buf, sizeof buf);
        SIE_CHECK("255-byte push via OP_PUSHDATA1 is minimal -> accepted",
                  sie_run(&s, SCRIPT_VERIFY_MINIMALDATA, NULL, true, SCRIPT_ERR_OK));
    }
    /* 5d. Same 255-byte payload re-encoded via OP_PUSHDATA2 (non-minimal:
     * check_minimal_push requires OP_PUSHDATA1 for len<=255) -> reject
     * under MINIMALDATA, accept without it. */
    {
        unsigned char raw[3 + 255];
        raw[0] = OP_PUSHDATA2;
        raw[1] = 255 & 0xff;
        raw[2] = (255 >> 8) & 0xff;
        memset(raw + 3, 0x43, 255);
        struct script s; script_set(&s, raw, sizeof raw);
        SIE_CHECK("255-byte payload via OP_PUSHDATA2 -> SCRIPT_ERR_MINIMALDATA",
                  sie_run(&s, SCRIPT_VERIFY_MINIMALDATA, NULL,
                          false, SCRIPT_ERR_MINIMALDATA));
        SIE_CHECK("same non-minimal push accepted without MINIMALDATA",
                  sie_run(&s, SCRIPT_VERIFY_NONE, NULL, true, SCRIPT_ERR_OK));
    }

    /* ==== 6. MAX_SCRIPT_SIZE exact-boundary ACCEPT ====
     * Exactly 10000 bytes of OP_1: the size gate (`> MAX_SCRIPT_SIZE`)
     * must NOT fire at ==. Execution then proceeds and hits a DIFFERENT,
     * later limit — MAX_STACK_ITEMS overflow on the 1001st push — which
     * proves the size check specifically passed at the boundary. A
     * regression that tightened the size gate to `>=` would instead
     * report SCRIPT_ERR_SCRIPT_SIZE immediately, failing this assertion. */
    {
        struct script s; script_init(&s);
        s.size = MAX_SCRIPT_SIZE;
        memset(s.data, OP_1, MAX_SCRIPT_SIZE);
        SIE_CHECK("exactly-MAX_SCRIPT_SIZE script not rejected by the size gate",
                  sie_run(&s, SCRIPT_VERIFY_NONE, NULL,
                          false, SCRIPT_ERR_STACK_SIZE));
    }

    /* ==== 7. OP_CHECKMULTISIG accurate key-count op-count boundary ====
     * `nOpCount += nKeysCount` (script_interp.c:599) is a distinct code
     * path from the generic +1-per-opcode cap: N leading OP_NOPs + a
     * 1-of-1 multisig contribute (N + 1 [the CHECKMULTISIG opcode itself]
     * + 1 [nKeysCount]). N=199 lands exactly on 201 (accept); N=200
     * overflows to 202 (SCRIPT_ERR_OP_COUNT). */
    {
        for (int variant = 0; variant < 2; variant++) {
            int n_nops = (variant == 0) ? 199 : 200;
            struct script s; script_init(&s);
            for (int i = 0; i < n_nops; i++)
                script_push_op(&s, OP_NOP);
            script_push_op(&s, OP_0);           /* nulldummy */
            script_push_op(&s, OP_0);           /* 0 sigs */
            unsigned char pk1[1] = { 0xAA };
            script_push_data(&s, pk1, 1);       /* 1 key placeholder */
            script_push_op(&s, OP_1);           /* 1 key */
            script_push_op(&s, OP_CHECKMULTISIG);

            if (variant == 0) {
                SIE_CHECK("199 NOPs + 1-key CHECKMULTISIG lands exactly on "
                          "op-count 201 -> accept",
                          sie_run(&s, SCRIPT_VERIFY_NONE, NULL,
                                  true, SCRIPT_ERR_OK));
            } else {
                SIE_CHECK("200 NOPs + 1-key CHECKMULTISIG overflows to "
                          "op-count 202 -> SCRIPT_ERR_OP_COUNT",
                          sie_run(&s, SCRIPT_VERIFY_NONE, NULL,
                                  false, SCRIPT_ERR_OP_COUNT));
            }
        }
    }

    /* ==== 8. Stack-underflow: previously-untested opcode families ==== */
    {
        struct { enum opcodetype op; int need; const char *name; } cases[] = {
            { OP_2OVER,      4, "OP_2OVER"      },
            { OP_2SWAP,      4, "OP_2SWAP"      },
            { OP_ROT,        3, "OP_ROT"        },
            { OP_SWAP,       2, "OP_SWAP"       },
            { OP_NIP,        2, "OP_NIP"        },
            { OP_WITHIN,     3, "OP_WITHIN"     },
            { OP_RIPEMD160,  1, "OP_RIPEMD160"  },
            { OP_CHECKDATASIG, 3, "OP_CHECKDATASIG" },
            { OP_IFDUP,      1, "OP_IFDUP"      },
            { OP_2DROP,      2, "OP_2DROP"      },
            { OP_3DUP,       3, "OP_3DUP"       },
        };
        for (size_t c = 0; c < sizeof(cases)/sizeof(cases[0]); c++) {
            struct script s; script_init(&s);
            /* provide need-1 items (one short) */
            for (int i = 0; i < cases[c].need - 1; i++)
                script_push_op(&s, OP_1);
            script_push_op(&s, cases[c].op);
            char msg[96];
            snprintf(msg, sizeof msg, "%s with %d/%d operands -> "
                     "SCRIPT_ERR_INVALID_STACK_OPERATION",
                     cases[c].name, cases[c].need - 1, cases[c].need);
            SIE_CHECK(msg,
                      sie_run(&s, SCRIPT_VERIFY_NONE, NULL,
                              false, SCRIPT_ERR_INVALID_STACK_OPERATION));
        }
    }

    return failures;
}
