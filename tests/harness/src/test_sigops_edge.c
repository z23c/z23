/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * NET-NEW consensus edge-case tests for signature-operation counting.
 *
 * Companion to test_domain_consensus_sigops.c — does NOT duplicate any
 * case there. Sigop counting feeds the MAX_BLOCK_SIGOPS consensus limit;
 * a single off-by-one here forks the chain at the next sigop-dense block.
 *
 * The existing suite pins: null contracts, empty tx, single CHECKSIG -> 1,
 * bare CHECKMULTISIG -> 20, P2SH gating (flag/coinbase/non-P2SH/NULL prevout),
 * one 2-of-3 P2SH multisig -> 3, a large mixed shape, and the
 * domain==legacy-wrapper cross-check.
 *
 * This file adds the boundaries that suite leaves uncovered:
 *
 *   1. OP_CHECKSIGVERIFY counts identically to OP_CHECKSIG (consensus var.).
 *   2. OP_CHECKMULTISIGVERIFY counts identically to OP_CHECKMULTISIG.
 *   3. ACCURATE CHECKMULTISIG with an OP_1..OP_16 key-count prefix returns
 *      the EXACT key count, exercised at both ends of the range (OP_1 -> 1,
 *      OP_16 -> 16) via the P2SH redeem-script path. This is the
 *      "20 vs actual key count" distinction in the assignment.
 *   4. ACCURATE CHECKMULTISIG whose preceding opcode is OUTSIDE OP_1..OP_16
 *      (here OP_0) falls back to 20, not to a literal. CVE-class: a miner
 *      must not under-count by abusing the accurate path.
 *   5. P2SH scriptSig containing a NON-PUSH opcode disqualifies the whole
 *      P2SH count -> 0 (mirrors zclassicd's "only push ops" rule). An
 *      attacker must not be able to hide redeem-script sigops behind a
 *      non-push prefix.
 *   6. MAX_BLOCK_SIGOPS-scale summation: a tx whose legacy count lands
 *      exactly on the 20000 limit, proving 64-bit accumulation is exact at
 *      the consensus boundary (no truncation / overflow at block scale).
 */

#include "test/test_core.h"

#include "domain/consensus/sigops.h"
#include "validation/sigops.h"
#include "validation/main_constants.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/script_flags.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define SE_CHECK(name, expr) do { \
    printf("sigops_edge: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* HASH160 <20-byte> EQUAL — the canonical P2SH scriptPubKey shape that
 * script_is_pay_to_script_hash() recognises. Hash bytes are irrelevant to
 * sigop counting. */
static void set_p2sh_script(struct script *s)
{
    s->data[0] = OP_HASH160;
    s->data[1] = 0x14;
    memset(s->data + 2, 0xAA, 20);
    s->data[22] = OP_EQUAL;
    s->size = 23;
}

/* Run the full legacy counter for a single-output tx whose scriptPubKey is
 * `spk[0..spk_len)`, asserting both the domain function and the
 * core/modules/validation wrapper agree and equal `want`. Returns failure delta. */
static int expect_legacy_vout(const char *name, const unsigned char *spk,
                              size_t spk_len, uint64_t want)
{
    int failures = 0;
    struct transaction tx; transaction_init(&tx); transaction_alloc(&tx, 0, 1);
    memcpy(tx.vout[0].script_pub_key.data, spk, spk_len);
    tx.vout[0].script_pub_key.size = spk_len;

    uint64_t domain_n = 0;
    struct zcl_result r =
        domain_consensus_tx_legacy_sig_op_count(&tx, 0, &domain_n);
    uint64_t wrapper_n = get_legacy_sig_op_count(&tx, 0);
    SE_CHECK(name, r.ok && domain_n == want && wrapper_n == want);
    transaction_free(&tx);
    return failures;
}

int test_sigops_edge(void)
{
    int failures = 0;

    /* ---- 1. OP_CHECKSIGVERIFY counts like OP_CHECKSIG ---- */
    {
        unsigned char spk[] = { OP_CHECKSIGVERIFY };
        failures += expect_legacy_vout(
            "OP_CHECKSIGVERIFY counts as 1 (like CHECKSIG)", spk, 1, 1);
    }
    /* Two CHECKSIG-family opcodes in one script sum (1 + 1). */
    {
        unsigned char spk[] = { OP_CHECKSIG, OP_CHECKSIGVERIFY };
        failures += expect_legacy_vout(
            "CHECKSIG + CHECKSIGVERIFY -> 2", spk, 2, 2);
    }

    /* ---- 2. OP_CHECKMULTISIGVERIFY counts like OP_CHECKMULTISIG ---- */
    /* Bare (accurate=false in the legacy path) -> 20, same as MULTISIG. */
    {
        unsigned char spk[] = { OP_CHECKMULTISIGVERIFY };
        failures += expect_legacy_vout(
            "bare OP_CHECKMULTISIGVERIFY -> 20 (like CHECKMULTISIG)",
            spk, 1, 20);
    }

    /* ---- 3. ACCURATE CHECKMULTISIG key-count boundaries via P2SH redeem.
     * The P2SH path runs script_get_sig_op_count(redeem, accurate=true),
     * so a redeem of "OP_n <n pubkeys> OP_m OP_CHECKMULTISIG" must yield
     * exactly the m of the *preceding* push opcode (the key count). We
     * vary the trailing key-count opcode (OP_1 and OP_16) — that's the
     * opcode immediately before OP_CHECKMULTISIG, which the accurate
     * counter reads. ---- */
    {
        /* helper-free, explicit so the redeem bytes are obvious */
        struct mtest { enum opcodetype keycount_op; uint64_t want; const char *name; }
        cases[] = {
            { OP_1,  1,  "P2SH accurate CHECKMULTISIG OP_1  -> 1"  },
            { OP_16, 16, "P2SH accurate CHECKMULTISIG OP_16 -> 16" },
        };
        for (size_t c = 0; c < sizeof(cases)/sizeof(cases[0]); c++) {
            struct transaction tx; transaction_init(&tx);
            transaction_alloc(&tx, 1, 1);
            memset(tx.vin[0].prevout.hash.data, 0x91, 32);
            tx.vin[0].prevout.n = 0;

            /* redeem = OP_1 <push33> OP_<keycount> OP_CHECKMULTISIG.
             * Only the opcode immediately preceding OP_CHECKMULTISIG (the
             * keycount_op) is read by the accurate counter; we keep a real
             * 33-byte pubkey push so the redeem is well-formed. */
            unsigned char redeem[64];
            size_t rsz = 0;
            redeem[rsz++] = OP_1;
            redeem[rsz++] = 33;
            for (int j = 0; j < 33; j++) redeem[rsz++] = 0xC1;
            redeem[rsz++] = (unsigned char)cases[c].keycount_op;
            redeem[rsz++] = OP_CHECKMULTISIG;

            script_init(&tx.vin[0].script_sig);
            bool pushed = script_push_data(&tx.vin[0].script_sig, redeem, rsz);
            SE_CHECK("P2SH accurate: redeem push fits scriptSig", pushed);

            struct tx_out prev; memset(&prev, 0, sizeof(prev));
            set_p2sh_script(&prev.script_pub_key);
            const struct tx_out *prevs[1] = { &prev };

            uint64_t n = 0;
            struct zcl_result r = domain_consensus_tx_p2sh_sig_op_count(
                    &tx, prevs, SCRIPT_VERIFY_P2SH, &n);
            SE_CHECK(cases[c].name, r.ok && n == cases[c].want);
            transaction_free(&tx);
        }
    }

    /* ---- 4. ACCURATE fallback: keycount opcode OUTSIDE OP_1..OP_16.
     * Redeem = OP_0 OP_CHECKMULTISIG. OP_0 (0x00) is NOT in [OP_1,OP_16],
     * so even in accurate mode the counter must fall back to 20 — never
     * to 0. A miner must not be able to under-count by prefixing OP_0. ---- */
    {
        struct transaction tx; transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        memset(tx.vin[0].prevout.hash.data, 0x92, 32);
        tx.vin[0].prevout.n = 0;

        unsigned char redeem[2] = { OP_0, OP_CHECKMULTISIG };
        script_init(&tx.vin[0].script_sig);
        bool pushed = script_push_data(&tx.vin[0].script_sig, redeem, sizeof(redeem));
        SE_CHECK("P2SH OP_0-prefix: redeem push fits scriptSig", pushed);

        struct tx_out prev; memset(&prev, 0, sizeof(prev));
        set_p2sh_script(&prev.script_pub_key);
        const struct tx_out *prevs[1] = { &prev };

        uint64_t n = 0;
        struct zcl_result r = domain_consensus_tx_p2sh_sig_op_count(
                &tx, prevs, SCRIPT_VERIFY_P2SH, &n);
        SE_CHECK("P2SH CHECKMULTISIG with OP_0 prefix -> 20 (not 0)",
                 r.ok && n == 20);
        transaction_free(&tx);
    }

    /* ---- 5. P2SH scriptSig with a NON-PUSH opcode -> whole P2SH count 0.
     * The redeem we push contains 16 CHECKSIGs, but we prepend a non-push
     * opcode (OP_CHECKSIG) to the scriptSig. Per the "scriptSig must be
     * push-only" rule the P2SH counter returns 0 for that input — the
     * redeem sigops are NOT counted. (The legacy counter separately sees
     * the bare OP_CHECKSIG; here we assert only the P2SH contribution.) ---- */
    {
        struct transaction tx; transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        memset(tx.vin[0].prevout.hash.data, 0x93, 32);
        tx.vin[0].prevout.n = 0;

        /* redeem = 16x OP_CHECKSIG (would count 16 if it were reached). */
        unsigned char redeem[16];
        for (int j = 0; j < 16; j++) redeem[j] = OP_CHECKSIG;

        /* scriptSig = OP_CHECKSIG (NON-push) followed by a push of redeem. */
        script_init(&tx.vin[0].script_sig);
        bool op_ok = script_push_op(&tx.vin[0].script_sig, OP_CHECKSIG);
        bool push_ok = script_push_data(&tx.vin[0].script_sig, redeem, sizeof(redeem));
        SE_CHECK("P2SH non-push: scriptSig built", op_ok && push_ok);

        struct tx_out prev; memset(&prev, 0, sizeof(prev));
        set_p2sh_script(&prev.script_pub_key);
        const struct tx_out *prevs[1] = { &prev };

        uint64_t n = 99;
        struct zcl_result r = domain_consensus_tx_p2sh_sig_op_count(
                &tx, prevs, SCRIPT_VERIFY_P2SH, &n);
        SE_CHECK("P2SH scriptSig with non-push opcode -> 0",
                 r.ok && n == 0);
        transaction_free(&tx);
    }

    /* ---- 6. MAX_BLOCK_SIGOPS-scale exactness.
     * 1000 outputs each a bare OP_CHECKMULTISIG (20 sigops, accurate=false
     * in the legacy path) = exactly 20000 = MAX_BLOCK_SIGOPS. Proves the
     * 64-bit accumulator is exact at the consensus boundary and that the
     * total sits ON (not over/under) the limit blocks are rejected against. ---- */
    {
        const size_t nout = 1000;
        struct transaction tx; transaction_init(&tx);
        bool alloc_ok = transaction_alloc(&tx, 0, nout);
        SE_CHECK("MAX_BLOCK_SIGOPS-scale: alloc 1000 vout", alloc_ok);
        for (size_t i = 0; i < tx.num_vout; i++) {
            tx.vout[i].script_pub_key.data[0] = OP_CHECKMULTISIG;
            tx.vout[i].script_pub_key.size = 1;
        }
        uint64_t domain_n = 0;
        struct zcl_result r =
            domain_consensus_tx_legacy_sig_op_count(&tx, 0, &domain_n);
        uint64_t wrapper_n = get_legacy_sig_op_count(&tx, 0);
        SE_CHECK("legacy count == 20000 == MAX_BLOCK_SIGOPS exactly",
                 r.ok && domain_n == 20000 && domain_n == (uint64_t)MAX_BLOCK_SIGOPS
                 && wrapper_n == domain_n);
        transaction_free(&tx);
    }

    return failures;
}
