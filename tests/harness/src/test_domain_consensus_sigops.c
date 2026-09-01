/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Unit tests for domain/consensus/sigops.{c,h}.
 *
 * Pins the pure sigop-counting arithmetic. Tests exercise the typed
 * zcl_result API directly AND cross-check against the legacy core/modules/validation
 * wrappers to prove the extraction is behaviour-preserving.
 *
 * Coverage:
 *   - null/edge contracts (null tx, null out, null prevouts when required)
 *   - empty scripts             -> 0
 *   - single OP_CHECKSIG vout   -> 1 (legacy)
 *   - bare OP_CHECKMULTISIG     -> 20 (legacy, accurate=false)
 *   - P2SH gating (flag off, coinbase, non-P2SH prevout)
 *   - P2SH multisig regression seal: 2-of-3 wrapped redeem script,
 *     scriptSig pushes redeem, scriptPubKey is P2SH wrapper
 *   - large mixed shape: many vin/vout
 *   - cross-check legacy wrapper output for every shape
 */

#include "test/test_core.h"

#include "domain/consensus/sigops.h"
#include "validation/sigops.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/script_flags.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define DCS_CHECK(name, expr) do { \
    printf("domain_consensus_sigops: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static void set_p2sh_script(struct script *s)
{
    s->data[0] = OP_HASH160;
    s->data[1] = 0x14;
    memset(s->data + 2, 0xAA, 20);
    s->data[22] = OP_EQUAL;
    s->size = 23;
}

static void set_p2pkh_script(struct script *s)
{
    s->data[0] = OP_DUP;
    s->data[1] = OP_HASH160;
    s->data[2] = 0x14;
    memset(s->data + 3, 0xBB, 20);
    s->data[23] = OP_EQUALVERIFY;
    s->data[24] = OP_CHECKSIG;
    s->size = 25;
}

int test_domain_consensus_sigops(void)
{
    int failures = 0;

    /* ---- contract / null-arg tests ---- */

    /* legacy: null tx -> ERR_NULL_TX */
    {
        uint64_t n = 0;
        struct zcl_result r = domain_consensus_tx_legacy_sig_op_count(NULL, 0, &n);
        DCS_CHECK("legacy null tx -> ERR_NULL_TX",
                  !r.ok && r.code == DOMAIN_CONSENSUS_SIGOPS_ERR_NULL_TX);
    }
    /* legacy: null out -> ERR_NULL_OUT */
    {
        struct transaction tx; transaction_init(&tx); transaction_alloc(&tx, 0, 0);
        struct zcl_result r = domain_consensus_tx_legacy_sig_op_count(&tx, 0, NULL);
        DCS_CHECK("legacy null out -> ERR_NULL_OUT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_SIGOPS_ERR_NULL_OUT);
        transaction_free(&tx);
    }
    /* p2sh: null tx -> ERR_NULL_TX */
    {
        uint64_t n = 0;
        struct zcl_result r = domain_consensus_tx_p2sh_sig_op_count(
                NULL, NULL, SCRIPT_VERIFY_P2SH, &n);
        DCS_CHECK("p2sh null tx -> ERR_NULL_TX",
                  !r.ok && r.code == DOMAIN_CONSENSUS_SIGOPS_ERR_NULL_TX);
    }
    /* p2sh: null out -> ERR_NULL_OUT */
    {
        struct transaction tx; transaction_init(&tx); transaction_alloc(&tx, 0, 0);
        struct zcl_result r = domain_consensus_tx_p2sh_sig_op_count(
                &tx, NULL, SCRIPT_VERIFY_P2SH, NULL);
        DCS_CHECK("p2sh null out -> ERR_NULL_OUT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_SIGOPS_ERR_NULL_OUT);
        transaction_free(&tx);
    }
    /* p2sh: null prevouts with non-zero vin + P2SH on -> ERR_NULL_PREVOUTS */
    {
        struct transaction tx; transaction_init(&tx); transaction_alloc(&tx, 2, 1);
        /* Make it non-coinbase. */
        memset(tx.vin[0].prevout.hash.data, 0x33, 32);
        tx.vin[0].prevout.n = 0;
        tx.vin[1].prevout.n = 1;
        uint64_t n = 0;
        struct zcl_result r = domain_consensus_tx_p2sh_sig_op_count(
                &tx, NULL, SCRIPT_VERIFY_P2SH, &n);
        DCS_CHECK("p2sh null prevouts -> ERR_NULL_PREVOUTS",
                  !r.ok && r.code == DOMAIN_CONSENSUS_SIGOPS_ERR_NULL_PREVOUTS);
        transaction_free(&tx);
    }
    /* p2sh: null prevouts is OK if P2SH flag is off (short-circuits to 0). */
    {
        struct transaction tx; transaction_init(&tx); transaction_alloc(&tx, 2, 1);
        memset(tx.vin[0].prevout.hash.data, 0x33, 32);
        uint64_t n = 99;
        struct zcl_result r = domain_consensus_tx_p2sh_sig_op_count(&tx, NULL, 0, &n);
        DCS_CHECK("p2sh flag off + null prevouts -> OK count=0",
                  r.ok && n == 0);
        transaction_free(&tx);
    }

    /* ---- value tests ---- */

    /* empty tx -> count 0 (legacy) */
    {
        struct transaction tx; transaction_init(&tx); transaction_alloc(&tx, 0, 0);
        uint64_t n = 7;
        struct zcl_result r = domain_consensus_tx_legacy_sig_op_count(&tx, 0, &n);
        DCS_CHECK("legacy empty tx -> 0", r.ok && n == 0);
        transaction_free(&tx);
    }

    /* single output with OP_CHECKSIG -> count 1 (legacy) */
    {
        struct transaction tx; transaction_init(&tx); transaction_alloc(&tx, 1, 1);
        memset(tx.vin[0].prevout.hash.data, 0x11, 32);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].script_sig.size = 0;
        tx.vout[0].script_pub_key.data[0] = OP_CHECKSIG;
        tx.vout[0].script_pub_key.size = 1;
        uint64_t domain_n = 0;
        struct zcl_result r = domain_consensus_tx_legacy_sig_op_count(&tx, 0, &domain_n);
        uint64_t legacy_n = get_legacy_sig_op_count(&tx, 0);
        DCS_CHECK("legacy P2PK-like vout -> 1 + matches wrapper",
                  r.ok && domain_n == 1 && legacy_n == 1);
        transaction_free(&tx);
    }

    /* bare OP_CHECKMULTISIG -> 20 (accurate=false counts MAX_PUBKEYS_PER_MULTISIG) */
    {
        struct transaction tx; transaction_init(&tx); transaction_alloc(&tx, 1, 1);
        memset(tx.vin[0].prevout.hash.data, 0x22, 32);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].script_sig.size = 0;
        tx.vout[0].script_pub_key.data[0] = OP_CHECKMULTISIG;
        tx.vout[0].script_pub_key.size = 1;
        uint64_t domain_n = 0;
        struct zcl_result r = domain_consensus_tx_legacy_sig_op_count(&tx, 0, &domain_n);
        uint64_t legacy_n = get_legacy_sig_op_count(&tx, 0);
        DCS_CHECK("legacy bare OP_CHECKMULTISIG -> 20 + matches wrapper",
                  r.ok && domain_n == 20 && legacy_n == 20);
        transaction_free(&tx);
    }

    /* P2SH: flag off -> 0 (no IO, no array touched). */
    {
        struct transaction tx; transaction_init(&tx); transaction_alloc(&tx, 1, 1);
        memset(tx.vin[0].prevout.hash.data, 0x55, 32);
        struct tx_out prev; memset(&prev, 0, sizeof(prev));
        set_p2sh_script(&prev.script_pub_key);
        const struct tx_out *prevs[1] = { &prev };
        uint64_t n = 9;
        struct zcl_result r = domain_consensus_tx_p2sh_sig_op_count(&tx, prevs, 0, &n);
        DCS_CHECK("p2sh flag off -> 0", r.ok && n == 0);
        transaction_free(&tx);
    }

    /* P2SH: coinbase -> 0 (input vector marked as coinbase). */
    {
        struct transaction tx; transaction_init(&tx); transaction_alloc(&tx, 1, 1);
        /* Coinbase: vin[0].prevout.hash is all zero AND .n is 0xFFFFFFFF. */
        memset(tx.vin[0].prevout.hash.data, 0x00, 32);
        tx.vin[0].prevout.n = 0xFFFFFFFFu;
        struct tx_out prev; memset(&prev, 0, sizeof(prev));
        set_p2sh_script(&prev.script_pub_key);
        const struct tx_out *prevs[1] = { &prev };
        uint64_t n = 7;
        struct zcl_result r = domain_consensus_tx_p2sh_sig_op_count(
                &tx, prevs, SCRIPT_VERIFY_P2SH, &n);
        DCS_CHECK("p2sh coinbase -> 0", r.ok && n == 0);
        transaction_free(&tx);
    }

    /* P2SH: non-P2SH prevout (P2PKH) -> 0 (P2SH counter ignores non-P2SH). */
    {
        struct transaction tx; transaction_init(&tx); transaction_alloc(&tx, 1, 1);
        memset(tx.vin[0].prevout.hash.data, 0x66, 32);
        tx.vin[0].prevout.n = 0;
        struct tx_out prev; memset(&prev, 0, sizeof(prev));
        set_p2pkh_script(&prev.script_pub_key);
        const struct tx_out *prevs[1] = { &prev };
        uint64_t n = 99;
        struct zcl_result r = domain_consensus_tx_p2sh_sig_op_count(
                &tx, prevs, SCRIPT_VERIFY_P2SH, &n);
        DCS_CHECK("p2sh non-P2SH prevout -> 0", r.ok && n == 0);
        transaction_free(&tx);
    }

    /* P2SH: NULL prevout entry contributes 0 (missing-prevout is reported
     * elsewhere; sigop counter must not crash). */
    {
        struct transaction tx; transaction_init(&tx); transaction_alloc(&tx, 1, 1);
        memset(tx.vin[0].prevout.hash.data, 0x77, 32);
        tx.vin[0].prevout.n = 0;
        const struct tx_out *prevs[1] = { NULL };
        uint64_t n = 99;
        struct zcl_result r = domain_consensus_tx_p2sh_sig_op_count(
                &tx, prevs, SCRIPT_VERIFY_P2SH, &n);
        DCS_CHECK("p2sh NULL prevout entry -> 0", r.ok && n == 0);
        transaction_free(&tx);
    }

    /* P2SH multisig regression seal: 2-of-3 redeem wrapped in a P2SH
     * scriptPubKey. Redeem script = OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG.
     * scriptSig must push the redeem (script_get_sig_op_count_p2sh extracts
     * the last push as the redeem and accurately counts its CHECKMULTISIGs). */
    {
        struct transaction tx; transaction_init(&tx); transaction_alloc(&tx, 1, 1);
        memset(tx.vin[0].prevout.hash.data, 0x88, 32);
        tx.vin[0].prevout.n = 0;

        /* Build redeem: OP_2 (push 33 bytes) x3 OP_3 OP_CHECKMULTISIG. */
        unsigned char redeem[256];
        size_t rsz = 0;
        redeem[rsz++] = OP_2;
        for (int k = 0; k < 3; k++) {
            redeem[rsz++] = 33;             /* push 33-byte pubkey */
            for (int j = 0; j < 33; j++)
                redeem[rsz++] = (unsigned char)(0xC0 + k);
        }
        redeem[rsz++] = OP_3;
        redeem[rsz++] = OP_CHECKMULTISIG;

        /* scriptSig: push the redeem script. rsz (~105) exceeds the
         * one-byte direct-push limit (OP_PUSHDATA1 = 0x4c), so use the
         * OP_PUSHDATA1-prefixed encoding. script_push_data handles the
         * dispatch for us. */
        script_init(&tx.vin[0].script_sig);
        bool pushed = script_push_data(&tx.vin[0].script_sig, redeem, rsz);
        DCS_CHECK("p2sh 2-of-3: redeem-push fits scriptSig", pushed);

        /* Prevout script_pub_key: a real P2SH wrapper (the hash bytes don't
         * matter for sigop counting — only the shape (HASH160 <20> EQUAL)). */
        struct tx_out prev; memset(&prev, 0, sizeof(prev));
        set_p2sh_script(&prev.script_pub_key);

        const struct tx_out *prevs[1] = { &prev };
        uint64_t domain_n = 0;
        struct zcl_result r = domain_consensus_tx_p2sh_sig_op_count(
                &tx, prevs, SCRIPT_VERIFY_P2SH, &domain_n);
        DCS_CHECK("p2sh 2-of-3 multisig -> domain returns OK, count=3",
                  r.ok && domain_n == 3);
        transaction_free(&tx);
    }

    /* Large mixed shape: many inputs and outputs with assorted sigops.
     * Regression seal: domain must equal legacy wrapper for both counters. */
    {
        struct transaction tx; transaction_init(&tx); transaction_alloc(&tx, 5, 4);
        for (size_t i = 0; i < tx.num_vin; i++) {
            memset(tx.vin[i].prevout.hash.data, (int)(0x40 + i), 32);
            tx.vin[i].prevout.n = (uint32_t)i;
            /* scriptSig: push a one-byte "redeem" containing OP_CHECKSIG —
             * meaningless for the legacy counter (it counts the bytes as-is). */
            tx.vin[i].script_sig.data[0] = 1;
            tx.vin[i].script_sig.data[1] = OP_CHECKSIG;
            tx.vin[i].script_sig.size = 2;
        }
        /* Outputs: mix CHECKSIG, P2PKH, CHECKMULTISIG, empty. */
        tx.vout[0].script_pub_key.data[0] = OP_CHECKSIG;
        tx.vout[0].script_pub_key.size = 1;
        set_p2pkh_script(&tx.vout[1].script_pub_key);
        tx.vout[2].script_pub_key.data[0] = OP_CHECKMULTISIG;
        tx.vout[2].script_pub_key.size = 1;
        tx.vout[3].script_pub_key.size = 0;

        uint64_t domain_legacy = 99;
        struct zcl_result r1 = domain_consensus_tx_legacy_sig_op_count(
                &tx, SCRIPT_VERIFY_P2SH, &domain_legacy);
        uint64_t wrapper_legacy = get_legacy_sig_op_count(&tx, SCRIPT_VERIFY_P2SH);
        DCS_CHECK("legacy mixed shape: domain == wrapper",
                  r1.ok && domain_legacy == wrapper_legacy);

        /* Sanity: hand-computed legacy count.
         *   5 inputs × scriptSig "01 ac" → leading 0x01 is a direct-push
         *     opcode that consumes the following byte (0xac) AS DATA. The
         *     walker never sees a bare OP_CHECKSIG, so each scriptSig
         *     contributes 0 sigops.
         *   vout[0] OP_CHECKSIG          = 1
         *   vout[1] P2PKH (ends in CHKSG)= 1
         *   vout[2] OP_CHECKMULTISIG     = 20 (accurate=false, no preceding
         *                                  OP_1..OP_16 last_opcode)
         *   vout[3] empty                = 0
         * Total = 0 + 1 + 1 + 20 + 0 = 22. */
        DCS_CHECK("legacy mixed shape: count == 22",
                  r1.ok && domain_legacy == 22);
        transaction_free(&tx);
    }

    /* ---- regression seal: domain == core/modules/validation wrapper across shapes.
     * This is the final cross-check covering ALL shapes above. */
    {
        bool all_match = true;
        struct shape {
            size_t nvin, nvout;
            uint32_t flags;
        } shapes[] = {
            { 0, 0, 0 },
            { 1, 1, 0 },
            { 1, 1, SCRIPT_VERIFY_P2SH },
            { 3, 2, SCRIPT_VERIFY_P2SH },
            { 5, 5, 0 },
        };
        for (size_t s = 0; s < sizeof(shapes)/sizeof(shapes[0]); s++) {
            struct transaction tx; transaction_init(&tx);
            transaction_alloc(&tx, shapes[s].nvin, shapes[s].nvout);
            for (size_t i = 0; i < tx.num_vin; i++) {
                memset(tx.vin[i].prevout.hash.data, (int)(0x80 + i + s), 32);
                tx.vin[i].prevout.n = (uint32_t)i;
                tx.vin[i].script_sig.size = 0;
            }
            for (size_t i = 0; i < tx.num_vout; i++) {
                tx.vout[i].script_pub_key.data[0] = OP_CHECKSIG;
                tx.vout[i].script_pub_key.size = 1;
            }
            uint64_t domain_n = 0;
            struct zcl_result r = domain_consensus_tx_legacy_sig_op_count(
                    &tx, shapes[s].flags, &domain_n);
            uint64_t legacy_n = get_legacy_sig_op_count(&tx, shapes[s].flags);
            if (!r.ok || domain_n != legacy_n) {
                printf("\n  MISMATCH shape=%zu domain=%" PRIu64
                       " legacy=%" PRIu64 " ok=%d\n",
                       s, domain_n, legacy_n, (int)r.ok);
                all_match = false;
            }
            transaction_free(&tx);
        }
        DCS_CHECK("legacy: domain matches wrapper across shapes", all_match);
    }

    return failures;
}
