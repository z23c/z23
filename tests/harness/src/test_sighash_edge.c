/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * NET-NEW consensus edge-case tests for the transaction signature-hash
 * computation (domain/consensus/sighash.c, exposed via
 * validation/sighash.h:signature_hash). These complement — and do NOT
 * duplicate — test_domain_consensus_sighash.c, which pins the
 * legacy==domain regression seal across the (sigver x base x ACP)
 * matrix and the basic out-of-range/NOT_AN_INPUT contracts.
 *
 * The signature hash is the message a signature commits to. If two
 * builds of the node disagree on it, or if it silently stops committing
 * to a field, the chain forks (every spend either re-signs or rejects).
 * So the cases below pin BEHAVIOUR (verdict and commitment), not just
 * "domain matches legacy":
 *
 *   1. SIGHASH_SINGLE sentinel asymmetry. In legacy Bitcoin/Sprout the
 *      classic SIGHASH_SINGLE bug returns the constant hash uint256(1)
 *      when nIn >= num_vout. This node instead REJECTS that case in the
 *      Sprout regime (returns false) — matching zclassicd bug-for-bug,
 *      which throws (zclassic-cpp interpreter.cpp:1158-1163, no sentinel)
 *      and catches to false in CheckSig (:1197-1202). The ZIP-243 Sapling
 *      regime does NOT reject it — it commits to a NULL outputs digest
 *      and succeeds. That asymmetry is consensus-load-bearing and must
 *      be pinned on both sides, including the nasty num_vout==0
 *      boundary, plus an end-to-end verify_script pin (1b-e2e) proving
 *      the reject is observably IDENTICAL to zclassicd's catch->false.
 *   2. SIGHASH_SINGLE commits to exactly vout[nIn] (Sapling). Mutating
 *      the matched output changes the hash; mutating a different output
 *      does NOT. (The whole point of SINGLE.)
 *   3. ANYONECANPAY isolates the signed input (Sprout). Mutating a
 *      different input's prevout/sequence must not change the hash;
 *      mutating the signed input must.
 *   4. consensus_branch_id is mixed into the ZIP-243 personalization
 *      (cross-fork replay protection). A different branch id => a
 *      different hash for an otherwise-identical tx.
 *   5. Empty scriptCode (size 0) is committed with a 0x00 varint length
 *      and is distinct from a 1-byte scriptCode (Sapling).
 *   6. Empty vout (num_vout==0) with SIGHASH_ALL is a valid degenerate
 *      tx (shielded-only / value carrier) and yields a deterministic,
 *      non-null hash without crashing — across all three sig versions.
 *   7. value_balance is committed only in Sapling (ZIP-243), not in
 *      Overwinter (ZIP-143): changing it flips the Sapling hash but
 *      leaves the Overwinter hash untouched.
 *
 * Every case invokes the real consensus function (signature_hash) and
 * asserts the correct verdict, so a regression actually fails the test.
 * Deterministic, no network, no node process.
 */

#include "test/test_core.h"

#include "validation/sighash.h"
#include "validation/tx_verifier.h"

#include "core/uint256.h"
#include "keys/key.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/sighashtype.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHE_CHECK(name, expr) do { \
    printf("sighash_edge: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Build a transparent value-carrier tx with n_vin inputs / n_vout
 * outputs, deterministic bytes throughout. Allocates at least one slot
 * for each vector even when the logical count is 0, so the buffer
 * pointer stays valid (the consensus code iterates by num_*, never
 * touching the spare slot). No shielded components. */
static struct transaction she_build_tx(unsigned int n_vin, unsigned int n_vout,
                                       bool overwintered, uint32_t version,
                                       uint32_t version_group_id)
{
    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = version;
    tx.overwintered = overwintered;
    tx.version_group_id = version_group_id;
    tx.lock_time = 0;
    tx.expiry_height = overwintered ? 1000 : 0;
    tx.value_balance = 0;

    tx.num_vin = n_vin;
    tx.vin = zcl_calloc(n_vin ? n_vin : 1, sizeof(struct tx_in), "she_vin");
    for (unsigned int i = 0; i < n_vin; i++) {
        memset(tx.vin[i].prevout.hash.data, (int)(0xA0 + i), 32);
        tx.vin[i].prevout.n = i;
        uint8_t sig[] = {0x00, (uint8_t)i};
        script_set(&tx.vin[i].script_sig, sig, 2);
        tx.vin[i].sequence = 0xFFFFFFFFu - i;
    }

    tx.num_vout = n_vout;
    tx.vout = zcl_calloc(n_vout ? n_vout : 1, sizeof(struct tx_out), "she_vout");
    for (unsigned int i = 0; i < n_vout; i++) {
        tx.vout[i].value = (int64_t)((i + 1) * 100000000LL);
        uint8_t pk[] = {0x76, 0xa9, 0x14, (uint8_t)i};
        script_set(&tx.vout[i].script_pub_key, pk, 4);
    }
    return tx;
}

static void she_free_tx(struct transaction *tx)
{
    free(tx->vin);
    free(tx->vout);
}

/* Convenience: compute one sighash, returning the bool verdict and the
 * 32-byte result by out-param. Exercises the no-cache path (the cache
 * path is already pinned bit-for-bit by the sibling test). */
static bool she_sig(const struct script *sc, const struct transaction *tx,
                    unsigned int nIn, uint32_t raw_type, int64_t amount,
                    uint32_t branch_id, struct uint256 *out)
{
    struct sighash_type ht = { .raw = raw_type };
    return signature_hash(sc, tx, nIn, ht, amount, branch_id, NULL, out);
}

int test_sighash_edge(void)
{
    int failures = 0;

    /* A representative P2PKH-style scriptCode reused by most cases. */
    uint8_t p2pkh[] = {0x76, 0xa9, 0x14, 0x11, 0x22, 0x33, 0x44,
                       0x55, 0x88, 0xac};

    /* ====================================================================
     * 1. SIGHASH_SINGLE sentinel asymmetry (the classic SIGHASH_SINGLE
     *    bug surface). Sprout rejects nIn>=num_vout; Sapling accepts and
     *    commits to a null outputs digest.
     * ================================================================== */

    /* 1a. Sprout, plain SINGLE, nIn (=1) >= num_vout (=1): REJECTED.
     *     (Already covered by the sibling test for nIn=1; here we also
     *     nail the most adversarial boundary: nIn=0, num_vout=0 below.) */
    {
        struct transaction tx = she_build_tx(2, 1, false, 1, 0);
        struct script sc; script_set(&sc, p2pkh, sizeof(p2pkh));
        struct uint256 r;
        bool rejected = !she_sig(&sc, &tx, 1, SIGHASH_SINGLE, 0, 0, &r);
        she_free_tx(&tx);
        SHE_CHECK("sprout SINGLE nIn(1)>=num_vout(1) rejected", rejected);
    }

    /* 1b. Sprout, SINGLE | ANYONECANPAY, nIn=0 with num_vout=0: the
     *     historical "return uint256(1)" trigger. This node REJECTS it
     *     (consensus contract violation), and the ACP bit must not let
     *     it slip through. */
    {
        struct transaction tx = she_build_tx(1, 0, false, 1, 0);
        struct script sc; script_set(&sc, p2pkh, sizeof(p2pkh));
        struct uint256 r;
        bool rejected =
            !she_sig(&sc, &tx, 0,
                     SIGHASH_SINGLE | SIGHASH_ANYONECANPAY, 0, 0, &r);
        she_free_tx(&tx);
        SHE_CHECK("sprout SINGLE+ACP nIn=0 num_vout=0 rejected (no sentinel)",
                  rejected);
    }

    /* 1b-e2e. zclassicd parity pin — DO NOT "FIX" the reject into
     *     Bitcoin's uint256(1) sentinel. zclassicd THROWS logic_error at
     *     zclassic-cpp/src/script/interpreter.cpp:1158-1163 (Zcash
     *     deleted the one-hash sentinel); CheckSig catches it at
     *     :1197-1202 and returns false, so OP_CHECKSIG pushes false and
     *     the script fails EVAL_FALSE — indistinguishable from any bad
     *     signature. This case proves the c23 LOG_FAIL→false path lands
     *     on the SAME observable verdict: a Sprout 1-vin/0-vout tx
     *     spending a P2PK output, signed with SIGHASH_SINGLE over the
     *     would-be sentinel hash uint256(1), must fail verify_script
     *     with SCRIPT_ERR_EVAL_FALSE (push-false, not an abort). If a
     *     future "fix" makes signature_hash return uint256(1)+true, the
     *     signature below VERIFIES, OP_CHECKSIG pushes true, and this
     *     test FAILS — implementing the sentinel forks from zclassicd. */
    {
        struct privkey key;
        privkey_make_new(&key, true);
        struct pubkey pub;
        privkey_get_pubkey(&key, &pub);

        /* P2PK prevout scriptPubKey: <pubkey> OP_CHECKSIG. */
        struct script spk; script_init(&spk);
        bool ok = script_push_data(&spk, pub.vch, pub.size)
               && script_push_op(&spk, OP_CHECKSIG);

        /* Sprout tx, 1 vin / 0 vout: the SIGHASH_SINGLE trigger. */
        struct transaction tx = she_build_tx(1, 0, false, 1, 0);

        /* Sign the would-be sentinel hash uint256(1). Under the
         * sentinel this signature would verify (zclassicd would still
         * reject the tx); under the parity reject the sighash is never
         * produced, so the signature cannot matter. */
        struct uint256 one;
        uint256_set_null(&one);
        one.data[0] = 0x01;
        unsigned char sig[80];
        size_t siglen = sizeof(sig);
        ok = ok && privkey_sign(&key, &one, sig, &siglen) && siglen <= 72;

        /* scriptSig: <DER sig || hashtype byte>. */
        struct script ssig; script_init(&ssig);
        if (ok) {
            sig[siglen++] = SIGHASH_SINGLE;
            ok = script_push_data(&ssig, sig, siglen);
        }

        struct tx_sig_checker tsc;
        tx_sig_checker_init(&tsc, &tx, 0, 0 /* amount: Sprout ignores */,
                            0 /* branch_id: Sprout ignores */, NULL);
        struct sig_checker checker = tx_make_sig_checker(&tsc);

        ScriptError serr = SCRIPT_ERR_OK;
        bool verdict = verify_script(&ssig, &spk,
                                     SCRIPT_VERIFY_P2SH |
                                     SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
                                     &checker, 0, &serr);
        she_free_tx(&tx);
        SHE_CHECK("sprout SINGLE e2e: verify_script false + EVAL_FALSE "
                  "(zclassicd parity, no uint256(1) sentinel)",
                  ok && !verdict && serr == SCRIPT_ERR_EVAL_FALSE);
    }

    /* 1c. Sapling (ZIP-243), plain SINGLE, nIn=1 >= num_vout=1: NOT
     *     rejected. The ZIP-243 path falls through to a null outputs
     *     digest and SUCCEEDS, producing a well-defined non-null hash.
     *     This asymmetry vs Sprout is the load-bearing fact. */
    {
        struct transaction tx =
            she_build_tx(2, 1, true, 4, SAPLING_VERSION_GROUP_ID);
        struct script sc; script_set(&sc, p2pkh, sizeof(p2pkh));
        struct uint256 r;
        bool ok = she_sig(&sc, &tx, 1, SIGHASH_SINGLE, 100, 0x76b809bb, &r);
        ok = ok && !uint256_is_null(&r);
        she_free_tx(&tx);
        SHE_CHECK("sapling SINGLE nIn>=num_vout accepted (null outputs digest)",
                  ok);
    }

    /* 1d. Overwinter (ZIP-143) shares the no-reject behaviour: SINGLE
     *     with nIn>=num_vout succeeds (null outputs digest). */
    {
        struct transaction tx =
            she_build_tx(2, 1, true, 3, OVERWINTER_VERSION_GROUP_ID);
        struct script sc; script_set(&sc, p2pkh, sizeof(p2pkh));
        struct uint256 r;
        bool ok = she_sig(&sc, &tx, 1, SIGHASH_SINGLE, 100, 0x5ba81b19, &r);
        ok = ok && !uint256_is_null(&r);
        she_free_tx(&tx);
        SHE_CHECK("overwinter SINGLE nIn>=num_vout accepted (null outputs)",
                  ok);
    }

    /* ====================================================================
     * 2. SIGHASH_SINGLE commits to EXACTLY vout[nIn] (Sapling). Changing
     *    the matched output changes the hash; changing a DIFFERENT output
     *    does not. This is the defining property of SINGLE.
     * ================================================================== */
    {
        /* 2 vin, 3 vout; sign input nIn=1 -> must commit only to vout[1]. */
        struct script sc; script_set(&sc, p2pkh, sizeof(p2pkh));
        const unsigned int nIn = 1;

        struct transaction tx =
            she_build_tx(2, 3, true, 4, SAPLING_VERSION_GROUP_ID);
        struct uint256 base, mut_match, mut_other;
        bool ok = she_sig(&sc, &tx, nIn, SIGHASH_SINGLE, 0, 0x76b809bb, &base);

        /* Mutate the MATCHED output (vout[1]) -> hash MUST change. */
        tx.vout[nIn].value += 1;
        ok = ok && she_sig(&sc, &tx, nIn, SIGHASH_SINGLE, 0, 0x76b809bb,
                           &mut_match);
        tx.vout[nIn].value -= 1; /* restore */

        /* Mutate a DIFFERENT output (vout[2]) -> hash MUST NOT change. */
        tx.vout[2].value += 1;
        ok = ok && she_sig(&sc, &tx, nIn, SIGHASH_SINGLE, 0, 0x76b809bb,
                           &mut_other);
        tx.vout[2].value -= 1;

        bool good = ok && !uint256_eq(&base, &mut_match)
                       && uint256_eq(&base, &mut_other);
        she_free_tx(&tx);
        SHE_CHECK("sapling SINGLE commits to vout[nIn] only", good);
    }

    /* ====================================================================
     * 3. ANYONECANPAY isolates the signed input (Sprout). Mutating a
     *    different input's prevout/sequence must NOT change the hash;
     *    mutating the signed input MUST.
     * ================================================================== */
    {
        struct script sc; script_set(&sc, p2pkh, sizeof(p2pkh));
        const unsigned int nIn = 0;
        const uint32_t ht = SIGHASH_ALL | SIGHASH_ANYONECANPAY;

        struct transaction tx = she_build_tx(3, 2, false, 1, 0);
        struct uint256 base, mut_other_in, mut_signed_in;
        bool ok = she_sig(&sc, &tx, nIn, ht, 0, 0, &base);

        /* Mutate a DIFFERENT input (vin[2]) -> ACP must ignore it. */
        tx.vin[2].sequence ^= 0xFFFFFFFFu;
        tx.vin[2].prevout.n ^= 0xFF;
        ok = ok && she_sig(&sc, &tx, nIn, ht, 0, 0, &mut_other_in);
        tx.vin[2].sequence ^= 0xFFFFFFFFu;
        tx.vin[2].prevout.n ^= 0xFF;

        /* Mutate the SIGNED input (vin[0]) -> hash must change. */
        tx.vin[nIn].sequence ^= 0x1;
        ok = ok && she_sig(&sc, &tx, nIn, ht, 0, 0, &mut_signed_in);
        tx.vin[nIn].sequence ^= 0x1;

        bool good = ok && uint256_eq(&base, &mut_other_in)
                       && !uint256_eq(&base, &mut_signed_in);
        she_free_tx(&tx);
        SHE_CHECK("sprout ANYONECANPAY isolates the signed input", good);
    }

    /* ====================================================================
     * 4. consensus_branch_id is mixed into the ZIP-243 personalization
     *    (cross-fork replay protection). A different branch id => a
     *    different Sapling hash for an otherwise-identical tx. Sprout, by
     *    contrast, ignores branch_id entirely (legacy double-SHA256).
     * ================================================================== */
    {
        struct script sc; script_set(&sc, p2pkh, sizeof(p2pkh));

        struct transaction tx =
            she_build_tx(1, 1, true, 4, SAPLING_VERSION_GROUP_ID);
        struct uint256 a, b;
        bool ok = she_sig(&sc, &tx, 0, SIGHASH_ALL, 50, 0x76b809bb, &a)
               && she_sig(&sc, &tx, 0, SIGHASH_ALL, 50, 0x2bb40e60, &b);
        bool good = ok && !uint256_eq(&a, &b);
        she_free_tx(&tx);
        SHE_CHECK("sapling hash depends on consensus_branch_id", good);
    }
    {
        /* Sprout: branch_id is not part of the message at all. */
        struct script sc; script_set(&sc, p2pkh, sizeof(p2pkh));
        struct transaction tx = she_build_tx(1, 1, false, 1, 0);
        struct uint256 a, b;
        bool ok = she_sig(&sc, &tx, 0, SIGHASH_ALL, 50, 0x00000000, &a)
               && she_sig(&sc, &tx, 0, SIGHASH_ALL, 50, 0xdeadbeef, &b);
        bool good = ok && uint256_eq(&a, &b);
        she_free_tx(&tx);
        SHE_CHECK("sprout hash ignores consensus_branch_id", good);
    }

    /* ====================================================================
     * 5. Empty scriptCode (size 0) is a distinct committed value vs a
     *    1-byte scriptCode (Sapling). Pins the 0x00 varint length-prefix
     *    branch of the script_code serialization.
     * ================================================================== */
    {
        struct transaction tx =
            she_build_tx(1, 1, true, 4, SAPLING_VERSION_GROUP_ID);

        struct script empty; script_init(&empty);          /* size 0 */
        struct script one;  { uint8_t b = 0x51; script_set(&one, &b, 1); }

        struct uint256 r_empty, r_one;
        bool ok = she_sig(&empty, &tx, 0, SIGHASH_ALL, 100, 0x76b809bb, &r_empty)
               && she_sig(&one,   &tx, 0, SIGHASH_ALL, 100, 0x76b809bb, &r_one);
        bool good = ok && !uint256_is_null(&r_empty)
                       && !uint256_eq(&r_empty, &r_one);
        she_free_tx(&tx);
        SHE_CHECK("sapling empty scriptCode accepted and distinct from 1-byte",
                  good);
    }

    /* ====================================================================
     * 6. Empty vout (num_vout==0) with SIGHASH_ALL is a valid degenerate
     *    tx. Must yield a deterministic, non-null hash without crashing,
     *    across all three sig versions.
     * ================================================================== */
    {
        struct {
            const char *label;
            bool overwintered; uint32_t version; uint32_t vgi; uint32_t branch;
        } vs[] = {
            { "sprout",     false, 1, 0,                           0          },
            { "overwinter", true,  3, OVERWINTER_VERSION_GROUP_ID, 0x5ba81b19 },
            { "sapling",    true,  4, SAPLING_VERSION_GROUP_ID,    0x76b809bb },
        };
        struct script sc; script_set(&sc, p2pkh, sizeof(p2pkh));
        bool good = true;
        for (unsigned int v = 0; v < 3; v++) {
            struct transaction tx = she_build_tx(1, 0, vs[v].overwintered,
                                                 vs[v].version, vs[v].vgi);
            struct uint256 r1, r2;
            bool ok = she_sig(&sc, &tx, 0, SIGHASH_ALL, 25, vs[v].branch, &r1)
                   && she_sig(&sc, &tx, 0, SIGHASH_ALL, 25, vs[v].branch, &r2);
            if (!ok || uint256_is_null(&r1) || !uint256_eq(&r1, &r2)) {
                printf("\n  empty-vout failed for %s ", vs[v].label);
                good = false;
            }
            she_free_tx(&tx);
        }
        SHE_CHECK("empty vout SIGHASH_ALL: deterministic non-null all versions",
                  good);
    }

    /* ====================================================================
     * 7. value_balance is committed in Sapling (ZIP-243) but NOT in
     *    Overwinter (ZIP-143). Changing it flips the Sapling hash and
     *    leaves the Overwinter hash unchanged. This guards against the
     *    two regimes being collapsed into one serialization.
     * ================================================================== */
    {
        struct script sc; script_set(&sc, p2pkh, sizeof(p2pkh));

        /* Sapling: value_balance is in the digest. */
        struct transaction txs =
            she_build_tx(1, 1, true, 4, SAPLING_VERSION_GROUP_ID);
        struct uint256 s0, s1;
        txs.value_balance = 0;
        bool ok = she_sig(&sc, &txs, 0, SIGHASH_ALL, 100, 0x76b809bb, &s0);
        txs.value_balance = 1234567;
        ok = ok && she_sig(&sc, &txs, 0, SIGHASH_ALL, 100, 0x76b809bb, &s1);
        bool sapling_sensitive = ok && !uint256_eq(&s0, &s1);
        she_free_tx(&txs);

        /* Overwinter: value_balance is NOT serialized -> hash unchanged. */
        struct transaction txo =
            she_build_tx(1, 1, true, 3, OVERWINTER_VERSION_GROUP_ID);
        struct uint256 o0, o1;
        txo.value_balance = 0;
        bool ok2 = she_sig(&sc, &txo, 0, SIGHASH_ALL, 100, 0x5ba81b19, &o0);
        txo.value_balance = 1234567;
        ok2 = ok2 && she_sig(&sc, &txo, 0, SIGHASH_ALL, 100, 0x5ba81b19, &o1);
        bool overwinter_insensitive = ok2 && uint256_eq(&o0, &o1);
        she_free_tx(&txo);

        SHE_CHECK("value_balance committed in sapling but not overwinter",
                  sapling_sensitive && overwinter_insensitive);
    }

    return failures;
}
