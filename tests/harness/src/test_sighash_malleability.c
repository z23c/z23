/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Adversarial coverage of the signature-hash (sighash) computation and the
 * signature-/pubkey-encoding malleability rules. These tests PIN existing
 * consensus behaviour with negative cases; none of them change a predicate
 * in domain/consensus/src/sighash.c or core/modules/script/src/sigencoding.c.
 *
 * This complements, and deliberately does NOT duplicate:
 *   - test_domain_consensus_sighash.c (domain==legacy regression seal
 *     across the (sigver x base-type x ACP) matrix, nIn out-of-range /
 *     NOT_AN_INPUT contracts)
 *   - test_sighash_edge.c (SIGHASH_SINGLE sentinel asymmetry Sprout vs
 *     ZIP-143/243, SINGLE-commits-to-vout[nIn], ANYONECANPAY isolation,
 *     branch_id sensitivity, empty scriptCode/vout, value_balance
 *     Sapling-only commitment)
 *   - test_script.c (exhaustive strict-DER boundary vectors,
 *     check_pubkey_encoding STRICTENC shapes)
 *
 * NEW ground covered here:
 *   1. A direct pairwise-distinctness matrix: all six (base-type x ACP)
 *      sighash-type combinations produce SIX DIFFERENT hashes for the
 *      SAME transaction — a signature is bound to exactly its type, no
 *      cross-type collision.
 *   2. An end-to-end cross-type malleability attack: take a real
 *      signature computed under one sighash type, splice a DIFFERENT
 *      (still-DEFINED) type byte onto the SAME DER body in the
 *      scriptSig, and prove verify_script rejects it — the encoding gate
 *      accepts the spliced encoding structurally, but the checker's
 *      sighash recomputation (now over the new type) no longer matches
 *      the ECDSA signature, so CHECKSIG fails closed.
 *   3. Low-S enforcement with real, mathematically-valid signatures:
 *      ECDSA signature malleability (r, s) vs (r, n-s) are both valid
 *      for the same message/key. We negate a real signature's S value,
 *      confirm check_transaction_signature_encoding accepts it as valid
 *      DER but rejects it under SCRIPT_VERIFY_LOW_S, and confirm the
 *      SAME asymmetry end-to-end via verify_script (accepts without the
 *      flag, rejects with SCRIPT_ERR_SIG_HIGH_S with it) — proving BIP62
 *      malleability protection has teeth against a signature that is
 *      otherwise completely valid.
 *   4. STRICTENC hashtype-byte validation via the REAL trailing-byte
 *      path (check_transaction_signature_encoding), not just the
 *      accessor-level sighash_is_defined() unit checks.
 *   5. Replay-protection teeth: consensus_branch_id (ZIP-243 forkid) is
 *      bound into the checker; a signature valid under branch A does
 *      NOT verify when the checker is bound to branch B, end-to-end via
 *      verify_script + tx_sig_checker (the SAME real checker connect_block
 *      would use), not just the raw-hash sensitivity already pinned in
 *      test_sighash_edge.c.
 *
 * For each case the comment states how "teeth" were confirmed: either
 * the assertion covers BOTH branches of the predicate (accept the
 * canonical form, reject the malleated one) so flipping the predicate
 * flips one of the two outcomes, or the test walks a distinctness matrix
 * where collapsing any two type combinations would fail a pairwise
 * comparison.
 *
 * No consensus predicate is modified anywhere in this file.
 */

#include "test/test_core.h"

#include "keys/key.h"
#include "keys/pubkey.h"
#include "validation/sighash.h"
#include "validation/tx_verifier.h"

#include "core/uint256.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/script_flags.h"
#include "script/sighashtype.h"
#include "script/sigencoding.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SM_CHECK(name, expr) do { \
    printf("sighash_malleability: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ------------------------------------------------------------------
 * Transaction builder — deterministic P2PKH-shaped value carrier, same
 * shape as the sibling sighash test files (no shielded components).
 * ------------------------------------------------------------------ */
static struct transaction sm_build_tx(unsigned int n_vin, unsigned int n_vout,
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
    tx.vin = zcl_calloc(n_vin ? n_vin : 1, sizeof(struct tx_in), "sm_vin");
    for (unsigned int i = 0; i < n_vin; i++) {
        memset(tx.vin[i].prevout.hash.data, (int)(0xB0 + i), 32);
        tx.vin[i].prevout.n = i;
        uint8_t sig[] = {0x00, (uint8_t)i};
        script_set(&tx.vin[i].script_sig, sig, 2);
        tx.vin[i].sequence = 0xFFFFFFFFu - i;
    }

    tx.num_vout = n_vout;
    tx.vout = zcl_calloc(n_vout ? n_vout : 1, sizeof(struct tx_out), "sm_vout");
    for (unsigned int i = 0; i < n_vout; i++) {
        tx.vout[i].value = (int64_t)((i + 1) * 50000000LL);
        uint8_t pk[] = {0x76, 0xa9, 0x14, (uint8_t)(0x40 + i)};
        script_set(&tx.vout[i].script_pub_key, pk, 4);
    }
    return tx;
}

static void sm_free_tx(struct transaction *tx)
{
    free(tx->vin);
    free(tx->vout);
}

/* ------------------------------------------------------------------
 * secp256k1 group order, big-endian, and a plain 256-bit subtraction
 * n - a used to malleate a canonical low-S signature into its
 * mathematically-equivalent high-S twin: (r, s) and (r, n-s) both
 * satisfy the ECDSA verification equation for the same key/message.
 * This is the textbook BIP62 malleability the LOW_S rule guards
 * against — no secp256k1 API needed, just integer subtraction.
 * ------------------------------------------------------------------ */
static const unsigned char SM_SECP256K1_N[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};

static void sm_negate_mod_n(const unsigned char a[32], unsigned char out[32])
{
    int borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int diff = (int)SM_SECP256K1_N[i] - (int)a[i] - borrow;
        if (diff < 0) { diff += 256; borrow = 1; } else { borrow = 0; }
        out[i] = (unsigned char)diff;
    }
}

/* Parse one DER INTEGER (0x02 len bytes...) at *idx, writing its value
 * right-aligned into a 32-byte big-endian buffer (dropping a mandatory
 * leading 0x00 pad byte if len==33). Advances *idx past the field.
 * Trusts well-formed input (only ever fed our own freshly-generated
 * canonical DER from privkey_sign). */
static void sm_der_parse_int(const unsigned char *p, size_t *idx,
                             unsigned char val32[32])
{
    size_t i = *idx;
    size_t len = p[i + 1];
    const unsigned char *bytes = p + i + 2;
    memset(val32, 0, 32);
    size_t copy_len = len;
    const unsigned char *src = bytes;
    if (copy_len == 33) { copy_len = 32; src = bytes + 1; }
    memcpy(val32 + (32 - copy_len), src, copy_len);
    *idx = i + 2 + len;
}

/* Re-encode a 32-byte big-endian integer as a canonical minimal DER
 * INTEGER: strip leading zero bytes, then re-add exactly one 0x00 pad
 * iff the remaining high bit is set (mirrors is_valid_signature_encoding's
 * expectations bit-for-bit). Returns bytes written (<= 35). */
static size_t sm_der_encode_int(const unsigned char val32[32],
                                unsigned char *out)
{
    size_t lead = 0;
    while (lead < 31 && val32[lead] == 0) lead++;
    size_t vlen = 32 - lead;
    bool need_pad = (val32[lead] & 0x80) != 0;
    size_t total = vlen + (need_pad ? 1 : 0);
    out[0] = 0x02;
    out[1] = (unsigned char)total;
    size_t off = 2;
    if (need_pad) out[off++] = 0x00;
    memcpy(out + off, val32 + lead, vlen);
    return off + vlen;
}

static size_t sm_build_der_sig(const unsigned char r32[32],
                               const unsigned char s32[32],
                               unsigned char *out /* caller: >=72 bytes */)
{
    unsigned char rpart[35], spart[35];
    size_t rlen = sm_der_encode_int(r32, rpart);
    size_t slen = sm_der_encode_int(s32, spart);
    out[0] = 0x30;
    out[1] = (unsigned char)(rlen + slen);
    memcpy(out + 2, rpart, rlen);
    memcpy(out + 2 + rlen, spart, slen);
    return 2 + rlen + slen;
}

/* Sign `hash` and return BOTH a canonical low-S DER encoding and its
 * high-S malleated twin (same R, S negated mod the group order) — two
 * DIFFERENT byte strings, both mathematically valid ECDSA signatures
 * for the same (key, hash). Neither carries a trailing hashtype byte
 * yet (callers append it). Returns false only on signing failure. */
static bool sm_sign_and_malleate(const struct privkey *key,
                                 const struct uint256 *hash,
                                 unsigned char low_s[72], size_t *low_s_len,
                                 unsigned char high_s[72], size_t *high_s_len)
{
    size_t siglen = 72;
    if (!privkey_sign(key, hash, low_s, &siglen))
        return false;
    *low_s_len = siglen;

    size_t idx = 2; /* skip 0x30, total-len */
    unsigned char r32[32], s32[32], s32_neg[32];
    sm_der_parse_int(low_s, &idx, r32);
    sm_der_parse_int(low_s, &idx, s32);
    sm_negate_mod_n(s32, s32_neg);
    *high_s_len = sm_build_der_sig(r32, s32_neg, high_s);
    return true;
}

int test_sighash_malleability(void)
{
    int failures = 0;
    uint8_t p2pkh[] = {0x76, 0xa9, 0x14, 0x11, 0x22, 0x33, 0x44,
                       0x55, 0x88, 0xac};

    /* ==================================================================
     * 1. Pairwise sighash-type distinctness matrix. All six (base-type x
     *    ANYONECANPAY) combinations MUST hash to six DIFFERENT values for
     *    the identical transaction/input — proving a signature is bound
     *    to exactly the type it was made under. Teeth: if any two type
     *    combinations collapsed to the same digest, a signature made
     *    under one type would ALSO validate under the other (the classic
     *    cross-type malleability hole) and this loop's pairwise
     *    comparison would flip from "all distinct" to "collision found".
     * ================================================================== */
    {
        struct transaction tx =
            sm_build_tx(2, 3, true, 4, SAPLING_VERSION_GROUP_ID);
        struct script sc; script_set(&sc, p2pkh, sizeof(p2pkh));
        const uint32_t branch = 0x76b809bb;

        uint32_t raw_types[6] = {
            SIGHASH_ALL,
            SIGHASH_NONE,
            SIGHASH_SINGLE,
            SIGHASH_ALL    | SIGHASH_ANYONECANPAY,
            SIGHASH_NONE   | SIGHASH_ANYONECANPAY,
            SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
        };
        struct uint256 digests[6];
        bool ok = true;
        for (int i = 0; i < 6; i++) {
            struct sighash_type ht = { .raw = raw_types[i] };
            if (!signature_hash(&sc, &tx, 0, ht, 100000000, branch, NULL,
                                &digests[i]))
                ok = false;
        }
        int collisions = 0;
        for (int i = 0; ok && i < 6; i++)
            for (int j = i + 1; j < 6; j++)
                if (uint256_eq(&digests[i], &digests[j]))
                    collisions++;
        sm_free_tx(&tx);
        SM_CHECK("6-way sighash type matrix pairwise distinct (0 collisions)",
                 ok && collisions == 0);
    }

    /* Toggling ONLY the ANYONECANPAY bit on an otherwise-identical
     * SIGHASH_ALL request must change the hash (isolated from the base
     * type change tested above — this pins the bit in isolation). */
    {
        struct transaction tx =
            sm_build_tx(2, 2, false, 1, 0);
        struct script sc; script_set(&sc, p2pkh, sizeof(p2pkh));
        struct uint256 plain, acp;
        struct sighash_type ht_plain = { .raw = SIGHASH_ALL };
        struct sighash_type ht_acp   = { .raw = SIGHASH_ALL | SIGHASH_ANYONECANPAY };
        bool ok = signature_hash(&sc, &tx, 0, ht_plain, 0, 0, NULL, &plain)
               && signature_hash(&sc, &tx, 0, ht_acp,   0, 0, NULL, &acp);
        bool good = ok && !uint256_eq(&plain, &acp);
        sm_free_tx(&tx);
        SM_CHECK("flipping ANYONECANPAY bit alone changes the hash", good);
    }

    /* ==================================================================
     * 2. SIGHASH_SINGLE out-of-range special case (the classic "sighash
     *    returns constant 1" surface) — confirm the CURRENT, real
     *    accept/reject verdict on both sides of the Sprout/ZIP-243 split.
     *    (The exhaustive edge matrix, including the e2e uint256(1)-
     *    sentinel parity pin, lives in test_sighash_edge.c; this is a
     *    compact presence check so a regression here is caught even if
     *    that file is ever skipped/filtered.) Teeth: each assertion
     *    checks the OPPOSITE of what a naive "always succeed" or "always
     *    fail" stub would produce — Sprout must reject, Sapling must
     *    accept, so a predicate flip in either direction fails exactly
     *    one of these two checks.
     * ================================================================== */
    {
        /* 2 vin / 1 vout so nIn=1 is a VALID input index (< num_vin=2)
         * that is simultaneously >= num_vout=1 -- isolates the
         * SINGLE-vs-vout boundary from the separate nIn>=num_vin bound
         * checked earlier in domain_consensus_signature_hash(). */
        struct transaction tx = sm_build_tx(2, 1, false, 1, 0); /* Sprout */
        struct script sc; script_set(&sc, p2pkh, sizeof(p2pkh));
        struct sighash_type ht = { .raw = SIGHASH_SINGLE };
        struct uint256 r;
        bool rejected = !signature_hash(&sc, &tx, 1 /* == num_vout */, ht,
                                        0, 0, NULL, &r);
        sm_free_tx(&tx);
        SM_CHECK("sprout SIGHASH_SINGLE nIn>=num_vout: rejected (no sentinel)",
                  rejected);
    }
    {
        struct transaction tx =
            sm_build_tx(2, 1, true, 4, SAPLING_VERSION_GROUP_ID); /* ZIP-243 */
        struct script sc; script_set(&sc, p2pkh, sizeof(p2pkh));
        struct sighash_type ht = { .raw = SIGHASH_SINGLE };
        struct uint256 r;
        bool accepted = signature_hash(&sc, &tx, 1 /* == num_vout */, ht,
                                       100, 0x76b809bb, NULL, &r)
                     && !uint256_is_null(&r);
        sm_free_tx(&tx);
        SM_CHECK("sapling SIGHASH_SINGLE nIn>=num_vout: accepted (null digest)",
                  accepted);
    }

    /* ==================================================================
     * 3. Cross-type malleability, end-to-end. Sign a real P2PK spend
     *    under SIGHASH_ALL, then an attacker splices a DIFFERENT
     *    still-DEFINED type byte (SIGHASH_NONE) onto the identical DER
     *    body inside the scriptSig — no re-signing. The encoding gate
     *    (structural DER + defined-hashtype check) is satisfied either
     *    way, so this exercises the CHECKER's sighash recomputation, not
     *    just check_transaction_signature_encoding. verify_script MUST
     *    reject: the recomputed sighash for SIGHASH_NONE differs from
     *    the one actually signed, so ECDSA verify fails. Teeth: the
     *    control case (unmodified ALL-typed scriptSig) is asserted to
     *    SUCCEED with the identical checker/tx/flags — so if signature
     *    binding to the type byte were ever dropped, the spliced case
     *    would flip from reject to accept while the control stays
     *    accept, and this pair of asserts would diverge from expected.
     * ================================================================== */
    {
        struct privkey key;
        privkey_make_new(&key, true);
        struct pubkey pub;
        privkey_get_pubkey(&key, &pub);

        struct script spk; script_init(&spk);
        bool built = script_push_data(&spk, pub.vch, pub.size)
                  && script_push_op(&spk, OP_CHECKSIG);

        struct transaction tx =
            sm_build_tx(1, 1, true, 4, SAPLING_VERSION_GROUP_ID);
        const uint32_t branch = 0x76b809bb;
        const int64_t amount = 100000000;

        struct sighash_type ht_all = { .raw = SIGHASH_ALL };
        struct uint256 hash_all;
        bool ok = built &&
                  signature_hash(&spk, &tx, 0, ht_all, amount, branch, NULL,
                                &hash_all);

        unsigned char sig[72]; size_t siglen = sizeof(sig);
        ok = ok && privkey_sign(&key, &hash_all, sig, &siglen);
        if (siglen > sizeof(sig))
            ok = false;

        /* Control scriptSig: <sig || SIGHASH_ALL>. */
        struct script ssig_ctrl; script_init(&ssig_ctrl);
        unsigned char sig_all[73];
        if (ok) {
            memcpy(sig_all, sig, siglen);
            sig_all[siglen] = SIGHASH_ALL;
            ok = script_push_data(&ssig_ctrl, sig_all, siglen + 1);
        }

        /* Attack scriptSig: SAME DER body, trailing byte flipped to
         * SIGHASH_NONE (still a defined type, still valid DER+hashtype
         * shape — the encoding gate alone cannot catch this). */
        struct script ssig_attack; script_init(&ssig_attack);
        unsigned char sig_none[73];
        if (ok) {
            memcpy(sig_none, sig, siglen);
            sig_none[siglen] = SIGHASH_NONE;
            ok = script_push_data(&ssig_attack, sig_none, siglen + 1);
        }

        struct tx_sig_checker tsc;
        tx_sig_checker_init(&tsc, &tx, 0, amount, branch, NULL);
        struct sig_checker checker = tx_make_sig_checker(&tsc);

        ScriptError serr_ctrl = SCRIPT_ERR_OK, serr_attack = SCRIPT_ERR_OK;
        bool verdict_ctrl = ok && verify_script(&ssig_ctrl, &spk,
                                                SCRIPT_VERIFY_P2SH, &checker,
                                                branch, &serr_ctrl);
        bool verdict_attack = ok && verify_script(&ssig_attack, &spk,
                                                  SCRIPT_VERIFY_P2SH, &checker,
                                                  branch, &serr_attack);
        sm_free_tx(&tx);
        SM_CHECK("cross-type splice (ALL->NONE, same DER) rejected; "
                 "unmodified control accepted",
                 ok && verdict_ctrl && !verdict_attack);
    }

    /* ==================================================================
     * 4. Low-S enforcement against a REAL, mathematically-valid
     *    malleated signature. (r, s) and (r, n-s) both satisfy ECDSA
     *    verification for the same (key, hash) — this is the textbook
     *    BIP62 signature malleability the LOW_S consensus rule exists to
     *    close. We assert BOTH directions so a predicate flip in either
     *    is caught: canonical low-S is valid DER AND passes LOW_S;
     *    malleated high-S is STILL valid DER (structural check
     *    unaffected) but FAILS specifically with SCRIPT_ERR_SIG_HIGH_S
     *    once SCRIPT_VERIFY_LOW_S is set, and passes when it is not.
     * ================================================================== */
    {
        struct privkey key;
        privkey_make_new(&key, true);
        struct uint256 hash;
        memset(hash.data, 0x42, 32);

        unsigned char low_s[72], high_s[72];
        size_t low_s_len = 0, high_s_len = 0;
        bool ok = sm_sign_and_malleate(&key, &hash, low_s, &low_s_len,
                                       high_s, &high_s_len);

        /* Sanity: the malleated signature is DIFFERENT bytes from the
         * original (else the negation math above is a no-op bug). */
        bool different_bytes = ok &&
            (low_s_len != high_s_len ||
             memcmp(low_s, high_s, low_s_len) != 0);

        unsigned char low_s_tx[73], high_s_tx[73];
        if (ok) {
            memcpy(low_s_tx, low_s, low_s_len);
            low_s_tx[low_s_len] = SIGHASH_ALL;
            memcpy(high_s_tx, high_s, high_s_len);
            high_s_tx[high_s_len] = SIGHASH_ALL;
        }

        ScriptError e1 = SCRIPT_ERR_OK, e2 = SCRIPT_ERR_OK, e3 = SCRIPT_ERR_OK;
        bool low_s_low_flag  = ok && check_transaction_signature_encoding(
            low_s_tx, low_s_len + 1, SCRIPT_VERIFY_LOW_S, &e1);
        bool high_s_low_flag = ok && check_transaction_signature_encoding(
            high_s_tx, high_s_len + 1, SCRIPT_VERIFY_LOW_S, &e2);
        bool high_s_no_flag  = ok && check_transaction_signature_encoding(
            high_s_tx, high_s_len + 1, SCRIPT_VERIFY_NONE, &e3);
        /* DER structure alone (no LOW_S, no STRICTENC) still accepts the
         * malleated form -- only the LOW_S bit gates it. */
        (void)e3;

        SM_CHECK("low-S encoding: canonical accepted under LOW_S",
                 low_s_low_flag && e1 == SCRIPT_ERR_OK);
        SM_CHECK("low-S encoding: malleated high-S REJECTED under LOW_S "
                 "(SCRIPT_ERR_SIG_HIGH_S)",
                 ok && !high_s_low_flag && e2 == SCRIPT_ERR_SIG_HIGH_S);
        SM_CHECK("low-S encoding: malleated high-S ACCEPTED without LOW_S "
                 "(DER structurally valid either way)",
                 high_s_no_flag);
        SM_CHECK("low-S encoding: malleation actually changed the bytes",
                 different_bytes);

        /* End-to-end: same asymmetry through the real script VM and a
         * real P2PK output, using the malleated high-S signature. */
        struct pubkey pub;
        privkey_get_pubkey(&key, &pub);
        struct script spk; script_init(&spk);
        bool built = ok && script_push_data(&spk, pub.vch, pub.size)
                        && script_push_op(&spk, OP_CHECKSIG);

        struct transaction tx = sm_build_tx(1, 1, true, 4,
                                            SAPLING_VERSION_GROUP_ID);
        const uint32_t branch = 0x76b809bb;
        struct sighash_type ht_all = { .raw = SIGHASH_ALL };
        struct uint256 real_hash;
        bool ok2 = built &&
                   signature_hash(&spk, &tx, 0, ht_all, 100000000, branch,
                                 NULL, &real_hash);

        unsigned char e2e_low[72], e2e_high[72];
        size_t e2e_low_len = 0, e2e_high_len = 0;
        ok2 = ok2 && sm_sign_and_malleate(&key, &real_hash,
                                         e2e_low, &e2e_low_len,
                                         e2e_high, &e2e_high_len);

        struct script ssig_high; script_init(&ssig_high);
        if (ok2) {
            unsigned char buf[73];
            memcpy(buf, e2e_high, e2e_high_len);
            buf[e2e_high_len] = SIGHASH_ALL;
            ok2 = script_push_data(&ssig_high, buf, e2e_high_len + 1);
        }

        struct tx_sig_checker tsc;
        tx_sig_checker_init(&tsc, &tx, 0, 100000000, branch, NULL);
        struct sig_checker checker = tx_make_sig_checker(&tsc);

        ScriptError serr_flag = SCRIPT_ERR_OK, serr_noflag = SCRIPT_ERR_OK;
        bool verdict_with_flag = ok2 && verify_script(
            &ssig_high, &spk, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_LOW_S,
            &checker, branch, &serr_flag);
        bool verdict_no_flag = ok2 && verify_script(
            &ssig_high, &spk, SCRIPT_VERIFY_P2SH,
            &checker, branch, &serr_noflag);

        sm_free_tx(&tx);
        SM_CHECK("e2e: high-S malleated signature REJECTED with LOW_S flag "
                 "(SCRIPT_ERR_SIG_HIGH_S)",
                 ok2 && !verdict_with_flag && serr_flag == SCRIPT_ERR_SIG_HIGH_S);
        SM_CHECK("e2e: SAME high-S signature ACCEPTED without LOW_S flag "
                 "(mathematically valid ECDSA signature either way)",
                 ok2 && verdict_no_flag);
    }

    /* ==================================================================
     * 5. STRICTENC hashtype-byte validation on the REAL trailing-byte
     *    path. A DER-valid signature with an UNDEFINED trailing type
     *    byte (e.g. 0x00 or 0x07) must be rejected with
     *    SCRIPT_ERR_SIG_HASHTYPE when SCRIPT_VERIFY_STRICTENC is set,
     *    and accepted (DER-valid, type not checked) when it is clear.
     *    Teeth: both directions asserted on the byte-identical input —
     *    only the flag differs — so a predicate flip in either
     *    direction (always-reject or always-accept regardless of the
     *    flag) fails one of the two checks.
     * ================================================================== */
    {
        struct privkey key;
        privkey_make_new(&key, true);
        struct uint256 hash;
        memset(hash.data, 0x77, 32);
        unsigned char sig[72]; size_t siglen = sizeof(sig);
        bool ok = privkey_sign(&key, &hash, sig, &siglen);

        unsigned char sig_undefined[73], sig_defined[73];
        if (ok) {
            memcpy(sig_undefined, sig, siglen);
            sig_undefined[siglen] = 0x07; /* not ALL/NONE/SINGLE(|ACP) */
            memcpy(sig_defined, sig, siglen);
            sig_defined[siglen] = SIGHASH_SINGLE | SIGHASH_ANYONECANPAY;
        }

        ScriptError e1 = SCRIPT_ERR_OK, e2 = SCRIPT_ERR_OK, e3 = SCRIPT_ERR_OK;
        bool undefined_strict = ok && check_transaction_signature_encoding(
            sig_undefined, siglen + 1, SCRIPT_VERIFY_STRICTENC, &e1);
        bool undefined_loose  = ok && check_transaction_signature_encoding(
            sig_undefined, siglen + 1, SCRIPT_VERIFY_NONE, &e2);
        bool defined_strict   = ok && check_transaction_signature_encoding(
            sig_defined, siglen + 1, SCRIPT_VERIFY_STRICTENC, &e3);

        SM_CHECK("STRICTENC rejects undefined hashtype byte "
                 "(SCRIPT_ERR_SIG_HASHTYPE)",
                 ok && !undefined_strict && e1 == SCRIPT_ERR_SIG_HASHTYPE);
        SM_CHECK("undefined hashtype byte accepted when STRICTENC is clear "
                 "(DER structure alone still valid)",
                 undefined_loose);
        SM_CHECK("STRICTENC accepts a defined type (SINGLE|ACP)",
                 defined_strict && e3 == SCRIPT_ERR_OK);
    }

    /* ==================================================================
     * 6. Replay protection (ZIP-243 consensus_branch_id / forkid) has
     *    teeth end-to-end. Sign for branch A, verify with a REAL
     *    tx_sig_checker bound to branch B (mismatched) via the same
     *    checker connect_block uses — the checker recomputes the
     *    sighash with ITS OWN bound branch_id (check_sig_cb ignores the
     *    branch_id argument passed by the script VM and always uses
     *    tsc->consensus_branch_id), so a signature valid on one branch
     *    must NOT verify against another. Teeth: the matched-branch
     *    control is asserted to SUCCEED with the identical signature/tx,
     *    so only the branch_id differs between the two verdicts.
     * ================================================================== */
    {
        struct privkey key;
        privkey_make_new(&key, true);
        struct pubkey pub;
        privkey_get_pubkey(&key, &pub);
        struct script spk; script_init(&spk);
        bool built = script_push_data(&spk, pub.vch, pub.size)
                  && script_push_op(&spk, OP_CHECKSIG);

        struct transaction tx =
            sm_build_tx(1, 1, true, 4, SAPLING_VERSION_GROUP_ID);
        const int64_t amount = 100000000;
        const uint32_t branch_a = 0x76b809bb; /* Sapling mainnet branch id */
        const uint32_t branch_b = 0x5ba81b19; /* Overwinter branch id — wrong fork */

        struct sighash_type ht_all = { .raw = SIGHASH_ALL };
        struct uint256 hash_a;
        bool ok = built && signature_hash(&spk, &tx, 0, ht_all, amount,
                                          branch_a, NULL, &hash_a);

        unsigned char sig[72]; size_t siglen = sizeof(sig);
        ok = ok && privkey_sign(&key, &hash_a, sig, &siglen);

        struct script ssig; script_init(&ssig);
        unsigned char sig_tx[73];
        if (ok) {
            memcpy(sig_tx, sig, siglen);
            sig_tx[siglen] = SIGHASH_ALL;
            ok = script_push_data(&ssig, sig_tx, siglen + 1);
        }

        struct tx_sig_checker tsc_match, tsc_mismatch;
        tx_sig_checker_init(&tsc_match, &tx, 0, amount, branch_a, NULL);
        tx_sig_checker_init(&tsc_mismatch, &tx, 0, amount, branch_b, NULL);
        struct sig_checker checker_match = tx_make_sig_checker(&tsc_match);
        struct sig_checker checker_mismatch = tx_make_sig_checker(&tsc_mismatch);

        ScriptError serr_match = SCRIPT_ERR_OK, serr_mismatch = SCRIPT_ERR_OK;
        bool verdict_match = ok && verify_script(&ssig, &spk,
                                                 SCRIPT_VERIFY_P2SH,
                                                 &checker_match, branch_a,
                                                 &serr_match);
        bool verdict_mismatch = ok && verify_script(&ssig, &spk,
                                                    SCRIPT_VERIFY_P2SH,
                                                    &checker_mismatch, branch_a,
                                                    &serr_mismatch);
        sm_free_tx(&tx);
        SM_CHECK("replay protection: signature valid on branch_a verifies "
                 "against a branch_a-bound checker",
                 ok && verdict_match);
        SM_CHECK("replay protection: SAME signature does NOT verify against "
                 "a branch_b-bound checker (wrong forkid)",
                 ok && !verdict_mismatch);
    }

    return failures;
}
