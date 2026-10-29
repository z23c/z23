/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Unit tests for domain/consensus/sighash.{c,h}.
 *
 * Pins the pure signature-hash computation, exercising the typed domain API
 * directly and cross-checking against the legacy wrapper
 * (validation/sighash.h).
 *
 * Coverage:
 *   - edge cases (nIn out of range; NOT_AN_INPUT accepted; SIGHASH_SINGLE
 *     with nIn >= num_vout in the Sprout regime)
 *   - signature_hash_version: Sprout / Overwinter / Sapling routing
 *   - precompute_tx_data: domain vs legacy byte-for-byte
 *   - signature_hash regression seal over P2PKH-style shapes, all three sig
 *     versions, hash types {ALL, NONE, SINGLE} x {plain, ANYONECANPAY} x
 *     multiple inputs.
 *   - sighash_overwinter_sapling and sighash_sprout, driven through
 *     domain_consensus_signature_hash: JoinSplit commitment and version
 *     gate, Sapling shielded commitments, scriptCode varint lengths,
 *     other-input sequence under NONE/ALL.
 */

#include "test/test_core.h"

#include "domain/consensus/sighash.h"
#include "validation/sighash.h"

#include "core/uint256.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/sighashtype.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DCS_CHECK(name, expr) do { \
    printf("domain_consensus_sighash: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Build a deterministic transaction with `n_vin` inputs and `n_vout`
 * outputs (no shielded components). */
static struct transaction build_tx(unsigned int n_vin, unsigned int n_vout,
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
    tx.vin = zcl_calloc(n_vin, sizeof(struct tx_in), "dcsh_tx_vin");
    for (unsigned int i = 0; i < n_vin; i++) {
        memset(tx.vin[i].prevout.hash.data, (int)(0xA0 + i), 32);
        tx.vin[i].prevout.n = i;
        uint8_t sig[] = {0x00, (uint8_t)i};
        script_set(&tx.vin[i].script_sig, sig, 2);
        tx.vin[i].sequence = 0xFFFFFFFFu - i;
    }
    tx.num_vout = n_vout;
    tx.vout = zcl_calloc(n_vout, sizeof(struct tx_out), "dcsh_tx_vout");
    for (unsigned int i = 0; i < n_vout; i++) {
        tx.vout[i].value = (int64_t)((i + 1) * 100000000LL);
        uint8_t pk[] = {0x76, 0xa9, 0x14, (uint8_t)i};
        script_set(&tx.vout[i].script_pub_key, pk, 4);
    }
    return tx;
}

static void free_tx(struct transaction *tx)
{
    free(tx->vin);
    free(tx->vout);
    free(tx->v_joinsplit);
    free(tx->v_shielded_spend);
    free(tx->v_shielded_output);
}

/* Cross-check the domain sighash against the legacy wrapper, with cache=NULL
 * and cache=precomputed. */
static bool xcheck(const struct script *sc, const struct transaction *tx,
                   unsigned int nIn, struct sighash_type ht,
                   int64_t amount, uint32_t branch_id)
{
    struct uint256 r_legacy, r_domain;
    struct precomputed_tx_data ptd_legacy;
    struct domain_consensus_precomputed_tx_data ptd_domain;

    precompute_tx_data(tx, &ptd_legacy);
    domain_consensus_precompute_tx_data(tx, &ptd_domain);

    /* The cached struct is byte-identical (same six uint256 fields, order
     * and layout; static-asserted in core/modules/validation/src/sighash.c). */
    if (memcmp(&ptd_legacy, &ptd_domain, sizeof(ptd_legacy)) != 0)
        return false;

    /* No-cache path */
    bool ok_l = signature_hash(sc, tx, nIn, ht, amount, branch_id, NULL, &r_legacy);
    bool ok_d = domain_consensus_signature_hash(sc, tx, nIn, ht, amount, branch_id,
                                                NULL, &r_domain);
    if (ok_l != ok_d) return false;
    if (ok_l && !uint256_eq(&r_legacy, &r_domain)) return false;

    /* Cached path */
    ok_l = signature_hash(sc, tx, nIn, ht, amount, branch_id, &ptd_legacy, &r_legacy);
    ok_d = domain_consensus_signature_hash(sc, tx, nIn, ht, amount, branch_id,
                                           &ptd_domain, &r_domain);
    if (ok_l != ok_d) return false;
    if (ok_l && !uint256_eq(&r_legacy, &r_domain)) return false;

    return true;
}

/* ---- rows pinning sighash_overwinter_sapling and sighash_sprout ----
 * Each row derives its expectation from core/consensus/src/sighash.c:
 * which fields the regime commits, and which it ignores. Each row also
 * pins the exact 32 bytes (memory order) that the mutated transaction
 * digests to, so a change to field order or to the committed set fails
 * the row even when both digests would still compare as equal or
 * different. nIn=0 and amount=0 throughout. */

static const uint8_t PIN_JS_PRESENCE_SAPLING[32] = {
    0x29, 0xf1, 0xe0, 0x9f, 0xd8, 0xd3, 0x03, 0x43,
    0x39, 0x4d, 0x86, 0x7b, 0xf3, 0x72, 0x34, 0xe9,
    0xa0, 0x94, 0x58, 0xf9, 0x61, 0x02, 0xb0, 0x93,
    0x61, 0x12, 0xc3, 0xfd, 0xd3, 0x78, 0xde, 0xa0,
};
static const uint8_t PIN_JS_VPUB_SAPLING[32] = {
    0xce, 0xcc, 0x6a, 0x78, 0xb3, 0x8b, 0xb6, 0x5b,
    0x22, 0xd2, 0x9a, 0x82, 0x60, 0xfa, 0x9c, 0xb8,
    0xae, 0x4f, 0xd0, 0x5c, 0x33, 0x47, 0x3a, 0x7c,
    0x19, 0x51, 0xbd, 0x1f, 0xc5, 0x50, 0xdc, 0x56,
};
static const uint8_t PIN_JS_VPUB_OVERWINTER[32] = {
    0xea, 0x05, 0xec, 0xa4, 0x6e, 0x4a, 0x5b, 0x0a,
    0xfa, 0x69, 0xb7, 0x0a, 0x53, 0x5f, 0x9d, 0x0a,
    0xb4, 0x45, 0x7f, 0xea, 0xf0, 0x8c, 0x81, 0x87,
    0x17, 0x0d, 0xb1, 0xb8, 0x1c, 0x66, 0x14, 0x48,
};
static const uint8_t PIN_PUBKEY_SAPLING_JS[32] = {
    0x22, 0xc3, 0xc7, 0x12, 0x20, 0xbd, 0x8c, 0xf7,
    0x4a, 0x23, 0xa6, 0xb7, 0xc4, 0x52, 0x41, 0xc3,
    0xe0, 0x1f, 0xba, 0xc3, 0x6b, 0xeb, 0x08, 0x5c,
    0xae, 0x57, 0xdf, 0xcb, 0x76, 0xb7, 0xc2, 0x7b,
};
static const uint8_t PIN_PUBKEY_SAPLING_NOJS[32] = {
    0x09, 0xdb, 0x6e, 0xb6, 0x60, 0xa2, 0x0a, 0x38,
    0xc1, 0x03, 0x59, 0x5a, 0x4e, 0xcd, 0xa4, 0x02,
    0x33, 0xbf, 0xd3, 0x4e, 0x2e, 0x54, 0x0c, 0xda,
    0xc1, 0x2a, 0xa2, 0x79, 0x11, 0xaf, 0x8f, 0x2b,
};
static const uint8_t PIN_CM_SAPLING[32] = {
    0xb3, 0xcd, 0xae, 0x98, 0xa7, 0x87, 0x3b, 0x97,
    0x5f, 0x6e, 0xc8, 0x3a, 0x2c, 0x19, 0x26, 0x54,
    0x3e, 0x98, 0x4d, 0xb4, 0x4f, 0x27, 0x4e, 0x38,
    0xfb, 0x30, 0x8e, 0x9d, 0x6a, 0x4a, 0x22, 0xca,
};
static const uint8_t PIN_CM_OVERWINTER[32] = {
    0x93, 0x96, 0xc9, 0xa2, 0xd9, 0xab, 0x8d, 0x03,
    0xe4, 0x5a, 0xcb, 0xe3, 0x83, 0x96, 0x1d, 0xb6,
    0x3a, 0xb4, 0xff, 0x8d, 0xb0, 0x02, 0xca, 0x07,
    0x00, 0x1c, 0xca, 0xd0, 0x20, 0xc4, 0x12, 0x74,
};
static const uint8_t PIN_SPEND_AUTH_SAPLING[32] = {
    0x33, 0x33, 0x82, 0x3d, 0x83, 0x3d, 0x7c, 0x2f,
    0x6f, 0xf2, 0xfe, 0x17, 0xbb, 0x6f, 0xb0, 0xe1,
    0x16, 0x16, 0x48, 0xfb, 0x33, 0xaf, 0x09, 0xdd,
    0x47, 0xda, 0xbf, 0xc2, 0x84, 0xa1, 0x41, 0x9d,
};
static const uint8_t PIN_SCRIPTLEN_SAPLING[32] = {
    0x08, 0xd8, 0x6c, 0x14, 0xaa, 0x11, 0xcd, 0xd9,
    0x64, 0x81, 0x81, 0x08, 0xf9, 0x62, 0xb4, 0x7f,
    0x46, 0x3c, 0x0a, 0x23, 0x58, 0xa8, 0x7f, 0x47,
    0xc5, 0xa1, 0xac, 0xdb, 0xaf, 0x89, 0xa5, 0xff,
};
static const uint8_t PIN_SCRIPTLEN_OVERWINTER[32] = {
    0x69, 0x78, 0x07, 0xf7, 0x8b, 0xac, 0x33, 0x79,
    0x7a, 0x37, 0x5f, 0xc5, 0x22, 0x3a, 0xb0, 0xd0,
    0x6e, 0xcc, 0xed, 0x5e, 0xe2, 0x41, 0x7a, 0xa8,
    0xd6, 0x2b, 0xf1, 0x27, 0xaa, 0x38, 0x38, 0xe5,
};
static const uint8_t PIN_SEQ_SAPLING_ALL[32] = {
    0xf6, 0xfe, 0xe1, 0x6a, 0xf3, 0xd4, 0x16, 0x91,
    0x93, 0xaf, 0x75, 0x0a, 0x79, 0x57, 0xbe, 0x04,
    0x50, 0x53, 0x19, 0x9d, 0x4a, 0x53, 0xd2, 0x43,
    0x74, 0xc7, 0x66, 0x81, 0x34, 0x48, 0x8c, 0x85,
};
static const uint8_t PIN_SEQ_SAPLING_NONE[32] = {
    0xd6, 0x00, 0xd7, 0x7b, 0x0a, 0x2d, 0x90, 0x52,
    0xee, 0x8b, 0x23, 0x55, 0xc3, 0xb9, 0x31, 0x16,
    0xfe, 0x47, 0xb4, 0x05, 0xca, 0x15, 0x40, 0x1a,
    0x49, 0xe0, 0x0a, 0x91, 0x1e, 0x38, 0xd4, 0x72,
};
static const uint8_t PIN_VPUB_SPROUT_V1[32] = {
    0xd6, 0xe1, 0x94, 0x57, 0xdd, 0x65, 0x46, 0x24,
    0xb4, 0xba, 0x85, 0xf6, 0x20, 0x76, 0x95, 0x05,
    0x86, 0x8d, 0x07, 0x7b, 0x57, 0xa5, 0x89, 0xc5,
    0x04, 0xf9, 0x7d, 0xb1, 0xcb, 0xb8, 0xa3, 0xc2,
};
static const uint8_t PIN_VPUB_SPROUT_V2[32] = {
    0x7a, 0x36, 0x3d, 0xac, 0xaa, 0xb7, 0xfd, 0x79,
    0x62, 0x7f, 0x79, 0x90, 0x92, 0xc0, 0xb4, 0x63,
    0x2c, 0x07, 0x30, 0xb4, 0x1a, 0x62, 0xa1, 0x20,
    0x5a, 0x1b, 0x5a, 0x28, 0xd5, 0xdf, 0x25, 0x61,
};
static const uint8_t PIN_PUBKEY_SPROUT_JS[32] = {
    0x55, 0x3a, 0xf7, 0x11, 0x68, 0x48, 0xb8, 0xe1,
    0x5c, 0x48, 0xda, 0x40, 0x25, 0x67, 0xdc, 0xad,
    0x0f, 0x40, 0x35, 0x42, 0xc7, 0x11, 0x69, 0x12,
    0x69, 0x69, 0xce, 0x36, 0xee, 0xf2, 0x78, 0xde,
};
static const uint8_t PIN_PUBKEY_SPROUT_NOJS[32] = {
    0x6a, 0x77, 0x13, 0x2b, 0x74, 0x6a, 0x2f, 0x20,
    0xa4, 0xbe, 0xa7, 0x3c, 0xab, 0x24, 0x0d, 0x3d,
    0x32, 0xb5, 0x91, 0x0f, 0x1c, 0x96, 0xea, 0xd6,
    0xe6, 0xb8, 0xc6, 0xcb, 0x76, 0x7f, 0x11, 0x69,
};
static const uint8_t PIN_SCRIPTLEN_SPROUT[32] = {
    0xca, 0x17, 0x90, 0x95, 0x2b, 0xc8, 0xf2, 0x78,
    0xc0, 0x04, 0x5e, 0x41, 0x86, 0x0c, 0x73, 0xbf,
    0xa5, 0xfe, 0x5b, 0x2e, 0x37, 0x58, 0x56, 0x31,
    0xe1, 0x36, 0xa5, 0xa7, 0xdf, 0xdf, 0xeb, 0x3c,
};
static const uint8_t PIN_SEQ_SPROUT_ALL[32] = {
    0xcd, 0x57, 0xae, 0x14, 0x48, 0x66, 0xee, 0xe1,
    0xdf, 0xb1, 0xd8, 0x26, 0x66, 0x31, 0xd2, 0x52,
    0xd9, 0x09, 0xaf, 0x27, 0xff, 0xf9, 0xe7, 0x64,
    0x86, 0x23, 0xe3, 0xfd, 0xb3, 0x91, 0x79, 0xe3,
};
static const uint8_t PIN_SEQ_SPROUT_NONE[32] = {
    0xbe, 0x8e, 0x03, 0x6b, 0x0b, 0x48, 0xf7, 0x3b,
    0x65, 0x22, 0x49, 0x90, 0xe4, 0xa9, 0x23, 0x57,
    0x02, 0xe5, 0xd4, 0x84, 0x0f, 0x3c, 0xa8, 0x51,
    0x08, 0x8f, 0x0a, 0x0b, 0xc3, 0x3b, 0x35, 0x54,
};

static bool dcs_pin_eq(const struct uint256 *r, const uint8_t pin[32])
{
    return memcmp(r->data, pin, 32) == 0;
}

/* True when both digests compute, they differ exactly when `committed`,
 * and the digest of b (the mutated transaction) equals `pin`. */
static bool dcs_expect(const struct transaction *a, const struct transaction *b,
                       const struct script *sc, uint32_t raw_type,
                       uint32_t branch_id, bool committed,
                       const uint8_t pin[32])
{
    struct sighash_type ht = { .raw = raw_type };
    struct uint256 ra, rb;
    if (!domain_consensus_signature_hash(sc, a, 0, ht, 0, branch_id, NULL, &ra))
        return false;
    if (!domain_consensus_signature_hash(sc, b, 0, ht, 0, branch_id, NULL, &rb))
        return false;
    bool differ = !uint256_eq(&ra, &rb);
    return differ == committed && dcs_pin_eq(&rb, pin);
}

static void dcs_one_byte_script(struct script *sc)
{
    uint8_t code[] = {0x51};
    script_set(sc, code, 1);
}

static void dcs_add_joinsplit(struct transaction *tx, int64_t vpub_old)
{
    tx->v_joinsplit = zcl_calloc(1, sizeof(struct js_description), "dcsh_tx_js");
    tx->num_joinsplit = 1;
    tx->v_joinsplit[0].vpub_old = vpub_old;
    memset(tx->joinsplit_pubkey.data, 0x5A, 32);
}

static void dcs_add_shielded(struct transaction *tx)
{
    tx->v_shielded_spend = zcl_calloc(1, sizeof(struct spend_description),
                                      "dcsh_tx_spend");
    tx->num_shielded_spend = 1;
    memset(tx->v_shielded_spend[0].nullifier.data, 0x6B, 32);
    tx->v_shielded_output = zcl_calloc(1, sizeof(struct output_description),
                                       "dcsh_tx_sout");
    tx->num_shielded_output = 1;
    memset(tx->v_shielded_output[0].cm.data, 0x7C, 32);
}

/* Sapling/Overwinter commit the JoinSplits hash only when num_joinsplit>0,
 * so adding a joinsplit to a joinsplit-free tx must change the hash. */
static bool dcs_row_js_presence_sapling(void)
{
    struct transaction a = build_tx(1, 1, true, 4, SAPLING_VERSION_GROUP_ID);
    struct transaction b = build_tx(1, 1, true, 4, SAPLING_VERSION_GROUP_ID);
    struct script sc;
    dcs_one_byte_script(&sc);
    dcs_add_joinsplit(&b, 0);
    bool ok = dcs_expect(&a, &b, &sc, SIGHASH_ALL, 0x76b809bb, true,
                         PIN_JS_PRESENCE_SAPLING);
    free_tx(&a);
    free_tx(&b);
    return ok;
}

/* Mutate vpub_old of the one joinsplit. Checks dcs_expect (committed:
 * true when the digest must move, false when ignored) and the cache-path
 * cross-check. */
static bool dcs_row_js_vpub_old(bool ow, uint32_t ver, uint32_t vgi,
                                uint32_t branch, bool committed,
                                const uint8_t pin[32])
{
    struct transaction a = build_tx(1, 1, ow, ver, vgi);
    struct transaction b = build_tx(1, 1, ow, ver, vgi);
    struct sighash_type ht = { .raw = SIGHASH_ALL };
    struct script sc;
    dcs_one_byte_script(&sc);
    dcs_add_joinsplit(&a, 0);
    dcs_add_joinsplit(&b, 1);
    bool ok = dcs_expect(&a, &b, &sc, SIGHASH_ALL, branch, committed, pin);
    ok = ok && xcheck(&sc, &b, 0, ht, 0, branch);
    free_tx(&a);
    free_tx(&b);
    return ok;
}

/* Mutate joinsplit_pubkey. The pubkey is committed (inside the JoinSplits
 * digest) only when a joinsplit exists; dcs_expect checks that and the pin. */
static bool dcs_pubkey_effect(bool ow, uint32_t ver, uint32_t vgi,
                              uint32_t branch, bool with_js, bool committed,
                              const uint8_t pin[32])
{
    struct transaction a = build_tx(1, 1, ow, ver, vgi);
    struct transaction b = build_tx(1, 1, ow, ver, vgi);
    struct script sc;
    dcs_one_byte_script(&sc);
    if (with_js) {
        dcs_add_joinsplit(&a, 0);
        dcs_add_joinsplit(&b, 0);
    }
    b.joinsplit_pubkey.data[0] = 0xA5;
    bool ok = dcs_expect(&a, &b, &sc, SIGHASH_ALL, branch, committed, pin);
    free_tx(&a);
    free_tx(&b);
    return ok;
}

/* Mutate a shielded output's cm. Sapling commits it (committed=true);
 * Overwinter has no shielded digest at all (committed=false). */
static bool dcs_row_shielded_cm(bool ow, uint32_t ver, uint32_t vgi,
                                uint32_t branch, bool committed,
                                const uint8_t pin[32])
{
    struct transaction a = build_tx(1, 1, ow, ver, vgi);
    struct transaction b = build_tx(1, 1, ow, ver, vgi);
    struct script sc;
    dcs_one_byte_script(&sc);
    dcs_add_shielded(&a);
    dcs_add_shielded(&b);
    b.v_shielded_output[0].cm.data[0] ^= 0xFF;
    bool ok = dcs_expect(&a, &b, &sc, SIGHASH_ALL, branch, committed, pin);
    free_tx(&a);
    free_tx(&b);
    return ok;
}

/* spendAuthSig is excluded from the ShieldedSpends digest (ZIP-243), so
 * mutating it must leave the Sapling hash unchanged. */
static bool dcs_row_spend_auth_sig_not_committed(void)
{
    struct transaction a = build_tx(1, 1, true, 4, SAPLING_VERSION_GROUP_ID);
    struct transaction b = build_tx(1, 1, true, 4, SAPLING_VERSION_GROUP_ID);
    struct script sc;
    dcs_one_byte_script(&sc);
    dcs_add_shielded(&a);
    dcs_add_shielded(&b);
    b.v_shielded_spend[0].spend_auth_sig[0] = 0xEE;
    bool ok = dcs_expect(&a, &b, &sc, SIGHASH_ALL, 0x76b809bb, false,
                         PIN_SPEND_AUTH_SAPLING);
    free_tx(&a);
    free_tx(&b);
    return ok;
}

/* scriptCode lengths 252 (1-byte varint), 253 (0xfd + 2 bytes) and
 * MAX_SCRIPT_SIZE (the largest a struct script can hold). 252 and 253
 * must differ; every length must succeed; cache path must match; the
 * 253-byte digest must equal pin. */
static bool dcs_row_script_len(bool ow, uint32_t ver, uint32_t vgi,
                               uint32_t branch, const uint8_t pin[32])
{
    struct script *sc = zcl_calloc(3, sizeof(struct script), "dcsh_scripts");
    unsigned char fill[MAX_SCRIPT_SIZE];
    memset(fill, 0x51, sizeof(fill));
    script_set(&sc[0], fill, 252);
    script_set(&sc[1], fill, 253);
    script_set(&sc[2], fill, MAX_SCRIPT_SIZE);
    struct transaction tx = build_tx(1, 1, ow, ver, vgi);
    struct sighash_type ht = { .raw = SIGHASH_ALL };
    struct uint256 r0, r1, r2;
    bool ok = domain_consensus_signature_hash(&sc[0], &tx, 0, ht, 0, branch,
                                              NULL, &r0)
           && domain_consensus_signature_hash(&sc[1], &tx, 0, ht, 0, branch,
                                              NULL, &r1)
           && domain_consensus_signature_hash(&sc[2], &tx, 0, ht, 0, branch,
                                              NULL, &r2);
    ok = ok && !uint256_eq(&r0, &r1) && !uint256_is_null(&r2);
    ok = ok && dcs_pin_eq(&r1, pin);
    ok = ok && xcheck(&sc[1], &tx, 0, ht, 0, branch);
    free_tx(&tx);
    free(sc);
    return ok;
}

/* Two-input tx; mutate vin[1].sequence. Sprout NONE zeroes other inputs'
 * sequences; Sapling NONE drops the sequence digest. Both ignore it
 * (committed=false). SIGHASH_ALL commits it (committed=true). */
static bool dcs_row_other_sequence(bool ow, uint32_t ver, uint32_t vgi,
                                   uint32_t branch, uint32_t raw_type,
                                   bool committed, const uint8_t pin[32])
{
    struct transaction a = build_tx(2, 1, ow, ver, vgi);
    struct transaction b = build_tx(2, 1, ow, ver, vgi);
    struct script sc;
    dcs_one_byte_script(&sc);
    b.vin[1].sequence = 0;
    bool ok = dcs_expect(&a, &b, &sc, raw_type, branch, committed, pin);
    free_tx(&a);
    free_tx(&b);
    return ok;
}

int test_domain_consensus_sighash(void)
{
    int failures = 0;

    /* --- signature_hash_version routing --- */
    {
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.overwintered = false;
        tx.version = 1;
        DCS_CHECK("version: sprout",
                  domain_consensus_signature_hash_version(&tx)
                    == DOMAIN_CONSENSUS_SIGVERSION_SPROUT);
    }
    {
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.overwintered = true;
        tx.version = 3;
        tx.version_group_id = OVERWINTER_VERSION_GROUP_ID;
        DCS_CHECK("version: overwinter",
                  domain_consensus_signature_hash_version(&tx)
                    == DOMAIN_CONSENSUS_SIGVERSION_OVERWINTER);
    }
    {
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.overwintered = true;
        tx.version = 4;
        tx.version_group_id = SAPLING_VERSION_GROUP_ID;
        DCS_CHECK("version: sapling",
                  domain_consensus_signature_hash_version(&tx)
                    == DOMAIN_CONSENSUS_SIGVERSION_SAPLING);
    }

    /* --- precompute_tx_data: domain == legacy --- */
    {
        struct transaction tx = build_tx(2, 2, false, 1, 0);
        struct precomputed_tx_data l;
        struct domain_consensus_precomputed_tx_data d;
        precompute_tx_data(&tx, &l);
        domain_consensus_precompute_tx_data(&tx, &d);
        bool ok = memcmp(&l, &d, sizeof(l)) == 0;
        free_tx(&tx);
        DCS_CHECK("precompute_tx_data: legacy byte-identical", ok);
    }

    /* --- contract: nIn out of range, NOT_AN_INPUT accepted --- */
    {
        struct transaction tx = build_tx(1, 1, false, 1, 0);
        struct script sc;
        uint8_t code[] = {0x51};
        script_set(&sc, code, 1);
        struct sighash_type ht = { .raw = SIGHASH_ALL };
        struct uint256 result;
        bool rejected = !domain_consensus_signature_hash(
            &sc, &tx, 7, ht, 0, 0, NULL, &result);
        free_tx(&tx);
        DCS_CHECK("contract: nIn >= num_vin rejected", rejected);
    }
    {
        struct transaction tx = build_tx(1, 1, true, 4, SAPLING_VERSION_GROUP_ID);
        struct script sc;
        uint8_t code[] = {0x51};
        script_set(&sc, code, 1);
        struct sighash_type ht = { .raw = SIGHASH_ALL };
        struct uint256 result;
        bool ok = domain_consensus_signature_hash(
            &sc, &tx, NOT_AN_INPUT, ht, 100, 0x76b809bb, NULL, &result);
        ok = ok && !uint256_is_null(&result);
        free_tx(&tx);
        DCS_CHECK("contract: NOT_AN_INPUT accepted (sapling)", ok);
    }
    {
        /* Sprout SIGHASH_SINGLE with nIn >= num_vout must be rejected. */
        struct transaction tx = build_tx(2, 1, false, 1, 0);
        struct script sc;
        uint8_t code[] = {0x51};
        script_set(&sc, code, 1);
        struct sighash_type ht = { .raw = SIGHASH_SINGLE };
        struct uint256 result;
        bool rejected = !domain_consensus_signature_hash(
            &sc, &tx, 1, ht, 0, 0, NULL, &result);
        free_tx(&tx);
        DCS_CHECK("contract: sprout SIGHASH_SINGLE nIn>=vout rejected",
                  rejected);
    }

    /* --- regression seal: walk a matrix of (sigver, base type, ACP) --- */
    {
        struct {
            const char *label;
            bool overwintered;
            uint32_t version;
            uint32_t vgi;
            uint32_t branch_id;
        } versions[] = {
            { "sprout",     false, 1, 0,                            0          },
            { "overwinter", true,  3, OVERWINTER_VERSION_GROUP_ID,  0x5ba81b19 },
            { "sapling",    true,  4, SAPLING_VERSION_GROUP_ID,     0x76b809bb },
        };
        uint32_t base_types[] = { SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE };
        bool acps[] = { false, true };
        int64_t amounts[] = { 0, 1, 100000000LL };

        bool all_match = true;
        unsigned int probes = 0;

        for (unsigned int v = 0; v < 3; v++) {
            for (unsigned int b = 0; b < 3; b++) {
                for (unsigned int a = 0; a < 2; a++) {
                    for (unsigned int amt = 0; amt < 3; amt++) {
                        /* In Sprout SIGHASH_SINGLE with nIn >= num_vout is rejected.
                         * Use 2 vin / 3 vout so nIn=0,1 are always legal. */
                        struct transaction tx = build_tx(2, 3,
                            versions[v].overwintered, versions[v].version,
                            versions[v].vgi);

                        struct script sc;
                        uint8_t code[] = {0x76, 0xa9, 0x14, 0x33, 0x33,
                                          0x33, 0x33, 0x33, 0x88, 0xac};
                        script_set(&sc, code, sizeof(code));

                        struct sighash_type ht = { .raw = base_types[b] };
                        if (acps[a]) ht.raw |= SIGHASH_ANYONECANPAY;

                        for (unsigned int nin = 0; nin < tx.num_vin; nin++) {
                            if (!xcheck(&sc, &tx, nin, ht,
                                       amounts[amt], versions[v].branch_id)) {
                                printf("\n  MISMATCH %s base=%u acp=%u "
                                       "nin=%u amount=%lld\n",
                                       versions[v].label, base_types[b],
                                       (unsigned)acps[a], nin,
                                       (long long)amounts[amt]);
                                all_match = false;
                            }
                            probes++;
                        }
                        free_tx(&tx);
                    }
                }
            }
        }
        printf("(probed %u sighash combinations) ", probes);
        DCS_CHECK("regression seal: domain == legacy across matrix", all_match);
    }

    /* --- regression seal: NOT_AN_INPUT path (JoinSplit signature) --- */
    {
        struct transaction tx = build_tx(1, 1, true, 4, SAPLING_VERSION_GROUP_ID);
        struct script sc;
        uint8_t code[] = {0x00}; /* empty-ish */
        script_set(&sc, code, 1);
        struct sighash_type ht = { .raw = SIGHASH_ALL };

        bool ok = xcheck(&sc, &tx, NOT_AN_INPUT, ht, 0, 0x76b809bb);
        free_tx(&tx);
        DCS_CHECK("regression seal: NOT_AN_INPUT (sapling) matches", ok);
    }

    /* --- determinism: same inputs -> same hash --- */
    {
        struct transaction tx = build_tx(1, 1, true, 4, SAPLING_VERSION_GROUP_ID);
        struct script sc;
        uint8_t code[] = {0x51};
        script_set(&sc, code, 1);
        struct sighash_type ht = { .raw = SIGHASH_ALL };

        struct uint256 r1, r2;
        bool ok = domain_consensus_signature_hash(&sc, &tx, 0, ht, 50, 0, NULL, &r1)
              &&  domain_consensus_signature_hash(&sc, &tx, 0, ht, 50, 0, NULL, &r2);
        ok = ok && uint256_eq(&r1, &r2);
        free_tx(&tx);
        DCS_CHECK("determinism: same inputs -> same hash", ok);
    }

    /* --- sensitivity: amount changes -> sapling hash changes --- */
    {
        struct transaction tx = build_tx(1, 1, true, 4, SAPLING_VERSION_GROUP_ID);
        struct script sc;
        uint8_t code[] = {0x51};
        script_set(&sc, code, 1);
        struct sighash_type ht = { .raw = SIGHASH_ALL };

        struct uint256 r1, r2;
        bool ok = domain_consensus_signature_hash(&sc, &tx, 0, ht, 50,  0, NULL, &r1)
              &&  domain_consensus_signature_hash(&sc, &tx, 0, ht, 100, 0, NULL, &r2);
        ok = ok && !uint256_eq(&r1, &r2);
        free_tx(&tx);
        DCS_CHECK("sensitivity: different amount -> different hash (sapling)", ok);
    }

    /* --- sighash_overwinter_sapling: JoinSplits, shielded, script length --- */
    DCS_CHECK("joinsplit: sapling presence changes hash",
              dcs_row_js_presence_sapling());
    DCS_CHECK("joinsplit: sapling vpub_old committed",
              dcs_row_js_vpub_old(true, 4, SAPLING_VERSION_GROUP_ID,
                                  0x76b809bb, true, PIN_JS_VPUB_SAPLING));
    DCS_CHECK("joinsplit: overwinter vpub_old committed",
              dcs_row_js_vpub_old(true, 3, OVERWINTER_VERSION_GROUP_ID,
                                  0x5ba81b19, true, PIN_JS_VPUB_OVERWINTER));
    DCS_CHECK("joinsplit: sapling pubkey committed when js present",
              dcs_pubkey_effect(true, 4, SAPLING_VERSION_GROUP_ID,
                                0x76b809bb, true, true, PIN_PUBKEY_SAPLING_JS));
    DCS_CHECK("joinsplit: sapling pubkey ignored without js",
              dcs_pubkey_effect(true, 4, SAPLING_VERSION_GROUP_ID,
                                0x76b809bb, false, false,
                                PIN_PUBKEY_SAPLING_NOJS));
    DCS_CHECK("shielded: sapling output cm committed",
              dcs_row_shielded_cm(true, 4, SAPLING_VERSION_GROUP_ID,
                                  0x76b809bb, true, PIN_CM_SAPLING));
    DCS_CHECK("shielded: overwinter ignores output cm",
              dcs_row_shielded_cm(true, 3, OVERWINTER_VERSION_GROUP_ID,
                                  0x5ba81b19, false, PIN_CM_OVERWINTER));
    DCS_CHECK("shielded: spend_auth_sig not committed (sapling)",
              dcs_row_spend_auth_sig_not_committed());
    DCS_CHECK("script length: sapling 252/253/max accepted, distinct",
              dcs_row_script_len(true, 4, SAPLING_VERSION_GROUP_ID,
                                 0x76b809bb, PIN_SCRIPTLEN_SAPLING));
    DCS_CHECK("script length: overwinter 252/253/max accepted, distinct",
              dcs_row_script_len(true, 3, OVERWINTER_VERSION_GROUP_ID,
                                 0x5ba81b19, PIN_SCRIPTLEN_OVERWINTER));
    DCS_CHECK("sapling ALL commits other input sequence",
              dcs_row_other_sequence(true, 4, SAPLING_VERSION_GROUP_ID,
                                     0x76b809bb, SIGHASH_ALL, true,
                                     PIN_SEQ_SAPLING_ALL));
    DCS_CHECK("sapling NONE ignores other input sequence",
              dcs_row_other_sequence(true, 4, SAPLING_VERSION_GROUP_ID,
                                     0x76b809bb, SIGHASH_NONE, false,
                                     PIN_SEQ_SAPLING_NONE));

    /* --- sighash_sprout: version gate on JoinSplit, script length, sequence --- */
    DCS_CHECK("sprout v1 ignores joinsplit vpub_old",
              dcs_row_js_vpub_old(false, 1, 0, 0, false, PIN_VPUB_SPROUT_V1));
    DCS_CHECK("sprout v2 commits joinsplit vpub_old",
              dcs_row_js_vpub_old(false, 2, 0, 0, true, PIN_VPUB_SPROUT_V2));
    DCS_CHECK("sprout v2 commits joinsplit pubkey when js present",
              dcs_pubkey_effect(false, 2, 0, 0, true, true,
                                PIN_PUBKEY_SPROUT_JS));
    DCS_CHECK("sprout v2 ignores joinsplit pubkey without js",
              dcs_pubkey_effect(false, 2, 0, 0, false, false,
                                PIN_PUBKEY_SPROUT_NOJS));
    DCS_CHECK("script length: sprout 252/253/max accepted, distinct",
              dcs_row_script_len(false, 1, 0, 0, PIN_SCRIPTLEN_SPROUT));
    DCS_CHECK("sprout ALL commits other input sequence",
              dcs_row_other_sequence(false, 1, 0, 0, SIGHASH_ALL, true,
                                     PIN_SEQ_SPROUT_ALL));
    DCS_CHECK("sprout NONE ignores other input sequence",
              dcs_row_other_sequence(false, 1, 0, 0, SIGHASH_NONE, false,
                                     PIN_SEQ_SPROUT_NONE));

    return failures;
}
