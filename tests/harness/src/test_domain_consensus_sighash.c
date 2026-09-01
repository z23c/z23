/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Unit tests for domain/consensus/sighash.{c,h}.
 *
 * These tests pin the pure signature-hash computation. They DO NOT go
 * through any chain/ wrapper that resolves coins from a view: they
 * exercise the typed domain API directly and cross-check the result
 * against the legacy lib/ wrapper (validation/sighash.h) to prove the
 * extraction was bit-for-bit behaviour-preserving.
 *
 * Coverage:
 *   - null/edge cases (nIn out of range; NOT_AN_INPUT accepted;
 *     SIGHASH_SINGLE with nIn >= num_vout in Sprout regime)
 *   - signature_hash_version: Sprout / Overwinter / Sapling routing
 *   - precompute_tx_data: domain vs legacy byte-for-byte
 *   - signature_hash regression seal across representative tx shapes
 *     (P2PKH-style), all three sig versions, base hash types
 *     {ALL, NONE, SINGLE} × {plain, ANYONECANPAY} × multiple inputs.
 *
 * If anyone "improves" one side of the wrapper-vs-domain pair without
 * the other, this test shouts.
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

/* Build a representative transaction with `n_vin` inputs and `n_vout`
 * outputs, deterministic bytes throughout so two builds produce the
 * same hash. Pure value carrier — no shielded components. */
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
}

/* Cross-check: compute the sighash via the domain function and via the
 * legacy wrapper, fail if they don't match. Exercises both
 * cache=NULL and cache=precomputed code paths. */
static bool xcheck(const struct script *sc, const struct transaction *tx,
                   unsigned int nIn, struct sighash_type ht,
                   int64_t amount, uint32_t branch_id)
{
    struct uint256 r_legacy, r_domain;
    struct precomputed_tx_data ptd_legacy;
    struct domain_consensus_precomputed_tx_data ptd_domain;

    precompute_tx_data(tx, &ptd_legacy);
    domain_consensus_precompute_tx_data(tx, &ptd_domain);

    /* The cached struct must be byte-identical (same six uint256
     * fields, same order, same layout — pinned by static asserts in
     * core/modules/validation/src/sighash.c). */
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

    return failures;
}
