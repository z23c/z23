/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression test for the fast-sync minimum-chainwork FLOOR.
 *
 * snapshot_verify.c rejects a local anchor whose accumulated chainwork is
 * below the consensus nMinimumChainWork. The floor is far below any genuine
 * snapshot and is not pinned to the checkpoint table. These cases pin the
 * predicate; test_snapshot_fc_binding.c drives the gate that uses it. */

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "consensus/params.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "validation/sync_evidence_policy.h"

#include <string.h>

/* Serialize a struct uint256 to the canonical 32-byte little-endian
 * chainwork layout (byte 0 least significant), as snapsync_verify_flyclient does. */
static void floor_le_from_consensus(const struct uint256 *src, uint8_t out[32])
{
    struct arith_uint256 a;
    struct uint256 le;
    uint256_to_arith(&a, src);
    arith_to_uint256(&le, &a);
    memcpy(out, le.data, 32);
}

/* Build an LE chainwork value equal to a small u64 (forged min-difficulty
 * chain accumulates trivial work). */
static void chainwork_le_from_u64(uint64_t v, uint8_t out[32])
{
    struct arith_uint256 a;
    struct uint256 le;
    arith_uint256_set_u64(&a, v);
    arith_to_uint256(&le, &a);
    memcpy(out, le.data, 32);
}

int test_flyclient_chainwork_floor(void)
{
    int failures = 0;

    const struct chain_params *cp = chain_params_get();
    if (!cp) {
        printf("test_flyclient_chainwork_floor: no chain params\n");
        return 1;
    }
    const struct consensus_params *consensus = &cp->consensus;

    uint8_t floor_le[32];
    floor_le_from_consensus(&consensus->nMinimumChainWork, floor_le);

    /* The mainnet floor must be non-zero, else the gate is a no-op. */
    TEST("flyclient_floor: consensus nMinimumChainWork is non-zero") {
        ASSERT(!zcl_chainwork_is_zero(floor_le));
        PASS();
    }

    /* A forged min-difficulty chain with trivial accumulated work
     * (work = 1) is below the floor and must be rejected. */
    TEST("flyclient_floor: trivial forged chainwork is below floor") {
        uint8_t forged[32];
        chainwork_le_from_u64(1, forged);
        ASSERT(zcl_chainwork_below_floor(forged, floor_le));
        PASS();
    }

    /* An all-zero offered chainwork is below the floor (it is also caught
     * earlier by the zero-chainwork guard, but the floor predicate must
     * agree). */
    TEST("flyclient_floor: zero chainwork is below floor") {
        uint8_t zero[32] = {0};
        ASSERT(zcl_chainwork_below_floor(zero, floor_le));
        PASS();
    }

    /* A value exactly one unit below the floor is rejected (boundary). */
    TEST("flyclient_floor: floor-minus-one is below floor") {
        struct arith_uint256 fa, one, below;
        struct uint256 below_le;
        uint8_t below_bytes[32];
        uint256_to_arith(&fa, &consensus->nMinimumChainWork);
        arith_uint256_set_u64(&one, 1);
        arith_uint256_sub(&below, &fa, &one);
        arith_to_uint256(&below_le, &below);
        memcpy(below_bytes, below_le.data, 32);
        ASSERT(zcl_chainwork_below_floor(below_bytes, floor_le));
        PASS();
    }

    /* The floor value itself is NOT below the floor (strict comparison). */
    TEST("flyclient_floor: floor value is not below floor") {
        ASSERT(!zcl_chainwork_below_floor(floor_le, floor_le));
        PASS();
    }

    /* A genuine ~3M-height snapshot has chainwork vastly above the floor and
     * must pass. The real mainnet floor is ~0x0af996bfd8e482 (~48 bits of
     * work); a genuine ~3M tip accumulates work many orders of magnitude
     * larger. Model a realistic large value and confirm it passes. */
    TEST("flyclient_floor: genuine high chainwork passes") {
        /* ~2^200 — far above the ~2^48 floor, comfortably representing a
         * multi-million-block PoW chain's accumulated work. */
        struct arith_uint256 hi;
        struct uint256 hi_le;
        uint8_t hi_bytes[32];
        arith_uint256_set_zero(&hi);
        hi.pn[6] = 0x100; /* bit 200 set */
        arith_to_uint256(&hi_le, &hi);
        memcpy(hi_bytes, hi_le.data, 32);
        ASSERT(!zcl_chainwork_below_floor(hi_bytes, floor_le));
        PASS();
    }

    /* A zero floor (no floor configured) must never reject — defensive
     * default so a misconfigured testnet/regtest params never blocks sync. */
    TEST("flyclient_floor: zero floor never rejects") {
        uint8_t zero_floor[32] = {0};
        uint8_t any[32];
        chainwork_le_from_u64(1, any);
        ASSERT(!zcl_chainwork_below_floor(any, zero_floor));
        uint8_t zero_work[32] = {0};
        ASSERT(!zcl_chainwork_below_floor(zero_work, zero_floor));
        PASS();
    }

_test_next:;
    if (failures == 0)
        printf("test_flyclient_chainwork_floor: all passed\n");
    else
        printf("test_flyclient_chainwork_floor: %d FAILED\n", failures);
    return failures;
}
