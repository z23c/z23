/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Tests for the in-memory utxo_snapshot_port adapter.
 *
 * Coverage spans every port method (lookup, apply_diff, revert_tip,
 * tip_height, tip_hash, sha3_commitment) plus all error paths:
 *   - empty snapshot: NOT_FOUND, tip=UINT32_MAX
 *   - apply_diff with creates only at h=0 → tip=0
 *   - apply_diff at wrong tip → TIP_MISMATCH
 *   - apply_diff with double-spend → DOUBLE_SPEND
 *   - apply_diff spending unknown outpoint → UNKNOWN_OUTPOINT
 *   - apply + revert round-trip yields identical state
 *   - sha3_commitment is order-independent and stable
 */

#include "test/test_core.h"

#include "adapters/outbound/persistence/utxo_snapshot_inmem.h"
#include "ports/utxo_snapshot_port.h"

#include <stdio.h>
#include <string.h>
#include "test/setup_result.h"

#define USI_CHECK(name, expr) do {                          \
    printf("utxo_snapshot_inmem: %s... ", (name));          \
    if ((expr)) { printf("OK\n"); }                         \
    else { printf("FAIL\n"); failures++; }                  \
} while (0)

static struct utxo_outpoint mk_op(uint8_t seed, uint32_t vout)
{
    struct utxo_outpoint o; memset(o.txid, 0, 32);
    o.txid[0] = seed;
    o.vout = vout;
    return o;
}

static struct utxo_coin mk_coin(uint64_t value, uint32_t height,
                                const uint8_t *spk, uint32_t spk_len)
{
    return (struct utxo_coin){
        .value_zat = value, .height = height, .is_coinbase = false,
        .script_pubkey = spk, .script_pubkey_len = spk_len,
    };
}

static struct block_hash mk_hash(uint8_t seed)
{
    struct block_hash h; memset(h.bytes, 0, 32); h.bytes[0] = seed;
    return h;
}

int test_utxo_snapshot_inmem(void)
{
    int failures = 0;

    /* ── 1. Empty snapshot. */
    {
        struct utxo_snapshot_inmem *h = NULL;
        struct utxo_snapshot_port p = {0};
        struct zcl_result r = utxo_snapshot_inmem_open(&h, &p);
        USI_CHECK("open -> OK", r.ok);
        USI_CHECK("empty tip = UINT32_MAX", p.tip_height(p.self) == UINT32_MAX);

        struct utxo_outpoint op = mk_op(0xaa, 0);
        struct utxo_coin coin = {0};
        r = p.lookup(p.self, &op, &coin);
        USI_CHECK("empty lookup -> NOT_FOUND",
                  !r.ok && r.code == UTXO_ERR_NOT_FOUND);

        utxo_snapshot_inmem_close(h);
    }

    /* ── 2. Apply a genesis-style diff at h=0 (creates only). */
    {
        struct utxo_snapshot_inmem *h = NULL;
        struct utxo_snapshot_port p = {0};
        ZCL_TEST_SETUP(utxo_snapshot_inmem_open(&h, &p));
        struct block_hash bh0 = mk_hash(0xb0);

        struct utxo_outpoint creates[2] = { mk_op(0x01, 0), mk_op(0x01, 1) };
        uint8_t spk_a[] = "OP_DUP OP_HASH160 ...";
        struct utxo_coin coins[2] = {
            mk_coin(50000, 0, spk_a, sizeof spk_a),
            mk_coin(25000, 0, NULL, 0),
        };
        struct utxo_diff d = {
            .target_height = 0, .target_block = &bh0,
            .spends = NULL, .spends_len = 0,
            .creates = creates, .creates_coin = coins, .creates_len = 2,
        };
        struct zcl_result r = p.apply_diff(p.self, &d);
        USI_CHECK("apply_diff(h=0, +2) -> OK", r.ok);
        USI_CHECK("tip_height now 0", p.tip_height(p.self) == 0);

        struct block_hash got;
        p.tip_hash(p.self, &got);
        USI_CHECK("tip_hash matches", got.bytes[0] == 0xb0);

        struct utxo_coin coin_out = {0};
        r = p.lookup(p.self, &creates[0], &coin_out);
        USI_CHECK("lookup creates[0] -> OK + correct value",
                  r.ok && coin_out.value_zat == 50000 &&
                  coin_out.script_pubkey_len == sizeof spk_a &&
                  memcmp(coin_out.script_pubkey, spk_a, sizeof spk_a) == 0);

        utxo_snapshot_inmem_close(h);
    }

    /* ── 3. TIP_MISMATCH: applying at h=2 with empty snapshot. */
    {
        struct utxo_snapshot_inmem *h = NULL;
        struct utxo_snapshot_port p = {0};
        ZCL_TEST_SETUP(utxo_snapshot_inmem_open(&h, &p));
        struct block_hash bh = mk_hash(0xc1);
        struct utxo_diff d = {
            .target_height = 2, .target_block = &bh,
            .spends = NULL, .spends_len = 0,
            .creates = NULL, .creates_coin = NULL, .creates_len = 0,
        };
        struct zcl_result r = p.apply_diff(p.self, &d);
        USI_CHECK("apply at h=2 from empty -> TIP_MISMATCH",
                  !r.ok && r.code == UTXO_ERR_TIP_MISMATCH);
        utxo_snapshot_inmem_close(h);
    }

    /* ── 4. UNKNOWN_OUTPOINT: spend something that doesn't exist. */
    {
        struct utxo_snapshot_inmem *h = NULL;
        struct utxo_snapshot_port p = {0};
        ZCL_TEST_SETUP(utxo_snapshot_inmem_open(&h, &p));
        struct block_hash bh = mk_hash(0xd1);
        struct utxo_outpoint phantom = mk_op(0x77, 0);
        struct utxo_diff d = {
            .target_height = 0, .target_block = &bh,
            .spends = &phantom, .spends_len = 1,
            .creates = NULL, .creates_coin = NULL, .creates_len = 0,
        };
        struct zcl_result r = p.apply_diff(p.self, &d);
        USI_CHECK("spend phantom -> UNKNOWN_OUTPOINT",
                  !r.ok && r.code == UTXO_ERR_UNKNOWN_OUTPOINT);
        utxo_snapshot_inmem_close(h);
    }

    /* ── 5. DOUBLE_SPEND: create collides with existing. */
    {
        struct utxo_snapshot_inmem *h = NULL;
        struct utxo_snapshot_port p = {0};
        ZCL_TEST_SETUP(utxo_snapshot_inmem_open(&h, &p));
        struct block_hash bh0 = mk_hash(0xe0), bh1 = mk_hash(0xe1);
        struct utxo_outpoint op = mk_op(0x02, 0);
        struct utxo_coin coin = mk_coin(100, 0, NULL, 0);
        struct utxo_diff d0 = {
            .target_height = 0, .target_block = &bh0,
            .creates = &op, .creates_coin = &coin, .creates_len = 1,
        };
        ZCL_TEST_SETUP(p.apply_diff(p.self, &d0));
        /* Now try to create the same outpoint at h=1 — collides. */
        struct utxo_diff d1 = {
            .target_height = 1, .target_block = &bh1,
            .creates = &op, .creates_coin = &coin, .creates_len = 1,
        };
        struct zcl_result r = p.apply_diff(p.self, &d1);
        USI_CHECK("re-create existing -> DOUBLE_SPEND",
                  !r.ok && r.code == UTXO_ERR_DOUBLE_SPEND);
        utxo_snapshot_inmem_close(h);
    }

    /* ── 6. Apply + revert round-trip. */
    {
        struct utxo_snapshot_inmem *h = NULL;
        struct utxo_snapshot_port p = {0};
        ZCL_TEST_SETUP(utxo_snapshot_inmem_open(&h, &p));
        struct block_hash bh0 = mk_hash(0xf0), bh1 = mk_hash(0xf1);

        struct utxo_outpoint op_a = mk_op(0x03, 0);
        struct utxo_coin coin_a = mk_coin(1000, 0, NULL, 0);
        struct utxo_diff d0 = {
            .target_height = 0, .target_block = &bh0,
            .creates = &op_a, .creates_coin = &coin_a, .creates_len = 1,
        };
        ZCL_TEST_SETUP(p.apply_diff(p.self, &d0));

        uint8_t com_after_d0[32];
        ZCL_TEST_SETUP(p.sha3_commitment(p.self, com_after_d0));

        /* h=1 spends op_a and creates op_b. */
        struct utxo_outpoint op_b = mk_op(0x04, 0);
        struct utxo_coin coin_b = mk_coin(950, 1, NULL, 0);
        struct utxo_diff d1 = {
            .target_height = 1, .target_block = &bh1,
            .spends = &op_a, .spends_len = 1,
            .creates = &op_b, .creates_coin = &coin_b, .creates_len = 1,
        };
        ZCL_TEST_SETUP(p.apply_diff(p.self, &d1));
        USI_CHECK("tip after 2nd apply = 1", p.tip_height(p.self) == 1);

        struct zcl_result r = p.revert_tip(p.self, 1);
        USI_CHECK("revert_tip(1) -> OK", r.ok);
        USI_CHECK("tip after revert = 0", p.tip_height(p.self) == 0);

        /* op_a must be back, op_b must be gone. */
        struct utxo_coin coin_out;
        r = p.lookup(p.self, &op_a, &coin_out);
        USI_CHECK("op_a re-present after revert",
                  r.ok && coin_out.value_zat == 1000);
        r = p.lookup(p.self, &op_b, &coin_out);
        USI_CHECK("op_b absent after revert",
                  !r.ok && r.code == UTXO_ERR_NOT_FOUND);

        /* Commitment must match the post-d0 state. */
        uint8_t com_after_revert[32];
        ZCL_TEST_SETUP(p.sha3_commitment(p.self, com_after_revert));
        USI_CHECK("commitment after revert matches pre-d1",
                  memcmp(com_after_d0, com_after_revert, 32) == 0);

        utxo_snapshot_inmem_close(h);
    }

    /* ── 7. revert_tip with wrong expected_height -> TIP_MISMATCH. */
    {
        struct utxo_snapshot_inmem *h = NULL;
        struct utxo_snapshot_port p = {0};
        ZCL_TEST_SETUP(utxo_snapshot_inmem_open(&h, &p));
        struct block_hash bh = mk_hash(0x55);
        struct utxo_diff d = { .target_height = 0, .target_block = &bh };
        ZCL_TEST_SETUP(p.apply_diff(p.self, &d));
        struct zcl_result r = p.revert_tip(p.self, 99);
        USI_CHECK("revert_tip with wrong expected -> TIP_MISMATCH",
                  !r.ok && r.code == UTXO_ERR_TIP_MISMATCH);
        utxo_snapshot_inmem_close(h);
    }

    /* ── 8. SHA3 commitment is canonical (order-independent across
     * two snapshots built with creates in different orders). */
    {
        struct utxo_snapshot_inmem *h1 = NULL, *h2 = NULL;
        struct utxo_snapshot_port p1 = {0}, p2 = {0};
        ZCL_TEST_SETUP(utxo_snapshot_inmem_open(&h1, &p1));
        ZCL_TEST_SETUP(utxo_snapshot_inmem_open(&h2, &p2));
        struct block_hash bh = mk_hash(0x66);

        struct utxo_outpoint ops[3] = {
            mk_op(0x10, 0), mk_op(0x11, 1), mk_op(0x12, 2)
        };
        struct utxo_coin coins[3] = {
            mk_coin(1, 0, NULL, 0),
            mk_coin(2, 0, NULL, 0),
            mk_coin(3, 0, NULL, 0),
        };
        struct utxo_diff d1 = {
            .target_height = 0, .target_block = &bh,
            .creates = ops, .creates_coin = coins, .creates_len = 3,
        };
        ZCL_TEST_SETUP(p1.apply_diff(p1.self, &d1));

        /* Build snapshot 2 with the same coins, different ordering. */
        struct utxo_outpoint ops_rev[3] = { ops[2], ops[0], ops[1] };
        struct utxo_coin coins_rev[3] = { coins[2], coins[0], coins[1] };
        struct utxo_diff d2 = {
            .target_height = 0, .target_block = &bh,
            .creates = ops_rev, .creates_coin = coins_rev, .creates_len = 3,
        };
        ZCL_TEST_SETUP(p2.apply_diff(p2.self, &d2));

        uint8_t c1[32], c2[32];
        ZCL_TEST_SETUP(p1.sha3_commitment(p1.self, c1));
        ZCL_TEST_SETUP(p2.sha3_commitment(p2.self, c2));
        USI_CHECK("commitment is order-independent",
                  memcmp(c1, c2, 32) == 0);

        utxo_snapshot_inmem_close(h1);
        utxo_snapshot_inmem_close(h2);
    }

    return failures + ZCL_TEST_SETUP_FAILURES();
}
