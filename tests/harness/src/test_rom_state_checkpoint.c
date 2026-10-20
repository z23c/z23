/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_rom_state_checkpoint: golden assertion for the compiled ROM state
 * checkpoint (core/chainparams/src/checkpoints.c:g_rom_state_checkpoint) at
 * height 3,056,758: the coins fold plus the Sprout/Sapling anchor history,
 * both frontier roots and the nullifier history.
 *   (1) re-derives rom_state_root from the struct fields (mirrors
 *       rtb_rom_state_root in tools/rom_two_builder_compare.c) and asserts
 *       equality with the baked constant;
 *   (2) asserts the coins fields match g_sha3_checkpoint;
 *   (3) asserts the test-override seam works;
 *   (4) pins the baked ladder rung at height 3,200,000 (g_rom_state_rungs).
 */

#include "test/test_core.h"
#include "chain/checkpoints.h"
#include "base/hex.h"
#include "crypto/sha3.h"
#include "storage/checkpoint_rung.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void rom_test_u64le(struct sha3_256_ctx *c, uint64_t v)
{
    unsigned char b[8];
    for (int i = 0; i < 8; i++)
        b[i] = (unsigned char)((v >> (8 * i)) & 0xff);
    sha3_256_write(c, b, sizeof(b));
}

/* The pinned rom_state_root preimage (see checkpoints.h): domain
 * "zcl.rom_state_checkpoint.v1/root" including the trailing NUL, then
 * height LE8 | block_hash | utxo_root | utxo_count LE8 | total_supply LE8 |
 * anchor_digest | anchor_count LE8 | sprout_frontier_root |
 * sprout_frontier_height LE8 | sapling_frontier_root |
 * sapling_frontier_height LE8 | nullifier_digest | nullifier_count LE8. */
static void rom_test_rederive_root(const struct rom_state_checkpoint *cp,
                                   uint8_t out[32])
{
    static const char domain[] = "zcl.rom_state_checkpoint.v1/root";
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const unsigned char *)domain,
                   sizeof(domain)); /* trailing NUL included */
    rom_test_u64le(&c, (uint64_t)cp->height);
    sha3_256_write(&c, cp->block_hash, 32);
    sha3_256_write(&c, cp->utxo_root, 32);
    rom_test_u64le(&c, cp->utxo_count);
    rom_test_u64le(&c, (uint64_t)cp->total_supply);
    sha3_256_write(&c, cp->anchor_digest, 32);
    rom_test_u64le(&c, cp->anchor_count);
    sha3_256_write(&c, cp->sprout_frontier_root, 32);
    rom_test_u64le(&c, (uint64_t)cp->sprout_frontier_height);
    sha3_256_write(&c, cp->sapling_frontier_root, 32);
    rom_test_u64le(&c, (uint64_t)cp->sapling_frontier_height);
    sha3_256_write(&c, cp->nullifier_digest, 32);
    rom_test_u64le(&c, cp->nullifier_count);
    sha3_256_finalize(&c, out);
}

#define RUNG_CHECK(desc, cond)                                            \
    do {                                                                  \
        printf("rom-state-checkpoint: %s... ", (desc));                   \
        if (cond) printf("OK\n");                                         \
        else { printf("FAIL\n"); failures++; }                            \
    } while (0)

/* Baked ladder rung h=3200000 (two-builder r1/r2 byte-identical). Pins the
 * rung to the independently derived sheet; the h=3056758 keystone assertions
 * stay in test_rom_state_checkpoint, untouched. */
static int rom_test_rung_table_and_root(void)
{
    int failures = 0;
    static const char want_root[] =
        "6b73cbe3d3c228f95f7213aa44db2f9e369fd5c8241e454d6750580b50866a21";
    static const char want_cw[] =
        "000000000000000000000000000000000000000000000000000b33f21b074f27";
    uint8_t w[32], re[32];
    const struct rom_state_rung *rg = get_rom_state_rung_at(0);
    RUNG_CHECK("rung table holds exactly the 3200000 rung",
               get_rom_state_rung_count() == 1 && rg != NULL &&
               get_rom_state_rung_at(1) == NULL && rg->cp.height == 3200000);
    if (!rg)
        return failures + 1;
    rom_test_rederive_root(&rg->cp, re);
    RUNG_CHECK("rung rom_state_root re-derives from its fields",
               memcmp(re, rg->cp.rom_state_root, 32) == 0);
    RUNG_CHECK("rung rom_state_root == two-builder sheet",
               zcl_hex_decode(want_root, w, 32) &&
               memcmp(w, rg->cp.rom_state_root, 32) == 0);
    RUNG_CHECK("rung chainwork == oracle header chainwork",
               zcl_hex_decode(want_cw, w, 32) &&
               memcmp(w, rg->chainwork, 32) == 0);
    return failures;
}

static int rom_test_rung_scalars_and_digest(void)
{
    int failures = 0;
    static const char want_self[] =
        "66746f2c8fb173bc071f45fc11057bb965a504f08d16d4aae7fd49165058d56c";
    uint8_t w[32];
    struct checkpoint_rung cr;
    const struct rom_state_rung *rg = get_rom_state_rung_at(0);
    if (!rg)
        return 1;
    RUNG_CHECK("rung counts and supply pin the sheet",
               rg->cp.utxo_count == 1345608 &&
               rg->cp.total_supply == 1041151456122215LL &&
               rg->cp.anchor_count == 639969 &&
               rg->cp.nullifier_count == 1501851);
    RUNG_CHECK("rung frontier heights pin the sheet",
               rg->cp.sprout_frontier_height == 2124937 &&
               rg->cp.sapling_frontier_height == 3199983);
    bool derived =
        checkpoint_rung_from_rom_checkpoint(&rg->cp, rg->chainwork, &cr);
    RUNG_CHECK("rung self_digest == exported artifact digest",
               derived && checkpoint_rung_self_consistent(&cr) &&
               zcl_hex_decode(want_self, w, 32) &&
               memcmp(w, cr.self_digest, 32) == 0);
    return failures;
}

static int rom_test_rung_lookup(void)
{
    int failures = 0;
    const struct rom_state_rung *rg = get_rom_state_rung_at(0);
    RUNG_CHECK("rung is strictly above the keystone",
               rg && rg->cp.height > get_rom_state_checkpoint()->height);
    RUNG_CHECK("lookup: keystone height -> keystone",
               get_baked_rom_state_checkpoint_at_height(3056758) ==
                   get_rom_state_checkpoint());
    RUNG_CHECK("lookup: 3200000 -> the baked rung",
               rg && get_baked_rom_state_checkpoint_at_height(3200000) ==
                         &rg->cp);
    RUNG_CHECK("lookup: any other height -> NULL",
               get_baked_rom_state_checkpoint_at_height(3100000) == NULL &&
               get_baked_rom_state_checkpoint_at_height(0) == NULL);
    RUNG_CHECK("keystone is unchanged by the rung bake",
               get_rom_state_checkpoint()->height == 3056758);
    return failures;
}

static int rom_test_ladder_rung(void)
{
    return rom_test_rung_table_and_root() + rom_test_rung_scalars_and_digest() +
           rom_test_rung_lookup();
}
#undef RUNG_CHECK

int test_rom_state_checkpoint(void)
{
    int failures = 0;

#define CHECK(desc, cond)                                                 \
    do {                                                                  \
        printf("rom-state-checkpoint: %s... ", (desc));                   \
        if (cond) printf("OK\n");                                         \
        else { printf("FAIL\n"); failures++; }                            \
    } while (0)

    const struct rom_state_checkpoint *rom = get_rom_state_checkpoint();
    const struct sha3_utxo_checkpoint *sha3 = get_sha3_utxo_checkpoint();
    CHECK("compiled keystone is present", rom != NULL);
    CHECK("transparent checkpoint is present", sha3 != NULL);
    if (!rom || !sha3) {
        printf("=== rom-state-checkpoint: checkpoint(s) missing ===\n");
        return failures + 1;
    }

    /* (1) Independent re-derivation of the folded root from the fields. */
    {
        uint8_t root[32];
        rom_test_rederive_root(rom, root);
        CHECK("rom_state_root re-derives from the baked fields",
              memcmp(root, rom->rom_state_root, 32) == 0);
    }

    /* (2) The two checkpoints must agree on the transparent state. */
    CHECK("height == sha3 checkpoint height (3056758)",
          rom->height == 3056758 && rom->height == sha3->height);
    CHECK("block_hash == sha3 checkpoint block_hash",
          memcmp(rom->block_hash, sha3->block_hash, 32) == 0);
    CHECK("utxo_root == sha3 checkpoint sha3_hash",
          memcmp(rom->utxo_root, sha3->sha3_hash, 32) == 0);
    CHECK("utxo_count == sha3 checkpoint utxo_count (1354769)",
          rom->utxo_count == 1354769 &&
          rom->utxo_count == sha3->utxo_count);
    CHECK("total_supply == sha3 checkpoint total_supply",
          rom->total_supply == 1036413794674881LL &&
          rom->total_supply == sha3->total_supply);

    /* (3) Scalar shielded fields pin the provenance sheet (the digests are
     * already committed by the root re-derivation above). */
    CHECK("anchor_count == 631645", rom->anchor_count == 631645);
    CHECK("sprout_frontier_height == 2124937",
          rom->sprout_frontier_height == 2124937);
    CHECK("sapling_frontier_height == 3056742",
          rom->sapling_frontier_height == 3056742);
    CHECK("nullifier_count == 1495126", rom->nullifier_count == 1495126);

    /* (4) Override seam: the getter returns the override while installed,
     * and the compiled-in checkpoint again after reset. */
    {
        static const struct rom_state_checkpoint fake = {
            .height = 42,
            .anchor_count = 7,
        };
        checkpoints_set_rom_state_override_for_test(&fake);
        const struct rom_state_checkpoint *got = get_rom_state_checkpoint();
        CHECK("override installed: getter returns the override",
              got == &fake && got->height == 42 && got->anchor_count == 7);
        checkpoints_reset_rom_state_override_for_test();
        CHECK("override reset: getter returns the compiled keystone",
              get_rom_state_checkpoint() != NULL &&
              get_rom_state_checkpoint()->height == 3056758);
    }

    failures += rom_test_ladder_rung();

#undef CHECK

    if (failures)
        printf("=== rom-state-checkpoint: %d keystone golden check(s) "
               "FAILED ===\n", failures);
    return failures;
}
