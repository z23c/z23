/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_rom_state_checkpoint — golden assertion for the compiled ROM state
 * checkpoint (the "shielded ROM keystone",
 * core/chainparams/src/checkpoints.c:g_rom_state_checkpoint).
 *
 * The keystone extends the transparent-only sha3_utxo_checkpoint to a
 * COMPLETE state commitment at height 3,056,758: the coins fold PLUS the
 * combined Sprout/Sapling anchor history, both commitment-tree frontier
 * roots, and the combined nullifier history. The values were produced by an
 * independent from-genesis fold of the real chain (producer bundle
 * consensus-state-bundle-3056758.sqlite) and re-derived from raw bundle
 * rows by tools/rom_two_builder_compare.c.
 *
 * This test is the bake's cross-check:
 *   (1) it INDEPENDENTLY re-derives rom_state_root from the struct fields
 *       (SHA3-256 over the pinned preimage below, written out by hand here
 *       — mirrors rtb_rom_state_root in tools/rom_two_builder_compare.c) and
 *       asserts equality with the baked constant, so a transcription slip in
 *       ANY field fails LOUD;
 *   (2) it asserts the coins fields are byte-identical to the existing
 *       g_sha3_checkpoint (the two structs must never drift apart);
 *   (3) it asserts the test-override seam works.
 */

#include "test/test_core.h"
#include "chain/checkpoints.h"
#include "crypto/sha3.h"

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

#undef CHECK

    if (failures)
        printf("=== rom-state-checkpoint: %d keystone golden check(s) "
               "FAILED ===\n", failures);
    return failures;
}
