/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sapling wave — Lane A: sim-local Sapling/Overwinter activation profile.
 *
 * Proves that simnet_activate_sapling_at() lowers the Overwinter+Sapling
 * activation heights on the sim's LOCAL params value-copy ONLY, so a
 * transparent-only block minted at a post-activation sim height passes the
 * REAL connect_block (connect_block.c:704-736 requires a non-zero
 * hashFinalSaplingRoot once Sapling is active). It also pins the inviolable
 * no-mainnet-leak property: chain_params_get() STILL reports Sapling at
 * mainnet height 476969 before AND after the sim mutation.
 *
 * If a mint here is rejected it means the harness built the wrong block, not
 * that the validator is wrong — no consensus predicate is touched.
 */

#include "test/test_core.h"

#include "sim/simnet.h"
#include "chain/chainparams.h"
#include "consensus/params.h"
#include "consensus/upgrades.h"
#include "sapling/incremental_merkle_tree.h"
#include "core/uint256.h"

#include <stdio.h>
#include <string.h>

#define SA_CHECK(name, expr) do {          \
    printf("%s... ", (name));              \
    if ((expr)) printf("OK\n");            \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Mainnet Sapling (and Overwinter) activation height — the golden value that
 * must NEVER move as a side effect of a sim-local activation profile.
 * Mirrors core/modules/chain/src/chainparams.c:130-132. */
#define MAINNET_SAPLING_HEIGHT 476969

/* First mintable sim height (simnet.c SIM_BASE_HEIGHT). The synthetic base tip
 * sits one below, so the first minted block is at this height. */
#define SIM_FIRST_MINT_HEIGHT 100

int test_simnet_sapling_activation(void)
{
    int failures = 0;

    /* ── No-leak baseline (BEFORE): mainnet params untouched. ─────── */
    const struct chain_params *mp = chain_params_get();
    SA_CHECK("mainnet Sapling activation is 476969 (before)",
             mp->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight
                 == MAINNET_SAPLING_HEIGHT);
    SA_CHECK("mainnet Sapling INACTIVE at sim height 100 (before)",
             !consensus_network_upgrade_active(&mp->consensus,
                                               SIM_FIRST_MINT_HEIGHT,
                                               UPGRADE_SAPLING));

    struct simnet s;
    SA_CHECK("simnet_init", simnet_init(&s));

    /* The value-copy inherits the mainnet profile until we lower it. */
    SA_CHECK("sim inherits mainnet Sapling height before override",
             s.params.consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight
                 == MAINNET_SAPLING_HEIGHT);
    SA_CHECK("sim Sapling INACTIVE at height 100 before override",
             !consensus_network_upgrade_active(&s.params.consensus,
                                               SIM_FIRST_MINT_HEIGHT,
                                               UPGRADE_SAPLING));

    /* ── Lower activation on the sim value-copy only. ─────────────── */
    simnet_activate_sapling_at(&s, SIM_FIRST_MINT_HEIGHT);

    SA_CHECK("sim Sapling activation lowered to 100",
             s.params.consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight
                 == SIM_FIRST_MINT_HEIGHT);
    SA_CHECK("sim Overwinter activation lowered to 100",
             s.params.consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight
                 == SIM_FIRST_MINT_HEIGHT);
    SA_CHECK("sim Sapling ACTIVE at height 100 after override",
             consensus_network_upgrade_active(&s.params.consensus,
                                              SIM_FIRST_MINT_HEIGHT,
                                              UPGRADE_SAPLING));
    SA_CHECK("sim Sapling still INACTIVE one below activation (99)",
             !consensus_network_upgrade_active(&s.params.consensus,
                                               SIM_FIRST_MINT_HEIGHT - 1,
                                               UPGRADE_SAPLING));

    /* Sanity: the empty Sapling tree root the mint helper stamps is non-zero,
     * which is exactly what defeats connect_block's all-zeros reject. */
    struct incremental_merkle_tree stree;
    sapling_tree_init(&stree);
    struct uint256 empty_root;
    incremental_tree_empty_root(&stree, &empty_root);
    static const uint8_t zeros[32] = {0};
    SA_CHECK("empty Sapling tree root is non-zero",
             memcmp(empty_root.data, zeros, 32) != 0);

    /* ── Drive a transparent-only post-activation block through the REAL
     *    connect_block. The mint helper stamps the empty Sapling root, so the
     *    (now active) hashFinalSaplingRoot check passes. ────────────── */
    struct uint256 cb0;
    bool minted0 = simnet_mint_coinbase(&s, &cb0);
    SA_CHECK("transparent coinbase accepted at post-activation height 100",
             minted0);
    SA_CHECK("tip advanced to height 100", simnet_tip_height(&s)
                 == SIM_FIRST_MINT_HEIGHT);
    SA_CHECK("post-activation coinbase coin is present in the UTXO view",
             minted0 && simnet_coin_exists(&s, &cb0));

    /* A second post-activation block confirms the empty-root path is stable
     * across mints, not a one-off. */
    struct uint256 cb1;
    bool minted1 = simnet_mint_coinbase(&s, &cb1);
    SA_CHECK("second transparent block accepted at height 101", minted1);
    SA_CHECK("tip advanced to height 101", simnet_tip_height(&s)
                 == SIM_FIRST_MINT_HEIGHT + 1);

    simnet_free(&s);

    /* ── No-leak (AFTER): the sim mutation did NOT touch mainnet. ──── */
    const struct chain_params *mp2 = chain_params_get();
    SA_CHECK("mainnet Sapling activation STILL 476969 (after)",
             mp2->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight
                 == MAINNET_SAPLING_HEIGHT);
    SA_CHECK("mainnet Overwinter activation STILL 476969 (after)",
             mp2->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight
                 == MAINNET_SAPLING_HEIGHT);
    SA_CHECK("mainnet Sapling STILL INACTIVE at height 100 (after)",
             !consensus_network_upgrade_active(&mp2->consensus,
                                               SIM_FIRST_MINT_HEIGHT,
                                               UPGRADE_SAPLING));

    printf("\n=== simnet_sapling_activation: %d failure(s) ===\n", failures);
    return failures;
}
