/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for consensus parameter functions: upgrades, halving, spacing. */

#include "test/test_core.h"
#include "consensus/upgrades.h"
#include "chain/chainparams.h"

int test_consensus(void)
{
    int failures = 0;

    const struct chain_params *chainparams = chain_params_get();
    const struct consensus_params *params = &chainparams->consensus;

    /* ── Mainnet activation heights (from chainparams.c) ─── */
    /* BASE_SPROUT: always active (0)
     * UPGRADE_OVERWINTER: 476969
     * UPGRADE_SAPLING: 476969
     * UPGRADE_BUBBLES: 585318
     * UPGRADE_DIFFADJ: 585322
     * UPGRADE_BUTTERCUP: 707000 */

    /* ── consensus_network_upgrade_active ────────────────── */

    printf("consensus_network_upgrade_active: Sprout at height 0... ");
    {
        bool ok = consensus_network_upgrade_active(params, 0, BASE_SPROUT);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus_network_upgrade_active: Sprout at height 1000000... ");
    {
        bool ok = consensus_network_upgrade_active(params, 1000000, BASE_SPROUT);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus_network_upgrade_active: Overwinter before activation... ");
    {
        bool ok = !consensus_network_upgrade_active(params, 476968, UPGRADE_OVERWINTER);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus_network_upgrade_active: Overwinter at activation... ");
    {
        bool ok = consensus_network_upgrade_active(params, 476969, UPGRADE_OVERWINTER);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus_network_upgrade_active: Overwinter after activation... ");
    {
        bool ok = consensus_network_upgrade_active(params, 476970, UPGRADE_OVERWINTER);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus_network_upgrade_active: Sapling at activation... ");
    {
        bool ok = consensus_network_upgrade_active(params, 476969, UPGRADE_SAPLING);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus_network_upgrade_active: Sapling before activation... ");
    {
        bool ok = !consensus_network_upgrade_active(params, 476968, UPGRADE_SAPLING);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus_network_upgrade_active: Bubbles at activation... ");
    {
        bool ok = consensus_network_upgrade_active(params, 585318, UPGRADE_BUBBLES);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus_network_upgrade_active: Bubbles before activation... ");
    {
        bool ok = !consensus_network_upgrade_active(params, 585317, UPGRADE_BUBBLES);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus_network_upgrade_active: Buttercup at activation (707000)... ");
    {
        bool ok = consensus_network_upgrade_active(params, 707000, UPGRADE_BUTTERCUP);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus_network_upgrade_active: Buttercup before activation... ");
    {
        bool ok = !consensus_network_upgrade_active(params, 706999, UPGRADE_BUTTERCUP);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus_network_upgrade_active: TestDummy never active... ");
    {
        /* UPGRADE_TESTDUMMY has nActivationHeight = -1 (NO_ACTIVATION) */
        bool ok = !consensus_network_upgrade_active(params, 0, UPGRADE_TESTDUMMY);
        ok = ok && !consensus_network_upgrade_active(params, 999999999, UPGRADE_TESTDUMMY);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── consensus_halving ───────────────────────────────── */

    printf("consensus_halving: pre-Buttercup height 0... ");
    {
        /* halving = (0 - slow_start_shift) / 840000
         * slow_start_shift = 2/2 = 1
         * halving = (0 - 1) / 840000 = negative, integer division = 0 or -1
         * In C, -1/840000 = 0 (truncation toward zero) */
        int halving = consensus_halving(params, 0);
        bool ok = (halving == 0);
        if (ok) printf("OK (halving=%d)\n", halving); else { printf("FAIL (halving=%d)\n", halving); failures++; }
    }

    printf("consensus_halving: pre-Buttercup stays at 0... ");
    {
        /* Pre-Buttercup halving interval is 840000 but Buttercup activates at
         * 707000, before any pre-Buttercup halving occurs. So all pre-Buttercup
         * heights (0..706999) have halving=0. */
        int h_early = consensus_halving(params, 100000);
        int h_late = consensus_halving(params, 706999);
        bool ok = (h_early == 0) && (h_late == 0);
        if (ok) printf("OK\n"); else { printf("FAIL (early=%d, late=%d)\n", h_early, h_late); failures++; }
    }

    printf("consensus_halving: post-Buttercup... ");
    {
        /* After Buttercup (707000), halving formula changes.
         * halvings = (nHeight - shift - buttercup_height) / postInterval + 3
         * At height 707000: (707000 - 1 - 707000) / 1680000 + 3 = -1/1680000 + 3 = 0 + 3 = 3 */
        int halving = consensus_halving(params, 707000);
        bool ok = (halving == 3);
        if (ok) printf("OK (halving=%d)\n", halving); else { printf("FAIL (halving=%d)\n", halving); failures++; }
    }

    printf("consensus_halving: well after Buttercup... ");
    {
        /* At 707000 + 1680000 + 1 = 2387001:
         * (2387001 - 1 - 707000) / 1680000 + 3 = 1680000/1680000 + 3 = 1 + 3 = 4 */
        int halving = consensus_halving(params, 2387001);
        bool ok = (halving == 4);
        if (ok) printf("OK (halving=%d)\n", halving); else { printf("FAIL (halving=%d)\n", halving); failures++; }
    }

    /* ── consensus_pow_target_spacing ────────────────────── */

    printf("consensus_pow_target_spacing: pre-Buttercup... ");
    {
        int64_t spacing = consensus_pow_target_spacing(params, 706999);
        bool ok = (spacing == PRE_BUTTERCUP_POW_TARGET_SPACING); /* 150 */
        if (ok) printf("OK (%"PRId64"s)\n", spacing); else { printf("FAIL (%"PRId64")\n", spacing); failures++; }
    }

    printf("consensus_pow_target_spacing: at Buttercup activation... ");
    {
        int64_t spacing = consensus_pow_target_spacing(params, 707000);
        bool ok = (spacing == POST_BUTTERCUP_POW_TARGET_SPACING); /* 75 */
        if (ok) printf("OK (%"PRId64"s)\n", spacing); else { printf("FAIL (%"PRId64")\n", spacing); failures++; }
    }

    printf("consensus_pow_target_spacing: well after Buttercup... ");
    {
        int64_t spacing = consensus_pow_target_spacing(params, 3000000);
        bool ok = (spacing == POST_BUTTERCUP_POW_TARGET_SPACING);
        if (ok) printf("OK (%"PRId64"s)\n", spacing); else { printf("FAIL (%"PRId64")\n", spacing); failures++; }
    }

    printf("consensus_pow_target_spacing: at height 0... ");
    {
        int64_t spacing = consensus_pow_target_spacing(params, 0);
        bool ok = (spacing == PRE_BUTTERCUP_POW_TARGET_SPACING);
        if (ok) printf("OK (%"PRId64"s)\n", spacing); else { printf("FAIL (%"PRId64")\n", spacing); failures++; }
    }

    /* ── consensus_current_epoch ─────────────────────────── */

    printf("consensus_current_epoch: height 0 = Sprout... ");
    {
        int epoch = consensus_current_epoch(0, params);
        bool ok = (epoch == BASE_SPROUT);
        if (ok) printf("OK\n"); else { printf("FAIL (epoch=%d)\n", epoch); failures++; }
    }

    printf("consensus_current_epoch: height 476968 = Sprout... ");
    {
        int epoch = consensus_current_epoch(476968, params);
        bool ok = (epoch == BASE_SPROUT);
        if (ok) printf("OK\n"); else { printf("FAIL (epoch=%d)\n", epoch); failures++; }
    }

    printf("consensus_current_epoch: height 476969 = Sapling... ");
    {
        /* Both Overwinter and Sapling activate at 476969, Sapling is later in enum */
        int epoch = consensus_current_epoch(476969, params);
        bool ok = (epoch == UPGRADE_SAPLING);
        if (ok) printf("OK\n"); else { printf("FAIL (epoch=%d)\n", epoch); failures++; }
    }

    printf("consensus_current_epoch: height 585318 = Bubbles... ");
    {
        int epoch = consensus_current_epoch(585318, params);
        bool ok = (epoch == UPGRADE_BUBBLES);
        if (ok) printf("OK\n"); else { printf("FAIL (epoch=%d)\n", epoch); failures++; }
    }

    printf("consensus_current_epoch: height 585322 = DiffAdj... ");
    {
        int epoch = consensus_current_epoch(585322, params);
        bool ok = (epoch == UPGRADE_DIFFADJ);
        if (ok) printf("OK\n"); else { printf("FAIL (epoch=%d)\n", epoch); failures++; }
    }

    printf("consensus_current_epoch: height 707000 = Buttercup... ");
    {
        int epoch = consensus_current_epoch(707000, params);
        bool ok = (epoch == UPGRADE_BUTTERCUP);
        if (ok) printf("OK\n"); else { printf("FAIL (epoch=%d)\n", epoch); failures++; }
    }

    printf("consensus_current_epoch: very large height = Buttercup... ");
    {
        int epoch = consensus_current_epoch(99999999, params);
        bool ok = (epoch == UPGRADE_BUTTERCUP);
        if (ok) printf("OK\n"); else { printf("FAIL (epoch=%d)\n", epoch); failures++; }
    }

    /* ── consensus_is_activation_height ──────────────────── */

    printf("consensus_is_activation_height: Sprout always false... ");
    {
        bool ok = !consensus_is_activation_height(0, params, BASE_SPROUT);
        ok = ok && !consensus_is_activation_height(1, params, BASE_SPROUT);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus_is_activation_height: Overwinter at 476969... ");
    {
        bool ok = consensus_is_activation_height(476969, params, UPGRADE_OVERWINTER);
        ok = ok && !consensus_is_activation_height(476968, params, UPGRADE_OVERWINTER);
        ok = ok && !consensus_is_activation_height(476970, params, UPGRADE_OVERWINTER);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus_is_activation_height: Sapling at 476969... ");
    {
        bool ok = consensus_is_activation_height(476969, params, UPGRADE_SAPLING);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus_is_activation_height: Bubbles at 585318... ");
    {
        bool ok = consensus_is_activation_height(585318, params, UPGRADE_BUBBLES);
        ok = ok && !consensus_is_activation_height(585317, params, UPGRADE_BUBBLES);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus_is_activation_height: DiffAdj at 585322... ");
    {
        bool ok = consensus_is_activation_height(585322, params, UPGRADE_DIFFADJ);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus_is_activation_height: Buttercup at 707000... ");
    {
        bool ok = consensus_is_activation_height(707000, params, UPGRADE_BUTTERCUP);
        ok = ok && !consensus_is_activation_height(706999, params, UPGRADE_BUTTERCUP);
        ok = ok && !consensus_is_activation_height(707001, params, UPGRADE_BUTTERCUP);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus_is_activation_height: TestDummy never... ");
    {
        bool ok = !consensus_is_activation_height(0, params, UPGRADE_TESTDUMMY);
        ok = ok && !consensus_is_activation_height(999999, params, UPGRADE_TESTDUMMY);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── consensus_is_activation_height_any ──────────────── */

    printf("consensus_is_activation_height_any: 476969 (Overwinter+Sapling)... ");
    {
        bool ok = consensus_is_activation_height_any(476969, params);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus_is_activation_height_any: 707000 (Buttercup)... ");
    {
        bool ok = consensus_is_activation_height_any(707000, params);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus_is_activation_height_any: 500000 (no upgrade)... ");
    {
        bool ok = !consensus_is_activation_height_any(500000, params);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── consensus_upgrade_state ─────────────────────────── */

    printf("consensus_upgrade_state: Sprout always active... ");
    {
        bool ok = consensus_upgrade_state(0, params, BASE_SPROUT) == UPGRADE_ACTIVE;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus_upgrade_state: TestDummy always disabled... ");
    {
        enum upgrade_state st = consensus_upgrade_state(999999999, params, UPGRADE_TESTDUMMY);
        bool ok = (st == UPGRADE_DISABLED);
        if (ok) printf("OK\n"); else { printf("FAIL (state=%d)\n", st); failures++; }
    }

    printf("consensus_upgrade_state: Buttercup pending at 706999... ");
    {
        enum upgrade_state st = consensus_upgrade_state(706999, params, UPGRADE_BUTTERCUP);
        bool ok = (st == UPGRADE_PENDING);
        if (ok) printf("OK\n"); else { printf("FAIL (state=%d)\n", st); failures++; }
    }

    printf("consensus_upgrade_state: Buttercup active at 707000... ");
    {
        enum upgrade_state st = consensus_upgrade_state(707000, params, UPGRADE_BUTTERCUP);
        bool ok = (st == UPGRADE_ACTIVE);
        if (ok) printf("OK\n"); else { printf("FAIL (state=%d)\n", st); failures++; }
    }

    /* ── consensus_current_epoch_branch_id ───────────────── */

    printf("consensus_current_epoch_branch_id: Sprout at height 0... ");
    {
        uint32_t bid = consensus_current_epoch_branch_id(0, params);
        bool ok = (bid == 0); /* Sprout branch id is 0 */
        if (ok) printf("OK\n"); else { printf("FAIL (0x%08x)\n", bid); failures++; }
    }

    printf("consensus_current_epoch_branch_id: Sapling at 476969... ");
    {
        uint32_t bid = consensus_current_epoch_branch_id(476969, params);
        bool ok = (bid == 0x76b809bb); /* Sapling branch id */
        if (ok) printf("OK\n"); else { printf("FAIL (0x%08x)\n", bid); failures++; }
    }

    printf("consensus_current_epoch_branch_id: Buttercup at 707000... ");
    {
        uint32_t bid = consensus_current_epoch_branch_id(707000, params);
        bool ok = (bid == 0x930b540d); /* Buttercup branch id */
        if (ok) printf("OK\n"); else { printf("FAIL (0x%08x)\n", bid); failures++; }
    }

    /* ── consensus_next_epoch / consensus_next_activation_height ── */

    printf("consensus_next_epoch: at height 0... ");
    {
        int next = consensus_next_epoch(0, params);
        /* Sprout active, TestDummy disabled, Overwinter pending at height 0 */
        bool ok = (next == UPGRADE_OVERWINTER);
        if (ok) printf("OK\n"); else { printf("FAIL (next=%d)\n", next); failures++; }
    }

    printf("consensus_next_activation_height: at height 0... ");
    {
        int h = consensus_next_activation_height(0, params);
        bool ok = (h == 476969); /* Overwinter activation */
        if (ok) printf("OK\n"); else { printf("FAIL (h=%d)\n", h); failures++; }
    }

    printf("consensus_next_epoch: after all upgrades... ");
    {
        int next = consensus_next_epoch(707000, params);
        bool ok = (next == -1); /* no more pending upgrades */
        if (ok) printf("OK\n"); else { printf("FAIL (next=%d)\n", next); failures++; }
    }

    printf("consensus_next_activation_height: after all upgrades... ");
    {
        int h = consensus_next_activation_height(707000, params);
        bool ok = (h == -1);
        if (ok) printf("OK\n"); else { printf("FAIL (h=%d)\n", h); failures++; }
    }

    /* ── consensus_averaging_window_timespan ──────────────── */

    printf("consensus_averaging_window_timespan: pre-Buttercup... ");
    {
        int64_t ts = consensus_averaging_window_timespan(params, 100);
        /* nPowAveragingWindow(17) * 150 = 2550 */
        bool ok = (ts == 17 * 150);
        if (ok) printf("OK (%"PRId64")\n", ts); else { printf("FAIL (%"PRId64")\n", ts); failures++; }
    }

    printf("consensus_averaging_window_timespan: post-Buttercup... ");
    {
        int64_t ts = consensus_averaging_window_timespan(params, 707000);
        /* nPowAveragingWindow(17) * 75 = 1275 */
        bool ok = (ts == 17 * 75);
        if (ok) printf("OK (%"PRId64")\n", ts); else { printf("FAIL (%"PRId64")\n", ts); failures++; }
    }

    /* ── consensus_is_branch_id ──────────────────────────── */

    printf("consensus_is_branch_id: known branch ids... ");
    {
        bool ok = consensus_is_branch_id(0);           /* Sprout */
        ok = ok && consensus_is_branch_id(0x76b809bb); /* Sapling */
        ok = ok && consensus_is_branch_id(0x930b540d); /* Buttercup/DiffAdj */
        ok = ok && !consensus_is_branch_id(0xDEADBEEF); /* unknown */
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Consensus constants ─────────────────────────────── */

    printf("consensus params: halving intervals... ");
    {
        bool ok = (params->nPreButtercupSubsidyHalvingInterval == 840000);
        ok = ok && (params->nPostButtercupSubsidyHalvingInterval == 1680000);
        ok = ok && (params->nPreButtercupPowTargetSpacing == 150);
        ok = ok && (params->nPostButtercupPowTargetSpacing == 75);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus params: pow averaging window... ");
    {
        bool ok = (params->nPowAveragingWindow == 17);
        ok = ok && (params->nPowMaxAdjustDown == 32);
        ok = ok && (params->nPowMaxAdjustUp == 16);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("consensus params: subsidy slow start... ");
    {
        bool ok = (params->nSubsidySlowStartInterval == 2);
        ok = ok && (consensus_subsidy_slow_start_shift(params) == 1);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
