/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for consensus parameter functions: upgrades, halving, spacing. */

#include "test/test_core.h"
#include "consensus/upgrades.h"
#include "chain/chainparams.h"

enum consensus_probe_kind {
    CONSENSUS_PROBE_UPGRADE_ACTIVE = 0,
    CONSENSUS_PROBE_ACTIVATION_HEIGHT = 1,
};

struct consensus_height_probe {
    const char *label;
    enum upgrade_index upgrade;
    int nchecks;
    int heights[3];
    bool expect[3];
};

static int tally_consensus_height_probes(const struct consensus_params *params,
                                          enum consensus_probe_kind kind,
                                          const struct consensus_height_probe *rows,
                                          int nrows)
{
    int failures = 0;

    for (int i = 0; i < nrows; i++) {
        printf("%s", rows[i].label);
        bool ok = true;
        int j = 0;
        while (ok && j < rows[i].nchecks) {
            bool got;
            if (kind == CONSENSUS_PROBE_UPGRADE_ACTIVE) {
                got = consensus_network_upgrade_active(params,
                                                        rows[i].heights[j],
                                                        rows[i].upgrade);
            } else {
                got = consensus_is_activation_height(rows[i].heights[j],
                                                      params,
                                                      rows[i].upgrade);
            }
            ok = (got == rows[i].expect[j]);
            j++;
        }
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int check_network_upgrade_active(const struct consensus_params *params)
{
    /* ── consensus_network_upgrade_active ────────────────── */
    static const struct consensus_height_probe rows[] = {
        {
            .label = "consensus_network_upgrade_active: Sprout at height 0... ",
            .upgrade = BASE_SPROUT,
            .nchecks = 1,
            .heights = {0, 0, 0},
            .expect = {true, false, false},
        },
        {
            .label = "consensus_network_upgrade_active: Sprout at height 1000000... ",
            .upgrade = BASE_SPROUT,
            .nchecks = 1,
            .heights = {1000000, 0, 0},
            .expect = {true, false, false},
        },
        {
            .label = "consensus_network_upgrade_active: Overwinter before activation... ",
            .upgrade = UPGRADE_OVERWINTER,
            .nchecks = 1,
            .heights = {476968, 0, 0},
            .expect = {false, false, false},
        },
        {
            .label = "consensus_network_upgrade_active: Overwinter at activation... ",
            .upgrade = UPGRADE_OVERWINTER,
            .nchecks = 1,
            .heights = {476969, 0, 0},
            .expect = {true, false, false},
        },
        {
            .label = "consensus_network_upgrade_active: Overwinter after activation... ",
            .upgrade = UPGRADE_OVERWINTER,
            .nchecks = 1,
            .heights = {476970, 0, 0},
            .expect = {true, false, false},
        },
        {
            .label = "consensus_network_upgrade_active: Sapling at activation... ",
            .upgrade = UPGRADE_SAPLING,
            .nchecks = 1,
            .heights = {476969, 0, 0},
            .expect = {true, false, false},
        },
        {
            .label = "consensus_network_upgrade_active: Sapling before activation... ",
            .upgrade = UPGRADE_SAPLING,
            .nchecks = 1,
            .heights = {476968, 0, 0},
            .expect = {false, false, false},
        },
        {
            .label = "consensus_network_upgrade_active: Bubbles at activation... ",
            .upgrade = UPGRADE_BUBBLES,
            .nchecks = 1,
            .heights = {585318, 0, 0},
            .expect = {true, false, false},
        },
        {
            .label = "consensus_network_upgrade_active: Bubbles before activation... ",
            .upgrade = UPGRADE_BUBBLES,
            .nchecks = 1,
            .heights = {585317, 0, 0},
            .expect = {false, false, false},
        },
        {
            .label = "consensus_network_upgrade_active: Buttercup at activation (707000)... ",
            .upgrade = UPGRADE_BUTTERCUP,
            .nchecks = 1,
            .heights = {707000, 0, 0},
            .expect = {true, false, false},
        },
        {
            .label = "consensus_network_upgrade_active: Buttercup before activation... ",
            .upgrade = UPGRADE_BUTTERCUP,
            .nchecks = 1,
            .heights = {706999, 0, 0},
            .expect = {false, false, false},
        },
        /* UPGRADE_TESTDUMMY has nActivationHeight = -1 (NO_ACTIVATION) */
        {
            .label = "consensus_network_upgrade_active: TestDummy never active... ",
            .upgrade = UPGRADE_TESTDUMMY,
            .nchecks = 2,
            .heights = {0, 999999999, 0},
            .expect = {false, false, false},
        },
    };
    return tally_consensus_height_probes(params, CONSENSUS_PROBE_UPGRADE_ACTIVE,
                                          rows,
                                          (int)(sizeof rows / sizeof rows[0]));
}

static int check_activation_height(const struct consensus_params *params)
{
    /* ── consensus_is_activation_height ──────────────────── */
    static const struct consensus_height_probe rows[] = {
        {
            .label = "consensus_is_activation_height: Sprout always false... ",
            .upgrade = BASE_SPROUT,
            .nchecks = 2,
            .heights = {0, 1, 0},
            .expect = {false, false, false},
        },
        {
            .label = "consensus_is_activation_height: Overwinter at 476969... ",
            .upgrade = UPGRADE_OVERWINTER,
            .nchecks = 3,
            .heights = {476969, 476968, 476970},
            .expect = {true, false, false},
        },
        {
            .label = "consensus_is_activation_height: Sapling at 476969... ",
            .upgrade = UPGRADE_SAPLING,
            .nchecks = 1,
            .heights = {476969, 0, 0},
            .expect = {true, false, false},
        },
        {
            .label = "consensus_is_activation_height: Bubbles at 585318... ",
            .upgrade = UPGRADE_BUBBLES,
            .nchecks = 2,
            .heights = {585318, 585317, 0},
            .expect = {true, false, false},
        },
        {
            .label = "consensus_is_activation_height: DiffAdj at 585322... ",
            .upgrade = UPGRADE_DIFFADJ,
            .nchecks = 1,
            .heights = {585322, 0, 0},
            .expect = {true, false, false},
        },
        {
            .label = "consensus_is_activation_height: Buttercup at 707000... ",
            .upgrade = UPGRADE_BUTTERCUP,
            .nchecks = 3,
            .heights = {707000, 706999, 707001},
            .expect = {true, false, false},
        },
        {
            .label = "consensus_is_activation_height: TestDummy never... ",
            .upgrade = UPGRADE_TESTDUMMY,
            .nchecks = 2,
            .heights = {0, 999999, 0},
            .expect = {false, false, false},
        },
    };
    return tally_consensus_height_probes(params,
                                          CONSENSUS_PROBE_ACTIVATION_HEIGHT,
                                          rows,
                                          (int)(sizeof rows / sizeof rows[0]));
}

static int check_subsidy_halving(const struct consensus_params *params)
{
    int failures = 0;

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

    return failures;
}

static int check_pow_target_spacing(const struct consensus_params *params)
{
    int failures = 0;

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

    return failures;
}

static int check_current_epoch(const struct consensus_params *params)
{
    int failures = 0;

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

    return failures;
}

static int check_activation_height_any(const struct consensus_params *params)
{
    int failures = 0;

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

    return failures;
}

static int check_upgrade_state(const struct consensus_params *params)
{
    int failures = 0;

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

    return failures;
}

static int check_epoch_branch_id(const struct consensus_params *params)
{
    int failures = 0;

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

    return failures;
}

static int check_next_epoch_and_activation(const struct consensus_params *params)
{
    int failures = 0;

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

    return failures;
}

static int check_averaging_window_timespan(const struct consensus_params *params)
{
    int failures = 0;

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

    return failures;
}

static int check_known_branch_ids(void)
{
    int failures = 0;

    /* ── consensus_is_branch_id ──────────────────────────── */

    printf("consensus_is_branch_id: known branch ids... ");
    {
        bool ok = consensus_is_branch_id(0);           /* Sprout */
        ok = ok && consensus_is_branch_id(0x76b809bb); /* Sapling */
        ok = ok && consensus_is_branch_id(0x930b540d); /* Buttercup/DiffAdj */
        ok = ok && !consensus_is_branch_id(0xDEADBEEF); /* unknown */
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

static int check_consensus_param_constants(const struct consensus_params *params)
{
    int failures = 0;

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

    failures += check_network_upgrade_active(params);

    failures += check_subsidy_halving(params);

    failures += check_pow_target_spacing(params);

    failures += check_current_epoch(params);

    failures += check_activation_height(params);

    failures += check_activation_height_any(params);

    failures += check_upgrade_state(params);

    failures += check_epoch_branch_id(params);

    failures += check_next_epoch_and_activation(params);

    failures += check_averaging_window_timespan(params);

    failures += check_known_branch_ids();

    failures += check_consensus_param_constants(params);

    return failures;
}
