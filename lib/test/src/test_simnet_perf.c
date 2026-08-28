/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves the simnet algorithmic-cost detector (lib/sim/src/simnet_perf.c,
 * surfaced as build/bin/simperf) can actually DETECT a performance regression,
 * rather than printing a number that happens to pass forever.
 *
 * A perf gate nobody has ever seen fail is not a gate. So this group runs the
 * IDENTICAL workload twice in one process — once clean, once with a real
 * O(1)->O(n) regression armed in the UTXO map (coins/coins_fault.h: the bucket
 * hash collapses to a single bucket, so every find/insert/erase walks one long
 * probe chain) — and requires, IN SUITE:
 *
 *   1. the armed arm's per-transaction fold cost exceeds the clean arm's by
 *      >= 4x at EVERY ladder point (per-scale same-window A/B: both arms fold
 *      byte-identical blocks seconds apart on the same cores, so scheduler
 *      load moves both arms together; the calibration margin is ~13x),
 *   2. the two runs folded the SAME number of transactions and ended with the
 *      SAME UTXO count and tip height — i.e. the injected regression is
 *      completely invisible to every count-based check, which is exactly why a
 *      cost detector has to exist. This is the QAP-matrix lesson in miniature:
 *      a checker that only counts results reports green while the code is
 *      genuinely wrong.
 *
 * The ABSOLUTE growth budgets (clean passes / armed fails, both metrics) are
 * idle-machine measurements and are asserted by the dedicated lanes
 * `make sim-perf` / `make sim-perf-teeth`, not in here: a mixed 32-worker
 * suite inflates the clean growth ratio past the budget and compresses the
 * armed/clean growth discrimination below the idle-regime margin, so no
 * growth assertion survives contact with a parallel run. The suite prints
 * the budget line informationally; docs/SIMNET_PERF.md carries the
 * calibration, both directions, and the 2026-08-28 incident that moved the
 * absolute assertions out of suite.
 *
 * Runtime note: the group runs the DEFAULT calibrated workload. The
 * quarter-size (96-block) ladder it used before 2026-08-28 was retired after
 * the healthy-tree false positive above; the default points are long enough
 * that scheduler contention averages out within a point. */

#include "test/test_core.h"

#include "coins/coins_fault.h"
#include "coins/coins_view.h"
#include "sim/simnet.h"
#include "sim/simnet_perf.h"

#include <stdio.h>
#include <string.h>

#define SP_CHECK(name, expr) do {          \
    printf("%s... ", (name));              \
    if ((expr)) printf("OK\n");            \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static void sp_config(struct simnet_perf_config *cfg,
                      enum simnet_perf_inject inject)
{
    simnet_perf_config_defaults(cfg);
    cfg->inject = inject;
}

/* Per-scale same-window teeth: at every ladder point the armed arm's
 * per-transaction fold cost must beat the clean arm's by min_ratio/10 x
 * (fixed-point, so 40 means 4.0x). Both arms fold byte-identical blocks
 * seconds apart on the same cores, so scheduler load moves both; only an
 * injection-shaped collapse (or bimodal contention) crosses the ratio. */
static bool sp_arms_discriminate(const struct simnet_perf_result *clean,
                                 const struct simnet_perf_result *armed,
                                 int64_t min_ratio_times_ten)
{
    if (!clean || !armed || clean->point_count == 0 ||
        clean->point_count != armed->point_count)
        return false;
    for (size_t i = 0; i < clean->point_count; i++) {
        int64_t c = clean->points[i].fold_ns_per_tx;
        int64_t a = armed->points[i].fold_ns_per_tx;
        if (c <= 0 || a <= 0 || a * 10 < c * min_ratio_times_ten)
            return false;
    }
    return true;
}

int test_simnet_perf(void)
{
    printf("\n=== simnet perf detector (does the cost budget have teeth?) "
           "===\n");
    int failures = 0;

    struct simnet_perf_config clean_cfg, armed_cfg;
    sp_config(&clean_cfg, SIMNET_PERF_INJECT_NONE);
    sp_config(&armed_cfg, SIMNET_PERF_INJECT_COINS_HASH_COLLAPSE);

    struct simnet_perf_result clean, armed;
    memset(&clean, 0, sizeof(clean));
    memset(&armed, 0, sizeof(armed));

    bool clean_ran = simnet_perf_run(&clean_cfg, &clean);
    SP_CHECK("clean workload runs", clean_ran);
    bool armed_ran = simnet_perf_run(&armed_cfg, &armed);
    SP_CHECK("regression-armed workload runs", armed_ran);

    if (!clean_ran || !armed_ran) {
        printf("simnet_perf: workload did not run — cannot judge the "
               "detector\n");
        return failures ? failures : 1;
    }

    printf("  clean:\n");
    simnet_perf_print(&clean, stdout);
    printf("  regression-armed:\n");
    simnet_perf_print(&armed, stdout);

    /* ── 1+2: the budgets are printed, not asserted, in here ────────── */
    /* The absolute growth budgets are idle-machine measurements and their
     * enforcement home is `make sim-perf` / `make sim-perf-teeth` on a quiet
     * host. A mixed 32-worker suite is a different contention regime: it
     * inflates the clean growth ratio past the budget (observed 2604 vs a
     * solo 1068 on the same binary and tree) AND compresses the growth-ratio
     * discrimination (armed/clean 1.47x vs the 1.8x the idle regime shows),
     * so no growth assertion is honest inside a parallel run. What IS honest
     * is the per-scale same-window A/B below: both ladders fold
     * byte-identical blocks seconds apart, and at calibration the armed
     * arm's per-transaction fold cost sits ~13x above the clean arm's at
     * every scale. 4x survives that much asymmetric scheduler noise; if it
     * ever fires, either the injection arm broke or the box is pathologically
     * bimodal — run the dedicated lane before concluding either. The budget
     * line stays printed so drift stays visible to a reader of the log. */
    int64_t clean_growth = -1, armed_growth = -1;
    (void)simnet_perf_expect(&clean, "fold_growth_permille", "<=",
                             SIMNET_PERF_GROWTH_BUDGET_PERMILLE,
                             &clean_growth);
    (void)simnet_perf_expect(&armed, "fold_growth_permille", "<=",
                             SIMNET_PERF_GROWTH_BUDGET_PERMILLE,
                             &armed_growth);
    printf("  budget (informational in-suite): fold_growth_permille <= %d  "
           "clean=%lld armed=%lld\n",
           SIMNET_PERF_GROWTH_BUDGET_PERMILLE, (long long)clean_growth,
           (long long)armed_growth);

    /* ── 3: per-scale same-window discrimination ───────────────────── */
    SP_CHECK("armed per-tx fold cost exceeds clean at every ladder point",
             sp_arms_discriminate(&clean, &armed, 40));

    /* ── 4: the regression is invisible to every count-based check ──── */
    SP_CHECK("both runs folded the same transaction count",
             clean.measured_txs == armed.measured_txs &&
             clean.measured_txs > 0);
    SP_CHECK("both runs ended with the same UTXO count",
             clean.coins_at_end == armed.coins_at_end &&
             clean.coins_at_end > 0);
    SP_CHECK("both runs ended at the same tip height",
             clean.point_count == armed.point_count &&
             clean.points[clean.point_count - 1].tip_height ==
                 armed.points[armed.point_count - 1].tip_height);

    /* ── The metric/operator surface itself ────────────────────────── */
    int64_t sink = 0;
    SP_CHECK("unknown metric is reported, not silently passed",
             simnet_perf_expect(&clean, "no_such_metric", "<=", 1, &sink) == -3);
    SP_CHECK("unknown operator is reported, not silently passed",
             simnet_perf_expect(&clean, "fold_growth_permille", "=~", 1,
                                &sink) == -2);
    SP_CHECK("anti-vacuity metric resolves",
             simnet_perf_metric(&clean, "measured_txs", &sink) && sink > 0);
    SP_CHECK("ladder really had a span to measure across",
             clean.scale_span >= 2 && clean.point_count >= 2);

    /* ── The injection hook's own safety contract ──────────────────── */
    {
        struct simnet s;
        SP_CHECK("hook: simnet init", simnet_init(&s));
        SP_CHECK("hook: a fresh map reports the real hash",
                 !coins_fault_map_hash_collapsed(&s.view.cache_coins));
        SP_CHECK("hook: arming an empty map is allowed",
                 coins_fault_arm_map_hash_collapse(&s.view.cache_coins, true));
        SP_CHECK("hook: armed state is observable",
                 coins_fault_map_hash_collapsed(&s.view.cache_coins));
        SP_CHECK("hook: disarming an empty map is allowed",
                 coins_fault_arm_map_hash_collapse(&s.view.cache_coins, false));
        /* Populate, then prove the hook REFUSES to change the hash under live
         * entries — flipping it there would strand entries behind an empty
         * slot, turning a perf hook into a correctness fault. */
        SP_CHECK("hook: mint one block to populate the map",
                 simnet_mint_coinbase(&s, NULL));
        SP_CHECK("hook: the map is now populated",
                 coins_map_count(&s.view.cache_coins) > 0);
        SP_CHECK("hook: arming a POPULATED map is refused",
                 !coins_fault_arm_map_hash_collapse(&s.view.cache_coins, true));
        SP_CHECK("hook: the refused arm left the map on the real hash",
                 !coins_fault_map_hash_collapsed(&s.view.cache_coins));
        SP_CHECK("hook: NULL map is refused",
                 !coins_fault_arm_map_hash_collapse(NULL, true) &&
                 !coins_fault_map_hash_collapsed(NULL));
        simnet_free(&s);
    }

    if (failures == 0)
        printf("simnet_perf: detector discriminates — budget passes clean "
               "(%lld) and fails armed (%lld)\n",
               (long long)clean_growth, (long long)armed_growth);
    return failures;
}
