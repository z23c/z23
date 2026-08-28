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
 * probe chain) — and requires:
 *
 *   1. the budget PASSES on the clean run,
 *   2. the SAME budget FAILS on the armed run,
 *   3. the armed growth is at least 1.8x the clean growth measured on this same
 *      machine under this same load (the load-normalized form of 1+2: a fixed
 *      threshold can be squeezed by scheduler contention, this comparison
 *      cannot, because both measurements ride the same contention),
 *   4. the two runs folded the SAME number of transactions and ended with the
 *      SAME UTXO count and tip height — i.e. the injected regression is
 *      completely invisible to every count-based check, which is exactly why a
 *      cost detector has to exist. This is the QAP-matrix lesson in miniature:
 *      a checker that only counts results reports green while the code is
 *      genuinely wrong.
 *
 * Assertions 1 and 2 are the same `expect METRIC OP VALUE` comparison the
 * chaos DSL uses (docs/CHAOS_HARNESS.md), evaluated through
 * simnet_perf_expect(), so the test and the tool gate on one shared mechanism
 * and one shared threshold constant.
 *
 * Runtime note: the group runs the DEFAULT calibrated workload, not a
 * quarter-size ladder. The quarter-size ladder was retired 2026-08-28 after a
 * healthy tree failed the absolute budget in-suite (clean growth 1905 vs the
 * calibrated 96-size 32-worker max of 1429; solo rerun on the same host gave
 * 1117, inside the idle band): at that size a mixed-suite worker mix inflates
 * the growth ratio the same way the calibration's own model does not. At the
 * default size the calibrated contention direction is compression
 * (32-concurrent max 1111 vs idle max 1254), and each ladder point is long
 * enough that scheduler contention averages out. The armed direction costs
 * ~4x its quarter-size runtime (~4 s), well inside this suite's per-group
 * budget. docs/SIMNET_PERF.md carries both calibration tables.
 */

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

    /* ── 1+2: the same assertion must pass clean and fail armed ─────── */
    int64_t clean_growth = -1, armed_growth = -1;
    int clean_rc = simnet_perf_expect(&clean, "fold_growth_permille", "<=",
                                     SIMNET_PERF_GROWTH_BUDGET_PERMILLE,
                                     &clean_growth);
    int armed_rc = simnet_perf_expect(&armed, "fold_growth_permille", "<=",
                                     SIMNET_PERF_GROWTH_BUDGET_PERMILLE,
                                     &armed_growth);
    printf("  budget: fold_growth_permille <= %d  clean=%lld armed=%lld\n",
           SIMNET_PERF_GROWTH_BUDGET_PERMILLE, (long long)clean_growth,
           (long long)armed_growth);

    SP_CHECK("clean tree PASSES the growth budget", clean_rc == 0);
    SP_CHECK("regression-armed run FAILS the same growth budget",
             armed_rc == -1);

    /* Same for the total-cost metric, so a future stage split cannot leave one
     * of the two gated metrics silently toothless. */
    int64_t clean_total = -1, armed_total = -1;
    SP_CHECK("clean tree PASSES the total-cost budget",
             simnet_perf_expect(&clean, "total_growth_permille", "<=",
                                SIMNET_PERF_GROWTH_BUDGET_PERMILLE,
                                &clean_total) == 0);
    SP_CHECK("regression-armed run FAILS the total-cost budget",
             simnet_perf_expect(&armed, "total_growth_permille", "<=",
                                SIMNET_PERF_GROWTH_BUDGET_PERMILLE,
                                &armed_total) == -1);

    /* ── 3: load-normalized discrimination ─────────────────────────── */
    /* Leave 10% headroom for asymmetric scheduler contention in the parallel
     * suite. The primary teeth remain the clean-pass/armed-fail budget above. */
    SP_CHECK("armed growth is >= 1.8x clean growth on this same machine",
             clean_growth > 0 && armed_growth * 10 >= clean_growth * 18);

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
