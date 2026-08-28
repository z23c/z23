/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simnet_perf — deterministic ALGORITHMIC-COST measurement over simnet.
 *
 * WHAT THIS IS
 * ------------
 * simnet (sim/simnet.h) drives the REAL consensus fold — `connect_block()`
 * over a real `coins_view_cache` — with no disk, no network, and no real PoW.
 * That makes it the one place in this tree where the cost of the UTXO fold can
 * be measured cheaply, deterministically, and in CI. This module runs a fixed
 * workload through it at several sizes and reports per-stage CPU cost.
 *
 * WHAT THIS IS NOT — read before quoting any number from it
 * ---------------------------------------------------------
 * This is NOT a wall-clock performance measurement of the node, and it is not
 * a replacement for the real coldstart-to-tip stopwatch. There is no disk, no
 * network, no P2P, no mempool, no real PoW and no real script/Groth16
 * verification in this path (simnet mints under a covering checkpoint, so
 * `expensive_checks=false`). A green run here says nothing about how long a
 * real sync takes. It is a cheap, CI-friendly PROXY for one specific failure
 * mode: an algorithmic-complexity regression on the block-connect / UTXO path.
 *
 * WHY THE GATED METRIC IS A RATIO, NOT A ns BUDGET
 * -----------------------------------------------
 * An absolute "ns per block" budget is a machine constant: it has to be
 * re-tuned per host, it drifts, and the honest way to keep it green is to
 * raise it — which is how a budget ends up passing forever while nothing
 * checks it. So the gated metric is how per-transaction cost GROWS as the
 * workload grows:
 *
 *     growth_permille = 1000 * (cost_per_tx at the largest scale)
 *                            / (cost_per_tx at the smallest scale)
 *
 * An O(n) fold keeps per-tx cost flat: ~1000 permille on any machine, fast or
 * slow, loaded or idle. An O(n^2) fold makes per-tx cost grow with n, so over
 * a 4x workload span it lands at several thousand. The threshold is therefore
 * a property of the ALGORITHM, not of the box, which is what makes it usable
 * in CI. Absolute ns figures are still reported — as information for a human,
 * explicitly not as a gate.
 *
 * The detector is proven to discriminate: `lib/test/src/test_simnet_perf.c`
 * runs the identical workload with the `coins/coins_fault.h` hash-collapse
 * regression armed and requires the SAME budget to FAIL, then requires the
 * armed growth to exceed the clean growth by a wide margin. A perf gate that
 * has never been shown to fail is not a gate.
 */

#ifndef ZCL_SIM_SIMNET_PERF_H
#define ZCL_SIM_SIMNET_PERF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Ladder bound. Three points (1x, 2x, 4x) is the default: the two endpoints
 * carry the gated ratio, the middle one makes the shape visible to a reader. */
#define SIMNET_PERF_MAX_POINTS 6

/* ── The gated budget ──────────────────────────────────────────────────
 * Per-tx cost may not grow past this over the ladder's full scale span.
 *
 * MEASURED, not guessed. Calibration on a 32-core host (docs/SIMNET_PERF.md
 * carries the full table), 32 concurrent runs each to model worst-case CI
 * contention, at the default workload:
 *
 *   clean tree        idle: 655-1254     32 concurrent: 359-1111
 *   O(n^2) armed      idle: 3276-3399    32 concurrent: 2271-5019
 *
 * So the worst clean observation is 1254 and the best armed one is 2271, and
 * 1800 sits inside that gap: 44% above the worst clean number, 21% below the
 * best armed one. test_simnet_perf re-proves BOTH directions on every suite
 * run, so a threshold that has drifted into "always passes" territory shows up
 * as a failing self-test, not as silence. */
#define SIMNET_PERF_GROWTH_BUDGET_PERMILLE 1800

/* Default workload (the calibrated one above). 192 measured blocks x 8 spends
 * keeps the smallest ladder point long enough (~1.7k txs, ~8 ms of fold) that
 * scheduler contention averages out, and keeps every point's UTXO working set
 * in the same memory-hierarchy regime — see docs/SIMNET_PERF.md "Why the
 * ladder cannot be arbitrarily wide". */
#define SIMNET_PERF_DEFAULT_BLOCKS 192
#define SIMNET_PERF_DEFAULT_TXS_PER_BLOCK 8

/* The in-suite self-test (lib/test/src/test_simnet_perf.c) runs THIS default
 * workload, not a quarter-size ladder. The 96-block quarter-size ladder it
 * used until 2026-08-28 was calibrated the same way (32 concurrent runs:
 * clean max 1429, armed min 2174) but its real-suite contention regime is
 * NOT its calibration regime: a mixed 32-worker suite inflates the growth
 * ratio (observed clean 1905 on a tree whose solo rerun gave 1117), while at
 * the default size the calibrated contention direction is compression
 * (32-concurrent max 1111 vs idle max 1254) and each point is long enough
 * that scheduler contention averages out. The armed direction costs ~4 s
 * in-suite at this size. */

/* Test-only regressions this harness knows how to arm. Default NONE. */
enum simnet_perf_inject {
    SIMNET_PERF_INJECT_NONE = 0,
    /* coins/coins_fault.h: collapse the UTXO map's bucket hash to one bucket.
     * Results stay bit-identical; lookups go O(1) -> O(n). */
    SIMNET_PERF_INJECT_COINS_HASH_COLLAPSE = 1,
};

struct simnet_perf_config {
    int blocks;         /* measured blocks at scale 1 (>= 1) */
    int txs_per_block;  /* transparent spends per measured block (>= 1) */
    int scales[SIMNET_PERF_MAX_POINTS];
    size_t scale_count; /* >= 2; strictly increasing, scales[0] >= 1 */
    int reps;           /* samples per point (>= 1); the median is reported */
    enum simnet_perf_inject inject;
};

/* One workload size, after median-of-reps. */
struct simnet_perf_point {
    int scale;
    int blocks;                 /* measured blocks at this scale */
    uint64_t measured_txs;      /* txs folded in the measured phase */
    uint64_t funding_blocks;    /* untimed setup blocks (map pre-load) */
    uint64_t coins_at_end;      /* live entries in the UTXO map */
    int tip_height;
    int64_t build_cpu_ns;       /* median: harness-side tx assembly */
    int64_t fold_cpu_ns;        /* median: merkle + REAL connect_block */
    int64_t total_cpu_ns;       /* build + fold */
    int64_t fold_ns_per_tx;
    int64_t total_ns_per_block;
};

struct simnet_perf_result {
    struct simnet_perf_point points[SIMNET_PERF_MAX_POINTS];
    size_t point_count;
    int scale_span;                  /* scales[last] / scales[0] */
    int reps;
    enum simnet_perf_inject inject;
    /* Derived, machine-independent (the gated metrics). */
    int64_t fold_growth_permille;
    int64_t total_growth_permille;
    /* Derived, machine-DEPENDENT (informational only). */
    int64_t fold_ns_per_tx;          /* at the largest scale */
    int64_t total_ns_per_block;      /* at the largest scale */
    /* Anti-vacuity: a budget can assert the workload actually ran. */
    uint64_t measured_txs;           /* at the largest scale */
    uint64_t coins_at_end;           /* at the largest scale */
};

/* Fill `cfg` with the calibrated defaults (see docs/SIMNET_PERF.md):
 * blocks=192, txs_per_block=8, scales {1,2,4}, reps=1, inject=NONE.
 * Every point additionally runs one DISCARDED warm-up sample. */
void simnet_perf_config_defaults(struct simnet_perf_config *cfg);

/* Run the whole ladder. Deterministic: the workload is a fixed sequence of
 * mints with fixed values and scriptSigs, so two runs at the same config fold
 * byte-identical blocks (only the ns figures differ).
 *
 * Returns false (and logs) on a bad config, OOM, or any rejected mint — a
 * rejected mint is a harness bug per the simnet contract, never a validator
 * bug, and it must never be reported as a perf result. */
bool simnet_perf_run(const struct simnet_perf_config *cfg,
                     struct simnet_perf_result *out);

/* Metric lookup by name, for `expect METRIC OP VALUE` assertions. Names:
 *   fold_growth_permille, total_growth_permille   (gated; machine-independent)
 *   fold_ns_per_tx, total_ns_per_block            (informational; per-machine)
 *   measured_txs, coins_at_end                    (anti-vacuity)
 *   scale_span, points, reps
 * Returns false for an unknown name. */
bool simnet_perf_metric(const struct simnet_perf_result *r, const char *name,
                        int64_t *out);

/* Evaluate one assertion in the same shape (and with the same operator set)
 * as the chaos scenario DSL's `expect METRIC OP VALUE` — see
 * docs/CHAOS_HARNESS.md. Operators: == != >= <= > <
 *
 * Returns 0 on pass, -1 on fail, -2 on an unknown operator, -3 on an unknown
 * metric. `*out_actual` receives the metric's value whenever it resolved. */
int simnet_perf_expect(const struct simnet_perf_result *r, const char *name,
                       const char *op, int64_t expected, int64_t *out_actual);

/* Human-readable per-point table plus the derived metrics. */
void simnet_perf_print(const struct simnet_perf_result *r, FILE *out);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_SIM_SIMNET_PERF_H */
