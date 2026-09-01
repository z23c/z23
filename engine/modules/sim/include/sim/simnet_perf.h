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
 * The detector is proven to discriminate: `tests/harness/src/test_simnet_perf.c`
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
 * MEASURED, not guessed. Re-measured 2026-08-28 on a 32-core 7950X3D after the
 * workload gained `funding_multiple` ballast and min-of-reps sampling — 17
 * observations spanning an idle box, a 32-worker synthetic memory load, and
 * four real 32-worker `test_parallel` suite runs:
 *
 *   clean tree     967 - 1339
 *   O(n^2) armed  3347 - 3647
 *
 * So the worst clean observation is 1339 and the best armed one is 3347, and
 * 1800 sits inside that gap: 34% above the worst clean number, 46% below the
 * best armed one. test_simnet_perf re-proves BOTH directions on every suite
 * run, so a threshold that has drifted into "always passes" territory shows up
 * as a failing self-test, not as silence.
 *
 * The figures this replaces (clean 655-1254 / armed 3276-3399 idle, and the
 * 32-concurrent columns) were taken before the 2026-08-28 workload change.
 * docs/SIMNET_PERF.md still carries that older table and its 96-block
 * self-test rows; they describe funding_multiple=1, reps=1 and need the same
 * refresh. */
#define SIMNET_PERF_GROWTH_BUDGET_PERMILLE 1800

/* Default workload (the calibrated one above). 192 measured blocks x 8 spends
 * keeps every point's UTXO working set in the same memory-hierarchy regime —
 * see docs/SIMNET_PERF.md "Why the ladder cannot be arbitrarily wide".
 *
 * It does NOT make the smallest point self-averaging. That claim used to be
 * here, and it was wrong: ~1.7k txs is an ~8 ms CPU window, short enough that
 * co-resident work inflates a single sample by 2x. Noise is handled by
 * SIMNET_PERF_DEFAULT_REPS (min-of-samples), and the discrimination margin by
 * SIMNET_PERF_DEFAULT_FUNDING_MULTIPLE — not by this size. */
#define SIMNET_PERF_DEFAULT_BLOCKS 192
#define SIMNET_PERF_DEFAULT_TXS_PER_BLOCK 8

/* Samples per ladder point, of which the MINIMUM is reported (plus one
 * discarded warm-up). Three, not one, because timing noise here is one-sided —
 * contention only ever ADDS time — so the minimum converges on the
 * uncontaminated cost while a single sample reports whatever that one window
 * happened to cost. Measured need: the smallest ladder point's clean fold is an
 * ~8 ms CPU window, and single samples of it were observed at 9556 and 9987
 * ns/tx against a ~4800 ns/tx floor (2.0x one-sided inflation) on a box running
 * other work — on its own enough to drag the armed/clean discrimination ratio
 * below the 4.0x self-test floor whatever the workload. Three samples cut the
 * armed arm's run-to-run spread to +-0.5% and the clean arm's to +-3%. See
 * engine/modules/sim/src/simnet_perf.c's perf_min() for why the minimum is also the
 * STRICTER estimator for that self-test.
 * Costs ~2x the wall time of reps=1. */
#define SIMNET_PERF_DEFAULT_REPS 3

/* How many coinbases the UTXO map holds per coinbase the measured phase
 * spends, all of the surplus minted BEFORE the spendable ones. 1 = the map is
 * exactly the measured working set (what this harness did before 2026-08-28);
 * 2 = every spendable coin sits behind one ballast coin that the measured fold
 * never touches.
 *
 * WHY THIS KNOB EXISTS
 * The map's SIZE and the measured fold's WORK used to be welded together —
 * every funded coinbase was spent, so the only way to deepen the map was to
 * time more transactions. That coupling left the detector self-test with no
 * margin at the smallest ladder point: test_simnet_perf requires the armed arm
 * to cost >= 4.0x the clean arm at EVERY point, and the smallest point measured
 * 4.37-4.54x idle and 3.89x under 32-worker load. A 4.0x floor under a 4.4x
 * signal is not a gate, it is a coin flip, and no estimator can fix a margin
 * the workload does not contain.
 *
 * WHY BALLAST BUYS MARGIN, AND WHY ORDER IS LOAD-BEARING
 * coins_map (core/modules/coins/src/coins_view.c) is open addressing with linear
 * probing. Under SIMNET_PERF_INJECT_COINS_HASH_COLLAPSE every key hashes to
 * bucket 0, so live entries form one contiguous run and a coin's find/erase
 * cost is its POSITION IN THAT RUN — not the map's entry count. So ballast
 * minted AFTER the spendable coins sits behind them and is never probed
 * (measured: scale-1 ratio 4.4x -> 4.8x, i.e. nearly nothing), while ballast
 * minted BEFORE them deepens every single spend (measured: 4.4x -> 6.3-8.4x
 * idle, 5.48-6.58x under a 32-worker load). This is the cheap axis: it deepens
 * the probe without timing one extra transaction. The clean arm is unaffected —
 * a real hash scatters the same entries and stays O(1) (measured clean
 * ns/tx is unchanged, and fold_growth_permille stays ~970-1190).
 *
 * COST: the ballast is untimed setup, but the armed arm's setup is O(n^2) in
 * the run length, and the armed MEASURED fold roughly doubles. In-suite the
 * group goes from 2.3 s (reps=1, multiple=1) to ~9 s (reps=3, multiple=2).
 * Raising this further is linear in discrimination and roughly linear in wall
 * time; 2 is the smallest value that clears the 4.0x floor with real margin. */
#define SIMNET_PERF_DEFAULT_FUNDING_MULTIPLE 2

/* The in-suite self-test (tests/harness/src/test_simnet_perf.c) runs THIS default
 * workload, not a quarter-size ladder. The 96-block quarter-size ladder it
 * used until 2026-08-28 was calibrated the same way (32 concurrent runs:
 * clean max 1429, armed min 2174) but its real-suite contention regime is
 * NOT its calibration regime: a mixed 32-worker suite inflates the growth
 * ratio (observed clean 1905 on a tree whose solo rerun gave 1117), and the
 * same proved true at this default size (in-suite clean 2604 vs solo 1068 —
 * see docs/SIMNET_PERF.md). Which is why the in-suite group asserts no
 * growth budget at any size: the budgets live in `make sim-perf` /
 * `make sim-perf-teeth` on a quiet host, and the suite keeps the per-scale
 * same-window armed-vs-clean discrimination. The armed direction costs ~4 s
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
    int reps;           /* samples per point (>= 1); the MINIMUM is reported */
    int funding_multiple; /* UTXO entries per measured spend (>= 1) */
    enum simnet_perf_inject inject;
};

/* One workload size, after min-of-reps. */
struct simnet_perf_point {
    int scale;
    int blocks;                 /* measured blocks at this scale */
    uint64_t measured_txs;      /* txs folded in the measured phase */
    uint64_t funding_blocks;    /* untimed setup mints (map pre-load + ballast) */
    uint64_t coins_at_end;      /* live entries in the UTXO map */
    int tip_height;
    int64_t build_cpu_ns;       /* min-of-reps: harness-side tx assembly */
    int64_t fold_cpu_ns;        /* min-of-reps: merkle + REAL connect_block */
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
 * blocks=192, txs_per_block=8, scales {1,2,4}, reps=3, funding_multiple=2,
 * inject=NONE.
 * Every point additionally runs one DISCARDED warm-up sample, and reports the
 * MINIMUM of its `reps` measured samples. */
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
