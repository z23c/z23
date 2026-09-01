# Simnet Perf — an algorithmic-cost detector for the block-connect path

## What this is

`simperf` (`tools/sim/simperf.c`, library in `engine/modules/sim/src/simnet_perf.c`) runs a
fixed, deterministic workload through the **real** consensus fold — assemble a
block, drive it through `connect_block()` over a real `coins_view_cache` — at
several workload sizes, measures the CPU cost of each stage, and gates on how
much the **per-transaction cost grows** as the workload grows.

It closes a specific gap. The simulation harness (`docs/SIMULATOR.md`,
`docs/CHAOS_HARNESS.md`) proves the chain is **correct** and **robust**: does it
converge, does it reject invalid blocks, does it recover. Nothing in it said
anything about **speed**, so an algorithmic-complexity regression on the UTXO
fold could land, pass every test, and only surface later as a slow real sync.

```bash
make sim-perf            # the detector, clean tree (the gate)
make sim-perf-teeth      # clean must PASS, regression-armed must FAIL
make t ONLY=simnet_perf  # the same both-directions proof, in-process
```

## What this is NOT

**This is not a wall-clock performance measurement of the node, and it does not
replace the real coldstart-to-tip stopwatch.** There is no disk, no network, no
P2P, no mempool, no real Equihash PoW, and no real script/Groth16 verification
on this path — simnet mints under a synthetic covering checkpoint, so
`connect_block` runs with `expensive_checks=false`. A green `simperf` run says
nothing about how long a real sync takes; the timed-sync harness against a real
peer is a separate, slower, wall-clock thing and remains the only authority on
that question.

`simperf` is a cheap, deterministic, CI-friendly **proxy for one failure mode**:
an algorithmic-complexity regression on the block-connect / UTXO path. It
detects complexity-class changes (O(1) → O(n), O(n) → O(n²)). It does **not**
detect constant-factor slowdowns — a change that makes every lookup uniformly
1.4× slower leaves the growth ratio flat and passes. That is a deliberate scope
limit, not an oversight: constant factors are what the wall-clock harnesses and
`check-crypto-perf` measure.

## Why the gate is a ratio, not a nanosecond budget

An absolute `ns_per_block <= K` budget is a machine constant. It has to be
re-tuned per host, it drifts with the compiler, and the easiest way to keep it
green is to raise it — which is exactly how a budget ends up passing forever
while nobody checks it.

So the gated metric is dimensionless:

```
growth_permille = 1000 * (cost per tx at the largest scale)
                       / (cost per tx at the smallest scale)
```

An O(n) fold keeps per-tx cost flat — ~1000 permille on a fast box, a slow box,
or a loaded box. An O(n²) fold makes per-tx cost grow with n, so over a 4×
workload span it lands at several thousand. The threshold is therefore a
property of the **algorithm**, not of the machine.

Absolute ns figures (`fold_ns_per_tx`, `total_ns_per_block`) are still reported.
They are **information for a human**, explicitly not a gate.

## The workload

At scale `s`, with `blocks` measured blocks and `M` spends per block:

- **Phase 1a, ballast** (untimed) — mint
  `blocks * s * M * (funding_multiple - 1)` coinbase-only blocks, txids
  discarded. Never spent, never looked up by the measured phase — see "Why
  `funding_multiple` exists" below for why this phase exists at all and why
  it is minted **before** phase 1b, not after.
- **Phase 1b, funding** (untimed) — mint `blocks * s * M` more coinbase-only
  blocks, keeping every coinbase txid. These are the coins the measured phase
  will spend; together with the ballast they are what pre-loads the UTXO map,
  so the map's live entry count scales with the workload.
- **Phase 2, maturity filler** (untimed) — `COINBASE_MATURITY` (100) more
  coinbase-only blocks, so the funded coinbases clear the real maturity
  predicate. Measured blocks consume funded coinbases in mint order from the
  front, so the tightest case is the last measured block spending the newest
  funded coinbase, which clears maturity by `COINBASE_MATURITY + blocks`.
- **Phase 3, measured** — `blocks * s` blocks, each carrying its own coinbase
  plus `M` transparent spends of distinct funded coinbases. CPU time splits
  into `build` (this harness assembling transactions) and `fold` (merkle root
  plus the real `connect_block`, i.e. the coins-view work).

Only phase 3 is timed, and it is timed `reps` times per ladder point (default
**3**), of which the **minimum** is reported. Timing uses
`clock_thread_cpu_ns()` (`platform/modules/platform/include/platform/clock.h`,
`CLOCK_THREAD_CPUTIME_ID`) — the existing per-thread CPU clock this tree
already uses for work-ratio measurement in `tests/harness/src/test_sapling.c`.
Per-thread CPU time removes plain scheduler preemption from the count, but not
memory-bandwidth or cache/SMT interference from a co-resident process, which
inflate CPU time too. Every ladder point also runs one further **discarded
warm-up sample** before the `reps` measured ones (same discipline as
`tools/simd_bench.c`), because without it the first point absorbs the
process's page faults, malloc arena growth, and cold icache, inflating the
ratio's denominator and flattering every result.

The workload is deterministic: fixed values, fixed scriptSigs, fixed heights.
Two runs at the same config fold byte-identical blocks; only the ns figures move.

### Why the minimum, not the median or the mean

Until 2026-08-28 each ladder point was a single sample. Timing noise on a
shared host is **one-sided** — contention from a co-resident process, cache
eviction, SMT sibling pressure, and page faults can only ever *add* time to a
sample, never remove it. A single sample therefore reports whatever
contamination that one window happened to carry, with no way to tell a clean
reading from a contaminated one. Measured case: a solo run on a loaded box put
clean scale-1 fold cost at 9556 and 9987 ns/tx against a ~4795 ns/tx
uncontaminated floor — up to a 2.0x one-sided inflation from an ~8 ms
measurement window alone, large enough on its own to erase the detector's
discrimination margin (see the self-test below) regardless of workload size.

The fix is the **minimum of several repetitions**, not a median. Under a
one-sided error model the minimum is the maximum-likelihood estimate of the
uncontaminated cost and the only estimator whose error goes to zero as `reps`
grows; a median still reports whatever the middle sample's contamination
happened to be. It is also the *stricter* choice for the self-test in
`tests/harness/src/test_simnet_perf.c`, which requires the armed arm to cost at
least 4.0x the clean arm at every ladder point: additive one-sided noise `d`
on both arms drags the observed ratio `(A+d)/(C+d)` toward 1.0, so noise is
what could either mask a real regression or manufacture a false one. Taking
the minimum on both arms strips `d` from both, so it can neither inflate the
armed arm into passing nor inflate the clean arm into failing. Default
`reps = 3` (`SIMNET_PERF_DEFAULT_REPS` in `engine/modules/sim/include/sim/simnet_perf.h`)
costs roughly 2x the wall time of `reps = 1`.

### Why `funding_multiple` exists, and why the ballast order is load-bearing

Before 2026-08-28 every funded coinbase was spent, so the UTXO map's size and
the measured phase's work were welded together — the only way to deepen the
map was to time more transactions. That coupling left the armed-vs-clean
self-test with too thin a margin at the smallest ladder point: the smallest
scale measured only 3.9-4.5x armed/clean, against the self-test's 4.0x floor —
a coin flip, not a gate, and no repetition count can widen a margin the
workload itself does not contain.

`funding_multiple` (default **2**) decouples the two: it mints
`funding_multiple - 1` untimed **ballast** coinbases per spendable one (phase
1a above), so the map holds more live entries than the measured phase ever
touches. `coins_map` (`core/modules/coins/src/coins_view.c`) is open addressing with
linear probing, and the self-test's injected regression
(`SIMNET_PERF_INJECT_COINS_HASH_COLLAPSE`, see "Proving the detector has
teeth" below) collapses every key to bucket 0, so live entries form one
contiguous probe run and a coin's find/erase cost is its **position in that
run**, not the map's entry count.

**Order is the whole effect.** Ballast minted *before* the spendable coins
(phase 1a, ahead of phase 1b) sits in front of every one of them in the probe
run and lengthens every subsequent lookup. Ballast minted *after* them sits
behind and is never probed by the measured phase at all — it changes almost
nothing. Measured at scale 1: ballast-after moved the armed/clean ratio 4.4x
→ 4.8x; ballast-before moved it 6.3-8.4x. This is the cheap axis for
discrimination margin: it deepens every probe without timing one additional
transaction. The clean arm is unaffected either way — a real hash scatters
the same entries and stays O(1), so `fold_growth_permille` on the clean arm is
unchanged by `funding_multiple`.

The cost is untimed setup only, but the setup is itself O(n²) under the armed
injection, and the armed arm's *measured* fold also grows (deeper probes cost
more even mid-fold, as coins are inserted and erased). Raising
`funding_multiple` further buys more discrimination at roughly linear
additional wall time; 2 is the smallest value that clears the 4.0x floor with
real margin — see the calibration in "The budget, and how it was calibrated"
below.

### Why the ladder cannot be arbitrarily wide

A wider scale span buys sensitivity — a quadratic path over a 16× span shows
~6500 permille instead of ~3200. It also buys a **memory-hierarchy artifact**:
at very small sizes the whole UTXO working set fits in L2, so the smallest point
is unrepresentatively fast and the growth ratio picks up cache-regime change on
top of algorithmic change. Measured on the calibration host, a
`--blocks=32 --scales=1,4,16` ladder reported **4239 permille on a clean tree**
— a false positive, purely from the 644-entry point living in cache and the
8804-entry point not.

The default ladder (`--blocks=192 --scales=1,2,4`) keeps every point's working
set in the same memory-hierarchy regime. It does **not**, on its own, make the
smallest point immune to timing noise — the smallest point is an ~8 ms CPU
window, short enough that a co-resident process can inflate a single sample by
2x (see "Why the minimum, not the median or the mean" above). Noise is handled
by repetition (`reps`, min-of-samples), and the armed/clean discrimination
margin by ballast (`funding_multiple`) — not by widening the ladder. Widen the
span only together with a re-calibration of both directions.

## The budget, and how it was calibrated

`SIMNET_PERF_GROWTH_BUDGET_PERMILLE = 1800`
(`engine/modules/sim/include/sim/simnet_perf.h`).

**2026-08-28 recalibration.** The workload changed that day (`reps` 1 → 3
min-of-samples, `funding_multiple` 1 → 2 — see "The workload" above), which
moves every absolute figure below it, so the growth-ratio numbers are quoted
from `engine/modules/sim/include/sim/simnet_perf.h`'s own calibration comment, not
re-derived here: 17 observations on a 32-core 7950X3D spanning an idle box, a
32-worker synthetic memory load, and four real 32-worker `test_parallel` suite
runs, at the default workload:

| Run | Range |
|-----|-------|
| Clean tree | 967 – 1339 |
| O(n²) armed | 3347 – 3647 |

1800 sits inside that gap: 34% above the worst clean observation (1339), 46%
below the best armed one (3347).

**The 1800 threshold itself was not changed** by the 2026-08-28 recalibration
— only the workload that measures against it. `test_simnet_perf.c` re-proves
both directions (budget passes clean, fails armed) on every suite run, so a
threshold that drifted into "always passes" territory would show up as a
failing self-test, not as silence.

Separately, and earlier the same day: the **in-suite** group stopped asserting
these absolute budgets at all. A healthy tree failed the budget assertion
inside a mixed 32-worker `test_parallel` suite even though the identical
binary passed solo (clean growth 2604 in-suite vs. 1068 solo on the same
tree) — the suite's worker mix is not the 32-concurrent-copies-of-this-test
regime the table above models, and it inflates the clean arm's growth ratio
past the budget. The absolute budgets (both directions, both metrics) are
therefore asserted only by the dedicated lanes `make sim-perf` /
`make sim-perf-teeth` on a quiet host; the in-suite group
(`make t ONLY=simnet_perf`) keeps the per-scale same-window armed-vs-clean
discrimination check instead (next section) and prints the budget line
informationally.

## Proving the detector has teeth

Per this project's own hard-won lesson — a Groth16 QAP-matrix bug satisfied
every count-based check while being genuinely wrong — a checker is worthless
until it has been shown to discriminate real-bad from real-good. So the budget
ships with a **parent-failing prover**.

`coins/coins_fault.h` arms one test-only regression in the real UTXO map. The
map (`struct coins_map`, `core/modules/coins/include/coins/coins_view.h`) is
open-addressed with linear probing, keyed by `coins_map_hash()` = the txid's
first 8 bytes. Arming `degraded_hash` collapses that bucket index to a single
constant, so:

- every `find` / `insert` / `erase` still returns the **correct** entry —
  linear probing over a *consistent* hash always does;
- every key lands on one probe chain, so lookups go **O(1) → O(n)** and the
  whole fold goes **O(n²)**.

### Why that injection site is defensible

It is a real, recurring bug class, not a strawman. A hash whose entropy silently
collapses — a truncation that keeps only a constant prefix, a mixing step
dropped in a refactor, a "simplified" key derivation — passes every correctness
test in the tree, because the map still answers every query correctly. It shows
up only as a node that got slower. And it sits on the single hottest structure
the block-connect fold touches: `coins_map_find` is called for every transaction
input, every BIP30 check, and every coin write in `connect_block`.

The hook is **default OFF for every map** (`coins_map_init()` clears it), costs
one already-resident struct-field load when unarmed (no global, no atomic, no
call), and `coins_fault_arm_map_hash_collapse()` **refuses on a non-empty map** —
flipping the hash under live entries would strand entries behind an empty slot,
which would turn a perf hook into a correctness fault. Nothing in the node ever
calls it; the only callers are `engine/modules/sim/src/simnet_perf.c` and
`tests/harness/src/test_simnet_perf.c`.

### The proof

Same workload, same binary, one flag apart. Regenerated 2026-08-29 by actually
running the default workload (`build/bin/simperf` and
`build/bin/simperf --inject=coins-hash-collapse`; `blocks=192
txs_per_block=8 reps=3 funding_multiple=2`) on the machine this doc was
written on. The exact ns/permille figures are a one-time snapshot on one host
under whatever else was running on it that moment — expect them to move
run to run within the range in "The budget, and how it was calibrated" above;
what the assertion checks is the *shape* (clean growth near 1000 = flat,
armed growth several thousand = superlinear):

```
$ build/bin/simperf
simperf: blocks=192 txs_per_block=8 reps=3 funding_multiple=2 inject=none
  scale  blocks  fund_blk  txs   coins   build_us   fold_us  fold_ns/tx  total_ns/blk
      1     192      3072  1728    4900        403      9286        5374         50469
      2     384      6144  3456    9700        843     20163        5834         54705
      4     768     12288  6912   19300       1625     39321        5688         53315
  growth over a 4x workload span (1000 = flat, per-tx cost unchanged):
    fold_growth_permille  = 1058
    total_growth_permille = 1056
expect fold_growth_permille <= 1800 (actual=1058) PASS
expect total_growth_permille <= 1800 (actual=1056) PASS
expect measured_txs == 6912 (actual=6912) PASS
expect coins_at_end >= 768 (actual=19300) PASS
expect points >= 2 (actual=3) PASS
SIMPERF ALL BUDGETS PASSED (5 assertions)

$ build/bin/simperf --inject=coins-hash-collapse
simperf: blocks=192 txs_per_block=8 reps=3 funding_multiple=2 inject=coins-hash-collapse
  scale  blocks  fund_blk  txs   coins   build_us   fold_us  fold_ns/tx  total_ns/blk
      1     192      3072  1728    4900        403     63754       36894        334153
      2     384      6144  3456    9700        872    236884       68543        619158
      4     768     12288  6912   19300       1701    908984      131508       1185788
  growth over a 4x workload span (1000 = flat, per-tx cost unchanged):
    fold_growth_permille  = 3564
    total_growth_permille = 3548
  INJECTED REGRESSION ARMED (inject=1) — this run is a detector self-test, not a measurement of the tree
expect fold_growth_permille <= 1800 (actual=3564) FAIL
expect total_growth_permille <= 1800 (actual=3548) FAIL
expect measured_txs == 6912 (actual=6912) PASS
expect coins_at_end >= 768 (actual=19300) PASS
expect points >= 2 (actual=3) PASS
SIMPERF BUDGET FAILED (2 of 5 assertions)
```

Note the `txs` and `coins` columns: **identical** in both runs. The injected
regression is completely invisible to every count-based check. That is the whole
argument for owning a cost detector.

`make sim-perf-teeth` runs exactly that pair and fails loudly if the armed run
*passes*. `make t ONLY=simnet_perf` (`tests/harness/src/test_simnet_perf.c`) runs
the same comparison in-process on every suite run, but does **not** assert
either absolute growth budget in-suite (see above) — instead it requires the
armed arm's per-transaction fold cost to beat the clean arm's by **at least
4.0x at every ladder point**, same-window (both arms fold byte-identical
blocks seconds apart on the same cores, so ordinary scheduler load moves both
arms together and mostly cancels out of the ratio). The smallest scale is the
binding one: the collapsed map's probe run is shortest there, so the
armed/clean ratio is weakest at scale 1 and grows with scale. Calibrated
worst case at scale 1: idle 6.29–8.38x; under a 32-worker synthetic load
across 10 runs, 5.48–6.58x — both comfortably clear of the 4.0x floor (see
`tests/harness/src/test_simnet_perf.c`'s own calibration comment above that
assertion). It also re-checks that both arms folded the same transaction
count and ended with the same UTXO count and tip height, i.e. that the
injected regression is completely invisible to every count-based check.

### The honest limit of this margin

The 5.48–6.58x calibrated floor at scale 1 is a property of *this specific
workload against this specific injected fault*, not a law. Two things can
move it, and either one needs a re-measurement, not a guess, before it is
trusted again:

- **The injected fault changes.** `SIMNET_PERF_INJECT_COINS_HASH_COLLAPSE` is
  one specific regression shape (every key collapses to one bucket). A
  different injected fault — a partial collapse, a different data structure
  entirely — would very likely change the armed/clean ratio and could
  legitimately need a different `funding_multiple` or a different threshold.
- **`coins_map`'s implementation changes.** The whole `funding_multiple`
  argument rests on `coins_map` being open addressing with linear probing, so
  a coin's cost under the collapsed hash is its position in the insertion
  run. If `coins_map` (`core/modules/coins/src/coins_view.c`) ever moves to a different
  collision strategy (chaining, robin hood probing, a different bucket
  layout), the ballast-ordering effect this section describes may shrink,
  vanish, or invert, and the calibration above would no longer describe the
  code.

If either changes: re-run `make sim-perf-teeth` and `make t ONLY=simnet_perf`
repeatedly (loaded and idle) and update the calibration comments in
`engine/modules/sim/include/sim/simnet_perf.h`, `tests/harness/src/test_simnet_perf.c`, and
this file together — they are three views of the same measurement and must
not drift apart. Do not "simplify" the ballast-before-funding ordering in
`engine/modules/sim/src/simnet_perf.c` without re-measuring first; it is the entire
source of the discrimination margin at the smallest ladder point (see "Why
`funding_multiple` exists" above), and a change that looks like harmless
cleanup there can quietly collapse the margin back to a coin flip.

## Assertions

`simperf` mirrors the chaos scenario DSL's assertion shape (see
`docs/CHAOS_HARNESS.md`, "expect METRIC OP VALUE") rather than inventing a
second grammar. Operators are the same six: `==` `!=` `>=` `<=` `>` `<`.

```bash
build/bin/simperf --expect='fold_growth_permille <= 1500' \
                  --expect='measured_txs == 6912'
```

Metrics:

| Metric | Kind | Meaning |
|--------|------|---------|
| `fold_growth_permille` | **gated**, machine-independent | per-tx `connect_block` cost growth across the ladder |
| `total_growth_permille` | **gated**, machine-independent | same, including harness-side tx assembly |
| `fold_ns_per_tx` | informational, per-machine | absolute fold cost at the largest scale |
| `total_ns_per_block` | informational, per-machine | absolute total cost at the largest scale |
| `measured_txs` | anti-vacuity | transactions actually folded |
| `coins_at_end` | anti-vacuity | live UTXO entries at the end |
| `scale_span` | anti-vacuity | largest scale / smallest scale |
| `points`, `reps` | anti-vacuity | ladder shape |

With no `--expect`, the default budget is applied: both growth metrics against
`SIMNET_PERF_GROWTH_BUDGET_PERMILLE`, plus derived anti-vacuity assertions on
`measured_txs`, `coins_at_end` and `points` — so a workload that silently folded
nothing FAILS rather than reporting a flattering ratio over two empty runs. The
library refuses a vacuous sample outright (`fold_cpu_ns <= 0` or zero
transactions), and any rejected mint aborts the run with no verdict, because
under the simnet contract a rejected block is a harness bug and must never be
reported as a perf result.

## Why a standalone tool rather than a `.scenario` command

The chaos DSL was the other candidate (`mode simnet` already drives real
consensus). It was rejected for three concrete reasons:

1. **The DSL is single-pass; this measurement is not.** A growth ratio needs the
   same workload replayed at several sizes plus discarded warm-up samples. That
   is a control-flow loop, and `tools/sim/chaos.c` is deliberately a flat,
   one-command-per-line interpreter with no iteration construct. Adding one for
   a single consumer would be the larger change.
2. **`make chaos` is an existing gate, and it must stay machine-independent.**
   Every checked-in `.scenario` runs there. Timing belongs behind a target that
   can be run in a quiet context — the precedent `check-crypto-perf` already
   sets in this tree ("deliberately NOT in the default `make lint` aggregate").
3. **Measurement methodology already has a home shape here.**
   `tools/simd_bench.c` established the shape this tool follows: a discarded
   warm-up, several repetitions rather than one sample, and a reference
   verified before any speed number is reported. `simd_bench.c` itself reports
   the *median* of its repetitions — appropriate there because its timing
   noise is not known to be one-sided. `simnet_perf` departs from that one
   detail deliberately: its noise IS one-sided (see "Why the minimum, not the
   median or the mean" above), so it takes the *minimum* instead. A standalone
   tool can make that call per-workload; a scenario line cannot.

The DSL's *assertion* shape is reused verbatim, which is the part worth sharing.

## Files

- `engine/modules/sim/include/sim/simnet_perf.h` — contract, budget constant, metric list
- `engine/modules/sim/src/simnet_perf.c` — workload, staged timing, growth math
- `tools/sim/simperf.c` — CLI, `--expect` parsing, verdict
- `core/modules/coins/include/coins/coins_fault.h` — the injected regression + its
  arming contract
- `core/modules/coins/src/coins_fault.c` — arming surface
- `tests/harness/src/test_simnet_perf.c` — the both-directions self-test
- `Makefile` — `sim-perf`, `sim-perf-teeth`, `sim-perf-clean`
