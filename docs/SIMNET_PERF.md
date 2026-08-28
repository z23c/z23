# Simnet Perf — an algorithmic-cost detector for the block-connect path

## What this is

`simperf` (`tools/sim/simperf.c`, library in `lib/sim/src/simnet_perf.c`) runs a
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

1. **Funding** (untimed) — mint `blocks * s * M` coinbase-only blocks, keeping
   every coinbase txid. This is what pre-loads the UTXO map, so the map's live
   entry count scales with the workload.
2. **Maturity filler** (untimed) — `COINBASE_MATURITY` (100) more coinbase-only
   blocks, so the funded coinbases clear the real maturity predicate. Measured
   blocks consume funded coinbases in mint order from the front, so the tightest
   case is the last measured block spending the newest funded coinbase, which
   clears maturity by `COINBASE_MATURITY + blocks`.
3. **Measured** — `blocks * s` blocks, each carrying its own coinbase plus `M`
   transparent spends of distinct funded coinbases. CPU time splits into
   `build` (this harness assembling transactions) and `fold` (merkle root plus
   the real `connect_block`, i.e. the coins-view work).

Only phase 3 is timed. Timing uses `clock_thread_cpu_ns()`
(`lib/platform/include/platform/clock.h`, `CLOCK_THREAD_CPUTIME_ID`) — the
existing per-thread CPU clock this tree already uses for work-ratio measurement
in `lib/test/src/test_sapling.c`. Per-thread CPU time, not wall clock, so
cross-process preemption does not land in the number. Every ladder point also
runs one **discarded warm-up sample** (same discipline as `tools/simd_bench.c`),
because without it the first point absorbs the process's page faults and cold
caches, inflating the ratio's denominator and flattering every result.

The workload is deterministic: fixed values, fixed scriptSigs, fixed heights.
Two runs at the same config fold byte-identical blocks; only the ns figures move.

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
set in the same regime and keeps the smallest point long enough (~1.7k
transactions, ~8 ms of fold) that scheduler contention averages out. Widen the
span only together with a re-calibration of both directions.

## The budget, and how it was calibrated

`SIMNET_PERF_GROWTH_BUDGET_PERMILLE = 1800`
(`lib/sim/include/sim/simnet_perf.h`).

Measured on a 32-core host, default workload, both idle and with 32 concurrent
runs to model worst-case CI contention:

| Run | Idle | 32 concurrent |
|-----|------|---------------|
| Clean tree (`--blocks=192`) | 655 – 1254 (max **1254**) | 359 – 1111 (max **1111**) |
| O(n²) armed (`--blocks=192 --inject=coins-hash-collapse`) | 3276 – 3399 | 2271 – 5019 (min **2271**) |
| Clean tree, self-test size (`--blocks=96`) | 1002 | 524 – 1429 (max **1429**) |
| O(n²) armed, self-test size | 3256 | 2174 – 4652 (min **2174**) |

1800 sits inside that gap at both sizes: 44% above the worst clean observation
and 21% below the best armed one at the default size, 26% / 17% at self-test
size (whose smaller workload is noisier in both directions). Every
one of those 32 concurrent clean runs passed and every one of the 32 armed runs
failed, in both sizes.

2026-08-28: the in-suite group stopped asserting the absolute budgets. A
healthy tree failed the budget twice in one day, at both ladder sizes: first
at the 96-block self-test size (clean growth 1905 vs the concurrent max 1429;
solo rerun 1117, inside the idle band), then — after the group moved to the
default workload on the compression argument above — again at 192 blocks
(clean 2604, armed/clean discrimination compressed to 1.47x vs the 1.8x the
idle regime shows; same binary, same tree, solo 1068). The suite's mixed
worker mix is simply not the 32-concurrent-copies-of-this-test regime the
calibration modeled, and at neither size does it compress growth. The
absolute budgets (both directions, both metrics) are now asserted only by the
dedicated lanes `make sim-perf` / `make sim-perf-teeth` on a quiet host;
the in-suite group keeps the per-scale same-window A/B (armed per-tx fold
cost >= 4x clean at every point; calibration margin ~13x), the count/UTXO/tip
identity checks, and the expect()-surface self-tests, and prints the budget
line informationally. The self-test-size rows stay as measured calibration
history.

## Proving the detector has teeth

Per this project's own hard-won lesson — a Groth16 QAP-matrix bug satisfied
every count-based check while being genuinely wrong — a checker is worthless
until it has been shown to discriminate real-bad from real-good. So the budget
ships with a **parent-failing prover**.

`coins/coins_fault.h` arms one test-only regression in the real UTXO map. The
map (`struct coins_map`, `lib/coins/include/coins/coins_view.h`) is
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
calls it; the only callers are `lib/sim/src/simnet_perf.c` and
`lib/test/src/test_simnet_perf.c`.

### The proof

Same workload, same binary, one flag apart:

```
$ build/bin/simperf --blocks=96
  scale  blocks  fund_blk  txs   coins   build_us   fold_us  fold_ns/tx  total_ns/blk
      1      96       768   864    1732        205      5011        5800         54341
      2     192      1536  1728    3364        447     10955        6339         59390
      4     384      3072  3456    6628        819     20096        5814         54467
    fold_growth_permille  = 1002
expect fold_growth_permille <= 1800 (actual=1002) PASS
SIMPERF ALL BUDGETS PASSED (5 assertions)

$ build/bin/simperf --blocks=96 --inject=coins-hash-collapse
  scale  blocks  fund_blk  txs   coins   build_us   fold_us  fold_ns/tx  total_ns/blk
      1      96       768   864    1732        196     12349       14293        130684
      2     192      1536  1728    3364        431     45530       26348        239386
      4     384      3072  3456    6628        849    160857       46544        421112
    fold_growth_permille  = 3256
expect fold_growth_permille <= 1800 (actual=3256) FAIL
SIMPERF BUDGET FAILED (2 of 5 assertions)
```

Note the `txs` and `coins` columns: **identical** in both runs. The injected
regression is completely invisible to every count-based check. That is the whole
argument for owning a cost detector.

`make sim-perf-teeth` runs exactly that pair and fails loudly if the armed run
*passes*. `make t ONLY=simnet_perf` runs the same comparison in-process on every
suite run, and additionally requires the armed growth to be at least **2× the
clean growth measured on the same machine under the same load** — the
load-normalized form of the check, which no amount of scheduler contention can
squeeze.

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
   `tools/simd_bench.c` established it: warm-up discarded, median not mean,
   reference verified before any speed number is reported. A standalone tool can
   follow that; a scenario line cannot.

The DSL's *assertion* shape is reused verbatim, which is the part worth sharing.

## Files

- `lib/sim/include/sim/simnet_perf.h` — contract, budget constant, metric list
- `lib/sim/src/simnet_perf.c` — workload, staged timing, growth math
- `tools/sim/simperf.c` — CLI, `--expect` parsing, verdict
- `lib/coins/include/coins/coins_fault.h` — the injected regression + its
  arming contract
- `lib/coins/src/coins_fault.c` — arming surface
- `lib/test/src/test_simnet_perf.c` — the both-directions self-test
- `Makefile` — `sim-perf`, `sim-perf-teeth`, `sim-perf-clean`
