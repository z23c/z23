<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Initial block sync throughput: profile and two optimisations

Date: 2026-09-03. Lane: perfsync. All numbers are hermetic: no live
node, no network, no canonical datadir. Fixture directories are
test-local tmpdirs removed after the run.

Resurrected 2026-09-08 from a never-landed branch after 5 days of
drift: `test_timing_budget.h` had since landed independently under a
different API, so the harness now reads budgets through that existing
header instead of adding a second one, and each timed stage was split
across small per-leg helper functions to clear the repo's cyclomatic
complexity gate (cap 15) without raising any baseline pin. The harness
itself is split across two files (`test_sync_throughput.c` for the
fixture, timing helpers, and S1-S5; `test_sync_throughput_index.c` for
S6-S7 and the group entry point, sharing declarations through
`test/test_sync_throughput_internal.h`) to stay under the repo's
per-file line ceiling. The measurements and optimisations below are
otherwise unchanged from the original run.

## Method

Registered group `sync_throughput` (`make -j16 t-fast
ONLY=sync_throughput`) builds every byte deterministically in-process
(fixed times, fixed values, one baked real Equihash (200,9) witness for
the PoW leg) and times the REAL production function per stage — never a
model of it. Budgets are declared in reference-box units and scaled for
the running box by `tests/harness/include/test/test_timing_budget.h`'s
`test_budget_scale()` (median of 3 samples hashing 1 MiB with SHA3-256,
compared against a 2000us idle-host reference, floored at 1x and
capped at 8x), so a busy machine reports a smaller margin, not a false
red. Budgets are order-of-magnitude trip-wires, not perf-tracking
gates: they catch 10-100x regressions on unknown CI hardware, they do
not flag 20% drifts.

Reproduce: `ulimit -s unlimited; make -s -j16 t-fast
ONLY=sync_throughput`. The run prints per-stage lines plus one
`sync_throughput summary:` line (headers/s, PoW us, merkle roots/s,
validation us/block, plan us, flat heights/s, forward-order speedup).

## Profile: where the time goes

Reference-box run, 7 stages (S6b/S7 are the optimisation after-legs):

| Stage | What is timed (production fn) | Measured | Budget | Share of sync CPU |
|---|---|---|---|---|
| S1 header wire round-trip | `block_header_serialize` + `block_header_deserialize` | ~12M headers/s | floor 60k/s | negligible |
| S2 header PoW verify | `check_equihash_solution` (baked real witness) | ~430-680 us/verify | ceiling 60ms | DOMINANT per-header cost |
| S3 merkle root | `compute_merkle_root`, widths 1/2/8/64 | ~0.7-1.0M width-8 roots/s | floor 25k/s | small |
| S4 structural block check | `check_block` (PoW excluded; 1-tx blocks) | ~0.2-0.9 us/block | ceiling 2ms | negligible |
| S5 range planning | `hrs_partition`, 28.5k anchors | ~59 us/plan asc, ~56 us desc | ceiling 250ms | negligible |
| S6 flat header point read | `block_index_flat_header_at`, 8k-row file | ~280-425 heights/s (~2.5-3.5 ms/height) | floor 40/s | DOMINANT per-height I/O |
| S6b/S7 | after-legs, see below | — | — | — |

Two findings drive the work:

1. **S6 scales with file size, not with heights read.** Each
   single-shot read re-opens, re-mmaps, and re-runs the embedded
   SHA3-256 verify over the WHOLE file (`ssio_verify_embedded` streams
   every payload byte). Cost per height is O(file size): ~0.9 ms at
   2k rows, ~3 ms at 8k rows — projected to ~seconds per height at a
   multi-million-row production index. The verify is mandatory (never
   skipped), but paying it N times for N heights is pure waste.
2. **The flat forward-pass qsort is an identity permutation.**
   Genuine flat files leave the writer height-sorted and the loader
   collects in file order, so the ~3M-pointer qsort before
   `block_index_forward_pass` reorders nothing at O(n log n) cost.

S2 (Equihash, ~0.5 ms/verify) is the largest per-header CPU cost and is
deliberately untouched: it is the sealed consensus predicate, and any
"optimisation" there would be a skipped check (see Refusals).

## OPT-1: batched flat-header cursor (engine/services)

`block_index_flat_cursor_{open,read,close}` in
`engine/services/src/block_index_flat_header.c`, declared in
`services/block_index_loader.h`. Open runs the identical
open+verify+format prologue once; reads binary-search the pinned
mapping with the identical lookup and error taxonomy (same codes).
The single-shot `_at` now delegates to the same shared prologue and
lookup, so one code path defines both — only the lifetime differs.
The cursor holds no lock of any kind (fd + read mapping), so the
reducer-drive/coins_kv lock order is uninvolved: drive holds coins_kv,
this holds nothing.

Before/after from the harness (same binary, same 8k-row file, 256 heights):

- before (S6 single-shot): ~280-425 heights/s
- after (S6b cursor): ~1.6-3.4M heights/s
- speedup: ~4700-10000x (per-read cost O(file size) -> O(log rows))

Behaviour-unchanged proof: S6b asserts every cursor row is
byte-identical to the single-shot bytes and the missing-height refusal
carries the identical code; the pre-existing `block_index_loader`
suite (flat round-trip, point-read vectors, integrity refusals) passes
unchanged.

## OPT-2: skip the flat forward-pass qsort on writer-ordered files (engine/services)

`load_block_index_flat` now checks
`block_index_ptrs_height_sorted` (linear, fused with collection order)
and qsorts only when the file is not height-ordered; the LevelDB rung
still always qsorts (hash-order collection is never sorted — a check
there would be pure overhead). Skipping is behaviour-identical: the
forward pass derives every field from the already-linked pprev, which
is always strictly lower height (hence processed first in ANY
height-sorted order), and equal-height rows share no ancestry, so
their relative order cannot change any output. Foreign/legacy
unsorted files take exactly today's qsort.

Before/after from the harness (S7, 8192 real `block_index` entries,
production comparator):

- before (qsort on ordered input): ~216 us
- after (linear predicate): ~6 us
- speedup: ~35x, growing with n (n log n vs n); at production
  row counts this removes most of the sort portion of boot index load.

Behaviour-unchanged proof: S7 pins that qsort-on-ordered-input is an
identity permutation (same height sequence), that the predicate accepts
ordered and rejects reversed input, and `block_index_loader` passes.

## Refusals (correctness over speed)

- **Skipping Equihash for assumed-valid ancestors: refused.** S2 shows
  PoW verify is the dominant per-header cost, which makes skipping it
  tempting and exactly why it is forbidden: it deletes a consensus
  check. No such change was made.
- **Caching the nBits->target expansion in `block_row_verify`:
  refused.** The expansion lives inside the sealed `CheckProofOfWork`
  predicate; caching it in owned code would duplicate consensus logic
  and could drift from it. The per-row gate stays a call to the frozen
  verifier in the frozen order.
- **Rewriting `hrs_partition` insertion sort: measured and reverted.**
  The hypothesis was quadratic anchors; the harness showed 59 us/plan
  ascending and 56 us descending on the old code (the span-table cap
  early-out already makes large inputs linear) versus 25 us ascending
  but 400 us descending for a sort-merge rewrite — a 2.4x common-case
  win bought with a 7x adversarial loss, in a stage the profile shows
  is negligible either way. Reverted; the S5b/S5c property legs stay as
  worst-case coverage. Planning is not the bottleneck and was left alone.

## Lock discipline

Neither optimisation takes a lock. The cursor pins an fd + read-only
mapping (snapshot semantics); the qsort skip changes no write path and
no cursor discipline. coins_kv remains held by the drive; nothing here
inverts that order. Consensus predicates (`check_block`,
`check_equihash_solution`, `CheckProofOfWork`, merkle) are called by
the harness but not modified anywhere in this slice.

## Files

- `tests/harness/src/test_sync_throughput.c` (new): fixture, shared
  timing helpers, and stages S1-S5.
- `tests/harness/src/test_sync_throughput_index.c` (new): stages S6-S7
  and the group entry point `test_sync_throughput()`.
- `tests/harness/include/test/test_sync_throughput_internal.h` (new):
  the seam between the two files above (shared constants, the `ST_CHECK`
  tooth macro, and prototypes for every symbol one file defines and the
  other calls).
  Together: group `sync_throughput`, 7 timed stages (each split across
  small per-leg helpers to stay under the cyclomatic complexity cap) +
  teeth (valid/mutated blocks with exact reject reasons, witness
  pos/neg, byte-identical cursor rows, golden + property partition
  pins, qsort-identity pin). Reads budgets through the pre-existing
  `tests/harness/include/test/test_timing_budget.h` (`test_budget_scale`,
  `struct test_budget`) rather than adding a second budget helper.
- `engine/services/src/block_index_flat_header.c`: shared
  open/lookup prologue + cursor API; `_at` delegates (same strings,
  same codes).
- `engine/services/src/block_index_loader.c`: non-static height
  comparator + sorted predicate + qsort skip at the flat site only.
- Headers: cursor decls + comparator/predicate decls in
  `services/block_index_loader.h`.
- Registration: `tools/dev/test_group_catalog.def`,
  `tests/harness/src/test.c` (ONLY + full run),
  `tests/harness/include/test/test_core.h` (entry declaration).
