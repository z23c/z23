<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Synthetic frontier evidence query

The hash-agreement query checks that the validated header hash is a 32-byte
blob. The header-admit and UTXO-delta witness columns have BLOB affinity. Once
the validated hash is known to be a 32-byte blob, `IS NOT` detects missing,
malformed and unequal mandatory witnesses without separate type and length
checks. Nullable script and proof witnesses retain their existing checks; the
query retains its range, ordering, returned columns and first-mismatch behavior.

On 2026-11-15 UTC, an isolated synthetic progress store used the existing
reducer frontier fixture and deterministic matching hashes. Source was
`9ad92d57f7c1186c1b38baa25334c8ffb807ca83`; the relevant frontier,
sovereignty, progress-store and fixture source files match `1836c146`, the
installed node source. The host was an AMD Ryzen 9 7950X3D with GCC 14.2.0.

For 263,106 consistent heights above the anchor, three paired executions of the
original query took 89,735, 90,224 and 89,743 microseconds; the simplified
query took 74,438, 74,415 and 75,059 microseconds. Each original execution used
18,154,330 SQLite VM steps and each simplified execution used 14,997,058, a
17.39% reduction in this fixture. The size matches the numerical difference
between the reported tip and compiled anchor; it is not a measurement of
phone rows. The database occupied 18,428 pages of 4,096 bytes on tmpfs.
Process and OS caches and host load were uncontrolled.

A differential matrix compared the original and simplified SQL over 37
synthetic cases, including malformed and differently typed values, missing
rows, equal malformed values and multiple mismatches. Three further cases
covered absent legacy nullable-witness columns. All passed. A first matrix run
failed due to incorrectly quoted test literals; the corrected bound-value
fixture and both runs are retained. A height-only output experiment preserved
results but did not reduce healthy-range VM steps.

The durable focused regression calls the actual H* fold for mandatory-witness
corruption, missing rows, equal malformed values and earliest mismatch. Existing
coverage includes the legacy nullable-witness schema. The registered focused
group passed without skips. The first shape check found an oversized test helper;
the helper was split and the checks passed.

These results do not establish a phone latency improvement or the cause of an
observed timeout. Trust-tier caching, thermal conditions, storage, contention
and RPC transport are outside this synthetic measurement. No core source or
spending guard was changed.

The archived `matrix-fixture-corrected.patch` is required to reproduce the opt-in
measurement on a clean checkout at the source above. Set `EXPERIMENT_ARCHIVE`
to the retained evidence directory, then run:

```sh
git apply "$EXPERIMENT_ARCHIVE/matrix-fixture-corrected.patch"
ZCL_TEST_HSTAR_TIMING=1 DEVBUILD_CLASS=normal devbuild --wait make -j4 t-fast-exact ONLY=reducer_frontier
git apply -R "$EXPERIMENT_ARCHIVE/matrix-fixture-corrected.patch"
```
