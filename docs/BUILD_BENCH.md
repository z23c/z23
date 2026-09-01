# build-bench — the measured baseline for the build and test loop

`make build-bench` runs the build and the test loop scenario by scenario with a
wall clock and writes `.cache/build-bench/last-run.json`. It carries no numbers
of its own: every duration in the artifact was produced by running the command
recorded next to it, on the host that wrote the file.

It exists so that a claim about build speed has something measured to be
compared against. Before it, the only build timings in the repository were
prose in `Makefile` comments — somebody's memory of a machine, at a commit
nobody recorded.

```
make build-bench                  # full baseline: two cold builds + the whole suite
make build-bench ARGS=--quick     # inner-loop subset, no cold work
make build-bench ARGS=--report    # re-read the last artifact, measure nothing
make build-bench-selftest         # prove the honesty states and the restoration
```

Other useful arguments: `--samples=N` (default 3), `--jobs=N` (default `nproc`),
`--group=<substr>` (which test group the single-group scenario runs).

## What it measures

| scenario | what it is |
| --- | --- |
| `compile_cold` | every translation unit compiled from an empty `build/` (`make build-only`) |
| `link_cold` | the whole product from an empty `build/`, including the whole-program LTO links |
| `compile_cold_ccache` | the same cold compile with the host's ccache in play |
| `compile_noop` | nothing changed |
| `link_noop` | nothing changed, whole product |
| `compile_edit_impl` | a one-line implementation edit to a low-fan-out `.c` |
| `compile_edit_header` | a one-line interface edit to the highest-fan-out header in the tree |
| `compile_edit_header_ccache` | the same interface edit, ccache enabled |
| `link_edit_header` | the same interface edit through the whole product |
| `test_suite_cold` | `make test-parallel`, the full suite |
| `test_group_one` | `make t-fast ONLY=<group>`, one group |
| `codeindex_cold` / `codeindex_warm` | the source navigator's store deleted, then reused |

The interface-edit scenarios are the point of the exercise. The edit lands in
`platform/modules/base/include/base/log_macros.h`, where the `LOG_*` / `GUARD*` macros live.
Almost every dependent reaches it through
`platform/modules/util/include/util/log_macros.h`, a one-line forwarder kept in place so the
files that already spelled the include that way did not have to change when
platform/modules/base was extracted. The artifact records both counts — files that include
the forwarder, files that include the platform/modules/base path directly, and the distinct
union — each derived at run time by `git grep` on the include directive, never
pinned and never a filename-substring count.

The derivation is scoped to `*.c` and `*.h`, because only a translation unit can
be recompiled. An unscoped grep for the same include line also matches
`tools/new_shape.sh`, a template generator that emits it, and
`tools/scripts/build_bench.sh` itself, whose own search strings would otherwise
inflate the number it reports — the count would grow because the benchmark
exists.

## Why ccache is disabled for the baseline

`Makefile` lines 6-11 auto-detect `sccache`/`ccache` and prepend whichever it
finds to `$(CC)`. On a host that has built this tree before — including from
another worktree, since the cache is shared — a default `make` reports a
compile time the compiler never paid. Every primary scenario therefore runs
`ZCL_USE_CCACHE=0`. The ccache-enabled variants are separate, labelled rows, so
the delta is visible instead of silently folded into the baseline.

## Honesty states

Same contract as [`make timings`](../tools/scripts/timings.sh): a row that is
not `ok` publishes **no duration**, in the artifact or in the printed report.

- `ok` — measured, and the scenario's own precondition held.
- `SKIPPED` — not run in this mode. Quick mode skips the cold scenarios; it
  invents nothing in their place.
- `FAILED` — the command exited nonzero, or a test run did not print
  `ALL TESTS PASSED`. The duration is real but it is not the cost of work that
  succeeded.
- `UNTRUSTED` — the command succeeded but did not measure what the scenario
  claims. Two cases occur in practice: an edit scenario that recompiled zero
  objects (the edit invalidated nothing, so the timing is a no-op build), and a
  no-op scenario that recompiled something (the tree was not converged, so the
  timing includes real work). A caveated number still gets quoted downstream,
  so these publish none.

Each row carries the evidence that makes its own claim falsifiable.
Compile-phase rows carry `objects_recompiled`, counted from object mtimes,
against the top-level `objects_per_epoch`: a row claiming to measure a one-file
edit while recompiling the whole tree says so in its own numbers. Product rows
carry `binaries_relinked` instead, because `make` builds each release binary
with one whole-program `cc` invocation over the whole source set and produces no
intermediate objects to count — for those the falsifiable signal is whether a
binary was actually republished.

## Restoration

The edit scenarios modify real tracked files. Each saves the file's exact bytes
first and restores them afterwards; an `EXIT` trap restores on interrupt. At the
end the run compares the `git status --porcelain` snapshot it took at entry with
the one at exit and re-checksums every file it touched, and reports
`tree_restored` in the artifact. The self-test performs the real edits with the
build commands replaced by no-ops, so the restoration path is exercised without
a build.

## Cost

Full mode runs two cold builds, a cold whole-program relink, and the complete
test suite. It is not a quick command; that is the number it exists to report.
Quick mode does no cold work and is usable in the inner loop.
