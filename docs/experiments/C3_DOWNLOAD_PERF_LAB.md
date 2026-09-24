<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# C23 download performance laboratory

Historical baseline: `a898cf77913f786e69c2e85b357004972d796976`.
Integration base: `163020d4593cf70bcd6e178f4fc962a9d689e253`. No production implementation changes.
Recorded 2026-09-13 UTC; local timezone America/Puerto_Rico (UTC-04:00).

## Baseline: one command

After the repository's documented `make setup` dependency preparation:

```bash
VENDOR_CC=gcc make -j12 c3-speed-bench
```

This builds the C23 mutex probe and runs the registered
`download_speed_contract` group. The old implementation intentionally returns
RED at 4K, 16K and 65K queues. Preserve that nonzero exit; it is the measured
regression, not a broken installation. The explicit target sets `C3_ENFORCE_SPEED_CONTRACT=1`. Normal registered
qualification preserves functional assertions and emits the same measured
`pass:false` records without treating the performance threshold as a test
failure. Broken fixture invariants always fail. A zero-duration control sample
remains a failed performance result and is enforced by the explicit target.
The test has no network or datadir
dependency. Use the host's existing build admission wrapper when required.

The probe is a declared test-only preload, never a product dependency or a
preload for a C3 node. Each command record states whether mutex and transport
timings were measured. Missing hardware cycle counters produce null plus an
error code. Frequency 0 means the host did not expose that sample.

## Successor: unchanged command

Independently reconstruct the declared successor in a separate checkout,
review its source and recipe, and apply this branch's diagnostic commit there
with normal Git cherry-pick. Resolve only diagnostic integration conflicts;
never alter the candidate implementation or threshold to obtain green. Then:

```bash
VENDOR_CC=gcc make -j12 c3-speed-bench
```

Compare the emitted `c3.speed_scaling.v1`, `c3.speed_contract.v1`,
`c3.command_contention.v1` and `c3.queue_work.v1` records against
[`C3_SPEED_BASELINE.md`](C3_SPEED_BASELINE.md).
Record exact source, compiler, flags, dependency hashes and CPU-frequency
samples for both runs. Cross-toolchain behavior is distinct from byte
reproduction. Never compare concurrent or differently throttled runs as a
software-only delta.

Success requires every queue depth to satisfy median forward thread CPU time
<= **16×** its matched history no-op control. Fixtures contain 1,024 duplicate
requests at depths 1K/4K/16K/65K, five fresh samples per class, alternating
class order. Five-sample nearest-rank p95 is the maximum, not a population-tail
estimate. Expected gate failure must become PASS without changing this bound.

## Measured baseline

Linux 6.12.94-1-MANJARO; Ryzen 7 PRO 8840U; GCC 16.1.1;
registered C23 test-fast `-O1`; probe C23 `-O2 -Wall -Wextra -Werror -pedantic`.
Measurements were collected on the preceding diagnostic checkout at 51de8dcf;
the production download implementation is byte-identical through a898cf77.
They are explicitly historical observations, not measurements invented for
this branch's commit identity.

The entry command was rerun on this a898-based checkout at
2026-09-13T17:46:28Z (2026-09-13T13:46:28-04:00). It again returned RED at
4K/16K/65K, with no skips and a 14.989s test body. The host reported about
544 MHz; those absolute timings are not compared to the faster historical
curve as a software-only change. The mutex probe compiled with strict C23
warnings; behavioral and handler checks passed while the performance gate
returned its expected RED result. All 32 lint-fast gates passed.
The final scoped entry command was verified again at 2026-09-13T17:55:53Z
(2026-09-13T13:55:53-04:00): 1.941s test body, 1K PASS and 4K/16K/65K RED,
no skips. This run used the final test-only `C3_REQUIRE_MUTEX_PROBE` name.

| Queue | Median forward mutex hold | Median user CPU cycles |
|---:|---:|---:|
| 1K | 0.467 ms | 2,261,916 |
| 4K | 1.823 ms | 7,613,810 |
| 16K | 8.310 ms | 29,225,858 |
| 65K | 31.128 ms | 118,111,742 |

An independent larger fixture, 65,536 queued identities and 65,536 duplicate
requests, measured **2.05–2.23 seconds** of actual mutex hold. Both classes
grew their dedup table identically; the matched history control took 16–23 ms.
The earlier 2.022s/10.421ms whole-call ratio used unequal capacities and must
not be treated as a matched mutex measurement. A later frequency-limited run
reported approximately 544 MHz and much longer times; it is not a software
regression. Source-derived scan counts are separate from runtime counters.

Under the controlled 1,024-duplicate load, the real downloadstats RPC handler
had p95 33.967 ms; the sync_monitor diagnostic handler had p95 32.962 ms.
Observed download-mutex wait accounted for 99.45–99.95% of handler duration.
The worker's outer recursive lock includes a declared event handshake;
enqueue time is recorded separately. These are handler measurements, not
CLI transport, cancellation or timeout measurements.

The isolated queue accepted 65,536 first-seen identities in 16.176 ms and
assigned/settled them at 382,824 identities/s. Those are queue operations,
not validated or persisted bodies. The previous live receiver measured
145.731 first-seen bodies/s with 31.955% repeats. C3 remains separate.

## Tools and source

- `tests/harness/src/test_download_speed_contract.c`: scaling, thread CPU time,
  frequency, command contention and isolated queue-work fixture.
- `tests/harness/src/test_download.c`: optional larger enqueue witness,
  registered as `download_enqueue_profile`.
- `tests/harness/fixtures/c3_mutex_probe.c`: bounded, selected-mutex wait/hold/unlock recorder.
- [`C3_SPEED_BASELINE.md`](C3_SPEED_BASELINE.md): machine-readable
  baseline rows, including CPU frequency, cycles and measurement scope.

The portable registered benchmark reports hardware cycles as unavailable
(`cycles: null`, `cycles_errno: ENOTSUP`). Historical hardware-counter results
above remain unchanged. The benchmark does not open privileged kernel counters;
thread CPU time, wall time, CPU frequency and mutex samples remain measured.

The receiver evidence bundle is rooted at
`85fc8942fbc6910ba61691c1fa7585869cc8bb3de14ed57a5db1987ff31c4305`.
It contains raw rows, source hashes, the C3 readiness recipe and two passing
harness selftests. No binaries, chainstate or operator credentials are inputs
to this laboratory.

## Next timing seam

`tip_finalize_stage_step_once()` holds `progress_store_tx_lock()` across
visible-body reconciliation and `stage_run_once()`. The existing
`tf_post_finalize_us` counter combines reconciliation outside the stage timer
with post-finalization work inside it. In archived snapshots it increased
8.798618s while the stage total increased 5.112s; dividing those counters is
not a meaningful stage percentage.

The next experiment must separately time visible-body reconciliation,
in-stage post-finalization and progress-store lock wait/hold. Preserve wallet,
mempool, MMR/MMB ordering and all authority checks. No production fix follows
from the combined counter alone. Independently rebuild the authorized
successor, run this contract unchanged, then fresh C3 and one clean restart
when the declared fixture window is available.

### Registered seam probe

```bash
VENDOR_CC=gcc make -j12 c3-tip-seam
```

This Linux test-only link profile wraps the existing registered
`tip_finalize_stage` and `tip_finalize_post_step` groups. It emits
`c3.tip_seam.v1` JSON with aggregate wall/thread-CPU time, maximum duration,
call count and unfinished-call count. Production link inputs are unchanged.

On 2026-09-13T17:58:59Z (2026-09-13T13:58:59-04:00), GCC 16.1.1,
AMD Ryzen 7 PRO 8840U, both groups passed in 1.545s test-body time:

| Stage-group phase | Calls | Total wall ms | Maximum ms |
|---|---:|---:|---:|
| Progress-store lock wait | 572 | 0.029739 | 0.001443 |
| Progress-store lock hold | 572 | 20.936960 | 0.779750 |
| Visible reconciliation | 99 | 1.222284 | 0.035376 |
| Post-finalization inside stage | 15 | 0.152455 | 0.011231 |
| Post-finalization inside visible reconciliation | 0 | 0 | 0 |

The separate post-step group observed four unlocked calls totaling 0.584446ms.
All unfinished-call counts were zero. Lock totals cover the entire group,
including setup; they are not a tip-only denominator. The probe adds timing
and atomic-counter overhead. CPU frequency was not captured for this seam
run, so these durations are not a cross-run speed claim.

The decisive coverage gap is the zero-call nested post-finalization path.
Next, exercise a readable visible cursor with served-tip lag in an isolated
fixture and retain wallet/mempool/MMR/MMB assertions. Existing tests establish
probe operation and preserve correctness checks; they do not yet isolate the
live-sync delay or prove reconciliation duplicates post-finalization work.

## Main integration qualification

Integration onto `163020d4593cf70bcd6e178f4fc962a9d689e253` preserves the
historical diagnostic threshold and separates its enforcement from normal
functional qualification. `C3_ENFORCE_SPEED_CONTRACT=1` is set only by the
explicit benchmark target. The portable frequency fallback reports zero
outside Linux; it does not invent a CPU-frequency measurement.

Measured 2026-09-13 on Linux 6.12.94-1-MANJARO, Ryzen 7 PRO 8840U,
GCC 16.1.1 (20260430), GNU Binutils 2.46.0:

- Five cold registered groups passed in 22.996s; the six-group affected run
  after initializing failed-worker timing slots passed in 8.355s. No skips.
- The explicit benchmark retained RED at 4K/16K/65K and PASS at 1K. Its
  65K median forward/control thread CPU times were 232.314409/1.012227ms.
  Frequency samples were about 544 MHz; these are not software-only deltas
  against the earlier multi-GHz historical curve.
- Under that benchmark load, `downloadstats` p50/p95 was
  284.274108/291.975586ms; `sync_monitor` was 235.716959/268.375205ms.
  Transport time and client timeouts remain unmeasured.
- The explicit tip-seam profile passed both groups in 1.787s with one worker.
  Nested post-finalization remains a named fixture-coverage gap.

Tor archives came from C's own independently built a898 checkout through
`tor_archives_ready.sh`, with provenance checks and independent inodes.
Other dependency archives were rebuilt locally from the pinned inputs.
The SQLite build emitted its existing discarded-const warning.
