<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Proof status execution projection — 2026-10-20

Compiler: GCC 14.2.0 (Ubuntu 14.2.0-4ubuntu2~24.04.1).
CPU: AMD Ryzen 9 7950X3D 16-Core Processor. Test baseline:
3c2d3eb0a7fc48bb4c54261ef492fe14a1b0f3c8.

The compatibility status remains running for an unclaimed request. The additive
projection distinguishes queued, reader-qualified executing, and unknown
execution. Request age is not worker activity; the existing ETA is remaining
timeout budget, not a completion prediction. Dispatch and receipt policy are
unchanged.

<!-- claim: symbol-present proof_execution_state tools/command/native_dev_proof_command.c -->

## Isolated evidence

The original proposed fixture exceeded the existing complexity cap: its live
worker helper measured 20 against cap 15. Runtime tests did not run for that
attempt. Extracting unconditional close, EINTR-aware wait and unlink cleanup
preserved their order and every assertion; the canonical ratchet then passed.
The cap and baseline were unchanged.

With unchanged parent production and the revised fixture, the cold registered
impact-composition group failed because execution_state was absent where queued
was required. The first attempt and the runner's single automatic isolated
retry both failed; both detailed captures were retained. Combined test wall
time was 191.9 seconds. The first capture has SHA256
fb891778fd56bbabb3b94b012cd988ec8c244d8b9041189fcefb42fa2f8a3a38.

With the reviewed production and documentation delta, the same fixture passed
one cold group in 82.7 seconds: zero failures, skips, unobserved environments,
flaky results or isolated retries. The real status reader established a live
fixture worker; queued age and unknown detail cases were asserted separately.
The GREEN log has SHA256
9ea8653ee5e87933b3800fe8af673b3be42c6f88544d2d6565be3d5964be25ea.

Both commands used compact 2 GiB admission with a three-CPU limit. Observed
cache-inclusive peaks were 1,781,288,960 bytes for RED and 1,507,618,816 bytes
for GREEN plus preflight, with zero memory-limit or OOM events. These are
focused workload observations, not full-qualification resource guarantees.

The six-gate preflight passed five checks, including capability closure, and
refused only stale generated capability inventory. Generated inventory remains
owned by native candidate preparation. No full qualification is inferred from
that preflight. Integration advanced to
7d203e340510e9906e5fca9116f570a75a7d32b2 with no change in the three scoped
source/document paths. Full native candidate qualification is a separate receipt.

## Landing preparation failure evidence

A retained landing attempt on base
`c90997a57a3a933555c7b6ce2fd0043bc7f74cfc` passed its 66-gate prebuild
lint and then exceeded the existing 600,000-millisecond deadline while
making `build/dev-loop/restart.env`. The preparation adapter retained only
its summary and discarded captured child output. The retained evidence
therefore establishes deadline expiry, not the underlying bottleneck.

Failed preparation now appends its bounded merged output to the existing
attempt log, with target, exit result, timeout state, elapsed milliseconds,
captured byte count and a conservative saturation marker. Explicit output
boundaries separate metadata from child text. The capture remains 256 KiB;
a saturated text buffer is marked possibly truncated. The production
timeout, successful preparation behavior and first-actionable error triage
are unchanged. Allocation failure is recorded without claiming a child ran.

The existing final-plan preparation fixture exercises the actual Make
adapter and attempt-log callback with merged stdout/stderr failure,
allocation refusal, saturated output and a test-only short child deadline.

On 2026-10-27 the registered route ran as:

```sh
DEVBUILD_CLASS=normal ZCL_TOOLS_LINK_JOBS=14 devbuild --wait \
  ionice -c3 make -j28 t-fast ONLY=dev_land_shard_04
```

One cold registered group ran 14 scenarios with zero failures, skips,
unobserved environment checks or load-flaky results. The actual failed-output
append, saturated-capture/real-child-timeout, and original final-plan refresh
and refusal cases each passed. The enclosing final-plan scenario reported
5,186,527 microseconds; the complete shard reported 196,376 milliseconds
of test body and zero milliseconds startup, or 196.4 seconds rounded wall.
Admission wait, build time and peak memory were not separately measured.

The tested diagnostic code was stacked on
`fe39c4a1b49ea553c18d5ec362d549979778b331`:

| Path | Git blob |
| --- | --- |
| `tools/command/native_dev_land_prepare.c` | `1b4313860b2e6248f6026a287a067315f0ceecf6` |
| `tools/command/native_dev_land_prepare.h` | `a33bf8172f7a9501b0c44e96460650f2d9dd34ef` |
| `tools/command/native_dev_land.c` | `5babd7bf21c45041d62415dd6414dc29ffdf1588` |
| `tests/harness/src/test_dev_land_merge_replay.c` | `3d1266e69dfad9e1c44905fd1c9bd5a547600ebd` |

The retained focused log SHA-256 is
`052822bc161f5aaf65ef4d093aff51b718c3e46dee8f54ef42380ecc080201e0`.
The compiler was GCC 14.2.0, Ubuntu package 14.2.0-4ubuntu2~24.04.1, on
an AMD Ryzen 9 7950X3D 16-Core Processor running Linux 6.8.0-139-generic
x86_64. Native normal admission used a 24 GiB memory ceiling and 28-CPU
quota; the command requested idle I/O priority.

This qualifies isolated Linux diagnostic fixtures. Other platforms were not
run. The original preparation bottleneck remains unknown; no timeout retry,
performance improvement or Groth16 correctness conclusion is established.
The production 600,000-millisecond deadline is unchanged. Full native exact
candidate proof remains pending; no live node or deployment was involved.

The observations above qualify the original component stack only. A separate
integration applies just the five-path diagnostic change to
`4ec8326118b381d4f1a5c35b937532ac62b2603a`; it does not include the earlier
Groth16 follow-up. The integrated caller blob is
`6faef04f3d077df7e76e4f0cf2b7bbba78171f55`; the preparation source/header
and test blobs in the table above are unchanged.

On 2026-10-27 the same admitted normal, idle-I/O command with
`ONLY=dev_land_shard_04` passed this standalone integration. One cold
registered group ran 14 scenarios with zero failures, skips, unobserved
environment checks or load-flaky results. The actual failed-output append,
saturated capture/real-child timeout and original final-plan refresh/refusal
cases all passed. The enclosing final-plan scenario reported 5,052,515
microseconds; the complete group reported 254,672 milliseconds body and
zero startup, or 254.7 seconds rounded wall. Five source/document hashes
matched before and after the run. Its log SHA-256 is
`8c343c85d4e630cc4d2738e4af51e55a8d49ca3b515cc4fd13511aea27b96e89`.

The compiler, CPU, Linux host and normal admission settings were the same
as reported above. Admission wait, build time and peak memory were not
separately measured. Other platforms remain untested. This is an isolated
integration fixture result, not full native exact candidate proof or a
performance comparison. The original preparation bottleneck remains unknown.

Preparation runs inside the invoking landing driver, before its candidate
proof process starts. Queuing this diagnostic source cannot update an older
running driver. Its new output retention becomes available only after a
reviewed, landed build containing it is adopted and a fresh driver uses that
build. No installed driver was replaced or restarted for this experiment.

## Private worktree-status refusal evidence

A later proof refusal reported worktree_not_clean without retaining the
actual captured porcelain status. The specific dirty path in that historical
attempt remains UNKNOWN.

The common cleanliness guard now retains its existing bounded Git status
capture only when status capture fails or reports a dirty tree. The private
attempt artifact is worktree-status.log, written atomically with mode 0600.
It records the calling phase, untracked-file policy, observed exit status,
signal, timeout, elapsed time, reported and retained output lengths,
truncation and conservative capacity saturation. Delimiters bound the raw
captured status. The capture capacity remains 65536 bytes; the existing
process capture retains a bounded tail and may begin within a row. No second
Git invocation or public raw-status dump is introduced.

<!-- claim: symbol-present worktree_status_record tools/dev/dev_proof.c -->

The five production contexts are root entry, generation preparation, source
recheck, generation publication and original-plan preparation. The initial
root-entry helper is also reached by a test-only wrapper, without invoking
Make. Existing refusal tokens, guard order and Git deadlines are unchanged.
A diagnostic write failure cannot accept a dirty tree.

The isolated fixtures use real Git for a tracked modification,
untracked input, clean source and the ignored vendor/.build.lock artifact.
A real set of long untracked names exercises the existing saturated-capture
refusal and bounded diagnostic. An invalid log destination exercises dirty
refusal despite diagnostic failure. The isolated qualification below covers
these cases; this section does not identify the historical dirty path or
establish a new full native candidate proof.

The first isolated qualification passed the new clean, ignored, tracked,
untracked and diagnostic-write-failure checks. Its saturation fixture failed
in both runner attempts because it expected a complete porcelain row
immediately after the output delimiter. The existing process capture retains
a tail, which can begin within a row. The fixture now checks the delimiter
and an intact retained porcelain row separately while preserving the exact
truncation refusal, privacy, capacity and end-delimiter assertions. Production
capture and refusal behavior were unchanged by this fixture correction.

On 2026-10-27 the repaired registered route ran under normal admission and
idle I/O priority:

~~~sh
DEVBUILD_CLASS=normal devbuild --wait ionice -c3 make -j28 t-fast ONLY=impact_composition
~~~

One cold group ran with zero failures, skips, unobserved checks or load-flaky
results. All three new root-entry cases passed: clean/ignored/tracked status,
untracked status with diagnostic-write refusal, and real saturated output
including the final generated row. Existing original-plan refusal cases
also verified their phase tags. The common root-entry helper executes the
same actual Git guard used at proof entry; no Make invocation is added to
that helper.

The tested source baseline was
41511e022901f60109beb5ef6438a730e159ed1e. Exact code identities were:

~~~text
tools/dev/dev_proof.c
979c3e571a907069966b2fc2e7adb0fb8b3d841f
tools/dev/dev_proof.h
f9fd9f918d855c2fb3e5730fbcb7caeba310aef0
tests/harness/src/test_impact_composition.c
afec331f265331c2678cad2c82cc552d9890f0b8
~~~

The focused log SHA-256 was
88d1397450abad91f497c9bfe15a46e638f8d9e8787f2b2f9c98abea82ece6e6.
The runner reported one millisecond startup and 224467 milliseconds for the
complete group body, rather than an isolated status case. The repaired
admitted batch, including relevant complexity/file-size checks and build,
recorded zero queue wait, 326 seconds runtime, 1817 MiB peak memory and
98 CPU seconds. The unchanged clock-policy receipts were reused; production
code did not change during the fixture correction. No baseline, exception or
deadline was relaxed.

The compiler was GCC 14.2.0, Ubuntu package 14.2.0-4ubuntu2~24.04.1, on an
AMD Ryzen 9 7950X3D 16-Core Processor. Four source/document hashes matched
before and after the run. These are isolated Linux fixture observations;
other platforms were not run and no speedup is established.

The original dirty path remains UNKNOWN. Historical failed captures and the
fixture correction are retained separately from the passing qualification.
Full native exact-candidate proof remains pending. A queued source change
does not update an already running proof driver; the diagnostic requires a
reviewed build containing it before it can report a future live refusal.
