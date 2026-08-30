<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Native push-receipt baseline

## Question

Can push admission verify an exact local commit and advertised remote base
without running build, lint, test, or shell work, and where does latency remain
outside that admission path?

## Environment

- Local time: `2026-08-30T04:36:46-04:00`
- UTC: `2026-08-30T08:36:46+00:00`
- Host: Linux 6.12.94-1-MANJARO x86_64
- CPU: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics
- Compiler: GCC 16.1.1 20260430, `-std=c23`

## Method and observations

`make git-hook-selftest` created one valid fixed-width aggregate receipt,
read, parsed, and validated it 1,000 times, then exercised stale, incomplete,
hollow, skipped, aggregate-tamper, and child-tamper refusals. The measured p95
was 7 microseconds. The selftest spawned zero child processes.

An actual missing-receipt invocation used a real Git ref tuple and the native
hook's ancestry check. It refused with the exact `dev proof wait` command in
42 milliseconds. No compiler, test, lint, Make, Bash, or PowerShell process is
reachable from receipt admission; `make check-dev-proof-native-fast-path`
enforces that source boundary.

Native impact planning for only `docs/CAPABILITY_INVENTORY.jsonl` completed in
28 milliseconds and selected exactly `test_code_inventory`. It selected no
`make_lint_gates` shard. The generated-output freshness gate itself took
47,497 milliseconds despite warm generator artifacts. The directly executed
inventory test reported 4,332 milliseconds of runner startup and 34
milliseconds of test body.

The Equihash prose/freshness lint gate initially took 16.734 seconds warm even
after its generated tool was current. Its script recursively visited ignored
build, vendor, and proof-generation trees before filtering their output, and
started a nested Make invocation on every run. Restricting the scan to Git's
tracked source set and making the generated fact tool an explicit parent-Make
prerequisite reduced the same warm gate to 46 milliseconds, with the same
plant/trip/recover self-test and document comparison.

The combined 30-file integration delta selected 50 distinct registered test
groups. The previous 32-group storage bound refused the complete result as
`path-group-cap`; the shared impact accumulator now retains 64 distinct path
groups. A central planner-header change legitimately reached more than 256
registered proof owners through the include graph. The composed ledger now
retains a measured 512-group envelope while continuing to fail closed beyond
it. The plan's wire renderer remains independently bounded and abridges only
presentation.

The same closure exceeded the broker's unrelated 4,096-byte test-selector
buffer after planning completed. The selector bound is now derived from the
maximum selection count and canonical registered-group width. A failed
`dev.proof.wait` also exposed a self-referential `next` action that the command
registry correctly refused to serialize; wait replies no longer prescribe the
same active wait leaf, and a 900,000 millisecond proof timeout is accepted only
for this command. The resulting typed failure serialized in 87 microseconds.

The first isolated compile refused because archive and include dependencies
were symlinked into the generation, which exact source identity intentionally
forbids. The broker now hard-links regular dependency files and recursively
materializes real include directories; it does not weaken source capture or
follow mutable dependency symlinks.

The first resulting cold `build-only` completed its object epoch after 515
seconds, but the detached broker inherited process-wide child-reaping state and
lost Make's successful exit status. Proof workers now establish the default
`SIGCHLD` disposition before launching children and retain exact nonzero exit
codes in failure evidence.

The subsequent warm proof reached `lint-fast` and exposed that its Equihash
tool prerequisite expanded before `EQUIHASH_FACT_TOOL` was defined. Moving the
definition ahead of the target preserved the no-nested-Make gate and produced a
green 24-gate `lint-fast` run in 12.838 seconds; Equihash itself took 139
milliseconds.

At `2026-08-30T11:38:02-04:00` (`2026-08-30T15:38:02+00:00`), an exact proof
after the Windows test-lane integration selected 152 runnable groups. It ran
all 152 because the isolated generation could not see 122 valid PASS objects
stored by the preceding generation. The run completed in 360.377 seconds with
151 groups passing, zero skips, and one deterministic failure:
`test_header_probe` remained blocked in `accept()` until the runner's
300-second silence limit. The portability change had replaced
shutdown-then-close with close alone. Restoring
`platform_socket_shutdown_both()` made the exact group pass with a 21
millisecond test body.

The test cache now separates the immutable source/depfile root from the
content-addressed PASS-object store. The proof broker points only the verdict
store at the primary checkout while every closure and source byte remains read
from the isolated generation. A three-group measurement with two cacheable
groups first took 6.045 seconds end to end, stored two exact PASS objects, and
ran all three groups. Repeating the same command took 0.569 seconds, reused both
cacheable objects, ran only the deliberately uncacheable cache self-test, and
reported complete accounting: two cached, one ran, zero failed, zero skipped.

Three independent helper admissions then spent 25 to 30 seconds each proving
the same mutation inventory. A scan that crossed its 30-second child timeout
incorrectly converted an available exact executable into a `build-only`
fallback. Helper admission now captures the isolated generation's complete
byte identity once, reads each already-open executable's embedded source record
directly, and compares the byte identity before hashing and hard-linking the
artifact. The generation also materializes every linked Tor archive included
by source identity. A stale helper now refuses admission without launching a
compiler.

Compile reuse initially left the isolated generation with no depfiles, so the
test cache correctly refused all 131 closure-based groups even though their
PASS objects were available. The broker now copies only the exact active test
epoch's depfiles into the generation with fresh private inodes, binds their
paths and content hashes into the test-helper receipt, and leaves object files
behind. Source and include-graph reads therefore stay generation-local while
the immutable PASS objects remain shared.

## Knowledge gained

- Exact receipt admission is comfortably below the 250 millisecond target.
- Missing evidence fails below the one-second target and does not start proof
  work at push time.
- The former broad inventory impact route is not responsible for remaining
  inventory latency.
- Make startup, repeated generator scanning, and test-runner startup dominate
  the current generated-inventory path. A five-second warm acceptance claim is
  not yet supported by measurement.
- Exact input enumeration removed 16.688 seconds from the warm Equihash gate;
  native gate execution remains a separate parity task.
- A coherent multi-component push can legitimately exceed 32 focused groups;
  storage bounds must cover measured repository diffs without converting a
  complete impact answer into a permanent refusal.
- A self-sealed aggregate is insufficient by itself. Selected dimensions now
  name fixed-width content-addressed child receipts, and the hook requires each
  child object to exist and match its exact accounting.
- Isolated generations must share only content-addressed verdict objects, not
  mutable source or include graphs. Keeping those roots separate changed the
  measured three-group replay from zero of two cache hits to two of two.
- Closing a listening socket from another thread is not a portable wakeup for
  a blocking POSIX `accept()`; shutdown-before-close is required by the tested
  lifecycle.
- Exact helper byte identity is reusable across worktrees; ABA mutation tokens
  are worktree-local and must not trigger one full inventory scan per helper.
- Compile reuse and test reuse are coupled: a reused binary still needs its
  exact depfile graph, but it does not need copied object files.

## Next experiment

Give generated-output and remaining lint producers native content-keyed child
receipt publication, then compare a cold audit with warm direct admission.
Move compile-epoch session validation, depfile restoration, and hit batching
into `zcc` and count process creation before and after. Port the remaining
single full source-byte capture to C23, then measure proof-start process count
and latency again.
