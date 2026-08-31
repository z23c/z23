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

At `2026-08-30T16:20:23-04:00` (`2026-08-30T20:20:23+00:00`), commit
`330461e0bd7a2c85c80b2073c5dcc39029afb9d4` removed a second overlapping
inventory rule that still selected `make_lint_gates`. A regression now requires
one shared-rule hit, `code_inventory` present, and `make_lint_gates` absent for
`docs/CAPABILITY_INVENTORY.jsonl`. The exact eight-group proof for the policy
and regression edit ran eight groups, reused zero, failed zero, and skipped
zero in 89.1 seconds. The resulting sealed receipt admitted the push.

On the same 16-logical-CPU AMD Ryzen 7 PRO 8840U host with GCC 16.1.1, 1,000
complete warm hook invocations measured 4,698 microseconds p95, 4,947
microseconds p99, and 5,178 microseconds maximum. Each invocation performed
the two bounded Git queries for repository root and ancestry plus native
receipt/child validation; it launched no compiler, test, lint, Make, Bash, or
PowerShell process. The bounded PASS output was 43 bytes. A real missing
receipt refused in 6,985 microseconds with a 307-byte exact wait instruction.

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
epoch's depfiles and validated current-epoch selector into the generation with
fresh private inodes, binds their paths and content hashes into the test-helper
receipt, and leaves object files behind. Source and include-graph reads
therefore stay generation-local while the immutable PASS objects remain
shared.

The first depfile-aware proof planned 131 cacheable groups, reused one prior
PASS, ran 160 groups, and stored 129 new PASS receipts in 429.1 seconds. Its
only failed group refused because the isolated generation did not contain the
required `zclassic23-acme` executable. The broker now builds and hashes that
test prerequisite alongside `zcl-nodectl`. The merged mesh-terminal acceptance
also requires the confined `fbsh` runtime, which is built and hashed in the
same isolated helper set; absence remains a hard failure.

## Resident queue cutover

At `2026-08-30T19:10:01-04:00` (`2026-08-30T23:10:01+00:00`), the Linux
host still reported 16 logical CPUs and an AMD Ryzen 7 PRO 8840U processor.
The canonical compiler was GCC 16.1.1 20260430 with `-std=c23`; Clang 22.1.6
was also installed.

Exact-pair scheduling moved from one detached worker per notification into the
singleton `z23-dev` watcher. A notification now atomically publishes one
versioned pair request and returns. The resident watcher advertises
`proof_queue_version=1`, coalesces only Git-proven superseded pending pairs,
owns one supervised proof slot, and assigns each claimed request a private
attempt directory and lease. Receipt, failure, and lease removal recheck that
lease while holding the queue lock; an obsolete attempt therefore cannot
publish over a newer one.

A disposable real watcher accepted an exact-pair request in 124 milliseconds
of caller-observed wall time. The typed command measured 316 microseconds
inside its handler, below its 250 millisecond budget. Status first reported
`resident_proof_request_queued`; two seconds later it reported the expected
fixture refusal, `head_changed_during_proof`. The attempt retained its claimed
request under a private directory, published one canonical failure, and left
no lease. Native stop verified and stopped the exact watcher ID in 20
milliseconds. No compiler, lint, test, Make, Bash, or PowerShell process is
reachable from notification enqueue or push admission.

The first clean-checkout launch exposed a separate scale refusal before any
proof work began: the Linux watcher stored at most 512 directory descriptors,
while the tracked tree contained 935 distinct directory paths. The watcher
now grows its checked descriptor table geometrically instead of placing a
fixed table on the stack. At `2026-08-30T19:31:42-04:00`
(`2026-08-30T23:31:42+00:00`), a disposable checkout fixture containing 600
child directories plus its root reached `watcher_ready=true` in 21
milliseconds, advertised `proof_queue_version=1`, and stopped its exact owner
in 20 milliseconds. The host had 16 logical CPUs, an AMD Ryzen 7 PRO 8840U,
and GCC 16.1.1 20260430. The exact clean pair then enqueued in one millisecond;
the earlier fixed-capacity binary had left the same pair queued without a
resident owner.

Build cost remains the measured dominant problem. A warm `make dev-bin` before
the directory fix took 35.319 seconds of wall time, 27.520 seconds of user CPU,
and 8.866 seconds of system CPU. Rebuilding the changed watcher and its test
artifact took 98.134 seconds wall, 74.433 seconds user, and 24.818 seconds
system. These are build measurements, not proof or push latency claims.

The registered `test_impact_composition` queue fixture enqueued two pairs,
selected the newer request, preserved the older request because its ancestry
was unavailable, then claimed both private attempts in order. Each attempt
published its intentional failure and released its lease. The complete group
passed one of one with zero skips and zero unobserved cases in 52.4 seconds;
most of that time remains the existing composition fixture, not the queue
operations. `test_dev_platform` passed one
of one in 2.8 seconds and `test_native_api_contract` passed one of one in 0.6
seconds, also with zero skips and zero unobserved cases. `lint-fast` passed all
24 selected gates in 14.075 seconds. The source-derived capability inventory
then regenerated 1,412 capabilities and 18,684 symbols; its freshness and
cross-artifact contradiction gates passed.

The full 182-gate lint run completed in 274.430 seconds. Before regeneration
and arm consolidation it passed 175 gates and refused seven. The two
slice-owned refusals—duplicate public definitions across platform arms and a
stale capability inventory—were corrected and their individual gates passed.
The tracked platform gate's missing executable bit was also corrected and its
individual gate passed. The remaining observed refusals were a partial
capability object epoch, pre-existing raw `/proc` use in `test_postmortem.c`,
and 27 pre-existing MinGW syntax failures across test translation units. No
green full-lint claim is made. Caller token count was not available from the
native tools and is not derivable.

## Native object publication and depfile cutover

At `2026-08-30T21:40:15-04:00` (`2026-08-31T01:40:15+00:00`), the host still
reported 16 logical CPUs and an AMD Ryzen 7 PRO 8840U processor. GCC was
16.1.1 20260430 and Clang was 22.1.6. The exact proof preceding this build
slice selected 41 groups, ran all 41, reused zero, and reported zero failures,
skips, or unobserved cases. Its registered-test phase took 103.3 seconds; the
complete isolated attempt ran from `2026-08-30T19:36:46-04:00` to
`2026-08-30T19:47:27-04:00`.

The source-identity hot path now batches NUL-delimited file hashing and mode
capture through one admitted C23 helper. Stable whole-tree capture changed
from 5.382 to 4.599 seconds, a 14.6 percent reduction. An execution trace
changed from 354 to 208 executed lines, with `stat` executions changing from
225 to 150 and `sha256sum` executions from 81 to 5. The native path started
two helper processes. A `make -n build-only` trace changed from 830 to 691
executed lines, with `stat` changing from 269 to 194 and `sha256sum` from 145
to 69. The untraced parse midpoint improved by approximately 3.5 percent.
Native and portable records remain byte-identical, and the selftest injects
file, index, directory, and exclude-policy races.

The first standalone-helper integration attempt failed after 92.003 seconds
because `source_identity_batch.c` was swept into the node source set. No
artifact was admitted. Classifying it with the existing direct-development
standalone sources removed it from node ownership while preserving its own
strict C23 bootstrap and parity tests.

`zcc --epoch-object` now owns session validation, no-follow descriptor
containment, compiler invocation, cache restoration, depfile publication,
coverage serialization, and depfile-before-object publication for the
`build-only` and `test-fast` profiles. Every publishing attempt first creates
or exactly reuses a durable `.unverified` aggregate marker while holding the
stable `.epoch-admission/<epoch>.lock`. Aggregate verification removes the
marker under the same lock. A killed build therefore causes the next session
to quarantine the complete epoch; moving the epoch cannot split the lock
inode. Native and legacy paths refuse malformed, mismatched, or symlinked
markers. The focused object gate passes strict GCC and Clang builds, ASan,
UBSan, and LeakSanitizer, and exercises cache hits, path replacement, lock
serialization, and record-last coverage publication. The integrated epoch
session selftest exercises dead-marker quarantine and fresh-session recovery.

Project, generated, and vendored dependency files now use `-MMD -MP` while the
compiler identity binds toolchain search roots and relevant environment.
Uninventoried include/search modifiers fail closed in the epoch key. The new
2,054-depfile `build-only` epoch occupies 4,554,845 bytes, down 67.0 percent
from the prior 13,797,422-byte `-MD` epoch. Its first population took 60.833
seconds. Identical warm runs took 43.379 and then 9.262 seconds; the stabilized
run is 87.1 percent below the prior 71.726-second identical-build measurement.
All 2,054 objects and 2,054 depfiles retained the same content, size, mtime,
and ctime digest across the 9.262-second run, and `.unverified` was absent
after admission. A dry-run parse still took 6.930 seconds, identifying Make
startup and source/build identity work as the dominant warm cost.

The newly keyed `test-fast` and required dev-helper epochs took 437.629 seconds
to populate while bounded at 16 jobs. The registered `native_api_contract`
group then passed one of one with zero failures, skips, or unobserved cases.
Subsequent identical invocations took 92.945 and 16.928 seconds; the test body
took 0.636 seconds. The longer invocation had no compiler process in a process
snapshot at 68 seconds, but no complete process trace was recorded, so its
cause is not assigned. This is green functional evidence, but it does not
satisfy the five-second focused-proof objective.

The versioned, length-prefixed epoch-batch manifest has a strict C23 decoder
and canonical encoder. Sixty codec cases, 785 truncations, allocation-fault
injection, GCC, Clang, and sanitizer runs pass. There is not yet a batch
executor, worker pool, or batch-cache-hit claim. The next measured slice is a
cache-hit-only coordinator that preflights every job, writes nothing on any
miss, restores complete hits without compiler children, and publishes its
ordered ready root last. Caller-reported token count remains unavailable and
is not derivable from repository evidence.

## Knowledge gained

- Exact receipt admission is comfortably below the 250 millisecond target.
- Missing evidence fails below the one-second target and does not start proof
  work at push time.
- The generated inventory has one impact-rule owner and cannot select the
  broad lint family; the remaining inventory latency is inside its native
  freshness and test work.
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
- System-header depfiles consumed approximately two thirds of the object
  epoch's dependency bytes without improving project-header invalidation.
  `-MMD` is sound only because compiler bytes, search roots, environment, and
  accepted search modifiers are independently bound.
- A lock stored inside a directory that can be quarantined is not a stable
  lock. The admission lock must remain in an unmoved parent namespace.
- Native per-object publication removes shell work from misses and hits, but a
  warm Make parse still dominates the stabilized identical build.

## Next experiment

Add a cache-hit-only `zcc --epoch-batch-restore` coordinator. Decode and admit
the complete manifest before writes, probe every L1 closure, refuse with zero
writes and zero compiler children on any miss, then restore and publish the
ordered ready root last under the stable epoch admission lock. Compare 1,000
complete-hit batches with the current Make traversal, including child-process
count and artifact metadata. Separately cache or residently serve the exact
compiler/build-system identity so the 6.930-second Make parse does not remain
the warm-build floor. Add miss scheduling only after captured diagnostics and
POSIX process-group plus Windows Job-Object containment are available.
