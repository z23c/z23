<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Landing convergence under moving main

Observed on 2026-09-22 local time (UTC-04:00) / 2026-09-23 UTC. Host:
Linux, AMD Ryzen 7 PRO 8840U; compiler: Clang 22.1.6.

## Failure reproduced

At `bedaf0f555e1b511bd99388156f688c83490250f`, the focused
`test_dev_land` fixture advanced main three times during exact proof. The
unmodified landing step consumed its attempt budget before publication. The
fail-before run stopped at `tests/harness/src/test_dev_land.c:4309` after the
first move: the attempt became 2 instead of retaining 1. The transcript is
`/tmp/z23-converge-fail-before.log` on the test host; it has no PASS claim.

## Correction and scoped result

The queue records the prepared commit, base, tree and proof intent before
execution. A lost worker can request the same pair again. A changed main
queues a new pair from the submitted tip; its prior receipt cannot authorize
the new pair. The row retains its submission time through bounded retries,
then yields behind already-queued work when the attempt limit is reached.
A bounded `dev land drive` call releases the step lock during proof and
reacquires it immediately for the publication attempt.

On `6408c5e09fa92fbc14924b996945e4bedb7cbde2`, the focused
`make -j8 t-fast ONLY=dev_land` run passed its one selected group with zero
failures and zero skips. The measured test body was 34,932 ms. Its fixture
covers three main advances followed by landing, a missing proof worker,
competing integrators after PASS, and bounded drive publication. The transcript
is `/tmp/z23-converge-6408-test6.log` on the test host. This is local fixture
evidence; exact candidate publication still requires its own full proof and
remote observation.

After integrating `68cee428bf62121257b1207c745ee4c742afcad0`, the same
focused target passed 1/1 groups with zero failures and zero skips; measured
test-body time was 30,684 ms. This run includes the upstream malformed-row
refusal cases. Its transcript is `/tmp/z23-converge-68-test.log` on the test
host.

After splitting the new logic to satisfy the shrink-only complexity ratchet,
`make -j8 t-fast ONLY=dev_land` again passed 1/1 groups with zero failures
and zero skips. The measured test body was 32,270 ms. The transcript is
`/tmp/z23-converge-68-test-final.log` on the test host.

After rebasing onto `5c3073ebc678e9b9513e78952584492588347e0d`,
the focused `dev_land` group passed 1/1 with zero failures and zero skips;
the measured test body was 76,772 ms. The transcript is
`/tmp/z23-converge-5c-test-resume.log` on the test host. The companion
`make -j4 lint-fast` run passed. Its transcript is
`/tmp/z23-converge-5c-lint.log`. These checks do not establish an exact
publication receipt for the candidate.

After integrating the upstream bounded-yield rule at
`ebdded20884c8ed7d4b4b064cbc51eb932036d46`, the first two focused runs
exposed assertions that still expected an attempt reset after the first main
move: the checks at original lines 4291 and 2481 each expected 1 and
observed 2. Their failed transcripts are `/tmp/z23-converge-eb-test.log` and
`/tmp/z23-converge-eb-test2.log`. The corrected `dev_land` run passed 1/1
groups with zero failures and skips; test-body time was 62,131 ms. Its
transcript is `/tmp/z23-converge-eb-test3.log`.
The transcript SHA-256 values, in that order, are
`f95c6ee203ac25c941a1aed73522dc7965dd3ec3fa761ab7a909c6a7d07ff577`,
`e5470c44f6471301dbd7473058cd9c7b99987b15a13965791dd3371c5b794c11`,
and `b3e435df8ab03f468ee9bb870a9f392bf03d5e2da7de045f5013d45216324695`.

On `bfbf009b63924ed36e5db8d05ec3023ce591fd7d`, the combined source
passed `make -j4 t-fast ONLY=dev_land`: 1/1 group, zero failures and skips,
189,529 ms test body. This run includes terminal-outcome replay after a
process death, a refused outcome append, three proof-time main advances,
competing integrators and missing-worker recovery. The transcript is
`/tmp/z23-converge-bf-test.log` on the test host. The targeted complexity
ratchet, flag registry, generated-artifact compatibility, and source-derived
capability inventory checks also passed on this combined source.
`make -j4 lint-fast` passed all 32 gates in 85,481 ms wall time; the soft
75-second timing budget was exceeded without a gate failure. Its transcript
is `/tmp/z23-converge-bf-lint.log` on the test host.
The subsequent `lint-preflight` run passed four gates and failed
`check-api-reference-generated`: the changed `dev land` latency and example
had not yet been regenerated into `docs/API_REFERENCE.md`. The failed
transcript is `/tmp/z23-converge-bf-lint-preflight.log`. Running
`make docs-api-reference` regenerated one changed catalog row; the direct
generated-reference check then passed over 894 catalog entries. The failed
transcript SHA-256 is
`55da8a94505eac9f76d2d6e002ded830fb333dd49ad088d728b9c71f15036c5c`.
The corrected `make -j4 lint-preflight` run passed all five gates in
172,773 ms wall time, including capability closure and generated inventory.
Its transcript is `/tmp/z23-converge-bf-lint-preflight2.log`.

## Current-base field observation

The exact `e893c0cf2f7b44ab0ec630d1572ac221b4e08248` proof against
`74e0b582ecc0aa8d185e9def3bd753bd348221bd` passed 41/41 selected
groups, with zero failures and skips and one preserved load-flaky first
attempt that passed its exclusive retry. Test body time was 675,208 ms.
The full lint gate set passed in 654,256 ms. The receipt SHA-256 is
`0c01f853be4778cf9345642d69970ef29584805d095fd3f9752d87a60b33ebcc`.
Main advanced to `ebdded20884c8ed7d4b4b064cbc51eb932036d46` before
publication, so that exact receipt remains evidence for its original pair,
not publication authority for the successor.

The next pair, `f186ed3da128ea90cfd4613c8d52f2c520faca13` against
`ebdded20884c8ed7d4b4b064cbc51eb932036d46`, also passed exact proof.
Its lint and test phases took 678,110 ms and 488,375 ms, respectively; the
receipt SHA-256 is
`87470c096db45881e0083bdea05342289ac1a1797cae5a07799816c9446ebea5`.
Main advanced again to `bfbf009b63924ed36e5db8d05ec3023ce591fd7d`
before publication. The landing queue persisted the submitted candidate
and started the new exact pair
`b9a9872297f686d49b3ff5279c7eafe84f35bdef` against that base.
Main then advanced to `5049646f6c12bf5fe88f66028816651ff50a6c5a`
while that proof was running. It cannot authorize publication on the new base.

## Pending-proof main movement

On `b7f5ac5168f68a8eb8b85dccfc07fb8b1011ecf3`, a new fixture held the
exact proof in its pending state while a separate writer advanced main. The
unmodified resume step returned `proving` instead of requeuing the current-base
successor. `make -j4 t-fast ONLY=dev_land` failed 1/1 selected group with zero
skips at `tests/harness/src/test_dev_land.c:3865` after 67,523 ms of test body.
The preserved transcript is `/tmp/z23-pending-b7-fail-before.log` (SHA-256
`7daf9a50197f820d4b91aba9a4c5242e1c8181427a4069873850023d9339c6cd`);
the focused group log is
`test-tmp/test_parallel_702897_777.log` (SHA-256
`6138b4878c133e7f6178f7833e801a498e1fa0a8f88c645114d3cc456ebf96f5`).
The resume path now compares the independently observed main SHA with the
persisted proof base before reading the old receipt. A mismatch immediately
creates the successor; the old proof remains evidence for its original pair.
With that change, the same focused target passed 1/1 group with zero failures
and skips; test-body time was 137,910 ms. Its transcript is
`/tmp/z23-pending-b7-pass-after.log` (SHA-256
`a7ed3a09668f26d5be4157e6b7ecb922bd193b01f4584093935879d2cf83a5e1`).
The first `lint-fast` attempt failed only the shrink-only cyclomatic gate:
placing the new case in the existing convergence test raised that function
from its cap of 15 to 16. The failed transcript is
`/tmp/z23-pending-b7-lint-fast.log` (SHA-256
`eacb4546bd4d9cad4c63b03ccdc07e01df70d8c27d16a6ee1a9d7149d9e4134e`).
Moving the case into its own fixture function restored the cap;
`make -j4 check-cyclomatic-complexity` then passed with 56,866 functions
scanned and 4,135 exact baseline pins. The transcript is
`/tmp/z23-pending-b7-complexity.log`.
The first post-extraction build failed because the harness macro requires a
local `_test_next` label; a concurrent documentation edit also tripped its
source-identity guard. That failed transcript is
`/tmp/z23-pending-b7-test-final.log` (SHA-256
`51fb98bd4660cfd338ced2fe0045d13a19cca420000890c7152d5c1cd0a194bb`).
After adding the label and freezing the source tree, the focused target
passed 1/1 group with zero failures and skips; test-body time was 205,109 ms.
Its transcript is `/tmp/z23-pending-b7-test-final2.log` (SHA-256
`d0a4182134b733f565a67da9c3354b6d77b64fc12cd15489e55f95d473740a69`).
`make -j4 lint-fast` passed all 32 gates in 21,756 ms wall time; its
transcript is `/tmp/z23-pending-b7-lint-fast-final.log` (SHA-256
`16ba990feb6495f7258063da2e071bc3ea87940c2ec4d0a32fc543be2f249b0c`).

## Terminal history and successor identity

On 2026-09-23 UTC, an isolated landing fixture submitted request `#1`,
cancelled request `#2` into durable terminal outcomes, then advanced main three
times while `#1` was proving. At the bounded retry yield, the unmodified
successor path chose `#2` from the last queue row instead of accounting for
terminal history. The registered `test_dev_land` group failed at
`tests/harness/src/test_dev_land.c:3949`: observed sequence 2, expected 3.
The fail-before transcript is `/tmp/z23-yield-seq-fail-before.log` (SHA-256
`90d1a4d596b157bbc62379556e70c5920053998d2c697b331ca3bc7cd81aa988`);
the test body took 160,012 ms. Its 832-second total included a cold worktree
rebuild and the runner's exclusive retry. The terminal `#2` outcome and
unpublished main were observed before the assertion. The crash/restart boundary
is the atomic queue rewrite that replaces an in-flight row with its queued
successor: a restart must see a sequence that has never named an older outcome.

The yield path now calls the existing history-aware sequence allocator under
the queue lock before replacing the row. Unreadable or exhausted terminal
history refuses the rewrite. The fixture checks the persisted cancelled
outcome, successor `#3`, and eventual landing of the original tip in its bare
test remote. `make -j4 t-fast ONLY=dev_land` passed 1/1 groups with zero
failures and skips; test-body time was 32,510 ms and command wall time 45 s.
The pass transcript is `/tmp/z23-yield-seq-pass-after.log` (SHA-256
`12772856ce5f9e9b9a868b6ffafce9791c96b842a913829dc574691ee4f6d6e3`).

The first `lint-fast` run exposed four source-line pointers shifted by the
allocator call; the failed transcript is `/tmp/z23-yield-seq-lint-fast.log`
(SHA-256 `c6a33711cf5ef648b3f3a1b412ab339d224327fb51a10d334b120030b2a11e35`).
After updating those pointers and regenerating the capability inventory,
`lint-fast` passed in 44 s (`/tmp/z23-yield-seq-lint-fast-final.log`, SHA-256
`7c357fa9dda43809bfd89e3975f56acbda0e73eeee7071a21bbe9f921f63a52f`).
`lint-preflight` passed five gates in 128 s
(`/tmp/z23-yield-seq-lint-preflight.log`, SHA-256
`f1d52296f7eba0e93aaa2e862f38671b1901ead80ba9ae5fd80f4fb0ac3c4bba`).
The host was Linux on an AMD Ryzen 7 PRO 8840U with Clang 22.1.6. Fixture
landing is not remote publication authority for this source candidate.

## Current-base proof refusal and deterministic competitor witness

Native request `#10` prepared candidate
`bbc14f5d6aa92a81beb424f345b5d66cf86531bd` against
`a0b65b4d1757ee0b2f47e93fb907754e89c0eb6a` and selected 51 groups:
28 ran and 23 used matching cache entries. Full lint refused that exact
pair at two independent gates. `check-no-real-clock-test-deadline` found the
fixed-iteration lock poll in the competing-integrator fixture; its gate log
has SHA-256 `271076c1dbbfdbde67f5cfaba678cef3ed75553ad4e920e635ab60a9f79d31b4`.
`check-doc-accuracy` found a pinned lint-gate count that had become stale;
its gate log has SHA-256
`77cce412b0b6b80536e25fd2f5142c4eec2e5cba0b0165a078e331668435152e`.
No PASS receipt or remote publication was claimed for that pair. Main moved
to `d65a02d818aa5c663970d63f075540b3ec9537a5` during proof; the
interrupted attempt phase has SHA-256
`54dc4699a36ee0cf5af09bac3289ad549b373c7ec41d39db2d05f6ff394183ac`.
Request `#10` was cancelled through the native queue command, preserving its
terminal outcome and the failed logs.

The fixture now uses a test-only pipe barrier after the first integrator
holds the native step lock and picks the queued row. The second integrator
must observe `STEP_BUSY` before releasing the first. The test then checks one
landed outcome and no residual work. The barrier replaces elapsed-time
polling, so the witness does not depend on scheduler timing. The stale gate
count was removed. Both previously failing gates passed in 7 s; transcript
`/tmp/z23-gatefix-two-gates.log` has SHA-256
`3d2dd168d93cf511430f6200bb1fc8ad02a8443cb91d24c08eb47f5e13e576a2`.
`make -j4 t-fast ONLY=dev_land` passed its one selected group with zero
failures and skips; test body took 32,237 ms, command wall time 306 s
including a cold rebuild. Transcript `/tmp/z23-gatefix-dev-land.log` has
SHA-256 `d02c4dcd76cdc0ff586a4fea9cc1714ed2192caf935473e1d7f0c453f18bf73a`.
The final fixture extraction retained the same result: 1/1 group passed,
zero failures and skips, with 140,310 ms test body and 200 s command wall
under concurrent build load. Transcript `/tmp/z23-gatefix-dev-land-final.log`
has SHA-256 `9c4be21f1c07eaab70e21c4dbd24187e5aa24ce635c4f9f106df47967392ad53`.
`lint-fast` passed 32/32 gates in 52 s; transcript
`/tmp/z23-gatefix-lint-fast-final.log` has SHA-256
`ae9ceecd348841f0eb76449a7a3a905b6520e10d59142643ae6ea82fce5eee29`.
The first preflight passed four gates but refused the stale generated
capability inventory after the fixture helpers were extracted. It took 163 s;
transcript `/tmp/z23-gatefix-lint-preflight.log` has SHA-256
`3adc29348d09232983e2160bb24029ca3ff5dde7e0b8ef2243b27313253aaf1a`.

After carrying the repair onto `3f52f37fb2388c37b7f23a611ee9a9e1185cc739`
as a single-parent candidate tree, `make -j4 t-fast ONLY=dev_land` passed
1/1 selected group with zero failures and skips. The test body took 81,869 ms;
the cold build and test command took 733 s. The transcript is
`/tmp/z23-current-dev-land.log` (SHA-256
`cb201df01860aaad9695485c21d86930b4ee3820e3a270a9d6db7f9aee353f14`).

The same source change was applied to fresh `origin/main`
`49f012603b19881cb30f32847cf83a88fa73b93e`; only the generated
capability inventory conflicted and was regenerated from the combined tree.
The registered `dev_land` group passed 1/1 with zero failures or skips on
Linux: test body 81,703 ms, cold command wall 298 s. Transcript
`/tmp/z23-convergence-current3-dev-land.log` has SHA-256
`19171fdadb76f39bcaf74a2ffba66956fce3cc44eca79e0ae1f0b83778560cec`.
`lint-fast` passed 32/32 gates in 16 s; transcript
`/tmp/z23-convergence-current3-lint-fast.log` has SHA-256
`635d63563cdce987ad8a2cb43700e2234b220492053a8eb041ae6635e978eb44`.
`lint-preflight` passed 5/5 gates in 72 s; transcript
`/tmp/z23-convergence-current3-lint-preflight.log` has SHA-256
`89982c7203dfe770d5311ba19b77991e5170e8c52d619f217944a90068956a15`.
