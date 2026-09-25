<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Queue outcome artifact roots, 2026-09-25

The local replay commands below use operator-supplied `Z23_*` paths for
isolated worktrees, retained receipts, scratch and the development binaries.
Verify each artifact against its listed SHA-256 before rerunning a command;
the paths are not part of a portable evidence root. `Z23_ISOLATED_DATADIR`
must name a new private fixture datadir; `Z23_SKYCOMBAT_WORKSPACE` names the
frozen game workspace; `Z23_QUAL_SCRATCH` is a writable isolated parent;
`Z23_ROOT_DEV_BIN` and `Z23_PREFLIGHT_DEV_BIN` are the measured binaries.
The other variables name the retained owner fixture, qualification worktree,
land outcomes and proof-receipt directory described at their use sites.

The development queue's `reap` outcome now records `receipt_sha256` and
`candidate_sha256` alongside token and wall-time usage. Each root is computed
from the bytes read through one regular-file handle beneath the queue engine
directory. A missing, changing, oversized, symlinked, or nonlocal candidate
artifact produces JSON `null`. Malformed receipts, duplicate candidate or
verdict keys, Unicode escapes in keys or verdict values, embedded NUL bytes,
non-JSON number spellings, raw control bytes in strings, conflicting cost
aliases, and saturated cost integers produce null roots and an unknown verdict.
An unrepresentable candidate value keeps the receipt's stated verdict and
receipt root but has a null candidate root. In particular, this JSON parser
substitutes `?` for Unicode escapes, so an escaped candidate value cannot
name artifact bytes until an exact decoder is available.
Historical outcome rows without roots remain readable and report `null`.
Failed and refused attempts retain their costs and any available roots.

These are read-time observations of a receipt and a run-local candidate file.
The receipt names the candidate file but does not prove which candidate bytes
existed when the receipt was published, and it does not name a Git commit. A
later verified association object must bind the roots to a signed Git tip
before queue cost can be attributed to landed output. Git landing alone does
not establish development or application acceptance.

Baseline `origin/main` was
`e9ef677ad1fc595af20a4bd09f3c0b41116703ac`. The existing queue outcome
ledger had SHA-256
`27ebb89c2d4e88c258a3ddf134ca6ba32e14e2dd0f4366b5804e494dca7e1a60`.
Its `ci-worker-executing` attempt 1 reports a refused run with 54,322 tokens
and 7,000 ms. The corresponding receipt has SHA-256
`2f4f55baeac7141b5ce766353c22320889c8e76f8c0f49da2d532f25c3d9a120`;
its one-byte candidate artifact has SHA-256
`01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b`.
The refused verdict is preserved. This sample establishes available bytes,
not a successful candidate or a landed join.

Verification on the isolated source tree used:

```sh
git diff --check
flags=$(make -s print-DEV-CFLAGS | tail -1)
nice -n19 ionice -c3 gcc $flags -fsyntax-only tools/command/native_devagent_queue.c
```

GCC 16.1.1 passed strict C23 syntax with `-Wall -Wextra -Werror -pedantic`.
Clang 22.1.6 passed the same syntax check after removing GCC-only warning
options from `flags`.

The existing isolated queue acceptance fixture now writes a deterministic
receipt and candidate artifact, renaming the completed receipt into place
before `reap` observes it. It asserts the exact SHA-256 roots in both
`reap` and `status`: receipt
`e2e65de83072530e02b0a7d58d37a03eb9a075a31ae6f8815d6eaf5fd38e1395`,
candidate
`57cb3c681d8e20b291dbd7eec190205f7b2dcb2d200017ede904832666bd36b8`.
Its refused branch asserts 31 tokens, 47 ms, an exact receipt root, and a
null candidate root. A historical row without root fields asserts null roots
while retaining its seven tokens and 11 ms. GCC 16.1.1 and Clang 22.1.6
passed strict C23 syntax on the extended test source. The isolated worktree
had no warm test binary; the focused executable group and full signed proof
remain unrun for this proposal.

Independent review on `origin/main` `51ffb4629` found two false-association
paths in the first proposal: an intermediate symlink could leave the run
directory, and substring extraction could accept duplicate receipt keys. The
correction opens receipt and candidate through the positioned-file confined
form from the queue engine, rejects NUL bytes, parses the complete receipt as
JSON, and requires unique top-level candidate and verdict fields. Added
fixtures replace the receipt with duplicate candidate keys and replace the
attempt directory with a symlink before reap; both require unknown verdict and
null roots. Strict GCC 16 C23 syntax and `git diff --check` pass on the
correction. A cold registered test attempt was interrupted after the review,
before a test verdict, while another live proof occupied the laptop. No
executable or publication acceptance is claimed from that attempt.

A second independent review found that the repository JSON parser substitutes
`?` for Unicode escapes and saturates oversized integers. The queue receipt
reader therefore refuses Unicode escapes in field names or candidate and
verdict values, plus sentinel-limit cost integers,
and refuses conflicting `tokens` and `tokens_used`. The negative fixture checks
duplicate candidate keys, an escaped candidate-key alias, an oversized token
count, conflicting token aliases, and an intermediate symlink. A third review
found the shared parser accepts leading-zero numbers and raw newlines inside
JSON strings. A bounded lexical check now refuses those before parsing; the
negative fixture covers both spellings and a Unicode-escaped verdict. Escaped
Unicode in provenance values remains readable; the queue does not use
provenance text as an artifact path. Strict GCC 16 C23 syntax passes on the
corrected source and fixture. A second low-priority
registered build was interrupted before a test verdict when the review found
these cases; its log SHA-256 is
`776aedbaf1292cd3881905a428324de556baaeff2ac25d808b298aa010f071db`.

The corrected candidate at signed commit
`09e426beeef8b26a7968aa0aae61f75576269977` passed the registered
`make CC=gcc -j2 t-fast ONLY=devagent_queue` gate under `nice -n 19` and
`ionice -c3` on 2026-09-25. Its three selected groups passed with zero
failures, zero skips, and 1.213 seconds of test-body time. The complete build
and test log has SHA-256
`98121b8021395cf4ebf7b5e3913f48067f20781a140eafecd7f4cff0721d9549`.
The log file's creation and last-write times span approximately 885 seconds,
from `2026-09-25T10:40:26Z` to `2026-09-25T10:55:11Z`; this is a build-and-test
envelope, not an instrumented CPU or I/O cost. The final test and development
epoch directories contain 3,602 and 2,366 object files and occupy 279,594,784
and 62,103,678 bytes respectively. These are directory occupancies, not a
claim that every byte was newly written in this run.
The queue writes outcome `ts` when `reap` observes the run, so that timestamp
is not execution finish. The worker receipt writes a Unix `ts` after its gate,
but the outcome does not validate or carry it. Existing rows therefore cannot
separate queue wait, service, and reap lag; `wall_ms` is the worker's reported
run wall time and is not active CPU. These limits are visible in queue source
SHA-256 `5c20a68bf61800e1332cf27faa711c753893d621879afad873f3465af22c2d9e`
and worker source SHA-256
`2797c79dd22ccbd95827d1377af6b2e2fc53c648b207e2a77ac357e3e66db30a`.
This is focused local acceptance only; full proof, signed association to a
landed Git tip, and remote observation remain outstanding.

The queue helper and fixture refactor at signed commit
`09f482d7fb719a9fc97a99ba0274ce261c6b7f80` was combined with
`origin/main` `eb3615ceb92aa67c132deef77d5bb8d96fd5d082` at signed merge
`ed2a9f75b616f5e0aa9f5d2474825cd7497eebdb`. The combined tree passed
the same three registered queue groups with zero failures and zero skips;
its complete log SHA-256 is
`56f309b488a8cdcc5992860980d6c289e4a1d6373c72fc2f8c5a6eb2354a07c8`.
The generated capability inventory was refreshed with
`make docs-capability-inventory`. `make -j2 lint-preflight` then passed all
five gates; log SHA-256 is
`55ca28c088a62476d584c0956a2d24bf4aef302c6f1bc8923c88c3305b254e51`.
The remaining `lint-fast` work is the shrink-only complexity baseline update
for `test_devagent_queue` from 34 to 28 and `dvq_reap` from 46 to 45. The
baseline file is claimed by another live writer; this worktree has not
modified it. Full proof and remote observation remain outstanding.

After the next `origin/main` update to
`4c0686358bdef195e4fbb4d9f3ffbd1be0cf190d`, the generated inventory
was regenerated from the combined tree at signed merge
`9f97bc8061afef233530e27335d693567d1c0820`. The focused queue suite
again passed 3/3 with zero skips (log SHA-256
`5d04b126ab2230d421fe8e50d788943cb270831364ac9bbe48f0d63bb9522764`),
and all five `lint-preflight` gates passed (log SHA-256
`f77704bd0dc29d919f485a667219f3fa52cd574c7993fe0b011620b4dd54d73b`).
`lint-fast` passed 32/33 gates; its sole failure is the two shrink-only
baseline pins above (log SHA-256
`0b702d906d95a3b686826dbaf6f4f24ff64c179a5eaca58f583cae722475d4f8`).
The owner request is fleet mail receipt 702, with routing receipts 703 and
704. No baseline edit, full proof, remote acceptance, or publication has
occurred in this worktree.

The next upstream publication-truth change, `origin/main`
`9dac5ee9022118a63c9f27b4d9ae8d608bee913d`, was integrated at signed
merge `2571871e7bf77f25677fbbb4175b857d1d974f84` and the inventory was
regenerated. On that combined tree the focused queue suite passed 3/3 (log
SHA-256 `a8a9d2c3e4bff3a5a1f23cf27abfb300c966f2cc0ec5a44646a7ca69b23c98e7`)
and `lint-preflight` passed 5/5 (log SHA-256
`bcee228ccdc191a73c14a2abd26003b96dc92b49e0e5a1da5ba85748c33d79ef`).
`lint-fast` again passed 32/33; only the same two shrink-only pins remain (log
SHA-256 `c6887266fc7c87fcfea34ab7cbcc73d6baaf1f842cca8fb8ab264e6e193576f0`).

## Cost attribution at the current shared baseline

At `origin/main` `9dac5ee9022118a63c9f27b4d9ae8d608bee913d`, the tracked
join audit `docs/experiments/2026-09-25-factory-join-audit.json` has SHA-256
`154e0b56d2e821ce3c4abf9ce66578e84c91cccc2e2080e60c38b799d99f28b1`.
It contains 24 queue outcomes, eight with positive token use, and 326 land
outcomes. Neither ledger has a task or candidate root. The 99 land rows labeled
`landed` are local publication states; their acceptance is unknown without a
bound remote receipt. The frozen mixed-100 ledger SHA-256
`7fc17ab494d13240eb17e5b23f8dd61226c49de4591093653d4d6e86115c006c`
has zero DEV and zero full acceptances. Thus the denominator for
cost per accepted novel C23 line is zero and a cost-weighted accepted-output
rank is **undefined**. A zero token or proof cost would be an invalid substitute
for these missing joins.

| Cohort and stage | Measured wall cost | Attribution limit |
| --- | ---: | --- |
| Two observed main-ancestry changes, four fresh proof attempts | 1,302.345 s proof service; 368.747 s queue wait | The attempts have remote-base and timing fields, but no signed task, candidate, model, token, or retained-C23 join. The two totals are disjoint fields within this cohort. |
| Frozen mixed-100, two-store commit and reproduction | 396.966 s of 497.373 s factory-call wall (79.8%) | All 100 were locally verified, none DEV or fully accepted; this is a separate cohort. |
| Two signed evidence publications, seq38 and seq37 | 11,085 s and 6,682 s submission-to-remote-receipt | These end-to-end intervals include waiting and cannot be added to the proof-service row. They establish publication, not app acceptance. |
| Cold focused queue gate on this candidate | Approximately 885 s build-and-test envelope; 1.213 s test body | CPU, I/O and per-object fresh/reused work were not sampled, so 883.8 s is an unattributed envelope, not a proven compile cost. |

The four proof-attempt totals are reproducible from the audit's `queue_us`
and `service_us` fields with:

```sh
awk '/"queue_us":/ {gsub(/[^0-9]/,"",$2); q+=$2; nq++} /"service_us":/ {gsub(/[^0-9]/,"",$2); s+=$2; ns++} END {printf "queue_rows=%d queue_s=%.3f service_rows=%d service_s=%.3f total_s=%.3f\n",nq,q/1000000,ns,s/1000000,(q+s)/1000000}' docs/experiments/2026-09-25-factory-join-audit.json
```

It printed `queue_rows=4 queue_s=368.747 service_rows=4 service_s=1302.345
total_s=1671.092` on 2026-09-25. The smallest prerequisite for a valid
accepted-output ranking is an immutable, verified association from queue
attempt and exact receipt/candidate bytes through signed task and candidate
identity to proof, publication and independently observed remote receipt.
Historical unmatched attempts must remain unknown. Fleet mail receipt 710
routes that join gap to the factory director; receipts 711, 712 and 714 route
the distinct timestamp, log-silence and CPU-state gaps to their owners.

## Executable candidate-drift counterexample

An isolated native-CLI run on 2026-09-25 tested whether the queue's two
read-time roots bind candidate bytes to the time its receipt was written.
The binary SHA-256 was
`197309e95f6f338715238b5adb9c1688efabc2ccb7ceec15890051be69fdb5eb`;
the queue source SHA-256 was
`5c20a68bf61800e1332cf27faa711c753893d621879afad873f3465af22c2d9e`.
The fixture used `XDG_STATE_HOME` under an isolated temporary directory and
never dispatched a model or used the operator's queue:

```sh
fixture_root=$(mktemp -d "$PWD/test-tmp/queue-mutation.XXXXXX")
export XDG_STATE_HOME="$fixture_root/state"
unit="$PWD/build/bin/z23-dev"
"$unit" dev agent queue --input='{"action":"post","kind":"leaf","name":"mutate","attempt":1}' > "$fixture_root/post.json"
"$unit" dev agent queue --input='{"action":"claim","worker":"fixture","session":"epoch1"}' > "$fixture_root/claim.json"
run_dir="$XDG_STATE_HOME/z23/dev/engine/mutate/a1"
printf 'candidate A\n' > "$run_dir/candidate.diff"
printf '{"verdict":"PASS","candidate":"candidate.diff","tokens":17,"wall_ms":23}\n' > "$run_dir/receipt.json"
sha256sum "$run_dir/candidate.diff" "$run_dir/receipt.json" > "$fixture_root/before.sha256"
printf 'candidate B\n' > "$run_dir/candidate.diff"
sha256sum "$run_dir/candidate.diff" "$run_dir/receipt.json" > "$fixture_root/after.sha256"
"$unit" dev agent queue --input='{"action":"reap"}' > "$fixture_root/reap.json"
```

The receipt retained SHA-256
`e2e65de83072530e02b0a7d58d37a03eb9a075a31ae6f8815d6eaf5fd38e1395`.
Candidate A was
`5e33b8586de752e2e72ad8b92b22a8f54ea7836ab876f8211fdc2489f93cc70b`;
candidate B was
`e1295538929323b8a7e07ef36c0a28a17cd19330377884bb64f3b0515a9839e6`.
The `reap` reply SHA-256 was
`a7011e242473240c671b15a07f397f464de3219a7c857ff61cb3242f5da165f3`;
it reported the unchanged receipt root, candidate B's root, receipt-stated
`verdict=PASS`, and `rc=-1` because this fixture did not run a worker.
The durable outcome row SHA-256 was
`428519c19032adb37d6d9a3ebef63ef6995848fc64929348236253af78204f5b`.
This is a counterexample to any claim that these two fields alone establish
which candidate bytes existed when the receipt was published. It does not
demonstrate a stale queue hash: the queue accurately hashes the bytes it reads
at reap. A downstream association must verify a candidate root stated by an
authenticated receipt or signed candidate object before joining this cost to
proof or accepted output. The queue's `PASS` is a receipt observation, not
independent execution or application acceptance.

## Queue timing retained in outcomes

After integrating `origin/main`
`52bee3bb8c719de149512ea9fdebe94b239cdf2a` at signed merge
`3ffb8f8e2`, the queue carries its existing row `seq`, enqueue ISO timestamp
as `queued_ts`, and claim/dispatch Unix start as `started_unix` into each
outcome row and both `reap` and `status` replies. The existing outcome `ts`
remains the reap observation time. No new ledger is created. Historical
outcomes missing these fields return JSON null. The enqueue-to-start queue
wait is derivable at whole-second resolution for newly recorded attempts;
negative intervals caused by wall-clock adjustment must remain unknown.
Neither `ts - started_unix` nor receipt `wall_ms` is active CPU or exact worker
service: finish time and reap lag remain unmeasured.

The combined source SHA-256 is
`4b5a68e330194285adcb8b751cf5001f99d29f5b96e62219ce89dd1a6f62f956`,
and the test source SHA-256 is
`a99c4e6ed258493879e38fee1ab84f776e9e2241eaa6d9ab1189b9e98d89dc2a`.
Strict GCC 16.1.1 C23 syntax passed for both files. The registered command

```sh
nice -n 19 ionice -c3 make CC=gcc -j2 t-fast ONLY=devagent_queue
```

passed all three selected groups with zero failures or skips. Its complete
log SHA-256 is
`f1fce783b1be2b0c21e23ed77a4b12b3ddf428fa33587a737701af70e5b19645`;
the test-body receipt reported 1,206 ms, and Bash reported 15.515 s wall,
17.219 s user and 5.949 s system for the command envelope. These aggregate
times do not split active worker CPU from build, wait or I/O. The generated
capability inventory was refreshed from the combined tree. The complexity
gate has one remaining shrink-only pin in the separately claimed baseline:
`test_devagent_queue` 34 to 28. `dvq_reap` is now M46 and matches its existing
pin, so the previous request to lower that pin was withdrawn in fleet mail
receipt 720. The focused pass is not full proof or remote acceptance.

The rebuilt native developer binary, SHA-256
`5e50f20d15e361ed0f1d6870d74fda4a898574cd9e228b4d29a5c082112d8164`,
also passed an isolated CLI timing and replay control on Linux. Its low-priority
`make CC=gcc -j2 z23-dev` build log SHA-256 is
`13baa085d696776f83fcf87039501535c461f275b47bca8af25b21b62aeb59c6`
(13.527 s Bash wall). The fixture used a new `XDG_STATE_HOME`: post one `leaf`
attempt, wait two seconds, claim it as `fixture/epoch1`, try a second claim as
`fixture/epoch2`, write a local control receipt and run-output file, then reap
twice. Reproduce its state transitions with:

```sh
fixture_root=$(mktemp -d "$PWD/test-tmp/queue-timing-cli.XXXXXX")
export XDG_STATE_HOME="$fixture_root/state"
unit="$PWD/build/bin/z23-dev"
"$unit" dev agent queue --input='{"action":"post","kind":"leaf","name":"timed","attempt":1}' > "$fixture_root/post.json"
sleep 2
"$unit" dev agent queue --input='{"action":"claim","worker":"fixture","session":"epoch1"}' > "$fixture_root/claim1.json"
"$unit" dev agent queue --input='{"action":"claim","worker":"fixture","session":"epoch2"}' > "$fixture_root/claim2.json"
run_dir="$XDG_STATE_HOME/z23/dev/engine/timed/a1"
printf 'timed candidate\n' > "$run_dir/candidate.diff"
printf '{"verdict":"PASS","candidate":"candidate.diff","tokens":2,"wall_ms":7}\n' > "$run_dir/receipt.json"
printf 'rc=0\n' > "$run_dir/run.out"
"$unit" dev agent queue --input='{"action":"reap"}' > "$fixture_root/reap1.json"
"$unit" dev agent queue --input='{"action":"reap"}' > "$fixture_root/reap2.json"
"$unit" dev agent queue --input='{"action":"status","json":true}' > "$fixture_root/status.json"
```

The outcome row SHA-256 is
`2e2e41409b3b4187106d193d16eede52c9ab54d5e95079dc60fc2a7befccf009`.
It states `seq=1`, `queued_ts=2026-09-25T11:52:46Z`,
`started_unix=1790337168`, and reap `ts=2026-09-25T11:52:48Z`:
enqueue-to-claim was two whole seconds. The second claim returned `state=empty`
(reply SHA-256
`550cdbca64354fde9cf556b216840525d3871bf790659ee95aa9217b8993ab35`),
the second reap returned no outcomes (reply SHA-256
`b5822977356f81e0a20c8f1b241f5077e47a13f9c0ce79ddf5bae7d8e5f1fa55`),
and the ledger retained exactly one row. Its receipt root was
`2d68510b189736fd0324dc67f9eeda969b01e5519b81a24d9b20aafe32b593d5`;
the candidate root was
`a7c4b6fc6761c0a312a00f882d700e16bab78de3ac98ca2894469eeb9c4c01eb`.
The manually written control receipt does not prove an agent consumed a
directive, executed a task, or earned acceptance. The control establishes
queue-level persistence and one-result behavior across a second session
claim and repeat reap only.

## Independent proof-ticket metric check

The newest shared proof-ticket baseline was `origin/main`
`52bee3bb8c719de149512ea9fdebe94b239cdf2a`. On the combined tree,
`nice -n 19 ionice -c3 make CC=gcc -j2 t-fast ONLY=proof_ticket` passed its two
registered synthetic groups with zero skips. Log SHA-256:
`5fcca9373bb34b84b49944f215afe6752ed92f63574985d27785883036fb7ae1`.
The six-candidate fixture reported 1,200 obligations, 889 reused proofs,
311 fresh proofs, 99.66% reuse of unchanged obligations, zero false hits,
299,536 modeled delta bytes versus 1,338,496 full-log bytes, and
`verify_cpu_us_total=39741`. These are deterministic in-process fixture
counts and bytes, not observed network savings or real runner proof seconds.

The CPU label is **RED**. The test source SHA-256
`c6870acf3e959db1dc8fc9c3aa72a638acbebce5b27f346ea4e2fa4380839d87`
accumulates `platform_time_monotonic_us()` differences around each decision;
the fixture source SHA-256
`5a6ca31296494fb2fecab00520a2a0509c716555c0732eea99eed76cb2f119e7`
does the same around checkpoint sync. Their sum is printed as
`verify_cpu_us_total`. Monotonic elapsed time includes waits. An independent
strict C23 clock control slept for 100 ms and reported 100,107 µs elapsed
versus 20 µs process CPU. Its source SHA-256 is
`6946013d1a0923ee4c65827f9d6c9a366341d232155b77c43f3bdec1d7a98b98`;
its output SHA-256 is
`c4ba0a479f8269287f0f1266113b24876259f6c4944838b8ae327cd87594ac97`.
The executable control uses `CLOCK_MONOTONIC`,
`CLOCK_PROCESS_CPUTIME_ID`, and `nanosleep`; its source remains in the
isolated `test-tmp/proof-clock-probe.0T8e0u/clock_probe.c` fixture.

The smallest owner correction is to label the existing sum as elapsed wall
microseconds and sample process CPU separately if a CPU claim is required.
Fleet mail receipt 724 routes the exact source and measurement roots to the
proof-ticket owner; receipt 725 informs the director. Functional reuse tests
passing do not qualify a live speedup: runners do not emit these tickets and
the fixture does not provide a separate-uid verifier.

## Current-main qualification and laptop resource boundary

`origin/main` advanced to `8e80d08cc6049d356c570aa2ba44f471579560fe`.
The queue branch integrated it at signed commit
`738abc3ef1ec7709d5ddf779901c43f32789b6cd`; the generated capability
inventory was regenerated on the combined source. Main now runs
landing-proof test groups cold until a verifier outside the candidate's trust
domain can sign eligible verdicts. This closes admission of same-uid planted
PASS records, but it is not a measured proof throughput gain. The fixed
mixed-100 cohort still has zero DEV and zero full acceptances, so the
cost-weighted accepted-output ranking remains undefined.

Two independent Linux C23 hot-swap fixtures on base `52bee3bb8` demonstrate
that the prior depfile alone is not the exact include-resolution closure. A
new `__has_include` header and a new header earlier in the `-I` search path
both returned the old object from cache with zero compiler processes. The
two-case registered group log SHA-256 is
`6e8680b09db81172cb9323e3474d5705af03a6006c1a3cb36f555378d6a16e28`;
the signed local RED evidence commit is
`035c74770e00157df6661cdcbe763eb980b37aef`. The builder was not
changed, and this deliberately failing fixture was not pushed. Fleet mail
receipts 727, 731, 732 and 734 route the measurements and complete-closure
requirement to the director. The fixture and artifact roots are recorded in
`docs/experiments/2026-09-25-hotswap-optional-header.md` <!-- doc-path-ok: unpushed signed evidence branch --> in that isolated
worktree.

An isolated receiver fixture on the same base found a separate lost-reply
path: a queue row persisted while mail-post failed, but the old receiver
advanced its answered marker and intake cursor. An exact retry produced no
acceptance reply. Its failing required-behavior log SHA-256 is
`b3dce4495b0ecf2fcd1b7dd7340582922498ad8c5a91c4b25bec3554743c7059`.
The signed local receiver fix `166f07103d6db42075d6d351521687c22a229662`
keeps the row replayable until the reply is durable; focused test log SHA-256
`ad95910e7cf88c6a217c377845401fad7abbc5cb4a22a25d5cbf887820d34581`
passed before its final revocation fixture and upstream merge. A later
revocation control showed one historical queued row and a current-grant
refusal, with no worker run; log SHA-256
`286c1a23422cdf2827f4ac967e96b93f354360c5873e0e4f882901482d071aa7`.
The reply does not disclose the historical queue row, so receipt consistency
remains unresolved. Fleet mail receipts 728, 730 and 733 carry those distinct
claims. Full lint and normal landing remain unverified.

Two bounded full-lint attempts on the laptop were stopped to preserve
operator responsiveness. The first parent used `make -j2 lint`, but a nested
build-epoch selftest launched `make -j8 windows-acceptance-compile`; CPU PSI
`some avg10` reached 31.54%. The partial log SHA-256 is
`14457e8e2a036e15d2716dd42fcc158b7f64296e9de54fcaf397998e49f51dac`.
A retry confined to two CPUs still reached CPU PSI `some avg10=75.62%`; its
partial log SHA-256 is
`e7e4f05e1956e963e004c99a06a662096e5f4dd4bf5ec40544ac8bc22d648733`.
Neither interrupted run has a lint verdict. Fleet mail receipts 735 and 736
route the nested-concurrency loss to the build/lint owner. A consenting
development route named `rhett2` passed a bounded command and exact small
object transfer in both directions. An exact Git bundle established an isolated
remote checkout of receiver candidate
`7b4225988f366ef6cc2735fc143a1aa5c2674732`, tree
`bf33c79938a440f70517cb7b14b210423d376e38`; its source and generated
inventory roots matched the local candidate. Clang 18.1.3 compilation refused
46 unchanged zero-variadic-argument `LOG_FAIL` calls under
`-Werror,-Wgnu-zero-variadic-macro-arguments`. The full remote log SHA-256 is
`bf245fddd8768bcb64acc76173e8f428630391c6c154f3c5b014ad3282031831`.
This is a base portability failure, not a receiver-specific lint verdict.
Fleet mail receipt 739 routes the exact blocker to the director.

On the same isolated exact tree, GCC 14.2 initially reported 212 passed, one
failed, zero skipped lint gates. The sole failure was
`check-git-hooks-installed`, because the fresh remote checkout did not yet
have its checkout-local hooks configured. That log has SHA-256
`e6ac2d341182859dc1dece114fe4511dbf81b8c9ada6dfff3d4c5778f3a65cae`.
After `make CC=gcc-14 install-hooks` in only that checkout, the complete
`make CC=gcc-14 -j4 lint` run passed 213/213 gates with zero skips and exit
status zero. Its complete log SHA-256 is
`28e813d1dcdf25181184660aa0bc6e7d71b38100c974888eece531fd9140c26e`;
shell wall time was 98.20 seconds, user CPU 476.28 seconds, system CPU
218.84 seconds, and maximum resident set 451,072 KiB. The checkout HEAD,
tree and working status were unchanged afterward. This is a remote development
lint result for the receiver candidate. It does not qualify a three-host app
journey, proof acceptance, publication, or release. Fleet mail receipt 741
routes the earlier remote lint wall-time bottleneck to the director.

## Shadow-selection and acceptance denominator at current main

`origin/main` `4bae4a290230eb9d1de05f57bfa32e04d072e4f5` added the
shadow obligation selector. Its experiment note SHA-256 is
`1581808bbfe03a92339a1eb2b16b58765d3a2deaa6b1d045b5a3af5680327136`;
the frozen corpus, prediction, bounded observation, and historical weights
have SHA-256 roots
`f0664990375336edd2fbac8392ff8f9ea4ce873bdb11d7bff5d14f5d08feeadd`,
`0f5b5ff438c15a790aa4ab3d77066b89495a9f26b3fdcceb65047bd16e3f25b7`,
`3a639d37c8a29bf7d45339058c0e6d205a450d41a88296cdefed9f0e6920af2b`,
and
`6cfe874076acbaba8565e24bdd50d7a589f1ea1a614065a54c15955333157e0e`
respectively. The report's 6,402.1 versus 3,145.7 seconds per candidate is
a cost-weighted counterfactual from historical obligation weights. It is not
observed saved proof time. The selector admits zero reused obligations today
because execution input closure and independently signed verdicts are
missing; its eligible bill remains 6,402.1 weighted seconds per candidate.
The 28-entry fixture has bounded observations only, no full-catalog reference
run and no edit-to-remote-acceptance association.

An independent bounded C23 harness against landed comparator source SHA-256
`f0389f582d61bf5d7c22eb29921c6c8e913e5d2acb15c8253e995e0abf584d2c`
put a failing observation outside the predicted set. The comparator reported
RED while that row was present, then GREEN when it was omitted or relabeled
PASS with an arbitrary evidence string. Harness source SHA-256 is
`3c2e139a1aa54180cc26def801d58e805c322555e5178ae65017c512e1b7db2e`;
output log SHA-256 is
`8655c3f224ba49a20dccf272e04f17f7d787403482f571b29f56e78cd5fd7568`.
This is a shadow-report coverage counterexample, not a production admission
failure. The report must keep the observation universe and signature status
explicit before a GREEN label can be read as more than a bounded comparison.
Fleet mail receipts 752–754 route the exact metrology and counterexample.

The requested cost-weighted accepted-output-loss ranking is still
**undefined**: the frozen 100-edit workload has zero DEV and zero full
acceptances, and the current queue and land rows have no authenticated
candidate-to-action-to-remote-receipt association. The table below ranks
measurement prerequisites by their effect on the ability to compute that
denominator. Wall costs belong to different cohorts and must not be summed or
divided by accepted lines.

| Priority for attribution | Exact observed loss or gap | Smallest next measurement | Owner boundary |
| --- | --- | --- | --- |
| 1. Accepted-output association | Frozen 100: 0 DEV/100 and 0 full/100; queue 24 and land 326 rows lack task and candidate roots | One signed exact task, candidate, action, proof, publication and remote-SHA join with retained novel C23 and reversion counts | Canonical lifecycle owner; the queue's read-time hashes cannot authenticate a historical candidate |
| 2. Actual proof service state | Four historical attempts: 1,302.345 s service and 368.747 s queue wait; shadow reuse eligible now: zero | Sample process CPU, child wait, log-silence age and fresh/reused proof seconds on the same exact attempts | Proof runner owner; `idle_ms` is last-log-progress age |
| 3. Factory reproduction wall | Frozen mixed-100: 396.966 s of 497.373 s in two-store commit and reproduction, with no accepted output | Run one exact app candidate through independent reproduction and a receiver acceptance receipt | Commons lifecycle and app owner |
| 4. Local gate resource oversubscription | Nested `make -j8` under local `make -j2 lint` reached CPU PSI 31.54%; later two-CPU attempt reached 75.62% | Bound child concurrency and compare full-gate wall, CPU, PSI and node health on one fixed candidate | Build/lint owner; no heavy laptop retry |

The single highest-leverage prerequisite is the authenticated lifecycle join
in row 1. It does not by itself save compute; it makes the acceptance
denominator and a later cost-weighted ranking measurable. The largest
measured wall share inside the separate frozen mixed-100 cohort remains the
two-store commit and reproduction stage at 79.8%. Neither observation is a
claim of increased accepted changes per day.

An independent read of the native objects on main
`4bae4a290230eb9d1de05f57bfa32e04d072e4f5` located the **first missing
edge** at queue attempt to canonical task/action. Main's queue source SHA-256
`28d7798bfe0e487e9e23e8810c23a549f26d6c5b6cedcad470371c6a9fde2a12`
records name, attempt, model, state and usage in unsigned rows. The retained
local `queue.jsonl` is empty (SHA-256
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`);
the `outcomes.jsonl` SHA-256 is
`27ebb89c2d4e88c258a3ddf134ca6ba32e14e2dd0f4366b5804e494dca7e1a60`.
Its refused `portable-proof-prerequisites` attempt 1 has no join root.
Downstream signed work, proof, publication and remote-receipt objects bind
their later edges, but none authenticates the earlier queue attempt. A
signed CAS attempt-to-task/action binding at claim or admission, exposed as a
locator in the queue outcome and verified by the receiver, is the smallest
honest insertion point. Adding an unsigned field alone would not close the
edge. Fleet mail receipt 757 routes this finding to the factory director.

## Latest reflex and cache qualification

At `origin/main` `e1cbb7fe4a997c6671857f38f8d0638dc36f091b`, the
committed 31-edit vault-core reflex ledgers have SHA-256 roots
`1dd821707adee444afd6299ad71f689d2ec066088a288d579f2a29fac97e8cdd`
before and
`67cb22d9e4b2519199379e2138a69c2fd8cf075e50308ca2fa7a6afd904d6199`
after. Warm visible-reply p95 fell from 384.098 to 166.909 ms on that bounded
workload. The post run ends with 31 `PROOF_PENDING` events, not complete proof
or accepted output. Its 10.05 to 6.04 seconds watcher-plus-reaped-child CPU
comparison excludes detached proof work. The ledger does not bind its
compiler, CPU model, executable SHA or the newly landed clean zygote source,
so it does not qualify end-to-end throughput or the new runner's speed.
Fleet mail receipts 759 and 762 route the exact observation and missing
full-work measurement.

The same post ledger's `cancellation_to_new_impact` metric has `count=0` and
null quantiles. Its `event_counts` record 31 `PROOF_PENDING` events and no
`SUPERSEDED` event. The committed benchmark script SHA-256 is
`e43a755a9b756ccf65e81c556735c2c1263b17142ebd539886ebcb6804c07b50`;
its acceptance expression explicitly requires
`cancellation_to_new_impact.count==0`. Thus this run does not measure a new
edit arriving while an older proof is active or a watcher reconnect replay.
The bounded next experiment is to hold proof A after `PROOF_PENDING`, save edit
B, measure B's `IMPACT_READY` and story response before releasing A, then
restart and replay the watcher cursor while checking unique sealed events and
one terminal receipt per epoch. `SUPERSEDED` is required only if the measured
overlap follows the code path that emits it. CPU, child wait, log-silence age,
and cancellation-to-B-impact wall time need separate observations. Fleet mail
receipt 770 routes this coverage gap to the factory director.

The clean runner source SHA-256 is
`c2bd169ea69b5b0746f53f97212550989387d624ba7a71b63054fe22a4d0f086`.
Its child retains the report-pipe descriptor while mapping candidate code;
the runner collects the first report-sized bytes and discards surplus bytes.
A bounded C23 pipe witness returned `report_complete=1` and stored GREEN
while the actual verdict was RED. Fixture source SHA-256 is
`dd63ad9a0f7b9414a5fd9794981823f7d86fb64b371e01d44806957d45b87367`;
output log SHA-256 is
`e353c224ea406aebdcc4664b4becb48900dccef8eea57c28230307e133da0354`.
This copies the collector statements; it did not run the production runner or
produce a candidate or independent observer root. A production GREEN forgery
is therefore unproven. The candidate-writable report channel is a source
boundary for the reflex owner to close before treating the story report as
independent evidence. Fleet mail receipts 760 and 761 retain the distinct
source and fixture claims.

The current-main hot-swap builder source SHA-256 is
`9063a19f68d197476e397ae620022012ccd2d9bef04b30e53d475ff22355cfb6`.
A signed isolated RED fixture commit
`0255eaa7cdb2fda26f050e26f5d27fab9887bb86` leaves that builder
untouched. Its registered shard failed 1/1 with zero skips: both a newly
present `__has_include` header and a same-name header appearing earlier in
`-I` reused stale objects with zero compiler processes. A separate registered
path-identity witness passed in 73 ms: equal preprocessed text can yield
different debug-object bytes when resolved header paths differ. The final
group log SHA-256 is
`3b8a72e2391ae4fdb8247c70de185fbdaaf1feafb75feab46a565fee7562b9f2`.
The exact fixture and retained artifact roots are in
`docs/experiments/2026-09-25-hotswap-optional-header.md` <!-- doc-path-ok: signed isolated evidence branch -->.

A second bounded GCC 16 C23 control changed only `app.gcda` under
`-fprofile-use`. Source, preprocessed output and depfile remained identical;
object SHA-256 changed from
`75705316a21ff5e5fd6fe9670e6565341d63b8ccb4a9113a6f3d43ef6f2d4591`
to `ddd2415965472e4fa6231f401d182ec05fc01eb005ef41f80f1f08a742b06f27`.
Its outcome log SHA-256 is
`bfd86a91e07d9f04c277b0c1761a7aed0c1e88b22af6c132c406abc6035236e0`.
Thus a preprocessor-plus-depfile cache key is still incomplete for arbitrary
accepted compiler flags. The attempted fix's own focused gate was RED; its
patch remains unlanded. The builder's primary writer must bind or refuse
external code-generation inputs before exact-object reuse can be claimed.
Fleet mail receipts 758, 764 and 765 route ownership and the counterexamples.

## Current local outcome coverage

On 2026-09-25, the owner-private queue outcome projection had 12
rows (10 refused, two failed), SHA-256
`27ebb89c2d4e88c258a3ddf134ca6ba32e14e2dd0f4366b5804e494dca7e1a60`.
The separate land outcome projection had 49 rows (21 landed, 17 cancelled,
seven failed, four conflict), SHA-256
`84ab1c6f8a9a55f76c41751f8c21aa73bb91597b7c441e29a0f1c748db63af03`.
No row in either file has a `task_root`, `candidate_root`, `action_root`,
`proof_root`, `publication_root`, or `remote_receipt_root` key: action-root
coverage is **0/61 outcome rows** in these two current projections. A
`landed` Git tip is not an accepted C23 change or proof of a queue-to-task
join. These 61 current rows are a different local cohort from the 24 queue
and 326 land rows in the earlier frozen audit; the counts are not additive.

## SkyCombat lifecycle lookup

The owner-approved SkyCombat preview remains separate from canonical lifecycle
acceptance. A bounded native `zcode tasks` query against the frozen
`apps/skycombat` workspace returned `tasks_scanned=0`,
`candidates_scanned=0`, and `total_matches=0` under
`REBUILT_CAS_TASK_PROJECTION` in 90 µs. The exact query output SHA-256 is
`346c4470b0b8842eb49a03cab06b7124843259125abe5d739e26781ac6d90c3e`;
the querying `z23-dev` executable SHA-256 is
`dc7bb62d731ef2c074efc8f788ad641b20b7354e8967d63f3b4c9f921639fdee`.
This result covers that workspace's local CAS only. It does not establish
absence on another node.

```sh
"$Z23_ROOT_DEV_BIN" zcode tasks \
  --input='{"workspace":"'"$Z23_SKYCOMBAT_WORKSPACE"'","details":true}'
```
<!-- doc-path-ok: frozen isolated SkyCombat workspace and measured executable -->

The source commit is `255990bfdc48e0c7e6f966aa2e8d6e678b25ca40`, tree
`5688c2a49474d6ff91e56aba378471cead0db7dc`, and complete game archive
SHA-256 `56b4ebc8d6fbbb9ec351a164512aa1a55c4ce0c8364a867716ee1f1a9670f165`.
The previously accepted local preview binary and frame have SHA-256 roots
`9a7a46565f2414bd8ccb5c9ee6ebb7c60b951ea690177f958123993091e4082c`
and `38fd50456fb394a84df18956cc2d13cc56daf55163f0caa560f82a1b309873e4`.
The first absent canonical object is `task.v1`: zero task-to-candidate,
candidate-to-proof, proof-to-publication, and publication-to-remote-receipt
edges can be verified for this workspace. The SkyCombat/Commons candidate
owner must start one new scoped change through the existing work authority
and bind its candidate to that task. The earlier preview remains its own
observation; a later task does not retroactively authenticate it. Fleet mail
receipt 773 routes the exact missing object; no task or acceptance was created
by this lookup.

An independent bounded preflight on the same frozen workspace returned
`INITIALIZATION_REQUIRED` with an empty `work_id` and
`authoritative_workspace=unchanged` from `zcode work start`; output SHA-256
`cce780371b21f5abaf4b30356196fb4597cc7987e4ad96f532c40963c30120a1`,
query binary SHA-256
`5e50f20d15e361ed0f1d6870d74fda4a898574cd9e228b4d29a5c082112d8164`.
The instructed `zcode project init plan` refused with
`PROJECT_INIT_PLAN_FAILED`, `LICENSE is required before project
initialization`, and `mutated=false`; output SHA-256
`ac6b93de5fc7c06800341e685a4f543739ddbbea85b17fc9e03e894c86e8d562`.
The repository root has `LICENSE`, while the `apps/skycombat` workspace does
not. The package owner must prepare an isolated package-shaped full-game
workspace with its own declared license and source/dependency closure, then
rerun the plan and start a new scoped task. The aircraft component's separate
undeclared-`libm` recipe refusal does not qualify the full game's platform
dependencies. Fleet mail receipt 775 routes this precise preflight blocker.
The measured preflight predates the isolated `datadir` input shown below; the
revised command is a safe rerun template and is not claimed to reproduce the
historical output byte-for-byte.

```sh
build/bin/z23-dev zcode work start --input='{"workspace":"'"$Z23_SKYCOMBAT_WORKSPACE"'","datadir":"'"$Z23_ISOLATED_DATADIR"'","goal":"Qualify exact full-game C23 candidate and declared platform dependencies","operation":"plan","profile":"standard","details":true}'
build/bin/z23-dev zcode project init plan \
  --input='{"workspace":"'"$Z23_SKYCOMBAT_WORKSPACE"'"}'
```
<!-- doc-path-ok: frozen isolated SkyCombat preflight workspace -->

The old demo source compile failure is fixed in current source SHA-256
`0f767ecb000bd289e86513b859c51467c48cd13e08cbfd5a7480d69626935305`;
the recorded `game-check` PASS belongs to an earlier tree and was not rerun
on current main.

The 154-file isolated package copy preserved the archived source bytes but
changed their package paths; its copied-file manifest SHA-256 is
`bc1348f443a5eb34e831bd6089a572e9f9225f46fa8651994af815dab640a605`.
With a root `LICENSE`, `zcode project init plan` then reached response
serialization and refused `RESPONSE_BUDGET_EXCEEDED` under its unchanged
4096-byte limit (output SHA-256
`2c0e9f184ce19cfc7476ab0103f6ce8c17a45d37ee4128dc912f75f798f6c196`).
An isolated, signed response-boundedness fix at combined-tree commit
`7759b124229bd8036a758600953ac175120c45f9` returns a 1174-byte
read-only plan (output SHA-256
`db717ea47724c0882d2b491eb7ba522bbd49d2839623b9caa466d18328de44db`)
with plan ID
`69919e4bc9a330ff3de9eaabc21bae352e5ef7eaee5bd2fdc59e413cef59e337`
and pre-initialization source root
`5ded3a309d0f91b1bfc4b61eadde59de4bec9daadeff3bf2c0a400b3d1277810`.
The shortened layout declares `complete:false` and exact counts. A registered
150-source case went RED then PASS 1/1 with zero skips; combined-tree focused
`zcode_package_dev` and `dev_shadow_select` each passed 1/1, lint preflight
passed 5/5, and `lint-fast` passed. The signed experiment note SHA-256 is
`2b4f663d266f8a143653443798e4daa010190d6f4e02b40b8ba8074852f6474a`.
This fix is **local and unlanded**: exact `dev proof status` returned
`data.status=missing`, the checkout's native pre-push hook was initially
absent and then installed, and `devbuild` was unavailable locally. No normal
push or remote receipt exists.
The plan reports `programs_count=0`, so it does not qualify a runnable game.
Fleet mail receipts 779, 780 and 782 carry the owner claim, local result and
proof blocker.

An isolated continuation moved the byte-identical game entry source
`src/sky_combat_multiplayer_ultimate.c` to `app/main.c` in a copy of that
package tree. Both source-file SHA-256 values were
`fd9ed527f3e027c192eadb2c0134e689ae33dbc6cb421d8b94da445cc25d2dbf`.
The changed path makes this a new fixture source root, not the frozen archive.
At signed project-init branch `9b8c6005167c689c13e5aaa6b8df3a93ca549cfe`,
the read-only plan passed in 48.501 ms with `programs_count=1`,
`sources_count=57`, `allowed_libraries_count=0`, and `complete:false`.
Its output SHA-256 was
`9e2fbc3449951d405596468cefa3574490521908fc508694ee2cd0ad6935a25b`;
plan ID `ac70a222de99662b84bbb291d191451fd4a5b74f6d296ce08289b57b4c16d6d7`
binds pre-init source root
`41aac10752f0412a75ec42a64e0fa796ddd5e783097a85f9559e4a313e2dde51`.
An isolated `zcode project init commit` of that exact plan created
`zcode-package.json` (file SHA-256
`528aeddbfd9df1096a93d9db661a051f7fc6b1cdf210a4e6803d815d9bbfc9ce`),
and `zcode project status` reported package root
`be5a939989cd1e2da1fd30bca2756f7c512a63b9ac6200cf51d51769973734e6`.
Neither plan nor metadata commit built or previewed the game.

One real SkyCombat startup-error goal then entered `zcode work start`
`operation=plan` in that isolated package workspace. It produced canonical
task root `480f41a9c02a0af158e4e284d734d568828b573555dcf8082b719fb4e342ed28`
and work ID `work-480f41a9c02a` with `state=AWAITING_CANDIDATE`.
The task response SHA-256 was
`2bbf1935da3d6448b05440c8bb9756a64514193e128ab3d20897e290fae45afd`;
it took 1.990009 s against a 750 ms command budget and reported
`budget_exceeded=true`. A separate native CAS projection returned one task,
zero candidates and zero receipts (output SHA-256
`9c5ed4c8af202f095a91ad843ac199a7a8df8c2e0156e959552756b669eef684`).
The planner selected `Aircraft` from one context file for a startup-error
goal; relevance to the requested startup behavior is unproven. This is one
verified task edge in an isolated fixture, not candidate, proof, DEV
acceptance, publication, or remote acceptance. The 1.990009 s plan latency
is a measured local feedback bottleneck, while the absent declared game
libraries remain a build-closure question.

Repeating the identical `zcode work start` input on the same workspace
returned `ACTIVE_TASK_CONFLICT` / `DUPLICATE_ACTIVE_WORK` after 307.369 ms
(output SHA-256
`ac55c1e2b58e89d9673009f5801c540415c3d09052d8ce7f5dd79f14259f456f`).
It named the same task root and said admission stopped before task/context
persistence; its generic error envelope nevertheless reported `mutated:true`.
A new CAS projection still showed one task and zero candidates or receipts
(output SHA-256
`6cf6742b83a4a1ad16374b47c6a450c3c1b5bc111a7aa03bf60824cb453bf8ba`).
This supports one avoided duplicate task record, not avoided execution or
proof. The `mutated:true` versus stopped-before-persistence tension remains
visible until the command owner identifies which local side effect it denotes.

The task's manual adapter returned a candidate workspace in 27.278 ms
(handoff output SHA-256
`0ccbce353b17a8296f4cccac69f61ce250a0da079cb24b256def4c93579321dc`),
without a candidate CAS record. Its 4303-byte packet selected
`src/philosophical_test.c` for this display-startup goal, although the entry
point is `app/main.c`. In that isolated candidate, a compile-valid
`IsWindowReady()` check after `InitWindow()` could not handle a missing X11
display: the exact linked candidate binary SHA-256
`79edb91b53a84542af0b45602a04508c4a16f6f35e06b87756a954f7c638c57b`
exited by SIGSEGV (139) before reaching the check. Its no-display log SHA-256
was `22f016099a196e5673db4a2fb43dc7d7afbfe367d29f428d8b1ee61d711e42c3`.
The candidate was compiled with GCC C23, `-Wall -Wextra -Werror -pedantic`
and the game's declared flags, then linked against the frozen game's existing
object closure and vendored raylib archive. This is an executable
counterexample to the proposed startup behavior, not package proof.

A second isolated candidate added a Linux `DISPLAY` presence check before
`InitWindow()`. It built as binary SHA-256
`a218ba237498c32368e444af4a4d7e9399d87ca0a4621224ad54a8ab34d935bd`.
With `DISPLAY` absent it exited 1 with a clear error (log SHA-256
`ff19c274ccae5d36bb64ee74eada57be2ead7ed41e4b0b0b3bad804b368b080c`);
with `DISPLAY=:9999` it still exited 139 (log SHA-256
`22f016099a196e5673db4a2fb43dc7d7afbfe367d29f428d8b1ee61d711e42c3`).
The source SHA-256 of this second candidate is
`535cdfa6d1b6c4294db2d3f04ea83e565ec1096e45af3c012f2301898dec8cf3`.
No candidate was admitted: the broad requested behavior is RED, and the
native package plan still declares no platform libraries. The game owner
needs a bounded backend display-failure path or a safe platform preflight
before the exact candidate can proceed.

The isolated executable counterexample script SHA-256 is
`699013d16cf4145573ed3de374e4e97b559e36a8b7d8dfd9d83dc836649d3f88`.
It checks the rooted second binary and requires exit 1 plus a clear error
with no `DISPLAY`, then exit 139 with `DISPLAY=:9999`:

```sh
cd "$Z23_QUAL_WORKTREE"
test-tmp/skycombat-display-counterexample.sh test-tmp/skycombat-candidate
```
<!-- doc-path-ok: isolated qualification script and binary are outside the tracked source tree -->

GDB localized the invalid-display SIGSEGV to
`RGFW_initPlatform_X11 → RGFW_init_ptr → InitPlatform → InitWindow → main`
(backtrace SHA-256
`dc9bd82619c1f2bd3b03d6b5f630524b60273e2ae1b2c5011729a7b95f4db03b`).
The vendored RGFW assigns `XOpenDisplay(0)` to its display pointer, then
passes that pointer to X11 calls without a null check. Its caller continues
mouse and monitor setup after a nonzero platform result, and window creation
does not check the implicit initialization result. The raylib platform
adapter also calls size and swap functions before testing its window pointer.
The game entry point cannot repair this by checking `IsWindowReady()` after
`InitWindow()`. A backend fix must propagate display-open failure through
these layers and test both absent and invalid `DISPLAY`; fleet mail receipt
789 routes this smallest fix to the game/vendor owner.

## Fresh-main proof and reuse audit

At `origin/main` `07b0d7408a738b5a6c94d1d45de6b26d99849797`, an
independent read-only audit found that the signed proof receipt binds exact
source/build roots, selected/ran/reused dimension counts, and total elapsed
time, but not active CPU or child wait. `phases.txt` carries step wall time
and `last_progress_age_ms`; that field derives from log progress and is not
CPU idle. The proof budget source SHA-256 was
`36f955a9febb8ab303ee149401004f11a3d2ad2879889791ae8990a0687d7e9a`;
the native status adapter SHA-256 was
`acf2afea39b4fe40184cf57783bd854e9ccada73af153607e83000bc881d8a4a`.
The proof runner already computes `request_age_s` for unclaimed requests, but
the status adapter omits it. Sampling at `zcl_dev_proof_step_poll` could
separate process-tree CPU, child wait/I/O, wall and log silence per attempt;
direct-child `wait4` usage alone would miss grandchildren. No proof attempt
was launched for this audit. Fleet mail receipt 790 carries the request to
the proof-runner owner.

The newest lint premise selector remains a shadow prediction with zero
eligible inherited verdicts. A bounded C23 `realpath` fixture SHA-256
`a707bf24cd7ac8d56775bfaa2209796802b412ce47a968e70839008c0d07b773`
was rejected at `-O0` and accepted at `-O2` under its base flags; adding
`-D_DEFAULT_SOURCE` through external compiler arguments made both pass.
The four-result artifact SHA-256 was
`5de72a99d9ed4440baace33df4f167a60b31d6846cf1b2357640891d7385ae80`;
the executable reproducer SHA-256 was
`596eb96ceaa09f57acff1d57263e36111d80cfd31e638a88f794008571054601`.
The gate derives its masked declarations from live compiler arguments, while
the premise hashes an absent toolchain pin and no live compiler argv. This
falsifies a proposed shadow inheritance under compiler-argument drift, not
an enabled admission decision or a full-gate verdict. The owner must bind a
verified compiler, arguments and toolchain closure before enabling it, or
refuse inheritance. Fleet mail receipt 791 carries these roots.

The consenting development peers now have bounded command and exact-object
transfer qualified in both directions. For the newly qualified Peer 1 to
Peer 2 leg, a pre-trusted public ED25519 known-hosts entry SHA-256
`275cf3c9d5b848a5ea444e4ce3e5bc82dc60799195f2d8906987066f39a8559b`
was copied byte-identically into a temporary file; transfer log SHA-256
`ed87f75fc4232e9f6f25e7c694cd83d9e7b14b7216564dc189419b360d63c106`.
Strict bounded command log SHA-256 was
`728b392a299dc0b3ebda44fd8a8e270cecbf6de95eaf5f2f920af087acba6210`.
A 9213-byte signed experiment note crossed that leg and returned to the
local host byte-identical at SHA-256
`5454641d272942210c03c28071fd462d1465651acb3017d21eb521f415a1826e`;
peer transfer log SHA-256 was
`7372f253244b2804421b84f638b75230593dd86d7f57f607d45a93dac4ad0e74`.
Temporary peer objects and public known-hosts file were removed. The local
laptop still has no independently reachable reverse command, so the full
three-host route remains unqualified. Neither peer has an approved
`devbuild` broker; no proof was dispatched. Fleet mail receipt 792 carries
the corrected pair-route qualification.

## Local fleet-mail observation boundary

The `dev agent mail` posts cited above are local outbox sequence numbers,
not consumed acknowledgements or peer delivery. A read-only pull for
`from=factory-director` after sequence 769 returned zero rows and named only
the local outbox as a source (output SHA-256
`18328de76e9ecc46e91407042063e3eb6ec61307a4ff745d95388b9bb821f35a`).
The host has no `z23-mail-carry` user unit installed (unit-list SHA-256
`6c726eb11af56ec765d2f2588fafa18a379b4c3c20489d46150d2afbdcfc8143`),
and its status is inactive (SHA-256
`e4235e9151696cad6c6efc96dcb096da88635642731f70b27ce63936afa811d1`).
The native `fleet board status` refused `NODE_UNAVAILABLE` (output SHA-256
`296156c82ee3c9c96c907cbeb3bccf002af0f3b7deee5c87aff3ad8c64f5ffe7`);
`z23-dev status` found zero live local instances. The in-tree boardmail
carrier needs an enrolled local node RPC and receiver grant; none was
started or borrowed from a production datadir for this experiment. Thus
directive → consumed acknowledgement → result is unproven on this host.
This is a coordination observation, not proof that any particular peer
never received a post by another route.

## Frozen SkyCombat plan cost and task identity

On 2026-09-25T17:44:40Z, the same SkyCombat package bytes and display-error
goal were planned in a fresh isolated workspace with GCC 16.1.1 on an
AMD Ryzen 7 PRO 8840U. The task command reported 1.984352 s against its
750 ms budget. A C23 `wait4` wrapper measured 2.081526 s wall,
0.408448 s direct-child user CPU, 0.208626 s direct-child system CPU,
0 input blocks, 66,688 output blocks, and 65,892 KiB peak resident memory.
The combined command-and-measurement artifact SHA-256 is
`8efb381023debd2bc362e74f8ade68b247b93a51c46b5c0d551c6fad5eb1887c`;
the wrapper source SHA-256 is
`9627ce18d2dd0df7b6cec19e751201289d0d162ab614762c581b4c91844865e4`.
`wait4` measures the direct child only. Wall minus direct-child CPU is not a
measurement of child wait or process-tree idle time.

The original and fresh task roots were
`480f41a9c02a0af158e4e284d734d568828b573555dcf8082b719fb4e342ed28`
and `b2513f8cdd806121d999090d236244ea58b2add01eba3c32e6122f4be1a57f40`.
Their 318-byte task wires had SHA-256
`8ec573cb95765dc65f2bce4b53da5fc4f1971e8def47fe6d9ed86672f43251a8`
and `5058741f119d90c7a8a0074a193ce78588d581626c8d498e5474f15bd80a005b`.
`cmp -l` found differences only at one-based offsets 311–313, within
`expires_unix`: `0x6ab7debf` versus `0x6ab80488`, 9,673 seconds apart.
The source, dependency, toolchain, write scope, acceptance tests, policy,
model, goal and task limits match byte-for-byte. The agent-context wire
includes the task root, so its root also changed even though the selected
symbol, source-tree root and excerpt metrics matched. Task roots remain
correct freshness identities; they are not stable keys for deduplicating
this same source-and-goal obligation across independently timed requests.
Any cross-task reuse would need a separately verified obligation identity
that preserves expiry and current-policy checks. No proof was reused or
candidate accepted in this measurement.

The operator's directive was appended to the local fleet-mail outbox at
sequence 793 with ref `ooda-north-star-20260925`. This is not a consumed
acknowledgement under the observation boundary above.

## Cold planning storage state

A second byte-identical isolated SkyCombat copy had no `.zvcs` or
`.codeindex` before planning. A Linux-only C23 sampler polled the direct
command process's `/proc` state and I/O counters every 10 ms while `wait4`
collected final direct-child resource usage. Its source SHA-256 is
`9b5e06bb03fe0dbbf4e345690131cc4a69a6392ea7a6d16ce0a7f8b146aad596`;
it compiled with GCC 16.1.1, `-std=c23 -Wall -Wextra -Werror -pedantic -O2`.
The source and package configuration matched the prior copy byte-for-byte.

The first `zcode work start` returned a new task rooted at
`8356fe406a8a83205d9bfee7fbe6e03f2eb8352be11d2f08a842a69596edc2b6`,
with the same source root
`bda7c07253a591f0c03a0e7b9d191620139ffe20ad04a6458f312c39b1781b24`.
It took 2.038930 s wall, 0.383214 s direct-child user CPU and 0.187986 s
direct-child system CPU. The 201 process-state samples were 67 runnable,
5 interruptible sleep, and 129 uninterruptible `D` state. `/proc` reported
34,439,168 bytes written, 0 bytes read from storage, 278 write syscalls and
2,738 read syscalls; `wait4` reported 67,264 output blocks and 73,252 KiB
peak resident memory. The exact result artifact SHA-256 is
`4363c61dfbc0c119e13b8ec70250567049f22301bbe8c66c9e9eb777d7b6dd54`.
These are sampled state counts, not precise per-phase wait durations. They
measure only the direct process and do not assign every disk write to a
specific source function.

The fresh run populated 163 CAS objects occupying 6.2 MiB and a 1.0 MiB
code index. `vcs_object_put_addressed` publishes each new object through a
flushed temporary file and parent namespace barriers; the source SHA-256 is
`d611fdd88e59eb3326c0cb7f2300bc32c802dd9184aeb3848fd30b723be96b6a`.
The observed write volume and `D` samples make serial durable publication a
specific profiling target, not yet a proved attribution for all 2.04 seconds.
Durability barriers must stay intact until a replacement has an equivalent
crash test.

Repeating the exact goal in that workspace refused `ACTIVE_TASK_CONFLICT`
without new task/context persistence. It took 0.383911 s wall and
0.359716 s direct-child CPU, with 35 runnable, 2 sleep and 1 `D` sample;
`/proc` reported 81,920 bytes written. The repeat artifact SHA-256 is
`027bc372f1ac940e6516f4194756828e2eed62fa0b398114e8118bf72380fae7`.
This is a different admission path, so its latency is not a valid cold-to-warm
speedup ratio. It confirms that duplicate admission was refused without a
second new task. The next bounded experiment should time individual CAS
publication and source-snapshot phases and compare a semantically new task
on cold and preverified object stores; any candidate optimization must retain
the exact durability, freshness and conflict gates.

An isolated copy then imported all 163 CAS objects but no task index or code
index, retaining byte-identical source and package configuration. The next
`work start` correctly refused `ACTIVE_TASK_CONFLICT`, citing the copied task
root `8356fe406a8a83205d9bfee7fbe6e03f2eb8352be11d2f08a842a69596edc2b6`.
It took 0.538016 s wall, 0.428685 s direct-child CPU, 8 of 53 samples in
`D` state, and wrote 2,359,296 bytes. Its result SHA-256 is
`7a1aa1c01d6721412dd3edc0ee753a7d53dc09c5eec9a7061e099e981205ea6b`.
This demonstrates a copied active task was recognized without copying the
task index. It avoids a second task admission in this fixture but cannot
measure the cost of an eligible new task on a warm CAS. No proof execution
occurred, so duplicate proof executions avoided remains zero.

## Receiver restart, revocation and queue-ACK identity

The tracked Linux executable fixture `tools/dev/fixtures/receiver/receive-revoke-replay.sh`
(SHA-256 `2d3afbe0a89d0001b858cb10b68702cf0357c9314e0cfd0f5ef8672e20ffa06d`)
uses only the native `fleet steer`, `dev agent receive`, `dev agent queue`,
and `dev agent mail` leaves against a new private state root and signed,
isolated one-file C23 Git checkout. It ran on the `z23-dev` binary SHA-256
`7c507c056f846a6d50629d5b6cf4dbf3cbb5b51c2f5fcdff05190b66d71c0d68`.
The receiver, steer and queue source files in the checkout containing that
binary are byte-identical to `origin/main`
`07b0d7408a738b5a6c94d1d45de6b26d99849797`
(`git diff --quiet` exit 0); their main-tree SHA-256 values are respectively
`1038bcfb320047335eefcc2ba68d9aca78b77325df0bf6c4d320758a78706e6b`,
`5ec20635e3f52bef808f08c110d3ad7f4f176f58e9f67f2e12f7b2a8851ab0c0`,
and `28d7798bfe0e487e9e23e8810c23a549f26d6c5b6cedcad470371c6a9fde2a12`.
No retained build receipt independently binds this binary to that checkout;
the executable verdict is bound to the binary SHA-256, not a fresh main build.

```sh
cd "$Z23_QUAL_BRANCH"
tools/dev/fixtures/receiver/receive-revoke-replay.sh \
    "$Z23_PREFLIGHT_DEV_BIN" "$Z23_QUAL_SCRATCH"
```
<!-- doc-path-ok: isolated fixture, signer and built binary are outside the tracked source tree -->

The run returned PASS under fixture Git HEAD
`554d1c3b1f8e13d66d5d8022c07fbeaaa4856bb6`.
An independent rerun also returned PASS, with complete command-output SHA-256
`e6ebc82ee83c17d8fd651f48a97276299753cfaf041ceb43f502bdd046117b99`.
The earlier tracked fixture revision (SHA-256
`403da4a3b245edcfb6da546f895cb3b6b769187ecc56c325d2744b0ad8d88b76`)
returned PASS with command-output SHA-256
`af3d600391ca3a799d2a90e69d529d6869e139a9a4f27a08b4ab050b1423a79e`.
The roots below refer to the first run; the rerun's roots are printed in that
command-output artifact. One grant sent a directive;
its same-key retry returned `duplicate:true` at the original send sequence.
A fresh receiver process admitted the directive once into queue sequence 1
and posted a `claim` with `stage=queued`, brief SHA3
`fff23e913f4adcc2389c4d56f41751a670a24b3a24cf7d1e0139b13d5011333a`
and the exact workspace HEAD. Restarting the receiver admitted zero further
rows. Revoking the grant cancelled the queued row, leaving the queue empty;
a send under that revoked grant refused `STEER_GRANT_REVOKED`. A new grant
for the same sender label could send the same ref and body again after
cancellation; the receiver admitted one new queued row.

The two durable claim rows have the same ref, `queue_seq=1`, brief SHA3 and
workspace HEAD, but distinct `src` tags (`a5ed741c729d2358` and
`f9ff6de3fefe5c11`). The claim-row artifact SHA-256 is
`3d1e0d9af61a3bcd707a2d5fb7535c2a7b4ba1c30690da2ace6e8f7fbc2885d9`;
the cancellation and regrant queue-status artifacts SHA-256 are
`5d58bd41e234c2ccb2fede457e737ff8065eea8bcfebefb90954c42900723bb9`
and `636dacde1bfcb63acf236bfa9b2dd5ade2f18be9a71ab7a040c8cea926b76f99`.
The revocation and renewed admission are intended, but they falsify a join
that treats ref plus queue sequence, brief digest or workspace HEAD as a
globally unique work instance. The two mail claims remain visible, while the
per-ref receiver evidence file describes the latest admission. A valid
end-to-end join needs the credential-bound directive observation and receiver
epoch before task/candidate/result roots. These claims prove queue admission,
not agent-session consumption or useful C23 output. Duplicate queue sends
avoided: one; duplicate active queue rows after restart: zero; duplicate
proof executions avoided: zero; accepted novel C23: zero.

The current fixture adds one compile-valid wrong-behavior edit in its own
tracked C23 file (`return 0` to `return 1`, edited file SHA-256
`d73ef92a79f3f70d85c173951403894ff2e9c3558d9941a09a865ead41f0e560`).
It then sends a fresh directive to the same receiver. The receiver returns
`RECEIVE_WORKSPACE_DIRTY` with `dirty-tracked-paths-1` and `refused=1`, does not
create a brief for that directive, and leaves the prior queue count at one.
The earlier dirty-work revision's complete PASS output SHA-256 is
`bb17d27ae449d05e73758882b1e0fdb711503936e29d83be796188ae2e8b8b86`;
the receive and queue status artifacts SHA-256 are
`8d080d2a3fe898150aad3f3691db8f0e1d4d70211ae6577784e4eb285639c2a8`
and `70c9722f99bcb65f5f0f03d8f517681d3fcf0b97a11ff2990eafa8208a162398`.
The fixture compiled the changed source under C23 with `-Wall -Wextra
-Werror -pedantic`; its log records 2026-09-25T18:12:51Z, GCC 16.1.1 and
AMD Ryzen 7 PRO 8840U.
This checks dirty-work takeover refusal at intake, not correctness of a
candidate or a downstream proof.

The current fixture then signs a commit containing that changed file, making
the workspace clean at HEAD
`80c417b8f45b844008850f32881ebdae4e3fa6fd`, and sends a fresh directive
with `muse-sha` pinned to the previous HEAD
`e0a4b89e11586d6c991d7315b4611cb3088e21de`. The receiver refuses
`RECEIVE_WORKSPACE_SHA_MISMATCH` with `refused=1`; the queue remains at one
row and no new brief exists. The current full PASS output SHA-256 is
`460743f3c196d0b258ed0bda3a7df8566490962efd0cfe4cb5c638dab6201c79`;
the stale-receive and queue-status artifacts SHA-256 are
`d026b2e1d447b3c8e1ed9ad22aa6b2b1f21c240a54768eb0e38e186c7c59f332`
and `3e1d11f91dd4e7a049234be3448105e9584c929ccf0d38c85c9827189f6f8c62`.
Its log records 2026-09-25T18:14:49Z, GCC 16.1.1 and AMD Ryzen 7 PRO 8840U.
This is source-identity refusal at receiver intake; it does not establish
proof reuse safety for changed headers, flags, layout or generated inputs.

## Independent hot-swap cache behavior check

The hot-swap lane owns the stale-header fixture and builder. Its signed HEAD
`0255eaa7cdb2fda26f050e26f5d27fab9887bb86` retained two RED cache
objects from the registered `test_dev_platform_shard_06` run on builder source
SHA-256 `9063a19f68d197476e397ae620022012ccd2d9bef04b30e53d475ff22355cfb6`.
The group log SHA-256 is
`3b8a72e2391ae4fdb8247c70de185fbdaaf1feafb75feab46a565fee7562b9f2`.
This lane independently linked those retained objects to a separate C23 probe
and compared them with freshly compiled objects from the retained source and
current header tree. It did not edit or rerun the owner's builder test.

The probe source SHA-256 is
`cfa60e4beffb77d2bc622c7eba21c36f95bacff7742f7b767d10092ef4bf13fd`.
The optional-header and include-shadow fixture sources have SHA-256
`c5e836d578d9e11a602ab92a7d374412b074cc47315b099c89387938d62bdf71`
and `6294b238c13c20be228e5c1be6933e2109e8db455d0e3b12b1f1e7f287f1d28a`.
Both cached object files have SHA-256
`2d01ed9a1cb5e0f1d9237e4dbbe7d80b9ab5fb44b47a8fb475a43469c68fcade`;
both independent fresh objects have SHA-256
`a8744afe7f262d7cea5f49ed719107b59cfc70ba0b19160864c07896ee26a689`.
The newly present optional and earlier shadow headers have SHA-256
`6ed627b3d5ad0b9a278a1aa558c892d0d28892f7a13ef5e5d5a75d77b3bc12c4`.

For each case, linking the cached object printed `1`; linking the fresh
object printed `2`. Cached output SHA-256 is
`4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865`;
fresh output SHA-256 is
`53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3`.
The four executable and output artifacts are retained under
`test-tmp/independent-hotswap/` in the qualification scratch worktree.
The independent object rebuild is reproducible from those retained bytes:

```sh
owner=$Z23_HOTSWAP_SCRATCH
out=$Z23_QUAL_SCRATCH/independent-hotswap
cc -std=c23 -Wall -Wextra -Werror -pedantic -DZCL_DEV_BUILD -fPIC \
    -c "$owner/dev_hotswap_optional_350668/contexts/commons/services/src/zcode_c23_corpus_service.c" \
    -o "$out/optional-rebuild.o"
cc -std=c23 -Wall -Wextra -Werror -pedantic -DZCL_DEV_BUILD -fPIC \
    -I"$owner/dev_hotswap_shadow_350668/include/early" \
    -I"$owner/dev_hotswap_shadow_350668/include/fallback" \
    -c "$owner/dev_hotswap_shadow_350668/contexts/commons/services/src/zcode_c23_corpus_service.c" \
    -o "$out/shadow-rebuild.o"
sha256sum "$out/optional-rebuild.o" "$out/shadow-rebuild.o"
```
<!-- doc-path-ok: retained isolated owner fixture and independent qualification scratch -->

Both rebuilt objects match the independent fresh object SHA-256 above.
GCC 16.1.1 on AMD Ryzen 7 PRO 8840U produced the comparison on
2026-09-25T18:20:38Z. The cached byte identity can therefore preserve
compile-valid wrong behavior when include resolution changes. Eligible
receiver-side reuse for these two obligations is zero. A safe cache lookup
must bind the current resolved input closure, including newly winning headers,
or refuse reuse and rebuild; the owning lane retains the repair and gate.

## Frozen compile-valid flag-drift control

The bounded `tools/dev/fixtures/factory_qualification/toolchain_drift.sh`
control uses one C23 source and four strict builds. It changes only the
compiler argument `-DZCL_FIXTURE_VALUE=1` to `=2` at `-O0` and `-O2`.
All four compile and execute; both baseline outputs are `1`, and both
changed-flag outputs are `2`. This establishes that compiler arguments belong
in an exact action's execution closure even when the source bytes do not
change. It does not claim that the current receiver admitted a stale object.

```sh
tools/dev/fixtures/factory_qualification/toolchain_drift.sh \
    /usr/bin/gcc "$Z23_QUAL_SCRATCH"
```
<!-- doc-path-ok: retained qualification scratch outside the tracked source tree -->

At the original run, the script and source SHA-256 values were
`fd50ce5105f044ec7e064dc7db2f169315806f65783ed29339ab9af4292c47c3`
and `6359bd81590332cd97e32258677b7dbb98a8ec22ade1444e23aa3ecab7414fe3`.
The current source has a purpose comment and SHA-256
`d33b5bc905b52441c2794c5f17cf524b00e7254edfdb28782be2c1b9a6760f4e`;
its repeated four-build control passed with the same output roots (full log
SHA-256 `ea171c386c51baa3afdfb917e7962db768eb1ce9eae8063cc9d23c2bc9a8fa5f`).
The full output log SHA-256 is
`6dfbd34b8e62f875b1c7029569c4620eef3e12773c06c5fa6198d62780da3106`.
The two output-byte SHA-256 values are
`4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865`
for `1` and
`53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3`
for `2`. The retained executable roots and compiler SHA-256
`896eb442ada77eb5d7db92a83ddb234926a46e5fa238e23cc2e190588e5aef01`
are listed in that log. The run used GCC 16.1.1 on AMD Ryzen 7 PRO 8840U
at 2026-09-25T18:26:15Z. The earlier untracked fortify/syntax-only control
remains a separate compiler-argument verdict witness, not part of these
compile-valid output counts.

The frozen qualification cohort is
[`FACTORY_QUALIFICATION_COHORT_20260925.md`](./FACTORY_QUALIFICATION_COHORT_20260925.md).
The receiver fixture also passed when independently rerun against this
worktree's `z23-dev` binary SHA-256
`5e50f20d15e361ed0f1d6870d74fda4a898574cd9e228b4d29a5c082112d8164`.
Its output log SHA-256 is
`ab764e8e5bdd92547515a02b8ac5501816f7194fbb9823b4787243b639cae48d`.
That log records signed fixture heads and the refusal paths. No build receipt
binds this second binary to current main, and its PASS is still intake-only.

## Typed queue and publication projection check

The read-only `dev agent queue status` output from binary SHA-256
`5e50f20d15e361ed0f1d6870d74fda4a898574cd9e228b4d29a5c082112d8164`
has SHA-256
`e5358a4f42f3927435144b5757e7d38268dddf83a694e0c564f868ca2e7287b2`.
It reports zero queued/running rows, ten historical outcomes, and null receipt
and candidate roots in all ten. Its pool status is `known:false` with reason
`pool-unmeasured`; that is unknown capacity, not zero capacity. The separate
read-only `dev land status` output SHA-256 is
`db5d5d1d0ea0b90b31538d61197a95724776b57830d59c03ca3c5e467d82a3ce`.
It displays ten recent outcomes: seven `landed`, one conflict, one failed and
one cancelled; all ten have `acceptance_state=unknown`. Six rows carry a
nonempty remote signer/signature and remote tip. The command reports an
independent fetch, source and ancestry receipt for those six. The separate
verification below checks their signatures, but does not bind them to a task.

The six exact remote tips were separately checked as commit objects and
ancestors of fetched `origin/main`
`07b0d7408a738b5a6c94d1d45de6b26d99849797`. The ancestry-output
SHA-256 is
`6470eac1f57a1bb39cf8f086530fae9c8fbe2554adbab57410d0d6de55b6e092`.
These six observations prove present Git ancestry on this fetched ref, not
candidate acceptance or a canonical `publication_root` to
`remote_receipt_root` join. The ten queue rows and ten displayed landing rows
are not necessarily a shared task cohort.

```sh
build/bin/z23-dev dev agent queue --input='{"action":"status","json":true}'
build/bin/z23-dev dev land --input='{"action":"status","json":true}'
```

The required accepted-output chain remains absent in these projections:
edit/source -> task -> candidate -> action -> proof -> publication -> remote
receipt. The local Git ancestry check resolves only the remote-ref end of six
landing rows. Unknown `acceptance_state` must not be counted as rejected or
accepted novel C23 output.

## Independent verification of six landing observation signatures

The ledger's six selected signed landing rows were checked by a separate
OpenSSL 3.6.3 Ed25519 verifier, using the exact publication-intent and
remote-receipt message formats in `tools/command/native_dev_land.c`
(source SHA-256
`33f3265d5c997c7491376ff11a6613650566fd14939df27fa81a51f9a3541dcc`).
The bounded script is
`tools/dev/fixtures/factory_qualification/verify_land_receipts.sh`
(SHA-256 `146824e05ac85e1545ce9fe0f84df960a52921831ecbb9bae84f97eba3434c4b`);
its six-tip manifest SHA-256 is
`2cda19d523146d7f7987c2057fff6d36fb86298f0a75f2ef10595cd4eb1f76cd`.
The source ledger SHA-256 is
`84ab1c6f8a9a55f76c41751f8c21aa73bb91597b7c441e29a0f1c748db63af03`.

All six publication signatures and six remote-receipt signatures verified.
Each row's `remote_source` and candidate tree matched the remote Git commit's
tree, and each tip was an ancestor of fresh `origin/main`. For each receipt,
changing one signature byte and separately changing one message byte made
verification fail. All six rows use the same signer for publication and
remote observation. The report labels signer authority and acceptance
`UNVERIFIED`; it does not count a second trust domain. The complete output
SHA-256 is
`7a670c0f0fb4e266743dc66b0015e604a6cab5a3431cf5b34aff058a15f972af`.
The Bash child-inclusive measurement was 0.343 s wall, 0.276 s user CPU and
0.125 s system CPU for all six rows, including JSON parsing, Git checks,
24 Ed25519 verifications, byte copies and shell startup; time-output
SHA-256 is
`7b0909c068fc0523b66c86a4e3b4d912a1f8220f21982fba4acab0ff677c4845`.
CPU can exceed wall because it sums child processes. The run used GCC 16.1.1
on AMD Ryzen 7 PRO 8840U at 2026-09-25T18:43:51Z.

```sh
make -j1 jsonq
tools/dev/fixtures/factory_qualification/verify_land_receipts.sh \
    "$Z23_LAND_OUTCOMES" \
    tools/dev/fixtures/factory_qualification/land_remote_tips_20260925.txt \
    "$Z23_QUAL_SCRATCH" "$PWD"
```
<!-- doc-path-ok: owner-private ledger and qualification scratch remain outside the tracked source tree -->

These signatures authenticate statements made by the keys in the rows. This
experiment did not establish current signer authority, prove the referenced
proof and bundle bytes, or connect those rows to task/candidate/action roots.
For the first selected row, `dev proof status` at its exact worktree, local
commit and remote base currently returns `status=missing` and
`detail=exact_receipt_missing` (output SHA-256
`c8cf2525b210b2819f8fa5409eb98fd1105858fd8db7085f04fd358aca7d8f30`).
That is a missing local receipt at the queried path, not proof that no peer
retains the artifact. The canonical accepted-output join remains open.

Isolated ledger copies exercised three separate fail-closed paths. Omitting
the first selected row returned `MISSING_OBSERVATION`; duplicating it returned
`CONFLICTING_OBSERVATIONS`; replacing its remote signature with 128 zero hex
digits returned `INVALID_REMOTE_SIGNATURE`. The mutated ledger SHA-256 roots
are respectively
`861b61cded825ff19402f69736b8327e16aa3c398fe7ff889fcf83ce803994c1`,
`af43b5fbb6597bf59cef45582e9e209f40e45947732a25da0aae0fa2c3b4eaec`,
and `031d3ddd5973cee35519b1872a064f9d71bc4176f396a6e590f433e78607cb51`.
Their diagnostic-log SHA-256 roots are
`9d78595957d3547dd3f31149c40229d97b8b7c02624fd0e0fbf028e2ea4297b2`,
`1ee13de91f1cbd00b8ac08c79c353b0a1f266fe5398df2fcc56ee9d591994c96`,
and `580814a00edd39f44042ebce1c25863bc93ef31e9ad8cb7fd8c7599eae165221`.
These are verifier-fixture refusals; they do not assert that production
publication admission consumed these altered rows.

## Exact local proof-artifact availability after landing

The six signature-qualified landing rows each name a local worktree, exact
local commit/base pair and SHA-256 digest of the signed proof receipt used at
publication. The read-only
`tools/dev/fixtures/factory_qualification/probe_land_proofs.sh` script
(SHA-256 `b9aec802a47b6ebf36325de1e6c43ce047b5a7ef969aa3d50055412f8d6687b4`)
queries the native `dev proof status` leaf for each exact pair and compares
receipt bytes with the row's digest if a passed local receipt is available.
All six currently return `status=missing`; local SHA-256 binding coverage is
**0/6**. The complete output SHA-256 is
`798941de97f94f29301e9034be2a1baa4a17a10b5f63ea23be5979b071e316a5`.
The six queries, JSON parsing and shell startup took 0.704 s wall,
0.471 s user CPU and 0.215 s system CPU on GCC 16.1.1 / AMD Ryzen 7 PRO
8840U; time-output SHA-256 is
`91ada1863c54dc089b2627bd2360f273e73e2baf5a3862e50c1dab06538c1b35`.

```sh
tools/dev/fixtures/factory_qualification/probe_land_proofs.sh \
    "$Z23_LAND_OUTCOMES" \
    tools/dev/fixtures/factory_qualification/land_remote_tips_20260925.txt \
    build/bin/z23-dev "$PWD"
```
<!-- doc-path-ok: owner-private landing projection outside the tracked source tree -->

The result covers these six worktree-local proof paths only. It does not
establish that the receipt bytes are absent from another node or a separate
store. The signed landing row keeps `publication_proof`, but that SHA-256
digest is not itself a retrievable CAS locator in this projection. A receiver
needs a verified path from that digest to retained proof bytes before using
the old publication as reusable proof. No peer fetch, duplicate execution
avoidance, proof-second saving or accepted C23 output is claimed here.

## Bounded development route and peer-lookup boundary

The local development host exchanged one fixed 32-byte object with each
consenting development peer in both directions, and each peer accepted a
bounded command. The two development peers also exchanged the same exact
object and command in both directions using temporary Ed25519 host-key pins
copied over the authenticated local route. The temporary files were removed.
The fixture SHA-256 was
`39ad24c01e40ffc5baecb070e8ea787c01650943b8df69bb1a86e3616323c2b5`;
the alias-only route matrix SHA-256 is
`1cf0090ad8f089ba283bfa3be1da556b3728199e668f7708bf3f74c35effb60e`.
Its bounded measured SSH wall times were 124–191 ms for local-to-peer
commands/transfers and 257–539 ms for the temporary peer-to-peer path.
Direct peer DNS and persisted host-key trust were unavailable, so a durable
autonomous dispatch route is not qualified by this temporary bootstrap.

The six signed landing rows provide proof SHA-256 digests, but no verified
content root or peer locator by which the native receiver can ask for those
exact proof bytes. Neither development peer had the first row's owner-worktree
path at the checked location. No peer proof object was requested or fetched:
peer proof hits, duplicate proof executions avoided, and proof bytes saved
are all **zero observed**. This is a lookup-contract and route-readiness gap,
not evidence that the proof bytes are absent fleet-wide. Local edit feedback
did not wait for the network trials.

## Signed proof receipt freshness and bounded peer verification

The root checkout retained 23 local proof receipts, including 16 signed v2
receipts. A historical 760-byte receipt for local commit
`f43384551597177d6b49c0b83d54f1682ca314df` and base
`e390e57d51a7aaf042c1b916fe1c54093c2e30b0` has SHA-256
`a368dd8529a3569415d57f87572006773b15028f8d435bb772eecab6712358ec`.
Its Ed25519 signature verified independently over the `zcl.dev_proof_receipt.v2`
domain and the first 664 receipt bytes. This authenticates the receipt's
signer and bytes, not the truth of its proof claim or current authority.

The executable
`tools/dev/fixtures/factory_qualification/proof_receipt_stale.sh`
(SHA-256 `3bba7226b3500f0829538092ec5f7f7d8e9fb6217782e4eb66cff3a37da86eca`)
copies the same receipt into four isolated proof stores. The native `dev proof
status` leaf returns `passed` for the old exact pair, then `missing` after
relabeling those bytes to current `origin/main` base
`07b0d7408a738b5a6c94d1d45de6b26d99849797`. A changed signature byte
and a truncated receipt also return `missing` at the old pair. Their object
SHA-256 roots are `4cec674440cb2972a3056d8220dfd42473ae14298acddc02063aadef5b22d5ca`
and `589bc933a1afd51c2ecae405814745354a91790c25a91fa26f49aab420769c45`.
The four native-status JSON roots and complete output are in local log
SHA-256 `0e00217a60dd3307f8a4c72468f8b899a95ddb1ab1fb7481dabb586b277ec230`.
This 0.464-second fixture used 0.301 user and 0.143 system seconds, including
OpenSSL, JSON parsing and native calls, on GCC 16.1.1 / AMD Ryzen 7 PRO 8840U
at 2026-09-25T18:59:26Z; time-output SHA-256 is
`ed416210e61e3228dc7fa0e1741dd6bfd0391b03a16f53adfdc993663fc75a2b`.

```sh
tools/dev/fixtures/factory_qualification/proof_receipt_stale.sh \
    "$Z23_ROOT_DEV_BIN" \
    "$Z23_PROOF_RECEIPTS/f43384551597177d6b49c0b83d54f1682ca314df-e390e57d51a7aaf042c1b916fe1c54093c2e30b0.receipt" \
    "$Z23_QUAL_SCRATCH" "$Z23_ROOT_CHECKOUT"
```
<!-- doc-path-ok: historical receipt and scratch are local evidence, not tracked inputs -->

The exact signed receipt was then streamed to each consenting development
peer over authenticated SSH by
`tools/dev/fixtures/factory_qualification/proof_receipt_peer_verify.sh`
(SHA-256 `0a07f99213dc0665a2646e939e8aa0fa34871d810910d5f716a9a4f4fcfdefc3`).
Each checked its 760-byte length and SHA-256, reconstructed the Ed25519
public key from the receipt, and verified the domain-separated signature with
OpenSSL; no C source was executed. Both returned `signature=VALID`, then
refused the 760-byte changed-signature variant after accepting its changed
SHA-256. The four bounded end-to-end wall times were 0.205, 0.200, 0.201 and
0.199 seconds. Direct SSH client CPU ranged from 0.012 to 0.014 seconds per
call and excludes peer CPU. The direct fixture output SHA-256 is
`24592b260cf48408ad005166a29c46b21d4620c146f18df4b1ebf6fb71a8d903`.
Exactly 760 receipt payload bytes were sent to each peer for each variant,
3,040 bytes total. This demonstrated
byte and signature verification on three hosts, not a current eligible proof
reuse: the historical base differs from current main, no signer-authority or
independent-run requirement was discharged, and no peer native proof-status
result was claimed. Local hit was one historical receipt; current eligible
local hits, peer hits, duplicate executions avoided, and bytes avoided were
all zero observed. Local status never waited on SSH.

```sh
tools/dev/fixtures/factory_qualification/proof_receipt_peer_verify.sh \
    "$Z23_PROOF_RECEIPTS/f43384551597177d6b49c0b83d54f1682ca314df-e390e57d51a7aaf042c1b916fe1c54093c2e30b0.receipt" \
    "<consenting-peer-alias>"
```
<!-- doc-path-ok: receipt is local evidence and host alias is a consenting development peer -->

The operator's North Star directive was appended to the local fleet-mail
outbox as sequence 807 with ref `ooda-north-star-20260925`. It has no consumed
acknowledgement under the local observation boundary above.

## Combined-tree focused gate and fixture repair

The qualification branch merged `origin/main`
`07b0d7408a738b5a6c94d1d45de6b26d99849797` at signed commit
`2e8adcc4c`. The only source conflict was the generated capability
inventory; regeneration produced SHA-256
`8f64305f8d87c6e38eed31b8f2a1f789c99609a282403227cb32601c637238c9`.
The source-derived inventory gate passed 1,507 capabilities and 1,154
registered roots, and `lint-preflight` passed five of five gates.

The cold combined-tree queue gate selected three registered groups and passed
all three, zero skipped. Its full log SHA-256 is
`d8f514eb0dc1a7ca846369ad062820bb7886e2c03fec417b156e3ed9f48f0492`.
At low CPU and I/O priority, the build-and-test envelope took 404.559 seconds
wall, 267.580 user and 133.298 system seconds; the harness reported only
1.211 seconds of test body. This is one cold test epoch, not an accepted-output
rate or proof of a compiler optimization. The 403.348-second remainder
includes build, link, runner startup and bookkeeping and is not all compiler
CPU. The test epoch produced 1,714 object files before completion. It ran on
2026-09-25 with GCC 16.1.1 on AMD Ryzen 7 PRO 8840U.

`lint-fast` then passed 31 of 33 gates (full log SHA-256
`cefae4df0d3109b9af0078eaa8bf8dbc2c2077380377437808e4d04e6cee666c`).
Its two failures were local to this
qualification lane: the queue test's complexity fell from M=34 to M=28 and
needed a shrink-only baseline update, while the receiver fixture carried two
`printf | grep -q` decisions under `pipefail`. The baseline now pins 28, and
those two decisions read here-strings. The revised receiver fixture SHA-256 is
`7cf14336f9816f12424396bf375b88f532af08533203d067f802b417c2ad7277`.
It passed against the just-built combined-tree dev binary SHA-256
`1385fc36b6e73ec5f9580a62bd4aeca82cc85cc132902320c9275c4f28ebf977`;
the fixture output SHA-256 is
`af1f9802c95098117bb7dd4dbd31a364fdfdf0fb77727da49cfe7a669e5386f2`.
The suite continues to demonstrate queue-only intake, revocation, duplicate
retry and source-head refusal, not an agent-session consumed acknowledgement.
After those two repairs, `lint-fast` passed all 33 gates in 13.678 seconds;
the complete output SHA-256 is
`92fb78dcc6694c2acf4d21798e3694a8e0486e9998c2fc2ee3254578a8ea1ca8`.

The one-worker full-lint baseline ran for 1,274.862 seconds, with 213 gates
and four failures. Its exact log SHA-256 is
`935f0487204b44919afde05bc8d59d04a8184e3ce68e4bf5dc0b55f0b1920010`.
`check-doc-claims` passed but spent 543.228 seconds waiting three times for
180 seconds for later gate verdicts that one serial worker could not produce
while it was occupied. `check-file-purpose` named the F1 source, and
`check-live-datadir-isolation` and `check-no-operator-paths` named this note;
the purpose comment and safe replay examples are repaired here. The remaining
`check-tor-provenance` mismatch is the recorded `gcc` versus actual `cc`
version label with identical compiler bytes. `check-no-operator-paths` also
reports growth in several files outside this lane. These failures remain
visible; the full gate is not green. Fleet mail outbox sequence 810 routes the
exact 543.228-second serial lint wait and smallest fix to the lint owner.

After the source and example repairs, focused checks returned: file purpose
0 unbaselined violations (log SHA-256
`8c4f8fb99beb8d39dea5a1558c20e4f3f02cc90ced853fa85d34695729903ed3`),
isolated datadir examples PASS (log SHA-256
`8c87f359d8b17b0c373f9de8837ecee644f866d98df636aa8d6c7c0915651795`),
and operator paths PASS (log SHA-256
`43ea3fb177aaf6118f864c65380b7b673ae89adaab9e3bd97168907ea7c4c6af`).
Tor provenance passed with `CC=gcc`, matching the archive's recorded compiler
invocation without changing the archive or gate (log SHA-256
`0e8fc19cfcfb52283d1a744c3c600a811d79c841e392960acaaea1eea430024d`).
The full 213-gate verdict was pending at that checkpoint.

On signed combined tree `1f2a9ee6eead1f3877fee8c79231cd1077af6ae6`
with main `47498630fddb6af37cc0a34bbf8cefe92a7191b0`, `make -j1 CC=gcc
ZCL_LINT_JOBS=2 lint` passed all 213 gates. The complete log SHA-256 is
`cef30df081ee70f1e48bbacf2a4e03c70b4746ce3adef154b5eca23c068151d9`.
The low-priority end-to-end wall was 742.767 seconds, with 2,032.509 user
and 790.701 system seconds summed across its child processes. The gate phase
was 466.820 seconds wall; its longest individual gate durations were
`check-windows-cross-syntax` 238.922 seconds,
`check-build-epoch-integrity` 139.829 seconds, and
`check-outparam-init-before-return` 100.054 seconds. Those overlapping gate
durations are not additive. `check-doc-claims` took 56.107 seconds with two
workers, versus 543.228 seconds in the earlier serial run. The two runs also
differed in source and compile epoch, so their wall difference is an observed
condition comparison, not a controlled speedup claim. Accepted-output cost
weight remains undefined because the queue-to-candidate join is absent.

## Native proof feedback on the exact qualification branch

The first native proof request for signed commit
`b3f795822d6f397e2117d73b82fbc2c45f551508` against
`origin/main` `005f2e706f6a45e1f35c7b7510a079da7d70b055` failed in
206.914 seconds wall, 214.832 user and 189.220 system seconds. Its typed
reason was `proof_generation_dependency_unavailable` for the absent
vendor/tor/Makefile, with an ineffective `make vendor` hint, before any signed
receipt. The CLI log SHA-256 is
`10d89cc50be4ec53a20391badb9359a3024afb05bd700580c1433b2a4029e9ee`.
The submitting worktree had the pinned Tor submodule and archive and manifest
identical to the primary checkout, but `tor-ready` had not carried its
generated `Makefile`; `make vendor` does not create that file. Copying the
primary checkout's exact generated file, SHA-256
`501e240eb139d82a9ed70815ed17d5f4f560ed92142886c8dd71701776ba3a4f`,
into this isolated worktree made `check-tor-provenance` pass. No source file or
gate was changed to repair this prerequisite. Fleet mail sequence 815 sent
the measured loss and the priming mismatch to the proof owner.

The explicit retry of the same exact pair ran 1,329.218 seconds wall,
2,999.633 user and 1,210.135 system seconds on GCC 16.1.1 / AMD Ryzen 7 PRO
8840U. Its full lint dimension passed 213/213 gates in 645.610 seconds (log
SHA-256 `691004dedc281cf9f1ccefa3d01e2725c12127d25947f5d618c95897460492a5`),
and its test preflight required 72 fresh groups with zero eligible reuse. The
test dimension ran 72 groups in 399.415 seconds and failed one: the existing
`test_devagent_worker` wide control-byte candidate case found queue verdict
`unknown` where its worker receipt said `pass` (test log SHA-256
`80b12191eed1ed8456b58bebf08be006c6b909728d8e420f74f447bb8dc535a5`).
The retry CLI log SHA-256 is
`e111a1ef92c186e36f691bbc15cdbd89cb72613687e0aadae6015aa9b0f58e6a`.
The test and lint dimensions overlap, so their durations must not be summed
to estimate proof wall time. No proof receipt or publication was issued.

The queue had applied its 64-byte job-name grammar to a worker candidate
filename. That incorrectly made an otherwise valid receipt verdict unknown.
The correction distinguishes receipt interpretation from candidate-root
eligibility: a string candidate that cannot be represented exactly or is
outside the confined artifact-name grammar retains the receipt's stated
verdict and receipt root, but yields a null candidate root. Escaped field
names, escaped verdict values, duplicate binding keys and invalid numeric
forms still refuse the receipt. Source SHA-256 is
`07f821a48cec72c40ad1f928c78dd309f93d7dc2fd179b0538a1bfce060d38bc`;
queue-test SHA-256 is
`f421fa848ef0abe8a914e141fe320063067dc74f1ae0c3148b9bab0b20c2401f`.
The registered worker selection passed 2/2 groups with zero skips (log
SHA-256 `8b38dd17ef2bf2f8a4528834a7018f76d9bce9355a7419546d50715103a09351`);
the registered queue selection passed 3/3 with zero skips (log SHA-256
`4462f62ac25cfb5edc3d9152f0e89f3ce2658dd7aa900075a6279110765e319f`).
Strict GCC C23 syntax passed, and `lint-fast` passed all 33 gates (log
SHA-256 `60b29f3b405d18fe0843bac1e91c449ced9dd9f5d1a04c0c9703b38d7bab0d94`).
These focused passes do not replace the failed full proof.
