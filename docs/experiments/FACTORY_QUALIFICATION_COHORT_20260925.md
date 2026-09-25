<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Factory qualification cohort, 2026-09-25

This cohort fixes eight initial adversarial obligations and six addenda before
further speed claims. Each verdict applies only to its named executable and
source tree. A pass in one row does not admit reuse or acceptance in another.
The full roots, commands and output bytes are in
[`QUEUE_COST_JOIN_20260925.md`](./QUEUE_COST_JOIN_20260925.md); the registered
hot-swap fixture is owned by the separate hot-swap lane.

| ID | Obligation and fixed input | Observation | Required next gate |
| --- | --- | --- | --- |
| F1 | Same C23 source `6359bd81590332cd97e32258677b7dbb98a8ec22ade1444e23aa3ecab7414fe3`, `-DZCL_FIXTURE_VALUE=1/2` | Four strict GCC 16 builds pass; output roots `4355a46b…` and `53c234e5…` differ with the flag | Receiver must bind the effective compiler arguments before reusing an action |
| F2 | New optional header `6ed627b3d5ad0b9a278a1aa558c892d0d28892f7a13ef5e5d5a75d77b3bc12c4` | Registered hot-swap shard RED: cached object `2d01ed9a…` prints `1`; independent fresh object `a8744afe…` prints `2` | Hot-swap owner repairs include-topology identity; rerun registered gate |
| F3 | Same-name header appears earlier in `-I`; new header root as F2 | Same registered shard RED with the same cached/fresh object roots | Hot-swap owner repairs search-order identity; rerun registered gate |
| F4 | Same-key directive retry and receiver restart; fixture `2d3afbe0a89d0001b858cb10b68702cf0357c9314e0cfd0f5ef8672e20ffa06d` | One queue row; retry marked duplicate; restart admits zero | Agent-session consumed ACK and result association remain unproved |
| F5 | Grant revoked after queue admission, then regranted with the same sender label | Revocation cancels the queued row; revoked send refuses; new grant admits one row with a distinct source tag | Bind grant and receiver epoch to the task/result join |
| F6 | Compile-valid tracked edit, then clean commit with directive pinned to prior HEAD | Receiver refuses dirty workspace, then stale source pin; queue count stays one | Carry the accepted source root through candidate and proof |
| F7 | SkyCombat invalid `DISPLAY=:9999`; display script `699013d16cf4145573ed3de374e4e97b559e36a8b7d8dfd9d83dc836649d3f88` | Executable exits 139 in vendored RGFW after `XOpenDisplay` fails | Game/vendor owner propagates initialization failure and retests |
| F8 | Shadow report drops a failing observation; harness `3c2e139a1aa54180cc26def801d58e805c322555e5178ae65017c512e1b7db2e` | Bounded report changes RED to GREEN when the failure is omitted or relabeled | Bind complete observation universe and signature status before promotion |

F1 is a compile-valid control, not an observed stale receiver decision. F2 and
F3 are observed stale-object failures. F4–F6 prove intake behavior, not
consumption. F7 is a real application failure. F8 is a shadow-report coverage
failure, not a production admission failure. The initial eight cases have no
publisher-death, resource-exhaustion, Mac, independent proof or remotely
accepted-output result. The later publisher-death addendum below is limited to
isolated landing fixtures. The frozen mixed-100 ledger separately reports
100 generated/buildable/previewed/tested/verified edits and zero DEV or full
acceptances. These different cohorts have no authenticated output join and
must not be summed into a daily accepted-LOC rate.

The current F1 source adds a required public purpose comment and has SHA-256
`d33b5bc905b52441c2794c5f17cf524b00e7254edfdb28782be2c1b9a6760f4e`.
The four strict GCC 16 controls still pass with the same output roots; the
new full output SHA-256 is
`ea171c386c51baa3afdfb917e7962db768eb1ce9eae8063cc9d23c2bc9a8fa5f`.
The original source root in F1 remains its historical run identity.

Run the two bounded tracked controls with:

```sh
tools/dev/fixtures/factory_qualification/toolchain_drift.sh /usr/bin/gcc test-tmp
tools/dev/fixtures/receiver/receive-revoke-replay.sh build/bin/z23-dev test-tmp
```

The second command requires a signed Git test identity and an isolated parent.
It also passed with this worktree's binary SHA-256
`5e50f20d15e361ed0f1d6870d74fda4a898574cd9e228b4d29a5c082112d8164`;
the full output log SHA-256 is
`ab764e8e5bdd92547515a02b8ac5501816f7194fbb9823b4787243b639cae48d`.
The earlier run used binary SHA-256
`7c507c056f846a6d50629d5b6cf4dbf3cbb5b51c2f5fcdff05190b66d71c0d68`.
No retained build receipt binds either binary to current main. The optional
header and shadow-report cases run in their owners' isolated trees. The
cohort's missing closure, not a faster selected test, controls acceptance.

## Addendum: package-cache trials inspected independently

The fast-object lane owns the registered `fastobj_carrier` test. Its signed
combined-tree commit `1ff14cb1022104e17c78394185d74734ee52baf1` has
test-source SHA-256
`d047d52b8685e604273317b0d1083ab3c84f13d09d34c3ccae2a74031a38954e`.
The retained focused log was independently opened and matched its published
SHA-256 `8d71edab934f19106875677eb198d211f2eb3969d10874e67df8900c68534a68`.
It reports one group passed, zero failures/skips, and 109.4 seconds of test
body under GCC 16.1.1. The source and log support two additional fixed
obligations; this lane reviewed the producer run and did not independently
execute the package verifier.

| ID | Input mutation | Observed producer gate | Qualification limit |
| --- | --- | --- | --- |
| F9 | Public C23 struct fields swap while header size and nanosecond mtime stay fixed | Changed package misses one affected object, reuses two unaffected objects, exits `1`; fresh cache matches package and program bytes | Focused Linux package-cache gate; no receiver proof or remote acceptance |
| F10 | Generated C function changes return `0` to `1` while source size and nanosecond mtime stay fixed | Changed package misses one affected object and reuses three; program exits `1`; fresh cache matches archive and program bytes | Focused Linux package-cache gate; no receiver proof or remote acceptance |

The same log reports a corrupted CAS chunk quarantined during the fixture,
but its presence in the log alone is not an independently verified
receiver-side corruption verdict. F9 and F10 do not repair the distinct
F2/F3 hot-swap cache failures. No saved proof seconds or accepted-output gain
is inferred from object hit counts.

## Addendum: signed publication and remote-observation check

F11 fixes six published Git tips in
`tools/dev/fixtures/factory_qualification/land_remote_tips_20260925.txt`.
The independent verifier
`tools/dev/fixtures/factory_qualification/verify_land_receipts.sh` checks
both signed messages from each local landing outcome, exact Git tree and
fresh-main ancestry, then requires a changed signature byte and a changed
message byte to fail verification. All six rows passed those checks; full
output SHA-256 is
`7a670c0f0fb4e266743dc66b0015e604a6cab5a3431cf5b34aff058a15f972af`.
The 24-check batch took 0.343 seconds wall and 0.401 seconds summed user and
system CPU, including subprocess and input parsing costs. It does not prove
the signer held current publication authority, the referenced proof bytes
survive, or that any task was accepted. The first selected row's exact local
proof receipt is currently missing at the queried worktree, so its proof
digest cannot be revalidated from that path.
All six publication and remote-observation signatures were made by the same
signer key in each row; they do not meet a separate-signer requirement.
Isolated ledger copies with the first row missing, duplicated or carrying a
corrupt signature all refused with distinct diagnostics. These refusal
results test the qualification fixture, not production publication admission.

## Addendum: proof-byte availability after publication

F12 uses the same six tips and their exact published local commit/base pairs.
The bounded `tools/dev/fixtures/factory_qualification/probe_land_proofs.sh`
queries the native proof status and compares a passed receipt's bytes with
the signed landing row's proof SHA-256. Current local-path availability is
**0/6**; all six status results are `missing`. Output SHA-256 is
`798941de97f94f29301e9034be2a1baa4a17a10b5f63ea23be5979b071e316a5`.
This establishes a local retrieval gap after publication, not global loss of
proof bytes. A peer lookup by a verified existing CAS object and policy is
the next qualification before recomputing any proof.

F13 fixes a 32-byte route object, SHA-256
`39ad24c01e40ffc5baecb070e8ea787c01650943b8df69bb1a86e3616323c2b5`.
It passed bounded command and exact transfer checks in both directions for
the local host and two development peers, plus both peer-to-peer directions
with temporary pinned host keys. Direct peer name lookup still failed, and no
durable peer route or proof-object lookup was qualified. The alias-only route
matrix SHA-256 is
`1cf0090ad8f089ba283bfa3be1da556b3728199e668f7708bf3f74c35effb60e`.

F14 challenges a retained 760-byte signed proof receipt, SHA-256
`a368dd8529a3569415d57f87572006773b15028f8d435bb772eecab6712358ec`,
against the current `origin/main` base. The executable
`tools/dev/fixtures/factory_qualification/proof_receipt_stale.sh` independently
verifies its Ed25519 signature, then asks the native proof-status leaf for the
old exact pair, a current-base relabel, a corrupt signature and a truncated
receipt. The old pair passes; the other three return `missing`. The current
pair therefore cannot reuse this historical receipt. Both consenting dev
peers independently verified the same 760 bytes and signature after bounded
transfer, and refused the corrupt signature, but neither accepted a current
proof obligation. Duplicate proof executions and bytes avoided remain zero
observed. The complete local output
SHA-256 is
`0e00217a60dd3307f8a4c72468f8b899a95ddb1ab1fb7481dabb586b277ec230`;
the two-peer verifier output SHA-256 is
`24592b260cf48408ad005166a29c46b21d4620c146f18df4b1ebf6fb71a8d903`.

## Addendum: isolated publisher-death recovery

F15 reran the registered `test_dev_land` group on combined tree
`088d9fe524f2fd79621cb8a04c0a141c9dbffa4b` with GCC 16.1.1 on an
AMD Ryzen 7 PRO 8840U, 2026-09-25T20:24:37Z. Test source SHA-256 was
`11f220d5b9d3f27d959867374935c1781ee2bee36a6c58256e3e2ed26a36d6b5`;
the runner executable SHA-256 was
`ac262d073d0873f99c1a4554b45f681e36dbe46b53984005e88bfcb9490a076a`.
The exact command was:

```sh
nice -n 19 ionice -c3 make CC=gcc -j1 t-fast ONLY=dev_land
```

The cold runner selected one group with zero cached groups, zero failures and
zero skips. The group passed its signed publisher-death case: an isolated
`post-receive` hook killed the publisher after the remote ref changed; a new
step recovered a signed receipt and the fixture's invocation marker remained
one call. The separate unsigned case resumed without another push. The group
also passed its lost-acknowledgement and outcome-append replay cases. Full log
SHA-256 is
`febb13ab29b56bef81d67110f7109b837171439c8ee78c18035c38b2fef063d7`.
The command envelope took 666.032 seconds wall, 473.118 seconds user CPU and
175.676 seconds system CPU; the runner reported 64.547 seconds of test body.
These totals include a cold 3,000-plus-object build and do not isolate
publisher recovery latency or process-tree wait. Sampled 10-second CPU
pressure stayed near zero with the single low-priority build job. The cases
use a stubbed proof, an
isolated local Git remote and an ephemeral signer. They establish local
recovery behavior, not an independently reproduced proof or remotely accepted
application change.

## Addendum: mail outbox short-write recovery

F16 is an isolated Linux resource-exhaustion counterexample for the existing
`dev.agent.mail` outbox. The executable fixture
`tools/dev/fixtures/factory_qualification/mail_fsize_partial.sh` has SHA-256
`04588eed7c59dfe4fcfba92d0aac290c29ba49a9ea11aaa4484f27b87468b2a4`.
It used development binary SHA-256
`da515771d618ef4158cf5203a1a957f69a915f1367f1c1f1a3b3577619efcdfe`
and native JSON helper SHA-256
`1169ee356970bc19ffe98ac7bda251f819e7dc1bb74167c742480f780937cb89`
on the same combined tree, with GCC 16.1.1 and AMD Ryzen 7 PRO 8840U on
2026-09-25. Reproduce in an isolated scratch parent with:

```sh
tools/dev/fixtures/factory_qualification/mail_fsize_partial.sh \
    build/bin/z23-dev test-tmp build/bin/jsonq
```

With `ulimit -f 1` and `SIGXFSZ` ignored inside the fixture, the first two
460-byte posts returned success. The third returned `MAIL_WRITE_FAILED` but
grew the outbox from 920 to 1,024 bytes, leaving an unfinished JSON row. Once
the file limit was removed, a new post returned success at sequence 4. `pull`
then returned only three rows: its third row carried sequence 3 and the failed
post's partial body with the new post's `after-limit` ref. The new message was
not an independently readable sequence-4 row. Fixture output SHA-256 is
`2d5d79c4cd0fc39937cae5beeb59e99a491ca885c910d7c14f9853af857be65f`;
the final outbox bytes have SHA-256
`c1ba2a0604da8fea75a0707399a842cf1e2b9c57160abcc2b9212606220c3f38`.
The source-side append is one `O_APPEND` write, returns failure on a short
write, and does not remove bytes already written. Its source SHA-256 is
`3497cd057e2cdb8e08d77eff2038bd066f79d8988796bf84863588ce96a5dcee`.
This is a real false-success and conflicting-observation path after recovery;
it does not prove that a receiver consumed the corrupted row. The mail owner
needs to keep a short append from leaving a readable partial row and prevent
a later success from merging with it. The fixture must turn green without
relaxing parser or write-failure gates.
