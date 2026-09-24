<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Factory qualification handoff

Snapshot: 2026-09-24T23:21:22Z. Requery native status before changing a
queue, proof, candidate, or node. This record separates measured local
verification from owner preview and operator acceptance.

## Mission capsule

- **Outcome:** qualify the real C23 package factory and SkyCombat application
  through exact preview, independent reproduction, publication, and local
  acceptance. Increase measured useful changes per day without weakening a
  gate.
- **Owned surface:** qualification fixtures, evidence audit, benchmark records,
  and read-only diagnosis. Factory, native land/proof, SkyCombat, and public-node
  implementation have separate primary owners.
- **Invariant:** an exact source hash, artifact hash, receipt, owner preview
  verdict, DEV acceptance, and full acceptance are distinct claims.
- **Escalate only for:** a consensus/custody risk, destructive production step,
  a gate that would need weakening, or a human product decision. SkyCombat's
  owner has already answered the exact visual-preview question.

## Current results

| Evidence | Result and root |
| --- | --- |
| Frozen mixed measurement and peer evidence | Signed measurement commit `81d632f4d3dea19afab33523f17edf43642b369c`; peer-evidence commit `17e730705e9393c6db61cf2a79e400745b0319a6` |
| Frozen factory ledger | `7fc17ab494d13240eb17e5b23f8dd61226c49de4591093653d4d6e86115c006c` |
| Revision 100 source | `src/history.c` <!-- doc-path-ok: generated package path --> SHA-256 `aa68289413d3cd13fd7c752c9aa6521027856bcf08423622115feb1c751d885b`; package root `654b455776cf1ac7996c052c9e260477ae9e574266084f2975e04fa0ce61dc82` |
| Independent final-state peer | GCC 14.2.0; input bundle SHA-256 `253727787a3e5a441fc68c1f57de9f0c61c9c79dd993dc6acfaf5997e8ebef2b`; returned archive `04ad314b5dad0dcdacc6cc28e88fec7f4840786da63086af52b6a0eef0efa475` |
| SkyCombat preview | Source commit `255990bfdc48e0c7e6f966aa2e8d6e678b25ca40`; game executable SHA-256 `9a7a46565f2414bd8ccb5c9ee6ebb7c60b951ea690177f958123993091e4082c`; 1920×1080 frame SHA-256 `38fd50456fb394a84df18956cc2d13cc56daf55163f0caa560f82a1b309873e4` |
| SkyCombat preview decision | The owner answered **“Preview accepted; continue qualification”** and **“Accept this preview”** for those exact binary/frame roots in this session. This is visual-preview acceptance, not a signed Commons publication or DEV/full acceptance receipt. |

The mixed corpus preserves prior prefix behavior and adds range, refactor,
terminal text/JSON, and strict-input milestones at revisions 25, 50, 75, and
90. Its funnel is 100 generated, 100 buildable, 100 previewed, 100 tested,
100 two-store locally verified, **0 DEV accepted, 0 fully accepted**.
Revisions 1–74 use a local test-binary preview; 75–100 use the real terminal
client. Added source LOC is 206 at each reached stage, with 5 removed LOC;
generated test LOC is excluded. Fresh publisher/stores per revision mean this
is not 100 same-publisher releases or installed-state migration. A same-store
control refused the second immediate release under publisher equivocation or
weekly frequency policy without changing the first installed artifact.

The independent peer rebuilt the final source and passed 101 prefixes, 5,151
ranges, 202 renders, 101 parser cases, five invalid cases, 101 exact text
outputs, and 101 exact JSON outputs. It did not rerun all 100 revisions.
Eleven adversarial modes have executable expected verdicts; the corrected
fault evidence matrix root is
`7d55b8eb5e5da3cf991c3334b227f4ca222ca59598f0507ff8a11a839b9c72b3`.
In particular, a new-interface candidate passed factory tests while an old
C23 client failed to compile, and two compile-valid mixed candidates were
refused for wrong value/UI behavior. Cache tamper and false-corruption race
controls are in the original experiment record.

## Throughput and limits

The mixed serial run spent 497.373 s in 100 factory calls, including 396.966 s
(79.8%) in two `add_commit` and two `reproduce_build` steps. Its p50/p95/p99
factory latencies were 4.186/4.548/30.467 s; revisions 91–93 were about 30 s
each without a proven cause. The measured host interval was about 519 s, or
694 **locally verified** changes/hour. The 32-candidate concurrency run used
widths 1, 2, 4, 8, 16, and 32. Width 16 reached 6,440 locally verified
changes/hour once and 1,188/hour on repeat; host contention was not isolated,
so neither is sustainable accepted throughput. Queue wait, CPU, per-job peak
RSS, and filesystem blocks are in the exact width ledgers in the linked
experiment. DEV and full acceptance throughput is zero.

Two development peers independently verified the exact SkyCombat aircraft
control input, and each refused a wrong-boost source. SkyCombat's canonical
aircraft recipe still refuses undeclared `libm`; the allowlisted-libm control
recipe passing isolation does not amend the canonical recipe. The repaired
game `make game-check` passed at the landed exact executable bytes. No app
release or operator install follows from the owner's visual verdict alone.

The accepted preview covers the complete SkyCombat game executable at source
commit `255990bfdc48e0c7e6f966aa2e8d6e678b25ca40`. The Commons control
package named `qualification/skycombat-aircraft` copies one aircraft source,
its header, raylib headers, and a focused flight test. Its package root
`9a2c62d39213dd36a2e05ca064ac011d100ff429f92eecedd2f2682307495acc`
does not identify the previewed game executable. Fixing its `libm` declaration
would qualify that component recipe only. A release of the accepted preview
requires an exact candidate that binds the complete game source and resulting
executable, the owner's existing verdict bound to that identity, and native
acceptance receipts.

The frozen complete-game source subsequently rebuilt locally to the exact
accepted executable SHA-256. A second development peer built the same source
with GCC 14.2.0 and rendered a 1920×1080 frame; its executable and frame have
different roots from the owner's GCC 16.1.1 preview. The first peer refused
missing X11 development headers. These are source-build and render evidence,
not a Commons candidate or owner acceptance of the peer artifact. Exact roots,
commands, compiler cohorts, cost, and node-health limitations are in the
[complete-game peer experiment](./2026-09-24-skycombat-fullgame-peer.md).

An isolated local regtest node stayed responsive at height 0 during factory
load (100 baseline, 539 during, one after successful block-count RPC), but
its log emitted `catchup: final commit missing tip hash` before workload and
again later. Remote peer node state was already blocked by bootstrap trust.
Chain synchronization safety under load remains unqualified; the public-node
owner received native mail sequence 407.

## Publication state at snapshot

Native land seq38 independently observed the same-publisher evidence on
`origin/main` at `1effa8fe671d06044adedc38f0b456ac4366a2fb`, source tree
`121e02d13e63f38fe43687756856a69c7de3ff8f`. Seq37 independently
observed second-peer and isolated-node evidence at
`284d854af96ae9165e036589b4773a765f1cdc46`, source tree
`2a5ed3c6f9ee7fa368fd607d15f21392e31aca5b`. Their native outcomes bind
the remote signer and fast-forward ancestry. Submission-to-remote-receipt
latencies were 11,085 s and 6,682 s, respectively. These are evidence
publication latencies, not application acceptance latencies.

Seq41 (`836287f7176c3359023f9130d48fec639d5c39c0`) failed its first full
proof with no receipt. Its test dimension passed: 16 required groups executed
and two eligible hotswap groups reused input-bound cache evidence. Full lint
failed three of 212 gates on the qualification files: the C23 auditor lacked
a purpose comment, four backticked generated-package paths were unmarked,
and the handoff included an operator home path. The operator-path gate's
source-derived identity prong then flagged other unchanged files. The
corrected source passes `check-file-purpose`, `check-doc-inline-paths`,
`check-no-operator-paths`, and `lint-fast`; its final-state peer bundle was
rebuilt and rechecked at the roots above. The signed successor received full
exact proof and landed as native seq42 at
`b984548202b55ce230eb9caf1ffaf0a13a43d6fc`, source tree
`0aa42709fa78eea24a10ec54940aca98a4d0486d`. The independent remote
receipt verified signer and ancestry. This evidence publication is not app
acceptance. Cancelled seq39 and seq40 are not publication evidence.

| Rank | Measured blocker | Owner |
| ---: | --- | --- |
| 1 | Exact publication proofs and moving-base retries cost 11,085 s and 6,682 s end to end for seq38/37; stale hook bytes also wasted one full seq38 attempt. | Native land/proof owner |
| 2 | Two-store `add_commit` and `reproduce_build` cost 396.966/497.373 s (79.8%) in the mixed serial factory run. | Commons factory owner |
| 3 | This qualification has no complete-game Commons candidate bound to the accepted preview; the aircraft control recipe separately refuses undeclared `libm`. | SkyCombat and Commons recipe owners |
| 4 | Height-0 node observations and pre-existing catchup errors leave chain-sync safety under package load unqualified. | Public-node owner |

The highest-leverage throughput repair is reuse of mandatory unit evidence
only when exact input closure and receiver policy permit it across Git-base
movement, followed by fresh mandatory publication evidence and independent
remote observation. The [`FORWARD_PLAN.md`](../work/FORWARD_PLAN.md) already
requires this. Native mail sequences 419, 431, 432, 447, and 458 bind the
measured factory and land costs to their owners. The immediate app release
step is an exact complete-game candidate with a real preview-to-source binding;
the aircraft component must also declare `libm` before its own package can
pass the confined verifier.

## Immediate continuation

```bash
git fetch origin main
git rev-parse HEAD origin/main
build/bin/z23-dev dev land status
build/bin/z23-dev dev agent mail pull --since=458
```

Use a built `z23-dev` whose command catalog includes `dev.land`; the above
`build/bin` path is a command template for a checkout with that binary. If a
proof is in flight, read its exact root, local commit, and remote base from
`dev land status` before invoking `dev proof status`. Do not run another build
in the private landing worktree while its proof is active. Establish a
complete-game candidate under the app owner's source ownership, bind the
accepted preview to that exact candidate, and run the real publication and
local acceptance journey. Repair and reverify the aircraft component recipe
separately. Never infer release acceptance from the accepted frame or from
the component control.

Full commands and raw roots are in
[`2026-09-24-factory-mixed-100.md`](./2026-09-24-factory-mixed-100.md),
[`2026-09-24-factory-100-skycombat-preview.md`](./2026-09-24-factory-100-skycombat-preview.md),
[`2026-09-24-factory-adversarial-qualification.md`](./2026-09-24-factory-adversarial-qualification.md),
the [complete-game peer experiment](./2026-09-24-skycombat-fullgame-peer.md),
and the landed second-peer and isolated-node evidence commit named above.
