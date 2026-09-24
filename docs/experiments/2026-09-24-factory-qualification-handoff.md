<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Factory qualification handoff

Snapshot: 2026-09-24T21:54:00Z. Requery native status before changing a
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
| Mixed 100-revision qualification tip | Signed commit `17e730705e9393c6db61cf2a79e400745b0319a6`; base experiment commit `81d632f4d3dea19afab33523f17edf43642b369c` |
| Frozen factory ledger | `7fc17ab494d13240eb17e5b23f8dd61226c49de4591093653d4d6e86115c006c` |
| Revision 100 source | `src/history.c` SHA-256 `aa68289413d3cd13fd7c752c9aa6521027856bcf08423622115feb1c751d885b`; package root `654b455776cf1ac7996c052c9e260477ae9e574266084f2975e04fa0ce61dc82` |
| Independent final-state peer | GCC 14.2.0; input bundle SHA-256 `2f265f85fd0e14dd4fb77b949b479efc464544997a905f9d8dc8c76d142b36f7`; returned archive `785131a53b0179af94fdf9d09641cd3bb0389048f3e9a828c7fa2272f4451d0c` |
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

An isolated local regtest node stayed responsive at height 0 during factory
load (100 baseline, 539 during, one after successful block-count RPC), but
its log emitted `catchup: final commit missing tip hash` before workload and
again later. Remote peer node state was already blocked by bootstrap trust.
Chain synchronization safety under load remains unqualified; the public-node
owner received native mail sequence 407.

## Live publication state at snapshot

The native land queue has seq38 in flight for same-publisher evidence tip
`ab697cb3b49f71dff0894aa2529bd85b4026862b`. Its exact proof pair is
`0a745b42964a7325062c6aaa4278145dad29e0d2@95f9a85d95e7620de77a1b2814769a81b7418743`.
The proof worker was running at snapshot; `origin/main` had advanced to
`247c32071629ceb0b58e1f36be8e5b75f6161c19`, so the receiver may mark
this pair superseded. Preserve the worker and requery before invoking another
step. Seq37 (`125f8753222a4c41399d5a88b547b10d1bdfc64a`) queues second-peer
and isolated-node evidence. Seq40 (`17e730705e9393c6db61cf2a79e400745b0319a6`)
queues the mixed workload and final-state peer evidence. The older seq39 was
cancelled after its successor seq40 was queued. None of these queue receipts
is publication evidence.

Three earlier full seq36 proofs were superseded when `main` advanced. This
repeated 15–25 minute end-to-end cost is the current publication bottleneck.
The land owner received native mail sequences 411 and 422. The highest-leverage
repair is reuse of mandatory unit evidence only when exact input closure and
receiver policy permit it across base movement, followed by fresh mandatory
publication evidence and independent remote observation. The
[`FORWARD_PLAN.md`](../work/FORWARD_PLAN.md) already requires this. The factory
owner received the measured 79.8% commit/reproduce share in native mail 419.

## Immediate continuation

```bash
git fetch origin main
git rev-parse HEAD origin/main
build/bin/z23-dev dev land status
build/bin/z23-dev dev agent mail pull --since=422
build/bin/z23-dev dev proof status \
  --root=/home/bob/.local/state/z23/dev/land/wt \
  --local_commit=0a745b42964a7325062c6aaa4278145dad29e0d2 \
  --remote_base=95f9a85d95e7620de77a1b2814769a81b7418743
```

Use a built `z23-dev` whose command catalog includes `dev.land`; the above
`build/bin` path is a command template for a checkout with that binary. If
the proof settles, advance the native land queue with `dev land drive` or
`dev land step` according to its live `discover describe dev.land` contract.
If it reaches `PUBLICATION_INTENT_REQUIRED`, attach only the exact proven
pair's signed intent with `dev land attach`, then drive and verify the remote
receipt and SHA. Do not run another build in the private landing worktree
while its proof is active. Continue seq37 and seq40 after the higher-priority
row settles. Repair the canonical SkyCombat libm declaration under the app
owner's source ownership, rerun its exact factory verifier, and obtain the
remaining native acceptance receipts. Never infer release acceptance from
the accepted frame.

Full commands and raw roots are in
[`2026-09-24-factory-mixed-100.md`](./2026-09-24-factory-mixed-100.md),
[`2026-09-24-factory-100-skycombat-preview.md`](./2026-09-24-factory-100-skycombat-preview.md),
[`2026-09-24-factory-adversarial-qualification.md`](./2026-09-24-factory-adversarial-qualification.md),
and the queued second-peer and isolated-node evidence commits named above.
