<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Bounded work-root transfer and cached possession

Date: 2026-09-25. Base source: `48c4e8ca4a151f7c7c4ba049f3a49e6233ac173d`.
Host: AMD Ryzen 7 PRO 8840U. Compiler: GCC 16.1.1 20260430, C23.

The work wire carries a signed REQUEST with a context package root, or a
signed RESULT with a receipt and output package root. The existing content.v2
swarm fetches a root-committed manifest before missing chunks. Its store
verifies each received chunk at the manifest coordinate. The work adapter now
starts these directed fetches with a persistent caller byte ceiling. Context
fetches use the 64 MiB package-store ceiling; result fetches use the matching
signed request's `max_output_bytes` plus the output carrier's 32-byte action
binding, capped at 64 MiB. A rejected fetch does not schedule a WANT.

A previously complete local CAS root is also checked against a new bounded
caller's ceiling. Both the live COMPLETE slot and the reopened-store fast path
return `BYTE_LIMIT` for an oversized root. A compatible caller still gets
`ALREADY_COMPLETE`. The regression in the registered `zcode_swarm` group
exercises both paths with a completed package and a smaller bound. The older
fast path returned `ALREADY_COMPLETE` without examining that bound.

The ceiling counts manifest-declared content bytes. It excludes manifest
framing and transport overhead. A root identifies bytes, and a complete CAS
status is not a local acceptance verdict; the downstream work-output and
context readers re-verify bytes and action binding. The context's task-specific
`max_context_bytes` remains inside the fetched, independently verified context,
so the prefetch ceiling is the receiver's 64 MiB store limit. An exact signed
prefetch context limit would require an authenticated request field or a
separately available task object.

The registered four-node `zcode_swarm_net` package lifecycle fixture records
cold, repeat, and source-edit objects and verified payload bytes, then checks
receiver CAS possession and independent local build evidence. It uses isolated
node fixtures rather than the three development hosts. Those counters do not
include framing, retransmissions, CPU verification time, or six-host effects.

## Observed verdicts

The first registered run was RED: the new cached-root fixture reused a node
whose earlier cases had failed and cancelled requests, so its ordinary fetch
did not complete. The four new cached-root assertions then had no complete
root to examine. Its child log SHA-256 is
`a3975f23f67a8fb83613844612de4a5247213fb7f78033547a7613c877d37685`
(`test-tmp/test_parallel_650065_744.log`). The fixture now uses a fresh
store, engine and package for the complete-root case; the production ceiling
code did not change between the RED and GREEN runs.

The corrected `make CC=gcc -j2 t-fast ONLY=test_zcode_swarm` run passed all
four matching registered groups, with zero skips or environment omissions.
Its complete wrapper log SHA-256 is
`e477c2a2a579ec366df7b3b21700d388de807be459e207bad2a678e3f0e7fde6`.
The new cached-root assertions all passed before and after store restart.
The group test body took 117.023 s; the ten-package lifecycle subcase took
65.939 s. These are fixture wall times under concurrent host work, not
verification CPU time or fleet queue latency.

After extracting the bounded fetch and cached-result helpers, the final source
passed `make CC=gcc -j2 lint-fast` (33 gates, log SHA-256
`59c46cf5f24c46cac73cc80813952e15e8a1c608c703279534157ca4a00d6397`).
The final-source `make CC=gcc -j2 t-fast ONLY=test_zcode_swarm` passed the four
matching groups with zero failures, skips, or environment omissions. Its log
SHA-256 is `35ff406332b5d63362ee7782f725b73e6e73d4fa63840c472b3691c9ab712545`.
The test body took 37.192 s with 16 runner workers on the same shared host.

The lifecycle receipt (`zcl.package_graph_lifecycle.v2`) reported:

| Case | Missing objects | Verified payload transferred | Already present / reused |
| --- | ---: | ---: | ---: |
| Cold ten-package graph | 123 | 404,688 bytes | 5 objects; 13,582 bytes reused |
| Exact repeat | 0 | 0 bytes | 128 objects; 406,787 bytes present |
| One source edit | 4 | 2,799 bytes | 6 objects; 5,777 bytes reused |
| One header edit | 4 | 2,382 bytes | 6 objects; 6,194 bytes reused |
| Revert to prior root | 0 | 0 bytes | 10 objects; 7,658 bytes reused |

These are separate fixture scenarios. The repeat's 406,787 bytes is the
content already present at that stage; it is not a measured subtraction from
the cold transfer's 404,688 bytes. The source edit reused 5,777 of the
8,576 bytes represented by its transferred-plus-reused counters (67.4%).
The fixture also observed the original publisher disappear before onward
transfer, and an explicit local build reused ten prior receipts on repeat.
It did not measure packet bytes, verification CPU, a host partition, or the
development fleet's actual CAS route.

## Reproduce

```bash
bash tools/scripts/worktree_init.sh
make CC=gcc -j2 t-fast ONLY=test_zcode_swarm
make CC=gcc -j2 lint-fast
git diff --check
```
