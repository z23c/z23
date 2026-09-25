<!-- Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 -->

# Resident reflex edit to behavior, 2026-09-25

The bounded raw receipts are
[`2026-09-25-reflex-stages-pre.json`](2026-09-25-reflex-stages-pre.json)
and [`2026-09-25-reflex-stages-post.json`](2026-09-25-reflex-stages-post.json).
Each records 31 distinct, compile-valid edits to the exercised vault decision
function, 30 warm samples, one cold sample, one compile-valid wrong-behavior
edit, and 20 exact edit/revert cache cycles. The shadow story requires the
candidate's loaded mapping root to equal its built module root and reports
`candidate_bytes_executed=true` for every distinct edit. The wrong-behavior
edit produces `STORY_RED` in 72,798 us before and 73,124 us after. Source is
restored after each run. All times below are monotonic microseconds.

| Stage | Before warm p50/p95 | After warm p50/p95 |
| --- | ---: | ---: |
| Edit start to `EDIT_SEEN` | 282,720 / 295,364 | 49,667 / 71,013 |
| Impact calculation | 690 / 990 | 727 / 908 |
| Compile | 46,195 / 49,054 | 47,869 / 53,835 |
| Link | 15,246 / 17,246 | 15,540 / 19,598 |
| Load or spawn | 408 / 871 | 365 / 868 |
| Execute frozen story | 10 / 16 | 15 / 19 |
| Story event to visible `dev drive` reply | 4,831 / 9,191 | 2,806 / 9,599 |
| Total edit start to visible reply | 371,279 / 384,098 | 129,954 / 166,909 |

Cold total was 78,538 us before and 84,404 us after. The largest measured
warm delay was before `EDIT_SEEN`: the watcher synchronously ran the affected
proof after a useful story, delaying the next edit. The single optimization
moves that existing proof into the cancellable proof worker after publishing
`PROOF_PENDING`. A new edit can now reach the watcher while the older proof
runs; the proof and its acceptance criteria are unchanged. These measurements
establish foreground latency, not completion of the later affected or full
proof. Both runs used the same shared host and `devbuild` normal admission;
other admitted jobs may account for tail variation.

Each run recorded 32 compiler children, 32 module linker children and 32
shadow forks across the 31 green edits and one red edit. Each distinct sample
had one compiler, one linker and one shadow fork; the foreground `dev drive`
client is one additional process. Plan cache hits were 30/31 and artifact
cache hits 0/31 for distinct edits. The 20 exact edit/revert cycles used zero
compiler and linker children. The measured reflex firewall counts were zero
for Make, shell, Git, network, remote and publication operations, and full
repository scans. CPU time for the watcher plus reaped children fell from
10.05 s to 6.04 s over the bounded runs; watcher peak RSS was 31,716 KiB
before and 25,552 KiB after. These process CPU totals exclude still-running
detached proof work at the instant the benchmark stops, so they are not a
complete proof-work cost comparison.

The raw receipts retain every edit epoch, exact candidate and loaded module
root, per-edit stage and process counts, cache result, latency firewall,
resource sample and target verdict. `make reflex-reactor-bench` reproduces the
bounded experiment and enforces the existing reflex latency targets.
