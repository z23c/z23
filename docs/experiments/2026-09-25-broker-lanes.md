<!-- Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 -->

# Bounded broker lane qualification, 2026-09-25

This is a development-host capacity experiment, not public-node or Commons
release acceptance. The measured host is an AMD Ryzen 9 7950X3D with 32
logical CPUs and 94 GiB installed RAM. The broker admits work within 28
logical CPUs and 48 GiB, reserving two physical cores outside the development
slice. Its ordinary default remains two compact lanes. Wider compact admission
requires an explicit `--qualification-width 4|8` trial.

`tools/dev/broker-lane-qualification.sh` starts one isolated regtest node in a
hotload scope, samples `getblockcount` 100 times before factory work and during
the work, and starts separately admitted compact scopes. Each scope runs two
real C23 textstat changes through the existing factory qualification. The
record includes nanosecond queue/admission timestamps, broker IDs and events,
per-job CPU time, maximum RSS, file-system I/O, source hashes, RPC latency and
errors, node survival, and Linux CPU/I/O/memory pressure deltas. The node is
at height 0; this measures local RPC responsiveness and cannot establish chain
sync, block processing, P2P peer health, or canonical-node safety.

| Trial with checkout HEAD `ece501608` | Factory results | Distinct / duplicate source hashes | Work interval | RPC baseline p95 | RPC load p95 | RPC errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Two compact scopes, shared node, concurrent QEDC work | 4/4 | 2 / 2 | 4.595 s | 8 ms | 8 ms | 0 |
| Four compact scopes, shared node | 8/8 | 2 / 6 | 11.952 s | 9 ms | 277 ms | 0 |
| Four compact scopes, shared node, pressure capture | 8/8 | 2 / 6 | 14.096 s | 30 ms | 141 ms | 0 |
| Four compact scopes, experimental hotload scheduling priority | 8/8 | 2 / 6 | 11.577 s | 12 ms | 305 ms | 0 |
| Two compact scopes, four distinct revisions, concurrent QEDC work | 4/4 | 4 / 0 | 8.586 s | 48 ms | 18 ms | 0 |

The two-lane raw record is
`test-tmp/broker-shared-node-2-20260925/`; its load pressure deltas were
20,846 CPU-some microseconds, 66,861 I/O-some microseconds, and 9
memory-some microseconds. The four-lane pressure record is
`test-tmp/broker-shared-node-4-pressure-20260925/`; its corresponding deltas
were 86,793, 2,764,144, and 2,171 microseconds. Its four queue waits were
28,544,409, 64,287,467, 263,497,000, and 301,992,033 nanoseconds.
The experimental hotload priority change worsened this workload and was
reverted. The forward plan calls for warm bounded local queries below 100 ms
p95; the measured four-lane trials exceeded that threshold. The policy stays
at two lanes until a real node-health trial demonstrates otherwise.

The distinct-revision run is
`test-tmp/broker-shared-node-2-v5-20260925/`. The two factory scopes entered
within 36 ms of queueing, and the isolated node remained alive. Its pressure
deltas were 20,209 CPU-some, 718,428 I/O-some, and 945 memory-some
microseconds. Four unique revisions passed the factory and node RPC load p95
was 18 ms. The 48 ms baseline reflects other admitted QEDC work on the host;
this experiment cannot establish that Z23 alone caused the baseline value.

The later `test-tmp/broker-shared-node-4-v5b-20260925/` run is an admission
failure, not a factory result. An unrelated Z23 release proof admitted after
the node baseline, so no compact lane entered; the harness cancelled the
queued wrappers after a bounded wait. The baseline and load RPC p95 were 139
and 144 ms under that shared-host pressure. This observation reinforces the
need to report admitted work separately from offered work.

The earlier factory fixture repeated two source hashes across lanes. The
distinct-revision trial offsets each lane, yielding four unique changes.
Dividing either count by a short work interval would overstate sustained useful
throughput. The factory ledger proves compile, preview, test and offline
independent-store checks. It does not publish a Commons package or produce a
remote observation receipt, so accepted C23 LOC/hour remains unmeasured here.
Those stages require a separate end-to-end qualification.
