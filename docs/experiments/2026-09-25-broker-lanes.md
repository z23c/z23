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

## Sixteen distinct factory revisions and eight-lane node load

The factory fixture now generates 16 cumulative, test-checked C23 statistics.
The revision offset and preview expected value are bound to the requested
statistic, so every revision is a distinct source and every preview checks its
actual result. The bounded ledgers live under `test-tmp/factory-distinct-{2,4,8,16}-20260925/`
and `test-tmp/factory-rev9-20260925/` for the one-change point. All 31 jobs
across the five runs compiled, previewed, tested and passed the offline
factory, with zero duplicate source hashes. One normal broker scope with eight
CPU slots admitted each batch; this is offered concurrency inside that scope,
not proof that the host admitted the same number of independent broker lanes.

| Offered changes | Batch wall | Good/distinct | CPU sum | Peak job RSS |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 3.773 s | 1/1 | 3.135 s | 97,792 KiB |
| 2 | 6.032 s | 2/2 | 5.843 s | 97,792 KiB |
| 4 | 12.280 s | 4/4 | 18.416 s | 98,048 KiB |
| 8 | 13.846 s | 8/8 | 36.197 s | 98,048 KiB |
| 16 | 5.261 s | 16/16 | 66.522 s | 98,304 KiB |

The nonmonotonic wall times show why these short batches cannot establish a
sustained rate under concurrent host work. The 16-change run's
`fully_accepted_loc` remains zero: it does not include publication or remote
observation.

An eight compact-lane isolated-node trial with the old eight-revision fixture
admitted 8/8 lanes, passed 16/16 factory jobs, but duplicated eight source
hashes; node RPC baseline/load p95 was 9/10 ms. Its raw record is
`test-tmp/broker-shared-node-8-v5b-20260925/`. The first distinct-revision
trial admitted 8/8 and produced 16 unique roots, but six previews failed
because the harness expected a result of one for every statistic. Its node RPC
p95 rose from 8 to 151 ms. After fixing preview expectations, the next trial
admitted only 4/8 lanes within the 30 s bound under concurrent shared-host
work. All eight admitted factory jobs passed, while node RPC p95 rose from 8
to 136 ms. The records are
`test-tmp/broker-shared-node-8-distinct-20260925/` and
`test-tmp/broker-shared-node-8-distinct-v2-20260925/`. Neither trial qualifies
eight lanes for default admission: one violates the node latency target and
the other does not admit the requested width. The default remains two.
