# Reflex substrate measurement and coverage audit

Measured 2026-08-12 on the merged reflex implementation plus the general
substrate candidate. The latency receipt is
`build/dev-loop/reflex-reactor-benchmark.json`; the weighted history and strict
replay receipts are `build/dev-loop/substrate-history-benchmark.json` and
`build/dev-loop/reflex-coverage-audit.json`. Build receipts are intentionally
local/ignored; this page preserves the reviewed results and reproduction
commands.

## Warm-loop measurement

`make reflex-reactor-bench` ran 20 distinct green edits, one compile-valid
behavior red, and 20 exact edit/revert cache cycles through one resident
watcher. Times below are event feedback latency, not command-dispatch wall
time.

| Measurement | p50 | p95 |
|---|---:|---:|
| edit detection | 15 us | 22 us |
| immutable epoch creation | 115 us | 366 us |
| impact calculation | 82 us | 327 us |
| `IMPACT_READY` | 252 us | 642 us |
| compile diagnostic | 87.064 ms | 119.284 ms |
| compiler body | 33.281 ms | 70.548 ms |
| `HOT_SHADOW` story | 90.931 ms | 110.687 ms |
| forked story runner | 4.297 ms | 5.053 ms |
| cancellation to newer impact | 247 us | 538 us |
| exact edit cache feedback | 4.581 ms | 6.180 ms |
| exact revert cache feedback | 4.579 ms | 5.852 ms |

The first useful red arrived in 129.122 ms. The resident watcher plus reaped
children used 4.560 CPU-seconds over 14.721 wall-seconds (30.98%). The edit
path reread 3,191 bytes at p50/p95. Distinct candidates created 21 compiler
processes, 21 module-linker processes and 21 forked stories; exact cache cycles
created zero compiler/linker processes. No foreground test process ran.

Every latency-firewall counter was zero: Git, GitHub, Make, command shells,
SQLite, DHT/network/remote work, publication, storage-ack waits, full links,
full-tree scans and full suites were absent. A saturated shared host ccache was
measured inflating compile p95 to 477.523 ms; the resident watcher now owns a
bounded checkout-local cache, restoring the protected ~90--114 ms story
baseline without changing proof or assertions.

## Recent-edit coverage

`make reflex-coverage-audit` froze the last 100 production-C commits at source
head `0ddfba7f641990086973117e4907d180cc67b672`; the 310-row history multiset is
sealed by SHA-256
`49251d335f01a092b02478bcfb037a65aff216167310ad9d1bd37085e7b6052d`.
Thirty-one forbidden authority edits are excluded, leaving 279 normal edit
occurrences. Each registered fast owner received a warm-up plus a distinct
timed source edit through the real resident watcher.

| Useful feedback bound | Occurrences | Coverage |
|---|---:|---:|
| under 100 ms | 151 / 279 | 54.12% |
| under 250 ms | 183 / 279 | 65.59% |
| under 1 second | 227 / 279 | **81.36%** |
| slower-proof fallback | 52 / 279 | 18.64% |

Every fallback class is exact:

| Reason | Occurrences | Unique paths | Meaning |
|---|---:|---:|---|
| existing module ABI does not admit owner | 32 | 24 | restart/full proof remains required |
| mutable file-scope state | 15 | 7 | state must first move behind a static owner or immutable input |
| direct global/state-owner dependency | 4 | 4 | calculation seam has not yet been isolated |
| dev RPC cookie absent | 1 | 1 | legacy app handler's local probe still requires a running dev node |

The highest-churn eligible owners became either direct pure service islands or
static authority shells mapped through `engine/composition/hotswap_shadow_owners.def` to a
pure candidate core. Static shells receive an exact semantic compile but are
never linked or loaded. Package, process, database, signing, wallet, network,
publication and other real authority stays in the resident/static code.

## Load-sensitive defect found by the audit

One strict replay initially scored 79.93% because four weighted edits to
`zcode_moderation_view_service.c` timed out. The preserved sealed journal
proved both `STORY_GREEN` records had been produced in roughly 0.3 seconds
while `drive` slept for 5.98 seconds. The consumer watched only the workspace
parent, indirectly depending on a ring-file modification or child-directory
record creation to wake it. The fix directly watches both producers: the
volatile ring file and sealed `cycle-events` directory. It adds no retry,
polling, sleep, or weakened assertion. Twenty immediate watcher turnovers on
the former victim were 20/20 green; the full replay then reached 81.36%.

## AI stream and proof boundary

An agent attaches once:

```text
z23-dev dev begin
z23-dev dev loop events --after=<cursor> --format=jsonl
```

It can continue thinking after each edit while the stream emits resumable
events and heartbeats. Red stories carry a bounded
`zcl.dev_diagnostic_capsule.v1`. A green story seals the one-way
`zcl.dev_proof_handoff.v1`: candidate/source epoch, affected component/count,
action, immutable proof-input root, and exact focused-evidence root. Later
server-side proof may add receipts but cannot delay, mutate, or invalidate the
already emitted reflex result. No networking was added.

Stage-0 remains load-bearing: the candidate watcher never certifies its own
replacement. Before publication, the saved pre-change executable must run the
final source-wide gate against the exact candidate source.
