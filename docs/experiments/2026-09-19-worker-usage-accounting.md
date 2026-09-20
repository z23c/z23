<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Turn-local worker usage accounting

Source baseline: `93d61f73b8f5b6b7b493eadd3273053ddb41f50a`.
Host: Linux, AMD Ryzen 7 PRO 8840U; GCC 16.1.1 20260430.
Initial validation observed on 2026-09-19T19:26:15-04:00 /
2026-09-19T23:26:15+00:00.

## Observed failure

The refused `portable-proof-prerequisites` worker session recorded thirteen
provider completions: 526,860 input, 2,799 output and 477,885 cached tokens.
The local receipt retained the input/output totals but recorded zero cache
reads. The durable export reported no gaps, duplicate records or parse errors.
Its redacted export SHA-256 is
`7b288cad12589787be703b69586964afa14638816f36a6861d1382c3dd053424`.
This is usage evidence, not monetary billing evidence or a successful task.

The existing `dev agent outcomes` command, using its `usage_log` input on the
durable session log, independently produced the same totals: thirteen distinct
events, 48,975 uncached input tokens, 477,885 cache-read tokens, 2,799 output
tokens and 1,054 reasoning tokens. Reasoning is a reported subset, not an
additional output charge. The scan reported zero duplicate, malformed,
unreadable or unkeyed usage events and no truncation. The model was
`muse-spark-1.3-contributor`; actual monetary cost remains UNKNOWN.

Attempt 1 was claimed at 2026-09-19T22:50:22+00:00 and its refusal receipt
was timestamped 2026-09-19T22:50:59+00:00. Executor wall time was 36,752 ms;
the worker receipt rounded it to 37,000 ms. Queue time is unmeasured. No
candidate from this attempt was accepted, no tests ran, and no publication
or remote receipt completed. The failed attempt remains included in usage.

The installed host's offline protocol schema specifies session-wide
`cumulative` prompt/output/total counters without cache counters. Per-event
`usage` carries cache counts, while `promptTokens` and `totalTokens` carry
the host's counted-once derivation. Schema export SHA-256:
`ed442d494cf8cdb85f0b1487f8d0f54b7570548561c6c92d6def09ce107e1664`.

The client read cache usage from the cumulative object, losing it, and copied
session-wide totals into turn outcomes. Its earlier duplicate-delivery and
budget fixtures omitted the cumulative object present on the real protocol.

## Regression and correction

```bash
make -j2 t-fast ONLY=muse_session
```

Adding protocol-shaped cumulative readings made the registered group fail:
first-turn budget completion, retained cache usage and second-turn-local
usage assertions failed. All earlier assertions passed. The canonical runner
repeated the failure alone; one group ran, one failed, zero skipped. Its
test-body measurement was 1,366 ms; the retained failure log was finalized
at 2026-09-19T19:22:48-04:00 / 2026-09-19T23:22:48+00:00.

The client now accumulates deduplicated per-event counted-once readings,
retains event cache counts and leaves session cumulative totals out of turn
outcomes. Raw terminal counters reconcile with normalized event evidence;
contradictions refuse settlement and further turns on that session. Settlement
checks the same budget as streaming, and observed usage is retained after a
failed wait. Saturating addition and subtraction-based limit checks prevent
arithmetic wraparound from admitting another turn.

After the initial event-fold correction, the same registered group passed:
one group ran, zero failures or skips, test-body time 802 ms. These two body
times do not establish a speedup.

The final focused command selected exactly `test_muse_session` and
`test_devagent_muse_run`; both passed. Added settlement fixtures cover two
distinct completions plus duplicate delivery, cache-exclusive provider input,
matching and contradictory terminal aggregates, refusal of another turn after
unresolved usage, and terminal-only over-cap consumption. Independent code
review approved this protocol-valid accounting scope; that review is not
real-provider journey acceptance.

All 32 fast lint gates passed. Bash measured 104.395 seconds for the complete
`make -j2 lint-fast` command; its gate runner reported 91.802 seconds with
twelve workers, exceeding its 75-second soft budget. A separate publication
proof was live on this host. These conditions are recorded, not adjusted away.
The preceding attempt to time the command with `/usr/bin/time` could not start
because that executable was absent; Bash timing was used for the actual run.
The generated capability inventory was refreshed and its consistency check
passed with 1,500 capabilities and 1,149 registered roots resolved.

## Completion measurement and limits

The baseline build was observed live by 2026-09-19T19:18:25-04:00 /
2026-09-19T23:18:25+00:00. Its exact dispatch timestamp was not retained, so
total task duration remains unknown, not the reported test-body duration.
Build, queue, proof and landing waits must be included before reporting total
completion latency. No matched-workload speedup, dollar cost, successful real
worker candidate, canonical publication or independently observed remote SHA
is established by this fixture result.

The earlier failed worker attempt was reconciled through the existing queue
as `refused`, with no requeue. No additional provider call or budget increase
was used to diagnose or test this correction. Existing bounded cursor replay
protection is not a claim of unlimited replay deduplication.

## Current-base extraction

On 2026-09-19T20:10:00-04:00 / 2026-09-20T00:10:00+00:00, the accounting
implementation and evidence were extracted onto canonical source
`a115621056bd31fc21a22b22630b89d0f6f6963a`. Source and tests applied without
conflicts; the capability inventory was regenerated from that exact source.
The preceding integration backlog remains separate and preserved. Independent
scope review found no apparent accounting dependency on its worker-status,
portable-build or model-selection changes. Earlier tests establish only the
earlier source identity; extracted-source acceptance and publication require
fresh evidence. The Sep 19 comparison baseline `61cb7b9bb` is unchanged, and
no comparison score is raised by extraction or fixture passes.

Fresh extracted-source validation started at 2026-09-20T00:11:46+00:00.
`make -j4 CC=gcc t-fast-exact ONLY=test_muse_session,test_devagent_muse_run`
passed both groups with zero skips or cached groups. The complete cold
build/test command took 389.463 seconds; test-body time was 37.952 seconds.
The test-runner SHA-256 was
`682698628e2fce1d5b801b5e04571466a1d866417236d3c538938ce78b15a52a`.
Pinned Tor archive, source and compiler provenance passed before the run.

The subsequent `make -j2 CC=gcc lint-fast
check-capability-inventory-generated` passed all 32 fast gates and the
inventory derivation/selftest. Complete command time was 39.751 seconds;
the lint runner reported 13.157 seconds with twelve workers. Independent
review confirmed that implementation, header and test changes match the
original repair's stable patch ID
`9cbb098f1ff2f9e47dca7c3977719092a1e2daff`. That review does not establish
full publication proof, real-worker acceptance or a matched speedup.
