<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Agent journey experiment: ontology focus packet

## Question

Can a resuming agent recover one exact work item from the existing ZCODE and
StoryGraph authorities without joining multiple overlapping responses or
trusting narrative memory?

The tested journey slice begins after a task exists. It covers exact goal and
work identity, selected source context, ontology state, missing evidence, and
the next safe action. It does not measure initial repository orientation or
GitHub coordination; those remain the next controlled journey.

## Baseline

The repository entry contract directed a fresh agent through six orientation
documents before source inspection:

| Measurement | Observed value |
|---|---:|
| Documents | 6 |
| Lines | 2,586 |
| Whitespace-delimited words | 23,766 |
| UTF-8 bytes | 180,535 |

The six files were `AGENTS.md`, `docs/work/FORWARD_PLAN.md`,
`docs/DEVELOPING.md`, `docs/CODEBASE_MAP.md`, `docs/AGENT_TRAPS.md`, and
`docs/CODE_FEARLESSLY.md`. An exact model-token count was not observable, so
none is inferred from bytes or words.

For an existing task, the native agent had to join `zcode work status` with
`story show`. The frozen 12-task benchmark measured 3,534 bytes and 3,872 bytes
respectively, or 7,406 bytes together. The canonical `agent_context.v1` root
was present, but no read command exposed its reverified selected source
locations.

StoryGraph command ownership was also concentrated in one 684-line source file
that mixed canonical work loading, causal projection, and JSON rendering.

## Intervention

`story focus` is a bounded read-only projection. It:

- invokes the existing canonical work-status reader with exact roots enabled;
- independently reloads and validates the task wire;
- reloads, parses, roots, and task/source/goal-binds the selected
  `agent_context.v1` bytes;
- returns file paths, starting lines, and excerpt sizes without duplicating
  excerpt bodies;
- returns PROVED, DISPROVED, UNKNOWN, and INCOMPLETE StoryGraph relations;
- returns one largest missing relation, next action, and next safe command;
- stores nothing and creates no parallel task, memory, queue, or evidence
  authority.

Missing context returns UNKNOWN. Multiple valid contexts and context bytes that
cannot be reverified return INCOMPLETE. Neither case exposes source locations.

Projection, canonical loading, and response composition now have separate
source files. The largest file is 455 lines, 33% smaller than the former
684-line mixed-ownership file. The three files total 970 lines; the increase is
the new context revalidation and focus response, not a deletion claim.

## Results

The registered 12-task, three-project benchmark produced:

| Measurement | Before | After | Change |
|---|---:|---:|---:|
| Resumption response bytes | 7,406 | 1,265 | -82% |
| Native responses joined by the agent | 2 | 1 | -50% |
| Selected context bytes | 312 | 312 | unchanged |
| Full project source bytes in fixtures | 816 | 816 | unchanged |
| Accepted feasible tasks | 10/10 | 10/10 | unchanged |
| Correctly refused out-of-scope tasks | 2/2 | 2/2 | unchanged |
| Upstream commits integrated during the slice | — | 2 | observed |
| Merge conflicts during integration | — | 2 | observed |
| Wrong next commands caught before publication | — | 1 | removed |
| Concurrent `make` verification collisions | — | 1 | invalidated and rerun serially |

The focus packet stayed below the 8,192-byte registered list budget. The
benchmark still performed canonical task creation, context selection, candidate
execution, proof, application observation, and acceptance; it did not replace
those transitions with fixtures that merely resembled their outputs.

Focused refusal coverage exercised missing, ambiguous, and unavailable context.
During the product-path review, `zcode work context` was found to report only
selector readiness, not recapture a task context. That initially proposed next
command was removed before publication; non-reverified context now directs the
agent to `zcode work start`.

Upstream advanced by two reviewed commits before integration. Applying this
slice produced two textual conflicts: the generated capability inventory was
regenerated from the combined source, and the StoryGraph conflict was resolved
by carrying the new canonical `accepted_work_root` through the split loader and
projection. The combined focused suites then passed. Duplicate work, exact
model-token count, and time to first correct edit were not instrumented in this
slice; recording zero for those dimensions would be unsupported. The next
experiment must start from a fresh agent, choose a real unowned issue, and
timestamp each journey transition.

One attempted parallel verification batch made independent `make` processes
contend on generated template output. Its affected platform results were
discarded and both Windows and macOS contract gates were rerun serially. The
serial Windows cross-syntax seam passed. The macOS capability matrix passed;
native macOS execution remained unobserved on this Linux host.

## Reproduction

Measured at 2026-08-31T19:09:59-04:00
(2026-08-31T23:09:59+00:00) from source
`0d90a2c05aeb5a9e2cc2d405599702fb360ec07e` plus this change.

- Compiler: `cc (GCC) 16.1.1 20260430`
- CPU: `AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics`
- Host: Linux x86_64

```bash
make -j"$(getconf _NPROCESSORS_ONLN)" fast-compile
make -j"$(getconf _NPROCESSORS_ONLN)" t-fast ONLY=story_graph
make -j"$(getconf _NPROCESSORS_ONLN)" t-fast ONLY=zcode_package_dev
make check-command-input-keys
make check-remote-command-classes
make check-api-reference-generated
make check-capability-inventory-generated
make check-windows-platform-seam
make check-macos-acceptance
```

The Linux C23 compile and Windows cross-syntax seam passed. The macOS capability
matrix passed, but native macOS execution was unobserved on this Linux host and
is not claimed.
