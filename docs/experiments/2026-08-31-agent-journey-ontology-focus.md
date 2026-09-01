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
| Upstream commits integrated during the slice | — | 9 | observed |
| Merge conflicts during integration | — | 5 | observed |
| Wrong next commands caught before publication | — | 1 | removed |
| Concurrent `make` verification collisions | — | 1 | invalidated and rerun serially |
| Exact-receipt bootstrap failures before admission | — | 4 | observed |

The focus packet stayed below the 8,192-byte registered list budget. The
benchmark still performed canonical task creation, context selection, candidate
execution, proof, application observation, and acceptance; it did not replace
those transitions with fixtures that merely resembled their outputs.

Focused refusal coverage exercised missing, ambiguous, and unavailable context.
During the product-path review, `zcode work context` was found to report only
selector readiness, not recapture a task context. That initially proposed next
command was removed before publication; non-reverified context now directs the
agent to `zcode work start`.

Upstream first advanced by two reviewed commits before integration. Applying
this slice produced two textual conflicts: the generated capability inventory
was regenerated from the combined source, and the StoryGraph conflict was
resolved by carrying the new canonical `accepted_work_root` through the split
loader and projection. Five more reviewed commits arrived during exact proof;
their integration produced only one generated-inventory conflict. One final
task-coordination commit arrived during the combined proof and produced one
more generated-inventory conflict. Its fail-closed write-scope collision
predicate complements the task board and focus packet. A final reviewed fix
made malformed or capacity-truncated task evidence fail closed and produced
one generated-inventory conflict. The new
bounded task-board projection and this single-work focus packet expose
different scopes, so neither leaf was discarded as duplicate. The combined
focused suites then passed. Duplicate work across unobserved sessions, exact
model-token count, and time to first correct edit were not instrumented in this
slice; recording zero for those dimensions would be unsupported. The next
experiment must start from a fresh agent, choose a real unowned issue, and
timestamp each journey transition.

One attempted parallel verification batch made independent `make` processes
contend on generated template output. Its affected platform results were
discarded and both Windows and macOS contract gates were rerun serially. The
serial Windows cross-syntax seam passed. The macOS capability matrix passed;
native macOS execution remained unobserved on this Linux host.

The first exact commit/base receipt was admitted 19 minutes 5 seconds after
the commit timestamp. Four preceding attempts failed closed on worktree setup:
missing generated OpenSSL headers, then a skipped zlib-header installation,
then a missing `build/dev-loop/restart.env`, then one private-checkout source
checkpoint command failure. The next retry completed the exact impact-mapped
proof. These are bootstrap measurements, not product-test failures.

## Post-integration orientation rerun

A concurrently integrated cleanup changed fresh-agent orientation from six
mandatory documents to three: `AGENTS.md`, `docs/work/FORWARD_PLAN.md`, and
`docs/DEVELOPING.md`. Source maps, traps, security doctrine, and live handoff
state are now conditional reads.

| Measurement | Before | After | Change |
|---|---:|---:|---:|
| Mandatory documents before editing | 6 | 3 | -50% |
| Lines | 2,586 | 1,276 | -51% |
| Whitespace-delimited words | 23,766 | 8,527 | -64% |
| UTF-8 bytes | 180,535 | 61,166 | -66% |

The rerun still does not establish model-token count or time to first correct
edit. It does remove three unconditional branches and explicitly forbids using
the maintainer live-state handoff as an ordinary work queue.

## Real package retrieval and coordination rerun

The next controlled task used the tracked `packages/zdemo` package and the
user-visible goal “Reject malformed or overflowing `--frames` and `--seconds`
values without opening a window.” The package source root remained
`b16fe46f77995f0b088088e0a66f1f0085cee13a55c74b14b9df571e21c4a080`
through both runs.

The baseline exact-symbol request could not find `zdemo_parse_options`.
Retrying without the override took 3,786 ms and selected `zdemo_world_step` in
`src/zdemo.c`. The resulting authority covered `include`, `src`, and `tests`,
but not the manifest-owned `app/main.c` where argument parsing and window
creation occur.

Two specialists then inspected disjoint claims under focus root
`059e7cf79c5a5ef4b2f73cbaa1fca26688e357be2a0329ec75a30e004ef8443f`.
One inspected `src/zdemo.c`; the other inspected `tests/test_zdemo.c`. Both
DISPROVED that their claimed path could implement or establish the requested
behavior. Together they opened two files, consumed 6,233 source bytes, made
five tool calls, reported one retry, and reported zero duplicate actions. The
slower report completed in 22,353 ms. These are agent-reported process metrics,
not scheduler telemetry.

The intervention reuses two existing authorities:

- the code index now includes conventional package-local `app`, `include`,
  `src`, and `tests` roots on POSIX and Windows;
- work scope and total-source-byte projections add manifest-owned C23 `.c`
  and `.h` files while retaining every build-recipe source path.

The fresh isolated rerun used the same tracked package bytes and produced focus
root `8822303e6653fdd7cf2762e06fb6b95a422a6068b1815c1c6bf0f5e828824dc1`.

| Measurement | Before | After | Change |
|---|---:|---:|---:|
| Exact-symbol lookup | failed | passed | failure removed |
| Work-start retries | 1 | 0 | -100% |
| Successful work-start elapsed | 3,786 ms | 385 ms | -90% |
| Selected symbol | `zdemo_world_step` | `zdemo_parse_options` | target corrected |
| Selected path | `src/zdemo.c` | `app/main.c` | target corrected |
| Selected context bytes | 4,628 | 10,570 | full owning file exposed |
| Manifest-owned C23 source bytes reported | incomplete | 18,840 | complete projection |
| Allowed write scopes | 3 | 4 | `app` added |
| Duplicate specialist actions | 0 | 0 | unchanged |

The exact override intentionally bypasses fuzzy retrieval, so the successful
response reports zero BM25 corpus and ranked files. This experiment proves
exact package-local indexing and manifest-derived authority; it does not prove
better heuristic ranking.

Three counterexamples remained fail-closed. Reusing one goal with different
contexts produced `AMBIGUOUS_CONTEXT`. Starting distinct active tasks with
overlapping scopes produced `WRITE_SCOPE_OVERLAP`. Rerunning the corrected
goal against the original still-live task produced `DUPLICATE_ACTIVE_WORK`.
No task history was deleted to obtain the successful result; the fresh rerun
used an isolated archive of the exact tracked package.

The registered `codeindex` and `zcode_package_dev` groups passed. The latter
parses the actual adapter packet and requires all four package-local scopes.
The 24-gate fast lint and the 374-file Windows cross-syntax proof also passed.
Native Windows and macOS execution remain unobserved in this rerun.

Measured at 2026-08-31T23:07:54-04:00
(2026-09-01T03:07:54+00:00) from source
`8f35c9b66e1a6d6981a91b81d314827e92d1de56` plus this change.

- Compiler: `cc (GCC) 16.1.1 20260430`
- CPU: `AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics`
- Host: Linux x86_64

```bash
make -j"$(getconf _NPROCESSORS_ONLN)" t-fast ONLY=codeindex
make -j"$(getconf _NPROCESSORS_ONLN)" t-fast ONLY=zcode_package_dev
make lint-fast
make check-windows-cross-syntax
```

## Specialist continuation and application proof

Two specialists continued from focus root
`8822303e6653fdd7cf2762e06fb6b95a422a6068b1815c1c6bf0f5e828824dc1`.
The code specialist claimed `app/main.c`, changed only that path in the
contained candidate, and reported PROVED after a strict build, 16 invalid
argument cases, and valid headless execution. The proof specialist claimed the
existing package test surface, changed nothing, and reported INCOMPLETE: the
declared KAT explicitly excluded the app/window translation unit, so it could
not observe CLI parsing or window creation. The two specialists produced no
write collision.

| Measurement | Code specialist | Proof specialist | Combined observation |
|---|---:|---:|---:|
| Changed paths | 1 | 0 | 1, no collision |
| Files opened | 4 | 10 | agent-reported; unique union not measured |
| Context bytes | 26,944 | 51,847 | 78,791 agent-reported bytes |
| Tool calls | 10 | 14 | 24 |
| Duplicate actions | 0 | 2 | 2 |
| Retries | 0 | 2 | 2 |
| Elapsed | 179,953 ms | 156,409 ms | wall-clock overlap not instrumented |
| Result | PROVED | INCOMPLETE | complementary evidence |

The first independent production compile disproved part of the code report:
strict C23 compilation without `_POSIX_C_SOURCE=200809L` could not see the
existing POSIX clock declarations. Repeating with that feature-test macro
passed. This counterexample is retained because the report's compile claim was
too broad even though its parser behavior was correct.

The retained implementation moved the two bounded numeric parsers into the
package's reusable source and header instead of leaving them private to the
application. The existing package-anatomy KAT now tests complete syntax,
conversion overflow and underflow, the frame-count bound, milliseconds
overflow, null inputs, unchanged outputs on failure, and valid decimal forms.
The application calls those exact functions and returns 2 on failure before
the window dispatch expression.

An instruction check found a separate fresh-checkout failure: the tracked
package README said `make zdemo`, but the tracked GUI application list omitted
`zdemo`, so the promised rule did not exist. Registering the existing tracked
package made the generated two-translation-unit build path real and reused the
same Linux, macOS, and Windows host seams as the other GUI applications.

The production binary then rejected 19 malformed, overflowing, or
underflowing argument cases with exit status 2 and no RGFW, window, or frame
presentation output. `--frames=2 --quiet` completed its moving-frame proof;
`--seconds=.001 --help` established that a valid duration parsed before the
help-only exit. The package-anatomy gate compiled and passed all three tracked
GUI package KATs. Time to first correct edit remains UNKNOWN because neither
specialist recorded the timestamp of its first edit; elapsed completion time
is not substituted for that metric.

Measured at 2026-08-31T23:33:49-04:00
(2026-09-01T03:33:49+00:00).

- Compiler: `cc (GCC) 16.1.1 20260430`
- CPU: `AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics`
- Host: Linux x86_64

```bash
make check-package-anatomy
make -j"$(getconf _NPROCESSORS_ONLN)" build/bin/zdemo
```

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
