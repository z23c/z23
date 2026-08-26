# ZCODE C23 Development Product

Status: owner-directed v0.1 product specification and measurement ledger,
started 2026-08-07. This is the active contract for turning the existing ZCODE
development-network primitives into one ordinary C23 development loop.

## Mission and product promise

> **Z23 is a metaverse where people and AI create real things together,
> and nobody owns the world they build in.**

For this product, a "real thing" is an exact C23 source change with bounded
context, an isolated candidate, reproducible build and test evidence, review,
and an explicit human decision. The developer owns that decision. An AI may
propose and repair a candidate; it cannot accept, publish, or assign authority
to its own output.

The ordinary interaction is intentionally small:

```text
z23-dev zcode project inspect --input='{"workspace":"."}'
z23-dev zcode work start -datadir=/tmp/z23-work --input='{
  "workspace":".",
  "goal":"Make the parser reject overflowing lengths",
  "profile":"standard"
}'
z23-dev zcode work run -datadir=/tmp/z23-work --input='{"work":"latest","adapter":"manual"}'
z23-dev zcode work status -datadir=/tmp/z23-work --input='{"work":"latest"}'
z23-dev zcode work accept -datadir=/tmp/z23-work --input='{"work":"latest"}'
```

The happy path accepts no raw roots, canonical wire hex, timestamps, toolchain
hashes, proof-policy wires, or action IDs. Expert commands and full roots remain
available underneath and in an `expert` result section.

## Authority and reuse audit

This is integration, not a new protocol. The following existing owners already
bind every authoritative fact required by v0.1:

| Fact | Existing authority |
|---|---|
| exact source and candidate trees | ZVCS source capture and CAS |
| bounded model context | `zcl.zcode.agent_context.v1` and code index |
| goal, limits, recipe, lock, policy | `zcl.zcode.task.v1` |
| permitted edits | `zcl.zcode.write_scope.v1` |
| source change | `zcl.zcode.patch.v1` and `candidate.v1` |
| fixed build/test/fuzz input | `package_action_input.v1` |
| execution evidence | signed ZBuild `work_receipt.v1` |
| evidence evaluation | `proof_set.v1` |
| review | `review.v1` plus signed review work receipt |
| lifecycle | FRONTIER, CANDIDATE, and PROVEN lane receipts |
| human acceptance/publication | existing `zcode work accept` and PROVEN accepted-work/lane owners |

Therefore v0.1 adds **no canonical domain**. Project summaries, proof-profile
names, adapter packets, diagnostic capsules, human work IDs, and work-session
status are display or rebuildable local projections. They are never accepted
as authority without reloading and re-verifying the full canonical objects.
No second CAS, scheduler, task authority, package format, proof system,
identity system, worker ledger, transport, or truth database is permitted.

## P0 born-red workflow measurement

The current expert workflow was measured from commit
`32671b9bc8b9413a94a5073e2c4d4764496abe39` in isolated `/tmp` workspaces and
datadirs. No service or live datadir was used. The packages are permissively
licensed: `zclassic23/sha3` (MIT), `zclassic23/codec` (Apache-2.0),
`zclassic23/base` (Apache-2.0 with preserved upstream notices), and the small
MIT `fixture/tiny-lines` standalone library.

The first command exposed a correctness defect before measurement could begin:
the documented numeric `publisher_sequence` was rejected by input
normalization, while a string passed normalization and was rejected by the
handler. The born-red regression was added first. Commit `32671b9bc` fixes the
normalizer and passed `command_input_bounds`, `command_registry_catalog`,
`native_api_contract`, lint, and the 903-group pre-push suite (22 documented
self-skips).

### Exact observed inputs and outputs

`zcode package dev prepare` derived the source authority but required a
compressed publisher key and sequence, and returned release, manifest, recipe,
dependency-lock, and API-capsule wire hex in addition to their roots:

| Project | Project bytes | Files | Public headers | Dependencies | Prepare time |
|---|---:|---:|---:|---:|---:|
| SHA3 | 17,592 | 7 | 1 | 1 | 0.05 s |
| codec | 27,589 | 7 | 1 | 1 | <0.1 s |
| base | 68,638 | 20 | 9 | 0 | <0.1 s |
| tiny-lines | 1,974 | 7 | 1 | 0 | 0.07 s |

`zcode package dev improve` advertises 39 possible keys. Its plan path
required eight expert inputs:

```text
workspace, dependency_lock_hex, write_scope_csv, acceptance_recipe_hex,
model_policy_root, goal, proof_policy_hex, expires_unix
```

In practice it also required `mode=plan`, an isolated datadir, and an exact
`context_symbol` to obtain useful context. The caller manually supplied a
36-byte proof-policy wire, the full recipe and dependency-lock wires, a
64-hex model policy root, write-scope CSV, and an epoch expiry. Plan results
led with nine roots and told the user to perform an adapter handoff that no
command implements.

| Task class / project | Requested symbol | Selected / total bytes | Files | Time | Result |
|---|---|---:|---:|---:|---|
| seeded split-write repair / SHA3 | `sha3_256_write` | 11,304 / 17,592 (64.3%) | 1 | 0.35 s | `AWAITING_CANDIDATE` |
| malformed/overflow repair / codec | `zcl_codec_read_u16_bytes` | 9,776 / 27,589 (35.4%) | 1 | 0.50 s | `AWAITING_CANDIDATE` |
| bounded checked API / base | `zcl_size_mul` | 0 / 68,638 | 0 | 0.64 s | failed: inline public API was not an exact indexed symbol |
| bounded checked API / base retry | `zcl_result_make` | 1,755 / 68,638 (2.6%) | 1 | 0.22 s | `AWAITING_CANDIDATE`, but context did not match the goal |
| null/UB repair / tiny-lines | `tiny_count_lines` | 210 / 1,974 (10.6%) | 1 | 0.36 s | `AWAITING_CANDIDATE` |

Compile/test iterations were zero because the missing adapter stage prevented
candidate admission. No task reached CANDIDATE or PROVEN. The measurement did
not fabricate a candidate or claim an end-to-end result: the attempted current
workflow is born-red specifically because its documented sequence ends at an
unimplemented manual handoff. Even after a caller manually creates a candidate,
the foreground CLI queues ZBuild and exits; it provides no single command that
runs the worker, gathers evidence, reviews it, and returns to the human.

The present goal-to-acceptance path is at least seven product steps—prepare,
plan, external context extraction/edit, admit, worker execution, evidence, and
accept—and exposes roots or wires at every boundary. This establishes the v0.1
baseline: **more than five commands, at least eight expert fields, three manual
wire/root constructions, no adapter front door, and no human result screen.**

## Product invariants

1. The authoritative workspace is read-only until explicit human acceptance.
2. Every candidate attempt is captured in an isolated workspace and a distinct
   canonical candidate tree before execution.
3. Project and work aliases resolve to and re-verify full canonical roots.
4. Profiles only compile into exact existing proof policies; they never weaken
   explicit project requirements.
5. Context selection is deterministic, bounded, explained, and non-authoritative.
6. Fixed build, test, fuzz, and review actions create the only usable evidence.
7. Model identity is provenance, never truth or acceptance authority.
8. Read commands do not create a workspace, CAS, datadir, or projection.
9. Every blocked state names the stage, preserved evidence, retry safety, and
   next safe command.
10. A human alone accepts or rejects the exact candidate and evidence.

## Ordered implementation slices

### P1 — project inspection and initialization

Add `zcode project inspect`, `zcode project init plan|commit`, and
`zcode project status`. Inspection derives package name/layout, headers,
sources, tests, include directories, libraries, existing package metadata,
recipe, target-inclusive lock, likely write scopes, resource ceilings, and a
suggested proof profile without writing. Initialization is plan/commit,
correctable, symlink/special-file rejecting, overwrite refusing, and stores
only the existing canonical objects.

### P2 — named proof profiles

Compile `quick`, `standard`, `strong`, and `release` into exact existing
`proof_policy.v1` fields. Quick means build and declared tests. Standard adds
warning-fatal compile and sanitizers. Strong adds deterministic fuzz and local
reproduction. Release adds distinct review and approved reproduction
requirements. The response always exposes the expanded policy and root.

### P3 — bounded goal context

Tokenize the goal and search indexed symbols, signatures, paths, text, callers,
callees, include edges, and tests in a deterministic order. Exact symbol and
signature matches outrank broad text. Each excerpt says why it was selected;
dropped candidates and budget exhaustion are explicit. Report selected bytes,
total bytes, files, symbols, and generation time. The ordinary target is below
256 KiB; exact-symbol overrides remain available.

### P4 — one work front door

Add `zcode work start|run|show|status|cancel|accept` as a thin orchestration
service over existing owners. Derive state from canonical objects rather than
creating another workflow truth table: PLANNED, AWAITING_CANDIDATE,
CANDIDATE_ADMITTED, BUILDING, REPAIR_NEEDED, EVIDENCE_READY,
READY_FOR_ACCEPTANCE, CANDIDATE_PROOFS_READY, PROVEN, BLOCKED, or CANCELLED.

### P5 — model-neutral handoff

The `manual` adapter exports a bounded packet and isolated candidate workspace.
One opt-in installed adapter may run through a fixed executable registry. It
accepts no arbitrary shell, receives a scrubbed allowlisted environment, sees
no wallet/datadir/SSH/node credentials, writes only inside the candidate, has
strict output/time limits, and cannot accept or publish. Unavailable, refused,
and timed-out are typed outcomes.

### P6 — bounded repair

Permit at most three candidate attempts. Each failed fixed action produces a
bounded diagnostic capsule containing the goal, prior patch, relevant compiler
or test diagnostic, and related excerpts—not an unbounded build log. Preserve
parent candidate, changed files, supplied context, adapter identity, elapsed
time, and resources for each separately captured attempt.

### P7 — review authorship

Manual and adapter review consume only the exact candidate, patch, public API
delta, immutable non-review proof set, goal, and policy. Review cannot create
build/test evidence, edit, or accept. Independent profiles reject an
author-self-review; conflicts remain visible.

### P8 — human result

Status leads with goal, state, changed files and lines, API changes, build and
test results, sanitizer and fuzz results, reproduction grade, review verdict,
risks, scope violations, and next safe command. Roots are grouped under
`expert`.

### P9 — self-hosting and benchmark

Use this exact product path to implement and accept at least one subsequent
improvement. Run the frozen twelve-task benchmark across at least three
projects: four seeded repairs, three bounded APIs, three malformed/UB/
portability repairs, and two intentionally impossible or out-of-scope goals.
Record all failures; do not edit tasks after seeing results.

### P10 — fresh-checkout acceptance

Provide a five-minute walkthrough and a hermetic target proving workspace
immutability before acceptance, candidate isolation, scope refusal,
candidate-bound evidence, byte-identical projection rebuild, restart behavior,
exact acceptance binding, and non-reachability of wallet/token/custody/
deployment/consensus paths.

## Implementation ledger

| Slice | Integrated commit | Ordinary inputs removed | Commands removed | Context effect | Production delta | Measured effect |
|---|---|---|---:|---|---:|---|
| P1 inspect | `3a43baeeb5c574cf5199c56b7e44dd2962442eb6` | publisher key, sequence, reward address, chain ID, manifest/recipe/lock wires | 1 expert prepare invocation | reports project bytes without creating `.zvcs` | recorded in commit | one required field: `workspace` |
| P2 profiles | `aa3a4c2c71dd40a704753b1e8159f7b99f0b4c6e` | proof-policy wire and manual policy fields | 0 | none | recorded in commit | `quick|standard|strong|release` expand to inspectable existing policy objects |
| P3 goal context | `20a698e33c184c54c03aaf8fb1a159394a1af458`, `0a28ffb607f3933ce3c22d4a2d432a6f727a2907` | exact symbol on the ordinary path | 0 | codec goal: 9,776 / 15,050 source bytes, 1 file, 8 candidates, 0 dropped, 24,213 us | recorded in commits | deterministic explained selection; exact override remains expert-only |
| P4 start/status | `4a0b7be71085c4d00e6e348564346cdc032585f6` | raw roots, wires, timestamps, toolchain capsule, write-scope CSV, context symbol | at least 5 expert composition/status steps | same codec packet: 65.0% of package source | +593 / -40 | `workspace`, `goal`, optional `profile`; human-first status |
| P5 manual handoff | `81502a4ae1d1b7148e13d314fe6f248def706abb` | candidate path construction and manual context/CAS lookup | 1 undocumented handoff procedure | reuses the exact P3 context with no expansion | +581 / -67 before generated docs/tests | isolated candidate tree and bounded packet; candidate admission/build remains next |
| P6a candidate admission | `1021f81aec22542ea458cebef625922107d6fed3` | planned task/context roots, scope/recipe/lock wires, candidate/patch roots, action IDs, timestamps, scratch datadir, adapter and author roots | 1 expert admit invocation | exact P3 context reused | +217 / -8 before lint rationale/tests/docs | one in-scope edit reaches `CANDIDATE_ADMITTED`; an out-of-scope license edit fails closed before build |
| P6b contained build | `5fa6b1c60c37b278a13c26cff26890c214173e43` | worker approval, lease, action ID, receipt lookup | 1 worker/evidence procedure | no context expansion | +193 / -10 before tests/docs | the same run captures, builds and tests the candidate; signed `work_receipt.v1` rebuilds status as `EVIDENCE_READY` |
| P6c bounded repair | `b7479b3f6934ecc025032795a1afd3f2648381de` (integrated by `ffbcda7d50d1dbdcb37421ecbd5579929775face`) | candidate sequence, parent and failure roots, next attempt path | 0 | reuses the same bounded excerpts; no build log expansion | +261 / -38 | a born-red compile failure becomes `REPAIR_NEEDED`, preserves signed failure evidence and attempt 1, then a repaired attempt 2 reaches `EVIDENCE_READY`; attempt 4 is unreachable |
| P8a patch summary | `7894d50cf852470a5fd3caa5525a9ef2f055b099` | patch root lookup and manual file counting | 0 | no context expansion | +210 / -7 | status re-verifies `patch.v1` and CAS blobs, then reports changed paths, files, exact line-content additions/deletions, and public-header impact |
| P6d declared-test evidence | `9726dbf148cb184b9ef14287ad6fef62174ebae5` | separate evidence command inputs for a declared package test | 0 | no context expansion | +134 / -3 | the existing package action's chunked output is reconstructed and independently rechecked; an exact isolated `TEST_PASS` now satisfies both compile and declared-test facts for `quick` |
| P4 accept | `483b0b76c10e5bc26459e9e02f63676be0d63d54` | action ID, source root, scratch ledger, evidence and lane commands | 3 expert calls | no context expansion | recorded in commit | one explicit human command advances the existing signed FRONTIER→CANDIDATE→PROVEN chain, is idempotent, leaves source unchanged, and rebuilds `PROVEN` from CAS after projection deletion |
| P1 init/status | `1e101f3126b16c9bc717d5a332f8af3b6607e4da` | hand-authored package metadata and unsafe filesystem setup | 0 on an existing project; initialization is one explicit plan/commit pair | no model context expansion | +622 / -12 production lines | inspection proposes correctable metadata before initialization; commit rechecks the exact source/config plan, creates only `zcode-package.json` with `O_EXCL`, refuses stale plans and overwrite, and status remains read-only |
| P5 Codex adapter | `aeb7586c559bad8e8d5f6fe916555d6e7e59ff5a` | external packet export/import ceremony | 0; `work run --adapter=codex` edits, captures, admits and builds in one command | exact P3 packet only; combined output capture capped at 32 KiB | +438 / -15 production lines | fixed executable registry, environment scrub, Landlock write-only candidate boundary, no model acceptance/publication authority, typed unavailable/refusal/timeout; measured runner rebuild fell from about 60 s to 10.5 s after replacing the whole-node link with its exact five-source dependency set; manual remains the default |
| P4 show / P10 acceptance | commit subject `docs(zcode): add the development acceptance path` | separate expert status spelling and undocumented acceptance procedure | 0 (`show` is the same verified read path) | no context expansion | recorded in commit | five-minute walkthrough plus one exact hermetic target covering source identity, isolation, scope refusal, repair, evidence, projection rebuild and explicit acceptance |
| P9 first self-host | `ac2709e190e9d9734cc88e1b6c649e1aa0280588` | all roots, wires, timestamps, toolchain and action IDs | ordinary path is 5 commands from goal through status | 541 / 1,487 source bytes (36.4%), 1 file, 1 symbol, 11,227 us | accepted patch +8 / -1 in a test-only fixture | one attempt passed confined build and declared tests, explicit acceptance reached PROVEN, and the committed files were byte-identical to the captured candidate |
| P7 manual review | commit subject `feat(zcode): execute independent manual reviews` | review wire, findings root, proof-set root, reviewer key and REVIEW action/receipt construction | replaces the expert review ceremony with one command | reviews the existing immutable non-review proof set; no context expansion | recorded in commit | a distinct scratch reviewer signs existing `review.v1` and a REVIEW receipt; status rebuilds verdict and review root from CAS without opening the scratch database |
| P9 frozen benchmark | `463255b19a3319eeed483df58c4e94f23a021764` | exact symbols plus all roots, wires, timestamps, action IDs and scratch paths | ordinary success path is exactly 5 commands | 312 / 816 aggregate source bytes (38.2%); 70,859 us selection time | +347 / -5 across selector, tests and ledger | 10/12 compiled, satisfied `quick`, and reached PROVEN; 2/2 out-of-scope requests failed closed; 14.933 s total |
| P2/P4 standard evidence | commit subject `feat(zcode): compose standard profile evidence` | compiler passes, action profiles, receipt IDs and sanitizer invocation | 0; the ordinary path remains 5 commands | no context expansion | +239 / -33 production lines before this ledger | two separately rooted confined package actions each enforce `-Wall -Wextra -Werror`; each performs a deterministic non-PIE, ASLR-disabled ASan+UBSan run and emits an existing package-build/work receipt; `standard` reports 2 compile + 2 test receipts and reaches PROVEN |
| P8 standard status rebuild | commit subject `fix(zcode): rederive standard sanitizer status` | scratch ledger lookup and remembered profile label | 0 | no context expansion | +31 / -2 production lines before this ledger | status reloads and re-roots the existing proof policy; only a PROVEN standard task reports `passed_asan_ubsan`, and the verdict survives deletion of the scratch ZBuild database |

The P5 delta includes promoting the build worker's private CAS-tree materializer
to one shared ZVCS primitive; 59 production lines of duplicate materialization
were removed. No canonical domain was added. The manual adapter is a closed
registry entry, creates no candidate authority, and does not run a model.

The P6 canonical-domain audit found no missing wire. `candidate.v1` already
binds the task, cumulative patch, captured source, adapter-policy root, author,
sequence, and creation time. `work_receipt.v1` already binds each candidate to
its fixed action, failed or passing output evidence, confinement, toolchain,
times, and signer. The repair adapter-policy digest additionally commits to the
prior candidate root, while the next cumulative patch remains based on the
task's immutable source as required by existing validation. The rebuildable
task index orders attempts by candidate sequence and derives `REPAIR_NEEDED`
only from a verified signed receipt for the latest candidate. Compiler output
is intentionally summarized to the canonical failure class and exit status;
unbounded logs are neither made authority nor copied into the adapter packet.
The same audit covers the Codex adapter: existing
`candidate.v1.adapter_policy_root` already owns adapter provenance. The
runner derives that field from the exact context, the parent candidate when
repairing, and a fixed local adapter-policy label. It adds no wire, source
store, task, candidate, receipt, or workflow authority.

The first installed-adapter dogfood run exposed two fail-closed integration
defects before any authoritative source changed. `RLIMIT_NPROC` was initially
applied as an absolute 128-task ceiling even though Linux charges it across the
real uid; the runner now rebases its 128-task allowance over the measured uid
task count. The next run reached the installed Codex client but the inherited
`OPENAI_API_KEY` produced HTTP 401. The fixed adapter now accepts exactly one
documented single-run credential, `CODEX_API_KEY` or `CODEX_ACCESS_TOKEN`, and
otherwise returns `ADAPTER_UNAVAILABLE`. It does not copy the user's
`auth.json` into the candidate or expose a credential to model-run commands.
This host currently has neither supported single-run variable, so the real
adapter benchmark remains honestly blocked while the manual adapter remains
operational.
The same dogfood run caught local `.zvcs` and `.codeindex` control directories
changing a package root. Package preparation now ignores only genuine
root-level directories with those two fixed names; a symlink or special file
under either name is still rejected. The derived package source and root stay
unchanged while local task/CAS and derived-index state remain non-authoritative.

The P4 cancellation audit found no reusable task-cancellation authority. The
existing signed `zcl.zcode.work_cancel.v1` wire cancels one requester-owned
in-flight P2P request ID; it does not cancel or erase canonical task/candidate
history. V0.1 therefore does not advertise `zcode work cancel`. A human rejects
a candidate by withholding `work accept`; adding a durable `CANCELLED` task
state remains blocked on an explicit authority decision rather than a display
projection or misuse of the transport cancel wire.

The first manual-adapter self-hosting exercise found three additional product
failures and preserved all canonical evidence. First, embedding an 11,607-byte
adapter packet in the ordinary response exceeded the command's 4 KiB human
result budget. Manual handoff now writes that bounded packet mode-0600 inside
the isolated candidate and returns only its path and byte count. Second, the
successful package action copied the expert admission payload back into the
ordinary response and again exceeded 4 KiB; the response now selects only the
eight exact roots and IDs needed for expert audit. Third, a codec candidate was
captured but could not execute because its exact base dependency was not
installed in the scratch worker. A repeated run previously created a fresh
empty attempt. It now fails closed as `CANDIDATE_EXECUTION_INCOMPLETE`, keeps
the captured candidate, and names the missing execution receipt instead of
advancing history. `CANDIDATE_ADMITTED` has exactly one meaning everywhere —
candidate captured, no signed work receipt yet — so when the bound datadir
holds an outstanding (not superseded) async proof chain for that candidate,
a repeated run is instead an idempotent "waiting for independent
reproduction" observation identical to `work status`; the fail-closed branch
remains for receipt gaps no supervisor can still close. The same discipline
now covers the terminal states: a repeated run on `EVIDENCE_READY`,
`CANDIDATE_PROOFS_READY`, or `PROVEN` is an idempotent observation of that
state — it never opens a fresh candidate attempt on work that `work status`
already calls accepted or ready for decision.

The dependency-free base dogfood task selected 470 of 56,140 source bytes
(0.84%) in 27,139 us, but ranked `memory_cleanse` above the requested checked
arithmetic API. Attempt 1 added the requested NULL-output regression and then
correctly exposed a pre-existing strict-C23 portability failure: `flockfile`
and `funlockfile` lacked the POSIX feature declaration. Attempt 2 added
`_POSIX_C_SOURCE=200809L`, passed the confined declared package tests, and
reached PROVEN with task `dc2505113e53b70d56f75dd6d39f21a2d9be2c5877b265d18d7ab7f0aff1ee3b`,
candidate `f9ddf356a2ecbecd794b5a3ebfd1147ceb728898faff0c615932efedaa63cf2b`,
work receipt `1f285da15457ddb5ff64aaffaa7b761e6166a2488ded4d744187cfd3a0b32609`,
proof set `c2796d706f8fb0802936914bd0093451e6143704d0335b2d3a7a42dcd78a9a40`,
and PROVEN lane `f235ef47595276737e6c811eb05cef305590122ba682a116820e6c5d18778f44`.
The accepted patch is not applied here because changing the frozen base root
would also invalidate the signed SHA3/codec dependency DAG. It is evidence of
the product path, not a claimed self-hosted commit.

The first committed self-host used the tracked dependency-free
`fixture/tiny-lines` project. The ordinary caller supplied only `workspace`,
`goal`, `profile`, the display `work` alias, and `adapter`; no canonical root,
wire, timestamp, toolchain, policy field, or action ID was supplied. The goal
was to reject embedded NUL bytes and prove that failure zeroes the output line
count. ZCODE selected the exact `tiny_count_lines` symbol, emitted a 2,001-byte
manual packet, captured two changed files, passed the declared package build
and tests in 1,264 ms, and reached PROVEN after the explicit human accept.
The authoritative files applied in commit
`ac2709e190e9d9734cc88e1b6c649e1aa0280588` were byte-identical to the
captured candidate. Its canonical audit trail is task
`a91af3fda92a797a27eddc397e0a5da9c724f768b3464a5faf78bca5449a2781`,
candidate `0211e7574d72e5e6d3fb8062351bc91d508981cd660c7720f4551f19a80e8ab1`,
patch `b0911db43c6b1348a59de01b3d0b794a27ee1712afe0ce5947ba1f1cd7b78bab`,
work receipt `05778f5a8591c81c83472848f920b86fc875077a743ce7dfc8222f433b26e4dc`,
proof set `a89fbfcee0f7ea3b8fb369d8cadea7bf9e180042134afcb296440037f2b8c877`,
and PROVEN lane `523eb5476448178c6779c8425c1b3228e349f49c8b324f1c03da1851c51e666b`.

P8 line counts are deterministic content-multiset deltas: identical lines are
matched regardless of position, so a pure move is not presented as creation.
Binary files and text files above the fixed 65,536-line bound set
`line_counts_complete=false` instead of silently inventing a number.
The package action is one fixed execution that compiles the package and runs
its declared tests. Its one signed work receipt remains one proof-set member;
the evaluator counts the two distinct facts it actually carries. It first
reconstructs the chunked build artifact and rechecks candidate, recipe, lock,
isolation, result class, `test_ran`, and exit status. A standalone test receipt
is still required when the package receipt did not run declared tests.

## Benchmark acceptance

The frozen targets are: zero ordinary raw roots or wire hex; no more than five
commands; at least 9/12 compiling candidates; at least 8/12 policy-satisfying
candidates; 2/2 impossible requests fail closed; zero writes outside candidate
workspaces; zero silent failures; zero false independence claims; every status
has a concise human summary; and honest context/time measurements.

Each slice reports expert inputs and commands removed, context reduction,
production lines added, lines deleted/consolidated, and benchmark effect.

### Frozen twelve-task result

The permanent `test_zcode_package_dev` benchmark runs twelve unchanged goals
against three freshly generated, permissively licensed C23 package workspaces.
The manual adapter harness performs the candidate edit because this host has no
supported Codex single-run credential. It therefore measures the ZCODE product
loop—context selection, isolation, capture, scope enforcement, package action,
evidence, human acceptance, status rebuild, and workspace immutability—not the
semantic coding quality of an external model.

| # | Project | Class | Frozen goal | Result |
|---:|---|---|---|---|
| 1 | benchmark-0 | seeded repair | Repair seeded parser branch A | PROVEN |
| 2 | benchmark-1 | seeded repair | Repair seeded parser branch B | PROVEN |
| 3 | benchmark-2 | seeded repair | Repair seeded parser branch C | PROVEN |
| 4 | benchmark-0 | seeded repair | Repair seeded return regression | PROVEN |
| 5 | benchmark-1 | bounded API | Add bounded API behavior A | PROVEN |
| 6 | benchmark-2 | bounded API | Add bounded API behavior B | PROVEN |
| 7 | benchmark-0 | bounded API | Add bounded API behavior C | PROVEN |
| 8 | benchmark-1 | malformed/UB | Repair malformed input handling | PROVEN |
| 9 | benchmark-2 | malformed/UB | Repair portability boundary | PROVEN |
| 10 | benchmark-0 | malformed/UB | Repair undefined behavior guard | PROVEN |
| 11 | benchmark-1 | impossible | Modify LICENSE outside the write scope | refused: `PATCH_OUTSIDE_SCOPE` |
| 12 | benchmark-2 | impossible | Replace package identity outside scope | refused: `PATCH_OUTSIDE_SCOPE` |

Measured aggregate: 12 tasks, 3 projects, 10 compiling candidates, 10 policy
satisfactions, 10 explicit human acceptances, and 2 scope refusals. Context was
312 of 816 source bytes (38.2%), selected in 70,859 us; the whole benchmark
took 14.933 seconds. Every successful path used five calls (`start`, two
`run` calls for handoff and admission, `accept`, `status`), supplied no raw
root or wire, and ended with a human summary. The impossible paths stopped at
the second `run`. Exact source roots captured before the tasks matched after
all tasks, proving zero authoritative-workspace writes. No result claims
independent reproduction or adapter authorship.

The born-red failure preceding this result was `CONTEXT_SELECTION_FAILED` for
goal language with no literal indexed-symbol overlap. The tasks were not
changed. The selector now performs a bounded deterministic project-entry
fallback, reports `project_entry_fallback` instead of pretending the goal
matched, and preserves the exact-symbol expert override. This was the largest
recurring product failure class in the frozen benchmark.

## V0.1 validation ledger and remaining blockers

The benchmark slice is commit
`463255b19a3319eeed483df58c4e94f23a021764`. Required current-main integration
is merge commit `4843d0b7da58abc2eee89578a37ba332cc637235`; it preserves the disjoint
concurrent transaction-lab history and changes no ZCODE product file.

The measured gates for the product slice were:

- `make zcode-development-acceptance`: PASS, including the twelve-task
  benchmark and fresh-workspace invariants.
- `make lint`: PASS, 134/134 gates.
- `make zcode-package-asan`: PASS under ASan+UBSan with no suppressions for
  isolated base/SHA3/codec and all 13 ZCODE lifecycle groups, including
  `test_zcode_package_dev`.
- Generic `make t-asan ONLY=zcode_package_dev`: did not reach tests because
  the pre-existing Sapling ADX assembly cannot allocate registers with that
  profile's `-fno-omit-frame-pointer`; the repository-prescribed ZCODE
  sanitizer posture above uses `-fomit-frame-pointer -O2` for the monolith and
  passed.
- Strict uncached suite: the final integrated pre-push run passed 912/912
  runnable groups, 0 cached, with 9 parameter-heavy groups policy-gated and 20
  declared self-skips. Earlier load-sensitive failures in `test_simnet_perf`
  and `test_native_api_contract` both passed their exact isolated reruns before
  the clean complete reruns.
- Release whole-program LTO build: PASS.
- `make ci-reproducible`: PASS on the integrated implementation, two
  same-checkout builds byte-identical at SHA3-256
  `dc77e053e94119c2dca26571d82f56920e40d729c2470d90c7697170689a4c13`
  and 23,080,328 bytes.
- `make repro-verify`: PASS across two deliberately different absolute build
  paths at SHA3-256
  `08607a56bb491eddf196b61251cd892126dd9e6c26aaba457b2ef41d93e055a2`
  and 23,080,408 bytes.
- Every implementation push and both integration merges passed the repository
  pre-push gate. The final integrated implementation was pushed and
  pull-verified as `deb59fea56ca6f3cd1169038371a76e0f2020725` before this
  documentation-only ledger update.

The safe quick- and standard-profile development loops are shipped. The broader owner
directive is not represented as fully closed for these reasons:

1. `strong` and `release` still fail closed on their additional deterministic
   fuzz, reproduction, and independent-review requirements. The runner now
   composes the standard base from two exact existing package actions and
   requires a clean warning-fatal ASan+UBSan result in both canonical package
   receipts. Composing the existing fuzz and reproduction owners without
   falsely claiming physical independence is the largest remaining product
   bottleneck.
2. The fixed Codex coding adapter is implemented, but this host has neither
   `CODEX_API_KEY` nor `CODEX_ACCESS_TOKEN`. No real adapter coding or
   adapter-produced review receipt was fabricated. Manual handoff and manual
   independent review are operational.
3. A codec dogfood candidate remains preserved but unexecuted because its
   exact frozen base dependency is not installed in that scratch worker.
4. Durable `work cancel` remains intentionally absent: the existing canonical
   cancel wire owns a P2P request, not a task. Rejecting a candidate means
   withholding human acceptance until an owner chooses an appropriate durable
   task-cancellation authority.
5. Genuine independent reproduction still requires another physical machine.

No new canonical domain was added. The product reuses the existing task,
context, scope, candidate, patch, recipe, lock, package action, work receipt,
proof set, review, lane and acceptance authorities.

The standard-profile born-red test first observed one compile/test receipt and
`PROOF_PROFILE_INCOMPLETE`. Its green form asserts the human result reports
exactly two compile receipts, two declared-test receipts, and
`passed_asan_ubsan`, then proves explicit acceptance reaches PROVEN. On this
host both sanitizer runtimes initially refused randomized placement with
`Shadow memory range interleaves`; the fixed confined sanitizer executor now
uses a non-PIE binary and the fixed `setarch x86_64 -R` wrapper. An unavailable
or dirty sanitizer still exits without a successful package receipt; it is
never relabeled as clean.

## Hard boundary

Living Commons O0–O7 is frozen except for correctness. This project performs no
ZC23 issuance, token launch, election-authority, custody, wallet, vault,
transaction, core, consensus, live-datadir, service, deployment, restart, GUI,
web IDE, arbitrary model shell, or multi-package workspace work. It never
executes downloaded source automatically and never lets a model accept or
publish its own result. Genuine independent reproduction requires another
physical machine and remains a separate owner-gated operational task.
