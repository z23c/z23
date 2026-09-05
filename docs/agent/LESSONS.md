<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Shared agent lessons

This file is the tracked input for `z23 code focus` path-bound lessons.

Each unresolved lesson is one line in this form:

```text
OPEN <tracked-path> — <measured failure and the invariant still to prove>
```

Replace `OPEN` with `DONE` only after the named invariant has repeatable
acceptance evidence. Keep historical closed entries so the evidence trail
remains inspectable. There are no open lessons at this baseline.


## How to approach it

Re-derive every count you touch from the tree itself and say which command produced it.

# Territory engine/modules/engine

What follows is the tree's own answer about this territory,
regenerated from the code index on this run. It is not a written
description and nobody maintains it by hand.

Read `routed` and `reached` as the different facts they are.
Routed says which registered group runs when a file here
changes. Reached says a registered test entry point actually
calls that public function. They are never added together, and
`unknown` is the call graph refusing to answer — not a quiet
vote for either neighbour.

{"schema":"zcl.result.v1","command":"code.territory","ok":true,"status":"passed","request_id":"local-0000000000000001","elapsed_us":10822616,"budget_ms":900,"elapsed_ms":10822,"budget_exceeded":true,"authority":{"policy":"exempt","agent_session":"none (local operator)"},"data_schema":"zcl.code_territory.v1","data":{"scope":"territory","territory":"engine/modules/engine","found":true,"kind":"module","purpose":"engine-dispatch harness (pure half): vendor registry, request document, hardened response decoder, file envelope, key holder + r...","owns":{"files":24,"headers":10,"sources":12,"bytes":252881,"truncated":false},"routed_groups":[{"group":"engine","files":24},{"group":"make_lint_gates","files":24},{"group":"cold_join_sovereign","files":22},{"group":"engine_rules","files":22},{"group":"command_registry_catalog","files":4},{"group":"native_api_contract","files":4}],"routed_group_count":6,"files_unrouted":0,"public_symbols":74,"reached":67,"unreached":7,"unknown":0,"public_types":37,"public_macros":61,"headers_without_functions":0,"headers_extern_c":0,"symbols_truncated":false,"reach":{"source":"walk","entry_points":1091,"closure_symbols":33243,"walk_steps":33243,"walk_us":273446,"truncated":false},"cost":{"owns_us":96,"routed_us":226838,"symbols_us":592,"deps_us":7,"index_lookups":0},"depends_on":[],"depended_on_by":[],"depends_on_count":0,"depended_on_by_count":0,"deps_dimension":"no-include-graph","unreached_symbols":["engine_endpoint","engine_prompt_template_sha3","zcl_rule_source_label","zcl_rule_state_token","zcl_rule_rewrite_status_label","engine_emit","engine_verdict_name"],"unknown_symbols":[],"unrouted_files":[],"summary":"engine/modules/engine: 24 files (10 headers, 12 sources, 252881 bytes); routed to 6 group(s), 0 file(s) routed to none; 74 public functions = 67 reached + 7 unreached + 0 unknown (0 header(s) contributed none, 0 of those are extern \"C\" and invisible to the index); depends on 0 territor(y/ies), 0 depend on it"},"next":[]}

## 2026-09-04 — flash units through the C23 harness

Flash headless runs carry no verdict. On node1, 40 run logs
contain no edit marker and every run exits 1. The transcript and
the exit code both stay silent about whether the edit happened.
The tree's own harness is the verdict path: `tools/engine_unit.c`
sends one prompt, expects a whole-file envelope reply, runs the
owning group cold, and writes `receipt.json`. Read the receipt,
not the log.

The vendor key is shared by the whole fleet. Five concurrent
calls on node1 returned 429 three times and opened the circuit
breaker while node2 ran six lanes against the same key. Node1 now
dispatches serially with a 15 s gap and requeues rate-limited
runs after 90 s. The durable fix is a fleet-wide semaphore per
vendor recorded in the task ledger.

Output shape decides routing. A 3 KB brief that asked for a
state-machine diagram made flash write 127 KB of reasoning and no
answer, and the harness refused the body. The same brief on
GLM 5.3 landed in one call. Send prose and code to flash; send
anything that invites planning to 5.3.

Specify interfaces, not goals. Flash implemented the first native
leaf on the first attempt with 22,844 completion tokens: the dev
agent situation, 180 lines of C, git through `zcl_spawn_capture`
declared in `platform/modules/util/include/util/spawn.h`. The
prompt carried the full contract and the pinned test. The leaf
wired into `tools/command/native_devagent_command.c` and its group
is registered in `tools/dev/test_group_catalog.def`.

One lander per worktree. Two landing loops ran on one worktree and
a stale lander from a previous session held the proof lock for
72 minutes while proving a head that a fresh rebase had already
replaced. Before starting a lander, check who holds the proof
lock. `tools/scripts/worktree_init.sh` and
`tools/scripts/worktree_gc.sh` govern the worktrees themselves.

Peer ids on the onion mesh churn. The node2 peer was id 60,
dropped between two sends ten minutes apart, and came back as
id 114 after a onetry dial. Resolve the id from `getpeerinfo`
before every send; never cache it across sends.

## 2026-09-05 — trains, proofs, reviews, and the ledger

A lane that only runs the group it wrote still breaks a train
on a pinned root count in another group. The checkout routes
every group for each file the lane touched. Ask
`build/bin/z23-dev code tests` and run every group it names.

A train claim names a box and can be transferred. When the
claiming box is overloaded, the train stays live while that
box cannot prove it. Bundle the train
(`git bundle create <f> origin/main..HEAD`), copy it to an
idle box, and post that the claim moved. The idle box proves
and pushes. The transfer rule lives in
`docs/agent/TRAIN_PROTOCOL.md`.

Proof generation runs on a RAM filesystem. Probes that
measure device I/O (fsync throughput, block counters) fail
there for reasons unrelated to load. A fixture must detect
the medium and say so; it never blames load.

`git cherry-pick -q` is not a valid invocation. Git prints
usage, applies nothing, and a pipeline that swallows the
exit code reports success. Always check the commit count
after assembling a train.

`LOG_ERR` logs and returns -1. A second call placed after
it in the same block is unreachable, so a reviewer who
reports a double call there is wrong. Reviewers must know
which log macros return; the returning set lives in
`base/log_macros.h`.

A test fixture that creates or removes files inside the
source tree while a proof runs changes the parent
directory's epoch. The prover correctly refuses the receipt
as superseded. Fixtures write under the generation's
scratch/state directory.

The prover's runner uses exit status 126 for its own
child-setup failures (setsid, chdir, dup2) and 127 for a
real exec failure. Only the former is transient and
retryable.

Every delegated task is a ledger row: model, thinking
level, tokens, wall time, outcome, lines changed.
Heuristics about executors are derived from the ledger,
never from impressions.
