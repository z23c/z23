# How the node works

The codebase looks big. The idea underneath it is small. Read this page once and
you can reason about the whole node.

## 1. The node in four lines

1. There is one durable record on disk: an append-only log of facts (in
   `consensus.db`, a SQLite kernel store). It is the only authority for
   consensus state. `progress.kv` is a separate, secondary SQLite file that
   holds only rebuildable projections (`address_index`, `txindex`) — never
   consensus state.
2. There is one kind of worker — a **reducer stage**. Each stage reads the height
   its upstream stage has finished, then either **advances its own cursor by one
   height** (writing one log row) **or names a typed blocker** saying exactly why
   it cannot. There are eight of these stages in a fixed line.
3. Everything else — the wallet, the block explorer, the peer list, the
   block-index view — is a **projection**: a read-only summary rebuilt by re-reading
   the log. Projections never decide anything; delete one and it rebuilds.
4. Health is **one number**: `network_tip − log_head`. `network_tip` is the best
   block height the network has told us about; `log_head` is the highest height the
   eighth stage (`tip_finalize`) has finalized. If that number is shrinking, the
   node is making progress. If it is stuck, some stage has named a blocker — there
   is no silent stop.

That is the entire mental model. The eight stages are below.

## 2. The state machine — eight stages

Each stage stores a **cursor** in `consensus.db`. For the first seven stages the
cursor is "the next height to process", not "the highest done"; `tip_finalize` is
the one exception — its cursor is the served tip itself (the highest finalized
height), which the frontier code normalizes to the same "next height" frame when
comparing stages (`reducer_frontier.c:149` `frontier_next_cursor` — served tip C is
treated as next-height C+1). A stage may
only run at heights its upstream stage has already finished (the upstream cursor is
its floor). It does one of two
things at that height: advance the cursor by one and write one authoritative log
row keyed by height, or stop and name a blocker. Cursor + log row are written in
the same database transaction, so a crash resumes cleanly at the stored cursor.

| # | Stage | What it proves | Cursor at height N means | What "stuck" looks like |
|---|-------|----------------|--------------------------|-------------------------|
| 1 | `header_admit` | A block-index entry exists for the height and is linked to its parent | Heights `[0,N-1]` admitted; N is next | Blocker `missing_parent` — the previous block's linkage is absent |
| 2 | `validate_headers` | Proof-of-work + Equihash are valid (or solution is missing but back-fillable) | Headers `[0,N-1]` checked, each logged ok/fail | Idle, parked on a repairable row (e.g. missing solution); a terminal reject moves the floor on |
| 3 | `body_fetch` | The block body is present on disk | Bodies `[0,N-1]` seen on disk or skipped as invalid | Idle until the body arrives; blocker `header_solution_missing` if the header was never validated |
| 4 | `body_persist` | The body reads back, hashes to its header, and rebuilds its merkle root | Bodies `[0,N-1]` verified readable + merkle-consistent | Idle — it clears the body and re-fetches on a read/hash/merkle failure |
| 5 | `script_validate` | Every input script verifies | Scripts `[0,N-1]` checked (ok, script-invalid, or internal error) | Idle until upstream is ready or the Sapling params are loaded |
| 6 | `proof_validate` | Shielded proofs verify (Groth16 / PHGR13 / Sapling / binding sig) | Proofs `[0,N-1]` checked (ok or rejected) | Idle until upstream is ready or Sapling params are loaded |
| 7 | `utxo_apply` | The coin changes (added/spent, transparent + shielded, nullifiers) are consensus-consistent | A verdict row exists for `[0,N-1]` | Blocker `apply_failed` (transient) — e.g. the upstream verdict row is missing |
| 8 | `tip_finalize` | Height N is the canonical finalized tip and the chain extends linearly into N+1 | The finalized tip is N | Idle at the frontier, or transient `successor_pending` if N+1 isn't body-ready / script-valid yet |

`log_head` from the four-line summary is the `tip_finalize` cursor — the maximum
finalized height. External readers (`getblockcount`, the height we advertise to
peers) report the height that `tip_finalize` has published. During process
startup, the public REST/native status surfaces may read the durable
`tip_finalize` cursor before the in-memory H* cache has been published, so the
website does not briefly fall back to height 0 while the node is already at tip.
At the live head, the applied active tip can briefly sit one block above H*
while the reducer waits for a successor. Once that head is fully UTXO-applied,
is exactly the best header (height and hash), has no failed verdict, and the
only hold is `lookahead_tip_missing`, the post-drain path publishes that one
head through the same local-authority anchor a clean restart already restores.
It cannot jump more than one height or run while header catch-up is pending;
this keeps the continuously-running money frontier equivalent to restart.

A **reorg** is just a disconnect: `utxo_apply` saved the inverse of each coin
change, so the node replays those backward to the fork point, then re-applies the
winning branch forward. Nothing special, same machinery.

A blocker is **transient** (solvable — retry with backoff, then a bounded number of
attempts) or **permanent** (needs the operator, or a condition + a supervised
restart). Either way it is named.

## 3. Watch the machine live

These are typed operator calls. Prefer the native `z23` command and stop
when you have your answer.

| Call | Shows |
|------|-------|
| `z23 agentinterface` | Preferred AI/operator interface contract. Typed native CLI JSON is the operator surface, and REST is read-only. No external wrapper logic is required. |
| `z23 api` | Native API discovery from the running node. Same `zcl.rest_index.v2` body as `GET /api` and `GET /api/v1`: version, base path, resource routes, CRUD conventions, `layer_model` for the ZCL L1 / z23 application-layer boundary, and first native/REST calls. Start here when choosing an interface. |
| `z23 appprotocols` | Native application-protocol catalog. Same contract as `GET /api/v1/protocols`: ZSLP, ZNAM, market, messaging, and script-contract overlay services, their CRUD/read models, anchors, and consensus boundary. |
| `z23 agentlanes` | Native canonical/soak/dev topology and deployment-safety contract; use it before choosing a deploy or restart target. |
| `z23 agentliveness` | Compact lane/service/supervisor/background-quality liveness. Use it when deciding whether a lane is active, stalled, missing quality verdicts, or only being inspected from a static binary. Use `agentliveness full` only for embedded method/lane/domain arrays. |
| `z23 status` | The operator-gated real-money first check: one line by default, or bounded `zcl.result.v1` / `zcl.status_journey.v1` JSON answering node/sync and wallet readiness, receive/send capability, aggregate spendable/pending/reserved money, backup/Sapling posture, the causal blocker, and one next action. Use `z23 core status brief` for chain-only scripting and `z23 core status` for the larger diagnostic tree. |
| `z23 milestone` | Node-computed ASCII and JSON progress to v1 MVP. Same contract as `GET /api/v1/milestone`: live systems bar, strict MRS goals bar, partial-proof subgoals bar, and next blockers. |
| `z23 core status` | The full diagnostic tree: height, peers, sync state, reducer frontier, tip-finalize, condition engine, typed blockers, and chain source scoring. |
| `z23 core sync diagnose` | Sync state, header-sync counters, watchdog health, chain/header heights, peer maximum height, and download statistics. **It does not list the eight stage cursors**—use `dumpstate reducer_frontier` for those. |
| `z23 dumpstate reducer_frontier` | The eight stage cursors, `H*` (deepest provably-consistent height—the tip `getblockcount` serves), and the success-checked log frontiers. |
| `z23 dumpstate blocker` | Active blockers with deadlines and escape actions. |
| `z23 dumpstate condition_engine` | Self-heal engine: active versus cleared conditions. |
| `z23 dumpstate service_state` | Operational mode: boot / restore / reconcile / degraded_serving / syncing / healthy / repairing. |
| `z23 dumpstate chain_evidence` | Native chain evidence: tips, cursors, evidence flags, and any contradiction reason. |

`z23 dumpstate` is a generic dispatcher—pass any registered subsystem
name. The eight
stage names work directly as subsystems too: `header_admit`, `validate_headers`,
`body_fetch`, `body_persist`, `script_validate`, `proof_validate`, `utxo_apply`,
`tip_finalize`. For drilling deeper, use `z23 getnodelog` for a bounded
server-side regex tail, `z23 dbquery` for SELECT-only node-database
inspection, and `z23 ops mirror` for the local reference-daemon view.

The complete subsystem list is one array in code:
`app/controllers/src/diagnostics_registry.c` (`g_dumpers[]`). Adding a new
introspectable subsystem is one entry there plus one `*_dump_state_json` function —
no new command route or schema.

## 4. What is real vs what is being deleted

**Real (load-bearing, stays):**
- The append-only fact log + per-stage success rows (ok=1). `H*` = the longest
  contiguous ok=1 prefix from the anchor. This is what makes a silent halt
  impossible to represent.
- The eight-stage reducer pipeline (advance-cursor-or-name-blocker).
- Consensus validation: PoW (Equihash, with height-selected parameters — see
  [`EQUIHASH_PARAMS.md`](EQUIHASH_PARAMS.md)), script signatures, shielded
  proofs, ZIP-209.
- Reorg handling via the saved inverse coin changes.
- The eight code "shapes" (controller / service / model / job / supervisor /
  condition / event / storage-adapter). Seven live one-folder-each under `app/`
  (`controllers`, `services`, `models`, `jobs`, `supervisors`, `conditions`,
  `events`); the Storage Adapter shape lives in the top-level `adapters/` + `ports/`
  trees (`app/views/` holds explorer templates and is not one of the eight). Shape
  placement is lint-enforced; per `docs/FRAMEWORK.md` Model/Condition/Job and the
  Storage Adapter are real and enforced, Supervisor is partial, Controller/Service
  still carry legacy debt.

**Being replaced:** today the coin set can be seeded on boot from a near-tip
snapshot minted by an external `zclassicd`. Its payload SHA3 authenticates the
file bytes and its anchor hash must match a validated local header. That
proves the selected chain location, not the derivation of UTXO or shielded
state: ZClassic headers commit none of the UTXO, Sapling/Sprout frontier, or
nullifier roots. The state is therefore **borrowed**, not consensus-bound or
re-derived from genesis.

The direction (`docs/work/self-verified-tip-plan.md`) is a **self-verified
UTXO anchor rebuild**: the internal boot path is `-refold-from-anchor`
(`app/jobs/src/refold_progress.c`, `app/services/src/anchor_selfmint.c`),
which rebuilds the coin set forward from a compiled checkpoint instead of
borrowing it. Landing this removes the older recovery-import code that feeds
the borrowed-seed path. A complete atomic state install and copy proof must
precede any live cutover away from a borrowed-state node.

Your own node's live status — wedged, cured, or holding tip on self-verified
state — is not something this page can tell you: check it with `z23 status`
and `z23 dumpstate reducer_frontier`.

## 5. Where to start

1. Read, in order: **`docs/work/FORWARD_PLAN.md`** (the current plan) →
   **`docs/MVP.md`** (the v1 acceptance bar). `docs/FRAMEWORK.md` is the canonical
   architecture; this page is its plain-language summary. **`docs/AGENT_TRAPS.md`**
   lists things that look broken but are not (don't re-chase them);
   **`docs/CODEBASE_MAP.md`** is where-things-live + how-to-do-each-thing.
   `docs/HANDOFF.md` records one maintainer's hosted-node state — read it only
   if you are operating that specific node; it says nothing about a node you
   run yourself.
2. Look at the live node before trusting any doc: start with
   `z23 agentmap` for the code/docs/test map, `z23 agentlanes` for
   canonical/soak/dev safety, `z23 agentliveness` for the current lane's
   listener/supervisor/quality rollup, `z23 agentbuild` for the cached
   build loop, `z23 api` for interface discovery, and `z23
   appprotocols` for the application-layer catalog. Then use `z23
   status` for compact live state and `z23 milestone` for v1 progress.
   Drill down with `z23 core status` and `z23 dumpstate
   reducer_frontier` only if needed. A doc can be stale;
   the node cannot.
3. To understand one stage, open its file — `app/jobs/src/<stage>_stage.c`. Each is
   one `step_*` function that does exactly the advance-or-name-a-blocker contract
   described in section 2.

One log, one kind of worker, one health number. Everything else is a view over the
log or a stage in the line.
