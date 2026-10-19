<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# How the node works

Use this page to follow a block through the node, read its progress, and find
the stage that is waiting. To inspect live state, you need the `z23` command
and access to a running node. Start with `z23 status`; section 3 lists the
calls for a closer look.

## 1. The node in four lines

1. The **kernel** is the reducer's authoritative chain state. Its changes
   share one physical transaction domain, `consensus.db`, so they can commit
   together. It holds the mutable coin/shielded state, stage cursors, verdict
   journals, inverse deltas, and kernel metadata that must recover coherently.
   The transparent coin set is the **UTXO set**: unspent transaction outputs.
   `progress.kv` is a separate SQLite file whose declared STAY set
   contains only the rebuildable address and transaction indexes.
2. Chain advancement runs through **reducer stages**, the workers in its
   ordered pipeline. A **cursor** is the stage's stored processing position;
   a **verdict** is its stored result. Each stage reads the height its upstream
   stage has finished, then **advances its cursor by one height** (normally
   committing cursor, verdict, and state changes together) or **names a typed
   blocker**, a recorded reason it cannot advance. There are eight stages in a
   fixed line. The opt-in **bulk-fold RAM overlay** holds coin changes in
   memory until a later flush. It is the explicit exception: boot rewinds to
   its durable watermark after a crash.
3. Address/transaction indexes and explorer summaries are **projections**:
   read models derived from chain state. The wallet, peers, Commons, and other
   product domains are not all projections of
   the chain kernel; they retain separately scoped persistent authorities.
4. Health is **one number**: `network_tip − log_head`. `network_tip` is the best
   block height the network has told us about; `log_head` is the highest height
   the eighth stage (`tip_finalize`) has finalized. If that number is shrinking,
   the node is making progress. If it is stuck, some stage has named a blocker
   — there is no silent stop.

That is the compact runtime model. The exact proof boundary and the presently
unproven single-writer claim are in
[`CHAIN_AUTHORITY.md`](CHAIN_AUTHORITY.md). The eight stages are below.

## 2. The state machine — eight stages

Each stage stores its cursor in `consensus.db`.

| Stages | Stored cursor | Position used to compare stages |
|--------|---------------|---------------------------------|
| First seven | Next height to process | Stored cursor |
| `tip_finalize` | Highest finalized height C | C+1 |

The conversion is `frontier_next_cursor` in
`engine/reducer/jobs/src/reducer_frontier.c:221`. A stage processes a height
only after its upstream stage has finished it:

1. Read the upstream cursor to find the permitted processing boundary.
2. Advance its own cursor and write an authoritative verdict row for that
   height, with any stage-owned state changes; or stop and name a blocker.
3. In the normal SQLite path, commit those changes in one database transaction
   so a crash resumes at a coherent stored boundary.

Opt-in bulk-fold mode is the exception: the cursor and verdict can commit
while coin changes remain in RAM. A later `coins_ram_flush` transaction
persists the overlay, watermark, applied height, and cursor. Boot purges and
rewinds an unflushed tail. Supervised recovery also writes the kernel under a
narrower contract. Neither is another forward stage.

| # | Stage | What it proves | Cursor at height N means | What "stuck" looks like |
|---|-------|----------------|--------------------------|-------------------------|
| 1 | `header_admit` | A block-index entry exists for the height and is linked to its parent | Heights `[0,N-1]` admitted; N is next | Blocker `missing_parent` — the previous block's linkage is absent |
| 2 | `validate_headers` | Proof-of-work + Equihash are valid (or solution is missing but back-fillable) | Headers `[0,N-1]` checked, each logged ok/fail | Idle, parked on a repairable row (e.g. missing solution); a terminal reject moves the floor on |
| 3 | `body_fetch` | The block body is present on disk | Bodies `[0,N-1]` seen on disk or skipped as invalid | Idle until the body arrives; blocker `body_fetch.header_solution_missing` when `validate_headers` logged `no-header-solution-backfill-required` (solution missing, back-fillable) |
| 4 | `body_persist` | The body reads back, hashes to its header, and rebuilds its merkle root | Bodies `[0,N-1]` verified readable + merkle-consistent | Idle — it clears the body and re-fetches on a read/hash/merkle failure |
| 5 | `script_validate` | Every input script verifies | Scripts `[0,N-1]` checked (ok, script-invalid, or internal error) | Idle until upstream is ready or the Sapling params are loaded |
| 6 | `proof_validate` | Shielded proofs verify (Groth16 / PHGR13 / Sapling / binding sig) | Proofs `[0,N-1]` checked (ok or rejected) | Idle until upstream is ready or Sapling params are loaded |
| 7 | `utxo_apply` | The coin changes (added/spent, transparent + shielded, nullifiers) are consensus-consistent | A verdict row exists for `[0,N-1]` | Blocker `utxo_apply.apply_failed` (transient) when an upstream verdict is present but not ok, or the coin apply fails. A missing `proof_validate` row is an upstream-log hole and stays `JOB_IDLE`. |
| 8 | `tip_finalize` | Height N is the canonical finalized tip and the chain extends linearly into N+1 | The finalized tip is N | Idle at the frontier, or transient `successor_pending` if N+1 isn't body-ready / script-valid yet |

The `body_fetch` blocker branch is in
`engine/jobs/src/body_fetch_stage.c:342`. The missing upstream row returns
idle in `engine/jobs/src/utxo_apply_stage.c:324`; failed upstream verdicts and
coin application call `block_apply_failure` at lines 381 and 571, with the
blocker initialized at line 250.

External readers (`getblockcount`, the height we advertise to peers) report
the height that `tip_finalize` has published. During process
startup, the public REST/native status surfaces may read the durable
`tip_finalize` cursor before the in-memory **`H*`** cache has been published.
`H*` is the deepest provably-consistent height `getblockcount` serves once
that cache is published: the minimum, across the success-checked stage logs,
of each log's contiguous ok=1 run from the anchor, then capped below the first
`validate_headers` / `script_validate` hash split and clamped up to the anchor.
The log set and cursor conversion are in
`engine/reducer/jobs/src/reducer_frontier.c:199`; the minimum, hash cap, and
anchor clamp are in that file at lines 600, 645, and 693.
The startup fallback means the
website does not briefly fall back to height 0 while the node is already at tip.
At the live head, the applied active tip can briefly sit one block above `H*`
while the reducer waits for a successor. Once that head is fully UTXO-applied,
is exactly the best header (height and hash), has no failed verdict, and the
only hold is `lookahead_tip_missing`, the post-drain path publishes that one
head through the same local-authority anchor a clean restart already restores.
It cannot jump more than one height or run while header catch-up is pending;
this keeps the continuously-running money frontier equivalent to restart.

A **reorg** replaces the active branch:

1. Replay the inverse coin changes saved by `utxo_apply` backward to the fork
   point.
2. Apply the winning branch forward.

The blocker registry distinguishes four classes:

| Class | Response |
|-------|----------|
| `transient` | Retry with a bounded budget. |
| `permanent` | No automatic retry; the operator clears it. |
| `dependency` | Escalate to the subsystem's supervisor. |
| `resource` | Operator action is required; escape opens the circuit. |

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
| `z23 dumpstate reducer_frontier` | The eight stage cursors, `H*`, and the success-checked log frontiers. |
| `z23 dumpstate blocker` | Active blockers with deadlines and escape actions. |
| `z23 dumpstate condition_engine` | Self-heal engine: active versus cleared conditions. |
| `z23 dumpstate service_state` | Operational mode: boot / restore / reconcile / degraded_serving / syncing / healthy / repairing. |
| `z23 dumpstate chain_evidence` | Native chain evidence: tips, cursors, evidence flags, and any contradiction reason. |

`z23 dumpstate` is a generic dispatcher: pass a registered subsystem name.
The eight stage names work directly as subsystems too:
`header_admit`, `validate_headers`,
`body_fetch`, `body_persist`, `script_validate`, `proof_validate`, `utxo_apply`,
`tip_finalize`. For drilling deeper, use `z23 getnodelog` for a bounded
server-side regex tail, `z23 dbquery` for SELECT-only node-database
inspection, and `z23 ops mirror` for the local reference-daemon view.

The subsystem dispatcher uses `g_dumpers[]` in
`engine/controllers/src/diagnostics_registry.c`, generated from the domain
descriptor files included by
`engine/controllers/include/controllers/diagnostics_dumpers.def`. Add a new
subsystem's descriptor row to its owning domain file and implement its dump
function; the generic dispatcher looks up the registered name.

## 4. What is real vs what is being deleted

**Real (load-bearing, stays):**
- The kernel state + per-stage verdict rows (ok=1). The frontier checks the
  contiguous ok=1 prefix from the anchor. This is what makes a silent halt
  impossible to represent.
- The eight-stage reducer pipeline (advance-cursor-or-name-blocker).
- Consensus validation: PoW (Equihash, with height-selected parameters — see
  [`EQUIHASH_PARAMS.md`](EQUIHASH_PARAMS.md)), script signatures, shielded
  proofs.
- Reorg handling via the saved inverse coin changes.
- The eight code "shapes" (controller / service / model / job / supervisor /
  condition / event / storage-adapter). Six live one-folder-each under `engine/`
  (`controllers`, `services`, `models`, `jobs`, `supervisors`, `conditions`);
  `event` has no folder — it is owned by `engine/modules/event/` +
  `engine/modules/storage/src/event_log.c`. The Storage Adapter shape lives in
  the top-level `platform/adapters/` + `platform/ports/` trees.
  `contexts/explorer/views/` holds explorer templates and is not one of the
  eight shapes. Shape placement is lint-enforced; per `docs/commons/FRAMEWORK.md`,
  Model/Condition/Job and the Storage Adapter are real and enforced,
  Supervisor is partial, and Controller/Service still carry legacy debt.

**Being replaced:** today the coin set can be seeded on boot from a near-tip
snapshot minted by an external `zclassicd`. Its payload SHA3 authenticates the
file bytes and its anchor hash must match a validated local header. That
proves the selected chain location, not the derivation of UTXO or shielded
state: ZClassic headers commit none of the UTXO, Sapling/Sprout frontier, or
nullifier roots. The state is therefore **borrowed**, not consensus-bound or
re-derived from genesis.

ZIP-209 (a shielded pool total must not go negative) is implemented in
`core/modules/validation/src/connect_block.c:231` and is not on the reducer
path that finalizes blocks. See
[`work/reducer-shielded-consensus-plan.md`](../work/reducer-shielded-consensus-plan.md).
The reducer's boot-reindex-only boundary is documented in
`engine/jobs/src/utxo_apply_delta.c:527`.

The direction (`docs/work/self-verified-tip-plan.md`) is a **self-verified
UTXO anchor rebuild**: the internal boot path is `-refold-from-anchor`
(`engine/jobs/src/refold_progress.c`, `engine/services/src/anchor_selfmint.c`),
which rebuilds the coin set forward from a compiled checkpoint instead of
borrowing it. Landing this removes the older recovery-import code that feeds
the borrowed-seed path. A complete atomic state install and copy proof must
precede any live cutover away from a borrowed-state node.

Your own node's live status — wedged, cured, or holding tip on self-verified
state — is not something this page can tell you: check it with `z23 status`
and `z23 dumpstate reducer_frontier`.

## 5. Where to start

1. Read **`docs/work/FORWARD_PLAN.md`** (the current plan), then
   **`docs/MVP.md`** (the v1 acceptance bar). `docs/commons/FRAMEWORK.md` is the
   canonical architecture; this page is its plain-language summary.
   **`docs/agent/AGENT_TRAPS.md`** lists things that look broken but are not
   (don't re-chase them);
   **`docs/CODEBASE_MAP.md`** is where-things-live + how-to-do-each-thing.
   `docs/HANDOFF.md` records one maintainer's hosted-node state — read it only
   if you are operating that specific node; it says nothing about a node you
   run yourself.
2. Check the node with `z23 status` and `z23 milestone`. Use the calls in
   section 3 for diagnostics and interface discovery.
3. For development, use `z23 agentmap` for the code/docs/test map and
   `z23 agentbuild` for the cached build-loop contract.
4. To understand one stage, open `engine/jobs/src/<stage>_stage.c`, replacing
   `<stage>` with its name from section 2. Follow its registered step function
   and the helpers it calls.
