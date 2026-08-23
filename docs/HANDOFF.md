> **Read this file first for current live-node state.** This page can be
> stale and the node cannot. Older revisions are evidence, not standing
> fact — recover them with `git log --follow -- docs/HANDOFF.md`.

# HANDOFF — current state

This page is maintainer-only. It records how to re-check the project's
hosted node; it does not define product direction or development priority.
Read [`../AGENTS.md`](../AGENTS.md) for the durable contract and
[`work/FORWARD_PLAN.md`](work/FORWARD_PLAN.md) for the current ordered
mission, then re-derive every live claim through the node.

Typed status commands are ground truth. This page is a pointer to evidence
files, never a substitute for re-checking them. Do not copy live heights,
peer counts, wallet amounts, soak hours, restart counts, or binary SHAs
into this file or into durable entry documents.

## 0-LATEST

Re-check the hosted node before trusting any paragraph on this page:

```bash
z23 status
z23 dumpstate reducer_frontier
tail -5 ~/.local/state/zclassic23-slo/uptime-ledger.jsonl
```

Do not copy those outputs here. A later session must run the same commands
again. `z23 status` and `z23 dumpstate reducer_frontier` answer live height,
blockers, and frontier posture; the uptime-ledger tail answers reachability
and sample history. Recovery and cure design live in
[`TENACITY.md`](TENACITY.md) and
[`work/self-verified-tip-plan.md`](work/self-verified-tip-plan.md), not in a
copied snapshot.

Check whether the running binary matches this checkout before diagnosing
anything live:

```bash
make agent-doctor | sed -n 2p     # live_node=… running_this_tree=true|false
```

`running_this_tree=false` means stop and ship, or read the deployed source.
Do not reason about live behaviour from this checkout. The node can look
exactly like a node with a real bug when the fix is already in `main` and
merely never shipped.

## How to read the ledgers

| Claim | Command or file |
|---|---|
| Compact live state, blockers, frontier | `z23 status`; `z23 dumpstate reducer_frontier` |
| Loopback reachability, local-oracle height gap, peers, RSS, disk, Tor, standing blocker | `~/.local/state/zclassic23-slo/uptime-ledger.jsonl` |
| 72h hold accrual | `~/.local/state/zclassic23-slo/hold-ledger.jsonl`; judge `tools/scripts/slo_hold_judge.sh`; `make install-hold-certifier` |
| Cure / refold verdict | `~/.local/state/zclassic23-cure/verdict.jsonl` |
| EXTERNAL availability (not a loopback dial) | `~/.local/state/zclassic23-public-smoke/availability-ledger.jsonl`; collector `tools/scripts/public_explorer_smoke.sh` |
| Operator interventions, declared and undeclared | `~/.local/state/zclassic23-intervention/intervention-ledger.jsonl`; detector `tools/scripts/intervention_ledger.sh`; front door `tools/scripts/zcl_intervene.sh` |
| Off-host tip-hash agreement | `~/.local/state/zclassic23-parity/agreement-ledger.jsonl`; `make tip-agreement-status` |
| Zero-intervention window | `tools/scripts/intervention_ledger.sh summary` (optional epoch) |
| Soak evidence | `make soak-evidence-report` |
| Lane health | `make lane-health`; `z23 agentlanes` |
| Transaction-lab bars | `make transaction-lab-status` |
| MVP / MRS | [`MVP.md`](MVP.md); `z23 milestone` |

`reachable` in the uptime ledger is a **loopback** RPC dial from the same
host as the node. It answers "the process is answering", never "a user can
reach the service". External availability is the public-smoke ledger only.

`gap_vs_oracle` is a **height delta against the local sibling `zclassicd`**.
It compares numbers, not blocks. Do not read it as hash or UTXO parity.

Block-hash comparison against remote peers is a **separate** ledger:
`~/.local/state/zclassic23-parity/agreement-ledger.jsonl`. Read
`make tip-agreement-status` and `clean_agrees`, not raw `agrees`. A sample
can say `agrees` at one height while a rival two-host cluster disagrees
elsewhere in the window. Tor-only peer sets cannot satisfy the two-host
rung: `net_addr_to_string` renders every torv3 peer as `[torv3]`, so onion
peers collapse to one host key. `ZCL_PARITY_EXCLUDE_HOSTS` can only make
that gate harder.

A claim that the node ran N days untouched is only checkable against the
intervention ledger. `NRestarts` counts automatic restarts only; a manual
`systemctl restart` resets it, and it is blind to a config edit or a binary
swap that does not restart the process.

## Lanes

| Lane | Datadir | Deploy | Purpose |
|---|---|---|---|
| **live** | `$HOME/.zclassic-c23` | `make deploy` (owner-gated) | Public daily-driver node; restart only for a vetted live deploy. |
| **dev** | `$HOME/.zclassic-c23-dev` | verify/probe only | Isolated build/test lane; public tooling cannot restart or publish to it. |
| **soak** | `$HOME/.zclassic-c23-soak` | deliberate re-baseline | Long-uptime / weekly evidence lane; do not churn during development. |

`z23 agentlanes` / REST `/api/v1/agent` report each lane's
`operator_lane` (`zcl.operator_lane.v1`) and restart policy; prefer that
contract over parsing systemd names. The units declare the same intent with
`-operator-lane=canonical|dev|soak`. `zclassicd` (the C++ reference) runs
co-located — never stop it.

`make deploy-dev`, `make deploy-dev-fast`, and `make agent-deploy-fast` are
Phase-0 contained: every public invocation refuses before service, datadir,
or generation mutation. Build, source verification, simulation, and hermetic
fixture probes stay available.

`make lane-health` is the read-only three-lane status check. `role_ready`
answers whether a lane serves its assigned purpose; `soak_eligible=false`
means the soak lane is alive but not earning clean MVP-C6 evidence. It is
an observability check, not automatic failover.

Its bounded report includes height and lag from the live lane, peer and
restart posture, memory pressure, role readiness, soak-evidence eligibility,
and `bootstrapstatus.snapshot_loader` details: snapshot seed height, active
loader path, and `recovery_hint`.

`make lane-recover LANE=dev|soak` is a read-only bounded recovery planner
emitting `zcl.lane_recovery_plan.v1`. Public `--apply` and
`ZCL_LANE_RECOVERY_APPLY=1` refuse before any mutation; `live`, `canonical`,
and `main` are refused outright.

Copy-prove every recovery path on a datadir COPY before live; never live
surgery. Gate on **H\* CLIMB**, never "booted without FATAL." Never weaken a
safety/operator gate. Replay any consensus-predicate tightening against
real chain history first — see
[`CONSENSUS_PARITY_DOCTRINE.md`](CONSENSUS_PARITY_DOCTRINE.md).

## Operator invariants

- `-import-complete-shielded` requires the source chainstate's best block to
  equal exactly the target coins-island root — a bind guard, not a bug.
- A `-bootstrapserve` zclassicd pins its on-disk chainstate at the serve
  anchor.
- `chainstate_legacy_reader` reads LevelDB SSTs only; it does not replay a
  non-empty WAL. A non-empty WAL must refuse loudly rather than silently
  drop data.
- `zclassicd invalidateblock` does not persist across restarts in this fork.
- Anyone — human or agent — who restarts a unit, edits a drop-in, or
  replaces a binary declares it first:

  ```bash
  zcl-intervene "why"                     # declare
  zcl-intervene "why" -- systemctl --user restart zclassic23   # declare + do
  ```

- Transaction laboratory: re-derive isolated vs live bars from
  `make transaction-lab-status`. Isolated proofs are not broadcast
  approval. Notebook and safety boundary:
  [`work/TRANSACTION_LAB.md`](work/TRANSACTION_LAB.md). Live classification
  and owner-review sequence:
  [`work/LIVE_TRANSACTION_DEMONSTRATIONS.md`](work/LIVE_TRANSACTION_DEMONSTRATIONS.md).

## MVP status

MRS and per-criterion evidence live in [`MVP.md`](MVP.md) and
`z23 milestone` (REST `GET /api/v1/milestone`). Only a run-passing
`make mvp-verify` member moves a ◐ to a ✅ — never hand-bump the count.
Soak accrual is `make soak-evidence-report`, not process uptime.

## Pointers

- [`work/FORWARD_PLAN.md`](work/FORWARD_PLAN.md) — the ordered mission.
- [`AGENT_TRAPS.md`](AGENT_TRAPS.md) — read before "fixing" anything.
- [`MVP.md`](MVP.md) — the v1 acceptance bar.
- [`TENACITY.md`](TENACITY.md) — copy-first recovery doctrine.
- [`work/self-verified-tip-plan.md`](work/self-verified-tip-plan.md) — sovereign-cure design.
- [`work/sovereign-cutover-runbook.md`](work/sovereign-cutover-runbook.md) — owner-gated cutover + revert.
- History of this page is `git log --follow -- docs/HANDOFF.md`.

A map, not the territory: trust the node you query this minute over this
file.
