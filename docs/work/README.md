# Work directory and parallel-worktree workflow

This directory holds the active plans, design records, and the
parallel-worktree protocol. It is not itself a priority queue:

1. [`../HANDOFF.md`](../HANDOFF.md) owns current live facts.
2. [`FORWARD_PLAN.md`](./FORWARD_PLAN.md) is the sole ordered execution plan.
3. [`../MVP.md`](../MVP.md) owns the v1 acceptance contract.

The active #1 track is the sovereign complete-state cure. Architecture
cleanup remains off the v1 path unless the owner explicitly promotes an
item. If this file and `../HANDOFF.md` ever disagree, HANDOFF wins — fix
this file to match it.

Worktrees are dynamic; never infer current workers from a hard-coded path
list. Inspect them with `git worktree list --porcelain`. The checkout at
`~/github/zclassic23` is normally the orchestrator. Every other registered
checkout is a worker or an isolated quality lane and must be inspected
before removal; dirty worktrees are preserved.

## How a worker session starts

Run `pwd` and `git worktree list --porcelain`, then follow
[`agent-protocol.md`](./agent-protocol.md). The assignment owns the branch,
scope, verification, and completion ritual; directory suffixes are labels,
not a permanent server inventory.

## Index — one line per file, annotated

**Authority** column: **PLAN** = ordering authority, read first; **LIVE** =
describes a shipped mechanism/procedure, reference as needed; **DESIGN** =
still-open design record, read before touching the area, not a priority
queue; **RETAINED** = superseded as a current plan but code/tests/scripts
cite specific numbered items from it by name — the file stays for that
citation, `git log --follow -- docs/work/<name>.md` recovers older intent.

| File | Authority | Purpose |
|---|---|---|
| [`FORWARD_PLAN.md`](./FORWARD_PLAN.md) | PLAN | THE ordered execution plan (autonomous / owner-gated / operational) |
| [`self-verified-tip-plan.md`](./self-verified-tip-plan.md) | PLAN | the `G-SOV` sovereignty-gate design + open hardening items; `G-SOV` is the active gate in `sovereignty_controller.c` |
| [`SOVEREIGN-NETWORK-ROADMAP.md`](./SOVEREIGN-NETWORK-ROADMAP.md) | PLAN | durable Phase 0–6 hierarchy and promotion gates; ordering authority when other plans differ |
| [`sovereign-cutover-runbook.md`](./sovereign-cutover-runbook.md) | PLAN/LIVE | owner-gated live cutover + revert procedure for the bundle install path |
| [`ZCODE_DEVELOPMENT_NETWORK.md`](./ZCODE_DEVELOPMENT_NETWORK.md) | PLAN | active agentic C23 development-network contract: canonical task/evidence objects, real ZBuild worker, requester-led P2P work, typed create/use/improve, and durability lanes |
| [`ZCODE_DEVELOPMENT_PRODUCT.md`](./ZCODE_DEVELOPMENT_PRODUCT.md) | PLAN | active v0.1 C23 product contract: measured expert-workflow baseline, project/work front door, bounded context/adapters/repair/review, self-hosting benchmark, and fresh-checkout acceptance |
| [`ZCODE_ADAPTER_BENCHMARK.md`](./ZCODE_ADAPTER_BENCHMARK.md) | EVIDENCE | frozen native-CLI adapter control, packet/order A/B measurements, shell-only app-server pilot, blockers, and adoption decision |
| [`ZCODE_DEVELOPMENT_WALKTHROUGH.md`](./ZCODE_DEVELOPMENT_WALKTHROUGH.md) | LIVE | five-minute small-C23-project path: inspect, start, bounded manual/Codex handoff, repair/evidence, explicit human acceptance, and the permanent hermetic acceptance target |
| [`C23_DEV_LOOP_PERFORMANCE.md`](./C23_DEV_LOOP_PERFORMANCE.md) | LIVE | single authoritative coverage/latency ledger for resident live reload, non-LTO fast restart, affected proofs, cache reuse and batched release proof |
| [`ZCODE_SCIENTIFIC_METAVERSE.md`](./ZCODE_SCIENTIFIC_METAVERSE.md) | PLAN | owner-directed ZCODE scientific object, evidence-network, discovery, proof-of-contribution, committee, and staged-custody implementation plan; includes parallel file ownership and no-live-funds gates |
| [`ZC23_LIVING_COMMONS.md`](./ZC23_LIVING_COMMONS.md) | PLAN | people+AI shared-metaverse mission, one creation API, immutable pre-genesis ZC23 naming, creation-backed issuance covenant, patronage boundary, and LC0-LC5 safe implementation order |
| [`ZC23_REPRODUCTION_RUNBOOK.md`](./ZC23_REPRODUCTION_RUNBOOK.md) | LIVE | O5 three-party portable-reproduction protocol, exact same-host acceptance gate, genuine second-machine verifier command, and explicit no-credit/no-live-authority boundaries |
| [`ZCODE_PLAN.md`](./ZCODE_PLAN.md) | FOUNDATION | original 15-slice ZCODE package-hosting order; slices 1–13 remain live foundations, while payout slices 14–15 are deferred behind the development network; `lib/vcs/include/vcs/package_reward.h` cites its "ZCL fuel economics" section by name |
| [`MARKETPLACE_PLAN.md`](./MARKETPLACE_PLAN.md) | PLAN | owner directive: on-chain P2P ZSLP/ZCL marketplace (same-chain single-tx swap + cross-chain HTLC) over the existing ZSWP/ZSLP primitives; application protocol only, no consensus surface |
| [`MARKETPLACE_NEXT.md`](./MARKETPLACE_NEXT.md) | PLAN | post-metaverse-MVP ordered checklist: two-laptop Tor market test, `zmarket_buy` end-to-end settlement wiring, ZC23 distribution design (owner decision gate) |
| [`MARKET_ONION_DELIVERY.md`](./MARKET_ONION_DELIVERY.md) | DESIGN | B5 onion-routed chunk delivery: offer v2 endpoint_type=onion wire, `/market/chunk` onion route, session-binding replacement, stub fail-closed policy, and the honest non-goals (timing, gossip metadata) |
| [`ZC23_DISTRIBUTION_OPTIONS.md`](./ZC23_DISTRIBUTION_OPTIONS.md) | DESIGN | Phase C1 owner-decision options: PoP naming, distribution model, earn-for-publishing mechanics, supply shape, and the six-point C2 decision list; decides nothing itself |
| [`shielded-history-importer.md`](./shielded-history-importer.md) | LIVE | reference for the shipped `-import-complete-shielded` operational cure; operational-vs-sovereign trust-mode split |
| [`CONSENSUS-STATE-BUNDLE.md`](./CONSENSUS-STATE-BUNDLE.md) | LIVE | naming/ownership authority for `zcl.consensus_state_bundle.v1` |
| [`fresh-start-seam.md`](./fresh-start-seam.md) | DESIGN | why a genuinely bare boot (empty datadir, isolated `$HOME`, no flags) reaches no state source and folds zero blocks: the two independent seams, every state source and the exact predicate that refuses it, and why the install gate is NOT circular at HEAD |
| [`never-stuck-plan.md`](./never-stuck-plan.md) | DESIGN | the wedge class this doc diagnosed is CURED; retained as the design record for the never-stuck hardening map + the per-height UTXO-ladder gap |
| [`fail-safe-architecture.md`](./fail-safe-architecture.md) | DESIGN | the progress law + universal repair ladder; absorbs `sticky-node-plan.md`'s invariants and `never-stuck-plan.md` §1b |
| [`sticky-node-plan.md`](./sticky-node-plan.md) | DESIGN/RETAINED | the stickiness invariants + gap analysis; §4 (the AAR/MTTUR metric) is cited by `tools/scripts/sticky_matrix.sh`/`sticky_fault_inject.sh` and the Makefile `sticky-matrix`/`sticky-matrix-v1` targets — keep §4 numbered as-is |
| [`canonical-frontier-derived-state-plan.md`](./canonical-frontier-derived-state-plan.md) | DESIGN | frontier-derived-state gates + heal-ladder deletion design; historical input, current gates are in `SOVEREIGN-NETWORK-ROADMAP.md` |
| [`ladder-carve-audit.md`](./ladder-carve-audit.md) | DESIGN | current per-file consumer graph for the borrowed-state ladder deletion; headline verdict: zero LOC deletable today |
| [`reducer-shielded-consensus-plan.md`](./reducer-shielded-consensus-plan.md) | DESIGN | anchor-membership + turnstile enforcement design (not implementation-ready — see its own §8 gaps) |
| [`concurrency-hazards-consensus-gated.md`](./concurrency-hazards-consensus-gated.md) | DESIGN | unfixed cross-thread hazards on the consensus/chain-advance path, boot-validation-blocked |
| [`refold-fold-rate-bottlenecks.md`](./refold-fold-rate-bottlenecks.md) | DESIGN | from-genesis refold fold-rate bottlenecks + fix order |
| [`tip-durability-collapse.md`](./tip-durability-collapse.md) | DESIGN | rationale of record for `coins_kv` as sole live UTXO author |
| [`wt-rom-fetch-engine.md`](./wt-rom-fetch-engine.md) | DESIGN | ROM-bundle fetch engine (client side of ROM delivery): trust model + open items |
| [`wt-s7-2-1-metaverse.md`](./wt-s7-2-1-metaverse.md) | PLAN | owner-directed S7.2.1 usability and consolidation lane over the existing Space/Scout foundation |
| [`os-substrate-plan.md`](./os-substrate-plan.md) | DESIGN | OS-substrate three-rung plan (shell-out removal, `os_proc` shim, sandbox facade) |
| [`os/A1-authority-receipt-idiom.md`](./os/A1-authority-receipt-idiom.md) | DESIGN | the Law-7 privileged-transition authority-receipt idiom, cited by `tools/lint/check_privileged_transition_receipt.sh` |
| [`os/A4-noise-transport-p1.md`](./os/A4-noise-transport-p1.md) | DESIGN | the Noise v2 P2P transport implementation contract |
| [`os/A6-adaptive-client-puzzle.md`](./os/A6-adaptive-client-puzzle.md) | DESIGN | load-adaptive client-puzzle primitive design (not yet built) |
| [`NAT_AND_ONION_TRANSPORT.md`](./NAT_AND_ONION_TRANSPORT.md) | DESIGN | onion-as-universal-rendezvous / clearnet-as-fast-path transport design notes (NAT traversal, onion hosting, package swarm); P2P-layer policy only, no consensus surface |
| [`DIRECT_TRANSPORT.md`](./DIRECT_TRANSPORT.md) | DESIGN | UDP datagram fast path + PEX-lite clearnet discovery + disclosure posture (`onion`\|`clearnet`\|`none`) + `zses:v1` session invites; application plane only, no consensus surface; complements NAT_AND_ONION_TRANSPORT |
| [`ONION_DIAL_GAP.md`](./ONION_DIAL_GAP.md) | LIVE | locally-reproduced defect record: outbound `.onion` P2P dials are never issued through the embedded Tor SOCKS path; names the fix slice and the two-node acceptance probe |
| [`palace-design.md`](./palace-design.md) | DESIGN | code-legibility layer: file/group purpose, `code room`, the three P1/P2/P3 lint gates (§3 cited by `test_make_lint_gates.c`) |
| [`service-result-convergence.md`](./service-result-convergence.md) | LIVE | `struct zcl_result` convergence ratchet inventory + lane plan for `app/services/`; gate is live, this is the shrinking-floor inventory |
| [`secure-transport-design.md`](./secure-transport-design.md) | DESIGN | Noise_XX v2 transport protocol contract (implemented, default off) |
| [`wire-next-wave-specs.md`](./wire-next-wave-specs.md) | DESIGN | next-wave `simnet_wire` lane specs (eclipse/partition, bandwidth/reorder, app-layer flows) |
| [`session-substrate-probes.md`](./session-substrate-probes.md) | DESIGN | measured rootless-sandboxing capability probes for the multi-user-server program |
| [`LLM-C23-APP-PLATFORM-CHECKLIST.md`](./LLM-C23-APP-PLATFORM-CHECKLIST.md) | DESIGN | future LLM/App platform execution checklist (Phases 3–5); not the current execution queue, cannot displace the sovereign cure |
| [`agent-spend-policy-design.md`](./agent-spend-policy-design.md) | LIVE/RETAINED | scoped agent authority over digital assets — shipped as `agent_sessions` (migration v36) + `app/services/include/services/agent_spend_policy.h`; 16 `.c`/`.h`/test files cite its "Minting + presentation" and "Enforcement" sections by name, so keep those headings as-is |
| [`UX_PLAN.md`](./UX_PLAN.md) | LIVE | the two-lane UX program (shared server-rendered design system + terminal presentation); both lanes have landed, `tools/command/cli_render.h`, `tools/command/native_command.c`, `src/main_cli_modes.c` and `lib/test/src/test_cli_render.c` cite its "terminal lane" by name |
| [`HOTSWAP.md`](./HOTSWAP.md) | LIVE | the dev-only hot-swap mechanisms |
| [`fast-path.md`](./fast-path.md) | LIVE | the information algorithm + fast inner-loop commands for any change |
| [`agent-protocol.md`](./agent-protocol.md) | LIVE | worker startup/completion protocol (this file's companion) |
| [`test-result-cache.md`](./test-result-cache.md) | LIVE | content-addressed per-group test result cache |
| [`stopwatch-gates.md`](./stopwatch-gates.md) | LIVE | the C3 / net-disruption wall-clock stopwatch gates |
| [`coldstart-remote-peer-proof.md`](./coldstart-remote-peer-proof.md) | LIVE | the C3 stopwatch run against a REMOTE peer (`make mvp-coldstart-to-tip-remote`) and what it names |
| [`mvp-ci-map.md`](./mvp-ci-map.md) | LIVE | each MVP criterion → its mechanical CI check |
| [`mvp-live-gate.md`](./mvp-live-gate.md) | LIVE | `tools/mvp_gate.sh`, the live-node MVP probe companion to the CI map |
| [`sim-phase2-plan.md`](./sim-phase2-plan.md) | LIVE | the in-memory simulation network reference |
| [`io-harness-design.md`](./io-harness-design.md) | LIVE | the `simnet_wire` adversarial network-IO harness design |
| [`GROTH16-SPEND-PARITY.md`](./GROTH16-SPEND-PARITY.md) | LIVE | native Sapling spend-circuit differential parity scoreboard |
| [`tenacity-roadmap.md`](./tenacity-roadmap.md) | RETAINED | superseded as a roadmap by `FORWARD_PLAN.md` + `self-verified-tip-plan.md` (`docs/TENACITY.md` remains the standing doctrine); items 3/5, the "Hold-class doctrine" and "Stability hardening backlog" sections, and §4's seal/window design are cited by name from reindex/replay-canary/`seal_kv` code and `tools/scripts/check_blocker_remedy.sh`/`reindex_smoke.sh`/the Makefile |
| [`parity-audit-round2-findings.md`](./parity-audit-round2-findings.md) | RETAINED | superseded audit, retained — findings L1/L2/L3 cited by the consensus-parity lock-in tests |
| [`consensus-parity-supplemental-audit-2026-06-08.md`](./consensus-parity-supplemental-audit-2026-06-08.md) | RETAINED | superseded audit, retained — §2 item 5 cited by `docs/AGENT_TRAPS.md`; landed-fix summary condensed into `docs/CONSENSUS_PARITY_DOCTRINE.md` |
| [`lint-gate-hollowness-audit.md`](./lint-gate-hollowness-audit.md) | RETAINED | the fail-loud-scan-floor lint-gate pattern, cited by `tools/lint/gate_lib.sh` and its self-test |

This table covers **every** tracked file in this directory. Reconcile it after
adding one — `git ls-files docs/work/` minus the paths linked above must be
empty, and an index that does not list everything is an index that lies.

Recover any prior version of a file in this directory with
`git log --follow -- docs/work/<name>.md`.

Before deleting anything here, clear all three: it is classified superseded
above (PLAN / LIVE / DESIGN / RETAINED are not deletion candidates — DESIGN
means still-open, RETAINED means deliberately kept for a by-name citation);
`git grep -n "<name>.md" -- "*.c" "*.h"` is empty; and
`git grep -n "<name>.md" -- "*.md"` is empty. A comment citation does not fail
`check-error-doc-refs` (it only reads string literals) but it is still a
load-bearing pointer for the next reader.

That third check is not theoretical. Seven files already deleted from this
directory are still named from code, tests, and other docs, and nothing fired:

```sh
git grep -ho 'docs/work/[A-Za-z0-9_./-]*\.md' -- '*.c' '*.h' '*.md' '*.sh' Makefile |
  sort -u | while read -r p; do
    git ls-files --error-unmatch "$p" >/dev/null 2>&1 || echo "DANGLING: $p"
  done
```

At the time of writing that prints seven names — two under a since-removed
`archive/` subdirectory (lb1-wiring-design, sovereign-service-roadmap) plus
`coin-backfill-repair.md`, `parallel-state-compiler.md`,
`sync-organism-map.md`, `worktree-cleanup-2026-07-16.md` and
`wt-phase4c-block-index-projection.md` — cited from
`app/jobs/src/stage_repair_coin_backfill*.c`,
`app/jobs/include/jobs/psc_range_fold.h`,
`lib/storage/include/storage/coins_kv.h`, `tools/scripts/worktree_gc.sh`,
`docs/AGENT_TRAPS.md` and six test files. Run the check before deleting, and
repoint or drop the citation in the same commit.

## Active control documents

- **Current work:** [`FORWARD_PLAN.md`](./FORWARD_PLAN.md) (THE plan),
  [`self-verified-tip-plan.md`](./self-verified-tip-plan.md) (the cure
  spine), [`CONSENSUS-STATE-BUNDLE.md`](./CONSENSUS-STATE-BUNDLE.md) (bundle
  naming/ownership authority), and
  [`sovereign-cutover-runbook.md`](./sovereign-cutover-runbook.md) (install
  runbook).
- **Current architecture:** [`../FRAMEWORK.md`](../FRAMEWORK.md) (reference,
  off the v1 path — §9 is the open-item debt board, which self-labels NOT
  the v1 path).
- **Session entrypoint:** [`../HANDOFF.md`](../HANDOFF.md).
- **Worker protocol:** this file plus [`agent-protocol.md`](./agent-protocol.md).

## Worker protocol

Each assignment lives at `docs/work/wt<N>-<slug>.md` and contains:

- **Branch name** — exact name to create
- **Scope** — files this assignment owns; files it must NOT touch
- **Dependencies** — other assignments that must complete first
- **Tasks** — ordered, testable steps
- **Acceptance criteria** — concrete tests that prove done
- **Commit + push instructions** — exact git commands
- **Completion ritual** — what to append at the end

## Conflict avoidance

- **Disjoint file scope**: each assignment lists exact files it owns; no
  other assignment may touch those files until it merges.
- **No concurrent edits to** `../FRAMEWORK.md` §9 (the debt board): only
  orchestrator writes it. Workers append to their own assignment doc.
- **Integrate deliberately**: follow the current operator skill and
  assignment instructions; do not assume every dirty checkout can safely
  rebase or push.

## Failure modes

- **Worker discovers assignment is wrong or impossible** → worker appends a
  `BLOCKED` section to its assignment doc with details, pushes, reports to
  user. Orchestrator session must respond.
- **Worker's tests fail** → worker does NOT merge; pushes a `WIP` branch +
  appends a `FAILED` section with the failing test output.
- **Two workers touch overlapping files (should not happen)** →
  second-to-merge rebases, orchestrator session resolves.

## Late-indexed records (reconciled 2026-08-23)

| File | Authority | Purpose |
|---|---|---|
| [`C23_LIVING_COMMONS_V2.md`](./C23_LIVING_COMMONS_V2.md) | DESIGN | additive pre-genesis protocol foundation: family commons + evidence economics objects and commands |
| [`C23_P2P_CORE_INVENTORY.md`](./C23_P2P_CORE_INVENTORY.md) | DESIGN | reviewed P2P core-consolidation code inventory (2026-08-12); a map, not a plan |
| [`canonical-unit-reconciliation.md`](./canonical-unit-reconciliation.md) | DESIGN | canonical unit reconciliation — explicitly PREPARED, NOT APPLIED; nothing here is live |
| [`LIVE_TRANSACTION_DEMONSTRATIONS.md`](./LIVE_TRANSACTION_DEMONSTRATIONS.md) | LIVE | runbook: which cataloged transaction shapes are demonstrated live, and how |
| [`REFLEX_REACTOR.md`](./REFLEX_REACTOR.md) | LIVE | local zero-wait reflex reactor: edit C23, receive first exact next-build result |
| [`REFLEX_SUBSTRATE_AUDIT.md`](./REFLEX_SUBSTRATE_AUDIT.md) | EVIDENCE | measured coverage/latency audit of the merged reflex implementation (2026-08-12) |
| [`SHOP_COMMAND.md`](./SHOP_COMMAND.md) | PLAN | owner-approved `zclassic shop` one-command sovereign storefront specification |
| [`TRANSACTION_LAB.md`](./TRANSACTION_LAB.md) | LIVE | transaction laboratory notebook; keeps its two questions separate |
| [`TRANSACTION_MICRO_LAB.md`](./TRANSACTION_MICRO_LAB.md) | PLAN | owner-visible 100-transaction micro lab demonstration plan |
| [`ZC23_DISTRIBUTION_RULES.md`](./ZC23_DISTRIBUTION_RULES.md) | PLAN | ZC23 distribution rules — phase C2, owner-decided 2026-08-09 |
| [`transaction-lab-events.jsonl`](./transaction-lab-events.jsonl) | EVIDENCE | event ledger backing TRANSACTION_LAB |
| [`transaction-micro-lab-events.jsonl`](./transaction-micro-lab-events.jsonl) | EVIDENCE | event ledger backing TRANSACTION_MICRO_LAB |
| [`zcode-selfhost-validation-ledger.json`](./zcode-selfhost-validation-ledger.json) | EVIDENCE | zcl.zcode_selfhost_validation_ledger.v1 snapshot |
| [`zcode-selfhost-evidence/`](./zcode-selfhost-evidence/) | EVIDENCE | frozen born-red replay artifacts: 15 paired json+log files (foundation-replay, codec-cursor, package-dev, package-registry, score-receipt, sha3-foundation) |
| [`zcode-selfhost-evidence/born-red-base-foundation-replay.json`](./zcode-selfhost-evidence/born-red-base-foundation-replay.json) | EVIDENCE | born-red replay artifact (base-foundation-replay json half of paired proof) |
| [`zcode-selfhost-evidence/born-red-base-foundation-replay.log`](./zcode-selfhost-evidence/born-red-base-foundation-replay.log) | EVIDENCE | born-red replay artifact (base-foundation-replay log half of paired proof) |
| [`zcode-selfhost-evidence/born-red-codec-cursor.json`](./zcode-selfhost-evidence/born-red-codec-cursor.json) | EVIDENCE | born-red replay artifact (codec-cursor json half of paired proof) |
| [`zcode-selfhost-evidence/born-red-codec-cursor.log`](./zcode-selfhost-evidence/born-red-codec-cursor.log) | EVIDENCE | born-red replay artifact (codec-cursor log half of paired proof) |
| [`zcode-selfhost-evidence/born-red-package-dev.json`](./zcode-selfhost-evidence/born-red-package-dev.json) | EVIDENCE | born-red replay artifact (package-dev json half of paired proof) |
| [`zcode-selfhost-evidence/born-red-package-dev.log`](./zcode-selfhost-evidence/born-red-package-dev.log) | EVIDENCE | born-red replay artifact (package-dev log half of paired proof) |
| [`zcode-selfhost-evidence/born-red-package-registry.json`](./zcode-selfhost-evidence/born-red-package-registry.json) | EVIDENCE | born-red replay artifact (package-registry json half of paired proof) |
| [`zcode-selfhost-evidence/born-red-package-registry.log`](./zcode-selfhost-evidence/born-red-package-registry.log) | EVIDENCE | born-red replay artifact (package-registry log half of paired proof) |
| [`zcode-selfhost-evidence/born-red-score-receipt.json`](./zcode-selfhost-evidence/born-red-score-receipt.json) | EVIDENCE | born-red replay artifact (score-receipt json half of paired proof) |
| [`zcode-selfhost-evidence/born-red-score-receipt.log`](./zcode-selfhost-evidence/born-red-score-receipt.log) | EVIDENCE | born-red replay artifact (score-receipt log half of paired proof) |
| [`zcode-selfhost-evidence/born-red-sha3-foundation-replay.json`](./zcode-selfhost-evidence/born-red-sha3-foundation-replay.json) | EVIDENCE | born-red replay artifact (sha3-foundation-replay json half of paired proof) |
| [`zcode-selfhost-evidence/born-red-sha3-foundation-replay.log`](./zcode-selfhost-evidence/born-red-sha3-foundation-replay.log) | EVIDENCE | born-red replay artifact (sha3-foundation-replay log half of paired proof) |
