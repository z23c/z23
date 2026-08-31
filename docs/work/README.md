<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Work directory and parallel-worktree workflow

This directory holds one active plan plus scoped design records, retained
rationale, and specialist procedures. It is not itself a priority queue:

1. [`FORWARD_PLAN.md`](./FORWARD_PLAN.md) is the sole ordered execution plan.
2. [`../MVP.md`](../MVP.md) owns the v1 acceptance contract.
3. [`../HANDOFF.md`](../HANDOFF.md) owns maintainer-host live facts only.

The ordered mission is the first open item in
[`FORWARD_PLAN.md`](./FORWARD_PLAN.md) at the current commit. This index does
not summarize or promote an older plan back into the queue. Hosted-node facts
belong only in `../HANDOFF.md`; source priorities do not.

Worktrees are dynamic; never infer current workers from a hard-coded path
list. Inspect them with `git worktree list --porcelain`. No checkout path is a
permanent orchestrator. Every registered checkout may be a worker, proof
generation, compatibility tree, or manually owned lane and must be inspected
before removal; dirty and locked worktrees are preserved.

## How a worker session starts

Read [`../../AGENTS.md`](../../AGENTS.md), choose the first open item in
[`FORWARD_PLAN.md`](./FORWARD_PLAN.md), then use `pwd` and `git worktree list
--porcelain` before following the compact [`agent-protocol.md`](./agent-protocol.md).
The assignment owns a disjoint surface and returns an immutable commit
identity; branch and directory suffixes are optional labels, not evidence or
permanent inventory.

## Index — one line per file, annotated

**Authority** column: **PLAN** = the sole ordering authority; **LIVE** =
describes a shipped mechanism/procedure, reference as needed; **DESIGN** =
still-open design record, read before touching the area, not a priority
queue; **RETAINED** = superseded as a current plan but code/tests/scripts
cite specific numbered items from it by name — the file stays for that
citation, `git log --follow -- docs/work/<name>.md` recovers older intent.

| File | Authority | Purpose |
|---|---|---|
| [`FORWARD_PLAN.md`](./FORWARD_PLAN.md) | PLAN | THE ordered execution plan (autonomous / owner-gated / operational) |
| [`TRI_PLATFORM_PLAN.md`](./TRI_PLATFORM_PLAN.md) | DESIGN | Linux, macOS, and Windows acceptance gaps and their platform-local closure order |
| [`self-verified-tip-plan.md`](./self-verified-tip-plan.md) | DESIGN | the `G-SOV` sovereignty-gate design + open hardening items; `G-SOV` is the active gate in `sovereignty_controller.c` |
| [`SOVEREIGN-NETWORK-ROADMAP.md`](./SOVEREIGN-NETWORK-ROADMAP.md) | FOUNDATION | durable Phase 0–6 hierarchy and promotion gates, subordinate to `FORWARD_PLAN.md` |
| [`SOVEREIGN_MACHINE_MESH_PLAN.md`](./SOVEREIGN_MACHINE_MESH_PLAN.md) | DESIGN | owner-paired Linux/macOS/Windows machine discovery, private transfer, typed control, secure remote-service tunnels, and hot-swap acceptance |
| [`sovereign-cutover-runbook.md`](./sovereign-cutover-runbook.md) | LIVE | owner-gated live cutover + revert procedure for the bundle install path |
| [`ZCODE_DEVELOPMENT_NETWORK.md`](./ZCODE_DEVELOPMENT_NETWORK.md) | DESIGN | agentic C23 development-network contract: canonical task/evidence objects, real ZBuild worker, requester-led P2P work, typed create/use/improve, and durability lanes |
| [`ZCODE_DEVELOPMENT_PRODUCT.md`](./ZCODE_DEVELOPMENT_PRODUCT.md) | DESIGN | v0.1 C23 product contract: measured expert-workflow baseline, project/work front door, bounded context/adapters/repair/review, self-hosting benchmark, and fresh-checkout acceptance |
| [`ZCODE_ADAPTER_BENCHMARK.md`](./ZCODE_ADAPTER_BENCHMARK.md) | EVIDENCE | frozen native-CLI adapter control, packet/order A/B measurements, shell-only app-server pilot, blockers, and adoption decision |
| [`ZCODE_DEVELOPMENT_WALKTHROUGH.md`](./ZCODE_DEVELOPMENT_WALKTHROUGH.md) | LIVE | five-minute small-C23-project path: inspect, start, bounded manual/Codex handoff, repair/evidence, explicit human acceptance, and the permanent hermetic acceptance target |
| [`C23_DEV_LOOP_PERFORMANCE.md`](./C23_DEV_LOOP_PERFORMANCE.md) | LIVE | single authoritative coverage/latency ledger for resident live reload, non-LTO fast restart, affected proofs, cache reuse and batched release proof |
| [`ZCODE_SCIENTIFIC_METAVERSE.md`](./ZCODE_SCIENTIFIC_METAVERSE.md) | DESIGN | owner-directed scientific-object and evidence-network design; includes no-live-funds gates |
| [`ZC23_LIVING_COMMONS.md`](./ZC23_LIVING_COMMONS.md) | DESIGN | people+AI shared-commons design and LC0-LC5 dependency order |
| [`ZC23_REPRODUCTION_RUNBOOK.md`](./ZC23_REPRODUCTION_RUNBOOK.md) | LIVE | O5 three-party portable-reproduction protocol, exact same-host acceptance gate, genuine second-machine verifier command, and explicit no-credit/no-live-authority boundaries |
| [`NATIVE_MACOS_RUNBOOK.md`](./NATIVE_MACOS_RUNBOOK.md) | LIVE | native arm64 macOS maintenance: expected-green set, per-host platform-seam selection, known host quirks, and the first fix move per gate that can go red there |
| [`NEON_CRYPTO_MATRIX.md`](./NEON_CRYPTO_MATRIX.md) | LIVE | per-crypto-family x86-64/arm64 tier matrix: gating, the test group proving bit-identity, the bench that times each tier, and honest no-clean-NEON-equivalent markers |
| [`ZCODE_PLAN.md`](./ZCODE_PLAN.md) | FOUNDATION | original 15-slice ZCODE package-hosting order; slices 1–13 remain live foundations, while payout slices 14–15 are deferred behind the development network; `lib/vcs/include/vcs/package_reward.h` cites its "ZCL fuel economics" section by name |
| [`MARKETPLACE_PLAN.md`](./MARKETPLACE_PLAN.md) | DESIGN | deferred application-protocol marketplace design; no consensus surface |
| [`MARKETPLACE_NEXT.md`](./MARKETPLACE_NEXT.md) | RETAINED | 2026-08-08 marketplace dependency ordering; unchecked boxes are not current work |
| [`MARKET_ONION_DELIVERY.md`](./MARKET_ONION_DELIVERY.md) | DESIGN | B5 onion-routed chunk delivery: offer v2 endpoint_type=onion wire, `/market/chunk` onion route, session-binding replacement, stub fail-closed policy, and the honest non-goals (timing, gossip metadata) |
| [`ZC23_DISTRIBUTION_OPTIONS.md`](./ZC23_DISTRIBUTION_OPTIONS.md) | RETAINED | the Phase C1 menu; C2 chose from it and `ZC23_DISTRIBUTION_RULES.md` §2 cites option **2A** by number, so the numbering stays as-is |
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
| [`os-substrate-plan.md`](./os-substrate-plan.md) | DESIGN | OS-substrate three-rung plan (shell-out removal, `os_proc` shim, sandbox facade) |
| [`os/A1-authority-receipt-idiom.md`](./os/A1-authority-receipt-idiom.md) | DESIGN | the Law-7 privileged-transition authority-receipt idiom, cited by `tools/lint/check_privileged_transition_receipt.sh` |
| [`os/A4-noise-transport-p1.md`](./os/A4-noise-transport-p1.md) | DESIGN | the Noise P2P transport implementation contract |
| [`os/A6-adaptive-client-puzzle.md`](./os/A6-adaptive-client-puzzle.md) | LIVE | the load-adaptive client-puzzle admission primitive, shipped as `lib/net/src/puzzle.c` + `lib/net/include/net/puzzle.h` (test group `puzzle`) |
| [`NAT_AND_ONION_TRANSPORT.md`](./NAT_AND_ONION_TRANSPORT.md) | DESIGN | onion-as-universal-rendezvous / clearnet-as-fast-path transport design notes (NAT traversal, onion hosting, package swarm); P2P-layer policy only, no consensus surface |
| [`DIRECT_TRANSPORT.md`](./DIRECT_TRANSPORT.md) | DESIGN | UDP datagram fast path + PEX-lite clearnet discovery + disclosure posture (`onion`\|`clearnet`\|`none`) + `zses:v1` session invites; application plane only, no consensus surface; complements NAT_AND_ONION_TRANSPORT |
| [`REMOTE_COMMAND_CHANNEL.md`](./REMOTE_COMMAND_CHANNEL.md) | DESIGN | `z23 remote <node> <leaf>`: carrying the typed command registry over the mesh instead of a shell — wire shape reusing the file-service session, owner-minted capability naming the leaves it grants, three typed refusals. Classification + gate have landed (`config/remote_command_classes.def`, `tools/lint/check_remote_command_classes.sh`); no transport, no dispatcher, no remote execution |
| [`palace-design.md`](./palace-design.md) | DESIGN | code-legibility layer: file/group purpose, `code room`, the three P1/P2/P3 lint gates (§3 cited by `test_make_lint_gates.c`) |
| [`service-result-convergence.md`](./service-result-convergence.md) | LIVE | `struct zcl_result` convergence ratchet inventory + lane plan for `app/services/`; gate is live, this is the shrinking-floor inventory |
| [`secure-transport-design.md`](./secure-transport-design.md) | DESIGN | Noise_XX transport protocol contract (implemented, default off) |
| [`wire-next-wave-specs.md`](./wire-next-wave-specs.md) | DESIGN | next-wave `simnet_wire` lane specs (eclipse/partition, bandwidth/reorder, app-layer flows) |
| [`session-substrate-probes.md`](./session-substrate-probes.md) | DESIGN | measured rootless-sandboxing capability probes for the multi-user-server program |
| [`LLM-C23-APP-PLATFORM-CHECKLIST.md`](./LLM-C23-APP-PLATFORM-CHECKLIST.md) | DESIGN | future LLM/App platform execution checklist (Phases 3–5); not the current execution queue, cannot displace the sovereign cure |
| [`agent-spend-policy-design.md`](./agent-spend-policy-design.md) | LIVE/RETAINED | scoped agent authority over digital assets — shipped as `agent_sessions` (migration v36) + `app/services/include/services/agent_spend_policy.h`; 16 `.c`/`.h`/test files cite its "Minting + presentation" and "Enforcement" sections by name, so keep those headings as-is |
| [`UX_PLAN.md`](./UX_PLAN.md) | LIVE | the two-lane UX program (shared server-rendered design system + terminal presentation); both lanes have landed, `tools/command/cli_render.h`, `tools/command/native_command.c`, `src/main_cli_modes.c` and `lib/test/src/test_cli_render.c` cite its "terminal lane" by name |
| [`HOTSWAP.md`](./HOTSWAP.md) | LIVE | the dev-only hot-swap mechanisms |
| [`fast-path.md`](./fast-path.md) | LIVE | the information algorithm + fast inner-loop commands for any change |
| [`agent-protocol.md`](./agent-protocol.md) | LIVE | compact parallel-worker adapter to AGENTS.md and DEVELOPING.md; no second workflow authority |
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
| [`utxo-mirror-authority-rewind.md`](./utxo-mirror-authority-rewind.md) | EVIDENCE | mirror-cursor-above-authority diagnosis (next-height cursors on both sides), the quarantine verdict, and the recovery experiment record |

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

That third check is not theoretical. Files already deleted from this directory
are still named from code, tests, `.def` tables and other docs, and no gate
fires on any of them. Run this and read the output — never a count written
here, which rots the moment someone deletes or repoints one:

```sh
git grep -ho 'docs/work/[A-Za-z0-9_./-]*\.md' \
    -- '*.c' '*.h' '*.md' '*.sh' '*.def' '*.txt' Makefile |
  sort -u | while read -r p; do
    git ls-files --error-unmatch "$p" >/dev/null 2>&1 || echo "DANGLING: $p"
  done
```

`.def` and `.txt` matter: `app/controllers/include/controllers/agent_impact_rules.def`
and the `tools/lint/*_baseline.txt` files cite these paths too, and a grep
limited to the C, header, Markdown and shell suffixes misses them.

Two kinds come back, and only one is a defect:

- **Deliberate** — a deleted file named so the reader can recover it with
  `git log --follow`, or a trap note naming a doc so nobody re-creates it.
  These read as recovery hints and carry their reason inline; leave them.
- **Load-bearing and broken** — a source or test comment that points the next
  reader at a design section by number for a file that is gone. The section
  numbers survive only in git history, so the pointer is now a dead end.

Run the check before deleting, and repoint or drop the citation in the same
commit — retiring a doc is not finished until its callers are gone too.

## Active control documents

- **Current work:** [`FORWARD_PLAN.md`](./FORWARD_PLAN.md) is the sole ordered
  plan. Other PLAN/LIVE rows below are scoped contracts and runbooks; they do
  not override its priority order.
- **Session entrypoint:** [`../../AGENTS.md`](../../AGENTS.md), then
  [`FORWARD_PLAN.md`](./FORWARD_PLAN.md).
- **Maintainer-host live state only:** [`../HANDOFF.md`](../HANDOFF.md); never
  use it to choose ordinary development work.
- **Architecture reference:** [`../FRAMEWORK.md`](../FRAMEWORK.md); its scoped
  debt inventory is not a priority queue.
- **Worker protocol:** [`agent-protocol.md`](./agent-protocol.md).

## Worker protocol

Parallel-worker mechanics are adapted in
[`agent-protocol.md`](./agent-protocol.md); project authority, integration, and
completion remain defined by `AGENTS.md` and `docs/DEVELOPING.md`.

## Late-indexed records (reconciled 2026-08-23)

| File | Authority | Purpose |
|---|---|---|
| [`ZC23_FAMILY_COMMONS.md`](./ZC23_FAMILY_COMMONS.md) | DESIGN | additive pre-genesis protocol foundation: family commons + evidence economics objects and commands |
| [`C23_P2P_CORE_INVENTORY.md`](./C23_P2P_CORE_INVENTORY.md) | DESIGN | reviewed P2P core-consolidation code inventory (2026-08-12); a map, not a plan |
| [`canonical-unit-reconciliation.md`](./canonical-unit-reconciliation.md) | DESIGN | systemd drop-in reconciliation runbook: lexical apply order, detecting an `ExecStart=` collision, reading `/proc/<pid>/cmdline` for ground truth vs. `systemctl show`, and the hazard of another actor rewriting drop-ins mid-reconciliation |
| [`LIVE_TRANSACTION_DEMONSTRATIONS.md`](./LIVE_TRANSACTION_DEMONSTRATIONS.md) | LIVE | runbook: which cataloged transaction shapes are demonstrated live, and how |
| [`REFLEX_REACTOR.md`](./REFLEX_REACTOR.md) | LIVE | local zero-wait reflex reactor: edit C23, receive first exact next-build result |
| [`REFLEX_SUBSTRATE_AUDIT.md`](./REFLEX_SUBSTRATE_AUDIT.md) | EVIDENCE | measured coverage/latency audit of the merged reflex implementation (2026-08-12) |
| [`SHOP_COMMAND.md`](./SHOP_COMMAND.md) | DESIGN | owner-approved `app shop` one-command sovereign storefront specification; not an execution queue |
| [`TRANSACTION_LAB.md`](./TRANSACTION_LAB.md) | LIVE | transaction laboratory notebook; keeps its two questions separate |
| [`TRANSACTION_MICRO_LAB.md`](./TRANSACTION_MICRO_LAB.md) | LIVE | owner-gated 100-transaction demonstration runbook; never ordinary development work |
| [`ZC23_DISTRIBUTION_RULES.md`](./ZC23_DISTRIBUTION_RULES.md) | RETAINED | owner-decided phase-C2 policy record; simulation-only and not an execution queue |
| [`WIRE_COMPILE_CACHE.md`](./WIRE_COMPILE_CACHE.md) | DESIGN | Commons WIRE lane working note: transfer framing, POINTER/PROVIDER discovery records, and the cross-node compile cache; subordinate to `../spec/c23-package-format.md`, which wins on any disagreement |
| [`transaction-lab-events.jsonl`](./transaction-lab-events.jsonl) | EVIDENCE | event ledger backing TRANSACTION_LAB |
| [`transaction-micro-lab-events.jsonl`](./transaction-micro-lab-events.jsonl) | EVIDENCE | event ledger backing TRANSACTION_MICRO_LAB |
| [`retrieval-gold-evidence/retrieval-gold-benchmark-b663f019ed20d6ece26aa94b5dfe92f41bd4c0be.jsonl`](./retrieval-gold-evidence/retrieval-gold-benchmark-b663f019ed20d6ece26aa94b5dfe92f41bd4c0be.jsonl) | EVIDENCE | frozen nine-record publishable retrieval receipt; exact evaluator-batch replay, six-task equal-weight macro denominator, 28 eligible relevance judgments, and explicit unavailable ceilings |
| [`retrieval-gold-evidence/retrieval-gold-benchmark-476e66661523.jsonl`](./retrieval-gold-evidence/retrieval-gold-benchmark-476e66661523.jsonl) | EVIDENCE | frozen 12-record publishable retrieval receipt for the distinct ten-task v2 cohort; exact evaluator-batch and per-task ranking-root replay, nine-task equal-weight macro denominator, 43 eligible relevance judgments, and explicit unavailable ceilings |
| [`retrieval-gold-evidence/retrieval-gold-benchmark-705d16ccab6b.jsonl`](./retrieval-gold-evidence/retrieval-gold-benchmark-705d16ccab6b.jsonl) | EVIDENCE | frozen 12-record publishable receipt for the same ten-task cohort with a current-driver directory-taxonomy scope proxy over exact-parent source: literal 7,209 bp and BM25 4,888 bp wrong-group selections at five; semantic scope, reuse success, and unique LOC avoided remain unobserved |
| [`retrieval-gold-evidence/retrieval-gold-benchmark-25fe3e353288.jsonl`](./retrieval-gold-evidence/retrieval-gold-benchmark-25fe3e353288.jsonl) | EVIDENCE | frozen 12-record publishable third-arm receipt with two sealed evaluator metric replays: the rare-identifier and observed-reverse-reference permutation records Recall@5 1,243 bp versus BM25 936 bp, equal Recall@20 at 3,502 bp, projected five-result context 733,211 versus 853,082 bytes, and directory-taxonomy proxy 4,666 versus 4,888 bp; vectors are not used, while scanner completeness, semantic scope, reuse success, and unique LOC avoided remain unobserved |
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
