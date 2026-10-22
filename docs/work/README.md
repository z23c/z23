<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Work directory and parallel-worktree workflow

This directory holds scoped product plans, design records, retained
rationale, and specialist procedures. It is not itself a priority queue:

1. The [Now list in `FORWARD_PLAN.md`](./FORWARD_PLAN.md#now) is the current work order, and
   [`FLEET_SCORECARD.md`](./FLEET_SCORECARD.md) owns the thirteen A+ completion
   bars. The rest of [`FORWARD_PLAN.md`](./FORWARD_PLAN.md) supplies scoped acceptance and
   implementation context.
2. [`../quality/MVP.md`](../quality/MVP.md) owns the v1 acceptance contract.
3. [`../agent/HANDOFF.md`](../agent/HANDOFF.md) owns maintainer-host live facts only.

Choose authorized work under the current tiers in `AGENTS.md`, closest to its
A+ bar within the tier; independent work may proceed in parallel. This index
does not promote an older plan back into the queue. Hosted-node facts
belong only in `../agent/HANDOFF.md`; source priorities do not.

Worktrees are dynamic; never infer current workers from a hard-coded path
list. Inspect them with `git worktree list --porcelain`. No checkout path is a
permanent orchestrator. Every registered checkout may be a worker, proof
generation, compatibility tree, or manually owned lane and must be inspected
before removal; dirty and locked worktrees are preserved.

## How a worker session starts

Read [`../../AGENTS.md`](../../AGENTS.md), select authorized work under its
fleet priorities and consult relevant scoped references, then inspect `pwd` and
`git worktree list --porcelain` before following the compact [`agent-protocol.md`](../agent/agent-protocol.md).
The assignment owns a disjoint surface and returns an immutable commit
identity; branch and directory suffixes are optional labels, not evidence or
permanent inventory.

## Index — one line per file, annotated

**Authority** column: **PLAN** = scoped product and implementation context;
**TARGET** = current acceptance target, not completion evidence; **LIVE** = describes a shipped mechanism/procedure, reference as needed; **DESIGN** =
still-open design record, read before touching the area, not a priority
queue; **RETAINED** = superseded as a current plan but code/tests/scripts
cite specific numbered items from it by name — the file stays for that
citation, `git log --follow -- docs/work/<name>.md` recovers older intent.

Developer references (hot-swap, test-result cache, fast path, lab) live in
[`../dev/`](../dev/README.md); agent and fleet documents live in
[`../agent/`](../agent/README.md); node, commons and quality references live in
[`../node/`](../node/README.md), [`../commons/`](../commons/README.md) and
[`../quality/`](../quality/README.md).

| File | Authority | Purpose |
|---|---|---|
| [`FORWARD_PLAN.md`](./FORWARD_PLAN.md) | PLAN | scoped acceptance and implementation context under AGENTS.md and the fleet A+ scorecard |
| [`FLEET_SCORECARD.md`](./FLEET_SCORECARD.md) | TARGET | thirteen owner-adopted A+ bars; work order is the Now list in `FORWARD_PLAN.md` |
| [`self-verified-tip-plan.md`](./self-verified-tip-plan.md) | DESIGN | the `G-SOV` sovereignty-gate design + open hardening items; `G-SOV` is the active gate in `sovereignty_controller.c` |
| [`SOVEREIGN-NETWORK-ROADMAP.md`](./SOVEREIGN-NETWORK-ROADMAP.md) | FOUNDATION | durable Phase 0–6 hierarchy and promotion gates, subordinate to `FORWARD_PLAN.md` |
| [`SOVEREIGN_MACHINE_MESH_PLAN.md`](./SOVEREIGN_MACHINE_MESH_PLAN.md) | DESIGN | owner-paired Linux/macOS/Windows machine discovery, private transfer, typed control, secure remote-service tunnels, and hot-swap acceptance |
| [`ZCODE_DEVELOPMENT_NETWORK.md`](./ZCODE_DEVELOPMENT_NETWORK.md) | DESIGN | agentic C23 development-network contract: canonical task/evidence objects, real ZBuild worker, requester-led P2P work, typed create/use/improve, and durability lanes |
| [`ZCODE_DEVELOPMENT_PRODUCT.md`](./ZCODE_DEVELOPMENT_PRODUCT.md) | DESIGN | v0.1 C23 product contract: measured expert-workflow baseline, project/work front door, bounded context/adapters/repair/review, self-hosting benchmark, and fresh-checkout acceptance |
| [`SEMANTIC_MANIFEST.md`](./SEMANTIC_MANIFEST.md) | DESIGN | canonical per-TU semantic manifest v1 (byte format, exact and hint roots, facts extension revision 2) and its one producer, the optional libclang sensor (a second parse at 1.2-1.6x `clang -fsyntax-only`); the planner consumer is not on main yet |
| [`ZCODE_SCIENTIFIC_METAVERSE.md`](./ZCODE_SCIENTIFIC_METAVERSE.md) | DESIGN | owner-directed scientific-object and evidence-network design; includes no-live-funds gates |
| [`ZC23_LIVING_COMMONS.md`](./ZC23_LIVING_COMMONS.md) | DESIGN | people+AI shared-commons design and LC0-LC5 dependency order |
| [`ZCODE_PLAN.md`](./ZCODE_PLAN.md) | FOUNDATION | original 15-slice ZCODE package-hosting order; slices 1–13 remain live foundations, while payout slices 14–15 are deferred behind the development network; `contexts/commons/modules/vcs/include/vcs/package_reward.h` cites its "ZCL fuel economics" section by name |
| [`MARKET_ONION_DELIVERY.md`](./MARKET_ONION_DELIVERY.md) | DESIGN | B5 onion-routed chunk delivery: offer v2 endpoint_type=onion wire, `/market/chunk` onion route, session-binding replacement, stub fail-closed policy, and the honest non-goals (timing, gossip metadata) |
| [`never-stuck-plan.md`](./never-stuck-plan.md) | DESIGN | the wedge class this doc diagnosed is CURED; retained as the design record for the never-stuck hardening map + the per-height UTXO-ladder gap |
| [`fail-safe-architecture.md`](./fail-safe-architecture.md) | DESIGN | the progress law + universal repair ladder; absorbs `sticky-node-plan.md`'s invariants and `never-stuck-plan.md` §1b |
| [`sticky-node-plan.md`](./sticky-node-plan.md) | DESIGN/RETAINED | the stickiness invariants + gap analysis; §4 (the AAR/MTTUR metric) is cited by `tools/scripts/sticky_matrix.sh`/`sticky_fault_inject.sh` and the Makefile `sticky-matrix`/`sticky-matrix-v1` targets — keep §4 numbered as-is |
| [`ladder-carve-audit.md`](./ladder-carve-audit.md) | DESIGN | current per-file consumer graph for the borrowed-state ladder deletion; headline verdict: zero LOC deletable today |
| [`reducer-shielded-consensus-plan.md`](./reducer-shielded-consensus-plan.md) | DESIGN | anchor-membership + turnstile enforcement design (not implementation-ready — see its own §8 gaps) |
| [`refold-fold-rate-bottlenecks.md`](./refold-fold-rate-bottlenecks.md) | DESIGN | from-genesis refold fold-rate bottlenecks + fix order |
| [`wt-rom-fetch-engine.md`](./wt-rom-fetch-engine.md) | DESIGN | ROM-bundle fetch engine (client side of ROM delivery): trust model + open items |
| [`os-substrate-plan.md`](./os-substrate-plan.md) | DESIGN | OS-substrate three-rung plan (shell-out removal, `os_proc` shim, sandbox facade) |
| [`os/A1-authority-receipt-idiom.md`](./os/A1-authority-receipt-idiom.md) | DESIGN | the Law-7 privileged-transition authority-receipt idiom, cited by `tools/lint/check_privileged_transition_receipt.sh` |
| [`os/A4-noise-transport-p1.md`](./os/A4-noise-transport-p1.md) | DESIGN | the Noise P2P transport implementation contract |
| [`os/A6-adaptive-client-puzzle.md`](./os/A6-adaptive-client-puzzle.md) | LIVE | the load-adaptive client-puzzle admission primitive, shipped as `core/modules/net/src/puzzle.c` + `core/modules/net/include/net/puzzle.h` (test group `puzzle`) |
| [`NAT_AND_ONION_TRANSPORT.md`](./NAT_AND_ONION_TRANSPORT.md) | DESIGN | onion-as-universal-rendezvous / clearnet-as-fast-path transport design notes (NAT traversal, onion hosting, package swarm); P2P-layer policy only, no consensus surface |
| [`DIRECT_TRANSPORT.md`](./DIRECT_TRANSPORT.md) | DESIGN | UDP datagram fast path + PEX-lite clearnet discovery + disclosure posture (`onion`\|`clearnet`\|`none`) + `zses:v1` session invites; application plane only, no consensus surface; complements NAT_AND_ONION_TRANSPORT |
| [`REMOTE_COMMAND_CHANNEL.md`](./REMOTE_COMMAND_CHANNEL.md) | DESIGN | `z23 remote <node> <leaf>`: carrying the typed command registry over the mesh instead of a shell — wire shape reusing the file-service session, owner-minted capability naming the leaves it grants, three typed refusals. Classification + gate have landed (`engine/composition/remote_command_classes.def`, `tools/lint/check_remote_command_classes.sh`); no transport, no dispatcher, no remote execution |
| [`service-result-convergence.md`](./service-result-convergence.md) | LIVE | `struct zcl_result` convergence ratchet inventory + lane plan for `engine/services/`; gate is live, this is the shrinking-floor inventory |
| [`PQ_HYBRID_RELEASE_SIGNATURE.md`](./PQ_HYBRID_RELEASE_SIGNATURE.md) | DESIGN | ZRS1 hybrid release signature: Ed25519 AND SLH-DSA-SHAKE-128s over the same zid prefix, v2 doc trailer layout, domain separation, resolved decisions, pair pins, k-of-n and migration plan; phase 1 and the signer half of phase 2 are implemented (`zid_hybrid`), pair pins and k-of-n are not |
| [`secure-transport-design.md`](./secure-transport-design.md) | DESIGN | Noise_XX transport protocol contract (implemented, default off) |
| [`separate-verifier.md`](./separate-verifier.md) | DESIGN | separate-account proof verifier: threat model, root setup and teardown, and slices; slice 1a (signed record, root-pinned key, admission) is `tools/dev/verify_attest.{h,c}` |
| [`verifier-contract-v2.md`](./verifier-contract-v2.md) | DESIGN | `z23verify.fixed_result.v2`: byte encoding of pins, launch request, result packet, launch receipt, signed record v2, store key and layout; retired v1 artifacts and refusal tokens |
| [`verifier-install-packet.md`](./verifier-install-packet.md) | DESIGN | root install and qualification packet for the fixed-result launcher, worker, signer and publisher: build hashes, accounts, trust files, key, units, qualification, RED fixtures, teardown |
| [`verifier-images.md`](./verifier-images.md) | DESIGN | fixed-result verifier images and seccomp filter: image format, discovered GCC 14 closure, pin values, no-root completeness proof, root install commands |
| [`wire-next-wave-specs.md`](./wire-next-wave-specs.md) | DESIGN | next-wave `simnet_wire` lane specs (eclipse/partition, bandwidth/reorder, app-layer flows) |
| [`session-substrate-probes.md`](./session-substrate-probes.md) | DESIGN | measured rootless-sandboxing capability probes for the multi-user-server program |
| [`LLM-C23-APP-PLATFORM-CHECKLIST.md`](./LLM-C23-APP-PLATFORM-CHECKLIST.md) | DESIGN | future LLM/App platform execution checklist (Phases 3–5); not the current execution queue, cannot displace the sovereign cure |
| [`agent-spend-policy-design.md`](./agent-spend-policy-design.md) | LIVE/RETAINED | scoped agent authority over digital assets — shipped as `agent_sessions` (migration v36) + `cognition/services/include/services/agent_spend_policy.h`; 16 `.c`/`.h`/test files cite its "Minting + presentation" and "Enforcement" sections by name, so keep those headings as-is |
| [`parity-audit-round2-findings.md`](./parity-audit-round2-findings.md) | RETAINED | superseded audit, retained — findings L1/L2/L3 cited by the consensus-parity lock-in tests |

This table covers **every** tracked file in this directory. Reconcile it after
adding one — `git ls-files docs/work/` minus the paths linked above must be
empty, and an index that does not list everything is an index that lies.

Recover any prior version of a file in this directory with
`git log --follow -- docs/work/<name>.md`.

Retired on 2026-10-18, recoverable with `git log --follow`: AGENT_SYNC_PLAN
(superseded by the canonical lifecycle), UX_PLAN (both lanes landed), and
TRI_PLATFORM_PLAN, MARKETPLACE_PLAN and MARKETPLACE_NEXT (unfinished items now
live in `FORWARD_PLAN.md` sections 3 and 5).

Still to fold into `FORWARD_PLAN.md` when their items are sized: the
LLM-first App platform checklist, the sovereign machine mesh plan and the
consensus-gated concurrency hazards.

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

`.def` and `.txt` matter: `cognition/controllers/include/controllers/agent_impact_rules.def`
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

- **Current work:** the [Now list in `FORWARD_PLAN.md`](./FORWARD_PLAN.md#now) is the work order and
  [`FLEET_SCORECARD.md`](./FLEET_SCORECARD.md) owns current A+ completion bars.
  The rest of `FORWARD_PLAN.md` and other PLAN/LIVE records supply
  scoped context and procedures under that order.
- **Session entrypoint:** [`../../AGENTS.md`](../../AGENTS.md), then
  [`FORWARD_PLAN.md`](./FORWARD_PLAN.md).
- **Maintainer-host live state only:** [`../agent/HANDOFF.md`](../agent/HANDOFF.md); never
  use it to choose ordinary development work.
- **Architecture reference:** [`FRAMEWORK.md`](../commons/FRAMEWORK.md); its scoped
  debt inventory is not a priority queue.
- **Worker protocol:** [`agent-protocol.md`](../agent/agent-protocol.md).

## Worker protocol

Parallel-worker mechanics are adapted in
[`agent-protocol.md`](../agent/agent-protocol.md); project authority, integration, and
completion remain defined by `AGENTS.md` and `docs/dev/DEVELOPING.md`.

## Late-indexed records

| File | Authority | Purpose |
|---|---|---|
| [`ZC23_FAMILY_COMMONS.md`](./ZC23_FAMILY_COMMONS.md) | DESIGN | additive pre-genesis protocol foundation: family commons + evidence economics objects and commands |
| [`SHOP_COMMAND.md`](./SHOP_COMMAND.md) | DESIGN | owner-approved `app shop` one-command sovereign storefront specification; not an execution queue |
| [`ZC23_DISTRIBUTION_RULES.md`](./ZC23_DISTRIBUTION_RULES.md) | RETAINED | owner-decided phase-C2 policy record; simulation-only and not an execution queue |
| [`WIRE_COMPILE_CACHE.md`](./WIRE_COMPILE_CACHE.md) | DESIGN | Commons WIRE lane working note: transfer framing, POINTER/PROVIDER discovery records, and the cross-node compile cache; subordinate to `../spec/c23-package-format.md`, which wins on any disagreement |
| [`retrieval-gold-evidence/retrieval-gold-benchmark-b663f019ed20d6ece26aa94b5dfe92f41bd4c0be.jsonl`](./retrieval-gold-evidence/retrieval-gold-benchmark-b663f019ed20d6ece26aa94b5dfe92f41bd4c0be.jsonl) | EVIDENCE | frozen nine-record publishable retrieval receipt; exact evaluator-batch replay, six-task equal-weight macro denominator, 28 eligible relevance judgments, and explicit unavailable ceilings |
| [`retrieval-gold-evidence/retrieval-gold-benchmark-476e66661523.jsonl`](./retrieval-gold-evidence/retrieval-gold-benchmark-476e66661523.jsonl) | EVIDENCE | frozen 12-record publishable retrieval receipt for the distinct ten-task v2 cohort; exact evaluator-batch and per-task ranking-root replay, nine-task equal-weight macro denominator, 43 eligible relevance judgments, and explicit unavailable ceilings |
| [`retrieval-gold-evidence/retrieval-gold-benchmark-705d16ccab6b.jsonl`](./retrieval-gold-evidence/retrieval-gold-benchmark-705d16ccab6b.jsonl) | EVIDENCE | frozen 12-record publishable receipt for the same ten-task cohort with a current-driver directory-taxonomy scope proxy over exact-parent source: literal 7,209 bp and BM25 4,888 bp wrong-group selections at five; semantic scope, reuse success, and unique LOC avoided remain unobserved |
| [`retrieval-gold-evidence/retrieval-gold-benchmark-25fe3e353288.jsonl`](./retrieval-gold-evidence/retrieval-gold-benchmark-25fe3e353288.jsonl) | EVIDENCE | frozen 12-record publishable third-arm receipt with two sealed evaluator metric replays: the rare-identifier and observed-reverse-reference permutation records Recall@5 1,243 bp versus BM25 936 bp, equal Recall@20 at 3,502 bp, projected five-result context 733,211 versus 853,082 bytes, and directory-taxonomy proxy 4,666 versus 4,888 bp; vectors are not used, while scanner completeness, semantic scope, reuse success, and unique LOC avoided remain unobserved |

## Also in this directory

- [`AGENT_FLEET.md`](./AGENT_FLEET.md): Fleet operation and measured development
- [`BOOTSTRAP_PLAN.md`](./BOOTSTRAP_PLAN.md): Bootstrap plan — not yet a public install path
- [`C23_TASK_CATALOG.md`](./C23_TASK_CATALOG.md): C23 task type catalog
- [`RETRIEVAL_GOLD_CORPUS.jsonl`](./RETRIEVAL_GOLD_CORPUS.jsonl): historical agent tasks used as the retrieval gold corpus; benchmark runs are in [`retrieval-gold-evidence`](./retrieval-gold-evidence/)
- [`cards.jsonl`](./cards.jsonl): current seed work cards, one JSON card per line
