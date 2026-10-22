<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Z23 documentation map

Copyright 2026 Rhett Creighton. Licensed under the Apache License, Version 2.0.

This is a curated map, not an inventory. The documentation hierarchy is:

1. [`../README.md`](../README.md) — public product explanation.
2. [`../AGENTS.md`](../AGENTS.md) — model-neutral entry point for maintainers and fleet agents. Public volunteers start at [`../.github/CONTRIBUTING.md`](../.github/CONTRIBUTING.md).
3. [`work/FORWARD_PLAN.md`](work/FORWARD_PLAN.md) — current ordered work.
3a. [`THE_Z23_WAY.md`](THE_Z23_WAY.md) — the one standard loop for Claude, Codex and humans: lane, brief, verify, review, land.
4. [`DEVELOPING.md`](dev/DEVELOPING.md) — detailed developer procedure.
5. [`HANDOFF.md`](agent/HANDOFF.md) — current state of the maintainer's hosted node
   only.
6. This page — map to specialist documentation.
7. [`../CLAUDE.md`](../CLAUDE.md) and vendor-specific skills — thin
   compatibility adapters, not independent project doctrine.

Commands: `discover.help`, `discover.search`, `discover.wiki`, `discover.read`

## North Star

Z23 exists to make useful software abundant without taking control away from
the user. **Software made for you, not imposed on you.** The whole product is
one journey — describe desired behavior, reuse existing C23 first, create only
the missing code, build fast, show the real consequence, reproduce it on
another node, accept the exact version, use it in a real application. Ask the
node for that journey with `z23 zcode guide`; every step returns the next
safe command. Checkout edits start with `z23 code guide`.

AI workers are replaceable. Z23 is the durable layer: exact source identity,
reusable packages, dependency graphs, bounded builds, independent
reproduction, local policy, distribution, release history, and preservation.
Documentation here should keep complexity hidden but inspectable, and give the
reader one obvious next action. The durable statement of this is
[`../AGENTS.md`](../AGENTS.md#north-star). How Z23 itself is developed toward
it, by people and agents, is [`agent/VISION.md`](agent/VISION.md).

### The shape of it

Z23 is one program you build from source that verifies everything it runs:
the money, the software, the peers and the agents. A hash names bytes, a
signature names a key, a receipt binds an observation, and acceptance is
always a decision made on your own machine. Each fact has one writer; every
other copy is a view of it.

The parts nest, each smaller and more sealed than the one around it:

| Layer | What it gives you |
|---|---|
| Core | ZClassic consensus, custody and network: money you verify yourself. Sealed, flat or shrinking. |
| Commons | Software named by its exact source, rebuilt and reproduced on another node, accepted by version, usable after its publisher is gone. |
| Runtime | Software that runs confined: one-file C23 programs and plugins, authority passed as descriptors, and, as a target, a FreeBSD-derived guest as the same fallback everywhere. |
| Mesh | Your machines and your peers: peer to peer, onion routing, pinned keys, no fee, no signup, no central server. |
| Agents | Replaceable workers outside the authority boundary. They propose; Z23 verifies; you accept. |

Z23 is developed with Z23. A card, a one-file lab run against its cases, a
receipt, an independent review, a landing, a release and a deployment are the
commons pipeline applied to Z23's own source. A step that needs a private
script or a manual action is a gap in the product, and closing it is product
work.

Less is more. The target is one program, one service per host, one ledger
per fact, one command registry for the command line and MCP, one tree of
documents. New
capability arrives as small, deletable plugins while the core stays small;
removing code while every test still passes is progress.

## Public product

Z23 is first a public ZClassic blockchain full node. It also offers an
optional decentralized C23 software commons where ordinary full nodes can
publish, discover, fetch, verify, build, independently reproduce, and serve
exact packages without a central registry.

- [`../README.md`](../README.md) — what the product is and what users can do.
- [`GETTING_STARTED.md`](node/GETTING_STARTED.md) — build and run it on a fresh
  machine, and what peer discovery does with no flags.
- [`MACOS_GUI_QUICKSTART.md`](node/MACOS_GUI_QUICKSTART.md) — a fresh Mac with only
  Apple's command-line tools to a native GUI application: scaffold it from
  `contexts/commons/packages/zhello`, see your change on screen, ship a reproducible `.app`.
- [`WINDOWS.md`](node/WINDOWS.md) — MSYS2 UCRT64 native C23 development, the
  remaining Win32 port boundary, and the current WSL2 full-node/service lane.
- [`PARAMS.md`](PARAMS.md) — why a node validates shielded proofs out of the
  box but cannot create a shielded payment until you supply the proving
  parameters yourself, and how to check the bytes you were given.
- [`JOIN.md`](node/JOIN.md) — the two independent senses of "joining": the
  blockchain P2P network (automatic, no command, no DNS seeder) and the C23
  software commons (`z23 join`, the swarm and DHT tiers, reading the verdict).
- [`C23_COMMONS_QUICKSTART.md`](commons/C23_COMMONS_QUICKSTART.md) — installed-node
  author, consumer, and reproducer journey for exact third-party C23 packages.
- [`MVP.md`](quality/MVP.md) — public-node V1 acceptance contract; `make mvp` reports
  the live criterion state and `make mvp-verify` runs the local aggregate.
- [`SELL.md`](node/SELL.md) — pay ZCL and sell a 1/1 collectible: yardsale,
  package-swarm, and onion shop; start with `z23 yardsale guide`.
- [`NATIVE_COMMAND_INTERFACE.md`](dev/NATIVE_COMMAND_INTERFACE.md) — discoverable,
  typed operator interface.
- [`BOOTSTRAPPING.md`](node/BOOTSTRAPPING.md) and [`SYNC.md`](node/SYNC.md) — how a node
  reaches the chain.
- [`OVERLAY.md`](node/OVERLAY.md) — FlyClient, SHA3 swarm, file-service overlay,
  and onion marketplace; consensus hashes stay SHA-256d.
- [`CUSTODY_MODEL.md`](node/CUSTODY_MODEL.md) — wallet ownership and spend
  authority.

## C23 Commons acceptance

The Commons uses content-addressed source, bounded build/test execution,
signed evidence, independent reproduction, and local policy. Fetching source
does not authorize execution or deployment.

- [`work/ZCODE_PLAN.md`](work/ZCODE_PLAN.md) — package and source protocol
  design.
- [`spec/c23-package-format.md`](spec/c23-package-format.md) — normative
  package format: root-only identity, versions as DAG edges, package anatomy
  discipline, and proven (not hoped) build determinism.
- [`C23_COMMONS_QUICKSTART.md`](commons/C23_COMMONS_QUICKSTART.md) — concise public
  workflow and its current portability/reproduction limits.
- [`ZVCS.md`](commons/ZVCS.md) — in-binary source identity and versioning.
- [`PLUGIN_APPS.md`](commons/PLUGIN_APPS.md) — plan for turning every z23 app and feature into a plugin.
- `make zcode-development-acceptance` — package developer lifecycle.
- `make zcode-async-proof-acceptance` — interchangeable full-node async work,
  lease recovery, stale-result refusal, and exact-action reuse.
- `make sovereign-source-network-acceptance` — real-process publication,
  discovery, no-Git reconstruction, and independent reproduction.
- `make zcode-reproduction-acceptance` — local reproduction-policy regression
  aggregate; its output states the limits of same-host signer simulation.

The active ordered combination of these targets is in
[`work/FORWARD_PLAN.md`](work/FORWARD_PLAN.md). Do not infer general code safety
from a hash, signature, test, or reproduction receipt.

## Change the code

- [`archive/README.md`](archive/README.md) — historical proposals and retired mechanisms; not current procedure.
- [`agent/README.md`](agent/README.md) — agent and fleet documents: lanes,
  fleet guide, board, ledger, triggers, wiki, work cards, safety gates.
- [`dev/README.md`](dev/README.md) — developer references: build and test
  loop, hot-swap, lab, plugins, services, flags, host maintenance.
- [`node/README.md`](node/README.md) — node references: boot, sync, custody, recovery, security.
- [`commons/README.md`](commons/README.md) — commons, metaverse, ZCODE, framework and architecture references.
- [`quality/README.md`](quality/README.md) — simulators, chaos, benchmarks, acceptance gates and transaction labs.
- [`work/AGENT_FLEET.md`](work/AGENT_FLEET.md) — consolidated fleet operating
  contract: storage admission, task ownership, native and guest execution,
  transport choices, timestamped JSON observations, and measured agent cost.
  It distinguishes available interfaces from unqualified integration.
- [`../AGENTS.md`](../AGENTS.md) — durable priorities, authority boundaries,
  initial commands, and continuation behavior.
- [`DEVELOPING.md`](dev/DEVELOPING.md) — navigation, reflex feedback, focused tests,
  integration, push, and asynchronous deep proof.
- [`CODEBASE_MAP.md`](dev/CODEBASE_MAP.md) — source ownership and extension recipes.
- [`DATA_INDEX.md`](dev/DATA_INDEX.md) — local data-source ingest/search (`z23-dev dev
  index`): the board, experiment ledger, landing outcomes, and logs, into
  one sqlite+FTS5 file.
- [`AGENT_TRAPS.md`](agent/AGENT_TRAPS.md) — intentional behavior and already-solved
  problems to check before editing.
- [`MIND.md`](dev/MIND.md) — the per-node resident that owns rebuilding this box's
  code index, what it holds, and why a stale answer is refused rather than
  rebuilt inside a query.
- [`WIKI.md`](agent/WIKI.md) — the fleet wiki: `z23 fleet wiki find <q>`, entry schema,
  search behavior, agent-harness access and how to write a good page.
- [`WORK_CARDS.md`](agent/WORK_CARDS.md) — owner-signed public work cards on the
  board: the card format, how state derives from claims and results, and
  `z23 work list` / `z23 work show`.
- [`LAB.md`](dev/LAB.md) — the one-file lab: `z23 lab run`, `lab test` and
  `lab show` compile one C23 file, run it confined and return a
  content-addressed JSON receipt; limits, confinement, cache and measured
  latency.
- [`DEFENSIVE_CODING.md`](DEFENSIVE_CODING.md) — lint-enforced C and
  architecture rules.
- [`CHAOS_HARNESS.md`](quality/CHAOS_HARNESS.md) — the two chaos/kill harnesses (the
  deterministic sim engine and the full-binary SIGKILL recovery test), and
  where in-process dev-proof worker-death acceptance lives.
- [`API_REFERENCE.md`](API_REFERENCE.md) — generated command catalog; edit its
  source definitions, not the generated file.
- [`CAPABILITY_INVENTORY.jsonl`](CAPABILITY_INVENTORY.jsonl) — generated
  public-header capability map: exposed symbols, verified direct-use counts,
  registered-test reachability, ranked duplicate candidates, and untested
  declared invariants. Scanner ambiguities are named `UNPROVEN` records rather
  than silently assigned. Regenerate it with `make docs-capability-inventory`;
  never hand-edit it.
- [`BUILD.md`](dev/BUILD.md) — vendored dependencies, profiles, and reproducibility.
- [`AI_SAFETY_GATES.md`](agent/AI_SAFETY_GATES.md) — claim and evidence discipline.
- [`SECURITY_AND_INTEGRITY.md`](node/SECURITY_AND_INTEGRITY.md) — project security
  boundary and review checklist.
- [`CONSENSUS_PARITY_DOCTRINE.md`](CONSENSUS_PARITY_DOCTRINE.md) — inviolable
  compatibility boundary.

## Understand the system

- [`HOW_THE_NODE_WORKS.md`](node/HOW_THE_NODE_WORKS.md) — reducer kernel, stages,
  projections, and health.
- [`CHAIN_AUTHORITY.md`](node/CHAIN_AUTHORITY.md) — current chain-mutation paths,
  proof limits, and the target typed ownership boundary.
- [`ARCHITECTURE_DIAGRAMS.md`](commons/ARCHITECTURE_DIAGRAMS.md) — current subsystem
  and boot topology.
- [`WHOLE_PICTURE.md`](commons/WHOLE_PICTURE.md) — one picture of the node, the commons,
  the emulated machine and the tunnels, each part labelled on main, candidate,
  experiment or target.
- [`ROM.md`](node/ROM.md) — compiled checkpoint and verification layers.
- [`RISCV_MACHINE.md`](commons/RISCV_MACHINE.md) — the built-in RISC-V machine and
  how to boot a kernel in it.
- [`BOOT_INVARIANTS.md`](BOOT_INVARIANTS.md) — boot-stage guarantees.
- [`EXTENSION_POINTS.md`](commons/EXTENSION_POINTS.md) — actively changing extension
  surfaces with claim-bound facts.
- [`LEGACY_LIFECYCLE.md`](node/LEGACY_LIFECYCLE.md) — active versus retired legacy
  paths.

## Operate and recover a node

- [`RUNBOOK.md`](RUNBOOK.md) — symptom-driven diagnostics and operations.
- [`FLEET.md`](agent/FLEET.md) — fleet operator guide: machines, joining, tunnel,
  shells, vitals, board, wiki, agents, roles and troubleshooting.
- [`fleet-dev/README.md`](fleet-dev/README.md) — maintainer setup for the
  opt-in `z23-fleet` plugin, `z23-fx` and the daily loop.
- [`FLEET_TRIGGERS.md`](agent/FLEET_TRIGGERS.md) — the closed registry of
  reactions to local events (`z23-dev fleet triggers`).
- [`TENACITY.md`](TENACITY.md) — copy-first recovery invariants.
- [`dev/fast-path.md`](dev/fast-path.md) — diagnose and reproduce on a datadir
  copy.
- [`BLOCK_EXPLORER_HOSTING.md`](BLOCK_EXPLORER_HOSTING.md) — public explorer
  operation.
- [`PROMOTION_RECEIPTS.md`](dev/PROMOTION_RECEIPTS.md) — promotion evidence ledger
  and owner setup.
- [`RELEASE_CANDIDATE_PIN.md`](node/RELEASE_CANDIDATE_PIN.md) — exact candidate
  identity.

## Current maintainer state

[`HANDOFF.md`](agent/HANDOFF.md) is the only document allowed to describe the current
hosted node. It is relevant only on the maintainer host and must be checked
against typed node status. [`work/FORWARD_PLAN.md`](work/FORWARD_PLAN.md) is the
current development mission; neither file redefines the durable product.

## Measurement

- [`BENCHMARKS_LOG.md`](quality/BENCHMARKS_LOG.md) — append-only measured benchmark
  ledger.
- [`BUILD_BENCH.md`](dev/BUILD_BENCH.md) — `make build-bench` scenario harness;
  how build-speed claims get a measured artifact.
- [`USER_BENCHMARKS.md`](quality/USER_BENCHMARKS.md) — user-facing measurement
  questions.
- [`SIMNET_PERF.md`](quality/SIMNET_PERF.md) — deterministic simulation performance
  gate.
- [`TELEMETRY_CONTRACT.md`](node/TELEMETRY_CONTRACT.md) — stable telemetry shape and
  unknown-value rules.

Keep remembered performance numbers out of onboarding prose; cite or rerun the
appropriate ledgered benchmark.

## Application and reference layers

These are useful but do not define the primary product or current critical
path:

- [`GAME.md`](commons/GAME.md) — Sky Combat (`apps/skycombat`), the split-screen flight
  game that ships from this repo behind the opt-in `make game`; not the node,
  and not on any node critical path.
- [`METAVERSE.md`](commons/METAVERSE.md) and [`METAVERSE_MVP.md`](commons/METAVERSE_MVP.md) —
  engine/application/creation layer; token economics remain simulation-only.
- [`FILE_MARKET_PROTOCOL.md`](node/FILE_MARKET_PROTOCOL.md) — marketplace protocol;
  the operator acceptance journey it once planned now lives as
  `make commons-multihost-acceptance` (see the top-level README).
- [`FRAMEWORK.md`](commons/FRAMEWORK.md) and [`AGENT_ARCHITECTURE.md`](agent/AGENT_ARCHITECTURE.md)
  — architectural reference, off the public-node critical path unless the
  current plan explicitly pulls in a bounded item.
- [`adr/`](adr/) — historical design decisions; useful context, not live state.
- [`zrc/`](zrc/) — the ZRC (Z23 Request for Comments) process for proposing a
  new subsystem or standing rule before it is built; see `zrc/README.md`.
- [`work/README.md`](work/README.md), [`agent/agent-protocol.md`](agent/agent-protocol.md),
  and [`agent/`](agent/) — one maintainer's optional orchestration references,
  not the universal contributor workflow.

## Contributing and attribution

- [`../.github/CONTRIBUTING.md`](../.github/CONTRIBUTING.md) — the public volunteer front door: build, work cards, submission and credit.
- [`ATTRIBUTIONS.md`](ATTRIBUTIONS.md) — concept and code attribution.
- [`../NOTICE`](../NOTICE) — upstream notices.

Historical plans and deleted reports remain available through Git history. Do
not promote a historical design or dated observation back into onboarding
without current acceptance evidence.
