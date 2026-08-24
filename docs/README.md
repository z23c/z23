<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Z23 documentation map

Copyright 2026 Rhett Creighton. Licensed under the Apache License, Version 2.0.

This is a curated map, not an inventory. The documentation hierarchy is:

1. [`../README.md`](../README.md) — public product explanation.
2. [`../AGENTS.md`](../AGENTS.md) — model-neutral coding-agent entry point.
3. [`DEVELOPING.md`](DEVELOPING.md) — detailed developer procedure.
4. [`work/FORWARD_PLAN.md`](work/FORWARD_PLAN.md) — current ordered work.
5. [`HANDOFF.md`](HANDOFF.md) — current state of the maintainer's hosted node
   only.
6. This page — map to specialist documentation.
7. [`../CLAUDE.md`](../CLAUDE.md) and vendor-specific skills — thin
   compatibility adapters, not independent project doctrine.

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
[`../AGENTS.md`](../AGENTS.md#north-star).

## Public product

Z23 is first a public ZClassic blockchain full node. It also offers an
optional decentralized C23 software commons where ordinary full nodes can
publish, discover, fetch, verify, build, independently reproduce, and serve
exact packages without a central registry.

- [`../README.md`](../README.md) — what the product is and what users can do.
- [`GETTING_STARTED.md`](GETTING_STARTED.md) — build and run it on a fresh
  machine.
- [`C23_COMMONS_QUICKSTART.md`](C23_COMMONS_QUICKSTART.md) — installed-node
  author, consumer, and reproducer journey for exact third-party C23 packages.
- [`MVP.md`](MVP.md) — public-node V1 acceptance contract; `make mvp` reports
  the live criterion state and `make mvp-verify` runs the local aggregate.
- [`SELL.md`](SELL.md) — pay ZCL and sell a 1/1 collectible: yardsale,
  package-swarm, and onion shop; start with `z23 yardsale guide`.
- [`NATIVE_COMMAND_INTERFACE.md`](NATIVE_COMMAND_INTERFACE.md) — discoverable,
  typed operator interface.
- [`BOOTSTRAPPING.md`](BOOTSTRAPPING.md) and [`SYNC.md`](SYNC.md) — how a node
  reaches the chain.
- [`OVERLAY.md`](OVERLAY.md) — FlyClient, SHA3 swarm, file-service overlay,
  and onion marketplace; consensus hashes stay SHA-256d.
- [`CUSTODY_MODEL.md`](CUSTODY_MODEL.md) — wallet ownership and spend
  authority.

## C23 Commons acceptance

The Commons uses content-addressed source, bounded build/test execution,
signed evidence, independent reproduction, and local policy. Fetching source
does not authorize execution or deployment.

- [`work/ZCODE_PLAN.md`](work/ZCODE_PLAN.md) — package and source protocol
  design.
- [`C23_COMMONS_QUICKSTART.md`](C23_COMMONS_QUICKSTART.md) — concise public
  workflow and its current portability/reproduction limits.
- [`ZVCS.md`](ZVCS.md) — in-binary source identity and versioning.
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

- [`../AGENTS.md`](../AGENTS.md) — durable priorities, authority boundaries,
  initial commands, and continuation behavior.
- [`DEVELOPING.md`](DEVELOPING.md) — navigation, reflex feedback, focused tests,
  integration, push, and asynchronous deep proof.
- [`CODEBASE_MAP.md`](CODEBASE_MAP.md) — source ownership and extension recipes.
- [`AGENT_TRAPS.md`](AGENT_TRAPS.md) — intentional behavior and already-solved
  problems to check before editing.
- [`DEFENSIVE_CODING.md`](DEFENSIVE_CODING.md) — lint-enforced C and
  architecture rules.
- [`API_REFERENCE.md`](API_REFERENCE.md) — generated command catalog; edit its
  source definitions, not the generated file.
- [`BUILD.md`](BUILD.md) — vendored dependencies, profiles, and reproducibility.
- [`AI_SAFETY_GATES.md`](AI_SAFETY_GATES.md) — claim and evidence discipline.
- [`SECURITY_AND_INTEGRITY.md`](SECURITY_AND_INTEGRITY.md) — project security
  boundary and review checklist.
- [`CONSENSUS_PARITY_DOCTRINE.md`](CONSENSUS_PARITY_DOCTRINE.md) — inviolable
  compatibility boundary.

## Understand the system

- [`HOW_THE_NODE_WORKS.md`](HOW_THE_NODE_WORKS.md) — append-only fact log,
  reducers, projections, and health.
- [`ARCHITECTURE_DIAGRAMS.md`](ARCHITECTURE_DIAGRAMS.md) — current subsystem
  and boot topology.
- [`ROM.md`](ROM.md) — compiled checkpoint and verification layers.
- [`BOOT_INVARIANTS.md`](BOOT_INVARIANTS.md) — boot-stage guarantees.
- [`EXTENSION_POINTS.md`](EXTENSION_POINTS.md) — actively changing extension
  surfaces with claim-bound facts.
- [`LEGACY_LIFECYCLE.md`](LEGACY_LIFECYCLE.md) — active versus retired legacy
  paths.

## Operate and recover a node

- [`RUNBOOK.md`](RUNBOOK.md) — symptom-driven diagnostics and operations.
- [`TENACITY.md`](TENACITY.md) — copy-first recovery invariants.
- [`work/fast-path.md`](work/fast-path.md) — diagnose and reproduce on a datadir
  copy.
- [`BLOCK_EXPLORER_HOSTING.md`](BLOCK_EXPLORER_HOSTING.md) — public explorer
  operation.
- [`PROMOTION_RECEIPTS.md`](PROMOTION_RECEIPTS.md) — promotion evidence ledger
  and owner setup.
- [`RELEASE_CANDIDATE_PIN.md`](RELEASE_CANDIDATE_PIN.md) — exact candidate
  identity.

## Current maintainer state

[`HANDOFF.md`](HANDOFF.md) is the only document allowed to describe the current
hosted node. It is relevant only on the maintainer host and must be checked
against typed node status. [`work/FORWARD_PLAN.md`](work/FORWARD_PLAN.md) is the
current development mission; neither file redefines the durable product.

## Measurement

- [`BENCHMARKS_LOG.md`](BENCHMARKS_LOG.md) — append-only measured benchmark
  ledger.
- [`USER_BENCHMARKS.md`](USER_BENCHMARKS.md) — user-facing measurement
  questions.
- [`SIMNET_PERF.md`](SIMNET_PERF.md) — deterministic simulation performance
  gate.
- [`TELEMETRY_CONTRACT.md`](TELEMETRY_CONTRACT.md) — stable telemetry shape and
  unknown-value rules.

Keep remembered performance numbers out of onboarding prose; cite or rerun the
appropriate ledgered benchmark.

## Application and reference layers

These are useful but do not define the primary product or current critical
path:

- [`METAVERSE.md`](METAVERSE.md) and [`METAVERSE_MVP.md`](METAVERSE_MVP.md) —
  application/creation layer; token economics remain simulation-only.
- [`FILE_MARKET_PROTOCOL.md`](FILE_MARKET_PROTOCOL.md) — marketplace protocol;
  the operator acceptance journey it once planned now lives as
  `make commons-multihost-acceptance` (see the top-level README).
- [`FRAMEWORK.md`](FRAMEWORK.md) and [`AGENT_ARCHITECTURE.md`](AGENT_ARCHITECTURE.md)
  — architectural reference, off the public-node critical path unless the
  current plan explicitly pulls in a bounded item.
- [`adr/`](adr/) — historical design decisions; useful context, not live state.
- [`work/README.md`](work/README.md), [`work/agent-protocol.md`](work/agent-protocol.md),
  and [`agent/`](agent/) — one maintainer's optional orchestration references,
  not the universal contributor workflow.

## Contributing and attribution

- [`../.github/CONTRIBUTING.md`](../.github/CONTRIBUTING.md) — contribution
  contract.
- [`ATTRIBUTIONS.md`](ATTRIBUTIONS.md) — concept and code attribution.
- [`../NOTICE`](../NOTICE) — upstream notices.

Historical plans and deleted reports remain available through Git history. Do
not promote a historical design or dated observation back into onboarding
without current acceptance evidence.
