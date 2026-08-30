# Z23 current forward plan

This file is the current ordered development mission. Durable product direction
and agent authority live in [`../../AGENTS.md`](../../AGENTS.md); public-node
acceptance lives in [`../MVP.md`](../MVP.md); current state of the maintainer's
hosted node lives only in [`../HANDOFF.md`](../HANDOFF.md).

Do not copy live heights, process state, or dated benchmark anecdotes here.
Derive them from the named commands and evidence ledgers. Earlier detailed
plans and incident narratives remain available through Git history.

## Near-term proof

One person creates or improves a real C23 application from reusable parts,
sees the consequence, reproduces it elsewhere, accepts the exact version, and
uses it. Everything below is ordered to make that one journey work end to end:
`z23 zcode guide` -> `zcode work start` -> `zcode work run` -> `zcode work
show` -> `zcode create` -> `zcode package fetch` -> `zcode package source
reproduce` -> `zcode work accept` -> `zcode use`. A change that does not make
some step of that journey work, or make it smaller, faster, safer, or easier
to reproduce, is not the current mission.

## Product priority order

1. **P0 — public-node correctness and remaining V1 acceptance.** Consensus,
   wallet custody, block processing, synchronization, peer health, and recovery
   retain absolute resource and authority priority.
2. **Temporary P0.5 — Fearless Scale code, proof, and science fabric.** Build
   the bounded, content-addressed navigation and evidence rails needed to work
   safely across a federated billion-line C23 corpus. This program may consume
   only resources left after P0 work and grants no consensus, custody,
   deployment, publication-signing, or fetched-code execution authority.
3. **C23 Commons Alpha complete user story.** An ordinary full node can
   publish, discover, fetch, verify, build, independently reproduce, and serve
   an exact C23 package without GitHub or a central registry.
4. **Core consolidation only when driven by that user story.** Reuse existing
   source, CAS, DHT, queue, lease, action, receipt, and policy authorities.
5. **Developer tooling outside the P0.5 mission is frozen except for
   correctness or product blockers.** The reflex reactor is factory equipment,
   not the product.
6. **Token economics and speculative expansion remain simulation-only.** They
   do not displace public-node or package-network acceptance.

The blockchain wins every resource and authority conflict. Package work must
remain bounded and asynchronous; it may not delay consensus, transaction relay,
sync, peer health, wallet custody, or deployment.

## Temporary P0.5: Fearless Scale

The user outcome is one versioned native interface through which an agent can
orient, query, assemble bounded context, plan conservative proof, and verify
the exact evidence behind each answer across local and federated C23 source.
The same existing Commons authorities carry immutable index shards and
universal science statements. SQLite remains an optional rebuildable local
catalog; metaverse remains a derived collection and visualization view.

Work proceeds in this order:

1. Govern one source universe and close the current index correctness gaps.
2. Use native immutable receipt admission; push hooks never compile, lint,
   test, wait, fetch, or invoke Make or shell.
3. Ship local navigation v2 behind born-red fixtures and dual-run it against
   v1 wherever v1 claims completeness.
4. Federate immutable shards through the existing Commons CAS/DHT and prove
   bounded 1M, 10M, 100M, and 1B non-deduplicated-line fixtures.
5. Project existing science evidence into universal statement and realm-head
   envelopes with rights-aware inert fetch and local action acceptance.
6. Retire compatibility only after two green release cycles and demonstrated
   reconstruction from immutable shards.

Temporary P0.5 ends only when all of these exit gates are evidenced:

- census, Merkle, inventory, and index agree on one governed source universe;
- clean and incremental Linux/macOS builds produce identical manifest and
  shard roots, with missing dimensions reported as typed `INCOMPLETE`;
- warm exact, ranked, context, incremental-delta, and federated billion-line
  acceptance meet their declared latency, RSS, and storage budgets without
  silent truncation, false completeness, overflow, or root disagreement;
- receipt admission and status meet their bounded latency contracts, ordinary
  small changes reach verified green within the program budget, and cold
  audits show no unexplained selector miss, cache disagreement, accounting
  hole, duplicate action, or omitted mandatory P0/P1 gate;
- the frozen multi-agent task corpus records exact model, prompt, tool schema,
  source root, outcome, context cost, proof latency, and landed correctness;
- three isolated peers can publish, discover, fetch, rederive, review,
  replicate, conflict, supersede, and retract rights-compatible science
  statements and realm heads while poisoned or incomplete evidence fails
  closed; and
- maximum corpus, science-radar, and indexing load demonstrably preserves
  blockchain sync, peer health, wallet custody, and consensus priority.

After these gates pass, public-node and Commons feature ordering above resumes
without the temporary elevation; the proven fabric continues as ordinary
Commons infrastructure.

## 1. Public-node V1 acceptance

The aggregate contract is [`../MVP.md`](../MVP.md).

```bash
make mvp
make mvp-verify
```

`make mvp` is the honest criterion reporter: PASS is earned only by the full
declared observation; unavailable external prerequisites remain named BLOCKED,
not silently green. `make mvp-verify` runs the local aggregate.

The remaining work follows the first non-PASS criterion in that reporter, with
these invariants:

1. Diagnose and reproduce on isolated datadir copies; no live database surgery.
2. Cold-start acceptance observes a fresh node reach the captured peer tip
   within the declared budget. A boot or intermediate climb is not completion.
3. Recovery acceptance observes post-fault H* climb and persistence, not only
   process survival.
4. Consensus parity uses a fresh from-genesis replay and exact same-height
   state comparison with `zclassicd`.
5. The soak clock starts only on an exact candidate after its baseline restart
   and resets on binary, configuration, datadir, restart, parity, or evidence
   discontinuity.

Primary exact gates include:

```bash
make mvp-coldstart-to-tip-stopwatch
make replay-canary-genesis
make test-crash-bootstrap
make test-two-node-peer-tip
make soak-evidence-report
```

Some require operator fixtures, real peers, parameters, or sustained time.
Their named BLOCKED result is evidence of an unmet prerequisite, never
permission to weaken the assertion.

## 2. C23 Commons Alpha complete user story

The user outcome is one end-to-end path:

```text
author publishes exact source/package facts
    -> ordinary peers discover and fetch inert bytes
    -> local policy admits bounded build/test work
    -> interchangeable untrusted workers execute immutable actions
    -> signed receipts bind exact inputs and outputs
    -> another node independently reproduces the result
    -> each receiver verifies and accepts or refuses locally
```

Fetching never authorizes building; building never authorizes installing,
linking, executing outside the bounded worker, or deployment. Evidence proves
only its exact declared observation.

Run the existing aggregate surfaces rather than adding another package network:

```bash
make zcode-development-acceptance
make zcode-async-proof-acceptance
make sovereign-source-network-acceptance
make zcode-reproduction-acceptance
```

Acceptance requires:

- exact source, package, recipe, dependency, toolchain, action input, artifact,
  and receipt roots remain bound end to end;
- fetched package bytes remain inert until explicit local admission;
- work leases are atomic, recoverable, and stale results fail closed by name;
- exact duplicate actions deduplicate without conflating tasks or candidates;
- requester foreground work stays responsive while remote proof runs;
- no node, AI vendor, scheduler, signer, or host has a permanent special role;
- independent signers and independently reconstructed inputs agree on exact
  artifact bytes where the claim requires reproduction;
- no GitHub access or central package registry is required by the acceptance;
- package resource budgets preserve blockchain responsiveness;
- the original publisher can disappear: `make commons-multihost-acceptance`
  runs the same journey with node B and node C on separate physical hosts,
  then takes host A down and proves host C still discovers, fetches,
  reproduces and runs the exact accepted bytes from B.

When the aggregate fails, fix the first violated ownership or identity boundary
and add a permanent regression there. Do not add retries, sleeps, alternate
state machines, or a new cache authority to mask it.

## 3. Consolidation driven by acceptance

Consolidate only after an acceptance exposes duplicated work or authority.
Prefer deletion and reuse over a new abstraction. In particular:

- one content carrier and one content-addressed store;
- one canonical task/candidate/action/receipt fact chain;
- one durable work/lease authority with derived lifecycle projections;
- one local policy decision point per receiving node;
- immutable IDs across transport, reconstruction, execution, and receipt
  verification.

Distributed workers share immutable CAS objects where practical and minimize
shared mutable SQLite state. A subsystem may not close, replace, rename,
checkpoint, or remove database files it does not own or explicitly lease.

## 4. Developer tooling freeze

Do not expand HOT_FORK, hot-swap, reflex, agent fleet, or benchmark machinery
for its own coverage. A tooling change enters the queue only when a current
public-node or C23 Commons acceptance is blocked by a demonstrated tooling
correctness defect or missing product capability.

The local feedback path must remain independent of peer networking:

```text
immutable candidate/action becomes available
    -> asynchronous peer proof consumes it
    -> signed events and receipts appear later
```

There is no direct agent-to-agent coordination and no dependency from local
editing back into remote proof.

## 5. Simulation and reference work

Metaverse, marketplace expansion, live-token design, speculative services, and
architecture-board cleanup are reference or simulation work until priorities 1
and 2 are green or an owner explicitly changes the product decision. They must
not change ZClassic consensus or imply live ZC23 economics.

## Integration cadence

For each coherent slice:

1. Run its focused acceptance.
2. Fetch current `origin/main` and integrate safely.
3. Rerun affected gates, then `make lint` and the required uncached suite.
4. Commit only owned files, push normally, and verify the remote SHA.
5. Continue to the next unfinished item.

A push is a checkpoint, not completion. A status report does not suspend work.
Escalate only under the conditions in [`../../AGENTS.md`](../../AGENTS.md).
