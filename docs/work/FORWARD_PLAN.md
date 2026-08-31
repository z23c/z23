<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Z23 current forward plan

This file is the current ordered development mission. Durable product direction
and agent authority live in [`../../AGENTS.md`](../../AGENTS.md); public-node
acceptance lives in [`../MVP.md`](../MVP.md); current state of the maintainer's
hosted node lives only in [`../HANDOFF.md`](../HANDOFF.md).

Do not copy live heights, process state, or dated benchmark anecdotes here.
Derive them from the named commands and evidence ledgers. Earlier detailed
plans and incident narratives remain available through Git history.

## 0. Current mission: one clear agent route

Before selecting another product or operations project, remove inherited
context that sends fresh agents toward completed work. Work in this order:

1. [x] Delete the completed architecture quest board that still presented
   itself as the whole current queue. Its history remains in Git.
2. [x] Make vendor-specific agent files thin adapters to `AGENTS.md`, this
   plan, and `docs/DEVELOPING.md`; they carry no independent workflow doctrine.
3. [x] Keep live-node, uptime, soak, server-lane, and deployment state in
   `docs/HANDOFF.md` or an explicitly operator-only runbook. Ordinary
   development entry documents link there only conditionally.
4. [x] Rename or label retained plans as scoped design records, references, or
   historical rationale. They do not choose the next task.
5. [x] Run the documentation and lint gates, then ask whether a fresh agent can
   choose the first open mission item without reading an old session history.
   Repeat until the answer is yes.

Fresh-agent check: **yes**. `AGENTS.md` routes directly here, this is the only
indexed `PLAN`, retained documents label their narrower scope, and live-node
procedures require an explicit maintainer-host assignment. With this cleanup
checkpoint closed, continue at the first unmet item in the ordered product
program below; do not revive a deleted scorecard or historical queue.

Do not start a time-running soak, uptime watch, server-lane operation, or live
node intervention during this mission unless the owner explicitly requests
that operation or a P0 incident requires it. Do not rewrite working
architecture merely to simplify its documentation.

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

### Token-efficient peer work inside the same journey

Agents do not need a chat network or a second coordinator. They need the
existing task, source, context, action, candidate, and receipt roots to be
reusable across nodes without retransmitting repository copies or accumulated
prose. Keep this asynchronous and content-addressed:

```text
exact task/source generation
    -> bounded local context or navigator-fact root
    -> peer asks for roots first and fetches only missing CAS chunks
    -> receiver re-roots bytes and verifies task/source/generation bindings
    -> exact active action attaches; exact completed work is revalidated
    -> model sees only selected bytes and explicit completeness gaps
```

The ordered checkpoints are:

1. Measure model-context bytes, approximate tokenizer counts, whole-file reads,
   unchanged-source reads, corpus walks, CAS hits/misses, peer bytes, and
   duplicate actions on the representative task corpus. Do not claim a token
   win from transport bytes alone.
2. Reuse the existing `agent_context.v1` wire by root. Transport it only as an
   ordinary inert `content.v2` carrier through the existing package swarm.
   Require the receiver to re-root it and check its expected task, source, goal,
   and completeness before use. The fixed task carrier and task authority do
   not change merely to make context convenient.
3. Make navigator facts generation/configuration/query-bound, canonical, and
   cursor-safe. A remote fact is a cacheable byte proposal; exact edit, impact,
   or proof selection still requires local verification. Missing call/include/
   build/policy dimensions widen proofs or refuse by name.
4. Rendezvous before spending model tokens: resolve already accepted work for
   the exact task, attach to an identical active action, or revalidate an exact
   completed action and its locally held outputs. A stranger's receipt remains
   `UNVERIFIED` until local policy and reproduction say otherwise.
5. Only after those read-only savings are measured, add candidate-free remote
   `DIAGNOSE`, then scoped `PROPOSE`, then independent `REVIEW` through the
   existing ZCode work swarm. A missing qualified out-of-process isolation
   backend, including on macOS, is a named refusal; fetched source never enters
   the node process.

Acceptance for the first checkpoint is two independent peers deriving the same
context root for the same exact generation, a warm handoff transferring no
excerpt chunks, no warm corpus-wide walk or unchanged-source read, explicit
truncation and stale-generation refusals, and unchanged proof selection. The
blockchain-priority assertion in the async-proof scaling gate remains
mandatory.

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

The current development reactor has two transitional orchestration paths: the
per-checkout native proof queue and the separate `tools/land` batching
chainlog. Both are duplicate transitional lifecycle models and neither is
product authority. Consolidation is complete only when a
signed Git intent freezes into the existing source/task/candidate/action/work
context, the build fabric owns its request and lease, canonical work receipts
materialize one proof-set root, a PROVEN lane yields one accepted-work root,
and a versioned Git publication job records immutable progress and outcome. The
existing package-publication job does not yet provide those Git phases.
Git identities remain provenance; no landing verdict may replace a source,
action, proof-set, or accepted-work root.

The action-fabric local Git adapter, shared resident coordinator, Git-target
publication phases, and native epoch-batch executor remain unfinished. Native
`zcc --epoch-object` currently covers the build-only and fast-test object
paths; a batch manifest codec is not a worker pool or object-set publisher.
Keep those distinctions explicit in code, commands, and documentation.

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

Today an integrator still fetches, merges normally, waits for the exact local
receipt, pushes, and verifies the remote SHA. The target workflow replaces that
waiting with a durable signed-commit handoff to one resident coordinator. That
coordinator alone reconciles current `origin/main`, reuses canonical child
proofs, admits the exact aggregate, performs a normal main-only publication,
and records the remotely observed outcome. Until that path exists and is
qualified, documentation must not describe enqueue as publish.

## 5. Simulation and reference work

Metaverse, marketplace expansion, live-token design, and speculative services
are reference or simulation work until priorities 1 and 2 are green or an
owner explicitly changes the product decision. They must not change ZClassic
consensus or imply live ZC23 economics.

## Integration cadence

For each coherent slice:

1. Run its focused acceptance.
2. Fetch current `origin/main` and integrate safely.
3. Rerun the exact affected gates. Run full lint or an uncached broad suite
   only when the changed closure or acceptance policy requires it.
4. Commit only owned files, push normally, and verify the remote SHA.
5. Continue to the next unfinished item.

A push is a checkpoint, not completion. A status report does not suspend work.
Escalate only under the conditions in [`../../AGENTS.md`](../../AGENTS.md).
