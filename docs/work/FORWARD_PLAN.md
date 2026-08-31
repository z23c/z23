<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

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

1. **Public-node correctness and remaining V1 acceptance.** Consensus, wallet
   custody, block processing, synchronization, peer health, and recovery have
   absolute resource and authority priority.
2. **C23 Commons Alpha complete user story.** An ordinary full node can
   publish, discover, fetch, verify, build, independently reproduce, and serve
   an exact C23 package without GitHub or a central registry.
3. **Core consolidation only when driven by that user story.** Reuse existing
   source, CAS, DHT, queue, lease, action, receipt, and policy authorities.
4. **Developer tooling is frozen except for correctness or product blockers.**
   The reflex reactor is factory equipment, not the product.
5. **Token economics and speculative expansion remain simulation-only.** They
   do not displace public-node or package-network acceptance.

The blockchain wins every resource and authority conflict. Package work must
remain bounded and asynchronous; it may not delay consensus, transaction relay,
sync, peer health, wallet custody, or deployment.

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

Metaverse, marketplace expansion, live-token design, speculative services, and
architecture-board cleanup are reference or simulation work until priorities 1
and 2 are green or an owner explicitly changes the product decision. They must
not change ZClassic consensus or imply live ZC23 economics.

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
