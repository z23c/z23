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
