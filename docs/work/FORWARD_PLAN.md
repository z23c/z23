<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Z23 current forward plan

This is the current ordered development mission. Durable product direction and
agent authority live in [`../../AGENTS.md`](../../AGENTS.md); public-node
acceptance lives in [`../MVP.md`](../MVP.md). Maintainer-host live state belongs
only in [`../HANDOFF.md`](../HANDOFF.md), consulted for an explicit host
assignment. Do not copy live heights, process state, or benchmark anecdotes here.

This file owns the active scope and the ordered queue. Passing all of MVP.md's
C1–C8 is necessary for platform v1 but not sufficient: platform v1 is the
release demonstration under *Acceptance and performance* below, together with
the existing acceptance targets. Open (◐) MVP criteria are P1 work under
`AGENTS.md`. When an authorized loop for one of them is ready, it outranks the
P3 development machinery in this queue. Each ◐ cell names its own remaining
condition or owner decision; recheck it against its ledger before starting.

## Current mission: fast C23 development with fleet Insight + Control

Make Z23 the durable P2P platform through which interchangeable agents
understand real problems, reuse C23, produce verified improvements, operate
permitted systems, and measure the consequences:

> Observe → understand → propose → build → independently reproduce → publish
> → operate → measure.

Deliver native APIs and CLI first on Linux and arm64 macOS; a browser console
follows. Aggregate fleet membership has no fixed ceiling, while every node's
connections, work, storage and responses remain bounded. Native documents and
signed task objects are the first live business sources. Transcripts, Slack,
email, tickets, CRM, analytics and feedback receive bounded import support;
direct connectors subsequently reuse the same adapter contract.

Canonical lifecycle convergence is the first milestone. The continuation queue
below replaces the earlier blanket fleet freeze and temporary P0.5 queue.
Existing design records supply scoped implementation detail; they do not reorder
this mission. Requirements below are acceptance targets, not claims of completed
implementation or measured performance.

## Invariants and authority

P0 consensus, wallet custody and public-node correctness retain absolute
priority; the durable P1–P4 ordering in `AGENTS.md` still applies. Insight,
Control and development machinery advance public-node reliability and C23
Commons acceptance. Telemetry, indexing, builds, transfers and application
operations may not delay chain advancement, synchronization or peer health.
Consensus predicates and byte-sealed core remain unchanged without the explicit
owner ritual. Custody and canonical node deployment retain separate authority.

Use existing signed objects, CAS, task, candidate, action, lease, receipt and
receiver-policy authorities. Databases and views are rebuildable projections.
Imported text and downloaded C remain inert; storing never authorizes building,
execution, installation or deployment. No central scheduler, mandatory SaaS
account, model vendor or permanent privileged worker becomes a dependency.
Token economics and speculative marketplace expansion remain simulation-only.

Autonomous live mutations require fresh, scoped receiver authority. A partition
allows observation and preparation but blocks new live mutations when freshness
cannot be established. Scope includes machines, services, capacity, cost and
permitted stages; privileged supervision installation needs its own grant.
This mission authorizes implementation and isolated qualification, not an
ungranted production operation or signing on another operator's behalf.

## Owned public surfaces

Extend existing command families and authorities. New names in this table are
target interfaces; discover implemented schemas from the built binary.

| Surface | Result |
|---|---|
| `code.*`, `zcode.work.*`, `dev.*` | Bounded context, reusable C23, distributed proposals and proofs, canonical publication |
| `fleet.machines`, new `fleet.query`, `fleet.watch` | Paginated membership, private observations, subscriptions and freshness |
| `ops.telemetry.*` | Continuous logs, traces, metrics, resource pressure, sync progress and agent activity |
| New `fleet.insight.*`, existing `story.*` | Permissioned ingestion, retrieval, evidence explanations, incidents, costs and experiment outcomes |
| New `ops.service.*` | Typed deployment, scaling, configuration, migration, status and rollback plans |
| New `ops.traffic.*` | Versioned routing, traffic mirroring, A/B allocation and canary progression |

Evidence and retrieval belong under cognition; package/application lifecycle
under Commons; node telemetry under engine services; OS integrations behind
platform ports and adapters. Product implementation is C23 with existing
dependencies. Extend action and receipt types instead of adding an operations
ledger. Queries identify source generation, policy, coverage, observation age,
missing information and continuation cursor. Plans bind exact targets,
artifacts, configuration, schema, authority, preconditions and rollback.

## Ordered continuation queue

### 1. Finish the foundation for fast, coordinated work

Read [`CANONICAL_LIFECYCLE.md`](./CANONICAL_LIFECYCLE.md) before changing
landing, proof, board, train or lane behavior. Its lifecycle remains:

```text
NEED → JOB → CANDIDATE → PROOF_SET → PUBLICATION → REMOTE_RECEIPT
```

<!-- claim: file-present docs/work/CANONICAL_LIFECYCLE.md -->

1. Freeze evidence interfaces, then develop runner, lifecycle and federation
   changes in parallel with one primary writer per component. Connect candidate
   bundles, signed observations and proof admission into the canonical chain.
2. Separate reusable input keys from immutable observation roots. Compute keys
   from actual source, dependencies, compiler, flags, environment, harness and
   policy inputs. Preserve contradictory observations and refuse unresolved
   eligible conflicts. Navigator keys remain advisory.
3. Reuse unchanged unit evidence across candidates only when its exact input
   closure and receiver policy permit it. Changed or incomplete closures trigger
   required proof; reuse never omits mandatory publication evidence.
4. Persist publication intent before updating Git. Require fast-forward ancestry
   and an expected-base check; independently observe the remote result and
   reconcile after publisher failure. Retain competing P2P heads under receiver
   policy. An enqueue acknowledgement is not publication evidence.
5. Exchange context and candidates by root, verify received bindings and fetch
   only missing chunks. Attach exact duplicate requests to eligible existing
   work. Bind context to task, source, goal and explicit completeness; remote
   navigation or evidence never acquires local acceptance authority.

Retire competing lifecycle formats only after canonical reconstruction and
acceptance pass. Read-only context reuse precedes remote diagnosis, scoped
proposal and independent review. Missing qualified worker isolation is a named
refusal on either platform.

### 2. Make fleet visibility private, continuous and scalable

1. Replace total-member limits with indexed pagination and immutable history
   shards. Bound active connections, streams, batches, caches and fair refresh;
   each receiver chooses the history it retains and serves.
2. Subscribe and selectively replicate through existing authenticated encrypted
   transport. Keep private membership, telemetry and evidence roots off public
   discovery channels. Use bounded local projections for immediate answers and
   asynchronous queries for broader history.
3. Complete telemetry watch coverage after replacing blocking runtime and agent
   collection with bounded snapshots. Batch stream changes with backpressure,
   resumable cursors, restart epochs and explicit lost intervals. Slow
   subscribers cannot block node work.
4. Anchor issuer policy heads with monotonic sequence and predecessor roots;
   retain receiver high-water marks. Lost authority state requires a fresh
   authenticated head before control resumes.
5. Revocation cancels queued actions and prevents subsequent stages of running
   operations. Already-running services continue unless the grant explicitly
   authorizes termination.

### 3. Connect operational evidence to useful outcomes

1. Continuously watch native documents and signed tasks, including updates,
   deletions and access changes. Add bounded JSONL/API imports for transcripts,
   Slack, email, tickets, CRM, analytics and feedback using one adapter contract.
   Preserve provenance, external identity, timestamps, access policy and links
   to services, code, work and releases.
2. Reuse evidence envelopes and local indexes. Enforce permissions before
   storage, replication, retrieval and agent-context assembly. Imported text
   remains inert evidence, including instructions embedded in its content.
3. Correlate logs, traces, incidents, costs, experiments and feedback with exact
   deployed generations. Distinguish measured facts, estimates and proposed
   explanations. Implement OTLP/HTTP JSON interoperability using the published
   [OTLP encoding](https://opentelemetry.io/docs/specs/otlp/), without requiring
   a separate collector service.
4. Assemble a bounded agent context packet containing the objective, relevant
   evidence, reusable code, current work, permitted actions and one next action.
5. Bound retention by age and bytes with visible coverage loss. Preserve
   accepted lifecycle evidence and explicit pins until locally released;
   exhausted pin budgets refuse additional admission.

### 4. Make live operations transactional on both platforms

1. Extend the existing activation transaction through native systemd and launchd
   adapters. Repair service-unit placement and test the real preparation
   adapter. Use a trusted C23 executor that verifies permitted artifacts and
   running-image identity. Qualify Linux descriptor execution and macOS
   suspended-spawn image verification separately; one platform's evidence does
   not establish the other's guarantee.
2. Immediately before each mutation, the receiver checks current authority,
   action identity and expected artifact/configuration/schema generations.
   Duplicates reconcile with the existing action; lost acknowledgements never
   cause blind reexecution. Support deployment, replica scaling, configuration
   and migrations within the exact grant.
3. Run application HTTP routing in a separate bounded worker. Route revisions
   bind backend identities, weights, stable cohorts, deadlines and health
   conditions. Canary plans declare stages and observation windows; missing or
   stale health stops progression. Failure restores the verified prior route
   and compatible service generation.
4. Mirror only permitted replay-safe traffic into isolated shadow state. Shadow
   failures cannot delay primary responses.
5. Require migration rehearsal, checkpoints and compatibility evidence. Data
   rollback is a declared capability; binary rollback does not imply it.
   Rearchitecture is a dependency graph of ordinary code, service, routing and
   migration actions.

### 5. Accelerate chain and software synchronization

1. Complete the chain stopwatch's production wiring through verified
   installation, readiness and durable catch-up. Report bootstrap readiness and
   complete sovereign validation separately. Actual canonical installation or
   node restart still requires its separate owner grant.
2. Measure download, installation and validation stage costs; optimize scheduling
   without changing consensus predicates or mandatory verification.
3. Reuse CAS accounting, resumable downloads and proof caches. Warm identical
   transfers move no content payload; interrupted transfers retain verified
   chunks, and edits transfer only missing content.
4. Qualify maximum admitted background load while blockchain advancement and
   peer-health acceptance remain green.

## Acceptance and performance

Every claim names exact source, hardware, topology, cache state and offered
load. Failed operations and missing required observations count as misses.
Targets must be demonstrated with useful requested fields and sustained work,
not empty queries or idle subscribers.

| Area | Required evidence |
|---|---|
| Interactive access | Warm bounded local queries: p95 below 100 ms |
| Live telemetry | Subscribed observations through applied acknowledgement: p95 within 1 second on healthy direct links |
| Development feedback | Warm compile and focused proof: p95 within 10 seconds on a frozen small-change corpus; publication retains all mandatory evidence |
| Chain sync | Fresh datadir: captured peer tip through durable H* within 600 seconds at 100 Mbps; sovereign validation reported separately |
| Fleet growth | 1,000, 10,000 and 100,000 simulated members with bounded active resources, churn, partitions and fair refresh |
| Transfer reuse | Zero repeat content payload, only missing content after edits, no redownload of verified chunks after interruption |

Qualify telemetry on declared 100 Mbps, ≤20 ms RTT direct links, with useful
subscriptions and sustained event load. Report broader propagation separately
for each topology. Measure model-context bytes, tokenizer estimates, reads,
corpus walks and duplicate work separately from transport savings.

Required correctness scenarios:

- Twenty three-node lifecycle cycles with candidate races, stale bases,
  reordered objects, contradictory proofs, worker crashes and publisher crashes.
- Forged evidence, revoked grants, truncated policy history, expired
  subscriptions, privacy capture and poisoned shards.
- Real Linux and arm64 macOS installation, upgrade, restart, image substitution,
  PID reuse, crash recovery and verified rollback in permitted environments.
- Stable A/B cohorts, stalled shadows, unhealthy canaries, incompatible schemas
  and interrupted migrations.
- Maximum admitted fleet load with chain advancement and peer health green.

The release demonstration uses three consenting physical hosts: an agent finds
one real problem, reuses C23, produces a candidate, another host reproduces it,
the canonical lifecycle publishes it, owner policy permits a canary, telemetry
measures the outcome, and rollback is exercised. Before distributed dispatch,
qualify authenticated bounded commands and exact-object transfer in both
directions for each pair, under each receiver's permitted workspace and limits.
Missing host access or authority is an explicit unmet prerequisite.

### Existing acceptance remains mandatory

Use canonical registered groups and existing aggregate targets:

```bash
make mvp
make mvp-verify
make zcode-development-acceptance
make zcode-async-proof-acceptance
make sovereign-source-network-acceptance
make zcode-reproduction-acceptance
make commons-multihost-acceptance
```

`make mvp` reports the actual criterion; unavailable external prerequisites are
named BLOCKED, never PASS. Public-node acceptance retains fresh-node captured-tip
catch-up, post-fault durable H* climb, fresh from-genesis parity against
`zclassicd`, and an exact-candidate soak whose clock resets on evidence or
candidate discontinuity. Operator fixtures and sustained observation are not
replaced by unit tests. Start live operations or soaks only with the applicable
authority. Diagnose recovery on isolated copies.

Commons acceptance continues to require exact source, package, recipe,
dependency, toolchain, action, artifact and receipt roots; inert fetch; atomic
recoverable leases; exact duplicate handling; independent reproduction; local
acceptance; and survival of the original publisher's disappearance without
GitHub or a central registry. Fix the first violated invariant and add its
regression; retries or a parallel state machine cannot substitute for proof.

## Integration and continuation

For each coherent slice, record its owned surface, failing witness, exact
focused acceptance and residual uncertainty. Run canonical registered tests,
required lint/build checks, architecture and generated-interface gates as
applicable, and independent review. Freeze shared interfaces before parallel
implementation; keep one writer per component.

Fetch current `origin/main`, integrate safely and rerun affected gates. Publish
through the qualified canonical lifecycle and record the independently observed
remote SHA; follow the current enforced publication policy while convergence is
unfinished. Do not describe a local commit or queue receipt as publication.
Continue with the first unfinished item after every checkpoint until the full
journey passes. Escalate only under [`../../AGENTS.md`](../../AGENTS.md).
