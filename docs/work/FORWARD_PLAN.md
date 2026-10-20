<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Z23 current forward plan

This file supplies scoped product and implementation context for development.
Durable product direction and
agent authority live in [`../../AGENTS.md`](../../AGENTS.md); public-node
acceptance lives in [`../quality/MVP.md`](../quality/MVP.md). Maintainer-host live state belongs
only in [`../agent/HANDOFF.md`](../agent/HANDOFF.md), consulted for an explicit host
assignment. Do not copy live heights, process state, or benchmark anecdotes here.

`AGENTS.md` owns work order; `FLEET_SCORECARD.md` owns the thirteen current
A+ completion bars. The sections below supply scoped acceptance context.
Passing all of MVP.md's
C1–C8 is necessary for platform v1 but not sufficient: platform v1 is the
release demonstration under *Acceptance and performance* below, together with
the existing acceptance targets. Open (◐) MVP criteria remain acceptance
context under `AGENTS.md`; work that needs a ZCL spend waits for an owner
authorization. Each ◐ cell names its own remaining
condition or owner decision; recheck it against its ledger before starting.

[`DEVELOPMENT_MVP.md`](../agent/DEVELOPMENT_MVP.md) retains eight scoped milestones
(D1–D8) for fast, coordinated, low-cost agent development of C23, each with one
measurement and one threshold. D1–D8 and C1–C8 remain acceptance context; they
do not replace the fleet A+ bars or reorder current work.

<!-- claim: file-present docs/agent/DEVELOPMENT_MVP.md -->

## Current mission

Make Z23 the program described in the [North Star](../README.md#north-star):
it verifies the money, the software, the peers and the agents, and it is
developed, released and deployed with its own commands. Work is chosen in
this order:

1. **Money (P0).** Canonical nodes run the latest landed build, agree with
   `zclassicd` on tip and block hash, and carry no unexplained blocker.
   Consensus parity and custody come before everything else.
2. **Self-hosting.** Landing, release, deployment, build admission and
   cleanup are `z23` commands; no private script is on the path from a card
   to a running node.
3. **Subtraction.** Retire legacy names, dead scripts, stub commands and
   duplicate plans. The core, the command count, the documents and the shell
   scripts trend down while every test passes.
4. **A stranger's first hour.** From a fresh clone to a verified node and a
   first lab result in minutes; then one useful application built as a
   one-file plugin and reproduced on a second node.
5. **Your own fleet.** Joining, updating, shell access, the wiki and
   telemetry work for any owner's machines, not only the maintainers'.

The app-to-plugin plan for item 4 is [`PLUGIN_APPS.md`](../commons/PLUGIN_APPS.md).

The [fleet A+ scorecard](FLEET_SCORECARD.md) and `z23 fleet goals` measure
the fleet features in item 5 and the self-hosting in item 2; they do not
reorder P0. Requirements below are acceptance targets, not claims of
completed implementation or measured performance.

## Invariants and authority

P0 consensus, wallet custody and public-node correctness retain absolute
priority; after P0, the fleet A+ scorecard order in `AGENTS.md` applies. Insight,
Control and development machinery advance public-node reliability and C23
Commons acceptance. Telemetry, indexing, builds, transfers and application
operations may not delay chain advancement, synchronization or peer health.
Consensus predicates and byte-sealed core remain unchanged without the explicit
unseal ritual. Custody retains separate authority; reviewed, landed builds may
be deployed and restarted.

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

<a id="five-product-acceptance-priorities"></a>

## Five product acceptance outcomes

**Software made for you, not imposed on you.** Describe a useful change, see
its real behavior, reproduce it elsewhere, and accept an exact version that
remains usable after its original agent or publisher disappears. The larger
vision connects sovereign C23 nodes, reusable software and an optional emulated
RISC-V FreeBSD environment through independently verified peer routes.

These five outcomes retain product acceptance context. Select work under
`AGENTS.md` and the fleet A+ scorecard, respecting dependencies and authority.
The items below describe work to prove, not capabilities declared complete.

1. **Make the public node and wallet verifiable first.** Close the literal
   [C1–C8 criteria](../quality/MVP.md) with evidence bound to the exact candidate.
   Literal payment qualification requires a previously uncredited recipient
   to receive **a minimal shielded payment within two blocks** (never a whole ZCL), with real proof verification and no
   double credit. Preserve the full from-genesis parity and uninterrupted
   seven-day soak requirements; a smaller decrypted note or a unit test cannot
   replace them. Missing prerequisites remain explicit; synchronization work
   maps to section 5.

   Criterion 4 is rerun later with the minimal amount, when the owner schedules the
   spend. Its [`MVP.md`](../quality/MVP.md) evidence is a 0.02 ZCL note decrypted
   after mempool entry; that shows decryption, not the balance within two blocks. Criteria 6
   and 8 retain their recorded acceptance gaps. Follow the fleet work order
   when selecting authorized work on these gaps.

2. **Qualify protected native and guest access through restart.** Reuse the
   existing `ops.mesh.terminal` Linux confined shell owner; qualify additional
   native SSH/development capabilities and macOS confinement, and retain an
   SSH client and daemon inside Z23's FreeBSD guest on participating Linux and
   Mac machines, with guest-held identity and tunnel recovery across restart.
   Execution and transport are separate policy choices: direct authenticated
   connections, SSH tunnels and embedded Tor share the same receiver authority
   and evidence requirements. Their capability and admission contract is
   [AGENT_FLEET.md](AGENT_FLEET.md#consolidated-operating-model). Reuse existing
   shell and SSH programs as bounded processes; do not place general shell
   execution inside the consensus node. Native execution, hardware
   virtualization where qualified, and RISC-V emulation are protected options,
   not permission to fall back to unconfined execution.
   Bind image identity, admission, guest boot, negotiated SSH algorithms, routing
   and reconnection to exact source, image, platform and configuration. First
   prove each layer separately, then the route between consenting machines, including wrong
   identity, downgrade, revoked access and interrupted-transport refusals.
   A host SSH endpoint cannot substitute for the guest route. Loopback and
   host-side fixtures establish only their measured layer;
   post-quantum key exchange does not make classical identities post-quantum.
   This depends on private visibility and transactional operations in sections
   2 and 4. Guest daemon activation, keys, login and production operation retain
   their separate authority requirements; this roadmap grants none of them.

   Next concrete task: choose and freeze one guest byte route, either the console transport or an attached network device (`rvvirtio_net_init` and `rvvirtio_net_receive` exist in `platform/modules/rvvirtio`; [`RISCV_MACHINE.md`](../commons/RISCV_MACHINE.md) says the machine attaches no network device), and qualify that chosen path with an actual stock-kernel acceptance run. The registered group `rvmachine_freebsd_ports` prints UNOBSERVED when its image is unavailable (`tests/harness/src/test_rvmachine_freebsd_ports.c`), so the run needs a supplied kernel.

3. **Complete one useful application journey.** Choose a real user problem,
   reuse existing C23 first, build the missing behavior and show its actual
   consequence. First complete the [three-host release demonstration](#acceptance-and-performance):
   request, exact source and dependencies, independent reproduction, publication,
   local acceptance, real application use, permitted canary, telemetry and
   rollback. This maps to section 3 and its lifecycle dependencies. One working
   application is not proof of arbitrary
   application generation.

   Next concrete task: add one registered hermetic case that links install, update, a forced failure and rollback for the shipped `ztasks` package (`contexts/commons/packages/ztasks`). The pieces exist apart: the group `resident_launch_contract` installs `ztasks` and lists rollback as its stage f (`tests/harness/src/test_resident_launch_contract.c`), and `package_lifecycle_rollback` in `contexts/commons/services/src/package_lifecycle.c` is tested in `tests/harness/src/test_zcode_add.c`. No canary or traffic-split mechanism exists yet: `ops.traffic.*` appears in no source file.

4. **Reuse verified work and publish reliably.** Qualify peer results against
   their complete input closure and receiver policy; preserve contradictions.
   First pass the twenty three-node lifecycle cycles and adversarial cases
   below, including duplicate work, stale bases, forged evidence, worker loss
   and publisher crashes.
   Persist publication intent and independently observe the remote result.
   This is section 1, supported by section 5's measured transfer of missing
   content. A signature, receipt or queue acknowledgement alone proves neither
   correctness nor publication.

   Current main already completes this task: `dl_hold()` writes the hold under `queue.lock` without acquiring `step.lock`; `test_dev_land` registers `dlx_hold_admissible_during_step()` and `dlx_hold_survives_step_rewrite()` to cover admission during a held step lock and survival across a step rewrite that would otherwise erase the hold. The publication-hold cases also assert that publication remains blocked until release. These cases are present in the current source; this note does not claim a new test run.

5. **Keep accepted software usable after its publisher disappears.** Preserve
   source, dependencies, recipes and evidence, then reproduce without the
   publisher through `make commons-multihost-acceptance`. Separately qualify
   permitted installation, updates, crash recovery and rollback on Linux and
   arm64 macOS, binding results to exact artifacts and platforms. Binary rollback
   does not establish data rollback. This combines retention in section 3,
   lifecycle operations in section 4 and transfer reuse in section 5; a hash or
   a link alone does not preserve the object it names.

   Next concrete task: add a registered case in `tests/harness/src/test_zcode_swarm_net.c` where the late joiner finds the surviving holder by announcement. The existing case `zwn_t_redundant_publish_disappear` fetches through `zwn_fetch_package_from_provider`, which calls `vcs_swarm_engine_fetch_from` with an explicit provider handle.

<a id="ordered-continuation-queue"></a>

## Scoped implementation references

Section numbers identify implementation areas; select work using `AGENTS.md`
and the fleet A+ scorecard rather than section order.

### 1. Finish the foundation for fast, coordinated work

Read [`CANONICAL_LIFECYCLE.md`](../node/CANONICAL_LIFECYCLE.md) before changing
landing, proof, board, train or lane behavior. Its lifecycle remains:

```text
NEED → JOB → CANDIDATE → PROOF_SET → PUBLICATION → REMOTE_RECEIPT
```

<!-- claim: file-present docs/node/CANONICAL_LIFECYCLE.md -->

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
6. Prove one real two-machine file-market trade over Tor: offer, purchase,
   authorized retrieval. Acceptance: `make commons-multihost-acceptance` ends
   with byte-identical content on two hosts and each friction point is fixed.
7. Complete the marketplace lane without a consensus change: cross-chain ZSLP
   HTLC (redeem is an SLP SEND), adversarial simulator cases (cancel by
   double spend, expiry and refund races, secret front-running, reorg during
   settlement, oversized ads), then a simulation-first ZC23 implementation plan.
   Acceptance: the simnet cases pass in their test group.

### 4. Make live operations transactional on both platforms

1. Extend the existing activation transaction through native systemd and launchd
   adapters. Repair service-unit placement and test the real preparation
   adapter. Use a C23 executor that verifies permitted artifacts and
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
   complete sovereign validation separately. Canonical installation and node
   restart use a reviewed, landed build.
2. Measure download, installation and validation stage costs; optimize scheduling
   without changing consensus predicates or mandatory verification.
3. Reuse CAS accounting, resumable downloads and proof caches. Warm identical
   transfers move no content payload; interrupted transfers retain verified
   chunks, and edits transfer only missing content.
4. Qualify maximum admitted background load while blockchain advancement and
   peer-health acceptance remain green.
5. Publish `darwin-arm64` and `windows-x86_64` bootstraps from native cuts, each
   with its real digest row. Acceptance: `build_release.sh
   --print-bootstrap-platforms` lists both and `tools/lint/check_published_platforms.sh`
   passes.
6. Earn a chain-sync receipt on macOS and Windows with `make mvp`, `make
   test-two-node-peer-tip` and `make mvp-coldstart-to-tip-stopwatch`.
   Acceptance: one recorded receipt per platform; BLOCKED stays named and Wine
   never substitutes.
7. Remove Linux-only harness assumptions. Acceptance:
   `z23-lint check-shell-host-assumptions` and the pipefail ratchet counts only
   shrink, with `ss`, `nproc`, `stat -c` and `sed -i` sites moved to portable helpers.
8. Enforce the ZIP-209 turnstile on the reducer path, owner-gated and
   copy-proved on a datadir copy. Acceptance: a block driving a shielded pool
   negative is refused, and `reducer-shielded-consensus-plan.md` section 8
   gaps are closed.

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
After every checkpoint, select the next authorized work under `AGENTS.md`
and the fleet A+ scorecard; retain the scoped journey acceptance requirements.
Escalate only under [`../../AGENTS.md`](../../AGENTS.md).
