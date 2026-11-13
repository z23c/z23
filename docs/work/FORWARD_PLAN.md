<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Z23 current forward plan

This file supplies scoped product and implementation context for development.
Durable product direction and
agent authority live in [`../../AGENTS.md`](../../AGENTS.md); public-node
acceptance lives in [`../quality/MVP.md`](../quality/MVP.md). Maintainer-host live state belongs
only in [`../agent/HANDOFF.md`](../agent/HANDOFF.md), consulted for an explicit host
assignment. Do not copy live heights, process state, or benchmark anecdotes here.

The [Now](#now) list below is the work order; `FLEET_SCORECARD.md` owns the
thirteen current A+ completion bars. The sections below supply scoped acceptance context.
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

## Strategy: do each piece of work once

For agents, writing code is cheap. What costs time and tokens is finding
what already exists, proving a change, and getting it running. Z23 does
each of these once and reuses the result by content address:

1. **Z23 knows every line of its own code.** Every line of every commit is
   indexed and sits inside wiki pages that maintain themselves. Any count,
   location or "do we already have X?" is one exact lookup, and every work
   brief carries its answer before anyone designs.
2. **The lab runs its newest self.** A landed improvement to the land path
   runs in the land queue after the next landing, not after a manual
   upgrade.
3. **One full proof per change.** The land proof is the only full check.
   Unchanged inputs are skipped by selection today, and by verdicts signed
   by a separate verifier once that is installed
   ([`separate-verifier.md`](separate-verifier.md)).
4. **Labs trade proofs, not trust.** A stranger's lab offers a change over
   Z23. This lab re-verifies it before admitting it, and peer labs cosign
   each other's verdict logs.

The number that steers the lab is the median time from a commit being
written to it landing on main: the tip's author time (`%at`) to its
`landed_at` in the land outcomes. Rebase rewrites the commit time, so `%ct`
does not measure it. Then comes the time to a running public node.

## Now

At most seven items, ranked. Take the first one nobody has claimed in the
native `dev.agent` registry, keep it to one lane with one writer, and land it
through `dev land submit`. A dev-tooling item names the number it moves, with
before and after values. Before starting, check that the work has not
already landed: match `git log origin/main` by subject and `git cherry` by
patch id, never by commit id, because the land queue rebases. On 2026-11-04
four units redid work that was already on main.

Where the time went, 2026-10-28 to 2026-11-04, over 459 landings:

| Stage | Median | p90 |
|---|---|---|
| Commit written to submit | 71 min | 313 min |
| Pre-submit stack gate (371 runs) | 57 min | 120 min |
| Submit to landed | 31 min | 85 min |
| Land proof | 12 min | 28 min |

Stack gates ran for 409 elapsed hours and land proofs for 96, and the land
proof repeats the stack gate's full lint and tests. 60 rows failed or
conflicted, costing 11.2 hours of proof. Items 3 to 5 remove these costs in
order of size.

1. **The node restarts in seconds.** `fleet objectives` names
   `node_warm_restart_s` as the biggest gap; read the live card, not this
   file. The boot timers split it: the landed bundle downloaded again, the
   coins read view, the prologue. Fix the largest step, read the next boot
   beacon, repeat. Resident memory (`node_rss_mb`) comes next. A boot that
   refuses to start names its stage and cause; an untyped refusal is a bug.
2. **A stranger runs a stranger's app.** Today an app travels only as a
   `.z23share` file handed between friends. Close the chain with pieces
   that exist:
   - `app publish COPY` posts one signed `zcl.app_offer.v1` entry to the
     public board room `apps` and serves the version on the swarm. Its plan
     half writes nothing.
   - `app get` lists that catalog. `app get NAME` fetches the version by
     root and refuses any sha256, root or publisher mismatch before a
     prompt. It then hands the bytes to the existing receive confirm of
     publisher fingerprint and exact root (owner decision 2026-11-06).
   - Trust needs no gatekeeper. Every receiver that rebuilds the same image
     posts a signed rebuild receipt, `app get` shows how many independent
     builds match, and any holder serves the bytes again, so the app
     outlives its author's node.
   - A received copy builds with z23, `cc` and `make` alone: no system
     `-dev` package (owner rule 2026-11-08).

   Lane `stranger-app-get-1108` held the first slice. Number: stranger to
   stranger journeys proven live between two isolated nodes. Before: 0;
   after: 1 — `make app-journey-live` (`tools/app_journey_live.c`) PASSed
   live on 2026-11-13 and landed as b1cff52d46: two isolated regtest nodes
   with real Tor, CREATE→MODIFY→SHARE→DISCOVER end to end, B types one
   name (zero hex), B's rebuilt image equals A's local build, B posts the
   signed rebuild report and hosts the carrier, and B still serves after
   A dies. The next journeys raise the count.
3. **One full proof per change.** The land proof is the only full lint and
   test run.
   - A lane submits after its focused groups, `lint-fast` and the cheap
     gates that fail land proofs. The pre-submit stack gate is not required.
     `check-kpi-floor` refused 4 rows in the week, 3 of them on 2026-11-04,
     and `lint-fast` does not run it.
   - The top cause of failed rows is the land worktree's own compiler step
     (`build/bin/zcc cc -s`, 7 rows), not a code defect. Fix it at the root.
   - A failed row's outcome carries the failing gate's own output lines, so
     the failure returns to its author without a search. Today the outcome
     keeps only the `FAIL` line, and the gate log sits under the land
     worktree's `.cache/lint-timing/gates/`.
   - A failing assertion prints what its test observed: child output, exit
     status, response body. On 2026-11-04 two of four agents could not
     root-cause the most frequently failing groups, because the logs held
     only the assertion line.
   - Lint gates that read one file at a time run only on changed files.
     Test groups run in order of their past failures on the changed paths.
     A group that fails only under load gets a root-cause fix, never a rerun
     or a weaker assertion.
   - Every gate earns its cost. Lint gates went from 168 to 215 in the week
     starting 2026-10-28, and each one runs in every land proof. The proof
     records each gate's and each group's runtime and catches, and a gate
     with no catch in four weeks moves to a scheduled sweep.

   Numbers: commit to landed median 102 min, target 45; p90 398 min, target
   90; failed or conflicted rows 60 against 459 landed, target under 5%.
4. **The lead is not on the path.** On 2026-11-04 every lane waited for the
   lead to rebase it, submit it and read its failure.
   - A recorded non-author LAND lets the author submit.
   - A failed row returns to its author with its evidence, and the author
     repairs and resubmits.
   - Add `dev land intake`, which takes READY posts from other agents and
     labs: signature, author allowlist, scope, merge-tree, then the queue.

   Number: lanes the lead handles by hand per landing. Before: all of them.
5. **The land queue proves in parallel and runs its newest driver.** One
   proof runs at a time, and a red train re-proves each member alone.
   - Bisect a red train.
   - Prove the next rows speculatively on an idle host, then confirm them on
     the current main.
   - The self-upgrade module (default off) keeps a content-addressed driver
     slot, compares the candidate's decisions with the current driver's,
     switches after matching rows and switches back after a failed row. Next
     come a read-only decision verb and the post-landing hook.

   Number: submit to landed p90, before 85 min, target 30.
   Number: the landings between a driver fix landing and the driver running
   it. Before: unbounded.
6. **Z23 knows every line of its own code.** The inventory is an overlay on
   git trees in `cognition/modules/codeindex`, keyed by tree and blob hash,
   so it answers for any commit without a checkout. It grows the
   [Palace](../dev/palace-design.md) `purpose` line and `code room` into
   pages.
   - **Exact counts.** `code count --at=REV` reads git objects with a
     per-blob cache. At f0e2092992 it gave 3,404,079 lines in 8,326 C files
     outside `vendor/`, equal to `git grep`, warm in 125 ms. Target: every
     inventory query at main under 100 ms.
   - **Every line indexed.** Symbols carry their end line, files their line
     count and hash, and design documents get a table, so `path:line` maps to
     its function and documents are searchable.
   - **Pages around every line.** Pages nest from symbol to file, group,
     area and root. Each page holds purpose, contract, callers, callees,
     covering tests, design documents, the commits that explain why,
     lessons, receipts and health. Facts are derived. Prose is written when
     a page is first read and when its subject's hash changes, cached by
     that hash and signed, so no agent writes the same summary twice. A
     landing dirties only the path from the changed lines to the root. A
     lesson anchors to a span hash and is flagged, never dropped, when the
     span changes. 123 module cards written on 2026-11-04 scored 1.95 of 2
     on a 20-card spot check and wait for the pages table.
   - **One ranker.** `code have`, `code guide`, `z23_search`, `discover
     wiki`, `general` and `fleet wiki find` share it. The known-answer set
     `tests/fixtures/code_have/cases.jsonl` holds 63 real questions, for
     example test result cache → `tests/harness/src/testcache.c`, separate
     verifier → `docs/work/separate-verifier.md`, Merkle mountain range →
     `core/modules/chain/src/mmr.c` and
     `contexts/commons/modules/vcs/src/zcode_observation_mmr.c`. Top five:
     16 of 63 before 2026-11-04, 21 after; target 90%.

   Number: the share of symbols with a fresh page. Before: 0.
7. **Labs trade proofs, not trust.**
   - Signed verdict reuse follows [`separate-verifier.md`](separate-verifier.md)
     and [`verifier-install-packet.md`](verifier-install-packet.md). Read
     the shadow verdict store's hit and divergence rates in
     [`tools/dev/dev_proof.c`](../../tools/dev/dev_proof.c) first, then
     clear the packet's blockers and run its one install script. Reuse
     admits only verdicts signed by the pinned verifier key and appended to
     its Merkle mountain range log. Number: shadow hit rate at zero
     divergences. Before: not measured.
   - A stranger's lab lands a change over Z23.
     [`tools/lab_peer.c`](../../tools/lab_peer.c) `verify` reads offers only
     from allowlisted keys, and `collect` never queues. Re-verify any key's
     offer with `--check=verify` in an isolated tree; admission stays a
     maintainer decision. One test group runs offer, receipt signing and a
     tampered-bundle refusal between two isolated nodes with the real
     binaries; the swarm, the board, verify and collect stay stubbed there
     ([`LAB.md`](../dev/LAB.md#peer-verification-over-the-swarm)). The
     change may be a one-file plugin built with `plugin dev`
     ([`PLUGINS.md`](../dev/PLUGINS.md)), which agents then call through the
     MCP adapter. When two labs agree on nearly every change, a second-lab
     receipt becomes required before landing. Number: stranger changes
     landed. Before: 0.
   - Port the shell scripts the land path runs on every change to C23. Each
     port proves the same output and exit status, deletes the script and
     lowers `tools/lint/bash_line_budget.txt` in the same commit. The
     cyclomatic cap stays 15 and its baseline stays empty.

**Not now.**
- No new search or brief command outside the one ranker.
- No new lint gate without the class of defect it catches.
- No land-path binary run from a development tree.
- No new plan document: this list is the work order.
- No pre-submit stack gate as a landing requirement.

## Invariants and authority

P0 consensus, wallet custody and public-node correctness retain absolute
priority; after P0, the [Now](#now) list applies. Insight,
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
   and 8 retain their recorded acceptance gaps. Follow the [Now](#now) work order
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
   --print-bootstrap-platforms` lists both and `tools/lint/lintc/gate_published_platforms.c`
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
