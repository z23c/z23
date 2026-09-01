# LLM-first C23 App and Game Platform — execution checklist

**Status:** execution companion for Phases 3–5 of
[`SOVEREIGN-NETWORK-ROADMAP.md`](./SOVEREIGN-NETWORK-ROADMAP.md), not a new
priority queue.

[`../HANDOFF.md`](../HANDOFF.md) owns current live facts,
[`FORWARD_PLAN.md`](./FORWARD_PLAN.md) owns immediate execution order, and
[`../MVP.md`](../MVP.md) owns the v1 acceptance bar. The sovereign
complete-state cure remains priority #1. The native command registry is the
sole agent interface. Nothing in this checklist authorizes runtime
publication, canonical deployment, or mutation of the protected mint
producer.

[`ADR-0004`](../adr/0004-capability-service-fabric-and-app-checkpoints.md)
supersedes this document's earlier same-binary/self-exec App-worker wording.
Core remains one immutable executable; fetched Apps are distinct static PIE
artifacts admitted from the private SHA3 CAS and launched out of process.

The source-distribution implementation checklist and optional non-consensus
ratio/burn-credit design live in
[`../P2P_SOURCE_HOSTING.md`](../P2P_SOURCE_HOSTING.md).

This document turns the long-term product direction into checkable work:

> An LLM edits a small amount of ordinary C23. Z23 derives the
> affected interfaces and mandatory proofs, automatically records correlated
> telemetry, and returns one compact green receipt or one deterministic
> failure capsule. Third-party Apps and games use the node through bounded
> capabilities and never execute inside the consensus process.

## How to use this checklist

- Complete items only with a commit/source epoch, named proof, and durable
  artifact/command receipt — a document claim alone is not completion.
- Treat unchecked items as unavailable regardless of a menu/prototype; verify
  with `discover describe <path>`.
- A required `SKIP`, stale receipt, omitted dirty path, retry-only green, or
  missing inspection tool is RED, not partial success.
- `progress.kv` stays consensus-authoritative; dev/telemetry stores are
  non-consensus evidence and never authorize chain state.
- Work in isolated worktrees with disjoint file scope; never use a dirty
  main worktree as an implicit source-epoch boundary.
- Profile before optimizing — token/latency/CPU/memory/telemetry-overhead
  claims require measured artifacts.
- Do not check an item off by weakening parity, proof selection, sandboxing,
  privacy, durability, or rollback requirements.
- Use exactly four availability labels — `ready`, `compat-contained`,
  `planned`, `blocked` — generated from the native registry, never a second
  hand-written catalog.

Evidence format: `- [x] <item>` with `Evidence:`, `Tests:`, and (for a
performance claim) `Measurement:` lines naming commit/source_epoch/receipt.

## External promotion prerequisites — owned elsewhere

Design, measurement, and hermetic simulation in this checklist may proceed
in isolated lanes. No App/runtime/package promotion may jump these gates,
owned by `HANDOFF.md`, `FORWARD_PLAN.md`, `MVP.md`, and the sovereign
roadmap: copy-prove the complete transparent/Sapling/Sprout/nullifier cure;
prove H* climbs with exact parity, warm restart, kill-9 resume, and
malformed-input no-publish; obtain explicit owner authorization before
canonical deployment; earn MVP 8/8 plus a fresh clean 168h soak; prove
native mutation/auth/audit/event/metric/notification/secret/rollback
behavior end to end; complete commit-bound quality/release evidence before
calling an App or package stable.

## Architecture decisions — freeze these first

- [ ] Land the four-plane ADR (consensus, platform control, per-instance App
  state, CAS/evidence) — decision accepted in
  [`ADR-0004`](../adr/0004-capability-service-fabric-and-app-checkpoints.md);
  landing stays unchecked until committed with exact source-epoch evidence.
- [ ] Freeze the LLM-authored C23/HTML/Markdown promotion rule: `source →
  validation → proof DAG → content/manifest digest → capability grant →
  publisher signature → optional chain anchor`.
- [ ] State explicitly: signatures/chain anchors prove provenance, byte
  integrity, ordering, revocation — never code correctness (compiler
  warnings, model validations, deterministic tests, sandboxing, and review
  remain independent release gates); telemetry is evidence, never consensus
  authority; an in-process native C module is trusted code, not a
  capability sandbox.
- [ ] Keep only audited built-ins statically linked; run fetched/third-party
  C23 Apps as separate static PIE artifacts admitted from private CAS.
- [ ] Use one manifest to generate commands, routes, topics, schemas,
  telemetry, simulations, documentation, and proof mappings; one native
  command ontology (extend existing leaves before adding AI-specific ones).
- [ ] Store full logs/traces as content-addressed artifacts; default command
  responses carry bounded semantic projections + artifact references.
- [ ] Use `.zclpkg`/`zcl.package_manifest.v1` from the sovereign roadmap for
  Apps and games — no parallel `.zapp` format.
- [ ] Require explicit local approval for new capabilities, publisher
  changes, migrations below the rollback floor, and wallet authority.
- [ ] Keep signing keys in the wallet-owned secret store; Apps submit typed
  intent through an opaque, generation-bound grant — never a raw key,
  capability bitmask, chain ID, App ID, or topic at the signing boundary.
- [ ] Keep dynamic loading on canonical/soak/release lanes at zero.
- [ ] Name the event stores precisely instead of calling all of them "the
  event log": `progress.kv` (consensus/reducer authority),
  `engine/modules/storage/event_log` (durable engine/application/projection replay),
  `engine/modules/event` (volatile bounded observability), development receipts and
  the proposed telemetry ledger (non-consensus evidence).
- [ ] Permit consensus state to flow into diagnostics; never let telemetry
  loss/truncation/contents flow into consensus validity or cursor advance.

## Current baseline — verify fresh

Foundations already present, not proof the target platform is complete.

- [x] Native registry has typed effect/risk/authority/cost/capability
  metadata + hard response budgets (`engine/modules/kernel/include/kernel/command_registry.h`).
- [x] Native `code` branch exposes bounded map/group/room/file/symbol/ref/test
  queries (`cognition/modules/codeindex/`, `tools/command/native_code_command.c`).
- [x] Verify-only native dev loop classifies changes, runs proofs, persists
  a verdict, refuses runtime publication (`tools/dev/`, `make dev-watch`).
- [x] Watcher + native diagnostics share worktree-scoped, SHA3-sealed cycle
  state and durable deterministic compiler-failure IDs; exact unchanged
  compiler failures coalesce, every other red reruns.
- [x] Public App ABI skeleton declares capabilities/routes/topics/state/
  migration/self-test/quiescence/leases without exposing consensus or
  private keys (`engine/modules/framework/include/zclassic23/app.h`).
- [x] `contexts/commons/apps/social/app.def` + a deterministic Social simulation prove the
  manifest and seeded-scenario shape.
- [x] Bounded event ring, traces, metrics, state dumpers, postmortem
  capsules, deterministic simnet, 64-bit replay seeds.
- [x] Runtime generation apply, resident `dlopen` probing, deploy-dev, and
  canonical mutation paths fail closed during Phase-0 containment.

Known gaps that remain unchecked: one authoritative worktree-scoped dev
receipt history; durable failure IDs/diagnosis for every red proof phase
(only the deterministic compiler-failure slice is complete); one C-owned
proof DAG shared by watcher/CLI/CI/code navigation; concurrent-reader-safe
daemon-owned semantic index snapshots; typed durable correlated telemetry
across node/dev-loop/Apps/games/jobs; strict manifest compiler + generated
App catalogs; generic AppSim on the production ABI; host-owned transactional
App state/events/projections; out-of-process App worker + capability
broker; generic App-topic transport + deterministic Game SDK; source-first
signed package build/discovery/upgrade/rollback.

### Native availability snapshot

Orientation only — re-check the running registry with `discover describe`.

| Status | Current surface |
|---|---|
| `ready` | `discover.*`; `code.*`; `dev app list/describe/plan/simulate`; `dev change plan`; `dev test plan/background`; `app list/inspect`; primary `ops health/diagnose/state/logs/timeline/metrics/selftest/debug/recovery` reads |
| `compat-contained` | verify-only `dev loop ensure/status/wait/stop`; `dev diagnose latest/show`; generation reads; apply/hot-swap compatibility leaves (confer no publication authority) |
| `planned` | `dev app scaffold/inspect/publish`; `dev loop events`; `dev test replay`; general `ops jobs`; App package/content commands; out-of-process App runtime; generic Game SDK |
| `blocked` | canonical/dev publication and resident dynamic loading while Phase-0 containment applies |

The Social App is prototype evidence: its deterministic simulation is
ready, but runtime invocation is checkout-only, not a sandbox/runtime proof.

## Reference App ladder: Blog → Social → Chat

Do not grow three bespoke protocols. Blog, Social Feed, and Chat consume
one immutable signed `AppEvent` ActiveRecord store, generic topic relay,
manifest compiler, capability broker, telemetry envelope, and HTTPS/onion
dispatcher. None of the three is complete until it has a clean source epoch
and durable proof receipt under this document's evidence rule.

- [ ] **Shared substrate:** immutable `AppEvent` persistence keyed by event
  ID (app/topic/receive-cursor and app/author/sequence/event-ID indexes);
  previous/successor/projection relationships as model APIs (retain all
  valid forks, select deterministically, never by arrival); generic signed
  `inventory/get/event` anti-entropy for manifest-declared topics (verify
  scope/size/event-ID/signature/replay/rate before persistence); nonblocking
  network callbacks (bounded enqueue, explicit backpressure, no peer-lock DB
  work); do not promote legacy ZMSG (plaintext/unsigned) into Chat — keep it
  as compatibility until the signed generic relay replaces it.
- [ ] **Blog** (`/blog` reference MVC shape today): manifest discoverable via
  `app.list`/`app.inspect`; BlogPost/BlogPublicationReceipt migration
  idempotent with relationship indexes and closed-fail on a future schema
  version; every write through AR lifecycle callbacks; `has_many`/
  `belongs_to` relationships fail closed on parent drift; all valid event
  forks retained and resolved to the same canonical slug regardless of
  arrival order; malformed requests fail before signing, wallet grant
  revalidated on every sign, private keys never cross the host boundary;
  ZNAM historical owner epochs proven at event/anchor heights; `ZBLG`
  OP_RETURN script parsed minimally with reorg-refreshed classification;
  signed events replicate via bounded P2P/onion anti-entropy with alternate-
  relay recovery for a late joiner; same accessible page on HTTPS and onion,
  503 (never unsigned fallback) when proof storage is unavailable; reviewed
  wallet composer broadcasts only after explicit operator approval.
- [ ] **Social Feed:** Profiles/Posts/Follows/Reactions/FeedCursors via the
  same MVC/AR scaffold as Blog; author/parent/replies/following/followers
  relationships with keyset (never offset) pagination; ranking/moderation
  deterministic/local (a relay may hide an event, never mutate its ID,
  signature, or another node's projection); one escaped responsive `/social`
  resource over HTTPS and onion; promote the existing Social simulation only
  once it invokes the production AppEvent storage/broker/relay path.
- [ ] **Chat:** Conversations/Memberships/Messages/DeliveryReceipts/
  ReadCursors/DeviceKeys with compound indexes; signed public rooms first
  (labeled plaintext), then private store-and-forward envelopes via
  wallet-owned X25519/HKDF/ChaCha20-Poly1305 (hop Noise alone is not
  end-to-end); Apps never receive wallet/encryption private keys — the
  wallet service signs/encrypts typed intent under exact generation/grant/
  device policy; batch high-volume ordering into signed/Merkle roots, never
  one chain tx per message; measure event encode/verify, AR batch/WAL/fsync,
  feed query p50/p95/p99, ingest-to-visible, send-to-ack, partition
  catch-up, saturation/backpressure, bytes/event, RSS, and render cost, each
  pinned to hardware/build/seed/fixture/WAL-mode; prove malformed/tampered/
  wrong-recipient/replay rejection, AEAD/low-order-X25519 KATs, offline
  delivery, alternate-relay censorship bypass, partition/rejoin, late join,
  route parity, bounded queues, privacy-safe telemetry (no IDs/names as
  metric labels).

## LLM operating checklist — available today

Use this loop while the later platform items remain incomplete.

1. **Establish authority and scope** — `pwd`, `git status --short`,
   `git worktree list --porcelain`; read `HANDOFF.md` (live facts),
   `FORWARD_PLAN.md` (before treating this as the active queue),
   `AGENT_TRAPS.md` (before fixing an apparent defect), and for
   consensus-adjacent work `CONSENSUS_PARITY_DOCTRINE.md` +
   `DEFENSIVE_CODING.md`; confirm the assignment owns an isolated file set.
2. **Discover before reading files** — `discover search <topic>`,
   `discover describe <leaf>` (verify `availability=ready`), `code room
   <path>`, `code sym/refs/tests <symbol|path>`; fall back to `rg`/bounded
   reads only for prose, comments, `.def` files, and plans the navigator
   doesn't index.
3. **Plan the exact change** — `dev change plan`, `dev test plan`, (for an
   App resource) `dev app plan`/`dev app describe`; name any unmapped file
   or incomplete proof relationship as a blocker rather than guessing a
   smaller proof set.
4. **Edit and verify** — keep the watcher verify-only (`dev loop ensure
   --input='{"mode":"verify"}'`); edit only owned files; read the verdict
   via `dev loop status/wait`; on failure follow `dev.diagnose.show`'s
   structured action; run the mapped focused test groups, `make build-only`,
   `make lint`, and deterministic App scenarios (`dev app simulate --seed=`);
   record exact seed/source-identity/proof-groups/receipt; never call
   apply/publish/deploy-dev/resident hot-swap as completion evidence.
5. **Diagnose runtime behavior** — start with `z23 status`/`ops
   health`; use `ops diagnose` for the causal rollup, `ops state
   <subsystem>` for one subsystem, `ops timeline` before raw logs, `ops
   logs --pattern=` only after state/timeline identifies a drilldown; any
   shell/process archaeology needed is a missing-telemetry finding to record.

### Source-of-truth routing

| Question | First source |
|---|---|
| What is live and protected? | `z23 status` + `docs/HANDOFF.md` |
| What should execute next? | `docs/work/FORWARD_PLAN.md` |
| Why is the code shaped this way? | `docs/FRAMEWORK.md` |
| How is a feature slice built? | `docs/AGENT_ARCHITECTURE.md` |
| What commands exist now? | `discover search/describe` |
| Where is a symbol and who uses it? | `code sym/refs/room` |
| Which proof is required? | `dev test plan` + `code tests` |
| What can an App request? | `engine/modules/framework/include/zclassic23/app.h` |
| What does an App declare? | `dev app describe` + `apps/<id>/app.def` |
| What apparent bug may be intentional? | `docs/AGENT_TRAPS.md` |

Detailed contracts: `../NATIVE_COMMAND_INTERFACE.md`,
`../AGENT_ARCHITECTURE.md`, `../../engine/modules/framework/include/zclassic23/app.h`. Daily
operating loop: `.claude/skills/z23-dev/SKILL.md`.

## Target compact protocol — extend, do not fork

Prefer extending current leaves with common digests/cursors/field-selection/
correlation selectors; add a new leaf only when the existing owner cannot
express the operation honestly.

| Existing leaf | Target responsibility | Default target budget |
|---|---|---:|
| `dev.loop.ensure/status` | Workspace/session identity, source epoch, registry/index/context digests, latest receipt | 2 KiB |
| `code.room` | Definition, callers/callees, routes, commands, schemas, invariants, owners, tests, confidence gaps | 4 KiB |
| `dev.change.plan` | Complete ordered proof DAG, cost estimate, reusable receipts, coverage gaps | 2 KiB |
| `dev.loop.wait` | One green/red proof receipt for a newer immutable epoch | 1 KiB green / 2 KiB red |
| `dev.diagnose.show` | Sealed compiler failure by durable ID; normal metadata + typed retry, optional full capsule | 2 KiB normal / 6 KiB full |
| `ops.diagnose` | Causal capsule selected by request/trace/job/app/session/match/height ID | 4 KiB |
| `ops.timeline` | Typed transition deltas with resumable sequence cursor | 8 KiB page |
| `app.inspect` | Manifest, grants, generation, health, resource/session/match state and replay references | 4 KiB |

`dev.diagnose.show` today serves workspace-scoped SHA3-sealed deterministic
compiler-failure artifacts, and `dev.diagnose.latest` returns the compact
ID/summary; expanding durable receipts to every red proof phase, exact
group/seed replay, pagination, and the full proof-DAG store remains open.
The other rows are extension targets, not claims the fields already exist.

Every compact response must include, when applicable: stable schema+digest;
source epoch/artifact/generation identity/lane/freshness; a summary without
duplicated prose copies of structured fields; explicit completeness/
truncation + resumable cursor; stable failure/blocker code; artifact
references for full evidence; one executable primary next action plus at
most two alternatives.

## Dependency order

```text
A. Measure token economics
        |
B. Unify source epochs, proof DAGs, and receipts
        +-------------------+
        |                   |
C. Semantic context     D. Typed causal telemetry
        +-------------------+
                |
E. Manifest compiler + generic AppSim
                |
F. Sandboxed App worker and capability broker
                |
G. Deterministic Game SDK and reference Apps
                |
H. Signed source-first packaging and discovery
                |
I. Permanent quality and budget ratchets
```

No workstream may waive an earlier applicable gate.

## A. Measure LLM development economics

**Depends on:** Phase-0 containment only. **Produces:** a
`zcl.quality_evidence.v1` profile named `llm_dev_benchmark`, an immutable
baseline, and reviewed budgets.

- [ ] Define a representative task corpus (command discovery, resource/
  model/service/route creation, compiler + focused-test failure, reducer
  blocker diagnosis, long-job inspection, P2P topic evolution,
  deterministic game-rule change, App migration/rollback, runtime App
  failure replay); record per task command count, request/response bytes,
  artifact bytes, source bytes read, cache hits, time-to-first-correct-edit,
  save-to-verdict latency, proofs selected/executed, retries, correctness.
- [ ] Instrument canonical native dispatch (path, result, elapsed, bytes,
  view, budget, truncation, trace ID) and capture the current baseline
  without changing behavior; separate measured bytes from approximate
  tokenizer counts; set budgets for menus/rooms/plans/receipts/artifacts;
  add injected-failure tests proving budgets never hide required evidence;
  add a regression gate only after baseline and variance are known.

**Exit gate:** the same task corpus reruns against an exact source epoch,
and every token/latency reduction claim names immutable before/after
evidence without weakening the required proof set.

## B. Unify source epochs, proof planning, and receipts

**Depends on:** A. **Produces:** `zcl.dev_source_epoch.v1`,
`zcl.dev_plan.v2`, `zcl.dev_proof_receipt.v1`, one worktree-scoped
append-only receipt store.

- [ ] Replace ambient dirty-tree identity with an immutable intended source
  epoch (all modified/deleted/mode-changed/symlink/generated/non-ignored
  untracked inputs); scope watcher/locks/socket/receipts/generation IDs/
  artifacts/caches by workspace identity.
- [ ] One C-owned impact engine selects the complete proof DAG for native
  commands, watcher, CI, and code navigation; remove independent shell
  reinterpretation once parity is proven; exact test-group IDs only (reject
  substring selection); normalize compiler/linker/lint/test/sanitizer/
  simulation results into typed records; store passing raw logs out of
  band, return counts/digests/durations only.
- [ ] Assign every red receipt a durable `failure_id` in the result
  envelope's failure field.
  - [x] Bounded summary/normal/full `dev.diagnose.show <failure_id>` for
    sealed deterministic compiler failures with a typed retry.
  - [ ] Extend to all red phases, field selection/cursors, exact
    epoch/group/seed replay.
  - [x] `dev.diagnose.latest` returns the most recent compiler-failure
    ID/summary rather than recursively nesting the cycle.
- [ ] Bind reusable green receipts to source/toolchain/flags/test-binary/
  proof-set/seed-corpus/environment/artifact digests; a newer edit
  supersedes older work and publishes zero stale receipts.
  - [x] Prove concurrent worktrees cannot overwrite each other's latest
    compiler failure or sealed cycle verdict.
- [ ] Prove every unmapped code change fails closed as `coverage_gap`.

**Exit gate:** an exact source epoch produces one bounded green receipt or
one durable red failure ID, independently replayable, with 100% of changed
code under a complete proof set or explicit coverage gap.

## C. Build semantic, digest-addressed context

**Depends on:** B. **Produces:** one daemon-owned semantic index snapshot
and an expanded, budget-aware `code.room` response.

- [ ] One persistent process owns code-index rebuilds; concurrent readers
  use the last complete immutable snapshot (lock/single-flight rebuilds;
  prove parallel reads cannot see zero-file snapshots, SQLite I/O errors,
  or temp-rename races); use content digests for freshness, not only
  path/mtime/size.
- [ ] Index `.c`/`.h`/`.def`, App manifests, migrations, SQL schema
  ownership, Make/build rules, route tables, command declarations, wire
  schemas, selected doc metadata; add relationships (command→handler→owner→
  tests; route→controller→service→model→table/index; dumper→producer→owner→
  drilldown; event→emitters→consumers→telemetry; manifest→capability→
  route/topic/resource/scenario; file/symbol→callers/callees/includes/
  proofs); preserve handler symbol names in generated registries; return
  relationship confidence and explicit coverage gaps.
- [ ] Add digest-aware delta responses; paginate large groups instead of
  `RESPONSE_BUDGET_EXCEEDED`; remove duplicate prose in compact JSON where
  structured data already carries it; link tested invariants/traps to their
  enforcing gates rather than preloading whole manuals.
- [ ] Measure peer-context reuse separately from model-token use: record
  context-root cache hits, manifest/chunk bytes transferred, model input bytes,
  approximate tokenizer counts, corpus walks, source files/bytes read,
  unchanged-source reads, query latency, and duplicate actions avoided. A CAS
  hit or a smaller network transfer is not by itself a model-token reduction.
- [ ] Preserve `agent_context.v1` as a compatibility reader and transport its
  canonical wire root-first through the existing inert `content.v2` carrier,
  package store, provider/pointer records, and swarm. The receiver re-roots the
  wire and checks expected task/source/goal roots; remote bytes grant no source,
  build, execution, proof, acceptance, or publication authority. Do not fork a
  context CAS, DHT, wire transport, task board, or scheduler.
- [ ] Add a generation-bound navigator/context envelope over the existing
  `code.capsule` and ZCode context owners. Bind repository/configuration,
  requested and indexed generation, normalized query, dimension mask,
  portable source/blob roots, canonical ranges, cursor, limits, freshness,
  completeness per lexical/call/include/build/impact-policy dimension, work
  counters, capsule/query-receipt roots, and one safe next action. Absolute
  paths never enter the portable identity.
- [ ] Verify every remote source excerpt against the locally held full blob or
  a locally verified range proof before proof/edit use. Ordinary navigation may
  show a stale cached range only when labeled with requested/indexed generation
  and lag. Proof, edit, and impact require the exact requested generation or
  refuse `INDEX_LAG`; incomplete dimensions conservatively widen the proof set
  or refuse when sound widening cannot be derived.
- [ ] Rendezvous by exact roots before a model call: resolve locally admissible
  accepted work for the task, attach to an identical active action, then look
  for a completed action whose task/candidate/input/context/policy/toolchain/
  work-kind/target/limits all match and whose output bytes are locally present
  and reverified. Remote-only receipts remain `UNVERIFIED` and cannot satisfy
  local acceptance.
- [ ] Add remote agent work only in this order: read-only `DIAGNOSE`, scoped
  candidate-zero `PROPOSE`, independent `REVIEW`. Carry typed inputs/findings as
  ordinary rooted CAS objects through the existing ZCode work swarm; never send
  accumulated free-form transcripts. Missing model policy, exact source,
  complete context, requested adapter, node headroom, or qualified disposable
  isolation refuses by a stable name. The node may preempt or refuse all such
  work for blockchain priority.

Peer-context acceptance:

- [ ] Same generation/config/query in two absolute worktree paths produces the
  same capsule/context root; changed generation or query changes it, and a
  cross-generation cursor refuses.
- [ ] A warm exact lookup performs zero corpus-wide walks, zero unchanged-source
  reads, and zero source-byte reads; a second peer/cache hit transfers no
  duplicate chunks. Establish the first-transfer baseline before ratcheting a
  percentage reduction.
- [ ] Every cap, missing shard, poisoned chunk, partial write, stale generation,
  or omitted dimension remains named; cursor exhaustion agrees with an oracle
  without gaps or duplicates; the last complete generation remains readable.
- [ ] The representative corpus still reaches first correct edit without a
  whole-file read on at least 90% of tasks, and no context optimization narrows
  the required proof union.

**Exit gate:** ≥90% of corpus tasks reach the first correct edit without a
whole-file read, and the room reports any missing relationship instead of
inventing confidence.

## D. Build typed, causal, privacy-safe telemetry

**Depends on:** B (may parallel C). **Produces:** a non-consensus telemetry
ledger, generated event descriptors, correlated runtime/dev evidence,
compact diagnostic projections.

- [ ] Three storage tiers: bounded no-allocation per-thread flight recorder;
  durable bounded transition/failure/job ledger; content-addressed full
  logs/traces/dumps/replay artifacts. Generate typed event IDs, payload
  structs, JSON schemas, severity, ownership, privacy, units, cardinality
  from one descriptor source (free-form `event_emitf` stays only as
  measured compatibility debt).
- [ ] Carry correlation fields (boot, workspace/lane, source epoch,
  generation, request/trace/span, job, app/app-generation, session/match,
  subsystem/operation, height, stable code, sequence/time) through native
  dispatch, HTTP, P2P framing, reducer/job boundaries, model transactions,
  capability IPC, and App callbacks; automatically measure every App
  boundary even with no custom telemetry; register every long operation as
  a job with heartbeat/progress/target/rate/ETA/warnings/artifacts; make
  the protected mint producer representable by one job-status response
  without `ps`/systemd/journal correlation; metrics queryable by
  select/top/diff + generation; `since`/`diff` state queries emit only
  transitions; classify problem events by stable typed codes.
- [ ] Enforce privacy at schema-registration and render time: classify
  every field `public`/`operator`/`private`/`forbidden-secret`, redact or
  reject before insertion anywhere; treat IPs/onions/paths/principals/
  wallet-attributed txids as private by default; prevent untrusted Apps
  from choosing metric names/labels/paths/log formats; seed unique secret
  canaries and scan every telemetry tier as a promotion test.
- [ ] Mark truncation/drop/overwrite/retention gaps explicitly with cursors
  and counters; bounded retention/GC (mutable `latest` is never
  authoritative evidence); backpressure drops evidence with an explicit gap
  instead of blocking reducer/consensus progress; capture the bounded
  pre-failure flight recorder into crash/failure capsules; benchmark
  overhead before setting a hard CPU/memory SLO, then gate on regression;
  fault-inject ENOSPC/slow-drain/corrupt-tail/ring-overrun/crash-reopen and
  prove consensus progress stays independent.

**Exit gate:** one `ops.diagnose` query by request/job/App/session/match/
height ID returns a deterministic causal chain from observed state to the
last transition, blocker/invariant, owning symbol, proof receipt, artifact,
and executable next action, with no secret or silent gap.

## E. Compile the complete App surface from one manifest

**Depends on:** B, C, D. **Produces:** strict manifest compiler, immutable
App catalog, host-owned App storage, generic AppSim. Runtime publication
remains contained.

- [ ] Replace the ad hoc Social-only parser/discovery with a strict
  deterministic manifest compiler (reject unknown/duplicate directives);
  package discovery stays bounded/declarative, never executing the C
  preprocessor/constructors/compiler/App code.
- [ ] Extend the manifest to declare identity/version/license/publisher/
  ABI range/digest; execution trust class, requested capabilities, local
  grants, quotas; resources/fields/relationships/indexes/validations/
  migrations; commands/effects/risk/authority/idempotency/schemas/budgets;
  REST/onion/websocket routes with auth/privacy/freshness/limits; P2P
  topics with signing/encryption/replay/reliability/rate/size policy; typed
  events/projections/jobs/assets/ZNAM bindings; required simulations,
  properties, fuzz targets, seed domains.
- [ ] Generate ordinary inspectable C for SDK types, validators, AR
  descriptors, migrations, command specs, routes/OpenAPI, topic tables,
  telemetry, tests, impact mappings, docs, `code.room` edges; `dev app
  scaffold` generates one conventional compilable slice (model+AR
  callbacks/validators/relationships, migration/indexes, service, thin REST
  controller, pure view, HTTPS/onion mount, manifest entries, focused
  tests, simulation seed, impact mapping, guide) deterministically and
  transactionally (preview, reject dirty targets, temp tree, compile/test,
  atomic install or no partial files).
- [ ] One transport-neutral route function bound to both HTTPS and onion
  with identical auth/limits/cache/failure behavior; a dynamic immutable
  App-catalog snapshot beside the immutable Core catalog (no hand-maintained
  parallel lists); separate requested vs operator-granted capabilities;
  evolve the ABI through size/version-tagged numeric operation IDs with
  generated typed wrappers (avoid open-ended string ops on hot/authority
  paths); separate portable package identity from exact host generation/
  build/proof identity.
- [ ] Host-owned transactional App storage without exposing SQL
  (begin/commit/abort, snapshots, read/write/delete, bounded scan,
  CAS/version, quotas, event append, projection cursor, outbox/inbox, job,
  asset handles); replicated App state event-derived and projections
  rebuildable, separate from local preferences/secrets/ephemeral session
  state; served height/hash/freshness/finality/reorg cursor in every
  chain-read capability result.
- [ ] Generic AppSim invoking the exact production ABI/dispatch path with
  virtual clock, seeded randomness, isolated storage, queued topics;
  covers partition/delay/loss/duplicate/reorder/crash-restart/late-join/
  migration/capability-denial/quota-exhaustion/malformed-input/reorg;
  returns transcript/state fingerprints, generation/manifest digests, seed,
  bounded last events/packets, exact replay command. Generate Social from
  its manifest; materialize Tic-Tac-Toe as the first Game App on the same
  compiler+AppSim host; keep scaffold/inspect/publish `planned` until real
  handlers/proofs exist.

**Exit gate:** a new resource and a new deterministic game rule can be
declared, generated, compiled, inspected, and simulated from one manifest
with no manual catalog edits and no runtime loading.

## F. Run third-party C23 Apps outside the node

**Depends on:** E and the Phase-3 immutable publication transaction.
**Produces:** native static-PIE App worker, minimal capability broker,
immutable generations, blue/green cutover, exact rollback.

- [ ] Two execution classes: audited built-ins (statically linked,
  reviewed) vs third-party/fetched Apps (never mapped or executed by the
  node process). Open and SHA3-verify the exact CAS App executable, then
  one descriptor-pinned `execveat` into a fresh address space after
  bootstrap confinement — never map fetched App code into Core.
- [ ] Enter rootless namespaces; apply Landlock, seccomp, `no_new_privs`,
  W^X, rlimits/cgroups, bounded restart budgets, closed inherited FDs
  before loading App code; give the worker no node database, wallet/key
  file, arbitrary filesystem, peer socket, network namespace, service
  manager, or process-control access; framed bounded binary capability IPC
  (shared-memory rings/eventfd only for profiled high-rate paths, with
  explicit backpressure); enforce manifest grants/principals/deadlines/
  cancellation/idempotency/quotas/audit at the parent broker.
- [ ] Inspect App artifacts before execution (constructors/imports,
  undefined symbols, deps, W^X, ABI/SDK identity, manifest/content digest,
  tests, proof receipts); load a candidate worker → self-test → shadow
  migrate/replay → behavioral probe → quiesce → atomic route switch →
  drain old leases → durably accept or restore exact last-good; prove
  worker crash/timeout/quota-breach/malformed-reply/migration-failure/
  kill-during-boundary cannot crash or mutate the parent; malicious
  fixtures attempting key/file reads, socket creation, process escape,
  consensus mutation, syscall escalation, resource exhaustion; keep
  canonical/soak/release dynamic loading at zero.

**Exit gate:** two nodes run the same sandboxed App, converge after
partition, survive worker crash/upgrade/rollback, reject invalid authority,
and leave H*, consensus storage, canonical datadir, and wallet keys
unchanged.

## G. Make games deterministic Apps

**Depends on:** E; live multiplayer additionally depends on F. **Produces:**
Game SDK, generic App-topic envelope, durable sessions, replay, reference
games.

- [ ] Replace the fixed `uint8_t` Ping/Tic-Tac-Toe registry as the extension
  boundary (retain compatibility adapters while peers migrate); a generic
  App-topic envelope (app/protocol/topic/wire version, session,
  sender/principal, sequence/ack, logical tick, payload length/hash,
  signature, replay window, reliability/encryption policy, budgets)
  negotiated/dispatched in the host — Apps never receive peer sockets.
- [ ] Deterministic game contract (`init`, `validate_input`, `reduce`,
  `hash`, `serialize`, `deserialize`, viewer-scoped `render_view`): fixed-
  width integers, canonical endianness/encoding, explicit bounds, no
  serialized padding; ban host randomness/wall-clock/locale/pointer-
  identity/filesystem/networking/UB/float from reducers — inject logical
  time and seeded randomness as facts.
- [ ] Sessions, participants, identities, matchmaking, spectators,
  reconnect/resync, snapshots, state-hash chains, durable signed input
  logs; every match reproducible from App generation, manifest/rules
  digest, seed, signed ordered input log; simulate latency/loss/
  duplication/reorder/partition/malicious-input/censorship/late-join/
  crash/migration/divergent-state-hash; optional settlement through wallet
  plan/commit/idempotent intents and chain-confirmation events (Apps never
  receive keys). Port Tic-Tac-Toe as the golden reference and prove parity
  with the compatibility wire/API; add a second reference game before
  freezing the SDK; keep the deterministic core portable enough for a
  future browser WASM client without adding a WASM runtime absent a
  measured need.

**Exit gate:** two nodes complete a full match through partition/reconnect,
produce the same final state/transcript hash from replay, reject forged or
replayed inputs, and recover from worker upgrade/rollback without changing
consensus state.

## H. Package, discover, build, upgrade, and roll back Apps

**Depends on:** F and G for executable games. **Produces:**
`zcl.artifact_manifest.v1`, `.zclpkg`, `zcl.package_manifest.v1`, package
commands, reproducible source-first distribution.

- [ ] **P2P source/content plane (`content.v2`):** reuse the proven chunk
  I/O/SHA3/backpressure/resume mechanics from `file_service.c` without its
  state-specific manifest, snapshot-trust claims, or payment gate; store
  source as canonical 1 MiB SHA3-256 chunks addressed only by hash, a
  bounded Merkle manifest mapping normalized path+mode+size to an ordered
  chunk list (peers never submit host filesystem paths); bind source-root,
  package manifest, tests/scenarios, dependencies, license/SBOM, build
  recipe, requested capabilities, publisher key, ZNAM name, and proof
  receipt digest into one signed package identity; bounded `inventory`/
  `want`/`chunk`/`cancel`/proof-of-possession messages with version,
  request ID, offsets, length/hash, deadlines, quotas, replay protection,
  Noise/Tor privacy; concurrent multi-peer fetch, verify before CAS commit,
  resume by bitmap, penalize corrupt/slow sources (partial downloads never
  discoverable); same read-only manifest/chunk resource over P2P/HTTPS/
  onion (open-source packages free; premium settlement is a policy layer,
  never a read-integrity gate); typed leaves `app package
  build/sign/publish/verify`, `app content offer/find/fetch/status/
  pin/unpin` — nothing is built/installed/executed merely because it was
  advertised or downloaded; keep publisher signature, local reproducible-
  build receipt, sandbox/ELF inspection, operator grant, and optional chain
  anchor as separate facts in the UI/API.
- [ ] Prove: normalized-tree determinism; traversal/symlink/duplicate
  rejection; corrupt chunk/manifest/signature rejection; partition/resume;
  opposite peer order; alternate-relay censorship bypass; quota/ENOSPC
  cleanup; two-builder byte identity; no wallet/canonical-datadir/consensus
  mutation.
- [ ] Package manifest carries source, generated-code recipe, assets,
  tests, simulations, license, content-only dependency lock, SPDX/CycloneDX
  SBOM, publisher identity/signature, proof receipts, using canonical
  normalized paths/modes/sizes/versioned-SHA3-identity/ABI-range/
  capabilities-quotas/rollback-floor/reproducible-recipe; reject traversal,
  symlink escape, duplicate path, oversized member, unpinned network
  dependency, publisher substitution, downgrade, signature failure,
  license omission, capability escalation; build offline in a compiler
  sandbox from two clean roots and require byte-identical output before
  stable publication (required before first execution in v1); generate
  `dev app.*`/`app package.*`/`app content.*` from one registry; advertise
  package identity through ZNAM without implying trust or auto-install;
  keep open-source bytes fetchable free; require explicit approval on
  publisher/protocol/grant/rollback-floor change; prove
  author→sign→publish→discover→two-node-fetch→offline-rebuild→sandbox-
  activate→use→upgrade→rollback end to end without mutating canonical
  chain state, wallet keys, or the serving datadir outside host-owned App
  stores.

**Exit gate:** the full Phase-5 promotion scenario in the sovereign roadmap
passes with independent build/signature evidence and exact rollback.

## I. Permanent quality, performance, and token ratchets

**Depends on:** all applicable earlier workstreams.

- [ ] CI size gates for root/branch/spec/status/context/receipt/error/list
  responses (fail when compact mode duplicates fields as prose); usable
  input field schemas (types, required/optional, enum, bounds, defaults,
  units, relationships, privacy, examples); every command/route/event/
  state-field/capability/job/App-resource has an owner, schema, privacy
  class, cost, test, drilldown; every code change maps to a complete proof
  DAG or fails as `coverage_gap`.
- [ ] ≥95% of injected failures produce an exact phase, source/test/
  assertion or runtime owner, durable failure ID, artifact, deterministic
  replay; ≥90% of corpus tasks reach first edit without whole-file reads;
  warm edit-to-green model-visible output ≤1 KiB / one post-save call; red
  failure-to-action ≤2 KiB / at most two calls; task-specific onboarding
  ≤4 KiB with delta-only unchanged digests.
- [ ] Preserve the sovereign roadmap Phase-3 latency targets measured on
  the reference machine (never inferred from verify-only runs); telemetry
  CPU/memory/allocation/lock/SQLite/I/O/storage budgets only after a real
  baseline, then regression-gated; no allocation on the hot event-emission
  path, bounded telemetry cardinality/retention; identical App generation+
  seed+inputs produce identical transcript/state hashes across builders/
  platforms; the malicious App campaign and ≥10,000 deterministic network
  seeds required before stable runtime/package promotion; two-builder
  identity, offline verify/install/upgrade/rollback, fuzz/sanitizer/
  coverage, independent review before stable publication; delete
  compatibility paths only after their replacement and rollback are proven
  (mutable `latest` is never authoritative evidence).
- [ ] Peer-collaboration receipts permanently report task/source/context/query/
  action roots, requested/indexed generation, completeness, CAS hit/miss and
  transferred bytes, source reads/walks, model input bytes, approximate token
  count, duplicate execution avoided, node-priority outcome, and whether the
  evidence is local, reproduced, or remote-observed only. Identical active
  actions execute once; changed context/toolchain/limit never reuses them.

## Recommended first implementation slice

Improves current cure and App development without loading Apps, changing
consensus, restarting a node, or touching the protected producer.

- [ ] Capture the LLM task-corpus baseline (`zcl.quality_evidence.v1`).
- [ ] Instrument canonical native dispatch with response bytes, budget,
  truncation, latency, result code, request ID, trace ID.
- [x] Shared worktree-scoped sealed cycle state + append-only deterministic
  compiler-failure store for watcher and native readers.
- [ ] Extend that store into one authoritative history for every proof
  receipt and remaining compatibility reader.
- [x] Durable deterministic compiler `failure_id` values + bounded
  `dev.diagnose.show`/non-recursive `latest` responses.
- [ ] Extend durable IDs and diagnosis to every red proof phase; apply
  summary/normal/full projection universally so a small budget reduces
  data instead of an avoidable overflow error.
- [ ] Make code-index rebuild single-flight/concurrent-reader-safe with
  explicit pagination; index command/App `.def` files preserving handler
  symbol names; one C proof-DAG engine accumulating every required group,
  proven at parity against the existing runners.
- [ ] Build a read-only typed job projection over the protected producer's
  existing evidence without changing its process/binary/command-line/
  files/lifecycle; use the same job contract for new long operations.
- [ ] Re-run the task corpus and publish exact before/after receipts. Stop
  there for independent review — do not add an App loader or runtime
  publication authority in this slice.

## Promotion summary

| Promotion | Required checklist state |
|---|---|
| Low-token verify loop | A–C complete; B receipt gate green |
| Correlated node/App diagnosis | D complete with privacy and gap proofs |
| Offline App development platform | E complete; runtime still contained |
| Public third-party App runtime | Phase 3 transaction + F complete |
| Public deterministic game platform | F + G complete |
| Sovereign package/content network | H complete plus Phase-2 release evidence |
| Permanent stable platform | I complete and applicable Phase-6 deletion gates green |

The governing rule is unchanged: reduce tokens through deterministic
routing, server-side projection, content-addressed reuse, typed causal
evidence, and generated structure — never by hiding uncertainty or
weakening proof.
