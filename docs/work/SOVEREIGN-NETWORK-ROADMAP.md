# Sovereign Network and C23 Platform — foundation roadmap

This scoped foundation record preserves the Phase 0–6 product hierarchy and
promotion gates. It does not choose current work. [`FORWARD_PLAN.md`](./FORWARD_PLAN.md)
is the sole execution queue; [`../HANDOFF.md`](../HANDOFF.md) is consulted only
for an explicit maintainer-host operation.

The preserved hierarchy is:

1. **Always-stable, fast, consensus-compatible synchronization.**
2. **The best transactional C23 hot-swap development platform.**
3. **A sandboxed sovereign App/content publishing network.**

Later work may proceed in isolated lanes, but it never delays the sync cure and
never earns stable publication before all earlier applicable gates pass.

`v1`/`v2` suffixes below are compatibility tags for durable schemas, ABIs, or
wire contracts—not parallel products, forks, trust levels, or milestones. Each
interface has exactly one current canonical version. An older version is either
read-only compatibility or deleted after cutover; a suffix increments only for
an incompatible encoding change.

## Invariant hierarchy

The first failing invariant stops promotion; a lower layer cannot waive a
higher one.

1. **Consensus parity:** ZClassic remains immutable. No application or local
   optimization changes block/transaction validity, Equihash, or activation
   rules first.
2. **State truth:** never publish an unproven chain value or accept a shielded
   spend across incomplete anchor/nullifier history. A matching ZClassic header
   proves an anchor's chain location, not UTXO or shielded-state contents.
3. **Atomic recovery:** complete transparent, Sapling, Sprout, nullifier,
   cursor, log, and provenance state promotes together or not at all.
4. **Witnessed liveness:** startup, retry, `SKIP`, escalation, and process
   uptime are not progress. Recovery must witness H\* movement or name one
   actionable blocker.
5. **Immutable evidence:** every quality, runtime, package, and release claim
   binds the complete source epoch, artifact, lane, proof results, and rollback.
6. **Execution isolation:** third-party Apps never enter the node process;
   native loading remains a tightly restricted operator-dev capability.
7. **Owner authority:** canonical deployment, stable publication, capability
   increases, and irreversible migrations stay explicitly owner-gated.

## Current baseline

Live state: `docs/HANDOFF.md`.

## Phase 0 — containment and truthful control planes

Goal: stop false publication and make the causal security blocker impossible to
hide.

- Keep source watching verify-only; every runtime application entrypoint is
  hard-contained until the Phase 3 transaction is complete. Candidate code is
  not probed with resident `dlopen`; use a disposable process until pre-load
  ELF/sidecar/import policy and immutable artifact receipts exist.
- Fail stable node/starter-pack publication closed while canonical sync,
  evidence, fuzz, coverage, reproducibility, or signatures are red/stale.
- Use one ID-aware causal blocker order across agent, native, and operator
  status. Shielded anchor/nullifier gaps outrank downstream script/peer
  symptoms; resource exhaustion may remain above them when it prevents repair.
- Reject/hold Sapling spends and Sprout JoinSplits while their required history
  is incomplete, before any coin mutation; keep provably safe transparent-only
  processing available.
- Refuse snapshot export/re-serving unless transparent state is self-derived at
  H\* and Sprout, Sapling, and nullifier history all have explicit complete
  provenance. Phase 0 additionally contains serving unconditionally: the legacy
  payload codecs read `node.db.utxos`, while H\* authority is `coins_kv`. Serving
  stays closed until export streams from `coins_kv` and binds its exact
  root/count/supply and active-chain H\* hash.
- Refuse runtime peer-snapshot promotion before any canonical mutation; a
  verified staging set is not success and cannot enter `SNAPSYNC_COMPLETE`.
- Model blocker dependencies and park retries until the dependency generation
  changes. Distinguish lag at different heights from an exact same-height hash
  disagreement.
- Keep standing docs and command output aligned with live truth.
- Trust-capability centralization exists: `app/services/include/services/sync_trust_policy.h`
  derives one `sync_trust_state` from the same provenance bits every gate
  above already reads (self-derived, proven authority, refold marker) and
  maps it to a capability mask; export, offer-advertisement, and guard call
  sites route the provenance-bit portion of their decision through this one
  table instead of re-reading the raw bits separately, while every other
  local AND (cursors, payload authority, `SNAPSYNC_ACTIVATION_CONTAINED`)
  stays exactly where it was.

Promotion gate: there is no autonomous runtime publication; an explicit apply
refuses omitted dirty or sealed paths; no shielded transaction can cross an
incomplete-history boundary; stable publish commands refuse; every operator
status surface selects the causal blocker. Source-root CAS and zero superseded
publications remain a Phase 3 gate. The full dependency/retry engine remains
explicitly open until its generation-driven tests pass.

## Phase 1 — sovereign, fast, total synchronization

Goal: cure canonical first, then make fast readiness and eventual sovereignty
honest, repeatable states.

### Immediate cure — LANDED

Shipped as the checkpoint-content consensus-bundle install path — see
`docs/work/sovereign-cutover-runbook.md` for the mechanism and acceptance
gate.

### Permanent architecture

- Expose `sovereign`, `release_assisted`, and `peer_assisted` trust states plus
  separate `T_ready` and `T_sovereign`. Peer state is never called PoW-bound.
- In assisted modes, default mining, snapshot re-serving, and wallet spending
  off until background full-history verification promotes a separate namespace.
- Freeze USS v1–v3 as legacy read-only import formats. The sole new writable
  format is `zcl.consensus_state_bundle.v1`, with independent transparent,
  Sapling-history, Sprout-history, nullifier, and payload commitments plus
  signed provenance. Do not append a USS v4 or create another active variant.
- Complete every recovery rung, rolling full-state recovery seals, exact
  zclassicd exporters/comparisons, event-driven peer fetching, and profiled
  ordered-commit performance work.
- Start soak only from a clean immutable candidate. Healthy means gap ≤1 under
  `normal_lookahead`, exact same-height hash, continuous reducer evidence,
  `coins_applied=H*+1`, and no security gap or manual intervention.

Phase gate: canonical is sovereign and continuously healthy; parity has zero
same-height/full-state mismatches; MVP is 8/8; a fresh clean 168-hour soak passes.
Operational targets: stall detection ≤15 s, local recovery ≤120 s, deep-anchor
recovery ≤10 min, warm restart p95 ≤10 s, kill-9 p95 ≤60 s (120 s hard), fold
≥250 blocks/s p95, refold extra memory ≤2 GiB, steady node memory ≤4 GiB.

## Phase 2 — commit-bound quality, integration, and releases

Goal: make every green result and released byte independently attributable.

- Add `zcl.quality_evidence.v1`: full commit/tree SHA3, dependencies/toolchain,
  gate/command/profile/lane, timestamps, `PASS|FAIL|SKIP`, logs/artifacts/hashes,
  counts/seeds, sanitizer/coverage/benchmark data, and runner identity.
- Run from immutable epochs in isolated roots. Required `SKIP`, retries, missing
  inspection tools, or mixed-tree evidence block promotion.
- Restore every registered test group, all fuzz targets under ASan/UBSan,
  coverage baselines, TSan, GCC/Clang, LTO/non-LTO, static/leak, and candidate
  benchmarks. Every production bug becomes a deterministic artifact.
- Protect main with exact-commit statuses, independent review, CODEOWNERS,
  isolated untrusted workers, base-revision scanners, and fully pinned actions.
- Separate native release build/package/sign/verify/publish operations and node,
  starter-pack, C23 package, and nightly channels.
- Stable outputs include offline inputs/provenance, license bundle, SPDX and
  CycloneDX SBOMs, hardening inspection, two-builder byte identity, and 2-of-3
  offline signatures. `--unsigned` is local-development only.

Phase gate: the exact protected candidate runs every required test without
retry/skip/sanitizer/fuzz failure; critical code reaches ≥90% line/≥80% branch
coverage; two independent builders produce identical binary/archive; offline
verify/install/upgrade/database-compatible rollback succeeds.

## Phase 3 — one native C23 development transaction

Goal: an edit is either a complete proven generation or it never becomes live.

- Add `zcl.dev_source_epoch.v1`, `zcl.dev_plan.v2`, and
  `zcl.dev_proof_receipt.v1`; derive complete changed/dependency sets from source
  roots, never caller path lists.
- Isolate watcher/ZVCS/generation/socket/datadir/ports/lease per workspace. Only
  integration may promote publishable generations.
- Snapshot source first; plan, build, test, and probe only that immutable epoch.
- Enforce signed single-use unseal capabilities for exact epoch/paths/lane;
  consensus paths always require replay/parity/copy proof and binary activation.
- Use one protocol: resolve → plan → seal → prove → build → candidate probe →
  epoch CAS → persist prepared provenance → quiesce → atomic publish → public
  postprobe/liveness → durable accept or exact rollback.
- Finish authenticated per-workspace Unix control sockets, typed dotted probes,
  candidate fixture invocation, generation attribution/retention/GC, bounded
  reload, and restricted-ELF ABI admission. Prove mutation, auth, audit,
  events, secrets, and edit/apply/rollback behavior through native commands.

Phase gate: 100% accepted publications bind source/artifact/proofs; stale or
superseded publications are zero; a real edit → build → native probe → apply →
changed behavior → rollback passes. Targets: classification p95 ≤250 ms,
planner p95 ≤10 ms, warm stateless verified commit p95 ≤1 s, cold p95 ≤2 s,
rollback p95 ≤100 ms, hot dispatch overhead <1%, dynamic loading on
canonical/soak/release zero.

## Phase 4 — public C23 App runtime

Goal: useful third-party C23 Apps without giving them node authority.

- Freeze ABI v1; add size/version-tagged ABI v2 invocation context, bounded
  capabilities/deadlines/cancellation/principal/idempotency, routes/topics/jobs,
  lifecycle/health, shadow migrations, leases, rollback floor, and signed event
  authority.
- Keep operator dev hot swap on an isolated lane. Run every fetched/published
  third-party App as its own verified static PIE artifact through a minimal
  broker: private-CAS descriptor pinning, one `execveat`, rootless namespaces,
  Landlock, seccomp, W^X, rlimits, inherited capability IPC only, blue/green
  replacement, and bounded restart budgets. Never self-exec Core as an App
  worker or map fetched App code into the node process.
- Bind authenticated roles to local capability grants. Integrate Noise/AEAD
  below message parsing without breaking byte-identical zclassicd v1 peers.
- Build Social and Games reference Apps proving signed replay/convergence,
  crash/upgrade isolation, durable sessions, package/protocol pinning, and full
  gameplay flow.

Phase gate: two nodes install the same App, converge after partition, survive
worker crash/upgrade/rollback, reject invalid authority, and leave consensus
state, wallet keys, and H\* unchanged.

## Phase 5 — sovereign publishing network

Goal: one signed content-addressed model for releases, starter packs, Apps,
games, sites, and large assets.

- Define canonical binary `zcl.artifact_manifest.v1` with JSON projection,
  bounded normalized paths, file hashes/modes, source/ABI/capabilities/recipe,
  proofs, dependencies, licenses, and signatures.
- Define `.zclpkg`/`zcl.package_manifest.v1`: mandatory source/tests/scenarios,
  public SDK ABI range, permissive SPDX default, dedicated recoverable
  domain-separated publisher keys, content-hash-only dependencies, and ZNAM
  package-root binding.
- Add typed `dev app.*`, `app package.*`, and `app content.*` commands.
- Add `content.v2` with 1 MiB SHA3 chunks, bounded Merkle manifests, resumable
  multi-source fetch, proof-of-possession, and Tor/Noise transport. Open source
  remains fetchable without payment; premium settlement is optional policy.
- Build offline in a compiler sandbox, twice from different roots, byte-compare,
  run tests/scenarios/ELF/sandbox checks, and require local build for v1 execute.
- Updates cannot silently change publisher, protocol, capabilities, or rollback
  floor; capability increases require explicit local approval.

Phase gate: author → sign → publish → ZNAM discover → two-node fetch → offline
reproducible build → sandbox activate/use → upgrade → rollback passes without
changing canonical datadir, wallet keys, or H\*.

## Phase 6 — permanent quality and maintenance ratchet

Goal: delete transitional machinery only after its replacement is proven and
make quality monotonic.

- Delete borrowed recovery after sovereign cutover and duplicated
  OS/write/repair paths after their owners are complete. Keep one
  boot lifecycle and shrink it.
- Ratchet lint exceptions, oversized/orphan files, raw booleans, coverage,
  binary/BSS size, startup/RSS, generation storage, and discovery size.
- Require independent review plus owner authorization for consensus, loaders,
  activation, migration, sandbox, signing, and releases.
- Preserve immutable nightly/release evidence; mutable `latest` is never
  authoritative.
- Operate: inspect health/evidence → select highest red invariant → claim an
  isolated epoch → prove deterministically → independent review → protected land
  → dev/soak/canonical promotion → GC only merged unreferenced artifacts.

Phase gate: every deleted path has a proven replacement and rollback; budgets
never regress without an explicit reviewed waiver; stable evidence remains
reproducible and attributable indefinitely.

## Non-negotiable adversarial campaigns

Before the applicable phase promotes, exercise truncation/wrong roots/counts/
height; missing shielded sections and old-nullifier replay; ENOSPC and kill at
every install boundary; outage/partition/reorg/peer churn/corrupt bodies/resource
pressure; omitted dirty files/inotify overflow/epoch races; ELF constructor/TLS/
import escalation and postprobe rollback; App sandbox/capability/deadline/migrate
failures; package traversal/signature/license/publisher/downgrade/revocation;
two-builder/offline verification; at least one-hour fuzz per stable candidate
(six hours for changed parsers); at least 10,000 deterministic network seeds;
and install/upgrade/restart/last-good rollback on every declared release profile.
