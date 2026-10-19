# ADR-0004: Capability service fabric and cartridge-style App checkpoints

- **Status:** Accepted 2026-07-15.
- **Deciders:** Project maintainer.
- **Partially supersedes:**
  [`ADR-0001`](./0001-personal-sovereignty-stack.md)'s literal
  dynamically-linked/single-executable deployment wording and its rejection of
  any multi-process shape, and
  [`ADR-0003`](./0003-os-substrate-verdict.md)'s one-process/no-helper
  conclusion. ADR-0001 remains authoritative for one operator-owned Core,
  onion, and stack. ADR-0003 remains authoritative for using the host kernel
  as the scheduler, rejecting a nested operating system, avoiding a custom
  central scheduler, keeping Linux first, and treating FreeBSD as a later
  native host.
- **Related:** [`ADR-0002`](./0002-sealed-consensus-core.md),
  [`HANDOFF.md`](../agent/HANDOFF.md),
  [`self-verified-tip-plan.md`](../work/self-verified-tip-plan.md), and
  [`LLM-C23-APP-PLATFORM-CHECKLIST.md`](../work/LLM-C23-APP-PLATFORM-CHECKLIST.md).

---

## Context

The one-binary promise has two meanings that must not be confused:

1. z23 Core is one immutable, independently identifiable executable.
2. The running personal-sovereignty stack may use host-kernel process
   isolation to keep public networking, keys, Apps, and compilers from sharing
   ambient authority.

A FreeBSD guest would require a hypervisor and another OS image. A jail needs a
FreeBSD host kernel. Neither belongs inside Core. Conversely, loading
third-party native code as a `.so` inside the consensus process gives that code
Core's keys, mappings, descriptors, and crash fate. That is not a capability
boundary.

The useful mental model is a console machine. Core is immutable firmware. An
App package is a signed cartridge. “Generation” is split deliberately: an
artifact root identifies executable bytes, an activation generation binds the
artifact/package/grant/routes, a state generation identifies one database
lineage, and a checkpoint root identifies an immutable manifest plus its
referenced state content. The image and logical roots identify the physical
SQLite image and canonical logical state separately. The
operator should be able to load an activation, cheaply fork its state for a
test, checkpoint it, restore it, or roll it back without minting new authority,
making consensus state part of the cartridge, or accepting a raw process-memory
image.

This model is especially important for LLM development. An agent should work
from small, content-addressed contexts; create cheap state forks; run a bounded
scenario; inspect a causal failure capsule; and either promote the exact tested
artifact/build/proof roots into a separately approved production activation or
discard them. Scenario state is never promoted. It should not reconstruct
context from an unbounded log or mutate the operator's only copy of App state.

## Decision

### 1. Host kernel and process topology

Linux is the first host. The host kernel remains the CPU scheduler, memory
manager, namespace provider, and final security boundary. A later FreeBSD
profile maps the same contracts to `jail`, Capsicum, `rctl`, `kqueue`, and
`rc.d`; it is not a guest image.

The target supervised tree is:

```text
systemd / future rc.d
└── z23 --role=init
    ├── --role=core       consensus, reducers, chain P2P, progress.kv
    ├── --role=edge       HTTPS, onion, App relay, package swarm
    ├── --role=wallet     keys, signing, proving; no public sockets
    ├── --role=appd       grants, routes, jobs, App databases, CAS
    │   └── one native App process per active generation
    └── --role=buildd     ephemeral networkless compiler sandbox
```

The role split starts in shadow mode. Existing runtime ordering and restart
behavior do not change until observation proves parity. All eight consensus
reducers and chain P2P remain together in Core. The service fabric is never a
reason to change ZClassic consensus.

“One binary” means one immutable Core executable. Native App executables and
toolchains are inert, SHA3-addressed private-store generations. They become
executable only after package, license, build, grant, sandbox, self-test, and
activation gates all accept the same exact roots.

This explicitly replaces the earlier same-binary/self-exec worker target. A
fetched App is its own static PIE artifact opened from the private CAS and
entered with one descriptor-pinned `execveat`; it is never mapped into or
self-executed from Core. Core, the App SDK, libc, compiler runtime, official
Apps, and every executable dependency must remain within the approved
permissive-license closure.

### 2. Four authority planes

The implementation keeps four planes physically and semantically separate:

- **Consensus:** block bodies, `progress.kv`, reducer logs, coins, anchors, and
  nullifiers. Only Core writes it.
- **Platform control:** `platform/control.log` and rebuildable `platform.db`
  projections for services, jobs, grants, generations, and audit.
- **App state:** one host-owned SQLite database per App instance, including
  immutable AppEvents, resources, relationships, projections, outbox, and job
  cursors.
- **CAS/evidence:** inert source, packages, artifacts, traces, SBOMs, and proof
  receipts. Private checkpoint chunks use a non-swarm App-state namespace with
  separate retention and disclosure policy; SHA3 addressing never makes them
  public evidence.

A matching hash or height in one plane does not authorize another. In
particular, an App checkpoint cannot name, open, restore, or replace
`progress.kv`, `node.db`, a wallet database, or another App's database.
Wallet keys and proving secrets remain in a wallet-owned secret store outside
all App/checkpoint/CAS operations; the four-plane taxonomy is not permission to
fold secret state into platform control. App-local route/job roots are only
cursor witnesses. Packages and platform control remain the authority for route
ownership, schedules, grants, and activation.

### 3. Capability service fabric

`zcl.service_manifest.v1` declares numeric service identity, role, trust
class, dependencies, readiness witness, permitted IPC operations and inherited
descriptors, budgets, restart policy, state schema, generation, health
deadline, and durable progress marker.

Lifecycle is:

```text
DECLARED → STARTING → READY → DEGRADED/BLOCKED → STOPPING → EXITED
```

Only typed transient failures may restart, within an explicit intensity
budget. Provenance, parity, corruption, policy, and authority failures become
durable permanent blockers. Shadow mode reports desired policy separately from
the behavior of today's in-process service kernels and supervisor; it does not
silently impose new restarts.

Parent-created `SOCK_SEQPACKET|SOCK_CLOEXEC` channels carry
`zcl.ipc.frame.v1`. Numeric schema/service/operation IDs, peer credentials,
principal, generation, grant revision, deadline, trace, idempotency key, quota,
payload length, and SHA3 digest are checked before payload decoding. IPC never
carries pointers, SQL, paths, private keys, key selectors, caller-supplied
capability masks, or undeclared descriptors.

### 4. Native App process contract

Public Apps are C23 static PIE processes linked only to the permissive SDK and
musl profile. They are never third-party `.so` code inside Core. The public
contract is the pointer-free process protocol in `zcl.app.manifest.v2`, not the
legacy callback-pointer ABI.

Artifact, activation, state-generation, and checkpoint identities are never
aliases. Forking a state generation does not copy or refresh a capability
grant. Every launch and switch rechecks the exact activation generation and
current grant revision under a generation lease.

`appd` owns App SQLite handles and re-enforces structural validations. Apps
receive typed model/query/event/broker operations, never raw SQL, raw paths,
wallet handles, or network sockets. A route transaction and its outbox records
co-commit through one broker operation.

### 5. Checkpoints are logical state, not process dumps

The authoritative portable checkpoint is `zcl.app.checkpoint.v1`. It binds:

- App, instance, publisher, package, artifact, activation generation, distinct
  state generation, exact grant root/revision, App schema, SDK ABI, logical
  root codec, and migration lineage. The state-generation root is an opaque,
  stable lineage identity minted by platform control, not the checkpoint's
  content root.
- An exact SQLite image root and a separately computed canonical logical-state
  root.
- AppEvent, outbox, subscription, route, and job cursors plus their roots.
- Chunk size, ordered chunk manifest, total bytes, creation cause, causal
  checkpoint, private storage class, state origin, and outbox quarantine mode.

The control-journal `ACCEPTED` event is not inside checkpoint content. The
event names the completed checkpoint root; a separate
`zcl.app.checkpoint_acceptance.v1` receipt binds that root to the control
sequence, event ID, and segment root. A crash before `ACCEPTED` leaves
collectable staging garbage. Journal replay after `ACCEPTED` recovers the same
accepted root without a manifest/event hash cycle.

An `INITIAL` checkpoint additionally requires a platform-verified
`INSTANCE_CREATED` receipt proving that the exact App instance has no accepted
predecessor. Dropping a parent and relabeling old bytes as `INITIAL/LIVE` is not
a valid way to reset lineage. An isolated-scenario admission accepts only an
isolated or synthetic origin with a quarantined outbox; it never targets the
operator's `LIVE/CONTROLLED` generation.

An optional warm-cache attachment has its own root over the checkpoint root and
exact host tuple. It is deliberately excluded from portable checkpoint
identity and acceptance.

Manual, scheduled, and pre-upgrade saves remain within the same state
generation. A restore, rollback, migration, LLM fork, or scenario fixture mints
a strictly newer state-generation identity. This keeps “another save of this
database” distinct from “a new database lineage” and prevents a checkpoint
digest from being reused as generation authority.

State chunks use the distinct `zcl.app.state_chunk.v1` domain and SHA3-256.
The initial native profile uses path-independent, ordered 64 KiB chunks: small
enough for useful CAS deduplication and dirty-range hash reuse, large enough to
avoid a manifest per SQLite page. Filesystem copy-on-write operates at the
filesystem's own extent size; the 64 KiB choice does not control it. Chunk size
remains an explicit versioned manifest field. Package chunks and private state
chunks are different domains and never authorize each other.

V1 checkpoint chunks are private-local state. Public convergence happens by
replicating signed AppEvents, not databases. Local preferences/secrets remain
private; ephemeral sessions and warm caches are discardable; wallet material
is never App state. Checkpoint chunks, logical diffs, and row artifacts are not
generic LLM context or package-swarm content. Encrypted export requires a
separate reviewed format rather than relabeling private-local bytes.

Checkpoint/restore has four tiers:

1. **Portable authority:** a host-owned SQLite generation, canonical logical
   root, signed event/outbox cursors, and a complete checkpoint manifest.
2. **Same-host fast copy:** `appd` first drains readers and the sole writer,
   commits the broker transaction, completes and verifies a SQLite WAL
   checkpoint, fsyncs the database, then creates a probed reflink of the main
   database. It resumes admission after the immutable snapshot descriptor is
   secured; hashing and verification continue outside the writer pause. If a
   clean WAL checkpoint/reflink is unavailable, SQLite online backup is the
   mandatory fallback. `VACUUM INTO` may be used only as a logical-equivalence
   copy. Reflink/byte-copy paths may retain the same image root; backup/VACUUM
   may produce a new image root and must prove the same canonical logical root.
3. **Discardable warm cache:** an App may emit deterministic pointer-free cache
   regions through bounded SDK checkpoint operations. `appd` places them in
   fully sealed, read-only, non-executable memory objects and may map them into
   the replacement worker with dump exclusion. Every offset, length, alignment,
   region, and zero-padding byte follows a canonical SDK encoding. The cache is
   bound to exact App artifact, SDK ABI, architecture, endianness, data model,
   page size, CPU feature floor, schema, activation/state generation, and grant
   revision. Any mismatch discards it and rebuilds from portable state.
4. **Demand paging:** `userfaultfd` or a platform equivalent is deferred until
   measurements prove it necessary. It is unavailable to an unverified App and
   is not required for correctness.

Raw core dumps, copied heaps, stack/register images, kernel objects, live
pointers, locks, TLS, file descriptors, and libc state are never checkpoint
authority. They are non-portable, can retain secrets, conflict with ASLR and
W^X, and would weaken the sandbox's non-dumpable policy.

Full-database rescans are a correctness fallback, not the fast path. `appd`
maintains a complete parent chunk manifest, but broker-level write knowledge is
not sufficient: B-tree splits, freelists, schema changes, and auto-vacuum can
dirty physical pages indirectly. A pinned SQLite VFS/WAL-frame observer tracks
page ranges under a persistent snapshot epoch. Any gap, restart, WAL reset,
unknown VFS operation, or epoch discontinuity invalidates incremental reuse and
forces a full image rescan. With continuous evidence, a child checkpoint reuses
unchanged chunk hashes and hashes changed 64 KiB ranges in a bounded parallel
pipeline. Logical projections maintain incremental roots and receive periodic
full scrubs. Manifests are always complete—there are no unbounded parent-delta
restore chains—and packed CAS segments avoid one inode per chunk.

### 6. Atomic save, restore, fork, and switch

A checkpoint executes:

```text
admission stop → drain generation leases → quiesce routes/jobs/writes
→ commit broker transaction/outbox → snapshot to descriptor-owned staging
→ independent integrity/schema/FK/signature/logical-root verification
→ SHA3 chunk + checkpoint root → fsync chunks/packed segment, manifest,
  CAS index, and containing directories → journal ACCEPTED(checkpoint root)
→ fsync control-log event and containing directory
→ acceptance receipt → resume
```

A restore never overwrites the current database. It creates a new App-state
generation, verifies package/grant/schema bindings, replays any signed tail,
runs migrations and self-test, starts a new sandboxed worker, and requires
readiness before one atomic switch of `{worker,state,routes,jobs}`. The old
worker and database remain under generation leases until drain completes.
Power loss or injected failure yields exactly the old or new generation. An
unknown commit outcome becomes a durable named blocker.

The checkpoint's route/job cursor roots do not authorize that switch. `appd`
re-derives routes and schedules from the admitted package and the platform
control grant, rejects conflicts, and rechecks the live grant revision under
the switch lease.

Forking is the same operation without switching `current`: the result is a new
state-generation checkpoint with a causal parent, not a copied activation or
grant. This is the default LLM test surface. The scenario runner assigns an
isolated principal and an attenuated test grant: no wallet requests, public
routes, peer/network publication, canonical topic delivery, or live outbox.
All side effects enter a quarantined sink.

Origin taint is transitive in platform control. Every child admission resolves
its accepted parent checkpoint and may only preserve or increase the lineage
class `LIVE → ISOLATED_FORK → SYNTHETIC_FIXTURE`; it can never decrease it. A
self-asserted `LIVE` label is not evidence. The checkpoint contract exposes
this parent-lineage validation, and `appd` must pass it before it may append an
`ACCEPTED` event.

Synthetic clock/RNG/network fixture state and isolated-fork output can never be
switched into production. A green scenario promotes the exact artifact/build
roots and its proof receipt; production activation repeats required probes
against a fresh production-state fork and creates a clean state generation. It
does not promote the scenario database. The production probe fork remains
tainted; a clean production generation is derived separately from an accepted
`LIVE` parent under the production grant.

### 7. LLM development surface

Native commands are the only long-term operator/LLM interface. The service/App
platform must expose bounded operations for:

- Declaring, building, verifying, loading, quiescing, and unloading an exact
  cartridge generation.
- `app checkpoint create/show/verify/fork/restore/diff/gc` with explicit App
  instance and generation identities.
- Running a scenario against an isolated fork with fixed clock/RNG/network
  fixtures and a bounded resource budget.
- Producing `dev context`: exact source epoch, dependency closure, active App
  and state roots, relevant tests, recent typed failures, and last-good
  evidence.
- Producing a sub-4 KiB causal doctor summary whose artifact IDs page into
  bounded logs, state diffs, traces, and test receipts.

The fast loop is therefore:

```text
capture exact source → build cartridge → fork last-good checkpoint
→ attenuate grant → load → run scenario → inspect bounded capsule
→ promote exact artifact/proof roots or drop
```

Each run emits `zcl.app.scenario_receipt.v1`, binding the source epoch,
package/artifact/activation roots, input checkpoint, deterministic fixture
roots, resource budget, output checkpoint/diff, relevant tests, and bounded
failure artifacts. The receipt records whether fixture state was synthetic and
is the evidence for artifact promotion; it is never authority to promote App
state.

An LLM never receives an unbounded database dump by default. Schema, resource
relationships, changed logical rows, event ranges, and causal failures are
content-addressed drill-down artifacts. This makes “memory” explicit,
reproducible, and cheap to reload rather than a conversational accident.

### 8. Low-level performance contract

The fast path has algorithmic gates before latency claims:

- Reflink writer pause is proportional to the committed dirty WAL/checkpoint
  barrier, not total database size.
- Incremental checkpoint hashing is proportional to changed chunks; a periodic
  full scrub is separately scheduled and never hidden in the interactive loop.
- Metadata admission validates layout while computing the image and checkpoint
  roots in one ordered descriptor pass per child/parent; ancestry checks reuse
  those validated roots instead of rescanning million-entry manifests.
- Restore uses descriptor-owned packed CAS reads or an already verified
  materialized state generation; it does not create one file per chunk.
- Warm-cache mapping is read-only and zero-copy after compatibility and seal
  checks. A miss changes only latency, never output state.

Benchmarks cover 1 MiB, 100 MiB, 1 GiB, and 10 GiB databases at 0%, 1%, and 10%
dirty ratios. Receipts report writer-pause p50/p95/p99, bytes copied and hashed,
hash/CAS throughput, dedupe ratio, fork-to-handle, restore-to-ready, cold/warm
worker start, peak RSS, and storage amplification. Results name filesystem,
kernel, SQLite, CPU feature floor, storage device, artifact, and source epoch.
No “instant,” “zero-copy,” or sub-millisecond claim exists without that exact
artifact.

## Rollout order

The sovereign shielded-state cure remains first. No service or App work may
weaken its containment, change consensus, or mutate the canonical datadir.
Pure schemas, canonical codecs, inert shadow catalogs, and hermetic tests may
land before cure/copy proof because they grant no runtime authority. Process
splits, save/restore commands, canonical mutation, and activation remain gated
after the cure.

After cure/copy proof, implementation order is:

1. Shadow service manifest and bounded projections; no behavior change.
2. Dedicated platform control journal/projector and explicit service principal.
3. Versioned IPC/grants and init/core shadow process supervision.
4. Per-App database ownership and the portable checkpoint codec/validator.
5. Atomic App state generations and restore/fork; then optional reflink and
   sealed warm-cache acceleration.
6. Edge, appd, wallet, and buildd compartments; package publishing last.

The checkpoint manifest/codec may be implemented and fuzzed before per-App
database ownership, but no command may claim to save/restore an App until the
host owns that App's isolated database and atomic switch transaction.

## Consequences

**Positive:**

- Core remains a small immutable authority while Apps gain OS-enforced fault
  and privilege isolation.
- App state can be forked, tested, restored, and rolled back without copying or
  relying on process-memory internals; a probed reflink may also avoid a full
  database byte copy.
- Portable correctness and same-host speed are separate: a corrupt or stale
  warm cache costs performance, never state.
- LLM work becomes exact and reviewable: source, cartridge, state, scenario,
  failure, and promotion are all named roots.
- The same contracts map to Linux namespaces/seccomp/Landlock and later native
  FreeBSD jails/Capsicum without embedding either OS.

**Negative / risk:**

- ADR-0003's one-process conclusion is no longer the destination. The process
  split adds IPC, lifecycle, and upgrade failure modes that require durable
  typed evidence and crash injection.
- Reflink behavior varies by filesystem and cannot be assumed. The verified
  SQLite copy remains mandatory fallback.
- Warm-cache compatibility tuples are intentionally strict, so cache hits may
  be rare until measurements justify more sophisticated translation.
- Cheap forks can consume CAS and database space. Quotas, leases, reachability
  GC, and pinned incident/release evidence are required before general use.

## Acceptance constraints

- Consensus replay and reducer behavior remain byte-for-byte compatible with
  `zclassicd`; App compromise cannot change H*, coins, anchors, nullifiers, or
  wallet keys.
- Checkpoint corruption, stale generation/grant/schema, cursor regression,
  route conflict, and wrong logical root fail before shadow launch.
- Crash injection at every checkpoint and generation-switch boundary recovers
  to exactly old or new state.
- A byte-preserving reflink/copy retains the same image and logical roots.
  SQLite backup/VACUUM may have a different image root but must reproduce the
  exact canonical logical root and cursor witnesses.
- Warm-cache rejection transparently rebuilds from portable state.
- Cold worker launch from an already verified, materialized generation targets
  p95 below 250 ms. Full restore-to-ready latency, checkpoint/restore
  throughput, fork-to-handle, bytes hashed/copied, storage amplification, and
  write-pause p95/p99 are measured separately from correctness across the
  required size/dirty-ratio matrix.
- One doctor summary plus at most three artifact reads is sufficient to
  diagnose a seeded generation/checkpoint failure.
