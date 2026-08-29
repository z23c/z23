<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Sovereign machine mesh plan

## User outcome

An owner can discover, inspect, transfer files between, and perform explicitly
authorized operations on all of their Z23 machines without depending on a
central controller, hosted account, Git repository, or permanent bootstrap
server. Linux, macOS, and Windows peers use the same identity and authorization
model. A machine remains useful when every optional coordinator is offline.

Permissionless network membership does not grant machine access. Each owner
chooses which identities may act on each machine, which operations they may
perform, and when that authority ends. Pairing, renewal, and revocation are
explicit local acts.

## One owner journey

The finished product has one obvious progression. Names below describe the
target command tree; only commands identified as implemented in the current
state table are available today.

```text
inspect this machine
    -> exchange a short-lived signed invite
    -> compare one short fingerprint on both machines
    -> pair with status-read authority only
    -> see all paired machines and their honest online/offline state
    -> grant one additional typed capability when it is first needed
    -> transfer an exact file, run one bounded task, or open one local service
    -> inspect its signed receipt
    -> revoke the grant or machine without contacting a coordinator
```

The eventual command families are deliberately narrow:

```text
ops mesh identity
ops mesh pair plan|commit|list|revoke
ops mesh machines
ops mesh file offer|fetch|status|cancel
ops mesh task submit|status|cancel|result
ops mesh tunnel open|status|renew|close
ops mesh terminal open|status|renew|close
ops mesh service plan|commit|health|rollback
```

Every mutating family uses plan/commit where the consequence survives the
request. Typed task and service commands never accept a shell command, ambient
environment, unrestricted path, wallet secret, canonical datadir, or arbitrary
executable. An interactive terminal is a separate, explicitly granted byte
stream to one configured confined worker; it does not widen task authority.

## Architecture

There is no fleet server and no privileged machine. Each node owns the same
four boundaries:

```text
permissionless discovery hints
        |
        v
Noise + active ZID authenticated session
        |
        v
target-local pairing, capability, expiry, replay and revocation decision
        |
        +----> typed control request ----> bounded native handler
        |
        +----> immutable object root ----> public or private transfer lane
                                            |
                                            v
                                  exact signed/refused receipt
```

Discovery is replaceable and untrusted. Session identity is cryptographic.
Authority is local to the target. Data is content-addressed. Receipts are
evidence, not authority. An offline machine is represented as unknown/offline,
never deleted from an owner's view merely because a coordinator cannot see it.

The control plane carries small versioned requests, capabilities, revocations,
status capsules, and receipts. The data plane carries bounded immutable
objects. Large file bytes, build inputs, artifacts, logs, and application
bundles never ride inside control messages.

### Control and data-plane route strategy

Routes are transport choices, not authorities. Direct TCP, onion, and a future
opaque relay must terminate in the same Noise static identity and active ZID
delegation before a private control or data request is admitted. An endpoint
record supplies only a candidate address. A successful connection supplies no
capability by itself.

The route procedure is:

1. collect bounded candidates from operator configuration and available
   signed discovery records;
2. connect without attaching a private request;
3. complete Noise and validate the peer's active delegation against the paired
   identity and network genesis;
4. select a route by locally configured policy and measured reachability, not
   by a privilege difference between transports;
5. send a small capability-bound control request; and
6. transfer any referenced immutable bytes through the bounded data lane,
   then bind the terminal receipt to both the control request and object root.

A route failure may try another candidate, but an identity mismatch,
delegation failure, plaintext downgrade, revocation, or capability refusal is
terminal for that request. Relays and rendezvous peers forward opaque records
only. They do not receive target credentials, plaintext, or machine authority.
The status requester now accepts one active, signed direct ZENDP endpoint as an
untrusted hint and submits at most three bounded dial requests. It sends no
status frame until the resulting Noise static and unique active delegation
match the local pairing. Multiple direct candidates, onion failover, relay
transport, and independent-host route receipts remain acceptance work.

## Current truthful state

| Capability | Current state | What remains before a product claim |
| --- | --- | --- |
| Local machine identity | Implemented: `ops mesh identity` reports redacted source, binary, platform, Noise, DHT, confinement, and hot-swap readiness | Restart-stable receipts from independent hosts and remote authenticated retrieval |
| Pairing authority | Implemented: durable schema-v76 records, status-read-only capability, expiry, session binding, and sticky revocation. Owner-facing `ops mesh pair plan|commit` create pairings only through `mesh_pairing_service_accept` with a mandatory out-of-band fingerprint; redacted `ops mesh pair list` and a 60-second generation-bound plan/commit `ops mesh pair revoke` cover inspection and revocation | Two-sided wire ceremony; each host still pairs the other independently |
| Fleet view | Implemented locally: `ops mesh machines` pairs durable verified receipt evidence (schema-v77 store, fresh/stale/never-seen, older/equivocal receipts refused) with a bounded live probe (8 actives, 12 s collective budget); rows merge the live verdict (online with responder identity fingerprint / refused:<status> / unreachable / timeout / unknown / expired / revoked) with persisted evidence; requester acceptance pins the responder's unique active delegated online signing key, fixed replay/cadence bounds protect both ends, and a supervised, sync-subordinate scheduler refreshes paired-machine status automatically (bounded in-flight, cooldown/backoff, admitted only at chain tip with clear disk, memory, and DB). A current signed direct endpoint can trigger a bounded Noise-only dial, but grants no authority and carries no private frame before identity proof. Every verified receipt persists through the one serialized db_service writer; offline machines stay listed | Independent-host direct-route receipts; multiple direct candidates and onion failover |
| Public immutable transfer | Implemented by the package CAS and swarm | Compose it into the owner journey without granting private or execution authority |
| Private file transfer | Foundation only: a signed offer is bound to the live Noise session, active delegated source, target-local pairing, exact one-use grant, nonce, roots, limits, and canonical 64 KiB independently authenticated chunks. Schema-v79 preserves an exact transfer claim for restart-safe resume; a bounded portable codec defines OFFER, REQUEST, CHUNK, and CANCEL frames. A current-user-only staging store durably journals authenticated ciphertext chunks, re-authenticates every recorded chunk on reopen, and verifies the complete ciphertext root. A serialized receiver composes that store with an eight-chunk request window, exact response correlation, unsent-request rollback, fresh admission binding, bounded active transfers, and restart resume | Private dispatcher and queue, atomic no-clobber plaintext publication, cancellation wiring, signed receipts, and independent-host acceptance |
| Remote build/test | Immutable task, bounded worker, CAS, and receipt primitives exist | Pairing-bound request transport, cancellation, platform confinement policy, remote result retrieval |
| Interactive access | Not implemented | Embedded terminal transport, platform PTY worker, confinement, and capability-gated service tunnels |
| Hot swap | Implemented for a small allowlisted read-only C23 leaf set on an isolated development node | Service-island and app-cartridge activation; node/core changes remain restart-only |
| Linux | Full node and embedded Tor path exist; confinement capabilities are host-measured | Multi-host owner-mesh acceptance and resource-priority proof |
| macOS | Native arm64 node build and isolated startup are measured; a launchd service template exists | Native service lifecycle, independent node/session receipts, embedded-Tor build and runtime proof, and truthful confinement/tunnel probes |
| Windows | Native UCRT64 `z23.exe` builds, retained-handle source-package traversal is cross-linked and rejects a real reparse point under Wine, and a Task Scheduler installer exists; WSL2 runs the Linux node. The native consensus store refuses before mutation because the default SQLite VFS is not directory-capability-bound | Retained-directory SQLite VFS and migration, native full-node and service acceptance, embedded Tor, and Windows confinement/tunnel probes |

### Platform service and activation truth

| Boundary | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Native node build/start | Measured | Measured on arm64; Intel remains unverified | Build path exists; full runtime acceptance remains open |
| User service definition | systemd unit with restart and watchdog policy | launchd template with `RunAtLoad` and failure keepalive; lifecycle unproved | Task Scheduler installer with restricted file ACL and exact binary hash; lifecycle unproved |
| Production binary rollback | Native A/B launcher and deployment checks exist | No equivalent accepted path | No equivalent accepted path |
| Embedded onion service | Available only when the full Tor archives are built and linked; the stub is not Tor | Full-Tor build path exists but has not been measured on a Mac | Native path currently uses the Tor stub |
| Live module activation | Development build only, isolated development datadir, allowlisted read-only leaves | Refuses native activation | Refuses native activation |
| Live module rollback | Prior in-process development image can be restored after the same admission checks | Unavailable | Unavailable |
| Confined build execution | Linux worker path exists with bounded action policy and host isolation | Required Linux toolchain/isolation identity is unavailable, so execution refuses | Worker execution refuses |

Service installation does not prove native node operation, Tor availability,
rollback, or confinement. A platform claim requires a native-host receipt for
each row. Linux production A/B rollback and Linux development module rollback
are distinct mechanisms and must not share one generic "hot swap" claim.

No row may be promoted from partial to implemented because another operating
system passed, because a simulator passed, or because one maintainer-owned
machine happened to work.

## Security boundary

The mesh carries narrowly typed requests, immutable objects, and signed
receipts. Interactive terminal access is absent until its separate owner-only
capability, confinement, revocation, and resource acceptance are complete.
Network membership, a human-readable name, possession of a content hash, a
transfer receipt, and a build attestation each prove only their stated fact;
none grants execution, installation, wallet, consensus, deployment, or custody
authority.

The blockchain, wallet, canonical datadir, and production deployment remain
outside the default machine-access capability set. Consensus and peer health
retain resource priority over discovery, transfer, build, and control traffic.

### Shared subordinate-work admission

The host operating system remains the process scheduler. Z23 needs one shared,
pure admission decision for work subordinate to the blockchain, not a second
general-purpose scheduler. Mesh refresh currently implements the strongest
version of this decision: the node must be running and at chain tip; disk and
memory pressure must be clear; no long database operation, open transaction,
turbo mode, or pending block application may exist.

Transfer, build, test, private-object maintenance, discovery refresh, service
activation, and terminal workers must consult the same named decision before
claiming durable work and again before starting an expensive or irreversible
stage. A resource refusal defers work without consuming an attempt, lease, or
failure budget. Work already running obeys its fixed limits and cancellation
contract, while new subordinate work remains closed until blockchain pressure
clears. Background workers also apply the native platform QoS primitive where
available. Shutdown stops admission before worker drain begins.

This is not yet a system-wide guarantee. Automatic mesh status refresh and the
build-fabric worker now share the same pre-claim decision; the worker also uses
background-thread QoS and reports its current refusal reason. Transfer,
private-object maintenance, discovery, activation, and terminal workers must
adopt the same contract as those surfaces are implemented.

## Verified substrate

The following components already exist and should be composed rather than
reimplemented:

- Noise XX and the Noise record layer provide authenticated encryption, transcript
  state, directional counters, replay resistance, rekey limits, and a persistent
  node static key. See
  [`lib/noise/include/noise/noise_handshake.h`](../../lib/noise/include/noise/noise_handshake.h),
  [`lib/noise/include/noise/session_transport.h`](../../lib/noise/include/noise/session_transport.h),
  [`lib/net/include/net/noise_transport.h`](../../lib/net/include/net/noise_transport.h),
  and [`lib/net/include/net/v2_identity.h`](../../lib/net/include/net/v2_identity.h).
- ZID delegation binds the network genesis, online signing key, Noise static
  key, finality-delayed beacon, and validity interval. The DHT validates signed
  frames against the active delegation and the current Noise session. See
  [`lib/vcs/include/vcs/zcode_dht_delegation.h`](../../lib/vcs/include/vcs/zcode_dht_delegation.h)
  and [`config/src/boot_zcode_dht.c`](../../config/src/boot_zcode_dht.c).
- Signed endpoint records, DHT reachability, ZNAM, and onion-directory entries
  provide discovery hints. They do not prove the identity of the responder;
  the completed Noise session and active ZID delegation do. See
  [`config/include/config/boot_endpoint_records.h`](../../config/include/config/boot_endpoint_records.h),
  [`config/src/boot_zcode_dht_reachability.c`](../../config/src/boot_zcode_dht_reachability.c),
  [`lib/net/include/net/onion_discovery.h`](../../lib/net/include/net/onion_discovery.h),
  and [`lib/znam/include/znam/znam.h`](../../lib/znam/include/znam/znam.h).
- The package store and swarm already provide manifest-first, bounded,
  content-addressed public transfer with SHA3 chunk verification, persistent
  resume state, quota enforcement, and path confinement. See
  [`lib/vcs/include/vcs/package_store.h`](../../lib/vcs/include/vcs/package_store.h),
  [`lib/vcs/include/vcs/package_swarm_node.h`](../../lib/vcs/include/vcs/package_swarm_node.h),
  and [`docs/P2P_SOURCE_HOSTING.md`](../P2P_SOURCE_HOSTING.md).
- Signed transfer receipts, storage acknowledgements, source-reproduction
  acknowledgements, local verifier policy, and the package lifecycle already
  separate transport, evidence, acceptance, build, install, and rollback. See
  [`config/include/config/boot_zcode_swarm_receipt.h`](../../config/include/config/boot_zcode_swarm_receipt.h),
  [`lib/vcs/include/vcs/zcode_dht_record.h`](../../lib/vcs/include/vcs/zcode_dht_record.h),
  [`lib/vcs/include/vcs/package_verify_policy.h`](../../lib/vcs/include/vcs/package_verify_policy.h),
  and [`app/services/include/services/package_lifecycle.h`](../../app/services/include/services/package_lifecycle.h).
- Linux has an embedded Tor onion path when the full Tor archives are built and
  linked; a binary linked to the offline stub must not claim Tor. The native
  macOS full-Tor build path exists but has not completed native-host acceptance.
  The Windows native dependency lane currently uses the stub. Each runtime must
  report its linked capability rather than infer it from the operating system.
  The measured platform boundary is recorded in
  [`docs/GETTING_STARTED.md`](../GETTING_STARTED.md). Windows support is not a
  completed or measured production baseline yet.

Important gaps remain. The Noise transport is not yet the universal default, static
key pinning is incomplete, the public package swarm does not require Noise,
and its host-derived peer key is not a machine identity. The legacy file
service protects against passive observation but does not authenticate an
active peer. Wallet agent sessions authorize bounded spending; they are not
remote-machine login sessions. No current component provides the complete
pairing, private-object, typed-control, or cross-platform failover product.

## Trust model

Each machine owns a persistent Noise static key and an operator-controlled ZID
master identity. A short-lived online key is delegated for one network genesis,
one Noise static key, a bounded interval, and the current finality-delayed
beacon. Rotation replaces online authority without replacing the owner's
master identity.

Discovery inputs are untrusted and interchangeable:

```text
operator seed / ZNAM / signed endpoint / DHT / onion directory
                              |
                              v
                     candidate endpoint only
                              |
                              v
                Noise static key matches active ZID
                              |
                              v
                     authenticated machine
```

A valid alias or endpoint never overrides a session-identity mismatch. Direct
TCP and onion are alternate paths to the same delegated Noise identity. A path
change does not add or remove privilege. Sensitive requests never downgrade to
plaintext when Noise negotiation, identity validation, or delegation validation
fails.

There is no global administrator or network-wide allowlist. Every target
machine evaluates a local policy document. A signed capability names:

- network genesis and target machine identity;
- authorized subject ZID and Noise static identity;
- one typed operation and its immutable input root;
- byte, CPU, memory, process, concurrency, and wall-clock limits;
- earliest use, expiry, nonce, and idempotency key;
- whether results may be stored, returned, built, tested, or installed; and
- an explicit deny-by-default authority mask for wallet, consensus, canonical
  datadir, deployment, secrets, and capability delegation.

Capabilities cannot be widened in transit. A receiver binds each request to the
current Noise transcript and connection generation, verifies the issuer and
subject under local policy, consumes or records its replay key, and returns a
signed receipt for the exact accepted or refused operation. Revocation is a
local, durable state transition and takes effect for new requests and renewed
sessions. Expiry is mandatory even when revocation distribution is delayed.

### Capability-grant lifecycle

Each grant follows one target-local lifecycle:

```text
absent -> planned -> locally committed -> active -> expired or revoked
                                   |          |
                                   |          +-> renewed by a new explicit grant
                                   +-> refused without authority change
```

Planning is read-only and names the exact target, subject, operation, limits,
expiry, and deny mask. Commit re-derives those facts from the live authenticated
session and requires an owner confirmation bound to the plan generation. The
target stores the grant through its durable lifecycle before it can authorize a
request. Request admission then verifies the active session, target and subject
identities, operation kind, immutable input root, limits, time window, replay
key, and current revocation state. Every outcome produces a bounded accepted or
refused receipt without widening the grant.

Renewal creates a new bounded grant; it does not mutate expiry in place or
revive a revoked record. Revocation is sticky and prevents new requests and
session renewal. Cancellation stops one admitted operation but does not revoke
its grant. Disconnect preserves durable cancellation, result, and revocation
state. Garbage collection may remove expired payloads only after the durable
receipt and replay windows no longer require them.

Today, pairing commit implements only the initial status-read authority and is
performed independently on each machine. Two-sided wire grant negotiation,
renewal, capability-specific plan/commit, and capability transport beyond
status-read remain unimplemented.

The transcript hash and transcript-derived connection generation are shared
session evidence. The transport's process-local connection serial is never a
wire field, signature input, replay key, or cross-peer comparison: honest ends
of one session intentionally assign different serials. Status-request replay is
instead keyed by the request id within the authenticated transcript generation.

## Pairing and recovery

Pairing is an explicit two-sided ceremony. The owner compares a short
out-of-band fingerprint or scans an equivalent local code, confirms the target
machine and requested capability template, and records the peer's ZID and Noise
static key locally. First contact without this confirmation may discover and
fetch public content but receives no private-machine capability.

Pairing records are exportable as encrypted, owner-controlled recovery objects.
They are never published to the public DHT or Commons. Removing a peer, rotating
its delegated key, or revoking a capability does not require a central service.
Lost-device recovery invalidates its online delegation and all local capability
records that name the lost static identity.

## Public and private content

Public C23 Commons objects remain content-addressed and transport-independent.
Their manifest and SHA3 chunk roots, not the serving peer, establish byte
identity. Any peer may serve those bytes, and local policy still decides whether
to build, accept, install, or execute them.

Private machine objects use a separate namespace, quota, index, and retention
policy. Plaintext private bytes and their identifying metadata are never placed
in the public Commons, provider DHT, or public receipt stream. A private object
is encrypted to the authorized recipient set before storage, binds its
ciphertext root to the capability and network genesis, and travels only over an
authenticated Noise session. Decryption occurs only after target, subject,
expiry, replay, and local-policy checks. Deduplication never reveals equality
between unrelated owners.

Transfer completion proves only that the receiver verified the exact encrypted
object and, when authorized, its plaintext root. It does not imply execution or
installation. Partial transfers are resumable, bounded, independently hashed,
and harmless until committed through the destination's private-file lifecycle.

## Typed remote operations

The first remote-control surface contains only operations whose inputs,
effects, resource limits, and receipts can be specified exactly:

1. inspect public node status and declared capabilities;
2. offer or fetch an immutable public or private object root;
3. submit a bounded build or test task against immutable inputs;
4. poll, cancel, or retrieve the result of that task;
5. request an explicitly authorized service-island or application-cartridge
   activation; and
6. retrieve signed logs, measurements, and receipts with declared redaction.

There is no generic command string, shell expansion, inherited ambient
environment, arbitrary filesystem path, or unrestricted process launch. The
target maps each operation to a fixed native handler and a confined worker.
Unknown operation kinds, fields, authority bits, platform guarantees, or
versions fail closed.

## Interactive remote access

Interactive access uses a small encrypted terminal protocol carried by the
same authenticated Z23 session. Z23 implements terminal framing, resize, flow
control, expiry, revocation, quotas, and receipts in C23; it does not parse
shell syntax. Windows connects the confined worker to ConPTY and
`CreateProcessW`; Linux and macOS connect it to a PTY and a descriptor-safe
spawn primitive. The worker launches only the locally configured shell or
agent entry point. No separately installed SSH server is required.

The worker runs under a dedicated unprivileged identity or an equivalently
proven restricted token, in a separately owned workspace. It cannot read the
node datadir, wallet, RPC cookie, deployment credentials, identity keys, or
canonical checkout. A platform that cannot prove those restrictions refuses
terminal activation. Optional tunnels to existing SSH, Remote Desktop, or
screen-sharing services remain a second access mode, not a prerequisite.

Each terminal or tunnel grant binds the target machine, subject identity,
service or terminal kind, connection count, byte and bandwidth limits, idle
timeout, hard expiry, and current Noise connection generation. A tunnel also
binds its local endpoint and direction. Neither grant conveys wallet,
deployment, custody, or capability-delegation authority. Closing, expiry,
revocation, identity mismatch, transport downgrade, or Noise rekey failure
tears down access and emits a bounded signed receipt. Relay and rendezvous
peers forward opaque ciphertext only and never acquire endpoint credentials or
access authority.

## Hot-swap taxonomy

"Hot swap" is not one guarantee. The operator and receipt must name the exact
class that occurred:

| Class | Mutable unit | Required boundary | User-visible interruption |
|---|---|---|---|
| Read module | Immutable data or read-only module selected by a live service | Hash verification, schema/version match, atomic pointer or generation change | None expected |
| Service island | Isolated non-consensus worker with typed IPC | New confined process, readiness proof, routed generation change, old-process drain | Bounded request retry |
| App cartridge | Separately accepted application bundle outside the node core | Local policy acceptance, immutable root, explicit plan/commit, rollback root | Application-specific bounded restart |
| Core restart | Node, wallet, networking, storage, or consensus binary | Signed exact binary, local deployment authority, graceful shutdown, startup and sync acceptance, rollback binary | Explicit node restart |

Consensus code, wallet custody, database schema ownership, and in-process native
code are never described as live-swappable unless a separate design proves the
relevant state and ABI invariants. A restart is the correct safe operation when
those invariants are absent. No hot-swap class may load fetched C directly into
the node process.

### Efficient update strategy

The mesh distributes content once and rebuilds only where platform identity
requires it:

1. publish one exact source/package root and dependency lock;
2. reuse an accepted platform artifact when its source, compiler, flags, ABI,
   sealed-core root, and local policy all match;
3. otherwise compile once on that machine or request bounded reproduction from
   another consenting machine of the same platform class;
4. hot-swap only an allowlisted stateless read module after in-process probe;
5. generation-switch an isolated service or accepted app cartridge after
   readiness proof; and
6. gracefully restart the node for networking, storage, wallet, consensus, or
   ABI/state changes, retaining an exact rollback binary.

This avoids unconditional rebuilds on every machine without treating a Linux
ELF, a macOS Mach-O, and a Windows PE as interchangeable. Source identity is
portable; native artifacts are platform- and toolchain-bound.

## Delivery phases

### Critical implementation queue

The phases below are delivered in this dependency order:

1. completed: the local identity capsule reports the pairing authority that
   exists without claiming a remote protocol;
2. completed: pairing list/revoke is owner-visible locally without creating a
   way to bypass the authenticated-session acceptance service;
3. completed: define and fuzz the bounded status request/response wire,
   transcript binding, nonce, expiry, and signed receipt;
4. completed: connect the wire only after Noise plus active ZID authentication
   and prove revocation races fail closed;
5. completed: project responses into `ops mesh machines` with honest fresh,
   stale, and unknown state, then refresh connected active pairings without
   competing with chain synchronization;
6. completed: extract the mesh resource gate into shared subordinate-work
   admission, use it before build-fabric lease claims, apply platform background
   QoS, and prove deferral never consumes an attempt or competes with chain
   synchronization;
7. in progress: identity-pinned single-direct-route acquisition is locally
   implemented; record independent-host native service and signed status
   receipts, then add bounded multiple-direct and onion route selection without
   changing authority when the path changes;
8. complete the two-sided capability plan/commit, renewal, cancellation, and
   sticky-revocation lifecycle for the next typed operation;
9. add the encrypted private-object envelope and resumable transfer before any
   remote execution surface;
10. bind existing immutable build/test actions to paired capabilities;
11. add local-service tunnels and the separately granted terminal worker; and
12. add service-island and app-cartridge activation last.

Each item lands with a local adversarial test and then an independent-host
receipt. Work does not skip forward because a later UI can be demonstrated
against fixtures.

### Parallel platform lanes

Linux, macOS, and Windows work proceeds concurrently without creating a fleet
controller or separate platform protocols. `origin/main` is the integration
blackboard; each lane consumes the same portable C23 protocol and publishes
native evidence for only the guarantees that host can prove.

| Lane | Owns now | Acceptance before promotion |
| --- | --- | --- |
| Portable protocol | Pairing/capability wire, private-object frames and store, receipts, terminal framing, route identity | Strict C23 build, adversarial codec/fuzz gates, restart-safe fixtures, no socket/disk work on message threads |
| Linux native | systemd lifecycle, full Tor, directory/descriptor confinement, PTY worker, A/B core restart | Signed native receipt for service restart, onion identity, confinement, terminal revocation, rollback, and chain-priority load |
| macOS native | launchd lifecycle, full-Tor measurement, directory transaction semantics, PTY worker, service-island generation switch | arm64 native receipts first; Intel remains unclaimed until independently measured; unsupported confinement refuses by name |
| Windows native | UCRT64 runtime, Task Scheduler lifecycle, ACL-safe private store, ConPTY worker, native Tor decision | Native—not Wine/WSL—receipts for start/restart, file publication, terminal teardown, and every advertised transport |
| Cross-host acceptance | Pair each platform combination and remove initiating agents, GitHub, and one route | Exact signed receipts prove identity stability, transfer resume, revocation, alternate-route authority parity, and continued chain sync |

Platform agents may improve their native lane before the shared protocol reaches
it, but they record measurements and portable seams rather than inventing an
alternate wire, identity, capability, scheduler, or update authority. Work is
ready to compose only after its commit is on `main`, its exact source identity
is named, and another host can independently reproduce the claimed behavior.

The immediate acceptance for item 6 queues an action while each admission fact
is independently unsafe: chain not at tip, low disk, high memory pressure, long
database operation, database service unavailable, database closed, transaction
open, turbo mode, pending block application, and shutdown. No case may acquire
a lease, increment an attempt, or start a worker. Clearing all facts admits
exactly one claim. Existing mesh-status gate tests must continue to pass from
the same decision table. The predicate belongs in a shared C23 service rather
than the boot layer: `boot_mesh_status_refresh.c` and
`build_fabric_runtime.c` must consume the same result and reason vocabulary.

Checkpoint measured 2026-08-29T07:50:42-04:00 /
2026-08-29T11:50:42Z: `mesh_capability_grant`,
`mesh_private_object_proto`, `build_fabric`, `mesh_status_wire`, `thread_qos`,
and `db_migration_idempotent` each passed with `groups_failed=0` and
`self_skips=0`; `make lint-fast` passed all 22 selected gates. This proves the
local grant lifecycle, canonical signed-offer refusal surface, shared pure
admission decision, and schema migration. Encrypted transfer and independent
host receipts remain unproved.

Checkpoint measured 2026-08-29T08:40:35-04:00 /
2026-08-29T12:40:35Z: schema-v79 grant authority binds the receiving master
and Noise identities, canonical 65,520-byte plaintext chunk geometry, both
object roots, storage and transfer ceilings, and mandatory denial of wallet,
consensus, canonical-datadir, deployment, secret, delegation, execution, and
installation authority. Exact claims resume across database reopen; a
different transfer and post-claim revocation are refused. The allocation-free
chunk codec uses X25519-safe, HKDF-SHA3-256, and ChaCha20-Poly1305 with a
per-offer key context and per-index nonce. Offer admission rechecks signature,
session transcript and generation, chain-active delegated source, pairing,
target, grant, time, limits, and the grant-nonce-derived request before claim.
The encryption context and transfer identity exclude transient session,
window, and online-key fields, so a newly authenticated re-offer resumes the
same exact ciphertext while an old offer still fails the new session check.
Canonical streaming root derivation now domain-separates plaintext from
ciphertext and binds the exact object size, ciphertext size, chunk count,
ordered chunk indices, and per-chunk lengths. It accepts only the fixed
65,520-byte plaintext / 65,536-byte sealed geometry, including the exact short
final chunk, and fails closed on incomplete, reordered, oversized, or reused
streams. Checkpoint measured 2026-08-29T09:22:48-04:00 /
2026-08-29T13:22:48Z. Focused
`mesh_capability_grant`, `db_migration_idempotent`,
`mesh_private_object_proto`, `mesh_private_object_crypto`, and
`mesh_private_object_admission` groups passed with `groups_failed=0` and
`self_skips=0`; the root-specific gate is recorded with the implementing
change. No network dispatcher, private store, resume journal, or
independent-host receipt exists yet; private file transfer remains incomplete.

Checkpoint measured 2026-08-29T09:55:08-04:00 /
2026-08-29T13:55:08Z: the allocation-free `ZMPO` v1 data-plane envelope
defines exact OFFER, REQUEST, CHUNK, and CANCEL frames. Transfer id, transient
offer request id, nonzero per-request replay id, chunk index, and sealed length
are explicit little-endian fields. The 65,624-byte maximum is build-time
asserted below the existing two-mebibyte carrier limit; unknown versions,
flags, kinds, zero identifiers, invalid sealed lengths, truncation, and trailing
bytes fail closed. This is a portable codec only. It performs no network,
database, file, admission, decryption, execution, or deployment work; the
bounded dispatcher and private staging store remain next.

Item 7 records one native-host service receipt per claimed platform containing
the OS and architecture, source identity, running-image digest, service-manager
identity, readiness result, graceful-stop result, and automatic-restart result.
Rollback is tested and recorded only on a platform that implements it. Route
acceptance then authenticates the same paired identity over each available
path, removes the selected path, and proves that fallback changes neither the
capability nor receipt signer. An unavailable path is an explicit refusal, not
a skipped success.

Item 8 proves that planning writes nothing; a tampered, expired, or stale plan
writes nothing; commit stores exactly the displayed grant; request replay has
no second effect; renewal creates a distinct bounded grant; cancellation does
not widen or revoke authority; and sticky revocation survives restart and
rejects a racing reconnect.

### Phase 0: measure and close transport prerequisites

The read-only `z23 ops mesh identity` capsule now reports the running daemon's
exact source identity, available running-image digest, native platform,
encrypted-transport counts, a domain-separated fingerprint of the public Noise
static key, authenticated DHT node identity, confinement, and native hot-swap
capability. Linux distinguishes WSL from native execution; Windows distinguishes
Wine from native execution. The capsule redacts local paths and private
material, names missing prerequisites, reports the durable local pairing
authority, and reports the implemented remote-status protocol separately from
its live session count and stored receipts. The capsule itself is local
observation only; restart stability, four-host distinctness, and native macOS
and Windows execution still require independent host receipts.

Checkpoint measured 2026-08-28T17:24:08-04:00 / 2026-08-28T21:24:08Z:
the strict C23 release build and the `noise_transport_parity`, `os_proc`,
`syncdiag_rpc`, `command_registry_catalog`, `native_api_contract`, and
`telemetry_network` focused groups passed locally with zero skips.

- Make the authenticated Noise capability visible and operable on every supported
  platform without claiming unsupported Tor or confinement features.
- Bind cached peer identity to the active ZID delegation and refuse downgrade
  for sensitive protocols.
- Repair all descriptor/file-identity publication seams before private transfer.
- Establish four independent machine identities and reproducible status output.

Exit: four hosts restart with stable independent identities; every sensitive
frame is refused before authenticated Noise and active delegation; malformed,
expired, revoked, replayed, and downgraded sessions fail deterministically.

### Phase 1: owner pairing and read-only fleet view

- Add durable local pairing and revocation records.
- Add typed status/capability inventory requests and signed responses.
- Present one local view assembled from peer responses, without storing global
  authority or requiring all peers to be online.

Exit: an owner pairs each host independently, sees honest online/offline and
platform capability state, revokes one host, and proves that the revoked host
cannot query private status after reconnect or transport failover.

### Phase 2: secure file transfer

- Reuse public package CAS for public immutable content.
- Add the separate encrypted private-object store and capability-bound transfer
  protocol.
- Add bounded resume, quotas, cancellation, signed receipts, and atomic
  destination publication.

Exit: files transfer in both directions across all supported platform pairs,
resume after process termination, reject malicious chunks and pathname races,
and never expose private roots or plaintext through public discovery.

### Phase 3: bounded remote work

- Add immutable task requests for registered build and test handlers.
- Apply platform-specific confinement honestly: Linux may advertise its proven
  isolation; macOS and Windows refuse task classes whose required isolation is
  unavailable.
- Return exact input, toolchain, output, log, resource, and result receipts.

Exit: the same public C23 input is built on independent consenting hosts; each
receipt is independently verified; cancellation and resource exhaustion remain
bounded; fetched code cannot acquire node, wallet, or deployment authority.

### Phase 4: secure interactive access

- Add typed terminal open, status, renew, and close operations over an embedded
  C23 framing protocol, backed by ConPTY on Windows and PTYs on POSIX hosts.
- Spawn only a configured shell or agent entry point under a dedicated
  unprivileged identity or proven restricted token and isolated workspace.
- Add optional tunnel operations for explicitly enabled local SSH, Remote
  Desktop, and screen-sharing services.
- Add direct-path, onion-path, and opaque-relay routing without granting the
  rendezvous or relay peer machine authority.

Exit: a paired owner opens a confined terminal on Linux, macOS, and Windows
without installing a separate remote-shell server or opening one to the public
Internet; expiry, revocation, path substitution, relay compromise, and
disconnect close access without exposing node secrets or affecting sync.

### Phase 5: service-island and cartridge activation

- Implement explicit plan, dry-run, commit, health, drain, and rollback handlers
  for non-core components.
- Preserve descriptor-bound artifact identity through activation.
- Keep core changes on the restart path.

Exit: a service island and an app cartridge each activate, survive client load,
roll back to the exact previous root, and leave consensus synchronization and
wallet custody unchanged.

### Phase 6: path independence and onion parity

- Prove direct and onion paths carry the same authenticated identity and
  capabilities.
- Provide a supported macOS and Windows Tor integration or continue reporting
  onion hosting unavailable on those platforms.
- Remove any remaining bootstrap dependency from steady-state operation.

Exit: removing a direct path, one directory source, and every central
development service does not prevent already-paired reachable machines from
discovering alternate paths, transferring objects, or completing authorized
typed work.

## Four-host adversarial acceptance

The initial acceptance fleet contains four independently keyed hosts and must
include Linux and macOS; Windows joins the acceptance claim only after its native
build and runtime gates are measured. Tests use isolated datadirs and consenting
peers, never production wallet state.

1. **Identity:** restart every host and verify stable local identity, distinct
   master/static keys, restrictive key-file permissions, active delegations,
   and no copied private key material.
2. **Decentralization:** remove GitHub, any package registry, the initiating
   operator process, and one discovery source. Remaining peers still discover,
   authenticate, transfer, verify, and serve already-published objects.
3. **Discovery attacks:** inject unsigned, stale, expired, revoked,
   wrong-genesis, equivocated, and alias-conflicting endpoint records. None may
   promote a peer or override the Noise/ZID identity.
4. **Transport attacks:** corrupt handshakes and records; replay, reorder, and
   truncate frames; substitute static keys; reuse connection generations; and
   attempt plaintext downgrade. Every sensitive request is refused without
   side effects.
5. **Path failover:** authenticate a machine over direct TCP, remove that path,
   and reconnect through onion where supported. Identity and privilege remain
   unchanged. Unsupported platforms report the missing path rather than pass.
6. **Capability attacks:** alter target, subject, operation, limits, expiry,
   nonce, or authority mask; replay a valid request; race revocation with a new
   session; and request an unknown operation. All fail closed and produce
   bounded diagnostic receipts.
7. **Transfer attacks:** use multiple providers including one that lies,
   corrupts chunks, stalls, disconnects, replaces staging paths, offers
   traversal or symlink names, exhausts quota, and replays receipts. The receiver
   commits only the exact authorized root and never marks substituted bytes
   complete.
8. **Private-data isolation:** inspect public DHT, Commons CAS, logs, receipts,
   temporary files, crash recovery, and a non-recipient peer. No private
   plaintext, private root, capability secret, or recipient relationship leaks
   beyond the declared protocol metadata.
9. **Local acceptance:** unapproved, duplicate, and self attestations do not
   satisfy verifier policy. Two distinct locally approved attestations for the
   same exact input may satisfy policy but still do not install without a local
   plan and commit.
10. **Resource priority:** saturate transfers and bounded tasks while each node
    maintains P2P health and chain synchronization. Consensus latency,
    disconnects, queue depth, CPU, memory, disk, and cancellation time remain
    within declared limits.
11. **Hot swap and rollback:** exercise every claimed class, verify its exact
    receipt, inject readiness and health failures, and recover the previous
    immutable root. Core changes perform a measured graceful restart rather than
    claiming a live swap.
12. **Cross-platform truth:** repeat applicable cases for every claimed
    Linux/macOS/Windows pair. A platform passes only the guarantees it actually
    implements; unavailable Tor, confinement, descriptor execution, or other OS
    facilities are explicit refusals.

## Measured checkpoints

- 2026-08-28: the local pairing authority reached schema v76. The focused
  `mesh_pairing` acceptance proved that fingerprint mismatch and Noise-static
  mismatch make no durable write, accepted status-read authority survives a
  database reopen, expiry is fail-closed, and sticky revocation survives a
  second reopen without timestamp or generation drift. This is local authority
  storage only; no remote status request is wired or claimed yet.
- 2026-08-28T19:54:30-04:00 / 2026-08-28T23:54:30Z: the live identity
  capsule stopped describing all pairing as absent. It now reports that local
  authority exists, exposes only redacted active/expired/revoked counts, and
  separately names the remote status protocol as unavailable. `mesh_pairing`,
  `syncdiag_rpc`, `models`, `db_migration_idempotent`, `make_lint_gates`, and
  `rpc`, `command_registry_catalog`, and `native_api_contract` passed cold with
  zero skips; `make lint-fast` passed 20/20 gates and `make lint` passed
  158/158 gates.
- 2026-08-28T21:08:08-04:00 / 2026-08-29T01:08:08Z: the bounded
  `mesh_status_proto.v1` request and signed-receipt codecs landed with a
  4,505-byte maximum fuzz input. The exact `mesh_status_proto`, `mesh_pairing`,
  and `crypto` groups passed 3/3 with zero skips. The ASan/UBSan fuzz target
  completed 10,000 iterations across the full maximum bound without a finding.
  The wire remains disconnected from Noise, DHT, and peer handlers; it grants
  no remote status authority and does not advance queue item 4.
- 2026-08-28T23:26:48-04:00 / 2026-08-29T03:26:48Z: local owners gained a
  bounded redacted pairing list and an explicit 60-second, generation-bound
  revoke plan/commit. Tampered or expired unused confirmations made no write;
  successful revoke replay remained idempotent after database reopen; and the
  RPC registry exposed no accept, create, or capability-widening method. The
  `mesh_pairing_controller`, `command_registry_catalog`, `native_api_contract`,
  and nine selected `rpc` groups passed cold with zero skips. Remote status and
  remote-control authority remain unavailable.
- 2026-08-29: queue item 4 connected the wire. `ZMSTAT`-prefixed
  request/receipt frames multiplex on the frozen `zpkgswm` P2P message — no
  new wire message, listener, or port — and are answered only on an
  established Noise session whose peer holds a live ZID delegation;
  plaintext or mid-handshake sessions are dropped with no receipt, so
  responder keys never cross an unauthenticated channel. The responder
  decides through `mesh_pairing_service_authorize_status` (including its
  revocation-race re-read) and signs every outcome — OK with the redacted
  `zcl.machine_mesh_identity.v1` capsule (4,096-byte bound, deterministic
  oversize marker instead of truncation) or a named refusal status — using
  the datadir online Ed25519 key. The requester lane (`mesh_status_request`
  / `mesh_status_poll` RPC, `ops mesh status`) admits a bounded pending
  request only to a paired peer with a live session, never auto-dials, and
  accepts a receipt only when its signature, request binding, current
  session binding, and paired responder master all verify. The identity
  capsule now reports `remote_status_protocol_implemented: true` and drops
  the `REMOTE_STATUS_PROTOCOL_UNAVAILABLE` blocker; the test pinning the old
  strings was updated to the new truth. The new `mesh_status_wire` group
  proves the decision and byte-level frame roundtrip between two in-process
  Noise transports with real Ed25519 keys and a real node.db fixture, including
  revoke-after-accept failing closed; `mesh_status_proto`, `mesh_pairing`,
  `zcode_swarm`, `command_registry`, `syncdiag_rpc`, `native_api_contract`,
  and `rpc` groups all passed with zero skips, and `make lint-fast` and
  `make lint` both passed. This is in-process proof; independent-host
  receipts remain for the phase exit. A later proto revision removed the
  per-side connection serial from the request and receipt (the shared
  transcript and generation remain the session binding).
- 2026-08-29: queue item 2 exposed the pairing ceremony to the operator.
  `ops mesh pair plan|commit` (RPC methods `mesh_pairing_plan` /
  `mesh_pairing_commit`) are the only path that creates pairings, driving
  the existing `mesh_pairing_service_accept` authority — no path bypasses
  the authenticated-session acceptance service, and all durable writes go
  through its ActiveRecord lifecycle. plan renders a no-write preview from a
  live re-derivation (established Noise session narrowed by an
  address-substring or fingerprint-prefix selector, held ZID delegation,
  status-read-only capability, default 7-day expiry, derived pairing id);
  commit makes `--fingerprint` mandatory (the out-of-band compared value),
  re-derives everything live, clamps the lifetime to [1, 30] days, maps
  every `mesh_pairing_reason` refusal to a named code that writes nothing,
  and renders the stored record through the same redacted public view as
  `ops mesh pair list`. Inspection and revocation ride the controller's
  redacted `ops mesh pair list` and confirmation-bound `ops mesh pair
  revoke`; the direct-revoke RPC method was retired in favor of that
  generation-bound flow. No command ever dials: a peer without a live
  session is PEER_NOT_CONNECTED, more than one match is AMBIGUOUS_PEER. The
  ceremony remains per-machine local — each host pairs the other
  independently; there is no two-sided wire ceremony yet. The
  `mesh_pairing` group gained the pure-layer proofs (days
  default/bounds/rejection, selector matching, state derivation, canonical
  fingerprint decode, distinct reason→code mapping); `mesh`,
  `command_registry`, `native_api_contract`, and `rpc` groups all passed
  with zero skips, and `make lint-fast` and `make lint` both passed.
- 2026-08-29: queue item 5 added schema-v77 latest-observation storage and
  `ops mesh machines`. Terminal status polling persists the exact verified
  signed receipt wire and root only after delegated identity and current Noise
  session acceptance. The local read performs no dial, exposes fingerprints
  rather than raw public keys, and distinguishes fresh, stale, and never-seen
  evidence. Older or same-time equivocal receipts cannot replace the durable
  row; exact replay is idempotent. Fixture acceptance proves restart retention,
  stale/unknown separation, redaction, migration idempotence, and strict MinGW
  C23 syntax. Automatic refresh and independent-host evidence remain open.
- 2026-08-29: queue item 5 landed the fleet view. `ops mesh machines` (RPC
  method `mesh_machines`) projects every durable pairing record — active,
  expired, and revoked — exactly once, and probes up to
  MESH_MACHINES_FLEET_MAX (8) active records over the existing status lane
  with a collective 12-second budget and 50 ms poll rounds inside the RPC
  worker thread. Each row carries the redacted pairing view plus a verdict
  from one pure mapping (`mesh_machine_derive_state`): online (signed OK
  receipt with observed time, responder Noise fingerprint, and a redacted
  capsule summary lifting platform/build/confinement/hotswap, including
  `same_source_as_this_node`), refused:<status> (a signed refusal receipt
  with its wire token), unreachable (no live Noise session or the Noise transport
  disabled), timeout (request expiry or budget exhaustion), unknown (named
  cause, counted only in `total`), expired, or revoked. The RPC watchdog
  extends only this method's slot to a bounded 20 s
  (RPC_MESH_COLLECT_TIMEOUT_MS) so the collective wait is never killed
  mid-reply; the native client deadline is 18 s. No dial, no write, and no
  persistent reachability history — every verdict is derived at call time.
  Proofs: the `mesh_status_wire` group gained the full derive matrix (both
  unreachable causes, both timeout causes, refused-token propagation,
  record/begin/poll precedence), probe-cap planning with the truncation
  flag, and the tally rollup including the empty fleet; the `rpc_timeout`
  group pins the method-scoped extension; the catalog pins
  `ops.mesh.machines` READY/read with its handler. Gates: t-fast ONLY=mesh
  7/7, ONLY=command_registry 2/2, ONLY=native_api_contract 1/1, ONLY=rpc
  9/9 groups with zero skips; the impact-rule check passed and
  `make lint-fast` passed. `make lint` reported three pre-existing upstream
  failures in files this slice never touched (doc-count drift
  test_groups=998-vs-994 in docs/CODEBASE_MAP.md, a publish-shaped printf
  string in tools/dev/grok-unit.sh, operator paths in
  docs/experiments/2026-08-28-mac-agentic-baseline.md). What remains before
  the product claim: independent-host receipts.
- 2026-08-29: merge reconciliation unified the two `ops mesh machines`
  implementations into one surface. Upstream's schema-v77 observation store
  and its read/render path are authoritative for durable evidence
  (fresh/stale/never-seen, fingerprints only); the live-probe fan-out became
  the bounded refresh that populates that store. Persistence moved into the
  status lane as `boot_mesh_status_persist_observation`
  (config/src/boot_mesh_status.c), called by both the single-machine poll
  RPC and the fleet refresh, so both writers share one handoff and one
  truth. The unified document keeps every upstream field and adds the live
  rollup (`live_probed`/`live_online`/… plus per-row `live_reachability`)
  only when a probe ran; the test hook renders the durable document alone.
  The row no longer embeds a capsule summary — `ops mesh status` already
  renders the full verified capsule for one machine, so the fleet row
  carries identity fingerprints and verdicts only. Duplicates removed: the
  second command-catalog leaf, the second native handler and declaration,
  and the upstream render/method copy in boot_mesh_status_rpc.c. The
  `mesh_pairing` group gained the agreement pin: one verified receipt feeds
  the live row, the store, and the rendered document, and all three agree
  on pairing identity and responder Noise fingerprint. Gates: `make z23`
  passed; t-fast ONLY=mesh 7/7, ONLY=command_registry 2/2,
  ONLY=native_api_contract 1/1, ONLY=rpc 9/9 groups with zero skips; the
  impact-rule check, `make lint-fast`, and full `make lint` (163 gates) all
  passed. What remains before the product claim: automatic bounded refresh
  scheduling and independent-host receipts.
- 2026-08-29: queue item 5 added a dedicated supervised refresh clock. It
  polls at most two requests, admits at most one connected active pairing per
  second, backs off unavailable peers, never dials, and admits no new work
  unless the chain is at tip and disk, memory, and serialized database state
  are clear. Verified terminal receipts enter the bounded asynchronous DB
  writer; manual polling uses the same writer synchronously. The focused wire
  group proves the resource gate matrix. Independent-host evidence remains
  open; it requires an owner-approved deployment and restart on each host.
- 2026-08-29T10:24:41-04:00 / 2026-08-29T14:24:41Z: the private-object
  staging store added exclusive per-transfer locking and a bounded portable
  journal under an already owner-private directory. Chunk acceptance performs
  AEAD verification before ciphertext write and flush, then persists and
  flushes the resume bit. Reopen checks exact file geometry and journal
  identity and re-authenticates every set-bit chunk; corruption refuses the
  staging state instead of silently repairing it. The focused
  `mesh_private_object_stage` group passed cold with one group run, zero
  failures, and zero skips, proving out-of-order resume, exact duplicate
  idempotence, short-final-chunk handling, full ciphertext-root verification,
  and corruption refusal. This does not publish plaintext, complete a grant,
  connect a network dispatcher, or establish independent-host acceptance.
- 2026-08-29T10:39:56-04:00 / 2026-08-29T14:39:56Z: an allocation-free
  private-object request scheduler added an eight-chunk sliding window,
  five-second monotonic deadlines, five-attempt exhaustion, out-of-order
  completion, exact in-flight response correlation, resume seeding, nonzero
  wrap-safe correlation ids, unsent-request rollback, and terminal
  cancellation. Its one focused group ran cold with five cases,
  zero failures, and zero skips. The scheduler performs no socket, disk,
  authority, or publication operation; dispatcher integration remains open.
- 2026-08-29T11:03:31-04:00 / 2026-08-29T15:03:31Z: exact Noise-static
  delegation lookup moved into the bounded DHT view. It compares retained
  contact keys before decoding and copies at most the caller's requested
  matches, including a second match so ambiguity remains fail-closed. The mesh
  status responder no longer allocates a maximum-chain delegation snapshot or
  decodes unrelated entries per authenticated request. The cold
  `zcode_dht_service` and `mesh_status_wire` groups passed with zero failures
  and zero skips; `make lint-fast` passed 22/22 gates.
- 2026-08-29T11:34:37-04:00 / 2026-08-29T15:34:37Z: a serialized private-object
  receiver composed admission, durable ciphertext staging, and the bounded
  request scheduler. An offer cannot allocate storage without a matching
  successful target-local admission capsule. Drive and chunk calls require the
  same current transfer and revocation generations; chunks require the exact
  issued request id and route. Local send backpressure rolls back the reserved
  attempt. Reopen re-authenticates durable chunks, a fully journaled object is
  root-verified before reporting `staged`, and staged slots are released rather
  than exhausting the four-transfer cap. All eight `mesh_private_object`
  groups ran cold with zero failures and zero skips. This proves ciphertext
  staging only; network dispatch, plaintext-root publication, grant completion,
  signed receipt, and independent-host acceptance remain open.
- 2026-08-29: merge reconciliation converged the fleet view with the new
  refresh architecture. Upstream's supervised, sync-subordinate refresh clock
  and its db_service writer lane are authoritative; the on-demand live-probe
  fan-out in `ops mesh machines` now persists its verified terminal receipts
  through `boot_mesh_status_receipt_persist` — the same serialized writer
  the poll RPC and the background refresh use — so all three writers share
  one lane and one store. The direct `boot_mesh_status_persist_observation`
  variant remains only as the synchronous test handoff. Upstream's duplicate
  render/method copy in boot_mesh_status_rpc.c was dropped again (the unified
  render with the live rollup stays in boot_mesh_machines_rpc.c); the poll
  path took upstream's db_service persist call. Gates: `make z23` passed;
  t-fast ONLY=mesh passed with zero skips; `make lint-fast` passed. What
  remains before the product claim: independent-host receipts.
- 2026-08-29T17:18:49-04:00 / 2026-08-29T21:18:49Z: paired status acquisition
  gained one bounded direct route from the exact master identity's active,
  chain-bound ZENDP record. The endpoint remains an untrusted address: the
  requester sends no `ZMSTAT` frame until an established Noise static and
  unique current ZID delegation match the local pairing. Eight fixed slots,
  three submissions, exponential backoff, a 15-second deadline, subordinate
  work admission, abandoned-slot reclamation, and exact-endpoint downgrade
  disconnection bound the lane. Wrong Noise identity and plaintext completion
  are terminal for the current acquisition and recover only after a fixed
  retention interval. The cold `mesh_route` group passed seven adversarial
  cases and `mesh_status_wire` passed twelve cases, each with zero failures and
  zero skips, using GCC 16.1.1 on an AMD Ryzen 7 PRO 8840U. This is local direct
  route evidence only; onion selection and independent-host receipts remain
  open.
- 2026-08-29T18:11:22-04:00 / 2026-08-29T22:11:22Z: Windows package
  preparation replaced pathname traversal with one retained-root,
  handle-relative NT walk and refused a real reparse point under Wine. Review
  of the separately merged native consensus-store path found that migration
  could mutate before directory validation and that the default SQLite VFS
  reopened main/WAL/SHM paths outside the retained capability. Windows now
  refuses that store before any mutation, with a strict cross-linked fixture
  proving a sentinel `progress.kv` and absent database families remain inert.
  Unicode state-root overrides and pre-existing ACL repair are also
  cross-linked. Six affected native groups passed with zero failures and zero
  skips. Native Windows node operation remains unclaimed until a
  retained-directory SQLite VFS and native-host acceptance exist.

## Completion rule

The sovereign machine mesh is ready only when the acceptance above runs from a
clean checkout, records exact binary and source identities, and succeeds without
a central controller. Unit tests, simulated peers, a successful transfer, or a
four-node status display alone do not prove the user outcome.
