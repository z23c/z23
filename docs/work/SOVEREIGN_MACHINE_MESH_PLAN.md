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

## Security boundary

The mesh carries narrowly typed requests, immutable objects, and signed
receipts. It does not expose an arbitrary remote shell in the initial product.
Network membership, a human-readable name, possession of a content hash, a
transfer receipt, and a build attestation each prove only their stated fact;
none grants execution, installation, wallet, consensus, deployment, or custody
authority.

The blockchain, wallet, canonical datadir, and production deployment remain
outside the default machine-access capability set. Consensus and peer health
retain resource priority over discovery, transfer, build, and control traffic.

## Verified substrate

The following components already exist and should be composed rather than
reimplemented:

- Noise XX and the v2 record layer provide authenticated encryption, transcript
  state, directional counters, replay resistance, rekey limits, and a persistent
  node static key. See
  [`lib/noise/include/noise/noise_handshake.h`](../../lib/noise/include/noise/noise_handshake.h),
  [`lib/noise/include/noise/session_transport.h`](../../lib/noise/include/noise/session_transport.h),
  [`lib/net/include/net/v2_transport.h`](../../lib/net/include/net/v2_transport.h),
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
- Linux has an embedded Tor onion path. macOS currently builds the native node
  without embedded Tor, and must report onion service unavailable rather than
  claim fallback coverage. The measured platform boundary is recorded in
  [`docs/GETTING_STARTED.md`](../GETTING_STARTED.md). Windows support is not a
  completed or measured production baseline yet.

Important gaps remain. V2 transport is not yet the universal default, static
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

Interactive access reuses the operating system's maintained local service
instead of adding a second shell or desktop protocol to Z23. A paired owner may
open an authenticated, capability-gated tunnel to one explicitly named local
service such as SSH, Remote Desktop, or a screen-sharing server. The service
stays bound to loopback or its existing private interface; Z23 does not publish
an unrestricted listener.

Each tunnel grant binds the target machine, subject identity, service kind,
local endpoint, direction, connection count, byte and bandwidth limits, idle
timeout, hard expiry, and current Noise connection generation. It grants no
filesystem, process, wallet, deployment, or capability-delegation authority of
its own. The target's native service performs its normal user authentication
inside the encrypted tunnel. Closing, expiry, revocation, identity mismatch,
transport downgrade, or Noise rekey failure tears down the tunnel and emits a
bounded signed receipt. Relay and rendezvous peers forward opaque ciphertext
only and never acquire endpoint credentials or access authority.

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

## Delivery phases

### Phase 0: measure and close transport prerequisites

The read-only `z23 ops mesh identity` capsule now reports the running daemon's
exact source identity, available running-image digest, native platform,
encrypted-transport counts, a domain-separated fingerprint of the public Noise
static key, authenticated DHT node identity, confinement, and native hot-swap
capability. Linux distinguishes WSL from native execution; Windows distinguishes
Wine from native execution. The capsule redacts local paths and private
material, names missing prerequisites, and reports pairing as unimplemented.
This is local observation only; restart stability, four-host distinctness, and
native macOS and Windows execution still require independent host receipts.

Checkpoint measured 2026-08-28T17:24:08-04:00 / 2026-08-28T21:24:08Z:
the strict C23 release build and the `v2_transport_parity`, `os_proc`,
`syncdiag_rpc`, `command_registry_catalog`, `native_api_contract`, and
`telemetry_network` focused groups passed locally with zero skips.

- Make the authenticated-v2 capability visible and operable on every supported
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

- Add typed tunnel open, status, renew, and close operations for explicitly
  enabled local SSH, Remote Desktop, and screen-sharing services.
- Keep each native service's own authentication, authorization, and audit
  boundary; do not implement a Z23 shell or desktop server.
- Add direct-path, onion-path, and opaque-relay routing without granting the
  rendezvous or relay peer machine authority.

Exit: a paired owner reaches an opted-in local service on Linux, macOS, and
Windows without opening that service to the public Internet; expiry,
revocation, path substitution, relay compromise, and disconnect close access
without affecting node synchronization.

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

## Completion rule

The sovereign machine mesh is ready only when the acceptance above runs from a
clean checkout, records exact binary and source identities, and succeeds without
a central controller. Unit tests, simulated peers, a successful transfer, or a
four-node status display alone do not prove the user outcome.
