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
| Private file transfer | Foundation only: a signed offer is bound to the live Noise session, active delegated source, target-local pairing, exact one-use grant, nonce, roots, limits, and canonical 64 KiB independently authenticated chunks. Schema-v79 preserves an exact transfer claim for restart-safe resume; a bounded portable codec defines OFFER, REQUEST, CHUNK, and CANCEL frames. A current-user-only staging store durably journals authenticated ciphertext chunks, re-authenticates every recorded chunk on reopen, verifies the complete ciphertext root, and persists one terminal canonical cancellation that survives reconnect without mutating grant authority. A serialized receiver composes that store with an eight-chunk request window, exact response correlation, unsent-request rollback, fresh admission binding, bounded active transfers, restart resume, and durable cancellation | Private dispatcher and queue, atomic no-clobber plaintext publication, signed completion/cancellation receipts, and independent-host acceptance |
| Remote build/test | Immutable task, bounded worker, CAS, and receipt primitives exist | Pairing-bound request transport, cancellation, platform confinement policy, remote result retrieval |
| Interactive access | Not implemented | Embedded terminal transport, platform PTY worker, confinement, and capability-gated service tunnels |
| Hot swap | Implemented for a small allowlisted read-only C23 leaf set on an isolated development node | Service-island and app-cartridge activation; node/core changes remain restart-only |
| Linux | Full node and embedded Tor path exist; confinement capabilities are host-measured | Multi-host owner-mesh acceptance and resource-priority proof |
| macOS | Native arm64 node build is measured; the registered marker test proves clean-shutdown marker persistence in an isolated fixture, not node startup; a launchd service template exists | Native service lifecycle, independent node/session receipts, embedded-Tor runtime proof, and truthful confinement/tunnel probes |
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
  [`core/modules/noise/include/noise/noise_handshake.h`](../../core/modules/noise/include/noise/noise_handshake.h),
  [`core/modules/noise/include/noise/session_transport.h`](../../core/modules/noise/include/noise/session_transport.h),
  [`core/modules/net/include/net/noise_transport.h`](../../core/modules/net/include/net/noise_transport.h),
  and [`core/modules/net/include/net/v2_identity.h`](../../core/modules/net/include/net/v2_identity.h).
- ZID delegation binds the network genesis, online signing key, Noise static
  key, finality-delayed beacon, and validity interval. The DHT validates signed
  frames against the active delegation and the current Noise session. See
  [`contexts/commons/modules/vcs/include/vcs/zcode_dht_delegation.h`](../../contexts/commons/modules/vcs/include/vcs/zcode_dht_delegation.h)
  and [`engine/composition/src/boot_zcode_dht.c`](../../engine/composition/src/boot_zcode_dht.c).
- Signed endpoint records, DHT reachability, ZNAM, and onion-directory entries
  provide discovery hints. They do not prove the identity of the responder;
  the completed Noise session and active ZID delegation do. See
  [`engine/composition/include/config/boot_endpoint_records.h`](../../engine/composition/include/config/boot_endpoint_records.h),
  [`engine/composition/src/boot_zcode_dht_reachability.c`](../../engine/composition/src/boot_zcode_dht_reachability.c),
  [`core/modules/net/include/net/onion_discovery.h`](../../core/modules/net/include/net/onion_discovery.h),
  and [`contexts/naming/modules/znam/include/znam/znam.h`](../../contexts/naming/modules/znam/include/znam/znam.h).
- The package store and swarm already provide manifest-first, bounded,
  content-addressed public transfer with SHA3 chunk verification, persistent
  resume state, quota enforcement, and path confinement. See
  [`contexts/commons/modules/vcs/include/vcs/package_store.h`](../../contexts/commons/modules/vcs/include/vcs/package_store.h),
  [`contexts/commons/modules/vcs/include/vcs/package_swarm_node.h`](../../contexts/commons/modules/vcs/include/vcs/package_swarm_node.h),
  and [`docs/P2P_SOURCE_HOSTING.md`](../P2P_SOURCE_HOSTING.md).
- Signed transfer receipts, storage acknowledgements, source-reproduction
  acknowledgements, local verifier policy, and the package lifecycle already
  separate transport, evidence, acceptance, build, install, and rollback. See
  [`engine/composition/include/config/boot_zcode_swarm_receipt.h`](../../engine/composition/include/config/boot_zcode_swarm_receipt.h),
  [`contexts/commons/modules/vcs/include/vcs/zcode_dht_record.h`](../../contexts/commons/modules/vcs/include/vcs/zcode_dht_record.h),
  [`contexts/commons/modules/vcs/include/vcs/package_verify_policy.h`](../../contexts/commons/modules/vcs/include/vcs/package_verify_policy.h),
  and [`contexts/commons/services/include/services/package_lifecycle.h`](../../contexts/commons/services/include/services/package_lifecycle.h).
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

Pairing is not the first step, because it cannot be. It needs a running node
with an on-chain identity delegation on both sides, and a computer the owner
has just switched on has neither. The first step is enrolment: `fleet
invite`, `fleet join`, `fleet admit` and `fleet machines`
(`engine/composition/commands/fleet_enrol.def`), which record a named machine
from two pasted strings and no network call, and grant nothing. `fleet join`
names this section's ceremony as its `next_step`. See
[`../agent/FLEET_JOIN.md`](../agent/FLEET_JOIN.md) for the owner-facing page.

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
spawn primitive. The Windows arm cross-compiles and enforces the same byte
and lifetime budgets as the PTY arm, but has not yet run a real session on a
Windows machine, and has no Landlock/seccomp-equivalent confinement cage or
process-group census there yet. The worker launches only the locally
configured shell or agent entry point. No separately installed SSH server is
required.

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

### Two-node terminal acceptance procedure

**Purpose.** On two isolated regtest nodes, prove that two independent ZID
masters anchor, provision chain-bound delegations, authenticate each other
over the DHT, and pair bilaterally with the commit-time terminal-exec
capability. Then drive a confined `fbsh` shell on the responder through the
ZMTERM lane: open, poll, write, read, resize, close. Finally, prove that a
mid-session revoke on the responder ends the live terminal with its named
evidence, and that a wrong fingerprint never writes a pairing.

**Topology.** Two nodes on loopback.

- Node A is the initiator. P2P `20032`, RPC `29311`, FS `29312`,
  HTTPS `29313`.
- Node B is the terminal responder. P2P `18043`, RPC `29321`, FS `29322`,
  HTTPS `29323`. Only B is started with `-terminalshell=<build/bin/fbsh>`.

The granted shell is `fbsh`, not `/bin/sh`. The cage's grant is the
filesystem (the per-terminal workdir plus the one granted binary). A
dynamically linked shell fails `execve` closed inside that cage, because the
kernel's ELF-interpreter open and every shared-library open fall outside the
grant. `fbsh` is the project's statically linked confined shell, the same
binary the worker group's live cases drive.

**Steps, in order.** Each step's assertion is the exact field or text checked.

1. **Preflight.** Assert the eight ports are free. Require the node, RPC and
   native C23 acceptance binaries, `build/bin/fbsh`, and `xxd`. Create the
   work directory with `dht_make_work zcl23-termacc`. Build the master-pubkey
   helper by sourcing only `dht_build_helper` from
   `zcode_dht_acceptance.sh`. Write one fixed test master seed per node to a
   mode-600 file, and derive each node's public key with the helper.
2. **Boot.** Start A, then start B with the initial link
   `-connect=127.0.0.1:<A P2P>`. Wait on RPC warm-up for both.
3. **Fund.** On A, call `getnewaddress`, then `dht_mine_to_address 101`.
   Wait for B to reach height `101` and for A's reducer fold to reach `101`.
4. **Custody phase.** Restart B onto the dead sink, then restart A. On A,
   call `addnode` with `127.0.0.1:<B P2P>` and `"onetry"`. Wait for
   connection, live sync, and the chain index at `101`. Unlock the wallet,
   top up the keypool with `getnewaddress`, take the encrypted backup, and
   wait for a positive spendable balance.
5. **Anchor both masters.** On A, call `dht_anchor` for A's public key with
   label `term-anchor-a`, then `dht_mine_empty 1`. Call `dht_anchor` for B's
   public key with label `term-anchor-b`, then `dht_mine_empty 1`. Then
   `dht_mine_empty 21`, and wait for B to reach height `124`.
6. **Provision delegations.** Run
   `zcode network delegate --input={"seed_file":...}` through `dht_native`
   on A and then on B. Assert `ok` is `True` for each. Assert these files are
   non-empty on each node: `v2_identity.key`,
   `zcode/dht/online_ed25519.key`, and `zcode/dht/delegation.v1`. Refusals:
   `A delegation failed: <output>`, `B delegation failed: <output>`, and
   `provisioned identity file missing: <path>`.
7. **Restart and authenticate.** Restart B, then A, with the same flags.
   On A, call `addnode` with `"onetry"` for B. Wait for mutual DHT
   authentication with `dht_wait_auth` on each side. Refusals:
   `A never authenticated B over DHT` and `B never authenticated A over DHT`.
8. **Pair A to B, with a wrong fingerprint first.** On A, call
   `mesh_pairing_plan`. Read `peer_noise_fingerprint_sha3` and `pairing_id`.
   Refuse with `A plan did not name B` if either is empty. Flip the last hex
   digit of the fingerprint, staying inside the hex alphabet. Call
   `mesh_pairing_commit` with that fingerprint, `"terminal":true`,
   `"days":1`. It must return `ok` `False`, or the script refuses with
   `a wrong fingerprint was accepted`. The PASS line is
   `PASS wrong-fingerprint commit refused (<code>)`.
9. **Commit A's pairing.** Call `mesh_pairing_commit` on A with B's real
   fingerprint, `"terminal":true`, `"days":1`. Assert `ok` is `True` and
   `pairing.capability` is `status_read+terminal_exec`. Refusals:
   `A commit failed` and `A commit did not record the terminal capability`.
10. **Pair B to A.** Call `mesh_pairing_plan` on B and read A's
    `peer_noise_fingerprint_sha3`. Refuse with `B plan did not name A` if it
    is empty. Call `mesh_pairing_commit` on B with that fingerprint,
    `"terminal":true`, `"days":1`. Assert `ok` is `True`. Read the pairing id
    from `pairing.pairing_id`, or from `pairing_id` if that is empty. Refusals:
    `B commit failed` and `B commit did not return its pairing id`.
11. **Open.** On A, call `mesh_terminal_open` with `pairing_id` set to A's
    pairing id, `"cols":80`, `"rows":24`. Assert `ok` is `True` and read
    `terminal_id`. Refusals: `terminal open failed` and
    `open returned no terminal id`.
12. **Live.** Poll `mesh_terminal_poll` with `terminal_id` until `state` is
    `live`. Assert `cols` is `80`. Refusals: `terminal never went live`
    (after `terminal <id> never reached state=live` is noted), and
    `live view lost the requested geometry`. The PASS line is
    `PASS terminal is live on B's confined cage`.
13. **Write and read.** Call `mesh_terminal_write` with `terminal_id` and
    `input_hex`, the hex of `echo <marker>` plus a newline. The marker is
    `z23-term-<epoch seconds>`. Then poll `mesh_terminal_read` with
    `"max_bytes":4096`, decode `output_hex`, and stop when the marker
    appears. Refusals: `terminal write failed` and
    `marker never appeared in terminal output`. Also
    `the confined shell never echoed the marker`. The PASS line is
    `PASS the confined shell echoed through the mesh`.
14. **Resize.** Call `mesh_terminal_resize` with `"cols":100`, `"rows":30`.
    Assert `ok` is `True`. Refusal: `resize failed`.
15. **Close.** Call `mesh_terminal_close` with `terminal_id`. Assert `ok` is
    `True`. Refusal: `close failed`. Poll until `state` is `ended`. Assert
    `close_reason` is `requested`. Refusals:
    `terminal <id> never ended` and
    `operator close did not end the session by name`. The PASS line is
    `PASS operator close ended the session by name`.
16. **Second open.** Open again with the same arguments, assert `ok` is
    `True`, and wait for `live`. This shows the responder spawns again after a
    clean end. Refusals: `second open failed` and
    `second terminal never went live`.
17. **Mid-session revoke.** On B, call `mesh_pairing_revoke_plan` with
    `pairing_id` set to B's pairing id, and read `confirmation`. Refuse with
    `revoke plan returned no confirmation` if it is empty. Call
    `mesh_pairing_revoke_commit` on B with the same `pairing_id` and
    `"confirm"` set to that token, and assert `ok` is `True`. Refuse with
    `revoke commit failed`. Poll the second terminal until `state` is `ended`.
    Pass if `close_reason` is `revoked` or `verdict` is `closed`. Refusals:
    `the revoked pairing did not end the live terminal` and
    `the terminal ended without revoked/closed evidence`. The PASS line is
    `PASS revoke ended the live terminal (reason=<r> verdict=<v>)`.
18. **Refused reopen.** On A, call `mesh_terminal_open` with A's pairing id.
    The admit succeeds locally, so assert `ok` is `True`. The verdict arrives
    as B's signed refusal receipt through the poll. Poll the third terminal
    until `state` is `refused`, and assert `verdict` is `revoked`. Refusals:
    `the post-revoke open never even went out`,
    `post-revoke open returned no terminal id`,
    `the revoked pairing did not refuse the next open`, and
    `the post-revoke refusal is not named revoked`. The PASS line is
    `PASS post-revoke open refused by name (verdict=revoked)`.
19. **Cleanup.** Run `dht_cleanup`, then `dht_assert_no_owned_processes` and
    `dht_assert_ports_rebindable`. Refusal: `cleanup failed`. The final line
    is `ALL MESH TERMINAL ACCEPTANCE PROOFS PASSED`.

**Reused from `tools/dev/node_lifecycle.sh`.** The script sources this file
and adds no lifecycle rules of its own. It takes the work directory
(`dht_make_work`), the port claims (`dht_assert_port`), process-group
ownership (`dht_register_owned_group`, `dht_kill_group`), the RPC readiness
waits (`dht_wait_rpc`), and the cleanup and EXIT trap (`dht_cleanup`). It
also uses the node helpers `dht_anchor`, `dht_mine_empty`, `dht_native`,
`dht_unlock_wallet`, and `dht_backup_wallet`, which are defined there.

**Diagnostics.** Progress and PASS notes print as
`mesh-terminal-acceptance: <message>` on stderr. Polls run until the DHT wait
budget expires and check every half second.

This procedure was last scripted as `tools/dev/mesh_terminal_acceptance.sh`, <!-- doc-path-ok: removed in 46a8af087 -->
removed in 46a8af087; that revision holds the exact text. No automated lane
runs it today.

### Streams

The terminal does not own a wire of its own. It is one **service** on a
multiplexed stream layer that rides the authenticated session: a service
registers a name once and receives open, data, window, close, tick, and
release callbacks; nothing else is exposed to it. Every stream lives in
one table shared by both ends, with initiator parity on stream ids so two
peers opening at the same instant can never mint the same id, and each
stream is pinned to the exact Noise session it was opened on — a frame
arriving on a newer or different connection is not that stream's frame.

Flow control is a credit window. The opener declares the window it will
accept, no DATA frame may exceed the credit the peer has granted, and a
WINDOW frame replenishes it as the reader makes room. A single frame is
bounded well below the bearer's message ceiling, so no one stream can
starve the link, and every peer is bounded by a per-peer stream cap, a
per-peer open cadence, and an idle timeout that ends a stream nobody is
using.

Every refusal is named and closes the stream rather than degrading it:
`stream_link_not_noise` (the link is not an established Noise session),
`stream_peer_unpaired` (no live pairing row grants the capability the
service asked for), `stream_service_unknown` (no service registered that
name), `stream_cap` (the peer already holds its share of the table),
`stream_credit_exceeded` (the peer spent credit it was never granted),
`stream_open_rate` (opens faster than the cadence a single peer is allowed),
`stream_id_parity` and `stream_id_in_use` (an id that is not the peer's to
mint), and `stream_malformed`. A stream that cannot be admitted is never
reserved, and a refusal that cannot be sent is never treated as an
admission.

### Tunnels

A tunnel is not a wire either. It is the second service on the stream
layer, named `tcp`, and one local TCP connection is one stream. The side
that opens a tunnel binds a listener on its own loopback and turns each
connection it accepts there into a stream carrying a fixed header that
names a target port and nothing else. The side that answers dials its own
loopback and only its own loopback: the dial address is a constant in the
code, not a field on the wire, so no payload and no configuration can send
the acceptor anywhere but the machine it is already running on.

**Nothing is allowed by default.** The acceptor consults one local table of
allow rows, each naming exactly one paired peer and exactly one port, with
the operator's own reason for it. No file means no rows; no row means every
open is refused. There is no wildcard port, no port range, and no default
entry, and a row is written on the machine being reached — never by the
machine doing the reaching. Forwarding ssh is therefore one row, for port
22, written by that machine's owner:

```text
z23 dev fleet tunnel allow --peer=<id> --port=22 --why=ssh   # on the far machine
z23 dev fleet tunnel open  --peer=<id> --remote-port=22 --local-port=2222
ssh -p 2222 localhost
```

`z23 dev fleet tunnel list` shows both directions at once: the entrances
open here, and the rows this machine admits for others. `deny` takes a row
back, and `close` drops an entrance and every connection on it.

Bytes move under the stream's own credit and nothing else. A side never
reads more from its socket than the credit it holds, and grants credit back
only as bytes actually reach the far socket, so a program that stops reading
stalls its own tunnel at one chunk instead of growing the node's memory.
Socket close becomes a stream close, and a stream close shuts the socket
down, so neither end can be left holding a connection the other has ended.

The refusals are the tunnel's own, and each names the thing it protected:
`tunnel_target_not_allowed` (no row admits this peer and this port),
`tunnel_peer_unpaired` (no live pairing row names this peer),
`tunnel_dial_failed` (a row admitted the port and nothing was listening on
the loopback behind it), `tunnel_local_bind_failed`, `tunnel_cap`,
`tunnel_no_such_tunnel` (no entrance here carries that id), and
`tunnel_malformed`. The stream layer's own refusals still stand in front of
all of them: an open over a link that is not an established Noise session,
or from a peer with no pairing row, never reaches the tunnel service at all.

### Fleet roster and the game service

An operator's machines are worth something to that operator, and the mesh
is where the fleet becomes visible as a fleet rather than as a list of
addresses. Two surfaces make it usable, and both rest on a rule the mesh
already keeps: never confuse what a peer established with what a machine
claimed.

`z23 fleet roster` answers, from the durable pairing and observation
projections under a datadir opened read-only, which machines this operator
paired and what each has proved. Every row carries the chain identity
fingerprint, a short Noise fingerprint, the pairing state, and two
separate fact arrays that never share a field: `verified` holds only facts
a peer established, each with the time that observation was made, and
`self_reported` holds the facts a machine states about itself. A fact this
node has no observer for comes back unobserved with the reason — an
unobserved fact is not a false one, and the roster says which it is
rather than flattening both to a silent false. The leaf dials nothing,
probes nothing, writes nothing, and asks no running node anything, so an
operator can point it at a copied datadir and the copy's hash still
describes it afterwards. It refuses an operator with no pairing at all
instead of rendering an empty fleet, and refuses two rows carrying one
chain identity instead of counting one machine as two. It is never
reachable remotely: naming every machine an operator runs is the map an
attacker would want before choosing a target.

What a verified fact is worth in a game is written in
`engine/composition/fleet_airship_rules.def` and nowhere else. Each fact
declares whether a peer observed it or the machine reported it, each rule
says how many in-game assets that fact earns and carries the sentence
saying why, and `check-fleet-airship-rules` refuses any edit that would
pay for a self-reported claim, name a fact or asset no row declares,
dress a zero row up as an observation, or leave the table paying nothing
at all. Today the mesh peer-verifies exactly one thing — whether a dial to
a machine connects — so a reachable machine earns an airship, a machine
answering on two independent paths earns an escort, and the core count,
the free disk and the build identity each earn zero, written down as rows
so the decision is visible rather than looking like an oversight. When a
challenge-response makes one of them peer-verifiable, that row's
verification changes and its count can rise in the same edit.

The roster returns that table with its answer. Every rule, including the
sentence saying why it pays what it pays, rides in the same reply as the
counts it produced, so an operator reading a zero can see the reason
without being sent to a file to find it. A number nobody can account for
is how a reward scheme stops being believed.

The `game` service is how two fleets meet. It registers on the stream
layer beside the terminal, so a match rides the Noise session and the
pairing that already exist: no new listener, no new port, no second
identity. Five frames and nothing else — `HELLO` (who is talking and which
roster they will send, carried in the stream open itself), `ROSTER` (the
sending fleet's machines and what each earned, verified fields only),
`MATCH_OPEN` (the shared seed and the airship count the match will fly),
`MATCH_STATE` (one tick and one opaque pose per airship), and
`MATCH_CLOSE` (the named end). There is no game inside the service: no
physics, no simulation, no scoring, no roster generation, which is what
lets the game change without the wire changing.

Each refusal ends the stream with its own token in the close payload, the
same token the log prints: `game_unknown_kind`, `game_malformed`,
`game_sequence` (a frame arriving where the session is not),
`game_hello_identity_mismatch` and `game_roster_identity_mismatch` (a
fleet may only ever claim its own machines), `game_roster_overflow`,
`game_asset_vocabulary` (a roster counting assets this build does not
declare), and `game_state_overflow` (a state frame carrying more airships
than the match declared). The peer's identity comes from the local pairing
row that authorized the stream — the same row the terminal lane reads —
and the wire is only ever compared against it. An idle match is reaped by
the stream layer's own timeout; the service adds no clock.

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
8. in progress: the signed bounded capability lifecycle codec and sticky local
   grant revocation exist; the private-object encryption context no longer
   depends on the later ciphertext-bound grant identifier. Add a canonical
   private-object template rooted by the proposal, then target-side
   plan/commit, renewal, remote cancellation/revocation acknowledgement, and
   two-host agreement for the next typed operation;
9. in progress: the encrypted private-object envelope, resumable ciphertext
   receiver, and durable terminal cancellation exist; add the dispatcher,
   atomic no-clobber plaintext publication, and signed receipts before any
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

## Completion rule

The sovereign machine mesh is ready only when the acceptance above runs from a
clean checkout, records exact binary and source identities, and succeeds without
a central controller. Unit tests, simulated peers, a successful transfer, or a
four-node status display alone do not prove the user outcome.
