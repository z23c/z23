# Power-Node Architecture Contract

The stable architecture and observability contract for a Z23 power
node: one C23 process serving chain state, application services, onion-hosted
surfaces, ZClassicDNS name resolution, and typed native commands. A contract, not an
implementation plan.

## Scope

Authoritative references:

- `CLAUDE.md` — current power-node feature set (full chain node, embedded Tor
  hidden service, fast sync, MVC web framework, ZSLP, Sapling, games, and store).
- `engine/services/README.md` — service-layer boundary.
- `engine/modules/event/include/event/event.h` — event taxonomy.
- `engine/composition/commands/*.def` — typed native command catalog.
- `engine/controllers/src/*_native_handlers.c` — command handler bodies.

Consensus, P2P wire parsing, rendering, and application orchestration stay
separated. Services may coordinate work and expose status, but must not define
consensus rules, parse raw P2P messages, render HTML/JSON, or dispatch routes.

## node_state_api

`node_state_api` is the process-wide persisted state contract backed by the
SQLite `node_state(key, value)` table: durable node cursors and small binary
checkpoints — schema version, best-block pointers, wallet scan cursors, UTXO
commitments, MMR/MMB state, snapshot metadata, Sapling tree state.

Invariants:

- Keys are named, versioned contracts. New keys must document owner,
  byte format, writer, reader, and rollback behavior before production use.
- `node_state` stores state snapshots and cursors only. It must not become an
  append-only event log, cache table, or opaque dumping ground for large
  domain records.
- Writes that advance chain, wallet, or snapshot state must be atomic with the
  data they point at. A persisted cursor must never reference unavailable block,
  UTXO, wallet, or Sapling data.
- Readers must treat missing keys as a recoverable cold-start condition unless
  the owning subsystem explicitly marks the key mandatory for that phase.
- Native commands and controller reads may report `node_state` values, but mutation remains
  behind the owning subsystem APIs.

Concrete files: `docs/spec/schema.sql`, `engine/models/src/database.c`,
`contexts/wallet/modules/wallet/src/wallet_sqlite.c`, `core/modules/coins/src/utxo_commitment.c`,
`engine/modules/storage/src/coins_view_sqlite.c`, `engine/composition/src/boot.c`.

## service_registry

`service_registry` is the boot-time ownership contract for services under
`engine/services`. Services are long-lived orchestration units: sync workflows,
snapshot lifecycle, wallet indexing/rescan, health/status aggregation,
explorer query aggregation, peer policy.

Invariants:

- Services own orchestration and status snapshots, not consensus validity,
  raw network message formats, or view rendering.
- Service startup must be idempotent. Registering or initializing the same
  service twice must leave one coherent owner, not duplicate workers.
- Services that run background work must expose a bounded status snapshot for
  `z23 status`, `z23 ops health`, or domain-specific native commands.
- Service failures must be observable through events and/or health status.
  Silent loops are contract violations.
- Service APIs must state thread ownership for mutable state and must avoid
  returning borrowed pointers across worker-thread boundaries.

Concrete files: `engine/services/README.md`, `engine/composition/include/config/runtime.h`,
`engine/composition/src/boot_services.c`, `engine/services/src/node_health_service.c`,
`engine/services/src/snapshot_sync_service.c`,
`engine/conditions/src/sync_state_stuck.c`.

## Onion Gateway

The onion gateway is the Tor-hidden-service ingress for the same surfaces
served locally. With `-tor`, the embedded Tor runtime publishes an ephemeral
`.onion` service and routes requests through dynhost into the normal
controller stack.

Invariants:

- Onion ingress must call the same controller/business logic as local HTTP or
  internal routes. It must not fork a second app implementation.
- Onion status must be visible through health/status surfaces, especially
  `z23 core status` and node UI status views.
- Onion request handling must preserve normal authentication, permission, and
  destructive-action rules.
- Directory publishing must expose only intended discovery metadata: onion
  address, optional clearnet endpoint, height, and version.
- The gateway must not bypass consensus, wallet, database, or command authorization.

Concrete files: `core/modules/net/src/onion_service.c`,
`core/modules/net/src/tor_integration.c`, `core/modules/net/src/https_server.c`,
`engine/controllers/src/network_controller.c`, `CLAUDE.md`.

## ZClassicDNS

`ZClassicDNS` is the human-readable naming contract built on ZCL Names (ZNAM)
— see `CLAUDE.md` ZNAM for the feature surface. Names are on-chain records
resolving to `.onion`, shielded, transparent, or text/content targets. The
DNS-like layer is resolution/routing convenience; the authoritative registry
is chain data.

Invariants:

- Name registration and update commands must be represented as on-chain ZNAM
  operations. Off-chain caches may accelerate reads but cannot become
  authoritative.
- Names must retain the existing syntax contract: 1-63 lowercase
  alphanumeric-or-hyphen characters, first-come-first-served ownership.
- Resolution APIs must distinguish absent names, malformed names, and records
  that exist but lack the requested target type.
- Messaging and app routing that use names must resolve through the ZNAM
  controller/library path, not ad hoc string maps.
- Multi-coin and text/content records must remain typed. A `.onion` target must
  not be silently treated as a payment address, and payment addresses must not
  be treated as routable hosts.

Concrete files: `contexts/naming/modules/znam/include/znam/znam.h`,
`contexts/naming/modules/znam/src/znam.c`, `engine/controllers/src/name_controller.c`,
`engine/composition/commands/app_features.def`, `engine/models/src/database.c`.

## Native Command Surface

The native command registry is the typed AI-agent API, divided by domain and
compiled from the declarative command catalog.

Invariants:

- Every command must have a stable dotted path, domain label, description,
  handler, and parameter schema when it accepts input.
- Handlers must validate parameters before dispatching to node RPCs or internal
  services. On failure they must set a structured error body and log context.
- Destructive tools must be explicit and gated by middleware policy. Read-only
  diagnostics must remain safe to call during incident response.
- Command calls must record path, result code, and latency so `z23 ops
  timeline` and `z23 ops metrics` can explain agent activity.
- The `z23 rpc` escape hatch is not the contract for new features. New
  stable functionality should get a typed command.

Concrete files: `engine/modules/kernel/include/kernel/command_registry.h`,
`engine/modules/kernel/src/command_registry.c`, `engine/composition/commands/*.def`,
`tools/command/native_command.c`, and
`tests/harness/src/test_command_registry_catalog.c`.

## Permissions

`permissions` are enforced at endpoint, controller, middleware, and filesystem
boundaries. The power node exposes local, onion, RPC, and native command surfaces, so
checks must sit close to each ingress and repeat before destructive state
changes.

Invariants:

- Read-only status, health, peer, and event surfaces may be broadly available
  unless they expose secrets or wallet-private data.
- Wallet mutation, file-market purchase/offer creation, swaps, name
  registration, peer mutation, rescans, and admin operations require explicit
  authorization or local-only policy.
- Cookie, backup, wallet, Sapling, and private-key material must use strict
  filesystem permissions and must never be returned by diagnostics.
- Onion-hosted views must not weaken local authentication or turn local-only
  actions into remote actions.
- The registry must classify destructive native commands independently from command
  descriptions so wording changes cannot alter permission policy.

Concrete files: `engine/modules/kernel/src/command_registry.c`,
`engine/models/src/authz_policy.c`,
`tests/harness/src/test_rpc_auth_hardening.c`,
`engine/controllers/include/controllers/file_controller.h`,
`contexts/wallet/controllers/src/wallet_controller.c`.

## Event Expectations

`event expectations` are the observability contract. The event log is the
shared explanation surface for networking, sync, validation, chain, boot,
database, model lifecycle, recovery, native commands, wallet backup, disk, mempool, and
integrity behavior. The event/projection model is canonical in
`docs/FRAMEWORK.md`.

Invariants:

- State-machine transitions must emit typed events with old state, new state,
  and reason where applicable.
- Rejections and recoverable failures must emit events with enough context to
  debug from `z23 eventlog` and `z23 getnodelog` without attaching a debugger.
- Long-running services must emit progress or status events at bounded
  intervals and completion/failure events at terminal states.
- Native dispatch must retain bounded request evidence; crash handlers must
  retain recent events; health/KPI surfaces should derive from event-backed counters where
  practical.
- Event payloads are bounded by `EVENT_PAYLOAD_SIZE`; emit compact structured
  text rather than unbounded JSON blobs.

Concrete files: `engine/modules/event/include/event/event.h`,
`engine/modules/event/src/event.c`, `engine/modules/kernel/src/command_registry.c`, and
`engine/controllers/src/ops_native_handlers.c`.

## Change Control

Changing serialized block/transaction formats, consensus constants, P2P wire
formats, or the meaning of existing `node_state_api` keys is outside this spec
row and requires coordinator review. New code should update this contract when
it adds a stable power-node surface, persistent state key, service, permission
class, native command family, or event family.
