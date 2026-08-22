# AGENT_API.md — native API for AI coding operators

The agent interface is the **native command registry** (`z23 <command>`);
[`docs/NATIVE_COMMAND_INTERFACE.md`](./NATIVE_COMMAND_INTERFACE.md) is the primary
reference. Shell wrappers are compatibility shims only. New feature work follows
[`docs/AGENT_ARCHITECTURE.md`](./AGENT_ARCHITECTURE.md): REST resource first,
database schema, ActiveRecord model, validations, relationships, service
workflow, REST route contract, then the native surface.

**The flat `agent*` / `statecatalog` / `dumpstate` / `proofbundle` / `timeline`
commands below are compatibility shims.** They work, but they are not in
`config/commands/*.def` and do not appear in `z23 discover help` — so
"the typed registry is the sole agent interface" and "`statecatalog` works" are
both true. Do not add new flat commands; add a registry leaf
(see [`docs/CODEBASE_MAP.md`](./CODEBASE_MAP.md) §2 "Add a native command").
Everything below the "First calls" table is response-schema transcription that
the running node returns anyway — prefer `z23 discover schema <leaf>` or
just calling the command.

## First calls

| need | native command |
|---|---|
| No-jq command center | `z23 agentops` |
| Bounded diagnosis | `z23 agentdiagnose` |
| Compact live status | `z23 status` |
| Full compatibility status | `z23 agent` |
| Code/docs/test map | `z23 agentmap` |
| Lane topology | `z23 agentlanes` |
| Unified liveness | `z23 agentliveness` |
| Changed files to tests/risk | `z23 agentimpact <files...>` |
| Versioned contracts | `z23 agentcontracts` |
| Fast build contract | `z23 agentbuild` |
| Unified save loop | `make dev-watch [MODE=verify\|check]` (`verify` default; publication modes refuse) |
| Compilation database | `make agent-index` |
| Developer-loop benchmark | `make dev-loop-bench` |
| In-process hot-swap status | `z23 ops state --subsystem=hotswap` |
| Read-only fast-lane plan | `make agent-plan` |
| Combined dev doctor | `make agent-doctor` |
| Generic state dump | `z23 ops state --subsystem=<name>` |
| Registry discovery | `z23 discover help` |
| Dev-lane status | `z23 agentdevstatus` (`make agent-dev-status`) |
| Anchor producer status | `z23 anchorstatus` |
| Operator proof bundle | `z23 proofbundle [anchor_datadir]` |
| Application protocol catalog | `z23 appprotocols` |
| Sovereign service catalog | `z23 servicecatalog [name]` |
| Sovereign operation catalog | `z23 serviceoperations [operation_id|key=value...]` |
| Preferred interface contract | `z23 agentinterface` |
| State subsystem catalog | `z23 statecatalog` |
| Semantic event timeline | `z23 timeline '{"category":"sync","count":50,"since_secs":3600}'` |
| Peer incident view | `z23 peerincidents` |
| Deploy/restart guard | `z23 agentdeployguard [action]` |
| Mirror lag/blocker contract | `z23 getmirrorstatus` |

The native RPC contracts are implemented in `app/controllers/src/agent_controller.c`
for the agent map/build surface, `app/controllers/src/agent_contracts_controller.c`
for the versioned contract registry, and `app/controllers/src/agent_ops_controller.c`
for the focused no-jq command center. `app/controllers/src/agent_diagnose_controller.c`
owns the bounded diagnosis packet. REST currently exposes the public status
contract at `GET /api/v1/agent`. First-call method/schema/command metadata lives in the C-owned registry
`app/controllers/include/controllers/agent_contracts.def`; runtime availability,
the contract registry, the interface capability matrix, the `agentops`
direct/drilldown command lists, and the REST API index's native command
fields consume that table instead of maintaining separate lists. Generic
diagnostic primitives such as `ops state`, `ops logs`, `core storage query`,
and `ops timeline` are registry rows too, so agent command catalogs do not
hand-copy their native names. `agentmap` rows that
are not one-to-one method contracts, such as `compact_status`,
`full_compatibility_status`, `full_status`, and `quality_lanes`, live in
`app/controllers/src/agent_contract_registry.c` with direct native fields
instead of local controller tuples. `agentops` first-call envelope fields
(`schema`, `method`, `native_command`, and `contract_source`) plus
scalar fields such as `diagnose_tool`, `timeline_tool`,
`anchor_status_command`, and `peer_incidents_tool` are grouped in the same file as
`g_agent_field_surfaces`, so the compact no-jq command center also reads
method names from registry data instead of hand-copying them. Registry rows
also own `probe_params_json`; parameterized first-call probes such as `dbquery`
and `eventlog` must declare a bounded sample there instead of adding
method-specific CLI branches. Operator drilldowns exposed by the REST index
(`healthcheck`, `milestone`, and `refold`) also live there, so native and REST
discovery share the same command/schema metadata. Nested first-call schema rows such as
`zcl.first_call_contract.v1`, `zcl.operator_lane.v1`,
`zcl.security_posture.v1`, and `zcl.node_resources.v1` are also registry-owned in
`agent_contract_schema_registry.c` instead of being hand-listed inside the
`agentcontracts` response builder.
The native `z23 -help` agent/operator command section is generated by
`agent_print_native_usage()` from the same registry; do not hand-copy agent
command rows into `src/main.c` usage text.
`z23 status` is the operator-gated real-money first check. It emits a
`zcl.result.v1` envelope with `zcl.status_journey.v1` data: node/sync and
wallet readiness, receive/send capability, custody-authoritative aggregate
money, backup/prover posture, one blocker, and one next action. It contains no
wallet identity, address, path, key, cookie, memo, or grant. The strict lean
chain projection remains `z23 core status brief` / `zcl.core_status_brief.v1`.
The larger `z23 agent` / `GET /api/v1/agent` document uses the distinct
`zcl.public_status.v3` contract.

**v3 names four readiness facts apart.** "Are you ready?" was one blurry
verdict answering four different operator questions, so `zcl.public_status.v3`
reports them separately (flat keys on the `agent` document, flattened onto
`z23 core status brief`):

| key | meaning |
| --- | --- |
| `tip_follow` | keeping up with the network tip (proven height vs tip, **not** the sync FSM's `at_tip` flag) |
| `wallet_view_ready` | wallet readable — keys loaded, canary passed |
| `wallet_spend_allowed` | wallet may spend; false in NO-SPEND mode (no passphrase, no plaintext opt-in) and on borrowed, not-yet-self-folded state |
| `archive_complete` | `complete` \| `incomplete` \| `unknown` — whether every old block body is held |
| `full_replay_verified` | history verified by replay |

Two rules about these:

- **`archive_complete` never gates `tip_follow`.** A complete archive is
  ~13 GB; a 600-second cold sync over 100 Mbps can move ~7.5 GB and needs only
  ~242 MB of it to reach the tip. Making archive completeness a precondition
  for tip-following would turn a reachable target into an arithmetically
  impossible one. `archive_complete: incomplete` alongside `tip_follow: true`
  is the normal shape of a freshly synced node, not a fault.
- **`unknown` is a real value, not a fallback.** It means a census has not
  established an answer. It is never quietly upgraded to `complete`.

Producers (`event_agent_summary.c`, `api_controller_status.c`) emit v3;
`zcl.public_status.v2` remains **fully readable** — the five v3 keys are
optional on the read side, so an older node's document still validates
strictly and still yields a complete brief, just without these facts. Both
versions live in one place, `ZCL_PUBLIC_STATUS_SCHEMA` /
`ZCL_PUBLIC_STATUS_SCHEMA_V2` in
`app/controllers/include/controllers/agent_operator_contracts.h`, shared by
every producer and by the CLI reader that validates them.

First-call recommendation arrays should use
`agent_push_contract_native_command_json()` for registry-owned command names;
keep only parameterized, composite, or subsystem-local commands inline.
Structured command arrays such as `agentlanes.commands` should use
`agent_push_contract_command_json()` for registry-owned commands and keep only
external helper scripts such as `tools/scripts/lane_health.sh --json` inline.
The static no-cookie native commands in `src/main.c` use one
`g_cli_static_agent_routes` table of method-to-handler pairs and only dispatch
routes whose method also exists in `agent_contracts.def`. Do not add a second
allowlist or a parallel `if/else` dispatch ladder for agent commands.
REST application-layer protocol metadata lives in
`app/controllers/src/api_controller_app_protocols.c`; the same rows feed
`z23 appprotocols`, `GET /api/v1/protocols`,
`GET /api/v1/protocols/{name}`, `layer_model`, route-contract
`application_protocol` fields, and generated OpenAPI
`x-zcl-application-protocol` / protocol CRUD extensions for ZLSP, ZSLP, ZNAM,
market, messaging, and script-contract resources. The registry also carries
object types, UX surfaces, projection/reorg behavior, cryptographic model,
transport model, privacy model, and diagnostics surface, so agents can reason
about what the node can safely read, construct, rebuild, expose, and explain
without scanning per-feature prose first. Treat
`zcl.application_protocols.index.v2` as the layer-2 overlay catalog: ZCL
remains the base layer; z23 exposes ZLSP-style versioned application
services that read, index, or construct valid ZCL transactions without changing
consensus rules. ZSLP is the token protocol inside this model; ZLSP is the
broader service/protocol umbrella.

The UX-facing service catalog lives in
`app/controllers/src/api_controller_service_catalog.c` and is exposed as
`z23 servicecatalog [name]`, `GET /api/v1/service-catalog`, and
`GET /api/v1/service-catalog/{service}`. Operations are first-class too:
`z23 serviceoperations [operation_id|key=value...]`,
`GET /api/v1/service-operations`, and
`GET /api/v1/service-operations/{operation_id}` list operations, filter
the operation set, or fetch one stable `service.operation` contract such as
`znam_names.resolve_name`. Server-side filters are exact-match:
`service`, `write_safety`, `preferred_interface`, `status`, and `surface`.
Examples: `z23 serviceoperations service=bootstrap
write_safety=public_read_only` and
`GET /api/v1/service-operations?service=znam_names&surface=rest`. The
collection includes `filter_contract` (`zcl.query_filter_contract.v1`), and
unknown filter names fail closed with `400 invalid_service_operation_filter`
instead of returning an accidentally unfiltered operation list. The same
contract is advertised in `/api/v1` route contracts and `/api/v1/openapi` as
`x-zcl-filter-contract`, so agents can validate query keys before making a
call. Use these
surfaces when the question is "what can this node host, advertise, verify, or
construct for a user?" They distinguish the stable service/operation
contracts from `/api/v1/services`, which remains runtime health.
REST route contracts bind back to this registry when a route is owned by a
REST-callable service operation: `/api/v1` emits `service_contract`,
`service_catalog_route`, `service_operation_id`, `service_operation_route`, and
the embedded `service_binding`; `/api/v1/openapi` mirrors the same operation
object as `x-zcl-service-binding`. Prefer these fields over hardcoded
route-to-service maps.
For bootstrap specifically, public peer listing is
`bootstrap.list_peer_projection` (`GET /api/v1/peers`,
`zcl.peers.index.v1`); peer incident analysis remains the operator diagnostic
operation `bootstrap.inspect_peer_bootstrap_readiness` via
`z23 core network peers incidents`.
The collection schema is `zcl.service_catalog.v2`; the member schema is
`zcl.service_contract.v2`; the operation collection schema is
`zcl.service_operations.index.v2`; operation members use
`zcl.service_operation.v2`. Together they cover names, bootstrap, Tor/onion
discovery, direct P2P, files, market, messaging, script contracts, CRUD
capabilities, transports, verification model, trust model, privacy model, and a
concrete UX story per service. Each service also carries an `operations[]`
array of operation objects that names the action, CRUD capability, REST route
when public, RPC method, native command, input/output contract, authority, execution
surface, write-safety class, and whether the operation is destructive or
operator-private. Each operation also carries `service_catalog_route`,
`agent_preferred_interface`, `agent_next_step`, and `*_callable` booleans so an
agent can choose REST for public reads, native commands for operator/private or
destructive actions, and RPC only when that is the explicit fallback. This is the
no-guesswork path for agents building a UX from names, bootstrap, Tor/P2P,
market, messaging, and script-contract capabilities. The operation collection
also carries `summary`, `service_facets`, `preferred_interface_facets`, and
`write_safety_facets`; read those first when choosing a workflow or rendering a
command palette, then fetch the specific operation contract only for the action
the user selected. Name service-directory reads are first-class:
`znam_names.resolve_service_directory` maps to public REST
`GET /api/v1/names/{name}/services` and returns
`zcl.names.service_directory.v1` without requiring a client to parse the full
name profile.
The collection also carries `sovereign_ux` (`zcl.sovereign_ux_contract.v2`):
a machine-readable flow from agent status → service catalog → ZNAM resolution
→ endpoint verification → direct P2P/onion routing → versioned CRUD operation.
The collection-level `runtime_probes[]` matrix is the compact first-pass live
verification checklist: one row per service with the REST route, expected
schema, operation contract, freshness source, success signal, and failure next
action. It is generated from the same service contracts as member
`runtime_probe`, and tests require every probe route and operation ID to resolve
through the REST/operation indexes.
Each member contract carries `depends_on_services`, `read_model`, and
`write_model`; use those fields instead of hand-inferring service dependencies.
Each member also carries `operation_summary`, a compact count of public reads,
operator-private calls, destructive calls, callable surfaces, status buckets,
and preferred interfaces for that service's `operations[]`. Each member also
has `runtime_probe` (`zcl.service_runtime_probe.v1`): the concrete REST route,
operation contract link, expected response schema, freshness source, success
signal, and failure next action to prove the service is usable on the running
node. Use it before telling a user that bootstrap, ZNAM, onion discovery, file
services, market, messaging, script contracts, or telemetry are live.

ZNAM resolution responses (`zcl.names.show.v1`) normalize service text records
for agents. In addition to raw `text_records`, read `service_records[]` and
`service_directory`: each service record has schema
`zcl.names.service_record.v1`, `service_name`, `transport`, `endpoint_kind`,
`endpoint`, `chain_verified`, `reachability_proof`, `service_contract`,
`service_catalog_route`, `recommended_operation_id`,
`service_operation_route`, `service_contract_known`,
`service_operation_required`, `service_operation_known`,
`contract_resolution_status`,
`contract_resolution`, `runtime_probe`, `endpoint_validation`,
`endpoint_routing`, `routing_priority`, `endpoint_hint_valid`, and
`next_action`. The nested
`contract_resolution` object is `zcl.names.service_contract_resolution.v1`;
`status=resolved` means the chain-projected service hint maps to a canonical
Zclassic23 service contract and, when present, operation contract. Unknown
service hints remain visible but are explicitly marked `service_unknown` so
agents do not treat arbitrary text records as trusted node capabilities. The
nested `runtime_probe` is the same `zcl.service_runtime_probe.v1` object
exposed by the service catalog member, so agents can verify the live route
without a second lookup. `endpoint_validation`
(`zcl.names.endpoint_validation.v1`) fails closed on malformed hints while
leaving the chain record visible; `endpoint_routing`
(`zcl.names.endpoint_routing.v1`) gives the preferred transport, fallback
transport, and priority for direct P2P vs onion decisions. When a client only
needs routing records, use the
dedicated subcollection `GET /api/v1/names/{name}/services`; it returns
`zcl.names.service_directory.v1` with `name_route`, `self_route`,
`operation_id=znam_names.resolve_service_directory`, concrete
`operation_route`, and the same
`records[]`/`endpoints[]` objects. The directory also publishes
`endpoints[]`, `endpoint_count`, `valid_endpoint_count`,
`invalid_endpoint_count`, `supports_onion`, `supports_direct_p2p`,
`supports_bootstrap`, `routing_plan`
(`zcl.names.service_routing_plan.v1`), the service/operation contract route
templates, the runtime probe schema/field name, and a routing policy. Agents
can ask the server to narrow this projection with exact-match filters:
`service`, `service_contract`, `transport`, `endpoint_kind`, `valid`, and
`endpoint_only`. For example,
`GET /api/v1/names/alice/services?transport=p2p&valid=true&endpoint_only=true`
returns only valid direct-P2P endpoint hints, with counts and routing plan
recomputed for that filtered view. Directory responses include
`filter_contract` (`zcl.query_filter_contract.v1`) with the allowed keys,
accepted aliases, and example call. Unknown filter names fail closed with a
structured `400 invalid_name_service_filter` response instead of returning an
accidentally unfiltered directory. The same contract is available from the
REST route index and from OpenAPI as `x-zcl-filter-contract`. The `{name}`
path parameter is also machine-described there as `path_param_contract` /
`x-zcl-path-param-contract` (`zcl.path_param_contract.v1`), pinned to
`znam_validate_name`: 1-63 lowercase ASCII letters/digits/hyphens, no leading
or trailing hyphen. Agents should
verify the
chain-projected ZNAM record first, inspect the linked service/operation
contract and runtime probe, then prefer direct P2P for low latency and fall
back to onion reachability when NAT or firewall conditions require it.

## Preferred Interface

The best interface for an AI coding operator is the native command registry
(`z23 <leaf> [--input=json]`): start with `z23 status` /
`z23 agent` for the compact no-jq command center, use
`z23 agentinterface` when checking the full transport contract, then use
`z23 agentdiagnose`, `z23 agentliveness`, `z23 agentlanes`,
`z23 getmirrorstatus`, `z23 agentimpact`, `z23 agentbuild`,
`z23 dumpstate <subsystem>`, `z23 timeline`,
`z23 appprotocols`, `z23 servicecatalog`, and `discover
help`/`discover search <q>` as needed. REST is the public read-only mirror.

For terminal work, keep the operator path inside the same binary: use native
commands such as `build/bin/z23 status`, `build/bin/z23 dumpstate
supervisor`, or `build/bin/z23 discover help`. Against the dev lane,
`build/bin/z23-dev status` queries the installed dev binary at
`~/.zclassic-c23-dev` on RPC port `18252`. The native command registry is the
sole agent interface.
Use `make agent-plan` before a build when you need the exact no-build fast-lane
decision: changed-path/test classification hints, source-wide compile plan, cache
hit/miss, dev-lane stage/deploy commands, and native command shortcuts.
`build/bin/zcl-rpc getblockcount` and an explicit
`build/bin/zclassic-cli -rpcport=18232 getblockcount` are legacy/debug checks,
not the preferred agent interface. Do not use bare `build/bin/zclassic-cli` as
a z23 status oracle: local defaults, cookies, datadirs, or environment
can point it at another RPC target and create a false "z23 is behind"
diagnosis. If a height/peer answer matters, the target lane must be explicit in
the command or supplied by the C-owned agent surface (`z23 agent`,
`z23 agentdiagnose`, or `z23 getmirrorstatus`).

The transport can vary, but the payload should not: AI-facing status surfaces
return stable JSON objects with a `schema` or an explicit command contract, and
they must identify the running node source with `source_id_sha256` whenever
deploy drift would change the interpretation of state. `build_commit` remains
additive display-only GitHub trace metadata. `getmirrorstatus` follows this
rule so an operator can distinguish a stale runtime binary from current source
or a freshly deployed dev lane.

`getmirrorstatus` also includes `mirror_contract` (`zcl.mirror_status.v2`).
Agents should prefer it over string-scraping top-level legacy fields. It names
that the mirror is advisory-only, the local consensus authority, whether the
mirror is running/reachable, and whether lag is known. Tip hashes are comparable
only when both tips are at the same height. When one node is behind, the
`comparison_*` fields instead bind both hashes to one explicit common height;
`comparison_known=true` plus `comparison_hashes_agree=true` is evidence of the
same chain at that height. `hash_disagreement_height` is a recovery floor, so
agreement below a previously observed mismatch cannot clear it. Unknown or
failed comparison RPCs never count as agreement. The contract also names
whether a blocker is active and whether operator action is required.

`agentliveness` (`zcl.agent_liveness.v2`) is the one-call runtime liveness
rollup. Its default mode is compact: it composes `current_runtime_lane`,
observed runtime listeners, compact `runtime_availability`,
`supervisor_state`, and `background_quality_status` count fields, then adds
direct fields such as `overall_liveness`, `agent_next_action`,
`liveness_summary`, `recommended_drilldowns`, `omitted_sections`, and
`full_mode_command`. Use `z23 agentliveness full` when you need embedded
`runtime_availability.methods[]`, supervisor `domains` / `root_orphans`, or
background quality `lanes[]`. Its top-level `schema`, `method`,
`native_command` and `contract_source` fields are populated from
`agent_contracts.def`, not handwritten in the controller.
`runtime_services` is only the producer process' in-process listener state;
when a native static command has successfully probed a target lane over RPC,
`runtime_availability` marks `target_rpc_reachable=true`,
`liveness_summary.effective_runtime_reachable=true`, and
`liveness_summary.effective_runtime_scope="target_rpc_probe"`. This keeps
`producer_runtime_state="inactive_or_static_probe"` from being mistaken for an
offline target lane. Use it when deciding whether a lane is alive, stalled,
missing quality verdicts, or merely being inspected from a static binary outside
a running node.

`agentdiagnose` (`zcl.agent_diagnose.v2`) is the bounded "what should I look
at next?" packet. The default mode is compact: it uses cheap `agent` status,
peer lifecycle incident summary fields, advisory `getmirrorstatus`, and
explicit drill-down commands while staying inside `zcl.first_call_contract.v1`.
`z23 agentdiagnose full` expands the packet with
embedded `agent`, bounded `healthcheck`, `peer_incidents`, mirror, and timeline
objects. Its
top-level `schema`, `method`, `native_command`, and
`contract_source` fields come from `agent_contracts.def`. The response
duplicates the decision fields agents need most (`verdict`, `safe_next_action`,
`gap`, `peer_count`,
`peer_incident_count`, `duplicate_host_group_count`,
`peer_host_incident_count`, `peer_host_count_returned`, `peer_primary_host`,
`peer_primary_host_issue_class`, `peer_primary_host_next_action`,
`peer_primary_host_direction`, `peer_primary_host_mixed_direction`,
`peer_primary_host_bootstrap_readiness`,
`peer_primary_host_fast_sync_readiness`,
`peer_bootstrap_readiness`, `peer_fast_sync_readiness`,
`peer_bootstrap_blocker`, `peer_fast_sync_blocker`,
`peer_primary_host_incident_score`, `peer_primary_host_issue`,
`peer_incident_severity`, `peer_stability_blocker`,
`peer_material_incident_count`, `peer_material_group_count`,
`peer_informational_incident_count`, `peer_incident_summary`,
`mirror_status`, `mirror_severity`, `mirror_advisory_only`, and
`mirror_operator_action_required`) and
marks skipped lower-priority sections as `partial_result=true` instead of
hanging. Use it before raw logs when the node is behaving oddly but still
answers RPC.
`z23 agentdiagnose` and `z23 agentdiagnose brief` use the compact
first-call shape: it
preserves the top-level verdict,
safe next action, peer/mirror counts, compact `peer_primary_host_issue`,
findings, and recommended commands while omitting the embedded `agent`,
`healthcheck`, `peer_incidents`, `mirror`, and `timeline` drill-down objects.
The response includes `detail_mode`,
`embedded_drilldowns=false`, `omitted_sections`, and a `full_mode_command`
that expands to `z23 agentdiagnose full`.
For chain status, `agentdiagnose` follows the same `zcl.agent_readiness.v1`
contract as `agent`: a small non-material tip gap remains healthy when
`chain_serving_ready=true`. It also echoes `chain_readiness_status` and
`height_contract_status` so agents can tell normal lookahead/minor lag from a
real serving blocker without re-parsing the embedded `agent` object.
For peer readiness, `peer_bootstrap_readiness=ready` means at least one current
handshaked peer has `NODE_NETWORK` and an advertised height. Any other value
sets `peer_bootstrap_blocker=true`, escalates the peer finding to attention,
and makes `safe_next_action=inspect_peer_lifecycle_bootstrap_readiness` unless
a higher-priority chain/operator issue exists. `peer_fast_sync_blocker=true`
with bootstrap ready means the node has usable peers but no current z23
fast-sync-capable peer; that is `info` unless material reconnect/duplicate
incidents are also present.
Raw peer `advertised_height` values are telemetry, not proof of bootstrap
usefulness. Treat `advertised_height_trust=trusted` /
`advertised_height_trusted=true` as the compact signal that the height came
from a current handshaked `NODE_NETWORK` peer; `untrusted_missing_NODE_NETWORK`
means the peer reported a height but did not advertise the service bit needed
for bootstrap. Host-level `advertised_height_trust` can also be
`split_bootstrap_capabilities` when one current connection has the service bit
and another has the height, but no single connection has both.
Public REST `GET /api/v1/peers` is the lightweight collection for explorers
and simple agents. Each row keeps the persisted projection flag as
`projection_is_zcl23` and adds live lifecycle evidence when available:
`live_peer`, `live_zclassic23`, `bootstrap_readiness`, `fast_sync_useful`,
`live_lifecycle`, and `zclassic23_verified_by`. The row-level `is_zcl23` is
the resolved verdict (`projection_is_zcl23 || live_zclassic23`), and
`zclassic23_projection_stale=true` means the live handshake has already proven
Z23 support even though the persisted peer projection has not refreshed.
`peer_incident_severity=info` means the raw peer lifecycle view still has
forensic detail, but there is no duplicate/reconnect storm and the overall
verdict can remain healthy. `peer_incident_severity=attention` means the
incident view found material duplicate, reconnect, timeout, reject, or no-peer
signals and `safe_next_action` will point at a host-specific
`peer_primary_host_next_action` when the compact host scorer can name one;
otherwise it falls back to the generic peer-lifecycle drill-down.
For a peer-only packet without the rest of `agentdiagnose`, use
`z23 peerincidents`; the generic fallback is
`z23 ops state --subsystem=peer_lifecycle --key=incidents`. The first-class response schema is
`zcl.peer_incidents.v2` and is bounded by design: it returns aggregate incident
counts, `primary_host_issue`, top per-host incidents, duplicate host groups,
last disconnect reasons, service flags, advertised heights, and bootstrap /
fast-sync usefulness without requiring log scraping. The native handler
adds registry-owned `method`, `native_command`, and
`contract_source` fields, and the full-mode embedded
`agentdiagnose.peer_incidents` object carries the same identity fields.
Host-level objects expose
`direction`, `mixed_direction`, `current_open_direction`,
`current_handshaked_direction`, and per-direction current open/handshaked
counts so reconnect storms that mix inbound ephemeral ports with outbound
dial attempts are visible without expanding the full peer list.
Host-level objects also split raw advertised-height counts into
`handshaked_trusted_advertised_height_connections` and
`handshaked_untrusted_advertised_height_connections`, and expose
`advertised_height_trust` so agents can see whether the host has a usable
bootstrap height, only an untrusted height report, or split capabilities across
multiple current connections.
Its top-level `bootstrap_readiness`, `fast_sync_readiness`,
`bootstrap_blocked`, `fast_sync_blocked`, `incident_severity`,
`stability_blocker`, and `safe_next_action` are the no-jq verdict fields.
`bootstrap_readiness` uses `ready`, `no_current_open_connection`,
`no_current_handshaked_connection`, or `no_bootstrap_useful_peer`.
`fast_sync_readiness` is `ready`, `no_zclassic23_fast_sync_peer`, or the active
bootstrap blocker. `incident_severity` only scores incident pressure;
`stability_blocker` also becomes true for bootstrap blockers.
Likewise, `mirror_severity=info` means the advisory zclassicd mirror is worth
watching but is not a local-node stability blocker; only
`mirror_operator_action_required=true` escalates the overall diagnosis. Use
the typed native `z23 getmirrorstatus` command for the full mirror
contract.

`anchorstatus` (`zcl.anchor_mint_status.v1`) is the offline/static status
packet for the sovereign UTXO anchor producer. Run
`z23 anchorstatus /path/to/anchor-datadir` against an
anchor-mint datadir to read the kernel store (`consensus.db`, or `progress.kv`
on a pre-flip datadir — resolved via `consensus_db_kernel_store_path()`)
directly without cookies, jq, Python, or a running service RPC. It reports the
anchor checkpoint, stage cursors,
durable coins frontier, validated backlog, stale header rows above the anchor,
snapshot presence/size and verified payload SHA3, a compact `summary`, and
`agent_next_action`. It emits an ETA only when at least 60 seconds of monotonic,
durable `utxo_apply_log.applied_at` samples exist. It never derives an ETA from
mtime or process uptime and never opens the producer database writable.
Producer recency is separate: `progress_activity_*` selects the newest of the
kernel-store main DB (`consensus.db`, or `progress.kv` on a pre-flip datadir),
its `-wal`, and the latest durable UTXO sample — `progress_activity_source`
reports the actual basename it came from rather than a hardcoded name. Its
stale budget
is the greater of 300 seconds or twice the observed durable sample interval,
bounded at one day. An offline packet without process identity requests
liveness/activity inspection; file age alone never recommends a restart. Its
`producer_import_preflight` pins the only valid preparation order:
`BIN --importblockindex "$HOME/.zclassic" "$MINTDIR/node.db"`.
`--importblockindex` must be argv[1]; placing `-datadir` first launches a normal
node. `body_position_preflight` also fails loud on the header-only/body-gap
shape because imported block-index offsets are trustworthy only with the exact
source `blk*.dat` corpus, not a filename-matched foreign copy.

`proofbundle` (`zcl.operator_proof_bundle.v2`) is the read-only evidence
artifact command for agents. Run
`z23 proofbundle /path/to/anchor-datadir` to collect live
`agent`, `milestone` / `zcl.mvp_operator_proofs.v1`, `refold`,
`anchorstatus`, `agentlanes`, and `agentdevstatus` payloads into one JSON
object. Redirect stdout when a durable artifact is needed; the command itself
does not mutate services or write files.

`z23 agentinterface` is the machine-readable
entry point for that rule. In addition to the human summary, it emits a
top-level `build_commit`, a `runtime_identity` block for the binary that
produced the interface contract, a `capabilities[]` matrix that names each
first-class agent operation, its schema, and its native/REST transport,
including the `zcl.mirror_status.v2` mirror lag/blocker contract, plus
a `machine_contract` block declaring that payloads are JSON objects with
required `schema`, `api_version`, and `status` fields. Those nested shapes are
versioned as `zcl.agent_runtime_identity.v1`, `zcl.agent_capability.v2`, and
`zcl.agent_machine_contract.v2`. Future operator APIs should extend that matrix
before adding new wrapper behavior.

`capabilities[]` is registry-owned: canonical rows and append-only v1 aliases
are emitted through `agent_push_contract_capability_json()` from
`agent_contracts.def`, so `method`, `schema`, `native`, `rest`, and
`contract_source` do not drift between `agentinterface`, `agentcontracts`,
and native CLI help. Alias rows set `registry_alias=true` and name their
`canonical_capability`; keep compatibility aliases there instead of repeating
schema/tool strings in `agent_interface_controller.c`.

`agentinterface`, `agentops`, `agentlanes`, and full-mode `agentliveness` also include
`runtime_availability` (`zcl.agent_runtime_availability.v3`). Native static
first-call commands are
produced by the binary you just ran, but that producer may be newer than the
target lane still serving RPC. The availability block separates those facts:
`producer_source_id_sha256` names the local producer for equality decisions,
`producer_build_commit` is display-only Git trace metadata, and
`availability_scope` says
whether the answer is producer-only or a target RPC probe, and each
`methods[]` entry reports `target_runtime_support` plus the
`probe_params_json` used by the bounded availability probe. If a target returns
`unsupported_method_not_found`, do not call that method on that lane; deploy and
smoke the dev lane first or use methods marked `supported`. If the probe says
`no_cookie` or `connect_failed`, treat target support as unknown instead of
inferring it from source files or local CLI output.
`producer_target_source_relation` compares the two source identities.
`producer_target_build_relation` remains `unknown` until both sides expose
exact artifact and build-epoch identities; equal source bytes alone do not
prove equal compiler inputs or linked executable bytes.

When a native first-call method from the C-owned registry is sent to a target
lane that returns JSON-RPC `-32601`, the CLI prints
`zcl.cli_rpc_diagnostic.v1` instead of a bare "Method not found" line. That
diagnostic includes `producer_source_id_sha256`, `producer_build_commit`,
`target_datadir`,
`target_rpcport`, `probable_cause`, and the same `runtime_availability` block,
so agents can distinguish a stale runtime lane from a missing source route.
This is expected during dev/canonical skew; it is not evidence that the new
method is absent from the producer binary.

No Python is required to consume the preferred agent API. Contract assembly,
status interpretation, changed-file test mapping, and deploy safety decisions
belong in C under `app/controllers/src/agent_controller.c`,
`app/controllers/src/agent_contracts_controller.c`, and
`app/controllers/src/agent_interface_controller.c`; compact
operator/architecture answers that should not require `jq` belong in
`app/controllers/src/agent_ops_controller.c`, then get exposed through native
commands and REST. Registry-backed command groupings for `agentmap` and
telemetry live in `app/controllers/src/agent_contract_registry.c`
(`g_agent_command_surfaces`); `agentinterface` capability rows are emitted
from `app/controllers/src/agent_contract_capability_registry.c`, while
registry-backed nested schema rows live in
`app/controllers/src/agent_contract_schema_registry.c`
(`g_agent_schema_surfaces`). Registry-backed review objects such as
`agentops.architecture_review` live in
`app/controllers/src/agent_contract_review_registry.c`
(`g_agent_review_surfaces`); keep only composite/local commands in the
controller that assembles the response. Ranked `agentops` planning lists
(`api_gaps` and `top_next_work`) live beside them in `g_agent_work_surfaces`
so the compact command center is data-owned by registries, not by response
assembly code. `agentcontracts` also exposes `contract_summary`, generated
from the same registries, so agents can read native/REST declaration
counts plus review/schema-surface counts without scanning the full contract
array. `registry_source` names the contract/command registry and
`review_registry_source` / `schema_registry_source` name the review and nested
schema registries, so API clients can pin reviews to the owning C tables.

## Command Center

For architecture and operator planning, the first call is `z23
agentops`. It returns
`zcl.agent_ops.v2`: direct decision fields, `no_jq_required=true`, current lane
and runtime build contracts, background quality summary fields, named
drill-down commands, direct scalar pointers such as `peer_incidents_command`,
API gaps, the registry-owned `workflow` for the expected agent loop, and the
top next architecture work list. `api_ux` names the preferred drill-down
commands (`z23 dumpstate`, `z23 getnodelog`, `z23
dbquery`, and `z23 ops timeline`) so agents can keep one-off diagnostics
simple before adding new
typed routes. Do not pipe larger discovery payloads through `jq` to build this
answer by hand; add a field to `agentops` when an agent repeatedly needs the
same decision.

The native first-call view is `z23 status`; it composes the lean H*/gap/peer
facts with wallet, receive/send, money, backup, Sapling, mempool, blocker, and
next-action readiness. The chain-only terse projection is `z23 core status
brief`. The expanded `z23 agent`
document returns the running
binary `build_commit`, height/gap, peer summary, active blockers, next action,
and recommended drill-down tools. It also includes
`security_posture` (`zcl.security_posture.v1`), which separates liveness from
security review: `bootstrap_model` names whether the node is still on a
borrowed snapshot path whose anchor location (not state contents) matches the
validated header chain, `snapshot_full_validation_complete`
names whether that seed has been independently validated from history, and
`anchor_history_complete` plus the per-pool anchor activation cursors and
`nullifier_history_complete` / `nullifier_activation_cursor` name whether old
shielded membership/nullifier history is fully covered or needs backfill /
from-genesis refold. Public `serving` and `chain_serving_ready` are false while
security review is required, even if a held diagnostic height exists. In
particular, incomplete anchor or
nullifier history must hold shielded spends fail-closed. The compact packet also includes
`provable_tip_published` and `indexer.block_source_status_cached` so agents can
tell when the first-call fast path intentionally avoided blocking projection
reads during startup or catch-up; use `z23 core status`, `z23
dumpstate <subsystem>`, or `z23 ops mirror` for heavier detail instead
of making `agent` wait on SQLite.
The same fast path uses cached mirror state and an internal optional-detail
budget. If that budget is already spent, `agent.partial_result=true` and
`first_call.partial_result=true`; the core status/readiness/height/peer/mirror
fields remain present, while lower-priority detail such as `resources` and
`restart_watchdog` can be deferred. Follow `first_call.full_mode_command`
(`z23 healthcheck`) when the omitted detail matters.
The native `zcl.operator_snapshot.v3` payload binds both its root and embedded
`zcl.operator_summary.v3`
to the same exact lowercase 64-hex `source_id_sha256`. The projection fails
closed when either identity is absent, malformed, or unequal. Its
`build_commit` fields are optional display-only GitHub trace metadata; they do
not participate in snapshot trust or acceptance.
Legacy native `zcl.operator_snapshot.v1` responses are classified explicitly
as untrusted and rejected; they are never silently reinterpreted as v2. A
target with no `operatorsnapshot` method may still use the marked, non-atomic,
never-healthy multi-RPC compatibility projection.
The first-call packet also includes `runtime_build` (`zcl.runtime_build.v2`),
which exact-compares the running
binary's SHA-256 source identity against deploy-installed intent
(`ZCL_AGENT_EXPECT_SOURCE_ID`). `running_build_commit` and
`expected_build_commit` remain display-only GitHub trace metadata and never
participate in the freshness decision. Canonical post-restart verification
also compares `ZCL_DEPLOY_EXPECT_ARTIFACT_SHA256` with the SHA-256 of the
running service's `/proc/<MainPID>/exe`, closing the same-source/different-
artifact gap. Because Git state is not embedded, `dirty_build_known=false` and
`dirty_build_state="unknown"`; the API never manufactures a clean-tree claim
from display-only Git metadata.
It also includes `operator_latch` (`zcl.operator_latch.v2`), `conditions`
(`zcl.condition_engine_summary.v2`), and `mirror_contract`
(`zcl.mirror_status.v2`). `operator_latch.active` names whether an
`EV_OPERATOR_NEEDED` page is still latched; `operator_action_required` is the
machine decision agents should use before interrupting work. Mirror-only stale
hash-disagreement latches can be marked
`suppressed_by_mirror_contract=true` when the mirror contract proves there is
no active advisory blocker. `conditions` gives cheap active/unresolved counts
and points to `z23 dumpstate condition_engine` for the full registered
condition list, attempts, thresholds, and detail. The operator summary's
`mirror` object exposes `contract_trusted`,
`blocker_active`, and `operator_action_required`; agents should key on those
booleans before any older `blocker` string. When `getmirrorstatus` includes
`mirror_contract.blocker_active=false`, the native operator summary suppresses stale
top-level mirror blocker strings.

`healthcheck` is also a first-call API, but its default shape is bounded:
`z23 healthcheck` returns `zcl.healthcheck.v1` with
`result_completeness="bounded"`, `partial_result=true`, cached fast fields, and
an embedded `agent` summary. Use `z23 healthcheck full` or
`{"mode":"full"}` only when a diagnostic needs the heavier chain evidence,
condition-engine, and chain-advance dumps. Agents should rely on the explicit
`result_completeness` field instead of assuming the default response is the
full evidence tree.
The bounded response duplicates the most important height/readiness fields at
top level and under `checks`: `readiness_status`, `chain_serving_ready`,
`height_contract_status`, `normal_lookahead`, and `sync_fsm_at_tip`. In bounded
mode, `checks.synced=true` means the served frontier is current or in normal
one-block lookahead and the chain surface is serving; `sync_fsm_at_tip` is the
raw legacy sync-state predicate for callers that specifically need it. The
lookahead is normally transient: when its head is fully applied and exactly
matches the best header, the reducer publishes that single head through the
same local-authority anchor used by clean-restart restore. Any failed verdict,
header lead, hash mismatch, or larger H* gap keeps the lookahead unpromoted.

`agent`, default `healthcheck`, `agentliveness`, and `agentdiagnose` also include
`first_call` (`zcl.first_call_contract.v1`): `api`,
`result_completeness`, `partial_result`, `source`, `budget_ms`,
`elapsed_ms`, and `budget_exceeded`. `agent` and `agentliveness` use that
budget to return valid partial JSON responses instead of continuing into
optional detail work after their first-call budget is spent. Default
`agentliveness` sets `partial_result=true` because it intentionally omits
the high-cardinality method, supervisor-domain, and quality-lane arrays; the
full mode restores them for drilldown work.
Default bounded `healthcheck` still preserves top-level deployment contract
fields (`consensus_authority`, `candidate_source`, `candidate_trust`) so
deploy verification and first-call clients do not need to parse nested
diagnostic objects for the node authority posture.

`milestone` (`zcl.milestone_status.v2`) is the v1 progress view, not a second
health authority. Its `live` block is derived from the bounded
`zcl.public_status.v3` agent summary when available and names that with
`live.source="agent_cached_summary"` / `live.source_schema="zcl.public_status.v3"`.
When the agent packet is available, `live.agent_fields_complete=true` means the
milestone live fields are copied from that same agent contract and are regression
tested against a direct `/api/v1/agent` read. If any required first-call field is
missing, milestone sets `live.source="agent_cached_summary_with_fallbacks"`,
`live.agent_fields_complete=false`, and names `live.fallback_source`; if the
agent contract is unavailable entirely, it falls back to the older node-health
snapshot and says so in `live.source`.
The same response embeds `operator_proofs`
(`zcl.mvp_operator_proofs.v1`): one row per MVP criterion with
`proof_command`, `ci_gate`, `proof_scope`, `primary_blocker`,
`local_dependency_required`, and `ci_regression_protected`. This is the
machine-readable version of the `docs/MVP.md` proof table: agents use it to
choose the next MRS-moving command without scraping docs. It does not change
the score; `mvp_readiness_score` still counts only accepted full operator
proofs.

The bounded agent packet may read a cached chain-advance decision for speed, but
it must reject internally inconsistent projection cache data. A stale decision
such as `projection_height=0`, empty `projection_state`, and zero lag while the
served/tip frontier is far above zero is surfaced as
`indexer.projection_state="cached_status_inconsistent"` with
`block_source_status_stale`; it must not lower top-level `indexed_height` or
make milestone/health disagree about a node that is effectively at tip.

When `runtime_build.stale=true`, the node is still useful to observe but its
behavior predates the expected deployed source; use the lane safety contract
before deciding whether to deploy dev or request an operator-gated canonical
restart. If no expected source ID is installed, `runtime_build.freshness` is
`unknown`, not a proof that the binary is current. The same packet includes
reducer frontier telemetry, download queue/in-flight/throughput counters,
recent error state, and precise download age fields:
`download.oldest_in_flight_age_seconds`,
`download.oldest_in_flight_height`,
`download.oldest_in_flight_peer_id`,
`download.overdue_in_flight`, and
`download.in_flight_peer_count`. It also reports
`download.queue_peer_avoid_count` and
`download.queue_peer_avoid_max_seconds` when timed-out block bodies are queued
for immediate retry by other peers while temporarily avoiding the peer that just
failed that exact hash. It reports `download.catchup_stalled` when a
lagging node has active download work but the served frontier has not advanced
for the stall window. It reports `download.dispatch_idle`,
`download.dispatch_stalled`, and `download.dispatch_idle_seconds` when queued
block work is waiting but no block request is currently in flight, so the AI
operator can tell dispatch starvation from ordinary catch-up. Assignment-loop
telemetry is in `download.assign_attempts`, `download.assign_successes`,
`download.assign_zero_results`, and the `download.last_assign_*` fields; the
string `download.last_assign_result` names the last planner result
(`assigned`, `no_queue`, `peer_window_full`, `global_window_full`, `no_slot`,
etc.). `download.dispatch_wakes` counts gap-fill wakeups of the connman message
dispatcher after queue refill or timeout requeue work. Stale in-flight requests
are swept both by the peer send loop and by the supervised gap-fill worker; when
the worker requeues timed-out blocks it wakes the C-native peer dispatcher, so a
connected-but-silent peer cannot own block requests forever. If gap-fill sees
queued body work with zero in-flight requests on a duplicate/no-op refill pass,
it also wakes the dispatcher; queued work is never allowed to sit idle because a
previous wake raced the message-handler wait. `download.message_cycles`,
`download.message_send_calls`, `download.message_process_calls`,
`download.message_recv_ready`, `download.message_idle_waits`, and
`download.message_wakes` expose the connman loop itself. The peer message cycle
sends outbound work before inbound processing, then yields from inbound
processing after a bounded batch (`ZCL_MSG_PROCESS_MAX_PER_CYCLE`) so the
outbound send/assignment phase keeps running even under a large receive backlog
or slow local reducer work. Use `z23 core status`
for the larger health packet, `z23 statecatalog` to discover every state
subsystem and its accepted keys, cost, freshness, owner file, safety level,
tests, and drill-down commands, `z23 dumpstate <subsystem>` for
subsystem internals, `z23 ops timeline` for category-filtered structured event history with bounded
server-side filters, semantic summaries, log-reference hints, type/peer counts,
recommended drill-downs, and seq cursors,
`z23 getnodelog` for bounded log search, `z23 dbquery` for
SELECT-only database inspection, and `z23 eventlog` for the raw recent
event ring.

Every new subsystem that has runtime state should expose it through the
diagnostics registry and become reachable through `z23 dumpstate`. The
same registry feeds `z23 statecatalog`
(`zcl.state_catalog.v2`), so agents can discover the subsystem name,
description, owner shape/file, expected cost, freshness, accepted keys, safety
level, focused tests, and drill-down commands without source search. Expensive
development proof state belongs in a named background quality lane with a JSON
verdict, not in an untracked terminal scrollback.

For "what happened?" questions, start with `z23 ops timeline
--category=sync --count=50 --since-secs=3600` and switch category
as needed (`peer`, `message`, `chain`, `validation`, `condition`, `oracle`,
`mirror`, `boot`, `db`, `wallet`, `disk`, `net`). Use object filters
for `since_secs`, `since_us`, `peer`, `height`, `reducer_stage`, `condition`,
`deploy`, and `lane`; the node scans a bounded retained window server-side
instead of making agents pipe raw events through `jq`. The response is
`zcl.timeline.v2`, includes `head_seq`, and returns `events[].seq` so agents can
tie a timeline slice to later drill-downs. The same payload includes
`semantic_summary`, `type_counts`, `peer_counts`, `log_references`,
`safe_next_action`, and `recommended_drilldowns` so common root-cause triage
stays server-side.

For peer churn, reconnect, or duplicate-entry reports, start with
`z23 core network peers incidents`; use `z23 dumpstate
peer_lifecycle incidents` only as the generic fallback. The first-class command
returns bounded
`zcl.peer_incidents.v2` JSON
with `primary_host_issue`, `top_host_incidents`, flat `primary_issue_host` /
`primary_issue_class` / `primary_issue_next_action` fields, `top_incidents`,
`duplicate_host_groups`, reconnect counts, last reasons,
direction, handshake age, advertised height, service summaries, bootstrap
readiness/usefulness, fast-sync readiness/usefulness, advertised-height trust,
current handshaked service/height/Z23 counts, trusted/untrusted
advertised-height host counts, host `direction` / `mixed_direction`,
current open/handshaked direction summaries, reconnect cadence (`last_reconnect_interval_secs` and
host min/max/latest reconnect intervals), current open/handshaked connection
counts, top-level bootstrap/fast-sync blocker verdicts, and separate
duplicate-host counts for historical entries versus live open/handshaked
duplicates. `primary_host_issue` and `top_host_incidents` are
the no-jq path for reconnect storms where many peer rows share one host; they
collapse the storm to one host-level `issue_class`, `incident_score`,
`next_action`, direction summary, readiness reason, and reconnect cadence.
`host_incident_count` is the total scored host count; `host_count_returned` is
the bounded number included in `top_host_incidents`.
Use the full
`dumpstate peer_lifecycle` only after the compact incident view identifies the
host or peer worth drilling into.

## Operator Lane

`z23 agent` and REST `GET /api/v1/agent` include `operator_lane`
(`zcl.operator_lane.v1`). The lane is normally declared by the node's own boot
context (`-operator-lane=canonical|soak|dev|test|copy`, or
`ZCL_OPERATOR_LANE`) and reports the lane name, runtime profile, datadir, ports,
and machine-readable restart policy. If a systemd override drops the explicit
lane flag, the agent API can still classify a first-class lane by an exact match
against the C-owned topology registry (`datadir + rpcport + p2p_port`). That
fallback reports `lane_source="inferred_exact_topology"`,
`lane_declared=false`, and `lane_inferred=true`; explicit declarations report
`lane_source="declared_boot_context"`.

Use it to distinguish the long-running canonical node from the pinned soak lane
and the restartable development lane. Tooling should branch on the booleans
`canonical`, `soak_evidence`, `development`, and `ephemeral`, not on systemd
unit names or comments.

The lane object also includes `deployment_safety`
(`zcl.operator_deployment_safety.v1`). Automation must read this nested contract
before any restart or binary deployment:

- `automation_restart_ok` / `automation_deploy_ok` — whether an agent loop may
  do the action without an operator confirmation.
- `requires_operator_confirmation` and `guard_env` — the explicit stop sign for
  canonical and soak lanes.
- `protects_public_endpoint`, `counts_for_soak_hours`, and
  `isolated_from_canonical_datadir` — why the lane exists.
- `preferred_deploy_target` and `safe_default_action` — where fresh code should
  go when the current lane must not be disturbed.

Canonical defaults to observe-only, soak defaults to preserving the evidence
window, and dev defaults to `deploy_dev_lane`.

For fast deploy loops and native summaries, the most important lane-safety values
are also duplicated as compact top-level fields on the public agent packet:
`operator_lane_name`, `automation_restart_ok`, `automation_deploy_ok`,
`requires_operator_confirmation`, `preferred_deploy_target`, and
`safe_default_action`. The lane source fields are duplicated there too:
`operator_lane_source`, `operator_lane_declared`, and
`operator_lane_inferred`. They are emitted by the same C helper as the nested
lane object. A canonical packet should therefore say
`operator_lane_name="canonical"`, `automation_restart_ok=false`,
`automation_deploy_ok=false`, and
`safe_default_action="observe_only_or_use_dev_lane"`.

`z23 agentlanes` returns the native
`zcl.agent_lanes.v2` topology contract for all first-class operator lanes:
canonical (`z23`, `~/.zclassic-c23`, RPC 18232 / P2P 8033), soak
(`zclassic23-soak`, `~/.zclassic-c23-soak`, RPC 18242 / P2P 8043), and dev
(`zcl23-dev`, `~/.zclassic-c23-dev`, RPC 18252 / P2P 8053). It also embeds
`current_runtime_lane`, the same `zcl.operator_lane.v1` object used by
`z23 agent`, plus `current_runtime_services`
(`zcl.agent_runtime_services.v1`). The lane object's port fields are the
configured boot intent; `current_runtime_services` separates those configured
ports from observed in-process listeners (`rpc_running`, `https_running`,
`https_bound_port`, `fs_running`, `fs_bound_port`). Use this C-native topology
before deciding where to deploy or restart; use `make lane-health` /
`tools/scripts/lane_health.sh --json` only as the external systemd/RPC
readiness probe that verifies the declared lanes are actually running.

Each lane also embeds `recovery_state`
(`zcl.operator_lane_recovery.v1`), a cheap C-native view over boot-owned
recovery sentinels that affect deploy safety. Today it reports the lane
datadir, `auto_reindex_request` marker path, marker presence, well-formed
status, anchor/count, `auto_reindex_pending`, `auto_reindex_terminal`,
`auto_reindex_malformed`, `deploy_blocker`, `deploy_blocker_reason`,
`explicit_recovery_env`, and `safe_next_action`. A pending marker is a deploy
blocker because a routine restart would consume it and enter a long pre-RPC
`-reindex-chainstate` rebuild. A terminal marker is reported as
`status="terminal_auto_reindex"` but is not pending; it means the bounded
budget already paged the operator and the marker should only be cleared after
repair is proven.

The same public status contract includes `resources`
(`zcl.node_resources.v1`) with cheap process-level RSS, RSS warning threshold,
Linux cgroup memory usage/limits when available, memory pressure (`ok`,
`watch`, `warn`, or `unknown`), `memory_pressure_detail`, pressure basis,
uptime, and source. Cgroup/systemd pressure is preferred over raw RSS because
canonical can have a large steady RSS while still running comfortably below its
service memory guardrails. When cgroup v2 `memory.stat` is available, the node
also reports anon/file/kernel buckets, reclaimable bytes, working set, and
working-set percentages against `memory.high` / `memory.max`. With a cgroup
`memory.high` limit, `watch` starts at 85% of total cgroup usage. `warn` starts
at 95% only when the unreclaimable working set is also near the limit; a high
total caused mostly by reclaimable file cache remains `watch` with
`memory_pressure_detail="cgroup_reclaimable_cache_high"`. Without
`memory.high`, the max limit gives an 80% watch and 90% warn fallback. This is
the first-call place to notice a lane that is still serving but approaching
memory pressure, before reaching for shell-only systemd probes.

The same contract also includes `restart_watchdog`
(`zcl.restart_watchdog.v1`). It is the cheap first-call view over the chain tip
watchdog's bounded restart memory: whether the watchdog is registered, whether
an autonomous no-progress recycle happened in the current episode, the stuck
height anchoring that episode, restart count, restart budget remaining, and the
deep drill-down command (`z23 dumpstate chain_tip_watchdog`). A recent
controlled liveness recycle appears as
`last_restart_autonomous=true`,
`last_restart_reason="no_progress_tip_stall"`, and
`status="restart_budget_burning"`, which lets agents distinguish a deliberate
watchdog remedy from a crash or manual soak rebaseline without scraping
`node.log`.

The top-level status always reports exact `gap`, `index_gap`, and
`target_height`, but it treats normal live-tip churn of up to 10 blocks as
serving-health-compatible. Larger gaps still become `chain_gap` /
`download_queue_idle` and can set `operator_needed`.

The same packet includes `height_contract` (`zcl.height_contract.v1`) so agents
do not confuse height surfaces. Top-level `height`, `served_height`,
`getblockcount`, `getblockchaininfo.blocks`, and P2P `start_height` are the
served/provable reducer frontier H*. `active_tip_height` is the internal
sync-window lookahead tip and may be one block above H* while `tip_finalize`
waits for a canonical successor. If that one-block head is fully applied and
exactly equals the best header, the reducer closes the edge with the same
authority anchor used on clean restart; otherwise
`height_contract.status=normal_lookahead` remains an honest transient status,
not a peer-connectivity failure. `lagging` means the served gap is material and
should be diagnosed with `getsyncdiag` / `dumpstate reducer_frontier`.

The same response includes `readiness` (`zcl.agent_readiness.v1`) so agents do
not have to infer operational safety from the top-level status string alone.
`chain_serving_ready=true` means the chain surface is serving with peers, no
operator-needed latch, no material tip gap, and no material reducer log-head
gap. `index_projection_ready=false` means explorer/projection reads may be
stale even though the chain is still serving. In that case the top-level status
can remain `degraded` with `primary_blocker="projection_lag"`, while
`readiness.status="serving_projection_deferred"` and
`agent_work_ready=true` tell automation that development and diagnostics can
continue without treating the node as down.

The same readiness booleans are also duplicated as compact top-level fields:
`readiness_status`, `chain_serving_ready`, `index_projection_ready`,
`agent_work_ready`, `operator_action_required`, and
`readiness_next_action`. They are computed by the same C helper that builds the
nested readiness object, so shell deploy guards and native callers can read one
flat key without re-parsing nested JSON.
The dev-lane deploy probe declares `AGENT READY` from `agent_work_ready=true`,
so projection lag stays visible without blocking unrelated development work.

`make deploy` is guarded by `tools/deploy_guard.sh canonical-deploy`. The guard
calls the running node's C-native `agentdeployguard` RPC
(`zcl.agent_deploy_guard.v1`) when available and falls back to the systemd
`-operator-lane=` flag only for older running binaries. An active canonical
lane is refused by default; set `ZCL_DEPLOY_ALLOW_CANONICAL=1` only for a
deliberate canonical restart window. `make deploy-dev` is currently contained;
the dev deploy-guard leaf remains a read-only policy diagnostic, not an
activation authority. The deploy-guard response also carries the same compact
lane-safety fields (`operator_lane_name`, `automation_restart_ok`,
`automation_deploy_ok`, `requires_operator_confirmation`,
`preferred_deploy_target`, and `safe_default_action`) so a refusal can be
handled without scraping nested JSON. The native no-RPC form is intentionally
safe by default: `z23 agentdeployguard deploy` refuses until a lane is
declared. Generic `deploy` and `restart` evaluate the current runtime lane.
Explicit lane actions evaluate their named target from the same C topology
registry used by `agentlanes`: `canonical-deploy` / `canonical-restart`
always evaluate `target_lane_name="canonical"` and refuse without an operator
window, while `deploy-dev` / `restart-dev` evaluate `target_lane_name="dev"`
even when the inspected service is canonical. Use
`z23 agentdeployguard deploy-dev` when checking the documented dev-lane
deploy path from automation. The native command prints the same JSON every
time and sets its process exit status from the JSON `exit_code`: `0` means the
guard allowed the action; nonzero means refuse. Scripts therefore do not need
`jq` just to decide whether to continue. `make check-agent-cli` runs the
hermetic executable regression for that contract: it creates isolated HOME
trees, proves a clean `deploy-dev` returns exit `0`, then plants a dev-lane
`auto_reindex_request` and proves the same command returns exit `1`. If the dev
lane has a pending
`auto_reindex_request`, the guard refuses with
`reason="pending_auto_reindex_requires_explicit_recovery_boot"`,
`recovery_deploy_blocker=true`, `recovery_status="pending_auto_reindex"`, and
`explicit_recovery_env="ZCL_DEV_ALLOW_AUTO_REINDEX_DEPLOY"`. Set that
environment variable only for a deliberate recovery boot, or prove the marker
stale before clearing it. `ZCL_OPERATOR_LANE=dev z23 agentdeployguard
deploy` and `z23 agentdeployguard -operator-lane=dev deploy` remain
supported for checking a process already declared as dev.

`make lane-health` is the read-only redundancy check for the canonical, soak,
and dev lanes. `make lane-recover LANE=dev` or `LANE=soak` plans a bounded
noncanonical repair as `zcl.lane_recovery_plan.v1`. Public `--apply` and
`ZCL_LANE_RECOVERY_APPLY=1` are containment probes: they refuse before unit,
datadir, snapshot-copy, drop-in, header-import, daemon-reload, or restart
mutation. The planner also refuses `live`, `canonical`, and `main`. Header
import and snapshot-loader details in the plan are proposed steps only; the
planner is not activation authority.

When lane RPC is reachable, `make lane-health --json` also consumes the native
`agent` contract and exposes `agent_rpc_state`, `agent_source_id_sha256`,
`agent_build_commit`, `agent_contract_trusted`,
`agent_contract_trust_reason`, `agent_status`, `agent_operator_needed`,
`agent_primary_blocker`, `agent_next`, `agent_validation_pack_ok`, and
`agent_validation_pack_detail`. Agent calls use
`ZCL_LANE_AGENT_TIMEOUT` (default 10 seconds), separate from the cheap generic
RPC timeout. `agent_rpc_state` is `ok`, `timeout`, `error`, `empty`, or
`not_called`; a timeout becomes `status=warn` with `reason=agent_timeout`
unless a stronger condition-engine operator page is already active. A current
native `agent` contract
(`agent_contract_trusted=true`, which requires a valid lowercase 64-hex
`source_id_sha256`) with `blocked`
or `operator_needed=true` makes the lane `status=fail` and clears role
readiness, even if basic peer/height/listener checks still look fine. Older
compact agent responses are still printed but do not override lane status by
themselves; lane health falls back to `condition_engine` operator-needed pages
for those runtimes. This keeps the shell lane summary subordinate to the
C-native API without letting stale wrapper-era responses hide or invent a
validation-pack hold. `build_commit` remains display-only GitHub trace
metadata and never grants trust or freshness.

Runtime generation publication is Phase-0 contained. Native
`dev.change.apply`, auto/apply watcher modes, Make
deploy/stage targets, and direct activation scripts all refuse before
mutation; caller-provided source identity is not authority. The one live
runtime surface is the gated swappable-leaf hot-swap (`make hotswap-try` /
`make hotswap-apply`) on the armed `zcl23-dev` lane. `dev.vcs.revert`
is source-only with `relink_generation=false`; `true` refuses before the source
revert. Existing
`zcl.agent_dev_deploy.v1` records and generation links remain readable for
diagnosis, but the activator cannot create a new accepted runtime generation.
The intended immutable source/proof/CAS/rollback transaction must be completed
before these entry points are re-enabled. The activator and
unit are hard-bound to the dev service, datadir, and ports; canonical and soak
targets are rejected.
`make agent-dev-status` / `z23 agentdevstatus` expose the same restart
hazard before deploy as
`deploy_blocker`, `deploy_blocker_reason`, `explicit_recovery_env`, and
`auto_reindex_stale_candidate`. The same response starts with the explicit
`worker_lane` contract (`role=worker`, `mutation_policy=noncanonical_dev_only`,
and `canonical_guard=never_touches_live_or_soak`), so a healthy dev RPC cannot
hide an `auto_reindex_request` or blur the dev lane into canonical/soak.
For a stale candidate, `make agent-clear-stale-dev-reindex` archives the marker
only after the dev RPC is serving at or above the marker anchor and the dev
agent contract is not blocked; it does not restart or mutate canonical/soak.

## Bootstrap Service Status

Use REST `GET /api/v1/bootstrap` or native RPC `bootstrapstatus` before
claiming a z23 node is helping fresh peers
bootstrap. Compatibility alias: `GET /api/v1/bootstrapstatus`. The response is
versioned as `zcl.bootstrap_status.v1` and separates two surfaces:

- `legacy_p2p_bootstrap`: ordinary full-node serving over `version`,
  `getheaders`, `getdata`, `getaddr`, and related P2P messages. This is the
  path used by zclassicd when its beta6 snapshot bootstrap is disabled with
  `-bootstrap=0`, or after its snapshot stage has completed.
- `beta6_snapshot_bootstrap`: the zclassicd v2.1.2-beta6 fast-bootstrap
  snapshot protocol. A compatible server must advertise `NODE_BOOTSTRAP`
  (`1 << 24`) and answer `getbsman/bsman`, `getbschk/bschk`,
  `getbspman/bspman`, and `getbspchk/bspchk`. z23 must not advertise
  that bit until the matching C service is implemented.

The key booleans are `serving_p2p_bootstrap`,
`serving_addr_bootstrap`, `serving_snapshot_bootstrap`,
`zclassic23_fast_sync_compatible`, `zclassicd_beta6_p2p_compatible`, and
`zclassicd_beta6_fast_bootstrap_compatible`. `blockers[]` names missing
requirements such as `not_listening`, `provable_tip_not_published`, or
`beta6_NODE_BOOTSTRAP_not_advertised`.

For a fresh z23 node, consume `readiness`,
`fresh_node_next_action`, and `zclassic23_bootstrap`
(`zcl.bootstrap.zclassic23.v1`) before using peer gossip or ZNAM endpoint
records. That object names whether this node is preferred for fresh z23
bootstrap, the `NODE_ZCL23` fast-sync service bit, the direct-P2P-first route
preference, the ZNAM service-record schema to use for onion fallback, and the
ordered `fresh_node_flow`. The intended UX is: connect to the direct P2P
endpoint when `serving=true`; if direct reachability fails, resolve a
`zcl.names.show.v1` service directory, pick an onion endpoint from
`zcl.names.service_record.v1`, then validate all downloaded data against
normal ZClassic L1 consensus.

The same response also includes `snapshot_loader` (`zcl.snapshot_loader.v1`),
the binary-owned recovery contract for the node's own fast-start bundle:
datadir, highest `utxo-seed-<h>.snapshot`, seed height, matching
`block_index.bin`, failed marker, active `-load-snapshot-at-own-height` path,
and `recovery_hint` (`loader_active`,
`restart_with_load_snapshot_at_own_height`, `install_tip_seed_snapshot`, etc.).
Its nested `authority` object (`zcl.snapshot_loader_authority.v1`) reports the
durable progress-store side of the proof: whether `coins_kv` is a proven local
authority, the `coins_applied_height`, the current reducer H*, whether the coin
set covers H*, whether the fast-rebuild authority surface is ready, and whether
the self-folded sovereignty marker is present. A node can have a bootable
snapshot bundle but still report `fast_rebuild_authority_ready=false` until the
loader/reindex epilogue has seeded `coins_kv`, cursors, and `utxo_sha3`.
Operational scripts should consume this versioned C API instead of scraping
systemd command lines whenever the node RPC is reachable.

## Build loop

This is a C23 project, so the edit loop should compile only what changed.

- `make dev-watch` is the public save-driven loop. It batches a quiet save,
  captures the same `zcl.agent_fast_plan.v1` impact routing used by
  `agentimpact`, performs focused verification, and writes exactly one durable
  `zcl.dev_cycle.v1` verdict. The default `MODE=verify` runs `make ff` and never
  activates a runtime generation. `MODE=check` is also verification-only.
  `MODE=auto`, `apply`, `hotswap`, `reload`, and `stage` return a containment
  refusal; no mode falls through to another activation path. Use
  `make dev-watch-once` for an explicit changed-file batch and
  `make dev-watch-selftest` for the hermetic watcher contract.
- Every watch attempt atomically refreshes
  `~/.local/state/zclassic23-dev/latest-cycle.json` and stores its immutable
  cycle record below `cycles/`. The record names changed files, impact-rule
  hits and mapped tests, selected path and reason, phase timings,
  candidate/running/last-good generations, probes, rollback result, failure
  capsule, and one executable `agent_next_action`. A heartbeat lets
  `zcl.agent_dev_status.v2` distinguish an idle watcher from a dead one.
- Process-activation machinery and its lock under
  `~/.local/lib/zclassic23-dev/` remain in-tree for completion and hermetic
  tests, but every public backend refuses before using them. Neither
  `ZCL_DEV_SOURCE_ID` nor an activation environment switch can authorize a
  runtime mutation. This does not replace strict compile, consensus,
  full-suite, reproducibility, or real-chain gates.
- `make agent-loop` is the manual one-shot AI/operator edit loop. It runs the
  cache-aware `make fast-ci` checks; set `ZCL_AGENT_LOOP_BIN=1` to also link
  `build/bin/z23-dev`. `ZCL_AGENT_LOOP_DEPLOY=stage|dev` cannot bypass
  containment; the downstream stage/deploy entry point refuses.
- `make agent-plan` is the read-only fast-lane decision packet
  (`zcl.agent_fast_plan.v1`). It reports changed-path/test classification hints,
  unmapped code changes, the source-wide compile plan, green-input cache hit/miss,
  dev-lane stage/deploy commands, and native command shortcuts.
- `make immutable-history-canaries` runs the fast real-chain consensus KATs:
  the h=478544 125,811-byte canonical transaction fixture
  (`domain_consensus_tx_structural`) plus `consensus_parity`. Use it whenever a
  bounded consensus predicate changes before paying the heavier
  `make replay-canary-anchor` / `make replay-canary-genesis` gates.
- `make build-only` compiles all node objects without linking. It uses
  `build/obj/epochs/<compile-epoch>/` plus complete depfiles (`-MD -MP` and
  included `.d` files). A source mutation selects a fresh object tree;
  `ccache`/`sccache` recovers unchanged translation-unit work.
- `make fast-changed-compile` is a compatibility name for the source-wide dev
  compile proof. Changed paths are classification hints only; every current dev
  source resolves through `make fast-compile` in the exact compile epoch.
- `make fast-compile` is the cheapest no-link edit-loop compile check. It uses
  the exact non-LTO dev object tree
  (`build/dev-obj/epochs/<compile-epoch>/`) and skips the final executable link,
  so it is the right first command for "does the current C source compile?".
- `make fast-rebuild` builds the local non-LTO node binary and is the preferred
  edit-loop rebuild target. It is an alias for `make dev-bin`, with a clearer
  name for agents and operators.
- `make dev-bin` builds `build/bin/z23-dev` from cached objects under
  `build/dev-obj/epochs/<compile-epoch>/`. It first links an exact immutable
  candidate under `build/bin/dev/epochs/<compile-epoch>/`, then atomically
  refreshes the stable alias after final source/compiler/session verification.
  It links without LTO, keeps symbols, defaults most code to
  `ZCL_DEV_OPT=-Og`, and keeps hot consensus/crypto/script/validation buckets
  at `ZCL_DEV_HOT_OPT=-O2`. `ZCL_DEV_LINKER` probes for `mold`, then `ld.lld`,
  then `ld.gold`, and expands to **empty** only when none is on `PATH`. That
  means dev links otherwise fall back to the platform linker with no speedup
  and no warning. Check the resolved choice with
  `make -sp 2>/dev/null | grep -m1 '^ZCL_DEV_LINKER'` (or
  `command -v mold ld.lld ld.gold`). Set it empty to force the platform linker
  explicitly. This binary is for local agent/API iteration, not deploy or
  release.
- `make agent-dev-status` is the no-build dev-lane status command. It reports
  the lane's explicit `worker_lane` contract (`role=worker`,
  `mutation_policy=noncanonical_dev_only`, safe status/deploy/stage/recover
  commands, and the guard that it never touches live or soak),
  the source and installed dev binaries, `zcl23-dev` linger service and RPC
  state, current/running/last-good/staged generations, exact-running-identity
  match, activation lock, rejected generations, rollback availability, saved
  deploy state, current `zcl.dev_cycle.v1`, watcher heartbeat, latency-SLO and
  background-quality freshness, auto-reindex state, deploy blocker/reason, and
  the next safe action. Use `make agent-dev-status ARGS=--json` for
  `zcl.agent_dev_status.v2`;
  use `z23 agentdevstatus` for the first-class native contract.
- `make agent-clear-stale-dev-reindex` archives a proven-stale dev-lane
  `auto_reindex_request` after the dev RPC serves at or above the marker anchor.
  It does not restart the lane and never touches canonical or soak.
- `make agent-dev-recover` emits a read-only recovery plan. Public
  `ARGS=--apply`, direct recovery apply, and the former recovery test-mode
  environment variable all refuse before relinking a generation, replacing a
  datadir, or invoking a service command. Only the fixture-bound
  `make dev-recovery-selftest` can exercise that retained machinery.
- `make agent-doctor` is the no-build combined development check. It reports
  build binary identity, dev-lane status, the embedded `zcl.agent_fast_plan.v1`
  fast-lane decision, recent focused-test failure hints, dirty-file count,
  native shortcuts, and a single next safe command. Use `ARGS=--json` for
  `zcl.agent_doctor.v1`.
- `make agent-stage-dev` is contained and always refuses before building or
  moving `staged`. The same is true of `deploy-dev*` and
  `agent-deploy-fast`.
- `make agent-index` atomically generates root `compile_commands.json` from a
  dry-run of the actual `DEV_OBJS` recipes. It keeps the real C23 flags,
  generated headers, compiler/cache wrapper, output object, and target-specific
  normal `-Og` versus hot consensus/crypto/script/validation `-O2` profile.
  Hash/freshness metadata lives under `.cache/zcl-agent-index/`. clangd is an
  optional consumer; generation and freshness reporting work without it.
- `make dev-loop-bench` writes `zcl.dev_loop_bench.v1` with configuration,
  source/host identity, per-case raw millisecond samples, failures, p50/p95,
  and separate hot-swap/reload SLO verdicts. With `ZCL_DEV_BENCH_ACTIVATE=1`
  the hot_swap case measures the REAL dev-lane path
  (`make hotswap-apply HANDLER=core.status`, resident leaf re-point in the
  armed `zcl23-dev` node); process-reload still needs an operator-supplied
  fixture command because generation publication remains contained.
- `zcl.hotswap_manifest.v2` currently admits only stateless native leaf sets. A
  load validates schema/host ABI, capabilities, build/source identities, exact
  input hash, mapped tests/probes, stateless state schema, and quiescence before
  generation code runs. It stages all route replacements, runs the generation
  self-test, and publishes one immutable resident router snapshot; any failure
  publishes zero replacements. REST, diagnostics, services, models, storage,
  events, conditions, supervisors, wallet/network/crypto state, reducers,
  consensus, and process/bootstrap ownership remain `reload_required`.
  Successful generations stay mapped so in-flight calls finish against their
  original code. Inspect provenance and rejection detail through
  `z23 dumpstate hotswap`, schema `zcl.hotswap_generation.v2`.
- The single-handler module ABI IS live on the dev lane
  (`zcl23-dev.service` passes `-hotswap-activate` +
  `ZCL_HOTSWAP_ACTIVATE=1`; canonical refused). `make hotswap-module-so
  HANDLER=<leaf>` builds one allowlisted read-only leaf into a module `.so`;
  `make hotswap-apply HANDLER=<leaf>` activates it in the running dev node;
  `make hotswap-try HANDLER=<leaf> ARGS="<command>"` (or
  `ZCL_HOTSWAP_PRELOAD=<module.so>` on a one-shot CLI) runs the freshly
  compiled body in the CLI process — the observable seconds-scale dev loop.
  The GENERATION (manifest/staging) mechanism stays contained: `make hotswap`,
  `tools/dev/hotswap-running-dev.sh`, `deploy-dev-lane.sh` public activation,
  watcher `auto`/`apply` modes, and `dev.change.apply` still refuse before
  publication. Use `make hotswap-sim` for the focused deterministic
  simulated-network proof; `make sim-fast` remains the broader checked-in
  scenario and seeded replay suite.
- For no-build terminal probes, prefer native commands like `z23 status`
  / `z23 dumpstate <subsystem>` run directly against a binary that
  already exists: `build/bin/z23 <command>` for the source-tree node, or
  `build/bin/z23-dev <command>` for the installed `zcl23-dev` linger
  lane (pass `-datadir=... -rpcport=...` for a custom target).
- `make t-fast ONLY=<group>` uses
  `build/test-obj/epochs/<compile-epoch>/` and the exact candidate under
  `build/bin/test-fast/epochs/<compile-epoch>/`, a cached non-LTO test harness
  for hot-path focused tests.
- `make fast-ci` runs `git diff --check`, shell syntax checks, `lint-fast`,
  the source-wide compile gate, the exact source-wide fast test candidate, and a
  native linger-service probe when the service is available. Repeated identical
  green inputs hit `.cache/zcl-agent-fast-ci/` and skip the repeated proven
  source-wide lint/build/test scope while still refreshing the live probe. The live probe trusts the
  native `zcl.public_status.v3` health contract instead of duplicating height
  gap policy in shell, and prints compact status JSON when it fails.
- Focused test routing is DRY: both native `z23 agentimpact` and
  `tools/agent_fast_ci.sh` read
  `app/controllers/include/controllers/agent_impact_rules.def`. Add a rule
  there first, then verify `agentimpact` reports `shared_rule_hits > 0`.
- `make fast-ci` auto-selects `sccache cc`, then `ccache cc`, then `cc`.
  Override with `ZCL_FAST_CC='ccache cc'`. Use `ZCL_FAST_JOBS=N`,
  `ZCL_FAST_COMPILE=dev` to force full `fast-compile`,
  `ZCL_FAST_COMPILE=strict` to replace the dev source-wide gate with strict
  `build-only`,
  `ZCL_FAST_CHANGED_FILES_ONLY=1` when an explicit changed-file list is exact,
  `ZCL_FAST_TESTS=group[,group]`,
  `ZCL_FAST_STRICT_TESTS=1`, and `ZCL_FAST_LIVE=0` as needed.
  Use `ZCL_FAST_CACHE=0` to force a rerun,
  `ZCL_FAST_CACHE_RESET=1` to clear the green-input cache, or
  `ZCL_FAST_CACHE_DIR=...` to move it.
- Normal Makefile compile/link recipes also auto-wrap `CC` with `sccache` when
  installed, otherwise `ccache`. Set `ZCL_USE_CCACHE=0` to force a direct
  compiler call.

Before pushing `main`, the tracked pre-push hook computes the exact
`origin/main..HEAD` changed-file set, rejects non-`main` remote refs, and runs
`make pre-push-ci`. That command uses cached `make t-fast ONLY=<group>` tests
selected by `tools/agent_fast_ci.sh`, plus `ZCL_FAST_COMPILE=strict` so the
compile gate is `make build-only` for compiler and `-Werror` coverage; it does
not rerun the full suite when the changed files only require narrower coverage.
It also sets `ZCL_FAST_LIVE=0`, so an already-running
node condition is visible through telemetry but does not block a code push. Set
`ZCL_FAST_STRICT_TESTS=1` when a change needs strict whole-harness focused
tests. Full-suite, fuzz, and coverage evidence belongs to the background quality lanes: install them with
`make install-quality-linger` and inspect them with `make quality-linger-status`.
Status JSON is written under `~/.local/state/zclassic23-quality`. The native
`z23 agentbuild` response also embeds
`recommended_loop` (`zcl.agent_build_loop.v2`) with the cheapest command for
each intent (`agent-plan`, `agent-loop`, `fast-changed-compile`, `fast-compile`,
`fast-rebuild`, `agent-index`, `dev-loop-bench`,
`immutable-history-canaries`, focused `t-fast`, and `pre-push-ci`),
`dev_node_binary` (`make dev-bin`, `build/bin/z23-dev`, hot-path
optimization buckets, and release/deploy boundary), `indexing`
(`zcl.agent_index_runtime.v1`, compilation-database presence/hash/freshness and
optional clangd status), `dev_loop_benchmark` (`zcl.dev_loop_bench.v1`, latest
artifact/SLO status), plus
`immutable_history_canaries` (`zcl.immutable_history_canaries.v1`, the pinned
h=478544 fixture, fast command, and replay gate commands) plus
`background_quality_status` (`zcl.background_quality_runtime.v1`), a C-native
reader for those status files. It reports the resolved state/status directory,
one entry each for `fuzz`, `coverage`, and `tests`, whether each lane verdict
file exists, whether it parsed as JSON, and the latest parsed
`zcl.background_quality_lane.v1` payload when present. Each lane also carries
`expected_source_id_sha256`, `latest_source_id_sha256`,
`source_id_matches_expected`, and `source_id_freshness` (`current`, `stale`,
`unknown`, or `no_verdict`). Legacy commit-named fields remain compatibility
aliases whose values are derived from the source-ID decision; the commit
strings themselves are display-only trace metadata. Treat
`background_quality_stale` as proof debt: a passed fuzz/test/coverage verdict
from different source bytes is useful history, not evidence for the running
build.
Agents should read that field first and use `make quality-linger-status` when
they need systemd timer logs or human-formatted service output.

## Remote Node Planning

Use `tools/scripts/remote_node_update.sh <ssh-host>` or
`make remote-node-plan ZCL_REMOTE_HOST=<ssh-host>` to compare a remote node's
checkout and service with `origin/main`. The contract schema is
`zcl.remote_node_update.v1`; `z23 agentbuild`
exposes the same read-only plan under `remote_node_update`.

The implementation is intentionally observe-only:

- `ZCL_REMOTE_DRY_RUN=1` prints the host, branch, current `HEAD`,
  `origin/main`, target systemd unit, and the planned action.
- The remote checkout must be `main`; `origin/main` is the only accepted
  remote ref. The script uses `git ls-remote` and never fetches or changes the
  checkout.
- Tracked local changes on the remote refuse the run unless
  `ZCL_REMOTE_ALLOW_DIRTY=1` is set after review.
- No Python or `jq` is required. Pass `--json`, set `ZCL_REMOTE_JSON=1`, or
  run `make remote-node-plan-json` for one JSON object per host; operational
  logs move to stderr.
- The plan records the requested future build profile but never executes it.
  `ZCL_REMOTE_DRY_RUN=0`, install target/artifact variables,
  `ZCL_REMOTE_RESTART=1`, deploy-guard actions, and
  `ZCL_DEPLOY_ALLOW_CANONICAL=1` all return
  `error:"runtime_publication_contained"` before SSH, fetch, merge, build,
  install, or service-control effects.
- `make remote-node-update` and `make remote-node-update-json` are retained as
  explicit containment probes and always refuse. Canonical deployment remains
  the separate owner-gated `make deploy` transaction.

Common commands:

```bash
tools/scripts/remote_node_update.sh <user>@<remote-host>
tools/scripts/remote_node_update.sh --json <user>@<remote-host>
make remote-node-plan-json ZCL_REMOTE_HOST=<user>@<remote-host>
```

For periodic read-only observation, run `make install-remote-status-linger`.
It installs the compatibility-source timer from
`deploy/examples/zclassic23-self-update.timer` as
`zclassic23-remote-status.timer`; the service pins `ZCL_REMOTE_DRY_RUN=1` and
`ZCL_REMOTE_BUILD=none`. Check it with `make remote-status`.
`make install-self-update-linger` is a containment probe and refuses.

For a long-running remote z23 test node, run
`make install-remote-test-node-linger`. It installs
`deploy/examples/zclassic23-remote-test-node.service` as
`zclassic23-test.service`, creates `~/.zclassic23-test`, and creates
`~/.config/zclassic23/remote-test.env` only if it does not already exist.
The service uses the remote test ports (`18033` P2P, `18233` RPC), appends
logs to `~/.zclassic23-test/node.log`, and carries the soak resource budget
(`MemoryHigh=24G`, `CPUWeight=30`, `IOWeight=30`) so a long bootstrap is not
throttled at the 12G plateau. Its env example sets
`ZCL_LANE_SNAPSHOT_LOADER_FLAG=-load-snapshot-at-own-height`, matching the
soak-node fast-bootstrap hook so remote nodes do not spend days replaying from
genesis when an explicitly assisted, reviewed loader is available. Dedicated remote hosts can
add a reviewed `MemoryMax=32G` drop-in; the committed template leaves the hard
cap out so the repo-wide systemd memory-budget lint does not double-count
mutually exclusive example nodes. Check it with `make remote-test-node-status`;
edit the env file before starting or restarting the service.

## Background proof lanes

The background lanes keep expensive proof work running without blocking every
push or AI edit loop.

- `zclassic23-fuzz.timer` runs the guarded
  `tools/scripts/background_quality_lane.sh fuzz` lane hourly. Default
  duration is 900 seconds per fuzzer; override with `ZCL_FUZZ_DURATION`.
- `zclassic23-coverage.timer` runs
  `tools/scripts/background_quality_lane.sh coverage` weekly.
- `zclassic23-test-suite.timer` runs
  `tools/scripts/background_quality_lane.sh tests` hourly.
- All four heavyweight timer services (including simnet nightly) enter through
  `tools/scripts/quality_job_guard.sh`: an active `*mint*` service or an
  unavailable mint-state query clean-skips without replacing the prior
  verdict. The guard retains the newest eight dated logs per lane and at most
  1 GiB total per lane while always preserving the newest verdict; override
  with `ZCL_QUALITY_LOG_KEEP` / `ZCL_QUALITY_LOG_MAX_BYTES`.
- `make quality-linger-status` prints timer status plus the latest
  `zcl.background_quality_status.v1` JSON verdict.
- `z23 agentbuild` exposes the same lane verdict files through
  `background_quality_status` (`zcl.background_quality_runtime.v1`) without
  invoking shell wrappers or Python.

## Reproducible build proof

Use `make ci-reproducible` for byte identity. It runs
`tools/scripts/check_reproducible_build.sh`, which builds twice in isolated
`BUILD_DIR`s using `tools/scripts/repro_build_vars.sh`, then compares the
binaries with `cmp`.

The reproducible profile pins `SOURCE_DATE_EPOCH` to the HEAD commit time
unless overridden, forces portable `-march=x86-64-v3`, and disables the linker
build id with `-Wl,--build-id=none`.

Both reproducibility front doors force vendor-offline mode and disable host
compiler caches before Make selects its compiler or runs any early input
bootstrap, and pin `LC_ALL=C`, `TZ=UTC`,
`HOME=/nonexistent`, `PATH=/usr/bin:/bin`, and umask 022. Vendor acquisition is
a separate `make vendor` phase; an absent pinned archive is a named failure,
not permission for the proof run to contact the network. The shared release
profile asks Make to expand its complete compiler/linker plan at execution
time; receipts never substitute the recursive `CFLAGS` definition for the
physical compiler flags. LevelDB likewise has one deterministic direct-C++11
vendor recipe; optional host CMake installation cannot select different input
archive bytes for the same node action.

## Rule

Keep operator logic in typed native `z23` commands. Add native JSON
once, expose it through other transports only when required, document the
schema, and cover it with focused tests. Do not require Python or an external
wrapper for the preferred operator API path.
