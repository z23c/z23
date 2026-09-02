<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# CODEBASE_MAP.md — where things live + how to do each thing

Copyright 2026 Rhett Creighton. Licensed under the Apache License, Version 2.0.

Fast reference for a fresh agent. Plain and technical. For the *why* (laws,
shapes, doctrine) read `docs/FRAMEWORK.md`; for the concrete feature-slice
contract (REST resources, ActiveRecord, validations, relationships, database
schema, services, native commands) read `docs/AGENT_ARCHITECTURE.md`; for *current
live state* read `docs/HANDOFF.md`; for *coding rules* read
`docs/DEFENSIVE_CODING.md`. For the one-page mental model read
`docs/HOW_THE_NODE_WORKS.md`.

**Never hand-write a file count into this page.** They drift 5-15% a week and a
wrong count reads as authority. Derive one when you need it:
`z23 code map` (per-authority and per-shape counts, straight from the
navigator), or `git ls-files 'engine/jobs/**/*.c' | wc -l` for one folder. The
only pinned counts live in the machine-checked `DOC-COUNTS` block below.

To pin *which* tree state an answer came from, or to ask "did anything under
`core/modules/net` change since I last looked", use
`z23 code provenance merkle [path]`: one
SHA3-256 root over every indexed source file, one subtree root per directory,
one leaf digest per file, plus the direct child subtree roots so a changed
subtree is found by comparison instead of a rescan. The reply's `build` block
reports what that call cost (files re-read of files total, directory nodes
rehashed) — a repeat call over an untouched tree reads no file bytes at all.
The digests are a derived cache (`.codeindex/source_tree.merkle`, gitignored);
deleting it is always safe and costs one full pass.

The index also carries its own scale evidence. Every cold build seals its wall
time and file count into the store meta (`build_cold_ms`/`build_cold_files`;
incremental refreshes never rewrite them), and the registered `codeindex_scale`
group proves the cost stays linear: it generates 50k- and 500k-file trees under
`test-tmp/`, cold-builds both, asserts warm queries answer within 50 ms, and
checks the 500k build stays within 30x of the 50k build. Run it with
`make t-fast ONLY=codeindex_scale`.

Three first-hour leaves answer the questions a fresh agent asks before touching
anything. `z23 code owner <path>` names the owning room: the authority root, the
sealed-core flag, the context/shape classification, the index group, and the
nearest owning module directory (unindexed paths are UNOWNED, never an error).
`z23 code cost <path>` prices the proof: the focused test route plus what the
last suite run measured each group to cost. `z23 code recent <path> --since
<commit>` lists what changed under a path lately, newest first. All three are
hermetically covered by `make t-fast ONLY=code_firsthour`.

`z23 code fetch --from=<checkout>` gives a fresh worktree a warm start: it
takes another checkout's published `.codeindex` generation, verifies it
against THIS checkout's sealed source roots (`source_root_sha3` and
`source_merkle_root_sha3`, recomputed live — fetched bytes are inert until
locally verified), and installs it through the rebuild path's own publication
ritual. A source mismatch, a format/schema drift, or an already-fresh local
store is a fail-closed refusal naming the key and both digests. Hermetically
covered by `make t-fast ONLY=code_fetch`.

---

## 1. Where things live

### Feature-first rooms

Product code is physically grouped by authority and feature. The same small
shape vocabulary repeats where it is useful: engine code under `engine/`,
software-understanding code under `cognition/`, and product behavior under
`contexts/<feature>/`. Filename and include-direction gates still enforce the
role; there is no global shape root.

| Shape | Path | Role | Exemplar |
|-------|------|------|----------|
| Controllers | `engine/controllers/` or a feature room | parse → authorize → call ONE service → return; no business logic, no raw storage | `engine/controllers/src/diagnostics_registry.c` |
| Services | `engine/services/` or a feature room | orchestrate a workflow; return `zcl_result` (typed code + message) | `contexts/wallet/services/src/wallet_scan_service.c` |
| Models | `engine/models/` or a feature room | ActiveRecord rows; own all reads (Law 5); save via `AR_*_SAVE` | `engine/models/src/block.c` |
| Jobs | `engine/jobs/` or a feature room | cursor-stamped idempotent background stages | `engine/jobs/src/header_admit_stage.c` |
| Supervisors | `engine/supervisors/` | liveness tree; children with `last_tick_age_us`, `progress_marker`, `deadline`, and a declared `progress_policy` (armed/exempt/undeclared) | `engine/supervisors/src/staged_sync_supervisor.c` |
| Conditions | `engine/conditions/` | (detect, remedy, witness) healers; poll/backoff/page-on-exhaustion | `engine/conditions/src/block_failed_mask_at_tip.c` |
| Views | `contexts/explorer/views/` | read-only explorer templates; no persistence writes; served over HTTPS + onion | `contexts/explorer/views/src/explorer_dashboard_view.c` |

### Command rooms — derived across the physical tree

Use an exact public command branch with `code room` to join the catalog subtree
to its registered handlers, physical source groups, focused proof routes, and
commands outside the branch that share those handler files:

| Feature | Derived room |
|---------|--------------|
| Wallet | `z23 code room core.wallet` |
| Naming | `z23 code room app.names` |
| Market | `z23 code room app.market` |
| Messaging | `z23 code room app.messaging` |
| C23 Commons | `z23 code room zcode.commons` |
| Agent development | `z23 code room zcode.package.dev` |

This is a read-only join over the command catalog, handler index, code index,
and shared impact rules—not a feature manifest or a new authority. Its
`implementation_scope` states the evidence boundary: registered handler
definitions are exact; indirect and unregistered dependencies remain
`UNKNOWN`. Descend from a returned handler with `code capsule <symbol>` and
check a candidate edit with `code impact <file>` before changing it.

The whole-tree counterpart is `z23 code context-map`. It derives one primary
bounded context and one architectural shape for every indexed production file,
then reports all unclassified paths, every multiple-context overlap (bounded
examples plus an exact count), and the strongest observed cross-context include
edges from compiler depfiles. The ten-context target is deliberately small:

| Context | Product meaning |
|---------|-----------------|
| `wallet` | keys, custody, balances, transaction creation, wallet workflows |
| `explorer` | read-only presentation, dashboards, and browsing surfaces |
| `naming` | names and service-directory behavior |
| `messaging` | ZMSG and message workflows |
| `market` | exchange, shop, yard-sale, ZSLP, and ZSwap behavior |
| `commons` | C23 packages, CAS, source distribution, ZVCS, and preservation |
| `cognition` | code intelligence, ontology, science, retrieval, and agent-development evidence |
| `engine` | event/reducer/application orchestration and runtime machinery |
| `core` | node, chain, validation, cryptography, policy, and consensus-adjacent behavior |
| `platform` | portable base, encoding, OS seams, generic tools, and composition support |

This taxonomy is derived from the physical roots by `cognition/modules/codeindex`.
`code context-map` gives the exact map digest
and completeness totals; `code room <file>` gives that file's `context`,
`shape`, classification basis, and every competing match. An overlap is a
navigation/refactor candidate, not proof of a bug. Include coupling is observed
build evidence, not a claim that every edge is architecturally allowed. Use
`code file <path>` for its concrete include set and `code impact <path>` for
the measured reverse blast radius before moving anything.

### Sealed consensus core — `core/`

`core/{consensus,chainparams,params,math}` — every consensus predicate and
parameter table. `z23 code map` reports it as *"sealed consensus core
(params, chainparams, math...)"*. This is where block/tx validity lives:
`core/consensus/src/{check_block,tx_structural,sapling_structural,sigops,
upgrades,checkpoints}.c`, `core/chainparams/src/{chainparams,checkpoints,
pow,equihash,subsidy}.c`, `core/params/src/{params,upgrades}.c`,
`core/math/include/core/{uint256,hash,serialize}.h`.

**Every byte is sealed.** `core/MANIFEST.sha3` pins the tree and the
`check-core-seal` gate fails `make lint` on any drift — *after* you have
already written the edit. The unlock is an owner ritual:

```bash
make core-unseal REASON="why this consensus change is parity-safe"   # mints .core-unseal-token, one commit
#   … edit core/ …
make core-seal                                                        # re-freeze MANIFEST.sha3
```

Read [`core/UNSEAL.md`](../core/UNSEAL.md) and
[`docs/adr/0002-sealed-consensus-core.md`](adr/0002-sealed-consensus-core.md)
before touching anything under `core/`. Include paths were preserved across the
move, so `#include "domain/consensus/…"` inside `core/` is correct and is *not*
a stale path (`-Icore/consensus/include`); a `domain/consensus/…` path in a
**doc** is stale. `check-core-include-boundary` governs only the four pure
contexts `core/{consensus,params,math,chainparams}`; it does not scan
`core/modules`. The byte seal is broader and currently covers every tracked
path below `core/` except `core/MANIFEST.sha3` itself. The ordering-layer
pathspecs repeated in `CORE_SEAL_PATHS` are already inside that tree and do not
enlarge the set.

### Pure domains

`platform/domain/encoding` and `contexts/wallet/domain` hold base58/bech32 and
key-derivation/mnemonic primitives beside their owning authority.
**No clock, no RNG, no IO** (lint: `check_no_raw_clock_outside_platform.sh`,
`check_domain_purity.sh`). Replayable from a 64-bit seed. Never put IO here.
The consensus modules that used to live here are under `core/` (above).

### Reusable modules — owned by an authority

Modules live under `core/modules/`, `engine/modules/`, `cognition/modules/`,
`platform/modules/`, or a product context's `modules/` room. Framework,
platform (the ONLY clock/RNG source: `time_compat.h`,
`random.h`), `storage/` (`event_log.c` + `*_projection.c`), `net`, `crypto`,
`validation`, `chain`, `consensus`, `keys`, `metrics`, `health`, JSON, kernel
utils. Boot stage enum: `platform/modules/util/include/util/boot_phase.h`.

`contexts/commons/modules/vcs/` owns ZVCS plus the `content.v2` package-manifest and source swarm.
Read [`ZVCS.md`](ZVCS.md) for internal source/version identity and
[`P2P_SOURCE_HOSTING.md`](P2P_SOURCE_HOSTING.md) for the source-hosting trust
boundary and the remaining CAS work. Three files with three different reaches;
check which one a claim is about before believing it:

- `package_swarm.c` — pure wire codec. No socket, no filesystem, no clock.
- `package_swarm_node.c` — scheduler/serving engine. Also has **no socket**,
  but it is not "pure" either: it takes a mutex and writes the package store
  on disk.
- `engine/composition/src/boot_zcode_swarm.c` — boots the swarm engine, gated behind
  `-packagehost=1` (default off). The frame send itself lives in
  `engine/composition/src/boot_zcode_dht.c` / `boot_zcode_swarm_membership.c`, carrying
  frames under the `zpkgswm` tag via `p2p_node_begin_message`
  (slice 12, `833d7f398`).

So the subsystem IS socket-wired while both `contexts/commons/modules/vcs` halves are not. It still
has no install, execution, wallet, or publication authority.
<!-- claim: symbol-absent socket contexts/commons/modules/vcs/src/package_swarm_node.c # the engine half has no socket either -->
<!-- claim: symbol-present p2p_node_begin_message engine/composition/src/boot_zcode_dht.c # the swarm IS socket-wired -->
<!-- claim: symbol-absent socket contexts/commons/modules/vcs/src/package_swarm.c # the codec half stays pure -->

The C23 Commons build/proof ontology is also owned here and by the build-fabric
service; it is one chain, not a family of interchangeable queue formats:

```text
task + candidate
  -> candidate source root + source-manifest identity
  -> action input + action root + work context
  -> build-proof REQUESTED event + durable action lease
  -> work receipt + proof-set root
  -> PROVEN lane receipt + accepted-work root
  -> versioned publication job + immutable target outcome
```

Canonical wire/root types live in `contexts/commons/modules/vcs/include/vcs/zcode_dev.h`,
`zcode_action_input.h`, `build_action.h`, `zcode_work_context.h`,
`zcode_lane.h`, `zcode_accepted_work.h`, and `vcs_devloop.h`. Durable lifecycle
and policy live in `engine/models/include/models/build_fabric.h` and
`engine/services/include/services/build_fabric_*.h`. A Git object ID records
provenance and intent; it is not a source closure, action, receipt, proof set,
or acceptance identity. `tools/land` and `.cache/zcl-dev-proof` are current
developer-factory mechanisms and must not become parallel product authority.

`contexts/commons/modules/metaverse/` owns the sovereign-property vocabulary: the `property_id`
(`<kind>:<64-hex root>`), the closed action bitmask, the view type with its
evidence grade, and one read-only adapter per property kind. It is a
**projection, never a truth** — every view is rebuilt from the kind's own
authoritative model at call time and thrown away, and adapters take a
*directory*, not a store handle, because `vcs_package_store_open()` runs a
mutating recovery sweep and `metaverse property list` is a read command. The
service that walks the adapter registry is
`engine/services/src/property_catalog_service.c`; the leaves are in
`engine/composition/commands/metaverse.def`.
<!-- claim: file-present contexts/commons/modules/metaverse/include/metaverse/property_id.h # the property vocabulary -->
<!-- claim: symbol-present metaverse_adapter_for contexts/commons/modules/metaverse/src/adapter_registry.c # the single dispatch point -->
<!-- claim: symbol-absent vcs_package_store_open contexts/commons/modules/metaverse/src/adapter_content.c # the read path opens no store -->
<!-- claim: symbol-present mv_cas_path contexts/commons/modules/metaverse/src/manifest_read.c # CAS byte verification without a store handle -->

`cognition/modules/fingerprint/` derives a *behavioral* fingerprint for a function: it
judges (fail-closed) whether a definition is pure and synthesisable, generates
a call harness from the signature alone, runs it over a corpus seeded from the
canonical signature SHAPE rather than from the function, and hashes the
observed outputs. Two functions with the same fingerprint are a **candidate**
semantic duplicate — name-, comment- and spelling-blind — never a proof. The
driver is `make fingerprint-scan`; `--select-only` prints just the coverage
breakdown. Read the LIMITS block at the top of
`cognition/modules/fingerprint/include/fingerprint/fingerprint.h` before quoting any number
it prints: only a small, honestly-measured slice of the tree is fingerprintable
at all, and a match on a corpus that never reached a validator's accepting set
means nothing (which is why the tool refuses to report a function whose output
never varied).
<!-- claim: file-present cognition/modules/fingerprint/include/fingerprint/fingerprint.h # the fingerprint contract and its limits -->
<!-- claim: symbol-present fp_index_select cognition/modules/fingerprint/src/fp_select.c # the fail-closed candidate filter -->
<!-- claim: symbol-absent system cognition/modules/fingerprint/src/fp_index.c # the scanner spawns nothing -->

### Reusable C23 packages — `contexts/commons/packages/`

The Commons packages (`zhex`, `zbuf`, `zjson`, …), one directory per
component: `zcode-package.json` manifest, `LICENSE`, `README.md`, one
namespaced public header `include/<pkg>/<pkg>.h`, primary TU `src/<pkg>.c`,
`tests/`. They are NOT compiled into the node by the Makefile (only the
Arena shelf and the `jsonq` helpers are); they are built, published,
fetched, and reproduced through the Commons machinery itself
(`tools/package_factory.c`, the swarm tests). The format discipline is
normative in [`spec/c23-package-format.md`](spec/c23-package-format.md) and
enforced by `make check-package-anatomy`.
<!-- claim: gate-passes check-package-anatomy # contexts/commons/packages/ format discipline -->
<!-- claim: file-present tools/package_factory.c # packages are built through the commons machinery -->

### Hexagonal seam — `platform/ports/` + `platform/adapters/`

Outbound-only by design: 13 port interfaces in `platform/ports/include/ports/*_port.h`
+ 14 sqlite/file write impls in `platform/adapters/outbound/persistence/{src,include}/`.
Reads are owned by Models (Law 5), so inbound repository ports are
reserved-empty. Both counts are pinned by the `DOC-COUNTS` block below —
`check_doc_counts.sh` fails if either directory changes shape without this
page changing with it.

<!-- DOC-COUNTS-BEGIN -->
<!-- Canonical code-derived counts (machine-checked by tools/scripts/check_doc_counts.sh). -->
<!-- Update BOTH this block AND any prose that cites these numbers when the code moves. -->
<!--   test_groups          = parallel test groups in tests/harness/src/test_parallel.c   -->
<!--   port_interfaces      = platform/ports/include/ports/*.h                                -->
<!--   persistence_adapters = platform/adapters/outbound/persistence/src/*.c                  -->
<!--   condition_registrations = condition_register() calls in engine/conditions/src    -->
<!--   command_bundles      = engine/composition/commands/*.def + engine/composition/commands/*/*.def       -->
<!--   command_roots        = ZCL_COMMAND_BRANCH rows with an empty parent           -->
<!--   dumpstate_subsystems = DIAG_* rows in diagnostics_dumpers.def                 -->
<!--   app_shape_folders    = directories directly under app/                        -->
<!-- Fix a mismatch with `tools/scripts/check_doc_counts.sh --fix`, never by hand.  -->

test_groups: 1084
port_interfaces: 13
persistence_adapters: 14
condition_registrations: 52
command_bundles: 26
command_roots: 12
dumpstate_subsystems: 164
app_shape_folders: 7
<!-- DOC-COUNTS-END -->

### Composition root — `engine/composition/src/`

Boot orchestration. `boot.c` (main orchestrator) + fragments
(`boot_services.c` legacy lifecycle, `boot_refold_staged.c` staged consensus
job chain, plus `address_backfill`, `bg_workers`, `bg_verification`,
`block_file_scan`, etc.).

### Agent + dev tooling — `tools/`

`command/` (native command dispatch + dev hot-swap RPC), `lint/` (gate
shell scripts), `fuzz/`, `soak/`, `sim/` (deterministic replay), `dev/`,
`githooks/`, `scripts/`, `data/` (fixtures). Stripped x86_64-linux node
packages land under `build/release/` from `platform/packaging/release/build_release.sh`
and are installed by `tools/scripts/install_z23.sh` from any node URL or
local directory. A remote URL requires the independently obtained SHA-256 of
its `SHA256SUMS`; the installer verifies that digest before downloading any
executable payload, so the serving mirror is not the authority for its own
manifest. Remote URL installs require curl 8.4.0 or newer because that is the
first release where `--max-filesize` also aborts transfers whose size was not
known in advance. Remote transfers use a 10-second connect deadline, a
30-second and 1-KiB checksum-manifest budget, and per-payload 300-second
deadlines with 64-MiB node/alias and 128-MiB verifier ceilings. The manifest
must contain exactly one strict lowercase SHA-256 row for each required payload. The
checksummed runtime set contains `z23`, its
`zclassic23` daemon alias, and the confined `zclassic23-package-verify` worker
that the daemon resolves beside itself (SHA256SUMS fail-closed; no registry).
`make release-deploy Z23_RELEASE_HOSTS='host1 host2'` builds that portable set
once locally, then bootstraps and process-qualifies fresh hosts sequentially;
the remote hosts never run a compiler or `make`. Each host receives the five
fixed release members through one SSH archive stream instead of five separate
SCP sessions, then independently verifies the exact manifest and payloads
before installation. The deploy selftest proves one stream per host, strict
post-transfer verification, sequential activation, and stop-on-first-failure.

The unified local loop is `tools/dev/watch-dev-lane.sh` (`make dev-watch`): it
classifies a coalesced save, runs the shared impact plan, and selects check,
stage, transactional reload, or the narrow stateless hot-swap path. Its
public surface is currently verify/check only. `MODE=auto`/`apply`, direct
`dev change apply`, watcher hot-swap/stage/reload modes, and generation
relinking all fail closed during Phase-0 containment. The live hot-swap loop
is the swappable-leaf module path (`make hotswap-try` / `make hotswap-apply`,
see §4), not a watcher mode.
Fleet-wide checkout truth is `z23 dev fleet`, implemented by
`tools/command/native_dev_fleet*.c`. It enumerates only `origin/main` and
`origin/agent/*`, joins matching attached worktrees, and admits lint claims
only from locally validated `.cache/agent-receipts` chains. Its isolated
three-worktree acceptance is `tools/scripts/dev_fleet_selftest.sh`; neither
path reads a live node or datadir.

`tools/dev/deploy-dev-lane.sh` contains the intended immutable
content-addressed generation transaction (activation lock,
`current`/`last-good` links, bounded probes, rollback, and rejection
quarantine), but its public entry refuses before mutation. `tools/dev/agent-dev-status.sh` is the
read-only `zcl.agent_dev_status.v2` view; `generate-compdb.sh` owns exact dev
compilation-database generation and freshness; `dev-loop-bench.sh` owns the
machine-readable latency evidence. Runtime hot-swap loading lives below the app
layer in `engine/modules/hotswap/`; the dev-only hot-swap RPC and generation commit are
registered by `tools/command/native_dev_hotswap.{c,h}` on the exact isolated
dev datadir. `dev_hotswap` mutation is live on the armed `zcl23-dev` lane,
gated on `-hotswap-activate` + `ZCL_HOTSWAP_ACTIVATE=1` + the exact dev
datadir (canonical hard-refused); only the READY read-only leaves listed in
`engine/composition/hotswap_swappable.def` can ever activate — read that file for the
current set rather than a number quoted here. Each swappable file also names
one probe leaf the loader dispatches before it publishes anything; most of
them are RPC front doors and so need a running node to probe, while
`zcode.package.policy.limits` is a pure decision leaf that probes in-process
with no node and no datadir. The release build keeps a refusal stub.
There is no watcher-owned resident transport or automatic reload fallback
during containment.

---

## 2. "I want to X → go here"

### Add a REST-backed feature/resource
Use `docs/AGENT_ARCHITECTURE.md` as the full checklist. The short path:

1. Name the noun/resource and REST shape first
   (`/api/v1/<resources>`, `/api/v1/<resources>/{id}`,
   `/api/v1/<resources>/{id}/<child_resources>`).
2. Add or migrate schema in `engine/models/src/database_schema.c` or
   `engine/models/src/database_migrate_features.c`: primary key, `CHECK`
   constraints, relationship columns, and indexes for every exposed list/filter.
3. Add the model in `engine/models/include/models/<resource>.h` and
   `engine/models/src/<resource>.c`: `DEFINE_MODEL_CALLBACKS`, `validate_*`
   using `validates_*`, `db_<resource>_save` via `AR_*_SAVE`, reads/scopes,
   and relationship helpers such as `db_order_product()` or
   `db_name_text_records()`.
4. Put workflow in `engine/services/src/` with `struct zcl_result`; services own
   transactions and call models, but do not parse HTTP/RPC inputs.
5. Add REST route metadata in `engine/controllers/src/api_controller_routes.c`
   or the relevant dynamic/member controller: method, path, resource, action,
   response schema, query filter contract, freshness, alias, privacy.
6. Add native command access only after the service/model contract exists.
   Terminal agents call it directly with `z23 <leaf> [--input=json]`
   (e.g. `z23 status`, `z23 dumpstate <subsystem>`). The native
   typed command registry is the sole agent interface.
7. Cover model validation, migration/schema, relationship failure, service
   success/failure, REST contract, and native command behavior with focused
   tests before running `make build-only` and `make lint`.

### Add a model
1. Struct in `engine/models/include/models/X.h`. <!-- doc-path-ok: X is a placeholder for your resource name -->
2. `DEFINE_MODEL_CALLBACKS` + `db_X_save`/`validate`/`find`/`delete` in
   `engine/models/src/X.c`. Use `AR_*_SAVE` macros — raw `sqlite3_step()` is <!-- doc-path-ok: X is a placeholder -->
   lint-rejected in app code (text-scan gate `check_raw_sqlite.sh`).
3. Add a migration in `engine/models/src/database_migrate.c` (per-feature tables
   in `database_migrate_features.c`; schema `database_schema.c`; validators
   `database_validators.c`). Migrations auto-run at `BOOT_STAGE_DB_OPEN`; no
   rollback.
4. Wire before/after save hooks (HARD-enforced, E3).

### Add a healer (condition)
1. `engine/conditions/src/name.c` with static `detect`/`remedy`/`witness` + <!-- doc-path-ok: name is a placeholder -->
   `struct condition` (set `poll_secs`, `backoff_secs`, `max_attempts`).
2. `condition_register()` at module scope.
3. Forward-decl `void register_name()` and call it in
   `engine/conditions/src/condition_registry.c`. Framework handles poll/backoff/
   witness/paging.

### Add a native command
1. Declare the command in the matching `engine/composition/commands/*.def` bundle.
   There are 26 command bundles; `ls engine/composition/commands/*.def
   engine/composition/commands/*/*.def` is the list — do not work from a remembered one,
   and do not drop the nested half of that glob. Docs said "eight" for months
   after `vault` and `zcode` landed, and the flat glob alone silently stopped
   being the whole catalog once the telemetry bundles moved into
   `engine/composition/commands/telemetry/`.

   Adding a bundle means adding it in **three** places — twice in
   `engine/composition/src/command_catalog.c` (the spec table and the handler table) and
   once in `tools/gen_api_reference.c`. Miss the third and the commands work
   but never appear in `docs/API_REFERENCE.md`; `check-api-reference-generated`
   now fails on that mismatch by name.
   Give it a name, transports (`ZCL_COMMAND_TRANSPORT_NATIVE`), and a handler
   symbol.
2. Implement the handler in the matching
   `engine/controllers/src/*_native_handlers.c`. Must set an error body on
   failure (never bare `return -1`).
3. The command registry loads every `.def` bundle at startup; there is no
   central per-command registry file to edit.
4. `tools/lint/check_command_contract.sh` HARD-fails any leaf whose
   `semantics` argument is empty. Write a real one-line semantics string or
   `make lint` rejects the command.

   Worked example of a plan/commit mutating leaf plus its read leaf, with
   the probe half split into a second TU to keep each near the file-size target:
   `app shop init` / `app shop status` — leaf rows in
   `engine/composition/commands/store.def` (branch row in `app_features.def`),
   handlers in `contexts/market/controllers/src/shop_native_handler.c`, datadir-local
   probes in `contexts/market/controllers/src/shop_native_probes.c`. The slice-C
   evidence readout `app shop reputation` (provable facts only over
   `<datadir>/zcode`; absent evidence reads `no_record`, never a zero)
   lives in `contexts/market/controllers/src/shop_native_reputation.c`. The slice-D
   buyer demand board `app shop want post|list|status|cancel|review`
   (signed shop_want.v1 ads — declared terms, never escrow; the
   `shop_wants` projection from schema v66; moderation visibility
   identical to moderated market offers) lives in
   `contexts/market/controllers/src/shop_native_want.c` with the codec + AR model in
   `contexts/market/models/src/shop_want.c`.

### Add a reducer stage (Job)
1. `engine/jobs/src/STAGE_stage.c` with `stage_exec()` returning <!-- doc-path-ok: STAGE is a placeholder -->
   `ADVANCED`/`BLOCKED`/`IDLE`/`FATAL`.
2. Persist the cursor in `consensus.db` keyed by stage name (re-run at same
   cursor = no-op).
3. Wire into the pipeline in `engine/composition/src/boot_refold_staged.c` (or `boot.c`).
4. E5 gate (`check-typed-blocker`) enforces advance-or-block.

Stage order and per-stage contract: see
[`docs/HOW_THE_NODE_WORKS.md`](HOW_THE_NODE_WORKS.md) §2. The reducer is the
**only** chain writer.

### Change a reducer stage
1. Locate `engine/jobs/src/STAGE_stage.c`; edit the advance path or the <!-- doc-path-ok: STAGE is a placeholder -->
   `blocker_set()` path.
2. If touching validation rules, verify against the `core/consensus/`
   predicates — and note that `core/` is byte-sealed (§1): an edit there needs
   `make core-unseal REASON="…"` before `make lint` will pass.
3. Run `make lint` (`check-consensus-parity`) + the `test_reducer_*` suite
   (`tests/harness/src/test_reducer_*.c`) before shipping.
4. Consensus parity is inviolable — never ship a consensus change to
   z23 first.

### Add a lint gate
Gates live in **two** directories and neither is deprecated:
`tools/lint/check_*.sh` and `tools/scripts/check_*.sh` (roughly half each).
Rule of thumb: put it in `tools/lint/` if it sources `tools/lint/gate_lib.sh`;
put it in `tools/scripts/` if it is also runnable standalone as an operator
tool (`check_consensus_parity.sh`, `check_doc_counts.sh`,
`check_domain_purity.sh`, `check_raw_sqlite.sh` all live there). Either way,
add it as a dependency of the `lint` target in the `Makefile`.

RATCHET gates compare against a baseline file (e.g.
`honest_witness_baseline.txt`, `no_raw_sqlite_in_controllers_baseline.txt`).

**Every new gate needs a fail-loud floor.** A gate whose scan set goes empty
(directory renamed, glob stops matching) reports CLEAN and nobody notices —
`check_domain_purity.sh` is one `find domain …` away from exactly that. Call
`gate_require_scanned <n> <min> <gate-name> "<what was empty>"` from
`tools/lint/gate_lib.sh`, as `check_command_contract.sh` does.

---

## 3. The agent surface

> The native typed command registry is the sole agent interface — see
> [`docs/NATIVE_COMMAND_INTERFACE.md`](NATIVE_COMMAND_INTERFACE.md). Command
> contracts carry native paths plus input/output schemas for discovery.
> Alongside it a set of ~40 **flat compatibility shims** (`statecatalog`,
> `dumpstate`, `agentdiagnose`, `proofbundle`, …) still work but are not in
> `discover help` and not in any `engine/composition/commands/*.def`. They are documented
> in [`docs/AGENT_API.md`](AGENT_API.md). Do not add new ones.

100+ typed commands. Discover them natively with `z23 discover help` /
`z23 discover search <q>`. Source of truth is the `engine/composition/commands/*.def`
bundles + `engine/controllers/src/*_native_handlers.c`.

### Enumerate before you guess

| I need the list of… | Run |
|---|---|
| the 164 dumpstate subsystems | `z23 ops statecatalog` — the typed leaf: every name in one call, then `--subsystem=<name>` for that descriptor in full (owner file, accepted key forms, owning test) or `--limit`/`--page` for a window. Node-free — the registry is compiled in. The flat `z23 statecatalog` is the same catalog through the legacy shim. **Not** `ops state` with no `--subsystem`: that errors `MISSING_SUBSYSTEM`. |
| test group names (one per line) | `git grep -hoE 'X\([a-z_0-9]+\)' tests/harness/src/test_parallel.c \| tr -d 'X()'` — instant, no build; `-h` matters or every name arrives glued to the filename. `make test_parallel && build/bin/test_parallel --list` gives the same list but costs a second link: `make -j$(nproc)` does **not** publish the `build/bin/test_parallel` alias, and `make test` / `make test-parallel` / `make t-fast` run an epoch candidate under `build/bin/test-strict/epochs/<epoch>/` and leave it absent |
| registry commands | `z23 discover help` — 12 command roots (`core`, `app`, `dev`, `ops`, `discover`, `code`, `vault`, `zcode`, `metaverse`, `yardsale`, `zses`, `story`) plus the bare `status` leaf, so 13 top-level names — then `discover help <path>` to descend |
| a command's exact input keys | `z23 discover schema <leaf>` |
| test groups a change touches | `z23 agentimpact <files...>` |

`discover search` takes its query **positionally** (`z23 discover search
sapling`); the `--input='{"query":"…"}'` form its schema advertises returns
`MISSING_QUERY`.

### Start here
- `z23 agentinterface` — preferred AI operator
  interface contract. Typed native CLI JSON is primary, REST is public
  read-only, and no external wrapper logic is required. Its `capabilities[]`
  matrix and
  `machine_contract` block are the programmatic source for agent transport,
  schema, and JSON expectations. Capability rows are emitted
  from `agent_contracts.def` via
  `cognition/controllers/src/agent_contract_capability_registry.c` instead of
  repeating schema or command strings in the controller.
- `z23 servicecatalog [name]` /
  `GET /api/v1/service-catalog` /
  `GET /api/v1/service-catalog/{service}` /
- `z23 serviceoperations [operation_id|key=value...]` /
  `z23 serviceoperations service=bootstrap write_safety=public_read_only` /
  `GET /api/v1/service-operations?service=znam_names&surface=rest` /
  `GET /api/v1/service-operations/{operation_id}` /
  `GET /api/v1/names/{name}/services` /
  `GET /api/v1/names/{name}/services?transport=p2p&valid=true&endpoint_only=true`
  — UX-facing sovereign
  service catalog. It answers what this node can host, advertise, verify, or
  construct for a user across names, bootstrap, Tor/onion discovery, P2P,
  files, market, messaging, and script contracts. The top-level
  `sovereign_ux` object gives agents the canonical names→services→Tor/P2P→CRUD
  flow. The top-level `runtime_probes[]` matrix is the compact checklist for
  proving every service on the running node, and member contracts expose
  `depends_on_services`, `read_model`, `write_model`, `runtime_probe`,
  `operation_summary`, and `operations[]` so agents do not infer dependencies,
  live proof routes, or write safety from prose. `runtime_probe` is the
  per-service recipe for verifying the running node: route, expected schema,
  freshness source, success signal, operation contract link, and next action on
  failure. Operation IDs are stable
  `service.operation` strings, such as `znam_names.resolve_name`. Each
  operation also publishes
  `service_catalog_route`, `agent_preferred_interface`, `agent_next_step`, and
  callable booleans so agents can navigate from service intent to the safest
  callable surface without route guessing. Filtered service-operation and
  name-service-directory responses include `filter_contract`
  (`zcl.query_filter_contract.v1`); unknown filter names fail closed with
  structured 400 errors instead of returning accidentally unfiltered
  collections. `/api/v1` route contracts and `/api/v1/openapi` expose the same
  data as `filter_contract` / `x-zcl-filter-contract`, so agents can validate
  query keys without probing an endpoint first. The implementation is split between
  `engine/controllers/src/api_controller_service_catalog.c` and
  `engine/controllers/src/api_controller_service_operations.c`; `/api/v1/services`
  remains runtime health.
- `z23 status` — the native compact first check. It emits a bounded
  `zcl.result.v1` envelope whose data schema is
  `zcl.core_status_brief.v1`; it is owned by the command registry.
  `z23 agent` and `GET /api/v1/agent` expose the separate full
  `zcl.public_status.v3` document. Its `security_posture` object is owned by
  `cognition/controllers/src/agent_security_posture.c` and names the borrowed
  snapshot/full-history-validation posture plus Sprout/Sapling anchor and
  nullifier history coverage. Public `serving` and `healthy` fail closed while
  that posture requires review; liveness-only internals remain separately
  visible for diagnosis.
- `z23 agentmap` — AI-coder map for the native
  operator surface: where code lives, which docs apply, and which tests cover
  each subsystem. The full contract guide is `docs/AGENT_API.md`.
  First-call method/schema/tool metadata is centralized in
  `cognition/controllers/include/controllers/agent_contracts.def`; registry-backed
  `agentmap` command rows and telemetry drilldowns are grouped in
  `cognition/controllers/src/agent_contract_registry.c`
  (`g_agent_command_surfaces`), including generic diagnostic commands
  `dumpstate`, `getnodelog`, `dbquery`, and the raw event-ring command
  `eventlog`, not as
  local string tables in the controllers. Non-method rows such as
  `compact_status`, `full_compatibility_status`, `full_status`, and
  `quality_lanes` also live there as direct native command-surface rows.
  `agentops` first-call scalar fields
  such as `diagnose_tool`, `anchor_status_command`, and `peer_incidents_tool`
  live there too as `g_agent_field_surfaces`, while its top-level
  schema/method/native identity fields come from `agent_contracts.def`.
  The same registry owns
  `probe_params_json` for parameterized availability probes; nested schema
  rows live in `cognition/controllers/src/agent_contract_schema_registry.c`
  (`g_agent_schema_surfaces`). REST-index
  operator drilldowns such as `healthcheck`, `milestone`, and `refold` also
  belong in that registry.
- `z23 agentops` — compact no-`jq` operator command
  center. Its first-call scalar command fields, direct/drilldown commands,
  API-gap list, and top-next-work list are registry-fed from
  `agent_contract_registry.c` (`g_agent_contracts`,
  `g_agent_field_surfaces`, `g_agent_command_surfaces`,
  `g_agent_work_surfaces`) and
  `agent_contract_schema_registry.c` (`g_agent_schema_surfaces`);
  architecture-review objects live in
  `agent_contract_review_registry.c` (`g_agent_review_surfaces`);
  keep controller code focused on assembling live state, not owning ranked
  planning tables. `agentcontracts.contract_summary` reports registry-derived
  native/REST, review-surface, and schema-surface counts plus separate
  contract/review/schema registry source fields, and command tests verify
  declared paths are registered.
- `z23 agentlanes` — native canonical/soak/dev lane
  topology, `zcl.operator_deployment_safety.v1` policy, and
  `zcl.operator_lane_recovery.v1` boot-recovery sentinel state. Use this before
  deciding where a fresh binary may be deployed or restarted.
- `z23 agentliveness` — unified current-lane
  liveness rollup: compact lane identity, observed listeners, supervisor
  counts, background quality counts, direct `overall_liveness`, and next
  drilldowns. Use `z23 agentliveness full` only when embedded runtime-availability
  methods, supervisor domains, and quality lane arrays are needed.
  Top-level schema/method/native identity fields are registry-owned by
  `agent_contracts.def`.
- `z23 proofbundle [anchor_datadir]` — read-only
  `zcl.operator_proof_bundle.v2` evidence artifact. It embeds the current
  `agent`, `milestone`/`operator_proofs`, `refold`, `anchorstatus`,
  `agentlanes`, and `agentdevstatus` contracts so agents can capture the
  current MVP/sovereign/dev-lane proof state with one native C command.
- `z23 agentdiagnose` — bounded no-jq
  diagnosis packet for first-call work: compact status, peer lifecycle incident
  counts/primary host issue, mirror status, drill-down pointers, and a safe
  next action. Use `z23 agentdiagnose full`
  only when embedded `agent`, `healthcheck`, `peer_incidents`, mirror, and
  timeline objects are needed. Its top-level schema/method/native identity
  fields are also registry-owned.
- `z23 core network peers incidents` — compact bounded peer
  incident packet for reconnect storms, duplicate host entries, last
  disconnect reason, flat primary issue fields, host direction/mixed-direction
  classification, services, advertised height plus whether that height is
  bootstrap-trusted, bootstrap/fast-sync readiness, and stability blocker
  verdicts. The native RPC and full-mode embedded
  `agentdiagnose.peer_incidents` payloads add registry-owned `method`,
  `native_command` and
  `contract_source` fields from `agent_contracts.def`, so help,
  `agentcontracts` and API discovery stay in sync with the native command.
  Use `z23 dumpstate peer_lifecycle incidents` for the generic
  subsystem view.
- `z23 agentimpact <files...>` — map changed paths
  to risk flags and focused test groups before choosing the verification set.
  The shared routing table lives at
  `cognition/controllers/include/controllers/agent_impact_rules.def` and is consumed
  by both native `agentimpact` and `make fast-ci`.
- `z23 agentbuild` — fast cached build contract:
  `make dev-watch`, `make agent-loop`, `make fast-compile`, `make build-only`,
  `make dev-bin`, `make agent-index`, `make dev-loop-bench`, `make t-fast`,
  `make fast-ci`, cache knobs, strict gates, native command registry calls,
  transactional dev activation,
  dev-lane status commands, and `make ci-reproducible`. The
  `indexing` and `dev_loop_benchmark` objects report current artifact freshness
  without requiring clangd or running an activation.
- `z23 statecatalog` — machine-readable catalog for every dump-state
  subsystem: name, description, accepted key forms,
  expected cost, freshness, owner shape/file, read-only safety level, focused
  tests, and native drill-down commands.
- `z23 ops timeline --category=sync --count=50 --since-secs=3600` —
  versioned semantic event timeline over the structured event
  ring with bounded server-side filters for `since`, `height`, `peer`,
  `reducer_stage`, `condition`, `deploy`, and `lane`. Categories include
  `sync`, `peer`, `message`, `chain`, `validation`, `condition`, `oracle`,
  `mirror`, `boot`, `db`, `wallet`, `disk`, and `net`; responses include
  `head_seq`, `semantic_summary`, `type_counts`, `peer_counts`,
  `log_references`, `recommended_drilldowns`, and `events[].seq` cursor fields.
  The response/category layer is
  `engine/controllers/src/event_timeline_controller.c`; object/CLI parsing and
  bounded filter matching live in
  `engine/controllers/src/event_timeline_filter_controller.c`.
- `z23 api` — native API discovery from the running node. It returns the
  same `zcl.rest_index.v2` body as REST `GET /api` and `GET /api/v1`, with
  `api_version`, `base_path`, resource routes, CRUD conventions, and the
  recommended native/REST first calls. Use this instead of wrapper scripts.
- `z23 agent` — compact status with stable
  top-level `status`, heights, gap, peer counts, primary blocker, and
  recommended next command. REST exposes the same contract at
  `GET /api/v1/agent`.
- `z23 milestone` — node-computed progress to the
  next version milestone. Returns `zcl.milestone_status.v2` with ASCII
  `systems`, `goals`, and `subgoals` bars, the underlying MVP criteria, and
  nested `operator_proofs` (`zcl.mvp_operator_proofs.v1`) that names each
  criterion's proof command, CI regression floor, and current blocker. REST
  serves the same contract at `GET /api/v1/milestone`.
- `z23 core status` — full composite diagnostic tree: served H* height, target/lag,
  peers, sync, onion, health, reducer frontier, tip-finalize, condition engine,
  typed blockers, and chain source scoring. It labels the composite execution
  locus; blocker data comes from the target node's native `dumpstate blocker`
  snapshot and fails closed (`blockers=null` + `blockers_error`) if that
  snapshot is unavailable or internally contradictory. Never read node-owned
  globals from a detached process.
- `z23 ops snapshot` — compact fail-closed composite. `gap` and
  `served_gap` are validated-header target minus served H*; `index_gap` is
  separately target minus the corroborating indexed/active frontier. Known
  adverse evidence wins over missing ancillary telemetry, while any evidence
  still required for a healthy verdict is typed or returned as `null` with an
  error. It rejects contradictory `served <= indexed <= header` ordering and
  treats an authoritative empty peer array as `no_peers` even at gap zero.
- `z23 core sync blockers` — target-node blocker state with target
  execution provenance and a derived dominant entry. It preserves the
  `dumpstate blocker` state fields; it is not byte-identical to that nested
  object.
- `z23 ops metrics` — aggregated KPIs (height, peer_count, sync, validation, mempool,
  wallet, chain, network). Peer counts come from a parsed object array;
  malformed/error responses yield `peer_count=null` and
  `peer_count_known=false`.

### Catalog and primitives (prefer these over a new bespoke command)
- `z23 ops statecatalog` — discover the subsystem list and metadata
  before drilling into a subsystem. The typed leaf; `z23 statecatalog`
  is the same catalog through the legacy flat shim and returns
  `zcl.state_catalog.v2`.
- `z23 dumpstate X` — generic target state dump (supervisor, watchdog,
  boot, block_index, health, chain_evidence, chain_advance_coordinator,
  legacy_mirror, oracle, header_probe, verify_engine, ...). The target's own
  catalog is authoritative — read it with `z23 statecatalog`, never a
  hand-list.
- `z23 getnodelog --pattern=... --since-secs=N --max-lines=N
  --level=...` — server-side reverse
  scan of node.log in 64 KB chunks.
- `z23 ops timeline` — category-filtered structured events with
  `zcl.timeline.v2` metadata, bounded server-side filters, semantic summaries,
  type/peer counts, log references, suggested drill-downs, and seq cursors;
  prefer this before raw `z23 eventlog` when answering root-cause questions.
- `z23 dbquery "SELECT ..."` — SELECT-only, semicolon-rejected, auto-LIMIT, 2 s
  budget, 100-row cap, rate-gated 1 RPS.

### Escape hatch
- `z23 rpc <method> '[params]'` — any node RPC method when no typed
  command fits.

### REST API versioning
`/api/v1` is the canonical REST base and `/api` is the compatibility base.
`z23 api` is the native no-HTTP discovery command and must return the
same `zcl.rest_index.v2` body as both REST index paths.
Keep version/schema constants in
`engine/controllers/src/api_controller_internal.h`, exact resource routes in
`engine/controllers/src/api_controller_routes.c`, and contract tests in
`tests/harness/src/test_api_*.c` (one file per API area, dispatched in order by
`tests/harness/src/test_api.c`). Unsupported version prefixes such as
`/api/v2/agent` must return `zcl.rest_error.v1` with
`error="unsupported_api_version"` and `supported_versions`.

Route contracts must be self-describing for CRUD clients. Every entry emitted
by `api_route_contracts_json()` carries `crud_operation` (`read`, `create`,
`update`, `delete`), `resource_scope` (`collection`, `item`, `singleton`,
`subcollection`, `subresource`), `crud_name` (`read_item`, etc.), and
`id_params`. Application-layer routes also carry `application_protocol`,
`layer`, `source_anchor`, `read_model`, `write_semantics`,
`consensus_boundary`, object types, UX surfaces, projection/reorg behavior,
cryptographic model, transport model, privacy model, and diagnostics surface.
Routes with strict path validators carry `path_param_contract`
(`zcl.path_param_contract.v1`); `/api/v1/openapi` mirrors that as
`x-zcl-path-param-contract`. ZNAM `{name}` routes currently advertise the
`znam_validate_name` lifecycle contract there so agents can reject malformed
names before probing a route.
Routes backed by a REST-callable service operation also carry
`service_contract`, `service_catalog_route`, `service_operation_id`,
`service_operation_route`, and embedded `service_binding`; OpenAPI mirrors that
as `x-zcl-service-binding`. Keep those bindings generated from
`api_controller_service_operations.c`, not duplicated in route docs. `test_api`
checks the full invariant: every REST-callable service operation must bind to a
route contract, and every route `service_binding` must point back to the same
operation.
Keep `/api/v1` and `/api/v1/openapi` generated from that
one contract source and pin representative collection/item/singleton routes in
`test_api` whenever adding a new route shape. Service-operation member routes
must stay read-only metadata lookups unless a separate, operator-authenticated
write surface is deliberately added and tested.

Application protocols such as ZSLP, ZNAM, market, messaging, and future
script-contract workflows should expose noun-shaped REST resources over
chain-derived projections. Treat **ZLSP** as the umbrella for this
engine/application/service layer: ZCL remains the base layer, while z23 exposes
versioned CRUD resources and typed native JSON methods for services built
from valid ZCL transactions. Reads come from indexed projections at the served
frontier; mutations construct/broadcast explicit transactions or operator-gated
actions and never bypass the base-layer reducer/consensus path with direct
state writes. The machine-readable version of this boundary is
`engine/controllers/src/api_controller_app_protocols.c`, surfaced as
`layer_model` in `z23 api` / `/api/v1`, `x-zcl-layer-model` in
`/api/v1/openapi`, and per-route `application_protocol` /
`x-zcl-application-protocol` plus security/projection/UX OpenAPI extensions;
update that C-owned registry before adding wrapper prose or out-of-band docs
for a new application protocol.

Public status/freshness endpoints must get their served height through
`api_served_tip_height()`, not by reading one endpoint-specific cursor. That
helper prefers the published in-memory H* frontier and falls back to the durable
`tip_finalize` cursor during process startup, keeping `/api/status`,
`/api/v1/hodl`, and `/api/v1/factoids` on the same visible-tip contract.
Milestone/version progress lives beside public status in
`api_milestone_status_json()` and is exposed through native RPC
`milestone`/`mvpstatus` and REST `/api/v1/milestone`.
Keep strict MRS scoring separate from partial/proxy subgoal progress. When
milestone says `live.source="agent_cached_summary"`, its live height, peer, and
sync fields must match a direct agent-status packet; `test_api` and
`test_syncdiag_rpc` enforce that. If any required agent field is missing, the
endpoint must say `agent_cached_summary_with_fallbacks` and name the fallback
source rather than silently mixing authorities. `operator_proofs` is static
MVP-proof metadata, not a live-health authority; update it with `docs/MVP.md`
when the accepted proof command or blocker for a criterion changes.
The bounded agent fast path may use a cached chain-advance decision only when
its projection fields are internally consistent with the served/tip frontier;
stale cache shapes are named as `cached_status_inconsistent` and leave the
top-level `indexed_height` on the current frontier.

Bootstrap-service readiness is the network-facing public singleton
`/api/v1/bootstrap` (compat alias `/api/v1/bootstrapstatus`) over the shared
`network_bootstrap_status_json()` contract. Keep it schema-identical with RPC
`bootstrapstatus`; do not duplicate bootstrap
field assembly in a REST-only handler. The nested
`snapshot_loader.authority` object is the C-native proof that a fast-start
bundle actually became local durable authority (`coins_kv`,
`coins_applied_height`, reducer H*, and self-folded marker), not just files on
disk.

ZNAM service records bridge chain-projected names into service contracts in
`engine/controllers/src/name_controller.c`. Keep `service_records[]` additive and
machine-readable: every endpoint hint should include `service_contract`,
`service_catalog_route`, `recommended_operation_id`, `service_operation_route`,
`service_contract_known`, `service_operation_required`,
`service_operation_known`, `contract_resolution_status`,
`contract_resolution`, `runtime_probe`, `endpoint_validation`,
`endpoint_routing`, `routing_priority`, `endpoint_hint_valid`, and
`next_action` so an agent can go
from a confirmed name to a Tor/P2P endpoint, distinguish canonical service
contracts from arbitrary chain text, prove the linked service is usable on the
running node, reject malformed endpoint hints without hiding them, and then
reach the exact CRUD operation contract without guessing.
`GET /api/v1/names/{name}/services` is the narrow read
subcollection for that same directory; it must stay a copy of the embedded
`service_directory` model plus standalone route metadata, not a second
service-record serializer. The directory-level `routing_plan` summarizes the
preferred transport order and valid/invalid endpoint counts for agents that
need one bounded object before deciding direct P2P vs onion fallback.
The route metadata must keep the ZNAM `{name}` path contract in sync with
`znam_validate_name`, and `test_api` pins the contract in both `/api/v1` and
OpenAPI.

### Node target gotcha
`build/bin/z23-dev <command>` hits the DEV node (`~/.zclassic-c23-dev`,
RPC port 18252). For LIVE, use `build/bin/z23 <command>` /
curl port 18232 (`~/.zclassic-c23`).
Confirm the target before acting.

### Add state introspection (no new command needed)
1. In the subsystem header:
   `bool <name>_dump_state_json(struct json_value *out, const char *key);`
2. Implement in the subsystem `.c` (caller does `json_set_object(out)` first;
   use `atomic_load` for thread-touched fields; don't allocate).
3. Add **one descriptor row** to the per-domain descriptor file your subsystem
   belongs to — `engine/controllers/include/controllers/diagnostics_dumpers_<domain>.def`,
   where `<domain>` is one of runtime, sync, network, storage, wallet, agents,
   zcode, metaverse. Choose by what the subsystem is *about*; use `_runtime`
   for a cross-cutting node concern that fits no narrower domain.
   `diagnostics_dumpers.def` itself is a **pure aggregator** — it holds nothing
   but the eight `#include`s, so a row added there is a row in no domain.
   `DIAG_ENTRY` is the long form (~12 fields: name, dump fn, description,
   category, state_class, owner `.c` path, freshness, cost, key form, two
   example keys, owning test path, bool); nine row macros exist and most rows
   use a short one. Pick by reading the `#define DIAG_*` block in
   `engine/controllers/src/diagnostics_registry.c` — it is the whole list, and
   `DIAG_LOCAL` / `DIAG_SERVICE` (not `DIAG_ENTRY`) are the two most common.
   **Do not edit `diagnostics_registry.c`'s table** — it builds `g_dumpers[]`
   by `#include`-ing the aggregator; there is no editable table in it.
   <!-- claim: symbol-present DIAG_LOCAL engine/controllers/include/controllers/diagnostics_dumpers_*.def -->
   <!-- claim: symbol-present DIAG_SERVICE engine/controllers/include/controllers/diagnostics_dumpers_*.def -->
   <!-- claim: symbol-absent DIAG_LOCAL engine/controllers/include/controllers/diagnostics_dumpers.def -->

Then `z23 statecatalog` and `z23 dumpstate <name>` expose it with
owner file, accepted key forms, safety level, tests, and drill-down commands.
No new command, route, or schema.

---

## 4. Build / test / deploy

### Reading a test result

`make test-parallel` prints a machine-greppable line **before** any verdict word:

```
SUITE VERDICT mode=<cold|cached> groups_total=N groups_ran=N groups_cached=N groups_gated=N groups_failed=N self_skips=N toolkey=…
```

then exactly one of `ALL TESTS PASSED`, `ALL TESTS PASSED (CACHED)`, or
`SOME TESTS FAILED`. There is no `N passed, M failed` line.

- `grep -q "ALL TESTS PASSED"` alone is a **false green**: it also matches the
  `(CACHED)` form, and a cached run can have `groups_ran=0`. That escape
  already shipped once — see the comment at `tests/harness/src/test_parallel.c`
  above the `SUITE VERDICT` printf.
- The correct wrapper is `tools/scripts/gate-and-report.sh <lintlog> <testlog>`:
  `make lint` → full link build → `make test-parallel` → reads `SUITE VERDICT`
  and rejects the cached form.
- Force a cold run: `make test-parallel TEST_PARALLEL_ARGS=--no-cache`.
- `ONLY=` is a **substring** match, not necessarily one group name. `make
  t-fast ONLY=wallet` runs every registered group whose name contains
  `wallet`. The target validates the selector before building and refuses an
  empty, placeholder, or unmatched value. Use `make t-list` for canonical
  group names.

| Command | Effect |
|---------|--------|
| `make -j"$(getconf _NPROCESSORS_ONLN)"` | Build `z23`, `test_zcl`, `zclassic-cli`. `-j` only overlaps the 2–3 binaries + LTO link, not per-binary front-end. |
| `make fast-changed-compile` | Compatibility name for the source-wide dev compile proof; changed paths are classification hints only. |
| `make fast-compile` | Fastest no-link dev compile check; exact non-LTO objects under `build/dev-obj/epochs/<compile-epoch>/`, with compiler-cache recovery. |
| `make build-only` | Strict release-flag source-wide `cc -c` proof under `build/obj/epochs/<compile-epoch>/`. **Compiles library objects only — it does not link, and never builds `engine/entry/main.c` or the binaries**, so it cannot catch a broken entry point, a missing symbol, or a link gap. Run `make -j$(nproc)` before claiming green. |
| `make fast-rebuild` | Fast local node binary alias for `make dev-bin`; cached per-file objects, no LTO, uses `ccache` automatically when installed. |
| `make dev-bin` | Link an exact epoch candidate, then atomically refresh `build/bin/z23-dev`; non-LTO/unstripped, with hot consensus/crypto/script/validation buckets still optimized. Local iteration only; not deploy/release. |
| `make dev-watch [MODE=verify\|check]` | Unified save loop. Both public modes prove and record without runtime activation. `auto`/`apply`/`hotswap`/`reload`/`stage` are recognized only to return a containment refusal. |
| `build/bin/z23-dev dev loop ensure/status/wait/stop` | Native C23 verify-watcher lifecycle. `ensure` is singleton/idempotent and accepts verify mode; publication modes refuse. `status` reports mode and containment posture, `wait` is bounded, and `stop` requires the exact watcher ID. |
| `build/bin/z23-dev dev proof ensure/status/wait` | Exact commit/advertised-base acceptance receipt lifecycle. Notification hooks make a best-effort per-checkout request; push admission validates the fixed-width self-sealed receipt without building, testing, linting, waiting, or invoking a shell. The queue is still filesystem-backed and is not the unfinished signed-commit publisher. |
| `make git-hook-selftest` / `make install-hooks` | Builds, measures, and installs the native C23 Git hook in the checkout-local hook directory. `pre-push` admits receipts; post-commit/merge/checkout schedule proof work. |
| `build/bin/z23-dev dev change apply --input='{"files":[...]}'` | Contained compatibility entry point: returns `publication_contained` before runtime mutation. Use `dev change plan`, verify/check watch, and focused proofs. |
| `build/bin/z23-dev dev vcs revert --input='{"to":"<commit>","relink_generation":false}'` | Source-only revert remains available. `relink_generation=true` refuses before source mutation and cannot activate a binary. |
| `make agent-index` | Atomically generate root `compile_commands.json` from dry-runs of the exact `DEV_OBJS` recipes, including generated headers and target-specific `-Og`/hot-bucket `-O2` flags. Writes hash/freshness metadata under `.cache/zcl-agent-index/`; clangd is optional. |
| `make dev-loop-bench` | Run controlled developer-loop cases and write `zcl.dev_loop_bench.v1` raw samples plus p50/p95. Activation cases stay skipped by default, so build/check timings cannot masquerade as hot-swap or reload SLO proof; `ZCL_DEV_BENCH_ACTIVATE=1` opts into measuring the armed dev-lane hot-swap activate path. |
| `make dev-activation-selftest` | Hermetically prove the contained activation machinery in a mode-0700 `/tmp` fixture. An inherited-FD sentinel and strict path/command allowlist prevent environment variables from authorizing a real dev-lane mutation. |
| `make agent-dev-recover` | Read-only dev recovery plan. Public `ARGS=--apply` is contained and cannot relink a generation, replace the datadir, or restart the service. |
| `make dev-recovery-selftest` | Hermetically prove retained recovery/rollback machinery through an inherited-FD capability bound to an isolated inert fixture. |
| `make agent-dev-status` | No-build read-only dev-lane status. Reports the explicit worker-lane contract (`role=worker`, `mutation_policy=noncanonical_dev_only`, never live/soak), source/staged binaries, service PID, RPC or pre-RPC recovery, current/running/last-good generations, activation lock, rejected generations, rollback availability, current cycle/watcher heartbeat, latency and background-quality freshness, saved deploy state, auto-reindex marker, deploy blocker/reason, and next safe action. Use `ARGS=--json` or native `z23 agentdevstatus` for `zcl.agent_dev_status.v2`. |
| `make agent-clear-stale-dev-reindex` | Clears a proven-stale dev-lane `auto_reindex_request` by archiving it after the dev RPC is up and served height is at or above the marker anchor. Never touches canonical or soak. |
| `make agent-stage-dev` | Phase-0 contained: always refuses before build/stage mutation. A caller-supplied source ID cannot authorize it. |
| `make agent-loop` | Manual one-shot AI/operator verification loop. Runs `fast-ci`; `ZCL_AGENT_LOOP_BIN=1` may also build `build/bin/z23-dev`. Runtime deployment remains contained. |
| `make fast-ci` | Cache-aware edit loop: `lint-fast`, exact source-wide compile/test proofs, and native live probe. Changed-path/test mappings are hints only. Use `ZCL_FAST_TESTS=...`, `ZCL_FAST_LIVE=0`, `ZCL_FAST_CACHE=0`, `ZCL_FAST_CACHE_RESET=1` as needed. |
| `make test` | Runs `test_parallel` (isolated per-process runner). **Use this**, not test_zcl. Green = regression floor, NOT a liveness proof. |
| `make t ONLY=simnet` | Runs the deterministic simulator harness and the current action coverage matrix documented in `docs/SIMULATOR.md`. |
| `make hotswap-sim` | Focused deterministic simulated-network proof for the dev hot-swap transaction. Use after loader/router/provider changes. |
| `make sim-fast` | Broader deterministic network proof: chaos-harness slice, checked-in scenarios, and a bounded reproducible seed sweep. |
| `make hotswap` | Phase-0 contained: refuses and directs the caller to `make hotswap-so` plus build/test verification. Whole-generation runtime publication stays contained; the live runtime path is the swappable-leaf module loop below. |
| `make hotswap-try HANDLER=<leaf> ARGS="<cmd>"` | The observable seconds-scale dev loop: rebuild one swappable leaf's module `.so` (`hotswap-module-so`), then run ARGS in a short-lived child CLI with `ZCL_HOTSWAP_PRELOAD` against the dev lane and print the result. Read-only leaves on `engine/composition/hotswap_swappable.def` only; the override dies with the child process. |
| `make hotswap-apply HANDLER=<leaf>` | Resident activation: commit the rebuilt leaf override in the RUNNING `zcl23-dev` service via `dev hotswap apply`. Gated inside the node on `-hotswap-activate` + `ZCL_HOTSWAP_ACTIVATE=1` + the exact dev datadir; refuses otherwise, and the canonical `z23` is never eligible. |
| `make test-full` | Runs the `test_zcl` monolith (sequential). |
| `make lint` | Every gate in the Makefile's `LINT_GATES` list (that variable is the count — never hand-pin a number). Must pass before tests. HARD gates fail the build; RATCHET gates compare to a shrink-only baseline. Always runs every gate cold — the canonical gate never accepts a cached verdict. |
| `make lint-cached` | Same gates, but one whose entire scannable input is byte-identical to the last time it passed is skipped. Helps only when nothing changed; after any edit every gate re-runs, because the key is the whole tree. Gates that build things, run compilers, or read build output / git config / `/proc` / untracked state are never cached and always run — see the reasons in `tools/lint/lint_cache.sh`. |
| `make lint-cold-audit` | Runs every gate FRESH and fails if any gate holding a cached PASS at its current key does not also pass the fresh run. This is what makes the cache trustworthy; run it after changing the gate set or `tools/lint/lint_cache.sh`. Warm the cache first or it has nothing to check. |
| `make ci` | lint + bench-regress + build + `test_parallel` (retry-once for flakes) + symbol-floor. This is an explicit full local gate; the native pre-push hook never invokes it. |
| `make deploy` | Pin the outer source record through recursive Make, freeze and preflight one candidate, install those exact bytes, WAL checkpoint, restart, then verify exact source/artifact identity over the canonical systemd `MainPID`'s forced loopback RPC endpoint (`deploy_verify.sh`). Inherited lane selectors cannot redirect the proof. If RPC stays closed during crash-only recovery, the verifier reports `reindex-chainstate` progress from that service's datadir log. |
| `make deploy-dev` | Phase-0 contained: always refuses before stopping a service or moving a generation link. |
| `make deploy-dev-fast` / `make agent-deploy-fast` | Phase-0 contained: always refuses; there is no public runtime-activation entry point. |
| `z23 ops state --subsystem=hotswap` | Read `zcl.hotswap_generation.v2`: active/retired/rejected in-process generations, source/build/input/artifact provenance, mapped tests/probes, pinned-artifact identity, and last rejection. These generations are ephemeral and currently admit only stateless native leaf sets; all other providers are `reload_required`. |
| `make lane-health` | Read-only canonical/soak/dev lane status, lag, peers, listeners, memory pressure, and snapshot-loader hints. |
| `make remote-node-plan ZCL_REMOTE_HOST=<host>` | Read-only `zcl.remote_node_update.v1` source/service plan using `git ls-remote`; no fetch, merge, build, install, or restart authority. Legacy `remote-node-update*` targets refuse. |
| `make lane-recover LANE=dev` | Read-only bounded recovery plan as `zcl.lane_recovery_plan.v1`. Public `--apply` / `ZCL_LANE_RECOVERY_APPLY=1` refuses before unit, datadir, snapshot-copy, header-import, drop-in, daemon-reload, or restart mutation; canonical/live/main is also refused. |
| `build/bin/test_zcl` | Run all tests directly. |
| `build/bin/z23 status` / `z23 dumpstate <subsystem>` | Native status/state calls against the release binary — no build required. |
| `z23 discover help` / `discover search <q>` | Native tool discovery over the command registry. |
| `build/bin/z23-dev <command>` | No-build native read against the installed `zcl23-dev` linger lane (`~/.zclassic-c23-dev`, RPC `18252`); pass `-datadir=... -rpcport=...` for a custom target. |
| `build/bin/zcl-rpc <method>` | Legacy/debug RPC helper. Do not build new agent workflows around it; prefer `z23` native commands. |
| `build/bin/zclassic-cli -rpcport=18232 <method>` | Explicit z23 RPC. Avoid bare `zclassic-cli` for stability diagnosis because local defaults may target another lane. |

### Boot stages (`platform/modules/util/include/util/boot_phase.h`)
12 ordered stages; out-of-order advance aborts:
`INIT → DATADIR_LOCKED → CRYPTO_READY → DB_OPEN → WALLET_LOADED →
BLOCK_INDEX_LOADED → CHAIN_TIP_RESOLVED → NETWORK_READY → SERVICES_RUNNING →
READY → SHUTDOWN_REQUESTED → SHUTDOWN_COMPLETE`. Migrations run at `DB_OPEN`.

### Recovery / deploy doctrine
- Copy-prove on a fixture datadir before any live change.
- Gate on **H\* CLIMB**, never "booted without FATAL."
- Two-step cold-sync (legacy, proven): `build/bin/z23
  --importblockindex $HOME/.zclassic` then a normal boot. Skipping the header
  import is a footgun (leaves a ~3.1M-header hole → pins).
- Validate consensus against the real CHAIN, not the zclassicd source text.

### Frozen vs replaceable
Frozen: the 8 shapes, 10 laws, lint ratchet, folder layout, event-log schema.
Replaceable: C23, SQLite, systemd, Tor v3, crypto algos (behind the agility
ladder). Build to the contract, not the implementation.
