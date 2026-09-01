# Agent Architecture Contract

This is the build path for future Codex and Claude work. Use it when adding or
changing a user-facing feature, REST resource, wallet flow, ZSLP/ZNAM/ZMSG/ZSWP
workflow, explorer projection, or operator API. The short version:

**One binary, REST resource first, noun-shaped REST, model-owned schema, ActiveRecord writes,
explicit validations, explicit relationships, service-owned workflows, typed
native calls.**

Z23 borrows the useful Rails ideas: resources, ActiveRecord lifecycle,
validations, relationships, migrations, strong parameters, and thin
controllers. It does not borrow reflection, hidden allocation, exceptions, or
runtime magic. Everything must be visible to C, grep, gdb, lint, and tests.

## The Feature Slice

Build each feature in this order.

1. **Name the resource.**
   Pick the noun first: `names`, `messages`, `file_offers`, `swaps`,
   `wallet_notes`, `zslp_tokens`. REST paths are plural collections and member
   resources: `GET /api/v1/names`, `GET /api/v1/names/{name}`,
   `GET /api/v1/names/{name}/services`. Native tools may be verbs, but the
   backing model and REST surface stay noun-shaped.

2. **Define the database schema.**
   Baseline tables live in `engine/models/src/database_schema.c`; versioned
   feature migrations live in `engine/models/src/database_migrate_features.c`.
   New tables need a primary key, bounded column types, `CHECK` constraints for
   money/heights/counts where possible, and indexes for every list/filter path
   exposed through REST or native commands. Migrations are forward-only, idempotent, and
   stamped in `schema_migrations` plus `schema_version`.

3. **Create the model.**
   Put the struct and public API in `engine/models/include/models/<resource>.h`
   and the implementation in `engine/models/src/<resource>.c`. The model owns all
   SQL for that table. Controllers and services do not hand-roll joins or
   direct table scans.

4. **Use the ActiveRecord lifecycle for every write.**
   A model file starts with `DEFINE_MODEL_CALLBACKS(<model>)`, has a
   `db_<model>_validate()` function using `validates_*` macros, and saves via
   `AR_BEGIN_SAVE`/`AR_FINISH_SAVE`, `AR_ADHOC_SAVE`, or `AR_CACHED_SAVE`.
   Before/after hooks belong in the model and emit events or update caches.
   Raw `sqlite3_step()` in app code is a build violation.

5. **Make relationships explicit C APIs.**
   A relationship is not a comment and not a controller query. Add model
   functions such as `db_block_transactions()`, `db_sapling_note_key()`,
   `db_order_product()`, or `db_name_text_records()`. Back each relationship
   with the right index in schema/migration code. If SQLite foreign-key
   enforcement is not the authority for a table, enforce ownership in the model
   validator or service before saving.

6. **Put workflow in a service.**
   Services live in `engine/services/src/` and return `struct zcl_result` for new
   code. They receive typed inputs, call models and lower-level services, and
   own transactions or multi-step workflows. They do not parse HTTP, JSON-RPC,
   or native argument shapes.

7. **Keep controllers thin.**
   Controllers parse, authorize, call one service or one model read, and render
   JSON. Use `controllers/strong_params.h` for RPC-style inputs. A controller
   does not own business rules, retry loops, raw storage, or consensus policy.

8. **Expose REST from the route contract.**
   Exact REST resources are declared in `engine/controllers/src/api_controller_routes.c`
   using `struct api_resource_route`. Each route declares method, path,
   resource, action, response schema, query parameters, freshness source, alias,
   and privacy. Dynamic/member route helpers must publish the same metadata
   through `/api/v1`, `/api/v1/openapi`, and service-operation contracts. Public
   REST is primarily read-oriented today; mutations stay operator-gated through
   native/RPC until an authenticated REST write surface exists.

9. **Expose typed native calls from the same contract.**
   Native operator commands live in the agent contract registry when they are
   first-class commands. The native typed command registry is the only agent
   interface. Terminal agents should prefer native commands —
   `z23 status`, `z23 dumpstate <subsystem>`,
   `z23 discover help` / `discover search <q>`, and
   `z23-dev status` for the installed dev lane. The agent contract still
   carries the native command path and schema metadata used by discovery and
   typed invocation.
   Do not add separate helper binaries. Before restarting or hot-swapping the
   dev lane, run `make agent-dev-status` or native `z23 agentdevstatus`
   and use its next-action hint.

10. **Test the slice.**
    Add model validation tests, migration/schema tests, service tests, REST
    contract tests, and native command tests proportional to the risk. Then run
    the focused `make t-fast ONLY=<group>` or `make t ONLY=<group>` path, plus
    `make build-only` and `make lint` before shipping.

## Schema Rules

- Primary keys are explicit and stable. Use `(txid,vout)`, `name`, `swap_id`,
  or an integer id only when that id is the resource identity.
- Store consensus hashes as fixed BLOBs, user-visible names/addresses as TEXT,
  and money in zatoshis as INTEGER.
- Add `CHECK` constraints for non-negative heights, counts, and bounded money.
- Add indexes before exposing a list/filter route; never make REST depend on a
  full-table scan by accident.
- Migrations must be safe to run repeatedly and safe on an existing live db.
- `consensus.db` (the kernel store — `progress.kv` on a pre-flip datadir) is
  not a domain model store. Do not route stage cursors through ActiveRecord.

## REST Rules

- REST resources are nouns, versioned at `/api/v1`, and self-describing through
  `/api/v1` and `/api/v1/openapi`.
- Every response has a stable schema string such as `zcl.names.index.v1`.
- Collection routes publish filter contracts and reject unknown filters.
- Member routes validate path parameters before touching storage.
- Operator-private routes must be marked `private_route=true`; untrusted
  listeners block them before dispatch.
- Freshness is part of the response contract: name the projection, served
  height, indexed height, or blocker instead of implying live truth.

## ActiveRecord Rules

- One model owns one table family. If two features write the same table, factor
  the model instead of adding a second write path.
- `validate_*` protects structural invariants: required fields, money range,
  hash length, address syntax, enum inclusion, ownership, and relationship
  existence when needed.
- Hooks are for local model side effects: event emission, cache invalidation,
  commitment refresh, and audit breadcrumbs.
- Services may open transactions, but the row writes inside them still use the
  model save functions.
- Read helpers and relationship helpers belong beside the model, even when a
  controller is the first caller.

## Review Checklist

Before calling a feature done, answer yes to each:

- Is there one resource noun and one owner model?
- Is the schema/migration indexed for every REST/native list path?
- Do all writes pass through AR validation and hooks?
- Are relationships expressed as model functions, not controller SQL?
- Does the service return `zcl_result` with actionable failure text?
- Does REST publish route metadata, schema, privacy, query filters, and
  freshness?
- Does the native command call the same service/model contract as REST?
- Do tests cover invalid input, relationship failure, schema upgrade, and the
  successful path?
