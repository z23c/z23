# The z23 Framework

> **One binary. One chain. One way to do each thing — and the compiler
> knows what that way is.**
>
> We are not Rails. We are high-performance C. But we borrow Rails' care for
> *making the wrong thing hard*, Phoenix's instinct for *supervised recovery*,
> and the *functional-core / imperative-shell* split — and we pay for none of
> them with reflection, GC, exceptions, or hidden allocation. Where a Rails
> idiom costs a cycle or a debuggable stack frame, we keep the idea and drop
> the implementation.

This is the canonical architecture doc. If you are a contributor (human or
AI), **read this before writing or moving any code.** The open-item debt
board (what remains) is §9, below — this doc describes both the
**destination and the laws** (§0–§8) and the current **open work** (§9) in
one place.

For the concrete future-agent feature slice — REST resource first, database
schema, ActiveRecord model, validations, relationships, service workflow,
route contract, typed native surface, and tests — use
[`docs/AGENT_ARCHITECTURE.md`](./AGENT_ARCHITECTURE.md). This file is the law;
that file is the build recipe.

---

## 0. The Prime Directive

A full node has exactly one job: **keep `(tip, utxo)` equal to the network's
best *valid* chain — or name, precisely, the one input it is missing.**
Everything else — wallet, explorer, market, ZNAM, messaging, swaps — is a
*read-model* over that one fact.

That boundary is intentional: Zclassic consensus is the base layer. z23
can act like an L2-style application/service layer over that base — ZSLP,
ZNAM, file market, messaging, script-contract workflows, wallet flows, and
CRUD REST resources may interpret, index, and construct transactions anchored
to ZCL — but they must not drift from the L1 rules. Product innovation lives in
versioned controllers, services, projections, OP_RETURN/memo/script protocols,
and operator APIs; Equihash parameters, activation heights, block/transaction
validity, and coin accounting remain consensus-parity territory. The working
umbrella for that application/service layer is **ZLSP** (ZCL Layer Service
Protocol): noun-shaped REST resources and typed native JSON methods over
ZCL-anchored services. ZSLP tokens, ZNAM names, messaging, market flows, and
script-contract workflows are ZLSP-style services; they may build valid ZCL
transactions, but they never become a second consensus engine.

Every failure this node has ever had is the same failure: `(tip, utxo)` fell
behind and the reason was *emergent* — smeared across a legacy mutate-in-place
path, proxy health checks, and a bolt-on self-healer that could lie. So the
architecture is built to remove the place where failure hides:

> **The node is an append-only log of raw facts (headers, bodies) and the
> reducer's own output deltas (utxo add/spend). State — tip, UTXO set, indexes,
> wallet — is a set of projections folded from that log. A single supervised
> reducer is the only writer, and its only verb is *advance-a-durable-cursor or
> name-a-typed-blocker*. No component holds authoritative chain state in RAM.
> No second write path exists. Health is one number: `network_tip − log_head`.
> Therefore a silent halt is not a bug to detect — it is unrepresentable.**

One honesty up front, because it shapes everything: **validation is not a pure
fold.** To validate block N you need the UTXO set as of N−1, which is itself the
output of folding the log up to N−1. So the reducer is a *left-fold with
feedback*: `state[N] = apply(validate(block[N], state[N−1]), state[N−1])`.
Validity is therefore a property the reducer *enforces at append time*, not a
pre-existing attribute of a fact. The UTXO projection is not an independent
side-projection you could rebuild in parallel — it is **on the reducer's
critical path**, and its write must land in the *same durable transaction* as
the cursor advance, or the two-store ordering hazard we are killing comes back.
State this precisely or the model misleads.

A second honesty, and this one is a standing architectural fact rather than a
live status (live status lives only in `docs/HANDOFF.md` §0-LATEST — never
here): above genesis, ZClassic headers commit none of the UTXO, Sapling/Sprout
frontier, or nullifier contents. A state artifact whose `anchor_block_hash`
matches a validated in-binary PoW header (`core/chainparams/src/checkpoints.c`) is
therefore not thereby proof- or consensus-bound for its UTXO/shielded payload
— that requires independently validating the transparent and shielded
contents and passing copy proof; matching a header alone is not enough. The
fold is genuinely pure *above* a complete, self-derived anchor; the
`-refold-from-anchor` sovereign cure folds from the verified checkpoint
forward and then deletes any borrowed seed. Whether this node is currently
running on self-derived vs. borrowed state is a live fact: see
`docs/HANDOFF.md` §0-LATEST.

The four promises this buys the operator:

- **⚡ Fast** — cold-sync to tip in seconds (FlyClient + SHA3 snapshot) is the *design target*; the FlyClient/snapshot stack is built but inert today. The legacy `--importblockindex` + boot path still works. Then stay current. Current sync/cure status is a live fact, not an architecture fact — see `docs/HANDOFF.md` §0-LATEST, not this file.
- **🪶 Lean** — one static binary, bounded RAM, no runtime it doesn't ship itself.
- **💪 Unbreakable** — cannot halt *silently*; a stall is always a named blocker or a growing `log_head` gap, and it pages a human before it gives up.
- **🔬 Honest** — forward progress on the live tip is the only acceptance bar. Green tests are not a healthy node.

---

## 1. The Ten Laws of Beauty

The charter. Each law is enforceable; §5 maps each to a gate. They are honest
for high-performance C, not Rails cosplay.

1. **The folder is the type; the filename is the entity.** If you cannot name a
   file's shape from its path, it is in the wrong folder. Convention resolves at
   *build time* — folder + filename + linker is our "reflection," at zero runtime cost.

2. **One way in, one way out.** Every persistent write goes through the
   ActiveRecord lifecycle. Every failure returns a `zcl_result` that explains
   itself. Every healer is `(detect, remedy, witness)`. Alternatives are
   compiler errors, not code-review comments.

3. **Declare the spec; generate the code.** Prefer `validates_*` tables,
   plain init-structs, and `tools/` codegen over block-macro DSLs you cannot set
   a breakpoint in. *If gdb cannot step it, it is not beautiful.* (This retires
   the fictional `MODEL(){…}` / `SERVICE_BEGIN` / `JOB(){…}` forms — see §3.)

4. **The core is pure; the shell is dirty.** No clock, no RNG, no I/O in
   `domain/`. A pure core replays from a 64-bit seed and benchmarks
   honestly. Lint-enforced, FAIL mode.

5. **Behavior attaches to the type, not the byte.** Fat models, lean structs:
   hooks and validations hang off one static registry *per model*; records stay
   dense, POD, cache-friendly. No per-instance vtables in a hot array.

6. **Don't crash — checkpoint and re-run.** The unit of recovery is an
   idempotent, cursor-stamped Job, not `abort()`. Restart resumes from a
   known-good cursor; never tear a write-ordering invariant to "fail fast."

7. **Heal in the open; page when stuck.** Conditions auto-remedy with backoff
   and a *witnessed* post-condition; on exhaustion they page a human. A remedy
   that returns `ok` without moving the symptom is a lie — forbidden.

8. **DRY the knowledge, not the cycles.** One source of truth per fact — one
   validator, one query string, one cursor name. But never add indirection to a
   hot loop to avoid duplication. Duplicated straight-line code beats a
   function-pointer in a tight path.

9. **Immutable at the boundary, mutable inside.** Readers see MVCC snapshots and
   append-only history; writers mutate dense arrays under clear ownership. No
   persistent data structures, no structural sharing, no GC.

10. **Green tests are not a healthy node.** Forward progress on the live tip is
    the bar. Never weaken a safety or performance gate to make the build pass —
    fix the real problem.

---

## 2. The architecture — log, projections, reducer

```
        network msgs ─┐
   zclassicd mirror ──┤
  snapshot/FlyClient ─┼──►  [ source adapters ]   candidate facts (headers, bodies)
        P2P bodies ───┘             │
                                    ▼
                    ┌───────────────────────────────┐
                    │   THE REDUCER  (one writer)     │   each tick, per stage:
                    │   validate(block, utxo@N-1)     │     • append validated fact
                    │   → append fact + utxo deltas   │       + advance cursor   (ADVANCED)
                    │   OR write one typed blocker     │     • or name the gap     (BLOCKED)
                    │     (height, missing, source)    │     • or nothing to do    (IDLE)
                    └───────────────────────────────┘
                                    │ append-only, same txn as cursor
                                    ▼
                    ╔═══════════════════════════════╗
                    ║   THE FACT LOG  (event_log)    ║  ◄── the ONLY source of truth
                    ║   durable, fsync'd, CRC'd       ║      (authoritative reducer
                    ║   headers · bodies · utxo Δ      ║       path; cleanup remains)
                    ╚═══════════════════════════════╝
                                    │ pure fold (cursor per projection)
              ┌─────────┬───────────┼────────────┬──────────┐
              ▼         ▼           ▼            ▼          ▼
            utxo    block-index   mempool      wallet    explorer …
          projection (tip)        projection  projection  (read-models:
              │                                            rebuildable, never
              │ reducer reads this to validate block N+1   authoritative)
              ▼
       health = network_tip − log_head.   ONE number.
       operator_needed ⟺ a blocker outlived its SLO (and the alert reaches a human).
```

The pipeline is the staged Job chain, and it is the reducer — eight stages in
a fixed line, each proving one thing and either advancing its cursor or
naming a blocker; see [`docs/HOW_THE_NODE_WORKS.md`](./HOW_THE_NODE_WORKS.md)
§2 for the full per-stage table (what each proves, what "stuck" looks like).

Each stage is a Job (§3.4): it advances a durable cursor or names a typed
blocker. `tip_finalize`'s cursor *is* the tip. Reorg is a fork-aware append:
disconnect emits the inverse UTXO deltas (restore-spent → ADD, erase-created →
SPEND), so a reorged projection is byte-identical to a direct build of the
winning branch.

**Why the silent halt becomes unrepresentable:** if the tip is `log_head`, and
every advance is a stage returning `ADVANCED` or a typed `BLOCKED`, then
"stopped" is *always* either a cursor that isn't moving (visible as
`network_tip − log_head` growing) or a named blocker at a known height. There is
no third state. That is strictly stronger than detectors watching proxies.

The staged reducer is the authoritative chain-advance architecture, but the
legacy block-connect engine still ships and is live-called on the recovery path
(`connect_block` at `config/src/boot_index.c:403`; `lib/validation/src/` ≈
7.7k LOC across its `.c` files, still linked). Cleanup remains — the
checklist tracks it.

---

## 3. The eight shapes — honest status

Every `.c` file under `app/` is exactly one of eight shapes. Open the folder,
know the shape.

| # | Shape | Folder | Canonical form | Status | Exemplar |
|---|-------|--------|----------------|--------|----------|
| 1 | **Controller** | `app/controllers/` | `static int h_x(req,res)` + route table | partial; E1 is empty, but import/sync controllers still carry legacy orchestration and raw-SQL debt is ratcheted | `chain_projection.c` |
| 2 | **Service** | `app/services/` | functions returning `struct zcl_result` | partial; file-level E2 and typed-blocker baselines are empty, but legacy bool compatibility APIs remain | `replay_verify_service.c` |
| 3 | **Model** | `app/models/` | `DEFINE_MODEL_CALLBACKS` + `validates_*` + AR save | **real, enforced** (E3+E4+model-validation HARD; file count in `docs/CODEBASE_MAP.md` §1's app-shapes table) | `block.c` |
| 4 | **Job** | `app/jobs/` | cursor-stamped stage: advance-or-blocker | **real** — eight reducer stages live in `app/jobs/`; E5 HARD (advance-or-block) | `*_stage.c` |
| 5 | **Supervisor** | `app/supervisors/` | declared liveness tree, restart policy | partial — `net`/`chain`/`staged_sync` declared; `boot_services.c` still owns lifecycle wiring | `app/supervisors/src/staged_sync_supervisor.c` |
| 6 | **Condition** | `app/conditions/` | `{detect, remedy, witness}` struct + `register()` | **real, the model citizen** (`condition_registrations` count is machine-checked in `docs/CODEBASE_MAP.md`'s DOC-COUNTS block) | `block_failed_mask_at_tip.c` |
| 7 | **Event** | *(no `app/` folder — concept, not a physical shape)* | typed append-only emit + subscribers | there is no `app/events/` folder (0 files ever lived there); the concept stays owned by `lib/event/` + `lib/storage/src/event_log.c` + `lib/storage/*_projection.c` | `lib/storage/src/event_log.c` | <!-- doc-path-ok: app/events/ deliberately does not exist — that is the row's point -->
| 8 | **Storage Adapter** | `adapters/` + `ports/` | port interface + swappable impl | **real — outbound-only by design** (§6); port/adapter counts are machine-checked in `docs/CODEBASE_MAP.md`'s DOC-COUNTS block; `check_raw_sqlite.sh` CLEAN | `adapters/outbound/persistence/` |

The honest read: **Model, Condition, Job, the projection/state-dump registry, and
the Storage Adapter (outbound-only by design) are real and enforced; Supervisor is
partial; Controller and Service still carry legacy debt.**

### The canonical form is struct-registration, not a block-DSL

The single most important correction this doc makes: **we bless the form the
code actually uses and rejects the DSL it never adopted.** A Condition is a
plain struct you can read, grep, and step through:

```c
// app/conditions/src/block_failed_mask_at_tip.c — the exemplar for ALL shapes
static bool detect(const struct condition_ctx *c)  { /* reads model state   */ }
static bool remedy(const struct condition_ctx *c)  { /* calls a service     */ }
static bool witness(const struct condition_ctx *c) { /* observable success  */ }

static struct condition cond = {
    .name = "block_failed_mask_at_tip", .severity = COND_CRITICAL,
    .poll_secs = 5, .backoff_secs = 30, .max_attempts = 5,
    .detect = detect, .remedy = remedy, .witness = witness,
};
void block_failed_mask_at_tip_register(void) { condition_register(&cond); }
```

No `CONDITION(){ DETECT{…} }` macro hides the control flow; the engine handles
poll, backoff, attempts, witness, and `EV_OPERATOR_NEEDED` paging. Adding a
healer is one ~50-LOC file plus one line in the registry. Every other shape
converges on this form — the form is always *struct + register*, never *macro
you can't breakpoint*.

The contracts, briefly:

- **Controller** — parse → authorize → call ONE service → return. No business logic, no storage, no swallowing errors. Dumb glue.
- **Service** — typed inputs → call models/other services → return `zcl_result`. No input parsing, no direct storage.
- **Model** — the only reader/writer of persistent state. AR lifecycle: `validate → before_save → write → after_save`. Raw `sqlite3_step` is a *compile error*.
- **Job** — idempotent, cursor-stamped in `consensus.db`. Returns `ADVANCED` / `BLOCKED(typed)` / `IDLE` / `FATAL`. Re-running at the same cursor is a no-op. The reducer stages are the model case.
- **Supervisor** — a declared tree of children with restart policy; the deadman that edge-triggers `on_stall`. Recovery is structural, not ad-hoc.
- **Condition** — `(detect, remedy, witness)` with backoff + max-attempts; pages on exhaustion. Every halt class is one file.
- **Event** — typed, append-only, totally ordered. Emitting writes the fact log. Subscribers receive asynchronously.
- **Storage Adapter** — the domain depends on the *port*; multiple adapters satisfy it. Swapping engines swaps one file.

---

## 4. Folder convention

```
app/
  controllers/   parse · authorize · delegate            (one service call)
  services/      orchestrate workflows → zcl_result
  models/        entities · AR lifecycle · validations    (only writers of state)
  jobs/          cursor-stamped stages (the reducer)
  supervisors/   liveness trees, one root per domain
  conditions/    auto-healers, one file per halt class
  views/         explorer templates
                 (Event shape has no app/ folder — see lib/storage/ below)

domain/          pure consensus core — NO clock/RNG/IO    21 modules: consensus/ wallet/ encoding/
                 (each fronted by a thin lib/ legacy wrapper + a seal test)

lib/
  framework/     the shape primitives (condition, projection, mailbox real; rest WIP)
  platform/      clock, rng — the only sanctioned source of time/entropy
  event/         the Event shape's pub/sub bus (typed append-only emit + subscribers)
  storage/       event_log + projections + (legacy) coins/sqlite
  net/ rpc/ crypto/ chain/ validation/ …                (primitives, incremental migration)

adapters/ ports/  hexagonal seam (outbound-only by design — port/adapter counts in CODEBASE_MAP.md's DOC-COUNTS block; reads owned by Models per Law 5)
config/           composition root (today: boot monoliths — to become supervisor decls)
tools/lint/       the ratcheting gates — beauty enforced by the build
docs/             FRAMEWORK.md (this — §9 is the debt board) · work/ (assignments)
```

**Rule:** every new `.c` under `app/` lives in exactly one shape folder. The
`check-framework-shape` gate enforces it (RATCHET today → HARD).

---

## 5. Beauty by the build — enforcement

> "If the compiler can't enforce it, it will be violated." — `DEFENSIVE_CODING.md`

Beauty here is not a style guide; it is a set of gates that turn the build red.
`make ci` runs `lint` *before* a single test, so a violation never reaches a
human reviewer. The ladder is deliberate:

- **WARN** — a gate the day it ships, measuring the existing tree before the refactor deletes the debt.
- **RATCHET** — a law the tree doesn't yet satisfy but must monotonically approach. The baseline can only shrink; growing it costs an ADR.
- **HARD** — a law the tree already satisfies. One regression is one too many.

Hygiene + adoption gates cover: no bare malloc, no raw `sqlite3_step`
(text-scan lint gate), no silent error returns, no raw clock/RNG outside
`lib/platform/`, threads only via the registry, observability-pairing,
before/after-save hooks, function ≤500 LOC, `lib/`→`app/` layering, supervisor
registration, typed blockers, framework-shape. The gates are themselves under
test (`test_make_lint_gates.c` plants a fixture, asserts the gate trips,
removes it, asserts green).

Of the 11 architecture gates, 6 are HARD (E3, E4, E5, E8, E9, E11), 4 are
RATCHET (E1, E2, E6, E10), and **E7** (no-authoritative-RAM-state) is clean at
zero grandfathered entries. The Ten Laws and the Prime Directive land as gates
with the work they guard:

| Gate | Enforces (law) | Mode |
|------|----------------|------|
| **one-write-path** | exactly one writer to chain state (Law 2, Directive) | ratchet → hard |
| **no-authoritative-RAM-state** | consensus state lives in log/projections/cursors, not globals (Directive) | ratchet |
| **projections-are-pure** | projection files don't `#include` services/controllers or emit writes (Law 4) | hard (small file set) |
| **stage-advances-or-blocks** | every Job references a cursor and `blocker_set()` on non-progress (Directive) | hard for the Job shape |
| **health-is-the-gap** | one `tip_not_advancing` Condition is the sole liveness authority; others don't emit `EV_OPERATOR_NEEDED` for liveness (Directive, Law 10) | ratchet |
| **operator-needed-has-a-sink** | every `EV_OPERATOR_NEEDED` emit pairs with a registered subscriber (Law 7) | hard |
| **shape-is-content-checked** | a shape file includes its shape header (closes the "mislabeled Service" hole) | ratchet → hard |
| **file-size-ceiling** | no `app/**/*.c` or `config/src/*.c` over 800 lines; mega-modules can't hide under <500-LOC functions (Law 1) | enforced ratchet (fails the build; grandfathered files listed in `tools/scripts/file_size_ceiling_baseline.txt`, shrink-only) |
| **one-result-type** | services return `zcl_result`, not bare `bool`/`int` (Law 2) | ratchet |

Both strategic gates (`framework-shape`, `controller-SQL`) have graduated
WARN → RATCHET (`5daf21742`); they harden as the refactor makes the boundary
load-bearing.

---

## 6. The hexagonal cut — inside vs outside

```
                 ┌──────────────────────┐
                 │       DOMAIN          │   pure: consensus rules, validation
                 │      domain/          │   predicates, UTXO arithmetic, crypto
                 │  (no clock/RNG/IO)    │   registry. Replays from a seed.
                 └──────────┬───────────┘
                            │ depends on PORTS (interfaces)
        ┌───────────────────┼────────────────────┐
     ┌──▼──┐  ┌──────┐  ┌───▼──┐  ┌─────┐  ┌─────┐
     │SQLite│  │flat- │  │ Tor  │  │ CLI │  │ P2P │   ADAPTERS — swap one file,
     │ /log │  │file  │  │      │  │     │  │     │   the domain doesn't move.
     └──────┘  └──────┘  └──────┘  └─────┘  └─────┘
```

**Dependency rule: inward only.** Controllers → Services → Models → Storage
Adapters → Domain. The domain depends on nothing dirty. This is what makes the
node 50-year-replaceable: C23 → next language, SQLite → next engine, Tor v3 →
next routing, all without the domain moving.

Honest status: the domain core is **real but partial** — `domain/` (top-level)
holds 21 pure no-clock/no-RNG/no-IO modules (consensus/ wallet/ encoding/), each
fronted by a thin `lib/` legacy wrapper and sealed by a `test_domain_*` regression
test. The adapter tree is **outbound-only by design**: `docs/CODEBASE_MAP.md`'s
machine-checked `port_interfaces` / `persistence_adapters` counts carry writes
out through swappable ports (Law 2); reads are owned by the Models (Law 5),
so no inbound "repository" port fronts them — the same kind of by-design absence
as the deleted `app/events/` folder (§3 row 7): the concept has a real home <!-- doc-path-ok: app/events/ deliberately does not exist -->
elsewhere and does not need an empty placeholder. App sites that call
`lib/storage/*_sqlite.c` directly are
legitimate (Models ARE storage; Jobs use the consensus.db kernel store; Views are
read-only introspection), and `check_raw_sqlite.sh` stays CLEAN with an empty
baseline. The `check-lib-layering` ratchet guards the write direction.

### The `application/` tier — staged consensus logic

When `application/` (the hexagonal application-level consensus boundary) is
populated, it should contain domain-level consensus state predicates and
use-case invariants that cross multiple models/services — checks that express
business rules of the chain itself before they migrate to the pure `domain/`
core. This keeps `application/` as the staged consensus-logic tier between
orchestration (`app/services`) and pure consensus (`domain/`).

---

## 7. What survives 50 years vs what gets rewritten

**Frozen (the spec):** the eight shapes and their contracts · the Ten Laws · the
lint ratchet · the folder layout · the typed event-log schema (version-stamped)
· chain consensus rules.

**Replaceable (the implementation):** C23 → next language · SQLite → next engine
· systemd → next supervisor · Tor v3 → next onion routing · specific crypto
algorithms (behind the crypto-agility ladder).

The framework holds; the implementation moves.

---

## 8. Where to start

- **New here:** read this (§9 is the open-item debt board — what's done,
  what's next) and [`docs/USER_BENCHMARKS.md`](./USER_BENCHMARKS.md) (the
  five acceptance numbers + the operator-paging clause everything is judged
  against). [`docs/ARCHITECTURE_DIAGRAMS.md`](./ARCHITECTURE_DIAGRAMS.md) has
  Mermaid diagrams of the current boot sequence and subsystem topology as a
  visual companion to §2-§4 below.
- **Driving the north star:** keep the lint baselines empty, finish deleting
  old cutover/shadow language, and keep reducer/log authority as the only
  architecture described in production docs.
- **Worker assignment:** [`docs/work/agent-protocol.md`](./work/agent-protocol.md),
  then your spec under `docs/work/`.
- **Reviewing a PR:** every changed file matches its folder's shape; lint
  passes; §9 is updated if it changed the open-item list.
- **Confused:** open the file's folder. The folder name is the shape. The shape
  is the contract. There is no gray area.

---

## 9. Architecture debt board (open items)

The eight-shape refactor (§3) is far along but not finished; this is the
open-item list — the "what's next," not the "how we got here" (that's git
history). Any ratchet-gate count belongs to its baseline file, never to
prose here: baselines drift release-to-release, so re-count from the file
(`tools/scripts/file_size_ceiling_baseline.txt`,
`tools/scripts/file_size_ceiling_lib_baseline.txt`, etc. — §5) before citing
a number.

| Item | Status |
|------|--------|
| `config/` boot monolith (`boot.c`, `boot_services.c`, `boot_refold_staged.c`) | GATED under the file-size-ceiling ratchet; grandfathered in the ENFORCED baseline, must not grow. Continue only behavior-preserving extractions; larger moves need an explicit seam design. |
| `domain/` fronted by thin `lib/` wrappers | base58 + bech32 collapsed into `domain/` (landed: callers moved to `domain_encoding_*`, the `lib/` wrappers deleted). `upgrades.c` is intentionally kept as two files — `core/params/src/upgrades.c` (the ex-`lib/consensus/upgrades.c`) owns the `NetworkUpgradeInfo`/`SPROUT_BRANCH_ID`/`EquihashUpgradeInfo` tables, `core/consensus/src/upgrades.c` (the ex-`domain/consensus/upgrades.c`) holds the pure activation-height arithmetic that reads them (correct layering, not duplication). The direction is easy to invert from the names alone — ADR-0002's "moved from" table is the authority. `lib/keys/*` + `core/params/src/params.c` remain a future scoping item. Both `core/` files are under the byte seal — see `core/UNSEAL.md`. | <!-- doc-path-ok: "ex-" names are the pre-ADR-0002 locations, deliberately gone -->
| Supervisor shape partial | `app/supervisors/` now declares `net`, `chain`, `staged_sync`, `legacy_mirror`, `self_heal` and the three domains (`domains.c`). Every other long-running service registers its own `liveness_contract` in its own file, so nothing is off the tree — what remains in `config/src/boot_services.c` is the ORDER those registrars run in (`boot_register_core_liveness_and_reducer`), which is load-bearing and pinned by ordering asserts in `lib/test/src/test_make_lint_gates.c`. Moving that sequence needs a seam design, not code motion. Coverage is measured by six gates (`check-supervisor-registration`, `check-supervisor-domain`, `check-thread-supervision`, `check-typed-blocker`, `check-blocker-escape-registered`, `check-blocker-remedy`); the residual debt is the shrink-only `tools/scripts/supervisor_baseline.txt` (10) and `tools/lint/thread_supervision_baseline.txt` (11), both documented per entry. |
| Controller/Service legacy compat | the file-level E1/E2/typed-blocker baselines carry no NEW violations, but import/sync controllers still carry legacy orchestration and services keep bare-`bool` compatibility APIs alongside `zcl_result`. Subtraction work, not new structure. |

Not tracked as debt (do not re-flag): the storage-adapter seam is
outbound-only **by design**, not a migration in progress (§6); there is no
`app/events/` folder — Event stays a concept owned by `lib/event/` + <!-- doc-path-ok: app/events/ deliberately does not exist -->
`lib/storage/src/event_log.c` + projections, never a physical `app/` folder (§3
row 7); the sealed `core/` consensus tree is landed — see
[`docs/adr/0002-sealed-consensus-core.md`](./adr/0002-sealed-consensus-core.md).

Gate mode/status is tracked in §5, not duplicated here.

---

## Glossary

- **Shape** — one of the eight allowed kinds of `app/` code.
- **AR (ActiveRecord)** — the model lifecycle (`AR_*_SAVE`, before/after hooks). Real and lint-enforced.
- **Cursor** — durable position in `consensus.db` a Job advances; enables crash-safe idempotent replay.
- **Reducer** — the stage pipeline; the only writer; advance-cursor-or-name-blocker.
- **Fact log** — `lib/storage/src/event_log.c`; the append-only durable source of truth.
- **Projection** — a pure fold over the log into a queryable view; rebuildable, never authoritative.
- **Witness** — observable post-condition confirming a Condition's remedy actually worked.
- **Blocker** — a typed, named reason a stage cannot advance (height, missing input, source tried).
- **Ratchet** — a gate that can only tighten; the refactor's monotonic guarantee.
