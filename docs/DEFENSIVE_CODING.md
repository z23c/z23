# Defensive Coding Standards — The Rails Way in C23

**Rule: if the compiler can't enforce it, it will be violated.**

These are architectural enforcement patterns that make it impossible for any
contributor (human or AI agent) to accidentally skip validation, swallow
errors, or leak memory. Read this before writing new code.

Modules prefixed `legacy_` are a compatibility layer with an external
`zclassicd` — see [`LEGACY_LIFECYCLE.md`](./LEGACY_LIFECYCLE.md) for which
paths are still load-bearing.

---

## 1. Every write goes through the AR lifecycle — no exceptions

**Problem:** `coins_view_sqlite.c` / `wallet_sqlite.c` once called
`sqlite3_step()` directly with no validation — an unvalidated raw write is how
a UTXO set gets silently corrupted at scale.

**Enforcement:** `activerecord.h` poisons raw `sqlite3_step` in app code at
compile time (a `_Pragma("GCC error …")` macro, guarded by `ZCL_AR_ENFORCE` /
opt-out `ZCL_AR_RAW_SQL` — see `app/models/include/models/activerecord.h`),
plus a CI lint that re-checks the same surface. The Makefile adds
`-DZCL_AR_ENFORCE` globally, so raw SQL becomes a conscious, visible decision.

**The three lifecycle entry points (all in `activerecord.h`).** All three run
the same `validate_*` → `before_save` → `after_save` chain, so model hooks fire
identically. Pick the one that fits the call site:

| Macro | When to use | What it does |
|-------|-------------|--------------|
| `AR_BEGIN_SAVE(cbs, name, rec, validate_fn)` + `AR_FINISH_SAVE(cbs, rec, ok)` | You build the statement yourself between the two macros (multi-statement transactions, conditional binds) | `AR_VALIDATE_RECORD` → `before_save` → your code → `after_save` → `return ok` |
| `AR_ADHOC_SAVE(ndb, stmt, sql, cbs, name, rec, validate_fn, bind_code)` | Single locally-prepared INSERT/UPDATE (the common case) | Wraps `AR_BEGIN_SAVE` + `AR_PREPARE_BOOL` + bind block + `AR_FINALIZE_STEP_DONE` + `AR_FINISH_SAVE` |
| `AR_CACHED_SAVE(stmt, cbs, name, rec, validate_fn, bind_code)` | Hot path with a cached prepared stmt owned by `node_db` | Same lifecycle, skips prepare — call `AR_RESET(stmt)` and bind |

For a worked call-site example (`db_wallet_script_save` using `AR_ADHOC_SAVE`),
see `app/models/src/wallet_key.c`.

Storage primitives that legitimately need raw SQL
(`lib/storage/src/coins_view_sqlite.c`) opt out with `#define ZCL_AR_RAW_SQL`.

**Status: shipped.** The ratchet allowlist
`tools/scripts/raw_sqlite_allowlist.txt` is empty. Raw `sqlite3_step()` is
linted across `app/`, `tools/`, `lib/`, `config/`, and `src/`; production step
calls must use `AR_STEP_ROW`, `AR_STEP_DONE`, `AR_STEP_ROW_READONLY`, or
`AR_STEP_WRITE` unless they carry a reviewed `// raw-sql-ok:<tag>`. Structured
domain-model saves still use the AR lifecycle entry points above so validation
and before/after hooks fire. Direct `sqlite3_exec(ndb->db|ndb.db, "...")` DML
(`INSERT`/`DELETE`/`UPDATE`/`REPLACE`) is also linted and must route through
`ar_exec_write_sql()` / `AR_STEP_WRITE` or a reviewed helper; transaction
control, PRAGMAs, ATTACH/DETACH, schema DDL, projection stores, and the kernel
store remain outside that narrow DML gate. `make lint` runs `check_raw_sqlite.sh`
(one of the gates in the canonical block below).

### The one principled exception: the kernel store (`consensus.db`)

The AR lifecycle is the law for **`node.db` domain models** — blocks, UTXOs,
wallet keys, peers, mempool entries. Those rows have an identity, a
`validate_*` function, and before/after-save hooks.

The reducer pipeline does **not** write its stage state to `node.db`. It writes
to `consensus.db` — a separate, singleton, WAL kernel store
(`lib/storage/src/progress_store.c`/`consensus_db.c`, opened once at boot via
`progress_store_open()`) holding the F-2 `stage` primitive's `stage_cursor`
table plus the per-stage `*_log` tables (`header_admit_log`, `body_fetch_log`,
`validate_headers_log`, `utxo_apply_log`, `utxo_apply_delta`, `created_outputs`,
`tip_finalize_log`, …). The store was physically `progress.kv` before the Wave
A3 flip; a pre-flip datadir is migrated in place on open, and `progress.kv` now
holds only the rebuildable `address_index`/`txindex` projections. This store
sits **below** the AR/domain-model layer by design (see
`storage/progress_store.h`, `storage/consensus_db.h`, `docs/FRAMEWORK.md`): a
`stage_cursor` row is not a model, has no domain identity, no save hooks.
Cursor commits are tiny, hot-path, and want their own WAL out of the way of
larger `node.db` transactions; the saga atomicity contract (a stage advance and
its log row commit together) lives in `progress_store_tx_lock()` +
`BEGIN IMMEDIATE`, not in AR.

Routing these through AR would be a **category error** (no model to validate, no
hook to fire). The discipline:

- A raw `sqlite3_step` on the kernel-store handle (always from
  `progress_store_db()`, never a `node_db`/`ndb` handle) is correct-by-design,
  not migration debt.
- Every such site MUST carry the canonical marker
  **`// raw-sql-ok:progress-kv-kernel-store`** (one no-space token after the
  colon). `progress_store.c` itself uses the equivalent `kernel-primitive` tag.
- This is a **bounded, stable exception**, not a deferred migration — the count
  changes only when the reducer gains/drops a stage table; it does not ratchet
  toward zero. `check_raw_sqlite.sh` treats `progress-kv-kernel-store` as the
  principled kernel-store hatch.

A reducer Job that writes a `node.db` **model** (not a kernel-store `*_log`/cursor
row) does NOT get the kernel-store marker — it goes through the AR lifecycle.

---

## 2. Every function that can fail returns a result type — not bare bool

**Problem:** `return false` with no context. Caller has no idea why.

**Enforcement:** standard result type `struct zcl_result` (`.ok`, `.code`,
`.message[256]`, `.source_file`, `.source_line`) with `ZCL_OK`, `ZCL_ERR`, and
`ZCL_CHECK` macros — see `lib/base/include/base/result.h`.

**Rule:** new service functions MUST return `struct zcl_result` instead of
`bool`. Existing code migrates incrementally.

**Why this works for agents:** an agent that writes `return false;` in a
function declared as returning `struct zcl_result` gets a compiler error. It
MUST write `return ZCL_ERR(-1, "reason: %s", detail);`, forcing it to explain
the failure.

---

## 3. Every malloc is checked — use zcl_malloc or die

**Problem:** 15+ unchecked malloc/calloc calls in sync services → silent NULL
dereference.

**Enforcement:** `lib/base/include/base/safe_alloc.h` provides:

- `zcl_malloc(size, label)` — logs (`malloc_failed` + `EV_OOM`) and returns
  NULL; use when graceful degradation is possible.
- `zcl_malloc_or_die(size, label)` — aborts via `zcl_oom_abort` on failure;
  use when there is no reasonable fallback.
- `zcl_realloc(ptr, size, label)` — never leaks the original pointer (does NOT
  free `ptr` on failure — caller decides).

**Makefile enforcement:** `check-malloc` greps `app/ lib/ config/ tools/` for
raw `malloc`/`calloc`/`realloc` outside the `zcl_*` wrappers, `safe_alloc.h`,
and `vendor/`. Files needing raw alloc add `// raw-alloc-ok` on the line.

---

## 4. Every error path logs with context — use the LOG_* macros

**Problem:** 100+ `return -1;` / `return false;` with no logging.

**Enforcement:** `lib/util/include/util/log_macros.h` provides log-and-return
macros (each logs `error` with `file`/`line`/`func` + varargs):

- `LOG_FAIL(domain, fmt, ...)` — log + `return false`.
- `LOG_ERR(domain, fmt, ...)` — log + `return -1` (for command handlers).
- `LOG_RETURN(val, domain, fmt, ...)` — log + `return (val)`.

**CI lint:** the shape-tier `check-silent-errors-*` gates grep `app/` for
`return -1;` not paired with `LOG_ERR`/`log_json`/`fprintf`.

---

## 5. Native command handlers must log on every error path

**Problem:** silent `return -1;` in a native command handler leaves the caller
with no diagnostic info.

**Status: enforced by lint.** `make lint` runs five shape-tier gates. Each
requires a bare `return -1;` to be preceded by a logging call or carry an
explicit `// raw-return-ok:<reason>` marker (no space after the colon):

| Gate | Surface |
|------|---------|
| `check-silent-errors-services` | `app/services/src/` |
| `check-silent-errors-controllers` | `app/controllers/src/` |
| `check-silent-errors-jobs` | `app/jobs/src/` |
| `check-silent-errors-conditions` | `app/conditions/src/` |
| `check-silent-errors-bool` | `app/{controllers,services,jobs,conditions,models}/src/` (RATCHET) |
| `check-wallet-raw-prepare-log` | raw `sqlite3_prepare_v2()` + unlogged NULL-check in `app/`, `lib/` (RATCHET) |

The service/controller/job/condition gates accept only an *error-level*
preceding log (`LOG_ERR`, `LOG_FAIL`, `LOG_RETURN`, or `log_json` at error
level) — a bare `printf`/`LOG_WARN` no longer satisfies the pairing, so a
silent failure can never masquerade as handled by a warn-level breadcrumb.

The command response helpers enforce that `res->body` is populated on every
error path; the lint also prevents the silent-fail class entirely.

---

## 6. Before/after save hooks — wired

**Status: shipped.** Every critical model wires `ar_register_before_save` and
`ar_register_after_save`. `check-before-save-hooks` enforces that `utxo`,
`block`, and `wallet_tx` keep these hooks — drop one and `make lint` fails.
`wallet_key` is deliberately absent from that list: the model has no AR save
at all (single-writer doctrine — the encryption-aware `wallet_sqlite` layer
is the only writer of the `wallet_keys` / `wallet_sapling_keys` /
`wallet_seed` secret columns, and it owns the `EV_WALLET_KEY_SAVED` /
`EV_SAPLING_KEY_SAVED` + wallet-projection key-add emission at the write
site). The same gate ratchets that the plaintext model saves never return.

| Model | before_save | after_save |
|-------|-------------|------------|
| utxo | Validate money range + script coherence | Update UTXO commitment cache |
| block | Validate hash matches header | Emit `EV_BLOCK_SAVED` |
| wallet_tx | Validate txid format | Emit `EV_WALLET_TX_SAVED` |
| mempool_entry | Validate fee + size envelope | (none) |
| tx_index | Validate txid + block height | (none) |

---

## 7. CI gates — the final enforcer

`make lint` runs the gates listed in the canonical block below (the Makefile
`lint:` target is authoritative); `make ci` runs `lint test fuzz-ci coverage`.

An agent that pushes code with raw malloc, silent errors, bypassed AR
validation, unpaired stderr diagnostics, a critical model missing its
before_save hook, a model file with no `validates_*` call and no
`ar-validate-skip:<tag>` marker, a model save that hand-runs
`ar_run_before_save()` / `ar_run_after_save()` instead of the AR lifecycle
macros, or a controller/service/config-src function over 500 lines
without a `long-function-ok:<tag>` override, gets a red build before any
human sees it.

Gates fall into three modes:

- **HARD / FAIL** — fails on any violation.
- **RATCHET** — fails on a *new* violation while tolerating a recorded
  baseline; the baseline file may only shrink (growing it requires an ADR).
- **WARN** — measures only, per-file, never fails on any ONE violation. Gate
  **#12** (`check-long-functions`) carries a WARN sub-tier for `lib/` (excl.
  `lib/test/`) + `domain/`, alongside its ENFORCED tier for the app-shape
  surfaces. #18 and #20 graduated WARN → RATCHET as **E10**; #19 ratcheted
  WARN → FAIL. **E1** (`check-file-size-ceiling`) used to carry a WARN tier
  with an aggregate drift-count ratchet; both are gone. E1 is now one policy
  for all production C with three bands — an advisory 800-line target, an
  allowed 801..1500 buffer that never fails, and a hard 1500-line limit —
  so there is nothing left to warn about between the target and the limit.

Each gate's intent is one row below. Implementation scripts live under
`tools/scripts/` or `tools/lint/`. The E-series gates are tested in
`lib/test/src/test_make_lint_gates.c` (plant fixture → assert trip → remove →
assert green).

### §3–§6 core gates

| Gate | Mode | Intent / marker |
|------|------|-----------------|
| `check-blob-read-bounds` | HARD | Fixed-size SQLite blob reads in app models use `AR_READ_BLOB` or prove `sqlite3_column_bytes` before `memcpy`. |
| `check-malloc`, `check-raw-malloc` | HARD | Raw malloc/calloc/realloc outside `zcl_*` wrappers (§3). Override `// raw-alloc-ok:<tag>`. |
| `check-raw-sqlite` | HARD | Raw `sqlite3_step` outside `AR_STEP_*` (§1). Override `// raw-sql-ok:<tag>`. |
| `check-json-value-init` | HARD | A `struct json_value` local reaches `json_set_*()`/`json_free()` without `= {0}` or `json_init()`. Those calls free the value's previous contents first, so on an uninitialised local they free/walk stack garbage — this is what segfaulted a serving fixture node every ~15 min through `zid_domain_dump_state_json`. No override: initialise it. |
| `check-silent-errors-services` (+ `-controllers`/`-jobs`/`-conditions`/`-bool`) | HARD | Bare `return -1;` with no error-level log (§4/§5). Override `// raw-return-ok:<tag>`. |
| `check-before-save-hooks` | HARD | `utxo`/`block`/`wallet_key`/`wallet_tx` keep before/after-save hooks (§6). |
| `check-coins-lookup-nullcheck` | HARD | Coins lookups null-check the returned coin before use. |
| `check-log-macro-return-type` | HARD | Returning `LOG_*` macros match the enclosing function return type (`LOG_FAIL` only in bool-returning functions, `LOG_ERR` only in int-returning functions, `LOG_NULL` only in pointer-returning functions). |
| `check-observability-pairing` | HARD | `fprintf(stderr,…)` pairs with an event emit / terminal propagation. Override `// obs-ok:<tag>`. |
| `check-pthread-create` | HARD | Thread spawns go through the sanctioned registry, not raw `pthread_create`. |
| `check-no-runtime-abort` | RATCHET | New runtime `assert(` / `abort(` in network-reachable modules. `_Static_assert` is NOT counted. Override `// abort-ok:<reason>`. |

### Detailed gates

- **Gate: `check-no-runtime-abort`** (RATCHET, shrink-only baseline
  `tools/lint/no_runtime_abort_baseline.txt`) — **`assert()` is live in this
  build.** `-DNDEBUG` appears in exactly two places in the tree, both of them
  the vendored LevelDB compile (`tools/scripts/build_vendor.sh`); the node's
  own `CFLAGS` never define it. Every `assert()` compiled into the node is
  therefore a live `abort()` on failure, and every `assert()` sitting where a
  peer, an RPC argument, an explorer URL segment or a stored blob can reach it
  is a remote process-kill primitive. The Base58 codec under every address,
  WIF, extended key and explorer lookup was exactly that until 2026-07-28, as
  were BIP32 public child derivation and extended-public-key serialization.
  This gate stops the pile re-forming.

  *Scan set* — named roots only (`lib/{crypto,keys,script,sapling,validation,
  net,sync,zid,znam,zslp,zdir,storage,mining,core,platform,util,rpc}`,
  `domain/{encoding,wallet}`, `core/{consensus,math,params,chainparams}`), not
  the whole tree: a whole-tree baseline is dominated by tooling and nobody
  reads it. The `lib/{core,platform,util,rpc}` roots hold no network parsers
  but do hold the entropy sources, the boot-order state machine and the RPC
  command table — the process-wide invariants whose violation must stay loud,
  so the gate counts them to keep those aborts justified rather than merely
  inherited. Note `lib/core/` is an ordinary subsystem; the byte-sealed
  directory is top-level `core/`, whose rows are **counted and frozen** and
  only editable through the owner unseal ritual.

  *Not counted* — `_Static_assert` / `static_assert` (compile-time, and the
  CORRECT replacement for a runtime assertion about a layout or a constant);
  anything inside a comment or a string literal. The gate carries a real
  block-comment state machine, because the rationale comments in this repo are
  multi-line and the word `assert()` lands on continuation lines that carry no
  comment opener of their own.

  *The fix* — reject the input the way every other rejection in this tree
  does: return `false` / `-1`, log the reason with `LOG_FAIL`/`LOG_ERR`/
  `LOG_NULL`, let the caller report it, and the node keeps running. Then lower
  (or delete) the number in the baseline. Raising a number is not a fix.

  *The escape hatch* — `// abort-ok:<reason>`, on the same line as the site,
  for an abort that is CORRECT because continuing would be worse than
  crashing. Unlike the single-token markers in §8 this one takes a **prose
  reason** (minimum six characters; a bare `// abort-ok:` is rejected), same as
  `// thread-supervision-ok:<reason>`. Annotating in place rather than
  baselining is deliberate: the baseline must stay a list of genuine debt that
  may only shrink, so nobody is ever pressured into "fixing" a correct abort to
  lower a number. Current holders: `lib/sapling/src/note_encryption.c` (an
  `esk` repeat would emit a two-time pad under the fixed zero nonce and leak
  the note plaintext), `lib/keys/src/key.c` and `lib/keys/src/pubkey.c` (the
  process-wide secp256k1 signing/verification context lifecycle, and the
  entropy source feeding it — no external input reaches them, each runs once at
  boot, and a node that carried on would silently mis-verify signatures or hand
  out a guessable key), `lib/sapling/src/sapling.c` (a fixed Jubjub generator
  that failed to derive, after which every scalar multiplication is garbage),
  `lib/core/src/random.c` and `lib/platform/src/rng.c` (no entropy source, on
  functions whose return type has no error value — continuing means handing
  back a zero-filled buffer or a predictable integer, and every key minted from
  it is guessable), `lib/util/src/boot_phase.c` (a backward or out-of-range
  boot-stage move, which is the one thing that state machine exists to catch),
  `lib/rpc/src/server.c` (a duplicate or overflowing command name at static
  registration — a node serving a half-built RPC table is worse than one that
  refuses to start).

  *A hatch is a claim, and it is checkable.* `lib/rpc/src/server.c`'s other
  site — `assert(rpc_in_warmup)` in `set_rpc_warmup_finished()` — is
  deliberately **baselined rather than hatched**, and carries a comment saying
  so. It enforces "called exactly once" with a live abort while the paired stop
  hook never restores the flag, so the service kernel's own
  `stop_all` → `start_all` cycle would kill the node there. It is unreachable
  today only because the frontend kernel starts once and the process exits
  after shutdown. That is debt with a real fix (make it idempotent, or re-arm
  warmup in the stop hook), not a correct abort, so it stays on the list that
  must shrink.

  A baselined file with no sites left is a FAILURE, not a pass: a stale row
  rusts the ratchet shut at a number the next regression can hide under.
  Impl: `tools/lint/check_no_runtime_abort.sh`, with a mandatory `--selftest`
  whose `_Static_assert` case is a negative control.

- **Gate #11: `check-model-validation`** (HARD) — every `app/models/src/*.c`
  has at least one `validates_*` call (from
  `app/models/include/models/activerecord.h`) OR a top-of-file
  `ar-validate-skip:<tag>` marker explaining why AR validation does not apply
  (e.g. `connection-handle-not-a-row`). Impl:
  `tools/scripts/check_model_validation.sh`.

- **Gate #11b: `check-model-ar-lifecycle`** (HARD) — `app/models/src/*.c` may
  not call `ar_run_before_save()` or `ar_run_after_save()` directly. Save paths
  must use `AR_BEGIN_SAVE`, `AR_ADHOC_SAVE`, `AR_CACHED_SAVE`, and
  `AR_FINISH_SAVE` so `before_validate -> validate -> before_save -> SQL ->
  after_save` stays one mechanically enforced lifecycle. Impl:
  `tools/scripts/check_model_ar_lifecycle.sh`.

- **Gate #12: `check-long-functions`** — flags any top-level function whose
  body spans >500 lines. Two tiers (a split Gate E1 no longer uses — E1 is
  one policy for all production C now): ENFORCED (HARD, fails the build) covers
  `app/controllers/src/*.c`, `app/services/src/*.c`, and `config/src/*.c`,
  ratchet-baselined at
  `tools/scripts/check_long_functions_baseline.txt` for grandfathered
  offenders (e.g. `config/src/boot.c`'s `app_init`); WARN (prints, never
  fails) covers `lib/**/*.c` excl. `lib/test/`, baselined at
  `tools/scripts/check_long_functions_lib_baseline.txt`. Long functions
  conceal multiple concerns. Override `// long-function-ok:<tag>` on the
  signature line (tag matches `[A-Za-z][A-Za-z0-9_-]+`) exempts a function
  entirely in either tier. Impl: `tools/scripts/check_long_functions.sh`.

- **Gate #13: `check-rpc-registrar`** — every RPC handler declared in
  `lib/rpc/src/` must appear in the registrar table at the bottom of the same
  file, so "method not found" is caught at build time.

- **Gate #14: `check-lag-slo-observable`** — any code path that can produce
  SLO-relevant lag (block lag, peer floor, watchdog miss) must pair with a
  structured event emit and a Prometheus gauge.

- **Gate #15: `check-lib-layering`** (RATCHET) — flags any
  `#include "controllers/…"`, `"models/…"`, `"services/…"`, `"views/…"`, or
  `"config/…"` in `lib/**/*.c|.h` outside `lib/test/`. lib/ is the
  foundation; app/ consumes it and config/ composes the whole process, so
  both sit above it. A backward include means a lib/ file is doing upstairs
  work — and for `config/` it is worse than a misplaced dependency: config/
  constructs the message processor, the reducer and the databases, so naming
  a config/ symbol from lib/ makes the two layers cyclic. When lib/ needs
  something the composition root owns, declare a port in lib/ and register
  the implementation from config/ (`lib/net/include/net/net_runtime_port.h`,
  `lib/storage/include/storage/node_db_runtime.h`). lib/hotswap's
  `../../../config/*.def` X-macro data tables are not matched and carry no
  link edge. Baseline `tools/scripts/lib_layering_baseline.txt` is empty (98
  originals all remediated). Override `// lib-layer-ok:<tag>`. Impl:
  `tools/scripts/check_lib_layering.sh`.

- **Gate #49: `check-shape-include-direction`** (RATCHET) — the eight app/
  shapes include DOWNWARD only (`controllers -> services -> models ->
  lib/core`). Flags any `#include "services/…"` or `"controllers/…"` from an
  `app/models/**` file, and any `#include "controllers/…"` from an
  `app/services/**` file. Baseline
  `tools/scripts/shape_include_direction_baseline.txt`: zero on the
  models/ -> services/controllers edge (its two originals — `principal.c` ->
  `services/authz_policy.h` and `db_txn.c` -> `services/disk_monitor.h` — <!-- doc-path-ok: illustrative bad include, not a real path -->
  were fixed at gate-introduction: the authz policy table moved down into
  `app/models/`, and db_txn's disk-critical check now goes through a
  registered callback, `db_txn_set_disk_critical_probe`, wired from
  `disk_monitor_start()` itself (`app/services/src/disk_monitor.c`); 13
  pre-existing entries grandfathered on the services/ -> controllers/ edge
  (undiscovered until this gate existed).
  Override `// shape-layer-ok:<tag>`. Impl:
  `tools/scripts/check_shape_include_direction.sh`.

- **Gate #45: `check-domain-purity`** (HARD) — `domain/` is the innermost
  layer. A `domain/**/*.c|.h` file (outside `*/test/*`) may only `#include` its
  own `"domain/…"` headers, C/system `<…>` headers, bare domain-local sibling
  files (a quoted include with no slash, e.g. `"reject_out.h"`), or one of the
  12 allowed lib subsystems (`bloom chain coins consensus core crypto keys
  primitives script support util validation`). Any include from an app/ shape
  (`controllers/`, `models/`, `services/`, `views/`) or an unlisted lib/
  subsystem (`storage/`, `ports/`, …) fails the build. No baseline (the tree is
  already clean). Override `// domain-purity-ok:<tag>`. Impl:
  `tools/scripts/check_domain_purity.sh`.

- **Gate #46: `check-core-include-boundary`** (HARD) — the sealed consensus
  core (top-level `core/`, the Wave 1.1 physical split) is the innermost
  layer. A `core/**/*.c|.h|.inc` file may only `#include` its own preserved
  headers (`"domain/consensus/…"`, `"consensus/…"`, `"core/…"`,
  `"chainparams/…"`), C/system `<…>` headers, bare siblings, or a pure leaf lib
  subsystem — **never** `lib/validation` (validation *drives* consensus, it is
  not consensus) or any app/ shape. The gate is **exception-free**:
  `check_block.c` calls the core sigops predicate instead of
  `"validation/sigops.h"`, and `chainparams.h` gets `MESSAGE_START_SIZE` from
  `chain/chainparamsbase.h` instead of `"net/protocol.h"`. Any forbidden
  include fails HARD. Override `// core-boundary-ok:<tag>`. Impl:
  `tools/scripts/check_core_include_boundary.sh`.

- **Gate #47: `check-core-seal`** (HARD — frozen at split wave W5) — pins
  the byte-integrity of `core/` to the SHA3-256 manifest `core/MANIFEST.sha3`
  (per-file digest + a ROOT digest over the sorted `(path, filehash)` stream).
  Any change to a sealed file changes ROOT. Regenerate with `make core-seal`;
  verify standalone with `make core-seal-check` (fails loud). A deliberate
  consensus-core change goes through the owner unseal ritual
  (`make core-unseal REASON=…` → append-only `core/UNSEAL.md` + one-shot
  `.core-unseal-token`). Tool: `tools/core_seal.c` (no external deps: links the
  in-tree FIPS-202 SHA3-256).

- **Gate #52: `check-core-seal-root-mirror`** (HARD) — the hot-swap consensus
  pin. A Tier-2 module .so is compiled from ONE shape-leaf TU and mounts into a
  resident that supplies every other body it calls, so the two halves must agree
  about the sealed consensus core they share. `hotswap_module_admit()` checks
  abi_version, fields, capacity, the allowlist row, duplicates and the probe
  leaf — six stages, none of them about consensus. That gap was reachable: the
  sealed headers ship `static inline` consensus arithmetic
  (`consensus_last_founders_reward_height()`,
  `consensus_subsidy_slow_start_shift()`, the compact-size sizing in
  `core/serialize.h`), and a controller including one compiles a PRIVATE COPY
  into its .so — so a module built before a seal re-cut still mounted and still
  ran its stale copy. `lib/hotswap/include/hotswap/core_seal_root.h` mirrors
  `core/MANIFEST.sha3`'s ROOT, the module emitter stamps it into every artifact
  as `zcl_hotswap_module_core_seal_root`, and `hotswap_activate.c` compares it
  on BOTH dlsym paths (resident mount and offline verifier) before admit. This
  prevents stale leaf publication; it is not a pre-execution sandbox because
  `dlopen` may run ELF constructors before a symbol can be checked. The
  gate proves all three: current, exported, enforced. Regenerate the mirror with
  `make core-seal`. The pin is the seal ROOT and NOT a whole-tree build id on
  purpose — a controller edit must not invalidate a module (that is the fast
  loop), a consensus edit must invalidate every one of them.

- **Gate #53: `check-hotswap-package-receipt-is-not-authority`** (HARD) — a
  packaged module ships a `<artifact>.manifest` receipt (schema
  `zcl.hotswap_package.v1`, written by `tools/dev/hotswap-package.sh`) recording
  its SHA3-256, source TU, leaves, `abi_version` and `core_seal_root`. That file
  is a receipt for a HUMAN, never an admission input, and the gate keeps the
  resident from ever growing a fast path that reads one. Be precise about what
  that buys, because the obvious stronger sentence is false: an attacker who
  can write the .so can also write the sidecar, and can stamp the correct
  `core_seal_root` into their own module — `ZCL_CORE_SEAL_ROOT` is a
  checked-in public constant, not a secret. Against *that* attacker neither
  mechanism helps, and `dlopen` has already run the module's `.init_array`
  constructors before any stage is consulted. What the gate actually enforces
  is that admission RE-DERIVES its facts from the artifact instead of caching
  them in a file: the dlsym'd `zcl_hotswap_module_core_seal_root`/`abi_version`
  and an fd-pinned digest hashed from the same descriptor that is then dlopened
  through `/proc/self/fd/N`. The fd discipline makes the load
  **redirect-proof** — the loader cannot be pointed at a different inode
  between hash and map — but NOT tamper-proof: an in-place overwrite of the
  same inode still swaps the mapped bytes (measured; see
  `hotswap/hotswap_artifact_digest.h` for the memfd-seal fix that would close
  it). The pin's real job is staleness — a module compiled against a
  superseded sealed core cannot mount — and that it does completely. The gate
  proves the resident never opens, stats or parses a manifest: no quoted
  `".manifest"` literal, no `zcl.hotswap_package` schema string, and no
  `fopen`/`open`/`openat`/`stat`/`lstat`/`access`/`opendir`/`readlink` on a line
  mentioning a manifest, anywhere under the loader and activation sources.
  `dlsym` is deliberately excluded — reading the artifact's own symbols is the
  behaviour this gate is protecting. It also refuses to report a clean scan of
  a tree containing no sources, and names the directories and file counts it
  actually scanned in its OK line. `--selftest` mirrors those directories into
  scratch, plants a violating TU in the COPY, and asserts the gate trips and
  then recovers — never writing into `lib/hotswap/`, because a fixture living
  briefly in the real tree races the other gates under `make -j24 lint`.

- **Gate #54: `check-hotswap-module-imports`** (HARD) — a Tier-2 hot-swap
  module is a `.so` compiled from ONE shape-leaf TU and `dlopen`'d into the
  **live** node's address space, so every body it does not define itself is
  resolved out of the resident image at load time. That makes the module's
  UNDEFINED dynamic-symbol set its complete, mechanically-derivable interface
  to the node — a device-driver contract in the literal sense. It existed in
  practice and was enforced nowhere. None of the sibling gates looks at what a
  module *links against*: Gate #52 checks the sealed-core pin, Gate #53 checks
  that admission re-derives its facts from the artifact,
  `check-hotswap-swappable-shape` checks the TU's path and its leaves'
  READY/read-only spec, `check-hotswap-static-state` checks mutable file-scope
  statics. So a controller edit that added one `#include` and one call could
  acquire a door into the reducer, the coins view, the wallet spend path or
  chain state, pass every one of them, and mount — with no diff a reviewer
  could read as a reach change, because the change *is* an `#include`. The
  declared contract is `config/hotswap_module_imports.def`: 282 rows derived
  mechanically from the real undefined-symbol union across the 93 built module
  artifacts (`nm -D --undefined-only`, `@GLIBC_x.y.z` version suffix stripped —
  a glibc bump renames a symbol without widening reach), each row carrying the
  group that says *why* it is allowed. Four groups are noise a reviewer should
  not have to approve — `TOOLCHAIN` (gcc's weak `__gmon_start__`/`_ITM_*`
  hooks), `LIBC`, `JSON` (the leaf's return path) and `LOG`. The remaining six
  are real node entry points and are the part to think about: `NODE_COMMAND`
  (the RPC bridge, argument builder and reply construction — `node_rpc_call`
  dispatches an arbitrary method by NAME and is the widest door in the file,
  allowed only because the leaf reaching it is independently pinned
  READY + `EFFECT_READ`), `NODE_STATUS`, `NODE_DB`, `NODE_UTIL`,
  `NODE_HOTSWAP` and `NODE_APP`. The `.def` is explicit that `NODE_DB` and
  `NODE_APP` are **not** uniformly read-only (`db_*_save`,
  `rom_seed_policy_set_enabled`, `wallet_recovery_run`, `auth_login_verify`
  and friends write) — the read-only property is enforced one level up by the
  leaf-spec gates, and a future row that mutates *consensus* state must be
  refused outright. The list is a CEILING, not a wish list: shrinking it is
  always safe, growing it is the reviewed act. Be precise about what this
  buys: it is a build-time lint over developer-produced artifacts, not a
  runtime authority — an attacker who can write the `.so` can write the
  `.def` too. What it enforces is that a mounted module's reach cannot grow by
  accident, and cannot grow deliberately without a line in a reviewed data
  file saying so. Zero modules is never a pass: the contract leg (file parses,
  ≥100 rows, every row classified, no duplicates) is fail-closed and needs no
  build, a `build/hotswap` that **exists and holds no `.so`** is FATAL (a
  producer that ran and emitted nothing is the hollow-scan shape), and a
  `build/hotswap` that was **never produced** prints `UNOBSERVED` — exit 0 but
  the word OK is never printed for the artifact leg, because making a fresh
  clone red is how a gate gets deleted and the invariant goes back to being
  enforced nowhere. `--selftest` compiles its own clean module plus a
  violating one into a scratch sandbox, mirrors the real artifacts in beside
  them, and asserts the gate trips naming both module and symbol and then
  recovers — never writing into `build/hotswap`, because a fixture living
  briefly in the real tree races the other gates under `make -j24 lint` and a
  concurrent build would try to consume it. Two further selftest legs prove
  the sandbox override is refused without the selftest marker and refused for
  any path outside the scratch root, so a stray environment variable can never
  redirect a real `make lint` scan.

- **Gate #48: `check-privileged-transition-receipt`** (RATCHET — Law 7, OS-A1) —
  every native command leaf whose spec is `ZCL_COMMAND_AUTH_OWNER` **and** effect
  `ZCL_COMMAND_EFFECT_MUTATE`/`ZCL_COMMAND_EFFECT_DESTRUCTIVE` is a candidate
  privileged transition and MUST carry a disposition in
  `tools/lint/privileged_transition_receipt_baseline.txt`: `receipt:<file>` (the
  handler binds an authority receipt — an independently-derived record over
  {artifact digest, context anchor, the exact running-binary image} re-checked
  fail-closed at use time, see `lib/util/include/util/authority_receipt.h`) or
  `exempt:<reason>` (not an artifact-install transition). A NEW owner-mutating
  leaf with no disposition FAILS, forcing a conscious Law-7 review. Each
  `receipt:<file>` line is positively checked: `<file>` must still call
  `authority_receipt_*_available(` (or the pre-generalized
  `consensus_state_replay_receipt_authority_available(`), so a wired gate cannot
  silently vanish. The generalized idiom (`lib/util/src/authority_receipt.c`) is
  the foundation for safe hotload AND signed off-chain contracts; the original
  live instance is `config/src/consensus_state_replay_receipt.c` (the sovereign-
  cure ACTIVATE gate, intentionally not rewired). Impl:
  `tools/lint/check_privileged_transition_receipt.sh`.

- **Gate #50: `check-telemetry-ontology`** (HARD) — every network telemetry
  field a covered `dumpstate` function emits must carry a machine-readable
  meaning row in `lib/util/include/util/telemetry_ontology.def`: what it
  counts, a machine-evaluable health rule, what an unhealthy value implies,
  and the exact next command. The defect it closes is real —
  `"pre_handshake_disconnects":27` on a healthy node and the same field at 8
  on a node that cannot start are IDENTICAL IN SHAPE, and only the second is
  the whole story. `tools/lint/telemetry_ontology_scan.txt` declares the
  covered surface as (subsystem, file, function, json-target-variable,
  path-prefix) rows; the gate slices each named function, extracts its scalar
  emissions, and fails on an UNANNOTATED FIELD (named with `file:line`) or an
  UNMAPPED EMISSION TARGET (a new JSON sub-object the manifest does not map,
  so its fields could not be checked at all). Floors on manifest rows,
  ontology rows, judged (non-info) rows and extracted fields make a hollow
  scan exit 2 rather than pass. Self-test:
  `lib/test/src/lint_gate_quality_selftests.c:t_telemetry_ontology_gate`.
  Impl: `tools/lint/check_telemetry_ontology.sh`.

- **Gate #51: `check-accel-oracle-pinned`** (HARD) — the `core/` seal (Gate #47)
  covers the TEXT of the consensus predicates, not the ISA-dispatched
  arithmetic they call. `core/math/src/hash.c` and
  `core/consensus/src/script_interp.c` call `lib/crypto/src/sha256.c`,
  `core/consensus/src/equihash.c` calls the batched BLAKE2b in
  `lib/crypto/src/blake2b_avx2.c`, and `coins/coins.h` reaches the BLS12-381 /
  BN254 Montgomery multiplies in `lib/sapling/`. Editing any of those changes
  which blocks are valid while `check-core-seal` stays green (proven: appending
  a comment to `sha256.c` leaves `make lint` fully green). Freezing them is the
  wrong answer — they exist to get faster — so this gate pins the PROPERTY
  instead of the bytes: every ISA-dispatched file in the include-closure of
  `core/` must carry a row in `tools/lint/accel_oracle_registry.txt` naming a
  differential oracle that proves it byte-identical to a portable reference.
  The gate recomputes the closure and the ISA set from source each run, so a
  NEW accelerator or a new `#include` edge from `core/` that reaches one fails
  HERE; it also fails on a stale row, a missing oracle, an oracle whose group
  is absent from `tools/dev/test_group_catalog.def` (compiled
  but never dispatched proves nothing), and an oracle that references no
  symbol the implementation exports. Each oracle carries the marker
  `ACCEL-ORACLE: <impl path>`. Impl:
  `tools/lint/check_accel_oracle_pinned.sh`.

- **`check-no-adx-overclaim`** (HARD) — the companion to the gate above. The
  accel oracle proves an accelerator computes the RIGHT answer; this one proves
  its operator-visible label describes the instructions it actually runs. The
  bug it exists for: `lib/sapling/src/bn254_accel.c` and the BLS12-381 Fr/Fp
  tier in `lib/sapling/src/fr_avx512.c` both carried
  `__attribute__((target("bmi2,adx")))` and both reported themselves as
  `"BMI2+ADX (MULX+ADCX+ADOX)"` into the boot banner — while
  `bn_fq_mont_mul_bmi2` disassembled to 8 `mulx`, 4 `adc`, 24 `add`, 13 `setb`
  and **zero** `adcx`, **zero** `adox`. The target attribute only makes the
  compiler WILLING to emit ADX; `_addcarry_u64` and `_addcarryx_u64` both lower
  to plain ADC because C cannot express "keep one carry in CF and another in OF
  simultaneously", which is the entire point of the instruction pair. An
  operator read that banner to decide a host was on the fast path, and an
  optimiser read it to decide the work was done. The gate grades object code,
  not prose: for every `lib/` source that carries the ADX target attribute **or**
  includes the shared inline-asm core `lib/sapling/src/mont_adx.h`, it compiles
  the file with the node's own `-std=c23 -O3 -march=x86-64-v3` and counts
  `adcx`/`adox` in the disassembly. Naming ADCX/ADOX outside a negation with
  none emitted is a violation. Fail-closed — a compiler or `objdump` it cannot
  run exits 2 rather than reporting a scan it never performed. Honest
  downgrades pass: a banner that says the tier is `"BMI2 MULX"`, or a comment
  that explicitly denies the claim, is the intended alternative to building the
  chains. Both files are repaired today (inline asm in `mont_adx.h` pins the two
  chains to the two flags); this gate keeps them that way and grades anything
  that joins them. Impl: `tools/lint/check_no_adx_overclaim.sh`.

- **`check-simd-os-support`** (HARD) — CPUID reports what the SILICON can
  decode. It does not report whether the OS agreed to save the corresponding
  register state across a context switch. If it did not, the first wide
  instruction is `#UD` — the process takes a SIGILL even though CPUID said the
  feature was present. `noxsave`, `clearcpuid=avx512f`, and hypervisors that
  mask XCR0 all produce exactly that machine. `lib/crypto/src/blake2b_avx2.c`
  shipped with it: `detect_features()` dispatched its AVX2 tier on CPUID.7.0:EBX
  bit 5 with no OS-state check at all, and that code path is Equihash PoW
  verification — the fault would have landed on the consensus path on a host
  whose boot flags we do not control. The AVX-512 arms in that file,
  `keccak_x4.c`, and `fr_avx512.c` *did* read XCR0, but executed `XGETBV`
  without first confirming CPUID.1:ECX[27] OSXSAVE, and `XGETBV` is itself `#UD`
  when the OS has not enabled XSAVE — checking the state word with an
  instruction that faults for the same reason the state word would have told you
  about is not a check. The rule: any file carrying
  `__attribute__((target("avx…")))` must (1) include `crypto/simd_dispatch.h`,
  (2) read XCR0 **and** name OSXSAVE locally, or (3) gate on a named delegate
  predicate, which the gate then holds to (1) or (2) in turn so delegation
  cannot launder the requirement. `target("sha,…")`, `target("sse…")` and
  `target("bmi2,adx")` are deliberately out of scope — XMM and
  general-purpose-register instructions with no XSAVE state component beyond
  what 64-bit mode always enables, so CPUID alone settles them. Form (1) is
  preferred because `crypto/simd_dispatch.h` splits the hardware PROBE from a
  PURE policy over three register words, which lets
  `lib/test/src/test_simd_os_support.c` hand the policy the exact CPUID/XCR0
  contents of an AVX-512 host whose OS disabled ZMM state — a machine we do not
  own — and pin that the answer is "no". Impl:
  `tools/lint/check_simd_os_support.sh`.

- **Gate #16: `check-supervisor-registration`** (RATCHET) — flags any
  `app/services/src/*_service.c` that spawns work (`pthread_create`,
  `thread_registry_spawn`, `health_register_periodic`) but does NOT call
  `supervisor_register(`, is not baselined, and has no `// supervisor-ok:<tag>`.
  The time-driven supervisor in `lib/util/supervisor.{c,h}` exists because an
  untracked periodic sweeper can wedge and leave every check it owns silently
  dead; registered children fire `on_tick` / edge-trigger `on_stall`
  independently. Standing children include `sync.watchdog`,
  `net.outbound_floor`, `chain.coord_escalation`. Baseline
  `tools/scripts/supervisor_baseline.txt` (drained to 0 entries). Impl:
  `tools/scripts/check_supervisor_registration.sh`.

- **Gate #17: `check-typed-blocker`** — any code raising a `block_id` must use a
  typed kind from `enum blocker_kind` (`lib/util/src/blocker.c`); raw string
  blockers fall in a baseline.

### Framework refactor gates (#18–#22)

- **Gate #18: `check-framework-shape`** (RATCHET, was WARN) —
  `tools/lint/framework_shape_check.sh`. Every `.c` under `app/` must live in
  one shape folder: `controllers`, `services`, `models`, `jobs`, `supervisors`,
  `conditions`, `events`, `views`. Baseline
  `tools/lint/framework_shape_allowlist.txt` (empty). Fix: move the file or
  split mixed responsibilities.

- **Gate #19: `check-no-raw-clock-outside-platform`** (FAIL) —
  `tools/lint/check_no_raw_clock_outside_platform.sh`. Bans direct
  `clock_gettime(`, `time(NULL)`, `getrandom(` outside `lib/platform/`. Route
  wall-clock/monotonic through the platform clock and entropy through platform
  RNG. Override `// platform-ok` on the line.

- **Gate: `check-no-shellouts`** (FAIL) —
  `tools/lint/check_no_shellouts.sh`. Bans `system(`, `popen(`, `execlp(` in
  the resident node binary's own code (`app/`, `lib/` excl. `lib/test/`,
  `src/`, `config/`). Every shell-out has been migrated onto the two in-tree
  primitives — `lib/util` `file_tree_ops` (`zcl_tree_copy` / `zcl_tree_remove`,
  fd-based, no shell) and `lib/util` `spawn` (`zcl_spawn_detached` /
  `zcl_spawn_capture`, argv-array, no `/bin/sh`). This is os-substrate Rung 0
  (`docs/work/os-substrate-plan.md` §1) and the precondition for a future
  seccomp `execve` deny-list. Standalone dev/bench/CLI binaries under `tools/`
  and the `lib/test/` fixtures are out of scope. Override `// shellout-ok` for
  a documented, reviewed exception.

- **Gate: `check-no-writer-below-sealed-frontier`** (FAIL) —
  `tools/lint/check_no_writer_below_sealed_frontier.sh`. The North Star's
  single-writer-per-frontier invariant
  (`docs/ARCHITECTURE_NORTH_STAR.md` invariant 1) made mechanical for the
  sealed ROM segment store (`lib/storage/chain_segment`), which is
  written-once-then-immutable (chmod 0444, never rewritten/appended). Only the
  designated sealer/RPC/healer surface — `lib/storage/src/chain_segment.c`, its
  header, `app/services/src/segment_sealer_service.c`,
  `app/controllers/src/chain_segment_controller.c`,
  `app/conditions/src/segment_corruption.c` — may call the store's two WRITE
  entry points, `chain_segment_seal_range()` /
  `chain_segment_manifest_rebuild()`. Any other production caller is addressing
  a block position below the sealed frontier with write intent and can race the
  one background sealer or the corruption healer's unlink-then-rebuild repair.
  `lib/test/` is out of scope. Override `// writer-below-frontier-ok` for a
  documented, reviewed exception (today: the deterministic simulator's
  sealed-segment corruption fixture, which seals only into a tmpdir it owns).
  Not hollow: the raw scan set is asserted against a floor via
  `gate_require_scanned`, and every allowlisted file must exist, so a rename
  aborts LOUD rather than reporting clean.

- **Gate: `check-proc-self-shim`** (RATCHET) —
  `tools/lint/check_proc_self_shim.sh`. Bans raw `"/proc/self` / `"/proc/uptime`
  string literals in `app/`, `config/`, `lib/`, `tools/` outside
  `lib/platform/`. Route process/host memory, uptime, and exe-path reads
  through `platform/os_proc.h` (os-substrate Rung 1,
  `docs/work/os-substrate-plan.md` §2). Baseline
  `tools/lint/proc_self_shim_baseline.txt` (shrink-only); the one permanent
  exemption is `lib/sim/src/postmortem.c`'s async-signal-safe crash-handler
  copy, which cannot route through a non-signal-safe shim.

- **Gate #20: `check-no-raw-sqlite-in-controllers`** (RATCHET, was WARN) —
  `tools/lint/check_no_raw_sqlite_in_controllers.sh`. Bans
  `sqlite3_prepare_v2(` / `sqlite3_exec(` in `app/controllers/`. Baseline
  `tools/lint/no_raw_sqlite_in_controllers_baseline.txt` (may only shrink). Fix:
  move reads behind projections/models, writes through the AR lifecycle.
  Override `// raw-controller-sql-ok`.

- **Gate #21: `check-supervisor-domain`** (FAIL) —
  `tools/lint/check_supervisor_domain.sh`. Production `supervisor_register(`
  calls under `app/`, `config/`, `lib/` must use
  `supervisor_register_in_domain(...)` (`chain`, `net`, `mempool`, `wallet`,
  `feature`, `onion`, `op`). Deliberate root child: `// supervisor-root-ok:<tag>`.

- **Gate #22: `check-framework-filename-suffix`** (FAIL/HARD) —
  `tools/lint/check_framework_filename_suffix.sh`. No `.c` under a shape folder
  may end in a DIFFERENT shape's suffix (the eight: `controller`, `service`,
  `model`, `view`, `job`, `supervisor`, `condition`, `event`). A file may keep
  its own folder's suffix or a bare entity name (`models/block.c`); only a <!-- doc-path-ok: suffix example, not a path -->
  foreign suffix is rejected. `_store`/`_repository` name no shape. Recurrence
  guard for the S1 renames. If an entity name legitimately ends in a shape word
  (`models/file_service.c`), add `// suffix-ok:<tag>`. <!-- doc-path-ok: suffix example, not a path -->

- **Gate #23: `check-thread-supervision`** (RATCHET) —
  `tools/lint/check_thread_supervision.sh`. Universalizes Gate #16 from the
  services dir to EVERY `thread_registry_spawn(` call site under `app/`,
  `lib/`, `config/`. Each spawned long-running thread must be accounted for:
  (a) SUPERVISED — its TU registers a liveness contract
  (`supervisor_register{,_in_domain}(` or the lib/util adapter
  `thread_liveness_register(`), or the spawn line/line-above carries a
  `// supervised:<child>` marker; (b) MARKED-EXEMPT — a
  `// thread-supervision-ok:<reason>` marker (bounded/joined worker pool,
  one-shot job); or (c) BASELINED — the thread's name literal is in
  `tools/lint/thread_supervision_baseline.txt` with a disposition +
  justification. Anything else is a NEW unaccounted thread → FAIL. The
  baseline may only SHRINK: a stale entry (thread renamed/removed/now-covered)
  fails, forcing the count down as threads gain contracts via
  `util/thread_liveness.h` (exemplar `lib/health/src/heartbeat.c`). Closes the
  gap where the lib/ + config/ infrastructure threads (health sweep, metrics,
  event dispatch, RPC-timeout, DB worker/checkpoint) were spawned but never on
  the supervisor tree — a wedged loop there was silent, the exact Round-5
  failure mode. Raw `pthread_create` is separately gated by
  `check-pthread-create`. The `SUPERVISOR_CAP` static registry was raised
  32→64 to seat the new root children.

#### Bounded thread restart policy (Erlang/OTP), alongside Gate #23

Universal supervision (Gate #23) makes a wedged/dead infra thread a *named
blocker* instead of a silent stop. The restart policy goes one step further for
threads that are safe to auto-restart: it *respawns* them under a bounded
intensity cap (`lib/util/include/util/supervisor.h` +
`util/thread_liveness.h`). The policy is opt-in per child; the default is
`SUPERVISOR_RESTART_TEMPORARY`, i.e. unchanged named-blocker behavior.

- **Policy enum** (`enum supervisor_restart_policy`): `TEMPORARY` (never
  auto-restart — the default and the only policy for consensus/stateful
  threads), `TRANSIENT` (restart only on abnormal exit), `PERMANENT` (always
  restart while the node runs).
- **Which threads may be PERMANENT — the safe-restart criterion:** ONLY a pure,
  stateless *periodic-loop* worker with NO consensus/shared mutable state, where
  re-entering the loop from scratch is a no-op on correctness. Today exactly
  three qualify and opt in via `thread_liveness_register_restartable`:
  `zcl_metrics` (stats printer + Prometheus gauge setter),
  `zcl_health_sweep` (independent snapshot-and-dispatch each sweep), and
  `zcl_rpc_timeout` (periodic timeout sweep; all persistent state lives on the
  manager, not the thread). Everything else stays `TEMPORARY`. In particular
  the **8 reducer stages, the reducer drive, and the DB worker/checkpointer MUST
  stay TEMPORARY** — respawning them mid-fold is a correctness hazard; they keep
  the named-blocker + operator model.
- **Die-vs-stall detection:** the worker publishes an atomic
  `worker_state` (ALIVE at loop entry / on every heartbeat, EXITED just before
  it returns). A *slow* worker is still ALIVE (heartbeat lapsed → the existing
  stall/named-blocker path); a *dead* worker is EXITED → the restart path.
  Honesty caveat: a hard SIGSEGV takes down the whole process (POSIX C has no
  per-thread crash recovery), so the recoverable failure is an abnormal RETURN
  from the loop, not an independent segfault. The respawn additionally reaps and
  guards with `pthread_tryjoin_np` (EBUSY ⇒ the worker is actually still alive ⇒
  abort without spawning) so a false EXITED can never double-spawn a live
  thread; a supervisor-only `RESTARTING` claim state prevents the reverse
  lost-signal race.
- **Restart-storm cap (OTP intensity/period):** at most N restarts within M
  seconds per child (the three workers use N=5 / M=60 s). The (N+1)th death
  inside the window stops respawning and names a PERMANENT blocker
  `thread_restart_storm_<name>` — the node stays alive and named, and never
  infinite-spawns or crashes the process. The cap is sticky (a resumed
  heartbeat does not clear it); an operator diagnoses and restarts.

`ZCL_LINT_MODE` (`WARN` | `RATCHET` | `FAIL`) selects mode for #18/#20; `make
lint` runs them in `RATCHET`.

### Build-checklist gates (E-series)

Tooling-only: each turns the build red on a *regression* without breaking the
current green tree.

| Gate | Mode | Intent / baseline / override |
|------|------|------------------------------|
| **E1: `check-file-size-ceiling`** | RATCHET | The file-size policy for every production `.c` (`app/`, `config/src/`, `lib/` excl. `lib/test/`, `domain/`, `src/`), in three bands: **800 lines is the advisory TARGET** (95% of the tree already meets it), **801..1500 is an ALLOWED buffer** — never fails, no baseline row, no churn — and **over 1500 FAILS**. 1500 is where a file stops fitting in one agent read, so past it every later reader works blind. Files already over 1500 are carried in `tools/lint/file_size_policy_baseline.txt` (`<path> <max-loc>`), which may only shrink: a row that grows fails, a row whose file drops to 1500 or fewer must be deleted, and nothing is ever added. No inline override; generated/tabular code is skipped via the tool's `ALLOWLIST`. Implemented as a C23 binary, `tools/file_size_policy.c`. |
| **`check-hex-codec-single`** | RATCHET | Base-16 encode/decode lives only in `lib/base/include/base/hex.h` (`zcl_hex_encode`, `zcl_hex_decode`, `zcl_hex_decode_lower`, `zcl_hex_decode_n`, `zcl_hex_nibble`). Per-file shape detectors: a hex-digit table **plus** a high-nibble index (encoder), or nibble-ladder arithmetic / `sscanf("%2x")` (decoder). Baseline `tools/lint/hex_codec_baseline.txt` (one path per line; may only shrink, and a row that no longer matches must be deleted). `lib/base/` is the canonical home; `lib/test/` is excluded because a known-answer fixture must not parse its vectors with the implementation under test. No inline override — the fix is to call the codec. `--selftest` plants a fresh encoder and decoder and requires the scan to reject them. |
| **`check-byte-order-codec-single`** | RATCHET | Packing/unpacking a fixed-width 16/32/64-bit integer at a byte address lives only in `lib/base/include/base/serialize_le.h` (`zcl_write_u{16,32,64}_le` / `zcl_read_u{16,32,64}_le`, the `i32`/`i64` forms, and the `u32`/`u64` big-endian pair); `crypto/common.h`'s `ReadLE`/`WriteLE` forward to it. Per-file shape detectors: an indexed shift loop (`>> (8 * i)` in either operand order), an unrolled ladder (a shift by 24 or 56 **plus** a byte-array subscript on the same line — a bare `>> 24` is ordinary bit work and does not match), or a hand-rolled byte-swap mask. Baseline `tools/lint/byte_order_codec_baseline.txt` (one path per line; may only shrink, and a row that no longer matches must be deleted). `lib/base/` is the canonical home; `lib/test/` is excluded because `test_byte_order_codec.c` deliberately keeps a verbatim copy of every replaced helper and asserts the canonical functions agree with it byte for byte; `core/` is excluded because it is byte-sealed. No inline override — the fix is to call the codec. `--selftest` plants each detected shape and requires rejection, plus innocent bit work and a canonical caller and requires acceptance. |
| **`check-zcode-package-registry`** | HARD | Re-derives the content manifest, unsigned release/signing root, recipe, target-inclusive exact dependency lock, and API capsule roots for the nine real C23 Commons Alpha packages directly from their authoritative `lib/<module>` trees. The public alpha-fixture publisher, sequences, empty reward address, `zclassic-main`, exact roots, and closed dependency DAG are projected in `config/zcode_package_registry.def`. Drift, an unresolved dependency, or a selected package source/API change without regenerating the projection fails. Production source ownership remains the unique `LIB_MODULE` row checked independently by `check-lib-module-order`, so the monolith compiles each package module source exactly once. No baseline or override. |
| **`check-zcode-package-standalone`** | HARD | Every registry package compiles from its OWN declared dependencies and nothing else. A package ships to a node that has only the packages its manifest names, so an include reaching outside that set makes it unbuildable there however well it builds inside this monolith, where every `-I` is already on the command line. For each `ZCODE_PACKAGE` in `config/zcode_package_registry.def` and `config/zcode_c23_commons_app.def`, every shipped source is compiled with `-I<pkg>/include` plus the include dir of each declared dependency, under the recipe's own quick profile read from `config/include/config/c23_commons_build_profile.h` so the gate cannot drift from the contract it mirrors. A manifest declaring `files[]` is honoured exactly. Include CLOSURE only: it does not link, run tests, or judge roots. Hollow scans (zero packages parsed, or zero sources compiled) exit 2. No baseline or override. |
| **E2: `check-one-result-type`** | RATCHET | New `app/services/src/*.c` reference `struct zcl_result` (§2) instead of bare bool/int. File-granularity. Baseline `one_result_type_baseline.txt` (empty; 9 originals migrated). Override `// one-result-type-ok:<tag>` (pure table/registry helper). |
| **`check-service-result-convergence`** | RATCHET | Phase 3 sibling to E2: counts *exported* (non-static, top-level) bare-bool function DEFINITIONS per `app/services/src/*.c` file, so a file cannot stay E2-clean forever while still exporting legacy bool functions alongside its one `zcl_result` use. Baseline `service_result_convergence_baseline.txt` (`<path> <count>`; may only shrink; a file whose live count reaches 0, or that gains the `// one-result-type-ok:<tag>` marker, must be deleted from it). Same override marker as E2. Inventory + lane plan: `docs/work/service-result-convergence.md`. |
| **E3: `check-shape-includes-header`** | HARD | A shape file must include its shape contract header: conditions → `"framework/condition.h"` or `"conditions/"`; models → a `"models/"` header (pulls AR lifecycle); supervisors → `"supervisors/"` or `"util/supervisor.h"`. `app/jobs/` skipped (no `job.h` yet). Override `// shape-include-ok:<tag>`. |
| **E4: `check-projections-pure`** | HARD | A projection (`lib/storage/src/*_projection.c`) is a pure fold: no `#include` from `app/services/`-`app/controllers/`, and no AR save path (`AR_*_SAVE`, which would fire another model's hooks). Override `// projection-cache-ok:<tag>` (memoize a derived value into the projection's own table). |
| **E6: `check-one-write-path`** | RATCHET | New chain-state write surfaces forbidden unless they route through the reducer/log authority. Scans for legacy writers (`active_chain_set_tip`, `coins_view_*` flush/write, `process_new_block`, `connect_tip`, `disconnect_tip`, `utxo_projection_set_author`) vs `one_write_path_baseline.txt`. Override `// one-write-path-ok:<tag>` (compat wrapper, not a second consensus writer). |
| **E6b: `check-frontier-single-writer`** | RATCHET | Every frontier in `arch_frontier_owners.tsv` has one canonical owner. Current non-owner writers are explicit in `frontier_single_writer_baseline.tsv`; a new clone or stale baseline row fails, and Q2 must shrink the baseline to empty. No inline override. |
| **E6c: `check-dumper-never-blocks`** | RATCHET | No `*_dump_state_json` function body reaches a blocking primitive (`progress_store_tx_lock(`, `stage_log_row_count(`, `stage_cursor_count(`, `from_anchor_target`) — it publishes through the snapshot plane (`util/subsystem_snapshot.h` / `jobs/stage_log_rows.h`) and reads lock-free, using `progress_store_tx_trylock` only for cold single-row detail. Manifest `dumper_blocking_primitives.tsv`; reviewed-but-unmigrated sites in `dumper_blocking_baseline.tsv` (goal empty). No inline override. |
| **E7: `check-no-authoritative-ram-state`** | RATCHET | No direct `active_chain` internals access / new global-static `struct active_chain`. Derived RAM indexes only via accessors; consensus authority is the log/projection/cursor surface. Baseline `no_authoritative_ram_state_baseline.txt` (empty). Override `// ram-state-ok:<tag>` (documented derived cache). |
| **E8: `check-no-silent-ready`** | HARD | The block-connection authority (`app/services/src/chain_activation_service.c`) must advance-the-tip OR name a typed blocker every tick (FRAMEWORK.md Prime Directive). Any `activation_set_state(…, ACTIVATION_READY, …)` must also route a typed blocker via `blocker_set(` (or `activation_set_behind_blocker(`). Closes the silent-ready hole class (e.g. READY reported as "behind_peers" while hundreds of blocks behind). Override `// no-silent-ready-ok:<tag>`. |
| **E9: `check-operator-needed-sink`** | HARD | `EV_OPERATOR_NEEDED` ("auto-healing gave up, page a human") is emitted in production AND has a registered subscriber in `lib/event/src/alerts.c` (rule with `.trigger = EV_OPERATOR_NEEDED` via `event_observe(`). Prevents the silent-halt class where the loud signal reaches no sink. No override. |
| **P1-3: `check-systemd-memory-budget`** | HARD | Systemd service hard caps (`MemoryMax` plus finite `MemorySwapMax`) must stay below 70% of the documented 96 GiB operator-host reference; deploy validation may override that capacity explicitly. The verdict is independent of a developer machine's RAM, and explicit `MemoryMax=infinity` fails. Prevents host-level OOM from cap drift without making 16 GiB contributors unable to lint the same source. |
| **E11: `check-doc-accuracy`** | HARD | The canonical gate block below matches the `check-*` prerequisites of the Makefile `lint:` target by count AND name set. On mismatch, fix the doc block — the Makefile is authoritative. No override. It also scans every in-tree `.md` for prose `<N> lint gates` claims and requires each to equal the derived count. **That scan enumerates via `git ls-files` only when the CWD is itself the worktree root git answers for** — merely being "inside a work tree" is not enough, because the lint-gate test sandbox is a private clone at `<root>.lint_sb_<pid>`, a sibling that still sits under an outer repo: `git ls-files` then answers for the OUTER repo (where the sandbox is untracked/ignored) and returns nothing, silently emptying the scan. Any other tree (tarball, export, sandbox) falls back to `find`. A fail-loud floor guards the SCAN SET, not the hit count — the repo legitimately carries zero prose claims today, so `<50` .md files enumerated exits 2 rather than reporting a clean pass off a dead scan. |
| **`check-markdown-links`** | HARD | Every local file/directory target in tracked Markdown resolves inside the repository. Network/mail/app URIs, page anchors, images, code examples, and explicit generated placeholders are outside this filesystem-only contract. The gate fails loud on an empty scan/parser result and carries isolated positive/negative self-tests. No baseline or override. |
| **`check-no-stale-pinned-facts`** | HARD (binary size) / RATCHET (height pin) | "Make staleness impossible": docs (CLAUDE.md + README.md + docs/\*\*/\*.md) must not hand-pin a fact with a live source. (A) A "\<N\> MB" size ADJACENT to "binary" fails HARD — de-pin to size-agnostic prose or quote `tools/scripts/binary_size.sh`; never baseline-exemptible (the stale "~15 MB" survived because it was hand-pinned). (B) A live-state HEIGHT PIN (`H*=`, "wedged at", "held at", "currently …at", "live tip", "stuck/pinned at" next to a height-shaped number) outside the one live-state page `docs/HANDOFF.md` fails RATCHET against the shrink-only `tools/lint/stale_pinned_facts_baseline.txt`. `docs/work/archive/**` (frozen narratives) is exempt. Per-line override `<!-- stale-ok: <reason> -->`. |
| **E12: `check-honest-witness`** | FAIL | Law 7 ("heal in the open, page when stuck"): a Condition's `witness_<name>()` must observe the symptom MOVE, not a constant, the pure inverse of `detect`, or an FSM/poison-flag the remedy itself set. Fails if TRIVIAL (every return a bare `true`/`false`), PURE-INVERSE (`return !detect_x()`), or NO-OBSERVABLE (references none of `active_chain_height`, reducer-frontier H\*, block_map iteration, a durable `SELECT`, a peer/inflight/staged/received progress counter). Exemplar: `app/conditions/src/block_failed_mask_at_tip.c`. Baseline `tools/lint/honest_witness_baseline.txt` (empty). Override `// honest-witness-ok:<reason>` (witness whose remedy returns `COND_REMEDY_FAILED` or re-verifies real structural state). |
| **`check-doc-inline-paths`** | RATCHET (`tools/lint/doc_inline_paths_baseline.txt`, shrink-only) | `check-markdown-links` gates Markdown LINK targets and explicitly excludes inline code — so a doc could say `` `domain/consensus/src/tx_structural.c:121` `` for months with lint green while the directory had moved to `core/`. A precise-looking dead path costs an agent more budget than a vague one, because it reads as verified. This gate resolves every backticked token in tracked `*.md` that contains a `/` and ends in `.c/.h/.cc/.def/.inc/.sh/.md/.txt/.tsv/.py/.json` (optionally `:LINE`), accepting a tracked path, a `/`-anchored suffix of one (so `util/log_macros.h` finds `lib/util/include/util/log_macros.h`), or a path relative to the doc's own directory. A second prong resolves MODULE DIRECTORIES: for any backticked token rooted at a top-level source directory, the first two components (`lib/consensus`, `app/events`) must be a tracked directory. A whole module that moves is invisible to a file-extension scan — `lib/consensus` and `domain/consensus` both survived the `core/` split in six docs with lint green — and a dead directory is the most expensive dead reference there is, because an agent greps it, finds nothing, and concludes the feature was deleted. Two components only: deeper shorthand (`lib/storage/chain_segment`) names a file stem, not a directory. Absolute paths, globs/brace expansions, external-URL link text, `vendor/` (submodule content absent until `make setup`), and `build/`/`.cache/`/`test-tmp/` are out of scope. Baseline keys omit the line number so a doc edit cannot churn them. Per-line override `<!-- doc-path-ok: <reason> -->` for a path that is deliberately absent (a deleted file cited for `git log` recovery, an upstream project's file in an attribution, a `X.c`-style recipe placeholder). Fails loud on an empty scan (`gate_require_scanned`). |
| **`check-error-doc-refs`** | HARD | A remedy the operator cannot follow is worse than none: three wallet-path boot refusals in `config/src/boot.c` said "see WALLET_PERSISTENCE_RECOVERY.md", a file that had never existed — and they fire exactly when private keys are already on disk and the node refuses to write over them. Scans every string literal in a tracked `.c`/`.h` for a token ending in `.md` and resolves it against the repo root, or by basename under `docs/` / `docs/work/`. Comments are ignored (only literals reach an operator); literals carrying a printf conversion or a shell/SQL glob are skipped, since the gate cannot know what they expand to. Complements `check-markdown-links`, which only covers `.md`-to-`.md`. Per-line override `// error-doc-ref-ok:<reason>` for a genuinely runtime-created path. Hermetic `--selftest`. Zero violations, no baseline. |
| **`check-api-reference-generated`** | HARD | `docs/API_REFERENCE.md` is GENERATED output — `tools/gen_api_reference.c` expands the same `ZCL_COMMAND_*` X-macros `config/src/command_catalog.c` uses over the same `config/commands/*.def` catalogs, so the C preprocessor (not a hand-rolled parser) reads the table, and editorial prose is copied through from the template `docs/API_REFERENCE.md.in` at `<!-- ZCL-GEN:… -->` markers. The page previously said of itself that every row was "transcribed directly" — by hand — and drifted accordingly: it still claimed 106 leaves across 41 branches long after the catalog had more than doubled, i.e. it named commands as `ready` that were `planned`. The gate compiles the generator (`-Werror`), regenerates into a temp file, and `diff`s; any difference fails and prints the drift. Fix with `make docs-api-reference`, never by editing the generated page. Fail-loud floors on the `.def` scan set and on the emitted entry count, so an emptied catalog exits 2 instead of reporting clean. Hermetic `--selftest` plants a hand edit and proves the gate trips. No baseline, no override. |
| **`check-describe-budget`** | RATCHET (`tools/lint/describe_budget_baseline.txt`, shrink-only) | Every leaf's `discover describe` document must FIT `ZCL_COMMAND_SPEC_BUDGET`. `discover describe` is the only surface that renders a leaf's long-form `semantics` contract at all — `docs/API_REFERENCE.md` carries summaries and `discover help` a five-field child row — and an over-budget document renders as NOTHING: `zcl_command_registry_describe_json()` returns 0, the leaf keeps dispatching, help and search keep listing it, and its written contract is silently unreadable. `core.wallet.recovery.restore` shipped that way with a money-safety warning inside the invisible text, and the CLI reported it as `UNKNOWN_PATH` (it now reports `DESCRIBE_BUDGET`, the same shape as `nc_emit_menu`'s `MENU_BUDGET`). `tools/check_describe_budget.c` is a SECOND consumer of the same `.def` X-macro grammar and calls the REAL renderer on every leaf, so there is no size model to drift; it reports how many bytes to trim. Fix by TRIMMING `semantics`, never by raising the budget — raising it would also re-hide the baselined pre-existing overflow. Baseline entries carry a written reason and may only shrink; a baselined leaf that now fits also fails, so a fix cannot leave a stale exemption. Hermetic `--selftest` pads a leaf past the budget and proves the gate trips. |
| **`check-no-uncited-victory`** | HARD | A progress claim without an external ledger line is not trustworthy — false "cured / at tip / fully synced" claims have repeatedly re-wedged without one. Splits the one live-state page `docs/HANDOFF.md` into blank-line paragraphs; a paragraph carrying a word-bounded VICTORY PHRASE (`at tip`, `at-tip`, `reaches tip`, `holds tip`, `fully synced`, `cured`, `unwedged`, `wedge cleared`/`closed`/`fixed`, `soak window open`/`running`, `proven live`, `live-proven`, `stable at tip`) FAILS unless the SAME paragraph carries a CITATION TOKEN (`uptime-ledger`, `slo-summary:`, `VERDICT=PASS`, `WALL_CLOCK_SECONDS`, `gap_vs_oracle`, a `ts=<digits>` stamp) or the explicit per-paragraph override `<!-- victory-ok: <reason> -->` (HISTORICAL narration only, never a current-state claim). Hollow-gate rule: `docs/HANDOFF.md` missing or < 10 lines FAILs. Hermetic `--selftest`. No baseline. |
| **`check-doc-claims`** | HARD | Doc freshness, author-owned. Generalizes the two hardcoded rows in `check-doc-no-false-deleted` into an annotation any author can write: one HTML comment binds one prose assertion to one machine-checkable predicate — a path that must still exist or still be absent, a symbol that must still be present or absent under a `git` pathspec, or an existing `check-*` gate that must still pass or still FAIL. The gate names the file, the line, the claim text and the contradicting reality. The `gate-fails` form turns the existing `check-no-*` ratchets into freshness oracles: an item that says work is outstanding goes red the day the gate watching that work turns green — exactly the failure that cost three agents a re-run of commit `9b5add018`. Predicates resolve against the repo root wherever the document lives; annotations inside fenced code blocks are syntax documentation and are skipped. Fail-loud floors (`gate_require_scanned`) on both the tracked-`*.md` scan set and the parsed-claim count, and a self-check with known-good/known-bad fixtures runs BEFORE every tree scan, so "clean" is only printed after the evaluator has demonstrated it still fires. `--selftest`, `--list`. **Covers tracked `*.md` only** — out-of-repo plans (`~/.claude/plans/`) need the explicit `--scan <dir>` invocation, which `make lint` does not and cannot run. Syntax and worked example: the section below this table. No baseline. |
| **E14: `check-condition-cooldown`** | HARD | Closes the multi-hour page-storm bug class: a `COND_CRITICAL` condition whose `detect()` calls a known peer/network-liveness primitive (`connman_max_peer_height`, `connman_get_node_count`, `sync_monitor_connman`, `sync_monitor_max_peer_height`) or the legacy `zclassicd` RPC oracle (`legacy_chain_rpc_*`) must set `.cooldown_secs > 0` (condition.c re-arms the remedy instead of latching permanently at `max_attempts`) or wire a `.progressing` callback (TL-1's alternate anti-latch mechanism, e.g. `reducer_frontier_reconcile_light.c`). Exemplar fix: `app/conditions/src/sync_violation_lag.c`. Self-tested against an isolated tmp dir (`ZCL_CONDITION_COOLDOWN_SELFTEST=1`), proven in `make test`/`make test-parallel` via `t_e14_condition_cooldown_gate()`. No baseline (structural, not a ratchet). |
| **`check-c23-only`** | HARD | Z23 has one compiled-language path: C23. Rejects tracked Rust source/manifests (`*.rs`, `Cargo.toml`, `Cargo.lock`, `build.rs`, `.cargo/`) and any Rust toolchain, archive, linker, build-flag, or FFI route on the executable build/configuration surface. Historical source attribution and inert fixed vectors may remain in prose, but cannot become a fetch/build/link authority. Hermetic matcher selftest; no baseline or override. |
| **`check-toolchain`** | HARD | `$CC` (default `cc`) must accept `-std=c23`, proven by compiling an empty translation unit — capability, not a version parse. Distinguishes "too old" (accepts `-std=c2x` but not `-std=c23`, the gcc 13 case) from "not a C compiler this project recognises" (accepts neither). Failure names what was tried, the compiler's `--version` line, the minimum that works (gcc 14 or newer; Apple Clang 17 is also known to work), and `make CC=gcc-14`. The Makefile also runs this at parse time before vendor bootstrap so a gcc 13 box does not spend minutes compiling archives and then print the same error 51 times. `--selftest` proves a gcc-13-shaped wrapper is refused and a usable compiler is accepted; gcc 13 need not be installed. No baseline or override. |
| **`check-no-python`** | HARD | Z23 has no Python runtime path. Rejects tracked interpreter-source files plus runtime invocations, discovery probes, and matching shebangs on the executable and operator surface. Comments that name the ban, `requires_python: false`, and historical vector attributions (for example python-mnemonic) are not invocations. Operator JSON uses grep/sed or `build/bin/jsonq`; SQLite inspection uses `build/bin/sqlq`. Hermetic matcher selftest; no baseline or override. |
| **`check-no-gnu-va-args`** | HARD | Variadic macros use the C23 `__VA_OPT__(,) __VA_ARGS__`, never the GNU comma-swallowing `, ##__VA_ARGS__`. A GNU-only idiom is invisible while exactly one compiler ever reads the tree, and this one was load-bearing: twelve uses — ten in `lib/util/include/util/log_macros.h` and `lib/net/src/addrman.c`, two inside the sealed consensus tree — produced 7,141 diagnostics under `clang -std=c23 -pedantic`, enough to bury every real finding. The two spellings expand to an identical token stream for the zero-, one-, and n-argument cases; the sealed-tree conversion was proven by compiling both revisions to **identical object files**. Opt out with `// gnu-va-args-ok: <reason>` on the line or the line above (no site uses it today). |
| **`check-clang-portability`** | RATCHET | Second-compiler portability: a whole-tree `clang -std=c23 -Wall -Wextra -Werror -pedantic -fsyntax-only` over the same source set the node binary is built from, ratcheted against `tools/lint/portability_baseline.clang.txt` (counts may only go DOWN). The node ships as one whole-program GCC build, so nothing had ever asked a second compiler whether the tree is even well-formed — and GCC-only spellings landed invisibly, including genuine undefined behaviour in `lib/net/src/p2p_game.c` where a `#undef` sat inside a function call's argument list (GCC tolerates it; clang rejects it and every use fails). Measured 3.0 s wall at 32 workers over 1174 translation units. **SKIP contract:** prints a loud SKIP and exits 0 when clang is absent, exactly like `check-ci-symbol-floor` without objdump — an outside contributor must never be blocked by a gate whose tool they do not have. |
| **`check-no-snapshot-struct-memcmp`** | HARD | No raw `memcmp`/`bcmp` over a `struct platform_positioned_file_snapshot` object. That struct (`lib/platform/include/platform/positioned_file.h`) is 64 bytes wide holding only 56 bytes of fields — two `uint32_t` nanosecond members sit in front of wider `int64_t`/`uint64_t` ones, so the compiler inserts 8 bytes of alignment padding it never has to initialize, and comparing the whole object by raw bytes can report an unchanged file as CHANGED. This landed three times — twenty test groups red the second time (commit `44c45f255`) — and the fix already exists: `platform_positioned_file_snapshot_equal()`. The gate is a text scan, not a type checker: per file, it collects identifiers declared on one line as a plain (non-pointer) `struct platform_positioned_file_snapshot <name>[, <name>...];`, then flags any `memcmp(`/`bcmp(` call in that SAME file naming one of those identifiers as its first or second argument. It deliberately cannot see a helper function doing the comparison elsewhere, a macro-wrapped `memcmp`, or a call whose argument list spans multiple lines — see the script's own header for the full, honest limitation list. |
| **`check-windows-platform-seam`** | RATCHET | Windows portability of the platform seam: cross-compiles every `lib/platform/src` translation unit the node still links off-Linux with `x86_64-w64-mingw32-gcc -std=c2x -fsyntax-only` at the build's own `ZCL_PLATFORM_CPPFLAGS` Windows API floor (read from the Makefile, not copied here -- compiling at mingw's permissive default asks an easier question and produced a real false green), ratcheted against `tools/lint/windows_platform_seam_baseline.txt` (counts may only go DOWN; the baseline is currently EMPTY — the whole seam compiles). Exists because a Windows worker's first symptom of a broken seam was a failed build on somebody else's machine, days later; this asks the question on the Linux box that is already running `make lint`. The exempt set is deliberately **not** a second hand-kept list — `exempt_files()` parses the Makefile's own `ifeq ($(ZCL_HOST_OS),Linux)` branch, so a file the build itself drops off-Linux is exempt here for exactly as long as the build drops it, and re-enters this gate on the same commit that re-enables it. `SRC_FLOOR=8` guards the file glob, because a "clean" verdict over a directory that silently emptied is hollow, not honest. **UNOBSERVED contract:** with no mingw toolchain installed it prints `UNOBSERVED`, in that word, and exits 0 — an outside contributor is never blocked by a tool they do not have — but UNOBSERVED is not a pass and is not cached, so the next box that does have mingw still pays for the check. |
| **`check-windows-acceptance`** | FAIL | Two steps over the platform-seam acceptance catalog (`lib/platform/tests/windows_acceptance.mk`), in this order. **1. Reconcile:** every acceptance program on disk -- in the directories the catalog itself keeps programs in, derived from its `_SOURCES` rows rather than typed into the gate -- must be a source in a `ZCL_WINDOWS_ACCEPTANCE_*_SOURCES` row, *or* the `int test_<name>(void)` entry point of a group registered in `tools/dev/test_group_catalog.def` (the suite then executes it natively, which is strictly better than a cross-link), *or* an entry in the gate's own EXEMPT table **with a written reason**. Anything else is exit 1 naming the file. An empty scan set, an unparseable catalog and an empty group registry are all hard failures: a broken glob must never read as clean. This step exists because two probe programs sat under `lib/platform/tests` read by nothing at all -- no catalog row, no Makefile rule, not in `lib/platform/zcode-package.json` -- while this gate printed a clean PASS, and because they were named `test_*.c` rather than `*_acceptance.c` a name-shaped scan would have walked past them too. **2. Compile:** then the original job -- cross-compiles the catalog for Windows with mingw at the product's own API floor, `$(ZCL_WINDOWS_API_FLOOR)`, shared with `ZCL_PLATFORM_CPPFLAGS` so the two cannot drift: they already had, because `217d3eb6e` raised the product to the Windows 10 baseline and left the catalog compiling against `0x0600`, grading a Windows the product does not ship. Compile, not execute: these are Windows binaries and this is a POSIX host, so the honest deliverable is a cross-link and it is labelled as one; `make windows-acceptance` additionally runs them under Wine and REFUSES rather than skipping when Wine is absent. **UNOBSERVED contract:** with no mingw toolchain the compile step prints `UNOBSERVED`, in that word, and exits 0 -- an outside contributor is never blocked by a cross-compiler they do not have -- but UNOBSERVED is not a pass and is not cached. The reconcile step needs no compiler and has already run by then. `--self-test` runs first on every invocation and plants an undeclared program in a throwaway fixture to prove the reconcile can go red. | `tools/lint/check_windows_acceptance.sh` |
| **`check-windows-cross-syntax`** | RATCHET | Syntax-only mingw sweep of every `.c` under `lib/` `app/` `config/` `core/` `domain/` `ports/` whose text contains `_WIN32`. The acceptance catalog cross-links 98 of those files; gcc/clang on a POSIX host never take the `_WIN32` branch of the rest, so a Windows-only syntax error sat uncompiled on this box. `x86_64-w64-mingw32-gcc -std=c2x -fsyntax-only`, every directory named `include` (plus `-I.` and `-Itools`), parallel `xargs`. File set is self-maintaining. Missing `command/native_command.h` / `command/native_dev_hotswap.h` is skipped by header name; missing openssl headers are skipped the same way only while vendor openssl headers are unbuilt. Remaining survivors live in a shrink-only baseline next to the gate script. **SKIP contract:** with no mingw toolchain it prints `SKIP` and exits 0 — not a pass, not cached. `--self-test` plants a Windows-only undeclared identifier. |
| **`check-app-bundle-reproducible`** | HARD | The macOS `.app` bundler is reproducible **and** its product actually launches. `tools/scripts/make_app_bundle.sh` wraps a built tool in the minimal launchable bundle and ad-hoc signs it, because arm64 macOS refuses to execute an unsigned binary at all — so "no signature" is not available and "whatever `codesign` did this time" is not reproducible. Two failures rot silently here and neither is visible by reading the script: `codesign` stamps a trusted timestamp unless it is disabled, and any input-dependent field drifting between runs makes two bundles of identical input differ; and a bundle whose signature does not verify is **SIGKILLed by the kernel**, so a smoke test that only checks an exit status cannot distinguish "ran and declined" from "never ran at all". The gate builds the subject tool twice byte-identically first (otherwise the comparison below would be over different inputs, and it says so rather than passing), then asserts the exact printed output *and* the exit status of the bundled executable. |
| **`check-result-discard`** | RATCHET | Shrink-only ratchet over `(void)` casts that discard a `struct zcl_result`, baseline `tools/lint/result_discard_baseline.txt`. Exists because C23 lets an explicit cast suppress `[[nodiscard]]`: annotating the type (done — see `lib/util/include/util/result.h`) fences off NEW silent discards but cannot excavate the existing population, measured at 94 cast discards versus ~67 bare ones. Fix a site with `ZCL_IGNORE_RESULT(expr, "why the failure is safe to drop")`, which requires a non-empty reason at compile time via `static_assert` — the point being to make the discard *expressible* rather than merely tolerated. |
| **`check-no-warning-suppression`** | HARD | A blanket warning suppression may not sit on a build surface unexplained. `-Wno-unused-result` and `-Wno-stringop-overflow` — in flag form, or as `#pragma GCC diagnostic ignored` — fail on any tracked makefile, `*.c`/`*.h`, or `*.sh` unless the line, or the line above it, carries `suppression-ok: <reason>` with a non-empty reason. `-Wno-unused-result` matters most: it is the SAME diagnostic GCC and Clang use to report `[[nodiscard]]`, so leaving it on silently voids the result-type discipline the repository is built around — a result type could be annotated and nothing would change. Both flags entered in the first commit as copy-forward defaults and had spread to seven compile rules; each now has one named definition (`ZCL_WARN_UNUSED_RESULT`, `ZCL_WARN_STRINGOP_OVERFLOW`) carrying the reason and the command to re-derive its blocking sites. `vendor/` (third-party recipes) and `.clangd` (editor diagnostics, never emitted code) are out of scope. Hermetic detector fixtures run BEFORE the tree scan on every invocation, so the gate cannot report clean while its matcher is broken, and an empty scan set exits 2. `--self-test`. No baseline. |
| **`check-fuzz-artifact-ledger`** | HARD | Every saved fuzz finding under `lib/test/fuzz_seeds/` carries a written verdict, and the cheap half of that contract runs in `make lint` (21 ms, text + git only). Exists because on 2026-07-14 a fuzzer found that a five-byte script from any peer hangs the node forever, the bytes were committed as `script/timeout-689f73ac…bin`, and nobody read them for two weeks — while THREE mechanisms had already replayed them and already gone red (`make fuzz-ci`, reachable only from `make ci` which nothing automatic runs; the hourly `background_quality_lane.sh`, whose verdict lands in a JSON file nothing gates on; and `promote_fuzz_artifacts.sh`, which exits 0 by design). The replay capability was never missing — the verdict had nowhere to go. This gate checks: every file matching a libFuzzer artifact prefix (`timeout-`/`crash-`/`leak-`/`oom-`/`slow-unit-`) has exactly one line in `lib/test/fuzz_seeds/ARTIFACT_VERDICTS.txt` with a valid verdict, an ISO date and a reason; no orphan ledger lines; no untracked repro sitting uncommitted in the corpus; and the corpus↔binary map is 1:1, DERIVED from the Makefile's `$(BIN_DIR)/fuzz_<kind>:` rules so a new target is covered the day it lands. The actual replay is `make fuzz-replay` (in `make ci`, plus its own CI job) — separated because the replay is 18.3 s at `-P6` while building the nine fuzz binaries it needs is 34 s cold at `-j6`. Verdicts are `regression-seed` (audited clean; reproducing again FAILS), `open` (a real unfixed bug — this does NOT suppress the failure, it only names it), and `accepted` (the only pass-while-reproducing path: per-file, dated, reason ≥ 30 chars, reprinted by name every run; **zero entries today**). An entry that stops being true fails in both directions, so the ledger cannot rot. Added 2026-08-26: a `crash-`/`leak-` artifact cannot close `regression-seed` on "it replayed clean" alone — the reason must name a fix (`fixed by <commit>`) or record a pattern-init replay (`pattern-init: clean (Nx)`), enforced via `tools/scripts/fuzz_verdict_lib.sh`; see the pattern-init section below. `promote_fuzz_artifacts.sh` no longer files a verdict from the filename either — it replays the artifact (stock, and pattern-init for `crash-`/`leak-` kinds) before writing anything, and files `unreplayable` (also rejected on sight, same as `unaudited`) rather than a false clean when it cannot get that evidence. Never cached (it reads untracked worktree state). `--selftest` plants an untriaged artifact and asserts the gate trips AND names the file. No baseline, no directory-wide exemption. |
| **`check-standalone-tools-link`** | HARD | Every standalone tool rule in the Makefile must actually BUILD. `make lint`, `make test-parallel` and `make ci` between them build the node, the test runners, the fuzzers and two lint helpers — and nothing else, so every other `$(BIN_DIR)/<tool>` rule was reachable from no gate and rotted unobserved. When `lib/base` absorbed logging and allocation behind forwarding headers, SIX standalone rules broke at once (missing `-I` paths, missing `lib/base/src/log_level.c`, missing `lib/platform/src/clock.c`) and every gate stayed green through it. The tool list is DERIVED from the Makefile — both the literal `$(BIN_DIR)/<name>:` spelling and the `$(SOME_BIN):` spelling resolved through its `SOME_BIN = $(BIN_DIR)/<name>` definition — never hand-written, so a newly added tool is covered the day it lands and an unknown tool is NOT exempt (fail-closed). Per-epoch CANDIDATE staging paths are skipped. The exempt set is closed and carries a mandatory reason per entry: already built by lint/ci (`gen_templates`, `core_seal`, `check_observability_pairing`, the nine `fuzz_*`, `crash_recovery_test`, `zcl-rpc`), whole-program relinks (`z23` + dev/asan/tsan variants, the test runners, `session`, `bot`), or outside the base toolchain (`zcl-blog` needs webkit2gtk). Covered tools are single-translation-unit builds: ~9 s warm, and a no-op once built. No baseline. |
| **`check-no-operator-paths`** | HARD (shrink-only ratchet) | No tracked file may name an absolute home path, the operator username, or the host name. A stranger who clones this repository must not learn where the machines that run it are: onion addresses are the committed network identity precisely because they carry no location, and an absolute `/home/<user>/...` path in a committed artifact silently undoes that. Three prongs: **A** absolute `/home/<x>` or `/Users/<x>` (universal, works on any checkout), **B** the operator username from `id -un`, **C** the host name — B and C are host-derived, so the PASS line says so rather than implying coverage they cannot have on someone else's machine. Keyed `<prong> <path> <occurrences>`, not lines: the corpus evidence records are single-line JSON, so a per-line ratchet would score a file holding sixty leaks as one. A new pair fails hard; a count above baseline fails; a count that has fallen to zero fails as a stale row so the baseline can only shrink. The gate runs a planted-violation selftest per prong first — a lint gate here has silently inverted before, and one that has never been seen to fail is not evidence. It is deliberately not exempt from itself. |
| **`check-no-unattended-publish`** | HARD (closed allowlist) | No script in the repository writes to the shared remote. Publishing is a deliberate act a person performs, never a side effect of a background loop: a timer that can move `main` moves it for every checkout that fast-forwards from it, with nobody reviewing what went out. **What motivated it:** a sync script ran on cron every ten minutes on four machines and pushed a per-box heartbeat commit to `origin/main` each cycle, carrying that box's onion address, P2P port, running-binary source hash, peer count, liveness and last error — filling public history with machine chatter, shipping live operator state to every reader, and making a project anyone can join look like it had a designated in-crowd. Two patterns are refused: `git push`, and `git commit-tree` — the subtle one, because it builds a commit object without touching the index or working tree, so `git commit-tree … \| git push origin <sha>:main` moves a branch from a detached HEAD while the checkout still looks untouched, and a reviewer scanning for `git commit` would never see it. A line whose first non-blank character is `#` cannot execute and is not matched, so an explanation of the rule is not itself a violation. The scan set is derived from `git ls-files`, never hand-listed, so a script added tomorrow is covered the day it lands, and an unknown file is refused rather than assumed benign. The allowlist is closed and every entry carries a mandatory reason: the operator-run deploy path, two hooks that only print advice naming the command, two lint fixtures whose input is the forbidden string, and this gate itself — listed rather than skipped, because a gate exempt from itself is a place to hide. Scan-floor guarded, so a scan set that silently emptied exits 2 instead of reporting a clean pass. No baseline. |


E10 = the WARN→RATCHET graduation of #18 and #20 (above).

### Closing a `crash-`/`leak-` fuzz finding: one clean replay is not exoneration

A `LOG_*` macro in this codebase expands to `return` (see §4 above). A hard
failure return that runs before a caller's output struct is initialized hands
that caller a `free()`/`_free()` call over whatever the stack held on entry.
On a freshly-mapped stack that is zero, so the call is a no-op; on a
long-lived process it is a stale pointer and a stale count. The bug is real
either way — the replay result is not.

`-ftrivial-auto-var-init=pattern` is the tool that turns this from
probabilistic into deterministic: it poisons every uninitialized stack slot
with a recognizable non-zero pattern instead of leaving it zero, so a stale
read fails the same way on the first replay that it would on the thousandth
in a live process.

Rule: a `crash-`/`leak-` fuzz artifact closes `regression-seed` only with a
named fix (`fixed by <commit>`) or an explicit pattern-init replay recorded
in the reason (`pattern-init: clean (Nx)`). "It replayed clean" by itself
names nothing and proves nothing about this bug class. `tools/lint/check_
fuzz_artifact_replay.sh` enforces this (`tools/scripts/fuzz_verdict_lib.sh`
holds the shared rule); `tools/scripts/promote_fuzz_artifacts.sh` runs both
replays before it ever writes a verdict, and files `unreplayable` — never a
clean verdict — when it cannot get the evidence this bug class requires.
`timeout-`/`oom-`/`slow-unit-` findings are algorithmic, not stack-state, and
are not held to this rule.

### Binding a document claim to a predicate (`check-doc-claims`)

A document that asserts something the code contradicts costs more than no
document, because a reader acts on it. The measured price in one session: a
plan listed a deletion as PENDING that had landed on main three days earlier
(commit `9b5add018`), and three agents were dispatched to redo finished work.

`check-doc-no-false-deleted` already proved the shape — fire only when a doc
says "gone" while the code is still present *and* wired — but its table of
claims is hardcoded in the gate, so only a gate author can extend it.
`check-doc-claims` inverts that: the author of a claim writes the predicate,
inline, next to the claim, in an HTML comment that renders invisibly.

```markdown
- `data_integrity_compute` shadow-seed: confirm non-consensus or repoint. The
  `utxo_projection` half of this question is CLOSED, not open — Program H1
  deleted the event-log-fed projection and its view.
  <!-- claim: file-absent lib/storage/src/utxo_projection.c # deleted by Program H1 -->
  <!-- claim: gate-passes check-no-utxo-projection # the copy must stay dead -->
```

Six predicates, each resolved against the repository root no matter where the
document lives:

| Predicate | Arguments | Holds while |
|---|---|---|
| `file-present` | `<path>` | the path still exists |
| `file-absent` | `<path>` | the path still does not exist |
| `symbol-present` | `<symbol> <git-pathspec>` | `git grep -lwF` still matches a tracked file |
| `symbol-absent` | `<symbol> <git-pathspec>` | it still matches nothing |
| `gate-passes` | `<check-*-gate>` | that gate still exits 0 |
| `gate-fails` | `<check-*-gate>` | that gate still exits non-zero |

Text after `#` is a free-text note. Annotations inside fenced code blocks are
syntax documentation, never live claims, and are skipped — which is why the
example above is fenced.

`gate-fails` is the highest-value form and the one that would have caught the
failure above. Write it under an item that claims work is outstanding, naming
the ratchet gate that watches that work: while the work is genuinely
outstanding the oracle is red and the item is fresh; the day the work lands the
oracle turns green and `check-doc-claims` turns RED, naming the plan file and
the stale line. Every `check-no-*` ratchet already in `LINT_GATES` is usable as
an oracle, so items they watch get freshness checking for free. Gates are
resolved through the same `gate_command()` table `tools/lint/run_lint.sh` uses,
run at most once per invocation, and a gate may not name itself.

**Out-of-repo documents are NOT covered by `make lint`.** The motivating
failure happened in `~/.claude/plans/*.md`, which sits outside the git
repository: invisible to `git grep` and unreachable by any repo gate. The
in-repo half (tracked `*.md`) is automatic; the out-of-repo half is a
deliberate, author-run command that scans an external tree while still
resolving every predicate against this repository:

```sh
make check-plan-claims            # same thing; PLANS=<dir> to point elsewhere
```

Run it before dispatching work *from* a plan, not in CI — CI has no business
reading a directory outside the checkout. Read its output carefully: with no
annotated plans it reports `0 bound claim(s)` and says **ZERO COVERAGE, not a
clean bill of health**, because the external mode deliberately drops the
non-empty-claim floor (a plan directory legitimately starts with none). A plan
only becomes checkable once its author binds an open item to a predicate.

**Canonical lint-gate list (E11 source of truth).** This block is machine-checked
against the Makefile `lint:` target. Keep it sorted; edit it whenever you
add/remove a gate.

<!-- LINT-GATES-BEGIN -->
- `check-lint-gate-wiring`
- `check-accel-oracle-pinned`
- `check-blob-read-bounds`
- `check-byte-order-codec-single`
- `check-zcode-package-registry`
- `check-zcode-package-standalone`
- `check-package-anatomy`
- `check-api-reference-generated`
- `check-before-save-hooks`
- `check-build-epoch-integrity`
- `check-checkout-lock`
- `check-coins-lookup-nullcheck`
- `check-condition-cooldown`
- `check-consensus-parity`
- `check-core-include-boundary`
- `check-core-seal`
- `check-core-seal-root-mirror`
- `check-doc-accuracy`
- `check-doc-claims`
- `check-doc-counts`
- `check-doc-inline-paths`
- `check-describe-budget`
- `check-domain-purity`
- `check-error-doc-refs`
- `check-file-purpose`
- `check-file-size-ceiling`
- `check-framework-filename-suffix`
- `check-framework-shape`
- `check-git-hooks-installed`
- `check-group-purpose`
- `check-honest-witness`
- `check-lag-slo-observable`
- `check-lib-layering`
- `check-lib-module-order`
- `check-log-macro-return-type`
- `check-long-functions`
- `check-markdown-links`
- `check-malloc`
- `check-model-ar-lifecycle`
- `check-model-validation`
- `check-no-raw-clock-outside-platform`
- `check-sysinit-ordering`
- `check-sandbox-wired`
- `check-no-raw-sqlite-in-controllers`
- `check-no-shellouts`
- `check-no-writer-below-sealed-frontier`
- `check-peer-floor-single-source`
- `check-proc-self-shim`
- `check-no-adx-overclaim`
- `check-simd-os-support`
- `check-no-authoritative-ram-state`
- `check-no-dev-history-in-contracts`
- `check-no-live-lab-history`
- `check-no-new-borrowed-seed`
- `check-no-new-coin-backfill-caller`
- `check-no-new-repair-rung`
- `check-no-retired-agent-protocol`
- `check-no-runtime-abort`
- `check-no-stale-pinned-facts`
- `check-no-uncited-victory`
- `check-route-command-parity`
- `check-no-orphan-placement`
- `check-no-silent-ready`
- `check-no-stray-untracked-source`
- `check-no-stray-root-files`
- `check-observability-pairing`
- `check-hex-codec-single`
- `check-one-result-type`
- `check-one-write-path`
- `check-frontier-single-writer`
- `check-dumper-never-blocks`
- `check-no-block-index-flat`
- `check-no-utxo-projection`
- `check-no-utxos-mirror-read`
- `check-operator-needed-sink`
- `check-projections-pure`
- `check-pthread-create`
- `check-json-value-init`
- `check-raw-malloc`
- `check-raw-sqlite`
- `check-rpc-registrar`
- `check-scanner-immunity`
- `check-service-result-convergence`
- `check-silent-errors-bool`
- `check-wallet-raw-prepare-log`
- `check-silent-errors-conditions`
- `check-silent-errors-controllers`
- `check-silent-errors-jobs`
- `check-shape-include-direction`
- `check-shape-includes-header`
- `check-silent-errors-services`
- `check-stage-advances-or-blocks`
- `check-supervisor-domain`
- `check-supervisor-registration`
- `check-systemd-memory-budget`
- `check-test-registration`
- `check-thread-supervision`
- `check-toolchain`
- `check-typed-blocker`
- `check-blocker-escape-registered`
- `check-blocker-handoff-declared`
- `check-supervisor-progress-declared`
- `check-stopwatch-skip-detector`
- `check-proof-server-pin`
- `check-promotion-receipt-chain`
- `check-verification-coverage`
- `check-ship-remote-transaction`
- `check-identity-parser-single`
- `check-source-identity-authority`
- `check-status-reason-single`
- `check-pipefail-status-pipe`
- `check-discarded-status`
- `check-no-wallclock-assertion`
- `check-blocker-remedy`
- `check-vendor-provenance`
- `check-doc-no-false-deleted`
- `check-stage-log-reorg-unsafe`
- `check-stable-publish-contained`
- `check-zclassicd-reach-allowlist`
- `check-z23-release-install`
- `check-published-platforms`
- `check-no-csr-lock-on-finalize-drive`
- `check-mint-skip-crypto-offline-only`
- `check-wire-harness-security-gate`
- `check-hotswap-dev-only`
- `check-hotswap-eligible-scope`
- `check-hotswap-denied-leaves`
- `check-hotswap-static-state`
- `check-hotswap-service-islands`
- `check-hotswap-swappable-shape`
- `check-hotswap-candidates-ledger`
- `check-hotswap-package-receipt-is-not-authority`
- `check-hotswap-module-imports`
- `check-release-no-dev-symbols`
- `check-vcs-no-git`
- `check-vcs-no-sha1`
- `check-command-contract`
- `check-command-availability-truthful`
- `check-command-input-keys`
- `check-read-leaf-no-boot-ceremony`
- `check-telemetry-ontology`
- `check-privileged-transition-receipt`
- `check-no-gnu-va-args`
- `check-no-snapshot-struct-memcmp`
- `check-clang-portability`
- `check-windows-platform-seam`
- `check-windows-acceptance`
- `check-windows-cross-syntax`
- `check-app-bundle-reproducible`
- `check-result-discard`
- `check-c23-only`
- `check-no-python`
- `check-no-trust-state-ordering`
- `check-no-warning-suppression`
- `check-fuzz-artifact-ledger`
- `check-live-datadir-isolation`
- `check-installed-acceptance-tools`
- `check-standalone-tools-link`
- `check-app-bundle-reproducible`
- `check-no-operator-paths`
- `check-no-unattended-publish`
- `check-tor-dial-prewarm`
- `check-fleet-source-status`
- `check-zcc-cache`
- `check-tu-random-seed`
- `check-outparam-init-before-return`
- `check-equihash-params`
<!-- LINT-GATES-END -->

(`check-consensus-parity` [E13, the parity mechanism — see
`docs/CONSENSUS_PARITY_DOCTRINE.md`], `check-no-new-repair-rung`, and
`check-stage-advances-or-blocks` appear in the canonical block and run in `make
lint`; they are documented in their own docs rather than expanded here.)

`check-lint-gate-wiring` (`tools/lint/check_lint_gate_wiring.sh`) keeps the two
halves of a lint gate in step. **Adding a gate is a two-file operation**: the
Makefile gets a `check-*:` target plus a line in `LINT_GATES`, and
`tools/lint/run_lint.sh` gets an entry in `gate_command()`'s case table —
because the parallel driver execs each gate's script directly and never reads
the Make recipe. Nothing enforced the second file, so gates shipped with only
the first half and `make lint` went FATAL (exit 2) for the whole tree,
reporting no gate results at all, until somebody wired them by hand. This gate
asserts the parity in both directions (a listed gate with no table entry, and a
table entry no list names), plus a real Make target behind every listed name
(the `ZCL_LINT_SERIAL=1` fallback runs the list as prerequisites) and an
existing script behind every table entry. It reads the lists with the same awk
extractor `check-doc-accuracy` uses and reads the case table through
`run_lint.sh --list`, which greps its own case labels — never a second parser
of either file. Its `--selftest` plants each defect class in a throwaway
fixture tree and asserts the gate rejects it *and names the offender*, with a
correctly-wired fixture as the positive control.

`check-no-retired-agent-protocol` rejects the retired agent-transport token in
tracked paths and filenames while explicitly allowing ordinary `memcpy` usage.

`check-no-stray-root-files` (`tools/lint/check_no_stray_root_files.sh`) keeps
the repository root a curated list. It compares the root's depth-1 entries
against git's tracked top-level set (derived, so a folder move needs no edit)
plus a short allowlist of generated or developer-local entries — `build/`,
`vendor/`, `test-tmp/`, `compile_commands.json`, tool caches. Anything else is
named as a stray. The gate exists because gitignoring debris hides it from
`git status` while `ls` still shows it: a stray database, a `nohup` capture,
and a second scratch directory all sat in the root indefinitely. The fix is
always at the writer — a test writes its scratch under
`./test-tmp/<prefix>_<pid>_<tag>` (`test_make_tmpdir`), a script writes its log
under a state/log directory — never by growing the allowlist.

`check-no-dev-history-in-contracts` (`tools/scripts/
check_no_dev_history_in_contracts.sh`) rejects a narrow, high-signal set of
dev-history phrases ("STEP-0 STATUS", "stub bodies"/"stub body", `lane
[0-9][A-Z]?` e.g. "lane 2A", "future slice") from production contract
surfaces: every `*.h` under any `**/include/**` directory, and every `*.def`
table. Once the real body lands, that phrasing is INCORRECT MODEL CONTEXT —
an agent or operator reading the header trusts it over the `.c` file and
wrongly concludes the feature is still a stub. `docs/`, `vendor/`, and any
path with a `test`/`tests` component or a `*_test.*` filename are allowed to
narrate dev history on purpose and are excluded from the scan.

`check-no-live-lab-history` (`tools/scripts/check_no_live_lab_history.sh`)
keeps funded experiment evidence out of Git. It requires the tracked micro-lab
ledger to remain its one-line empty campaign template, rejects tracked
`live_confirmed` receipts and micro-lab event rows, rejects recipient-wallet
manifests, and rejects duplicate tracked notebook paths. Reproducible simnet
evidence and public consensus fixtures remain allowed in the canonical broad
lab baseline. Both recorders independently refuse any ledger path inside the
repository, even when a developer supplies an environment override.

### `check-outparam-init-before-return` — what a later reader will free must never be a stale value

Two remote-reachable memory-safety bugs were found on the same day, 2026-08-26,
and they are one class: **the thing a later reader will free or dereference was
left in a state that reader's guard cannot see.**

`compact_block_reconstruct()` took `struct block *out_block` and refused an
empty announcement *above* `block_init(out_block)`. Its caller
`process_cmpctblock()` ran `block_free(&out_block)` on that outcome, so
`transaction_free()` walked whatever pointer and count the caller's own stack
happened to hold. Any connected peer could reach it with a valid header plus
two zero bytes (`bce343876`).

`sapling_init_params()` published the three Groth16 verifying keys into the
module globals the verifiers read, and a later Sprout failure path freed their
`ic[]` arrays and comb tables *without* storing `NULL` back into those globals.
Every verifier's fail-closed guard asks only "is the pointer NULL?", so the
guard passed and `groth16_verify()` read freed heap, reachable from
`accept_to_mempool` (`69518f2f3`).

Two things make this class hard to see, and the gate is shaped around both.
First, `LOG_FAIL` and the other `LOG_*` macros in this tree **expand to a
return**, so a line that reads like logging is a control-flow exit and a human
scanning for `return` above the init sees nothing. Second, a freshly mapped
stack reads back as zero, so a one-shot replay frees nothing and exits clean;
140 stock replays and a 1,265,835-execution fuzz session all missed the
compact-block bug. Rebuilding with `-ftrivial-auto-var-init=pattern` makes it
deterministic, and that is the way to reproduce anything in this family:
pre-fix it reproduces the lane's exact stack (`transaction_free <- block_free
<- process_cmpctblock <- msg_process_messages`), post-fix it is clean.

The rules, both required:

- **Initialize before anything can fail.** A function that hands back a struct
  the caller frees must `*_init()`/`memset()` it above the first thing that can
  fail, and the header must state that post-condition as a rule rather than a
  description.
- **Publish last, unpublish first.** A pointer stored into a module global is
  published only below every fallible step, and any teardown clears the global
  *before* freeing what it points at.

`tools/lint/check_outparam_init_before_return.sh` holds both closed. It runs
two legs over every tracked `.c` file:

1. **Out-parameter leg.** For each function it extracts the `struct T *name`
   parameters, finds the first `*_init(name)`/`memset(name, …)` in the body,
   and reports the pair when a `return` or a `LOG_*(` precedes it. It reports
   only when a `T_free` exists somewhere in the tree — the struct must be the
   kind a caller frees — and only when the pre-init exit is reachable with
   well-formed arguments. It walks *every* exit above the init, not just the
   first, because the first is very often `if (!a || !b) return false;`, which
   a caller that then frees the out-param cannot reach. Surviving cases are
   listed in `tools/lint/outparam_init_baseline.txt`, each with the caller-side
   mechanism that makes it safe; the allowlist is **closed**, so a new instance
   fails rather than joining a list, and a *stale* entry fails too, so fixing
   the code means deleting the waiver.
2. **Published-global leg.** It derives the set of publisher functions from the
   code — a function that stores a caller-supplied pointer into a file-scope
   variable — never from the name, so a `*_set_*` that merely writes *through*
   the pointer is not a publisher and a publisher spelled otherwise still is
   one. It then reports a publish of `&obj` followed, in the same function, by
   a free touching `obj` with no unpublish between. This leg is
   **zero-tolerance and has no allowlist**: production code has none today.

What it cannot check, stated so nobody over-trusts it: it is a line-order
scanner over C text, not a compiler. It does not follow control flow, so
`if (x) { init(out); } … return` reads as initialized. It does not resolve
macros, so a wrapper that expands to `return` and is not named `LOG_*` is
invisible. It does not prove the *caller* frees — that leg is the reviewer's,
recorded per baseline entry. It only recognizes `T_init(out)`/`memset(out, …)`
as initialization, so a field-by-field init over-reports and an init done by a
helper it cannot see is a miss. Multi-declarator declarations and
`struct T **out` owner-outs are out of scope. On the published-global leg it
sees only the first `free(` on a line, and it is scoped to production sources:
test harnesses legitimately hand a stage module a `&main_state` and free it at
case teardown, which is the same text about 870 times over and would bury the
one shape that actually shipped a use-after-free.

`--selftest` plants a clean function and a violating one for each leg and
asserts the verdict on each, including that a `set_*` which only writes through
its pointer is *not* read as a publisher. Both legs refuse to report clean off a
scan that found nothing (`gate_require_scanned` floors on the file set, the
derived `*_free` set, the publisher set, and the number of function bodies
actually walked).

### `check-tu-random-seed` and `make repro-build` — the build repeats

A node states which source it is running in its version handshake. That
statement is only worth anything if a second person holding the same source can
rebuild the same bytes and compare. Two things keep that true.

`check-tu-random-seed` (`tools/lint/check_tu_random_seed.sh`) is the cheap
guard, and it runs in `make lint`. GCC derives its default random seed from the
name of the object file it is writing. Every object in this tree is compiled
into a fresh temporary staging directory and published atomically, so that name
— and therefore the seed — differed on every single compile. Under `-flto` the
seed becomes the `.gnu.lto_*.<suffix>` section-name suffix, and the shipped
profile's objects stopped repeating even twice in the same directory. Measured
on GCC 14.2 over a representative sample of node translation units at the
shipped release flags: with the default seed every sampled object differed
between two compiles of unchanged source, and the object *size* moved too,
because GCC trims leading zeros from that suffix. With `$(ZCL_TU_RANDOM_SEED)`
pinning the seed to the relative source path, none did. The gate requires every
per-TU object recipe to carry that flag and requires the seed to be per-TU; the
coverage recipe is the one exemption, because gcov pairs a `.gcno` note with
the object that will emit the `.gcda`, and the gate asserts that exemption is
the only one.

`make repro-build` (`tools/scripts/repro_build.sh`) is the end-to-end proof.
It is opt-in — three whole-program LTO builds — and it reports four properties
separately rather than collapsing them into one verdict:

| | property | status |
|---|---|---|
| P1 | `build/bin/z23` identical across two builders at different absolute paths | asserted |
| P2 | `build/bin/z23.debug` identical across the same two builders | asserted |
| P3 | every per-TU object identical when one directory builds twice | asserted |
| N1 | per-TU objects identical across two directories | **not** asserted |

N1 is printed on success as well as on failure, with the measured count of
objects that differ. GCC streams absolute source and header paths into the
`.gnu.lto_*` IR and `-ffile-prefix-map` does not reach inside it; there is no
GCC 14 flag that fixes it. It does not touch P1 or P2, because that IR is
consumed at link time and never reaches the shipped output — which is why P1
measures the shipped artifact directly instead of inferring it from the
intermediates. A gate that quietly narrowed its scope to whatever happened to
pass would not be evidence, so this one names what it cannot prove.

`make repro-verify` remains the two-builder gate for the shipped binary alone;
`make ci-reproducible` builds twice in one source directory under the release
flag profile shared with `tools/release.sh`.

---

## 8. Lint-override discipline — every escape hatch is named

Several lint gates accept an inline override marker when the rule cannot
mechanically hold:

| Marker | Where allowed | Lint gate |
|--------|---------------|-----------|
| `// obs-ok:<tag>` | line with `fprintf(stderr, …)` whose nearby code emits no event / does not terminally propagate | `check-observability-pairing` |
| `// raw-sql-ok:<tag>` | line with `sqlite3_step(…)` outside the `AR_STEP_*` wrappers | `check-raw-sqlite` |
| `// raw-return-ok:<tag>` | bare `return -1;` in service/controller code with no preceding log line | `check-silent-errors-services`, `-controllers` |
| `// raw-alloc-ok:<tag>` | line with `malloc/calloc/realloc` outside the `zcl_*` wrappers | `check-raw-malloc` |
| `// long-function-ok:<tag>` | signature line of a function whose body spans >500 lines (controllers/services/config-src ENFORCED, lib/ WARN) | `check-long-functions` |
| `// lib-layer-ok:<tag>` | line in `lib/` that includes a `controllers/`, `models/`, `services/`, `views/`, or `config/` header | `check-lib-layering` |
| `// shape-layer-ok:<tag>` | line in `app/models/` that includes a `services/`/`controllers/` header, or in `app/services/` that includes a `controllers/` header | `check-shape-include-direction` |
| `// domain-purity-ok:<tag>` | line in `domain/` that includes an app/ shape or an unlisted lib/ subsystem header | `check-domain-purity` |
| `// supervisor-ok:<tag>` | any line in a long-running `app/services/src/*_service.c` that intentionally does not register a supervisor liveness contract | `check-supervisor-registration` |
| `// supervised:<child>` | a `thread_registry_spawn(` call site whose thread IS on the supervisor tree; names the watching contract | `check-thread-supervision` |
| `// thread-supervision-ok:<reason>` | a `thread_registry_spawn(` call site for a bounded/joined/one-shot thread that needs no liveness contract | `check-thread-supervision` |
| `// one-result-type-ok:<tag>` | top of an `app/services/src/*.c` that owns no fallible service surface (pure table/registry helper) | `check-one-result-type` |
| `// one-write-path-ok:<tag>` | chain-state compatibility wrapper that is not a second consensus writer | `check-one-write-path` |
| `// shape-include-ok:<tag>` | any line in a shape file (condition/model/supervisor) that is a genuine registry/aggregator and cannot include the shape header | `check-shape-includes-header` |
| `// projection-cache-ok:<tag>` | line in a `*_projection.c` with a legitimate cache write outside the strict fold | `check-projections-pure` |
| `// ram-state-ok:<tag>` | line with derived active-chain cache state that must stay non-authoritative | `check-no-authoritative-ram-state` |
| `// abort-ok:<reason>` | line with an `assert(`/`abort(` in network-reachable code where continuing would be worse than crashing (a leaked plaintext, a forged key, a silently mis-verified signature) | `check-no-runtime-abort` |

**Syntax (machine-enforced).** Every `<tag>` marker requires a non-empty
single-token tag matching `[A-Za-z][A-Za-z0-9_-]+` immediately after the colon.
The space-after-colon form (`// raw-sql-ok: state-kv …`) and the bare form
(`// raw-alloc-ok`) are rejected — hyphen-join multi-word tags instead.

The two `<reason>` markers — `// thread-supervision-ok:<reason>` and
`// abort-ok:<reason>` — take free prose instead, because a one-word tag cannot
carry the argument they exist to make (why this thread needs no liveness
contract; why crashing here beats continuing). They still refuse an empty
reason; `check-no-runtime-abort` requires at least six characters.

**Pairing rule.** A marker is a promise that the override is either:

1. **Logged at this site or nearby** — the diagnostic is already observable
   (LOG_FAIL above, fprintf on the previous line, the caller logs on receiving
   the propagated failure).
2. **Structurally safe by design** — qsort comparator, void-returning helper,
   pre-boot sentinel, build-time tool, test fixture.

If neither holds, the marker is a bug. Delete it, fix the underlying issue
(route through `AR_BEGIN_SAVE`, add `LOG_FAIL`, switch to `zcl_malloc`), and let
the lint go green naturally.

**Prefer reusable tags that name a structural property over one-off labels.**
`:debug` and `:operator` say nothing; `:helper-context-logged` and
`:bin-parser-bounds` describe a recognizable class of safe call sites. Reuse an
existing tag when the pattern matches; singleton tags survive only when they
name a genuinely unique structural property
(e.g. `fatal-true-triggers-rollback-and-partial-write-return`).

**Concrete tag taxonomy (current usage):**

- `obs-ok:` — `pre-existing-diagnostic`, `helper-context-logged`,
  `helper-return-path`, `paired-with-return-false-below`,
  `paired-with-event_emitf-below`, `warning-only-on-best-effort-path`,
  `crash-dump-banner`.
- `raw-sql-ok:` — `progress-kv-kernel-store` (reducer kernel-store cursor +
  `*_log` tables — `consensus.db` post-flip, historically `progress.kv`,
  the tag name is unchanged — below AR, see §1), `kernel-primitive`
  (inside `progress_store.c` itself), `kv-state-primitive`,
  `read-only-introspection`, `state-kv-write-caller-handles-rc`,
  `cvs-zcl-ar-raw-sql-rationale`, `test-fixture-setup`, `test-fixture-verify`,
  `standalone-dev-tool`.
- `raw-return-ok:` — `qsort-comparator`, `logged-above`, `sentinel`,
  `bin-parser-bounds`, `sentinel-no-compile-time-windows`.
- `raw-alloc-ok:` — `test-fixture`, `standalone-dev-tool`,
  `db-service-owns-heap-job`.
- `long-function-ok:` — `legacy-import-state-machine`.

Implementation: `tools/check_observability_pairing.c`,
`tools/scripts/check_raw_sqlite.sh`, `tools/scripts/check_raw_malloc.sh`,
`tools/scripts/check_long_functions.sh`, and the inline `check-silent-errors*`
recipes in `Makefile:1481+`.

---

## Naming — role-based, not birth-order

Instance, artifact, and file names are role-based (`zcl-serve`, the mint
datadir, `curebin-<githash>`), never birth-order sequence numbers
(`serve1`, `install4`, `boot4` are examples of the banned pattern — they only
encode "which attempt" of an otherwise-identical sibling). The exceptions:
wire-format/protocol version tags (`v1`/`v2` message schemas,
`zcl.result.v1`), crypto/algorithm names (`sha3_256`, `x4` batch width,
`ed25519`, `equihash 200_9`), heights, and other genuinely versioned
on-disk format markers.

This law governs names picked from here forward; it does not license
breaking references to already-existing artifacts or established labels.
`mint3` (`~/.zclassic-c23-mint3` on disk, distinct from `~/.zclassic-c23-mint`
— see `config/src/boot_promote_shielded_history.c`) is a real, currently-live
datadir name and stays literal in docs until it is naturally re-created under
a role-based name. Likewise the historical feature-round labels used
elsewhere in this document and in `CLAUDE.md` (Round 5, Round 6) predate
this rule and are not retroactively renamed — the law governs new names,
not history.

---

## Summary: How agents learn to follow the Rails way

1. **Compiler errors** for raw `sqlite3_step` (unless opted out).
2. **Type system** forces `struct zcl_result` with a message on failure.
3. **CI lint** catches raw malloc, silent returns, missing error bodies,
   long-function bloat.
4. **Macros** make the right thing easier than the wrong thing.
5. **Before/after hooks** wired by default — agents see the pattern and follow it.
6. **This document** in `docs/` — agents read it on `cat docs/DEFENSIVE_CODING.md`.

The Rails philosophy isn't "write good code." It's "make it harder to write bad
code than good code." These patterns achieve that in C23.
