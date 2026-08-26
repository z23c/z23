# Tier-1 in-process hot-swap (DEV-ONLY)

Z23 has three development layers:

1. A persistent native build authority inside the `z23-dev` watcher.
   In `mode=auto`, one edit to an allowlisted stateless island goes directly
   through compile, link, resident probe, and atomic registry publication. The
   edit path starts stock GCC/Clang and the linker as bounded children, but no
   Make process, shell, source-identity script, or throwaway native CLI.
2. The activatable MULTI-LEAF module ABI. It is ARMED on the dev lane
   (`zcl23-dev.service` passes `-hotswap-activate` and
   `ZCL_HOTSWAP_ACTIVATE=1`; the loader still refuses the canonical datadir).
   Verify-only probing (`dev.hotswap.probe`) skips the two arming gates but
   still requires the dev datadir, path confinement, and the admit gauntlet.
3. The older native-leaf manifest/staging mechanism. Its build, simulation, loader
   tests, and state inspection remain available, but every public publication
   entry point is contained before loading or registry replacement.

None is publication authority for the canonical node or a release build.

The build profiles are explicit: resident modules use `DEV_LIVE`, an isolated
incremental process replacement uses `DEV_RESTART`, static combined proof uses
`INTEGRATION`, and production uses `RELEASE`. The first three are permanently
non-LTO; the last deliberately retains whole-program LTO. `make
check-dev-loop-profiles` proves the expanded flags and recipe ownership, while
the resident action-plan loader rejects an action plan containing `-flto` or
linker-plugin flags before it compiles anything.

## Real module ABI (activatable, gated)

The module path loads ONE swappable translation unit per `.so`, carrying EVERY
command leaf that file owns, and publishes them in ONE all-or-nothing registry
batch. Editing a 761-line controller and swapping a single leaf used to leave
every sibling leaf in that file stale in the running process; a module now
re-points the whole file at once. After command dispatch drains every reference
to the superseded generation, the loader may unmap its module.

| Piece | Where |
|-------|-------|
| ABI struct + emitter + activation API | `lib/hotswap/include/hotswap/hotswap_module.h` |
| Loader, gate, retirement, and telemetry | `lib/hotswap/src/hotswap_activate.c` |
| Admit → probe → ONE batch commit | `hotswap_module_publish()` (same file) |
| Epoch/refcount drain + 64-entry batch replace | `lib/kernel/src/command_registry.c` |
| Swappable allowlist (ONE row per file) | `config/hotswap_swappable.def` |
| Stateless multi-TU island membership | `config/hotswap_islands.def` |
| Probe leaf per file | `config/hotswap_eligible.def` |
| Shape + READY-read-only lint, self-tested | `tools/lint/check_hotswap_swappable_shape.sh`, `lib/test/src/test_make_lint_gates.c` |
| Static-state lint over BOTH manifests | `tools/lint/check_hotswap_static_state.sh` |
| Per-file build | `make hotswap-module-so FILE=<tu.c>` (or `HANDLER=<leaf>`) |
| Resident no-Make compiler/linker authority | `tools/dev/devloop_hotswap_build.c` |
| 20-edit latency gate | `tools/dev/hotswap-resident-bench.sh` |
| Native verify/apply commands + publish hooks | `tools/command/native_dev_hotswap.c` |
| Stable host/App ABI + transactional state runtime | `lib/framework/include/zclassic23/app.h`, `lib/framework/src/app_runtime.c` |
| Activation flag | `src/main.c` |
| Tests | `lib/test/src/test_hotswap_module.c`, `lib/test/src/test_hotswap_module_v2.c` |

Each module exports one `zcl_hotswap_module` symbol:

```c
struct zcl_hotswap_leaf {
    const char *name;            /* canonical READY read-only leaf path */
    zcl_hotswap_handler_fn fn;   /* replacement handler (non-NULL) */
};

struct zcl_hotswap_module {
    uint32_t abi_version;                     /* == ZCL_HOTSWAP_MODULE_ABI_V2 */
    const char *source_tu;                    /* row in hotswap_swappable.def */
    uint32_t leaf_count;                      /* 1..64 */
    const struct zcl_hotswap_leaf *leaves;
    bool (*self_test)(char *err, size_t cap);
};
```

The emitter is `ZCL_HOTSWAP_MODULE_LEAVES(k_module_leaves, self_test)`. The
original single-handler `ZCL_HOTSWAP_MODULE("leaf", fn, self_test)` still works
as a compatibility alias — it expands to a one-entry table of the same v2
struct, so a TU that has not yet grown a multi-leaf table keeps building and
swapping unchanged. `source_tu` is stamped by the build recipe
(`-DZCL_HOTSWAP_MODULE_SOURCE_TU="<tu>"`), so a module cannot mislabel which
allowlist row it belongs to.

**ABI v1 is retired.** A `.so` still stamped `abi_version = 1` has an
incompatible layout and is refused at `stage=abi` before any other field is
read, with a reason naming both versions. Rebuild it.

A missing symbol, ABI mismatch, invalid field, a leaf count over 64, a leaf not
owned by that file, a leaf declared twice, a missing probe leaf, or a failed
self-test produces a typed refusal and never publishes anything.
`hotswap_module_admit()` is the pure admission gauntlet and
`hotswap_module_publish()` is the whole post-`dlsym` sequence; both compile in
every build and have direct unit coverage with fabricated module descriptors
(no `dlopen`, no dev build needed).

### Pure service islands

`config/hotswap_services.def` separately admits versioned calculation vtables.
These islands receive caller-owned values and buffers only; the static host
keeps parsing, authentication, storage, networking and every external effect.
Publication is an immutable snapshot swap with reader leases and quiescent
retirement. The resident contract—not the candidate—fixes ABI, schema, wire,
KAT and the observation operation. A candidate passes that frozen KAT before
publication; the ordinary static handler then supplies a bounded
post-publication observation in the activation receipt.

The initial frozen contracts are `zcode.c23.corpus.v1` and
`zcode.c23.economics.v1`. The loader resolves the candidate's immutable service
ID against that closed resident set before admission. An unknown descriptor is
therefore a recognized service that selects `DEV_RESTART`; it cannot be tested
against another island's ABI or fall through to the command-module loader.

`check-hotswap-service-islands` rejects mutable file-scope state, TLS,
constructors/destructors, filesystem/SQLite/socket/clock/RNG/process calls,
wallet/node-global/consensus/raw-storage access, and project calls outside the
manifest's stable-import list. A 1 ms coalescing window publishes live only when
every changed `.c` and private header resolves to one exact island owner. The
owner and its compiler-reported dependency closure compile once, then one
module and one registry generation publish; receipts bind the changed-path
count and label multi-path publication as atomic. A second owner refuses the
fast lane. Public contract headers are deliberately distinct: changing one
emits a process-free `DEV_RESTART` selection with no proof claimed and can
never fall through to live publication or the legacy Make/shell save path.

### All-or-nothing, and probe before publish

The publish order is fixed:

1. **Admit every leaf.** A partial admit publishes ZERO leaves — the loader
   never calls the commit hook at all.
2. **Probe.** The file's DECLARED probe leaf (from `config/hotswap_eligible.def`
   — a module never chooses its own probe, and must export it) is dispatched
   against the public command registry's contract for that leaf: the
   registry-resolved spec (still READY, read-only, non-alias), the registry's
   own validation of a bounded EMPTY request, and the reply envelope. The reply
   is checked against the leaf's DECLARED `output_schema` and response budget.
   Any mismatch publishes NOTHING. Activating with no probe hook at all is
   refused: a module asserting its own health is self-certification, and
   self-certification is not a publish credential.
3. **ONE `zcl_command_registry_replace_batch()`** carrying all the leaves. The
   registry pre-validates every path (READY + `EFFECT_READ` + resolvable +
   non-alias) BEFORE it clones or publishes, so in-flight readers observe the
   entire old or the entire new override set, never a torn one. Generations are
   strictly monotonic.

Widening a file's leaf list widens BATCH SIZE, not authority: the same
read-only requirement, the same shape-leaf requirement, the same
dev-datadir-only activation gate, and now an additional probe every candidate
must survive.

### Quiescent retirement

Command dispatch acquires the active override snapshot with an optimistic
refcount and revalidates it before calling the handler. A superseded module is
unmapped only after `zcl_command_registry_all_retired_quiesced()` reports that
every retired snapshot has drained to zero references. If bounded drain cannot
be proved, the module remains mapped. The no-override fast path stays zero-RMW.

### The hard line

`config/hotswap_swappable.def` is the authority allowlist, ONE row per owner:
`HOTSWAP_SWAPPABLE("<source_tu>", "<space-separated leaves>")`. The
`check-hotswap-swappable-shape` lint gate enforces BOTH halves of the line:

- **Shape.** Only shape-leaf translation units — controllers, views, and
  conditions — may be swapped. Any `source_tu` under a reducer stage, consensus
  validation, the storage engine, a supervisor, or another state root is
  rejected. Reducers, consensus code, storage, and supervisors are never
  swappable.
- **Leaf contract.** Every leaf must be declared with `ZCL_COMMAND_READY_READ`
  in the `config/commands` catalog — the READY, `EFFECT_READ` macro form — and
  must be claimed by exactly ONE source file. A leaf declared with any
  `COMMAND`/`PLANNED`/`COMPAT`/`DEV` form (which can carry `EFFECT_MUTATE` or a
  non-READY availability) fails the gate before it can reach the runtime, and a
  leaf claimed by two files fails too, which is what makes a duplicate leaf
  across two modules unrepresentable.

`config/hotswap_islands.def` widens code coverage, never command authority. An
island row binds additional stateless implementation TUs to one already-admitted
owner. Members may live only under controllers, views, conditions, pure
services, metaverse, or encoding roots; they gain no leaves of their own and
are compiled into the same `-Bsymbolic` unity module. Every member is included
in the mutable-static lint scan and may belong to only one owner. Storage,
wallet state, reducers, network ownership, consensus, supervisors, and release
builds remain outside the boundary.

Before the def grew a leaf column the gate checked shape FOLDERS only, and the
READY/read-only property was asserted nowhere but at runtime. Likewise
`check-hotswap-static-state` read only `config/hotswap_eligible.def`; it now
scans the UNION of both manifests, because a TU reachable only through the
swappable list would otherwise get a zero-initialized copy of its module-level
state inside the `.so` and silently lose live process state — no crash, just
wrong answers. Both holes were invisible only because the two lists happened to
name the same six files. Both gates are proven to trip by seeded-violation
fixtures in `lib/test/src/test_make_lint_gates.c`.

The current owners are read-only `app/controllers/` leaves, each with its
emitter in the owning TU. Status and wallet carry their read helpers. The
Metaverse owner carries its pure property-catalog closure and the read-only
agent status/audit/money/liquidity service. That service receives its
controller-owned RPC transport explicitly on each call; it owns no mutable
transport slot and cannot create wallet or transaction authority. All island
members are declared in `config/hotswap_islands.def`:

| Owning TU (`app/controllers/src/`) | Swappable leaves | Probe leaf |
|---|---|---|
| `status_native_handlers.c` | `core.status` | `core.status` |
| `net_native_handlers.c` | `core.network.peers.incidents` | `core.network.peers.incidents` |
| `meta_native_handlers.c` | `ops.metrics` | `ops.metrics` |
| `wallet_native_handlers.c` | `core.wallet.address.list` | `core.wallet.address.list` |
| `chain_native_handlers.c` | `core.consensus.utxo.audit` | `core.consensus.utxo.audit` |
| `app_native_handlers.c` | `app.names.list` | `app.names.list` |
| `metaverse_controller.c` | `metaverse.agent.status`, `metaverse.agent.money`, `metaverse.agent.liquidity`, `metaverse.agent.audit`, `metaverse.property.list`, `metaverse.property.show` | `metaverse.property.list` |

Adding a leaf to an existing file is: append it to that row's leaf list AND add
its trampoline to the TU's `#ifdef ZCL_HOTSWAP_MODULE_GEN` leaf table. Adding a
new file is one new row plus the emitter. The gate refuses a leaf that is not
`ZCL_COMMAND_READY_READ`, the runtime refuses a leaf its file does not own, and
the registry commit independently re-checks READY + `EFFECT_READ`, so a
mutating leaf fails closed three separate ways.

### Activation gate

`dev.hotswap.probe` verifies a module without committing it. A live swap
requires all of:

- the resident process started with `-hotswap-activate`;
- `ZCL_HOTSWAP_ACTIVATE=1` is present in that process's environment; and
- the exact `~/.zclassic-c23-dev` datadir is in use.

The canonical `~/.zclassic-c23` datadir is refused. The single authority check
is `hotswap_activation_authorized()`. Verify-only results are always labeled
`verify_only`. `zcl23-dev.service` carries all three, so the dev lane is armed
by default.

The resident commit also needs a bound registry in the node process:
`register_dev_native_hotswap_rpc()` binds the native catalog
(`zcl_command_registry_set_active`) when the RPC is registered at boot —
without it the commit fails closed with `no active registry bound`.

Inspect activation state with:

```sh
build/bin/z23-dev -datadir="$HOME/.zclassic-c23-dev" -rpcport=18252 \
  dumpstate hotswap
```

The state object reports the flag, environment gate, containment, counters,
active slots, and the last activation or rejection.

### The observable loop: resident compile and activation

Start the isolated dev node normally, then arm its persistent watcher once:

```sh
build/bin/z23-dev -datadir="$HOME/.zclassic-c23-dev" -rpcport=18252 \
  dev loop ensure --input='{"mode":"auto"}'
```

For a single changed owner or island member, inotify waits for a 1 ms quiet
window and calls the resident action executor directly. The action plan is
loaded from `build/hotswap/fast/flags.env` and invalidated by the Makefile,
owner manifest, or island manifest. The executor snapshots the existing
depfile closure, compiles the observed input, rejects dependency mutation or
expansion, links a content-addressed read-only `.so`, calls the resident
`dev_hotswap_native` RPC directly, and persists both
`zcl.hotswap_build_receipt.v1` and `zcl.dev_cycle.v1`. The mandatory candidate
probe's rendered data (or a bounded scalar summary plus its exact SHA-256 when
the leaf has a larger response budget) is included in the activation receipt,
so publication is itself proof of visible behavior; no second status process
is needed.

Before starting GCC, the executor consults one verified host-local artifact
cache. Its key binds the compiler capsule, compiler command, normalized
`DEV_LIVE` flags, link flags, island owner, and the path plus SHA-256 of every
known dependency. Checkout roots embedded in reproducibility flags normalize
to `${WORKTREE}`; source paths in the dependency closure normalize to paths
relative to that root. A hit is accepted only when the stored `.so` hashes to
its separately published marker, then it is hard-linked into the requesting
worktree's content-addressed build directory. A corrupt or partial entry is
removed under a per-key process lock and rebuilt. Cache hits therefore start
zero compiler and zero linker processes; their receipts expose
`artifact_cache_hit`, `artifact_cache_key`, `compiler_processes`, and
`linker_processes`. The first observation of a dependency closure still fails
closed and asks for one more save. Exact reverts and a second worktree can then
reuse the verified artifact; the cache is acceleration only and grants no
probe, activation, or publication authority.

If an event is multi-file or outside the compiled allowlist, auto mode discards
its publication authority and invokes the ordinary cycle in verify-only mode.
The generic reload path remains contained. Manual `make hotswap-try`,
`ZCL_HOTSWAP_PRELOAD`, `dev.hotswap.probe`, and `dev.hotswap.apply` remain
diagnostic and one-shot fallback surfaces, not the fast default.

The commit and probe hooks are ONE shared implementation
(`zcl_native_hotswap_publish_hooks()` in `tools/command/native_dev_hotswap.c`),
used by the resident RPC, `dev hotswap probe`, and the preload path alike — so
"how a candidate is validated and published" has exactly one definition.

`make t-fast-exact ONLY=dev_platform` permanently exercises a real isolated
cache miss, warm hit, changed-source miss, exact revert hit, and second-worktree
hit. The subprocess seam exists only in `ZCL_TESTING` with the explicit
`ZCL_DEVLOOP_TEST_PROCESS=1` fixture opt-in; release builds retain the literal
no-process implementation.

### Resident process-restart candidate

`make dev-bin` freezes non-LTO dev and proof relocatable bases plus a
`DEV_RESTART` action plan beside their object graphs. For a bounded set of
ordinary non-consensus `.c` edits, the
watcher now snapshots the source CAS, invokes the pinned compiler directly for
only those translation units, reuses every prior overlay whose generation and
source digest remain current, links those overlays ahead of the exact frozen
base, then
rechecks the source CAS, and runs `discover help` as a five-second
command-runtime probe. The resident owner starts only compiler, linker, and
candidate children: it starts no Make process or shell.

The save link never enumerates the complete object graph. Make performs one
epoch-owned `-r` prelink when it establishes the dev environment; the action
plan binds that regular file, and the artifact key hashes it. Each save then
links only the current overlay response plus that frozen base, with overlay
definitions ordered first. An overlay containing `.preinit_array`,
`.init_array`, or `.fini_array` ownership fails closed before the linker so a
translation unit cannot execute both its frozen and replacement initializer.
Receipts count all linker processes separately from
`complete_graph_linker_processes`; the latter stays zero on this path.

The cycle also exposes the exact source-CAS I/O it paid:
`source_guard_bytes_read`, `source_bytes_total`, `changed_source_bytes`, and
`source_byte_accounting_complete`. A newly started watcher deliberately
forgets the prior Merkle snapshot on its first observed edit so that events
between watch installation and the first cycle cannot be hidden; that first
cycle may therefore re-read the whole indexed source tree. Later edits on the
same resident watcher reuse the persistent snapshot and normally re-read only
the files whose stat keys changed. Missing, overflowing, or incomplete byte
accounting is labeled incomplete, never rendered as a trustworthy zero.
`dev.loop.wait` uses the list-sized response budget because the existing cycle
schema may contain a full bounded proof receipt; concise loop status continues
to project only its decision fields.

Candidate and proof links share a verified host-local restart-artifact cache.
Its key binds the compiler capsule, base object generation, normalized compile
and link actions, the ordered rewritten response, and the SHA-256 of every
active overlay object. Candidate and test profiles therefore remain distinct.
Each entry is process-locked and accepted only when the executable hashes to
its separate marker; a partial or corrupt pair is removed and rebuilt. A hit
is hard-linked into the worktree's content-addressed candidate directory when
both live on one filesystem; `EXDEV` uses an immutable temporary copy whose
SHA-256 is reverified before no-replace publication. It still runs the
compiler, source guards, candidate probe and affected tests—it removes only an
identical overlay link. Receipts expose
`artifact_cache_key`, `artifact_cache_hit`, and exact process counts. Exact
outputs and reverts may reuse an artifact; cache state grants no evidence or
publication authority.

Candidate health is not publication. After the command-runtime probe, the
same resident owner derives the complete existing proof plan, refuses an
incomplete dependency dimension or substituted path floor, expands plan
families to canonical exact test IDs, compiles the changed units under the
frozen non-LTO test profile, and directly links a content-addressed test
artifact from those bytes. The test runner may reuse an existing skip-free
content-addressed PASS only when its snapshot proves that the cached group's
closure does not reach the changed source; its summary must account for every
selected group as fresh or verified-cached with zero failures and zero
self-skips. Large-stack fixtures inherit the test profile's hard stack limit
directly in the child—no `ulimit` shell wrapper. The durable receipt carries
the exact-group count and selector SHA-256; `dev.test.plan` re-derives the
inspectable list.

The ordinary restart lane publishes a `reflex_ready` cycle immediately after
the source-bound candidate compile/link/probe. Affected tests continue as a
separate stage and publish `feedback_ready` later. See
[`REFLEX_REACTOR.md`](./REFLEX_REACTOR.md) for the stage contract, exact trace,
and reachability firewall.

The save tier never silently truncates a caller closure. When the immediate
union would exceed 32 exact groups, it runs the complete explicit path-owned
floor and moves the broader reverse-caller closure into the exact deferred
set. Both sets retain canonical order and separate hashes; the receipt exposes
`bounded_proof_deferred=true`, and `proof_complete` stays false until the
deferred set runs through integration. If the explicit path floor itself
exceeds the bound, the cycle still refuses before compilation. This is
trustworthy focused feedback, not acceptance or a claim that broader proofs
passed.

A complete run reports `status=proof_ready`, `phase=affected_proofs`, and
`proof_complete=true`. Even then `runtime_published=false`: the
content-addressed executables stay under the worktree build directory and no
node is restarted. Headers, build-graph changes, consensus-risk inputs,
oversized batches, and anything outside the frozen plan stay on the
conservative path.

On this host, the first candidate-only watcher event for
`tools/dev/devloop_restart_build.c` took 1.993 seconds end to end: 168 ms
compile, 1.416 seconds link, and 70 ms candidate probe. The first complete
resident proof, for `app/services/src/bg_validation_dump.c`, took 73.150
seconds: the process candidate took 2.649 seconds, the proof artifact took
2.078 seconds to compile/link, and 21 cold mapped groups took 63.412 seconds.
Every group passed with zero self-skips. This misses the five-second proof
target because the selected `make_lint_gates` heavy family dominates; compiler
and linker latency is no longer the limiting stage.

The generated source-identity object is part of every restart epoch rather than
the frozen base. The candidate and proof branches share the same already
captured native source-CAS record, compile `clientversion.c` with that record,
and substitute the resulting object ahead of the base. This is resident-only
proof identity: the full v2 source record remains publication authority. A
permanent fixture maps a `native_code_command.c` batch through `code_capsule`
and requires `proof_complete=true`, so the former setup-epoch stale-identity
refusal cannot return unnoticed.

The watcher also owns cancellation. `SIGTERM` records an async-signal-safe
cancellation request; the bounded process runner terminates and reaps the
active child process session, including nested process groups, before the
watcher releases its worktree lock. A new relevant source event uses the same
mechanism: the obsolete epoch emits no verdict, its exact replacement paths
remain queued, and the debounced newest batch runs next. Metadata-only
`IN_ATTRIB` events are excluded because compiler reads may update atime and are
not source saves. On
this host, `dev loop stop` interrupted a generic `make ff` tree and completed
in 0.30 seconds, where the prior implementation retained the lock past its
five-second command deadline. Cancellation is reported separately from a
process timeout and never activates a candidate.

The ordinary `dev-bin` bootstrap now writes the frozen non-LTO module action
plan. The resident no longer requires a one-off `make hotswap-module-so` just
to learn compiler and linker flags. A real latest-wins probe superseded an
active `bg_validation_dump.c` proof with a `status_native_handlers.c` save;
only the latter published a cycle epoch, the session had zero descendants
after stop, and its first dependency-baseline compile took 225.6 ms.

The candidate build used one compiler, one linker, one candidate, zero
Make/shell/LTO processes, and no datadir, port, or service access. A separately
audited isolated regtest launch took 11.054
seconds cold and 11.204 seconds after a crash; graceful shutdown did not drain
within ten seconds. That full-node path therefore does **not** satisfy the
five-second restart target and is not used by the watcher.

### Measured floor and the physical limit

`tools/dev/hotswap-resident-bench.sh` rewrites a retained fixed-width module
marker with a fresh nonce twenty times, requiring twenty uncached object files
and distinct artifact hashes, then restores the source. On this host the
2026-08-01 warm run recorded 227.280 ms p50 and 232.141 ms p95 edit-to-visible
against a 250 ms gate. Typical work was 153–166 ms compile, 13–16 ms link,
1–2 ms resident activation, plus
the debounce and receipt observation. The machine-readable result is
`build/hotswap/resident-benchmark.json` (`zcl.hotswap_edit_bench.v1`).

That is close to the practical floor for persistent **stock GCC C** without
keeping compiler internals in-process: preprocessing and native code generation
still have to run, and an ELF shared object still has to link and relocate. A
true interpreter can make parse-to-execute latency milliseconds but gives up
the exact production compiler model. An in-process incremental compiler/JIT
can remove the remaining compiler and linker process boundaries, but introduces
a second compiler authority, more retained memory, and a much larger correctness
surface. The next justified move is broader stateless islands and persistent
compiler experiments in shadow mode—not replacing pinned GCC while it already
meets the sub-250 ms human-feedback target.

### Module link rule: `-Wl,-Bsymbolic` is mandatory

Without it, the module trampoline's reference to its own freshly compiled body
(e.g. `zcl_native_status_body`) is interposed by the host executable's older
definition of the same symbol — the "swapped" handler silently runs the OLD
code. `-Wl,-Bsymbolic` binds intra-module references locally while leaving
host-only symbols (`json_*`, `node_rpc_call`, `zcl_native_bridge_run`, ...)
to bind against the `-rdynamic` host at dlopen. Both `make hotswap-module-so`
and `make hotswap-so` link with it.

The module self-test proves structure only. The behavioral precommit probe that
dispatches the candidate's declared probe leaf with a bounded empty request and
validates the reply against its declared output schema is now wired and
mandatory for any island publish (see "All-or-nothing, and probe before
publish"). This narrow read-only dev authority does not reopen executable
relinking, canonical-node publication, or releases; those still require the
full durable proof and exact-prior-generation rollback transaction.

## Native-leaf manifest and staging

The in-tree staging mechanism builds an eligible stateless native controller
translation unit into a content-identified generation `.so`. A generation can
stage every declared leaf, validate its complete manifest and ABI, and run its
self-test. Public entry points stop before commit, so a probe failure or a
containment refusal publishes no leaves.

This mechanism is dev-only. Release builds are static and have no dynamic-load
path. Every load operation is guarded by `ZCL_DEV_BUILD`; the
`check-hotswap-dev-only` gate enforces that dynamic-loader calls stay inside
`lib/hotswap/` and inside a development-build region.

### Ephemerality and module identity

Any future published override lasts only for the process lifetime and reverts
on restart. Accepted staging generations remain mapped so calls already inside
old code finish safely. Each accepted generation retains the descriptor for
the exact inode opened through `/proc/self/fd/N`; the descriptor is part of
generation identity because reusing its number while an older object is mapped
can make the dynamic loader return its cached object.

### Moving parts

| Piece | Where |
|-------|-------|
| Loader, generation registry, state dumper | `lib/hotswap/` |
| Manifest + `ZCL_HOTSWAP_EXPORT_LEAVES` | `lib/hotswap/include/hotswap/hotswap.h` |
| Eligibility allowlist | `config/hotswap_eligible.def` |
| Atomic leaf override layer | `lib/kernel/src/command_registry.c` |
| Eligible native translation units | `app/controllers/src/*_native_handlers.c` |
| Native bridge used by generated trampolines | `zcl_native_bridge_run()` in `tools/command/native_command.c` |
| Native probe/apply commands | `config/commands/dev.def`, `tools/command/native_dev_hotswap.{c,h}` |
| Build and verification | `make hotswap-so`, `make hotswap-sim`, focused loader tests |

No extra linker or watcher dependency is required: generation builds use the
system C compiler, shared-library support, and libc's dynamic loader.

### Generation build and admission

An eligible controller invokes
`ZCL_HOTSWAP_EXPORT_LEAVES(k_leaves, PARAM_COUNT(k_leaves))` once at file
scope. Under `-DZCL_HOTSWAP_GEN`, the macro emits the manifest and generation
initializer. The manifest binds:

- provider and host ABI versions and sizes;
- capabilities;
- the exact 64-hex source-tree identity;
- the complete generation-input digest;
- stateless state schema;
- mapped tests and probe leaf;
- self-test and quiescence requirements.

The loader requires byte-for-byte equality between the generation's build
identity and `zcl_build_source_id_sha256()` before entering generation code.
There is no dirty-tree compatibility exception, and a Git commit ID is never
authority for admission.

Generation initialization stages leaf replacements through the host API.
Staging cannot mutate the live command registry. After the full set and
self-test pass, the host may build and publish one immutable registry snapshot;
under current containment it stops before that commit.

The object is loaded local and with eager symbol resolution. Its unresolved
resident symbols, including `node_rpc_call` and JSON helpers, bind against the
development executable's exported global scope so handlers use live node state.

### Commands

```sh
# Build one eligible native controller generation.
make hotswap-so FILES="app/controllers/src/status_native_handlers.c"

# Verify loader policy without entering a resident node.
make t ONLY=hotswap_loader

# Inspect the resident staging state.
build/bin/z23-dev -datadir="$HOME/.zclassic-c23-dev" \
  ops state --subsystem=hotswap

# Deterministic three-node generation/network replay.
make hotswap-sim
```

For the manifest/staging mechanism, `make hotswap` and
`tools/dev/hotswap-running-dev.sh` remain contained: both refuse before
building, loading, forwarding, or registry replacement, and the staging path
itself stops before the commit. `dev.hotswap.apply` and `dev.hotswap.probe`
are NOT staging entry points — they are the live module-ABI commands
described under "Real module ABI" above. Use the simulation and focused
loader tests as the staging mechanism's end-to-end proof surfaces.

### Provider and ABI contract

The provider ID is `native.leaves`. Its host API exposes a leaf-staging
callback, and each staged replacement names a canonical native command path
plus its handler. The loader rejects an unknown provider, an incompatible
manifest or host size, missing capabilities, a duplicate or branch path, and
any attempt to target a non-ready or mutating command.

Each eligible translation unit owns its handler bodies and the generation-only
trampolines that call them through `zcl_native_bridge_run()`:

```c
#ifdef ZCL_HOTSWAP_GEN
static void tramp_status(const struct zcl_command_request *request,
                         struct zcl_command_reply *reply)
{
    zcl_native_bridge_run(request, zcl_native_status_body, reply);
}

static const struct zcl_hotswap_leaf_replacement k_leaves[] = {
    { "core.status", tramp_status },
};

ZCL_HOTSWAP_EXPORT_LEAVES(k_leaves,
                          sizeof(k_leaves) / sizeof(k_leaves[0]))
#endif
```

`lib/hotswap` forward-declares the command request/reply structures. Their
concrete definitions are needed only in the controller that emits the
trampolines, keeping the loader independent of app and kernel headers.

### Native development commands

The native registry exposes `dev.hotswap.apply` and `dev.hotswap.probe` through
`config/commands/dev.def`, with handlers in
`tools/command/native_dev_hotswap.c`:

```sh
z23-dev dev hotswap probe \
  --input='{"so_path":"/tmp/gen.so","probe_leaf":"core.status"}'
```

Both commands are live module-ABI entry points (see "Real module ABI"
above), not staging publication commands:

- `dev.hotswap.probe` runs verify-only in the CLI's own throwaway process:
  dlopen + ABI-validate + self-test of one module `.so`. It never commits,
  and `hotswap_module_admit()` runs its admission gauntlet before any
  candidate code is called.
- `dev.hotswap.apply` forwards to the resident dev node's
  `dev_hotswap_native` RPC, which performs the swap inside the running node.
  The swap is verify-only by default; a live activation requires all of
  `-hotswap-activate`, `ZCL_HOTSWAP_ACTIVATE=1`, and the exact
  `~/.zclassic-c23-dev` datadir (the canonical datadir is refused). The
  single authority check is `hotswap_activation_authorized()`.

The automatic GENERATION (manifest/staging) path stays contained:

- `make hotswap` refuses before any load or publication; `make hotswap-so`
  builds a read-only, unpublishable candidate only.
- The resident generation loader (`hotswap_load_leaves`) has no production
  caller; staging publication stops before commit.
- `deploy-dev-lane.sh` public activation, the watcher `auto`/`apply` modes,
  and `dev.change.apply` all refuse before generation relinking.

The deliberate exception is the owner-gated native transaction:
`z23-dev dev generation activate
--input='{"idempotency_key":"<key>"}'`. Its first
call stages and preflights the exact binary without stopping the service and
returns `commit_input`. Re-running the same leaf with that input verifies the
source identity, ABA mutation token, source CAS root, expiry, and resident
generation before invoking the rollback-capable activation engine. It is
confined to `zcl23-dev.service`, `~/.zclassic-c23-dev`, and RPC 18252.
Its fixed-argv service-control timeout is longer than that unit's
`TimeoutStopSec=300`, so the activator cannot race a still-running systemd stop.
Its 120-second readiness window also exceeds the measured 67.6-second
schema-59 recovery boot; the prior 60-second window rejected that healthy boot.

Only `make hotswap` and `tools/dev/hotswap-running-dev.sh` remain typed
containment refusals; the manifest/staging publication path likewise stops
before the commit. Re-enable staging publication only with a disposable
worker, pre-load sidecar/ELF/import policy, an immutable artifact receipt,
and bounded fixtures.

### Eligibility

#### The admission rule, in full

A translation unit is hot-swappable here if and only if it satisfies **all
nine** conditions below. They are not style preferences; each one is the reason
a specific failure mode cannot happen. Conditions 1–3 bound authority, 4–6
bound state, 7–8 bound the artifact, 9 bounds behaviour.

**1. It is a shape LEAF, never an authority.**
The source TU must live under `app/controllers/`, `app/views/`, or
`app/conditions/`, and must never resolve under `core/`, `lib/consensus/`,
`lib/validation/`, `lib/storage/`, `lib/net/`, `lib/coins/`, `lib/chain/`,
`lib/mining/`, `app/jobs/`, `lib/kernel/`, `lib/supervisor/`,
`app/supervisors/`, or `domain/consensus/`. A dlopen'd module of any of those
could silently diverge the node's consensus state or the reducer fold — a live
code swap that can change a consensus rule is a chain-split mechanism.
Enforced by `check-hotswap-swappable-shape`.

**2. Every leaf it re-points is READY and read-only.**
Each leaf must be declared `ZCL_COMMAND_READY_READ` in `config/commands/*.def`
— the READY, `EFFECT_READ`, non-alias macro form. A leaf declared with any
`COMMAND`/`PLANNED`/`COMPAT`/`DEV` form can carry `EFFECT_MUTATE` or a
non-READY availability and is refused before it reaches the runtime. The
command-registry batch commit re-checks READY + `EFFECT_READ` + non-alias for
every leaf independently, so this is asserted twice on different evidence.

**3. Each leaf is owned by exactly one file.**
Globally unique across `config/hotswap_swappable.def`, which is what makes "two
modules racing to own one leaf" unrepresentable rather than merely unlikely.

**4. The TU defines no mutable file-scope statics.**
This is the sharpest state rule and the least obvious. A module `.so`
recompiles the whole TU, so **any mutable file-scope static becomes a fresh
zero-initialized copy inside the `.so`**. The live process's state — registered
routes, boot-populated `main_state`, atomic provider slots — is silently lost.
No crash; just wrong answers. Resident state must live in a sibling
NON-eligible trampoline TU. A provably swap-safe static may carry a same-line
`hotswap-static-ok: <reason>` escape. Enforced by
`check-hotswap-static-state`, which scans the union of the eligible manifest,
the swappable manifest, **and every island member**.

**5. It owns no ambient effects.**
Parsing, authentication, persistence, log and filesystem I/O, and threads stay
in the resident half. A swappable body calculates over caller-owned values and
buffers. `ops.logs` is the model: the static RPC handler keeps the file access;
the swappable body owns request composition only.

**6. Nothing else holds a pointer into it.**
A leaf is reached only through the command registry's override slot, which the
loader re-points atomically. If another subsystem cached a function pointer
into this TU, or registered a callback the registry does not own, the swap
would leave that caller on the old code with no way to drain it. This is why
the unit of swap is a *command leaf*, not "a function".

**7. Every leaf body is inside the module's own island.**
The `.so` is linked `-Wl,-Bsymbolic` with `-Wl,-z,now`. A body defined in a TU
that is neither the owner nor one of its
`config/hotswap_islands.def` members is **imported from the resident node** at
dlopen. Re-pointing such a leaf gives you new *dispatch* into **old code** —
the swap silently does nothing for that leaf. The unity-include that builds an
island is what makes a multi-file module genuinely recompiled. (`core.status.brief`
was exactly this case: its body lives in `status_brief_native_handler.c`, which
had to join the status island before the leaf could really be swapped.)

**8. The artifact exports exactly one provider symbol.**
`zcl_hotswap_module` for the module ABI; `zcl_hotswap_gen_init` +
`zcl_hotswap_manifest_v2` for the generation ABI. See *One provider per
artifact* below — this is an ABI property, not a policy choice.

**9. It declares a resident-owned probe, and passes its own self-test.**
The TU names a canonical probe leaf in `config/hotswap_eligible.def`, resolved
to exactly one case in `config/hotswap_probe_cases.def`. The case freezes
bounded canonical JSON, the expected output schema, and a byte ceiling;
candidate code cannot choose or weaken any of them. The probe leaf must be one
of the leaves the module actually re-points, or probe-before-publish would be
validating code the module never installs. The module also supplies a
`self_test(err, cap)` structural hook, run before publish.

#### What this admits, and what it does not

The rule is deliberately narrow, and the narrowing is almost entirely
conditions 1, 4 and 7 — not the allowlist's length. Against the 1,967
production TUs in the tree (excluding `lib/test/`, `vendor/`, `tools/`):

| Class | TUs | Why |
|---|---|---|
| Forbidden (consensus/state/supervisor roots) | 367 | Condition 1. Never eligible, at any effort. |
| Ineligible root (not a shape leaf, not an island root) | 947 | Condition 1. Would have to be restructured into a controller/view/condition to qualify. |
| Owner-eligible root (`app/controllers`, `app/views`, `app/conditions`) | 373 | Of these, 271 already hold no mutable file-scope statics and 102 are blocked by condition 4. |
| Island-member-eligible root (`app/services`, `lib/metaverse`, `lib/encoding`, …) | 280 | 198 statically clean, 82 blocked by condition 4. |

Within the 373 owner-eligible TUs, only **10** currently define a
`zcl_native_*_body` — i.e. actually own a native command leaf. That, not the
consensus line, is the real ceiling today: **the mechanism reaches as far as
the native command bridge reaches.** Nine of those ten are now admitted; the
tenth (`status_journey_native_handler.c`) owns `core.status.journey`, which is
not declared `ZCL_COMMAND_READY_READ` and so fails condition 2.

#### The addressable population, and why it is not 297

The unit of swap is a command leaf re-pointed in the registry's override layer,
and a trampoline can only re-point a leaf that dispatches through the native
command bridge. Of the **297** `ZCL_COMMAND_READY_READ` leaves in
`config/commands/*.def`, only **61** name `zcl_native_bridge_command` as their
handler. The other 236 carry bespoke `zcl_native_handle_*` handlers, which are
not this seam.

Of those 61, **31 are now swappable** (the other 10 swappable leaves —
metaverse, and others — reach the registry by a different registered handler),
leaving 30 addressable-but-not-yet-swapped. Those 30 split into three very
different costs:

- **~20 have no controller body at all.** They are declarative rows in an
  RPC-passthrough table inside `tools/command/native_command.c`
  (`{ "core.network.peers.list", "getpeerinfo", JSON_ARR, … }`) — data, not
  code. `native_command.c` is the resident bridge itself: it is not under a
  shape-leaf root (condition 1), and making it swappable would mean swapping
  the swapper. Cost per leaf: move that row's request composition into a
  controller TU as a real `zcl_native_*_body`, bind it, then admit — roughly a
  30-line change each, plus a probe case. This covers most of the remaining
  `core.network.*`, `core.wallet.balance/status/audit`, `core.storage.stats`,
  `core.mining.*`, `ops.health`, and `ops.lanes` leaves.
- **2 are withheld on the consensus line**: `core.chain.block.get`,
  `core.chain.transaction.get` (see above). Cost: an owner decision, not code.
- **The rest are consensus/sync projections** (`core.consensus.integrity`,
  `core.consensus.mmb`, `core.consensus.utxo.commitment`,
  `core.sync.validation`) which are also passthrough rows and would need the
  same treatment plus the same owner judgement.

So "make hot-swap reach most of the codebase" is not reachable by widening
allowlists, and the blocker is not caution. This mechanism swaps *command-leaf
shape code*. Reaching further means either (a) routing more read leaves through
the native bridge from real controller TUs — mechanical, bounded, and the
obvious next lane — or (b) a different mechanism entirely for stateful
subsystems, which is what "Stable host/App ABI and stateful islands" below
sketches. Neither is an allowlist edit.

#### One provider per artifact

`make hotswap-so` refuses more than one file per generation with *"v2 pilot
admits one atomic provider per generation"*. That wording suggests pilot
caution. It is not: it is a hard property of the ABI. Both emitters define a
**single, fixed, well-known symbol**, so two provider TUs in one `.so` is a
duplicate-definition link error:

```
multiple definition of `zcl_hotswap_module'
multiple definition of `zcl_hotswap_gen_init'
multiple definition of `zcl_hotswap_manifest_v2'
```

What that limit does **not** constrain is the thing developers actually need:

- **Files per artifact** is already unbounded — `config/hotswap_islands.def`
  unity-includes N stateless TUs into one `.so` behind one provider symbol.
  `metaverse_controller.c` ships **13 files** in a single module today.
- **Leaves per swap** is 64 (`ZCL_HOTSWAP_MODULE_MAX_LEAVES`, matching
  `ZCL_COMMAND_HANDLER_OVERRIDE_MAX`), all published in ONE all-or-nothing
  batch.

So the restriction is *fundamental as written* and *incidental in effect*.
Lifting it properly would mean an ABI v3 that exports a **set** —
`zcl_hotswap_module_set` gathered via a linker section — plus a loader that
admits each member and commits the union as one batch. Nothing in the current
design needs that; widen the island instead.

| Native translation unit | Probe leaf | Leaves |
|---|---|---|
| `app/controllers/src/status_native_handlers.c` | `core.status` | 8 |
| `app/controllers/src/wallet_native_handlers.c` | `core.wallet.address.list` | 6 |
| `app/controllers/src/net_native_handlers.c` | `core.network.peers.incidents` | 2 |
| `app/controllers/src/meta_native_handlers.c` | `ops.metrics` | 2 |
| `app/controllers/src/chain_native_handlers.c` | `core.consensus.utxo.audit` | 1 |
| `app/controllers/src/app_native_handlers.c` | `app.names.list` | 9 |
| `app/controllers/src/ops_native_handlers.c` | `ops.debug.dash.summary` | 5 |
| `app/controllers/src/metaverse_controller.c` | `metaverse.property.list` | 6 |
| `app/controllers/src/diagnostics_native_handlers.c` | `ops.logs` with a fixed one-row, one-second case | 2 |

`core.chain.block.get` and `core.chain.transaction.get` are deliberately
withheld from `chain_native_handlers.c`. Both are `ZCL_COMMAND_READY_READ` and
would pass every gate, but they render block and transaction bytes — the
block/transaction path. Read-only is not the test there; admitting them is an
owner decision, not a lint pass.

#### Proving a row, rather than claiming it

An allowlist row that has never been loaded is a claim, not an admission. Every
hot-swap test in `lib/test/` drives `hotswap_module_admit()` with a struct
**fabricated in the test's own TU**, which proves the gauntlet's logic and
nothing about any real artifact. Two failure classes pass every text gate and
fail at load:

- a row whose TU emits no `zcl_hotswap_module` symbol at all
  (`diagnostics_native_handlers.c` was in exactly this state — listed as
  swappable, never loadable);
- a row that violates condition 7 (`core.status.brief`).

`make hotswap-verify` closes that gap. It builds each row with the shipping
recipe, dlopens the artifact, and runs the REAL
`hotswap_module_admit()` gauntlet against the REAL, compiler-emitted module
struct — no node, no datadir, no registry commit:

```
make hotswap-verify                 # every row of hotswap_swappable.def
make hotswap-verify FILE=<tu.c>     # one row
```

All dlopen/dlsym/dlclose stays in `lib/hotswap` behind `#ifdef ZCL_DEV_BUILD`
(`hotswap_verify_module_so`), so `check-hotswap-dev-only` still proves a
release build links zero dynamic-loading code.

Parameterized cases are parsed and validated by the resident immediately
before candidate dispatch. The public registry must still identify the exact
operation as READY/read-only, accept the frozen input, and declare the frozen
schema and an equal-or-larger response budget. Any drift publishes nothing.
`ops.logs` is the first non-empty case; filesystem access remains in its static
RPC handler while the island owns only request composition.

### Tests

- `make hotswap-sim` covers rejected-batch zero publication, in-flight old
  generations, atomic multi-provider commit, new-call visibility, and exact
  seed replay.
- `make t ONLY=hotswap_loader` covers paths, datadir policy, the generation
  registry, state dump, release refusal, and the leaf manifest/host contract.
- `make t ONLY=hotswap_simnet` atomically repoints the same fixture leaf across
  successive generations and rejects non-monotonic generation numbers without
  publishing.
- `make t ONLY=command_handler_snapshot` rejects branch-path replacement with
  nothing installed.

### Stable host/App ABI and stateful islands

`lib/framework/include/zclassic23/app.h` is the project-neutral C ABI: opaque
host-owned state handles, bounded route/topic tables, an explicit capability
ceiling, self-test/quiesce hooks, and prepare/commit/abort migrations. The host
copies its function table and never lends modules raw SQLite handles, sockets,
wallet private keys, consensus mutators, or release publication authority.

`zcl_app_runtime_v1_activate()` validates the candidate, runs its self-test,
prepares an exact schema transition, quiesces the old generation, commits the
migration, and atomically advances the active manifest/generation. Failed
validation, prepare, quiesce, or commit retains the exact prior active pointer
and records a rollback receipt; schema removal and rollback are refused. This
is direct-tested but is not yet a public dynamic loader. Selected stateful App
modules can move onto it only after their state is behind the opaque host API.
Storage, reducers, wallet state, network ownership, consensus, and releases do
not cross this boundary.

## ZVCS auto-anchor

Every warm passed development-cycle verdict—hot-swap, transactional reload, or
docs-only check—auto-anchors through `finish_cycle()` in
`tools/dev/devloop_cycle.c` and `vcs_devloop_anchor_cycle()` in
`lib/vcs/src/vcs_devloop.c`. The ZVCS commit binds the source tree, cycle
verdict, produced binary generation, and agent/session/task metadata.

The first durable snapshot can require thousands of object writes, so it is
kept off the foreground edit verdict. The library detects that a baseline is
needed and returns `vcs_deferred` plus a reason. The interactive dev loop then
launches `vcs_devloop_run_initial_baseline()` through the dev-only detached
worker in `tools/dev/devloop_baseline.c`. The library remains process-spawn
free, enforced by `check-vcs-no-git`.

Subsequent cycles synchronously bind their exact generation. Generated trees,
local agent worktrees, and caches are excluded, and stale stat-cache rows are
deleted during the baseline.

For a transactional reload, the generation is the candidate SHA-256 returned
by the activation engine. A docs-only check records an all-zero generation
hash while still binding source and verdict.

ZVCS failures are fail-open for the development verdict and are reported in
`vcs_error`. A sealed-path refusal is also labeled
`vcs_sealed_refusal:true`; source-integrity signaling never grants runtime
publication authority.

## Transactional reload (contained)

No public publication entry point reaches either retained reload backend.
Environment variables or direct script calls cannot opt into activation.

Both implementations stop the development service, atomically flip the
current-generation symlink, restart, and verify the exact `/proc` executable
identity before success, rolling back on any preflight or verification failure:

- The shell seam runs the contained development deployment script after a fast
  rebuild.
- The native engine calls `dev_activation_run()` with the exact dev-lane
  constants and carries its candidate SHA-256 directly into the ZVCS binding.

The retained selection seam exists for hermetic tests, not as publication
authority. The activation engine is covered by `test_dev_activation`; shared
request construction and result mapping are covered by `test_dev_platform`.

The native full-reload entry point requires immutable source epochs, an owner
plan/commit handshake, resident expected-epoch compare-and-swap under the
activation lock, exact post-publication probes, deterministic rollback, and an
isolated copy proof. Automatic watcher publication and canonical publication
remain outside that authority.

## Sealed-consensus refusal

The fast loop cannot publish changes under `core/`. A source unseal token does
not authorize hot-swap, reload, staging, or generation relinking.

When a cycle touches sealed consensus code without a token, it exits 3 with a
structured `sealed_consensus_core` refusal that names the paths, manifest,
consensus-parity law, unseal ritual, and elevated proof procedure. Both one-shot
and persistent-watch paths pass through this check before the dev-build gate.

Consensus fixes remain possible through the owner-gated route: record a reason
with `make core-unseal REASON=...`, run full CI and copy proof, deploy through
the owner gate, then reseal with `make core-seal`. The fast loop reads but does
not mint or consume the token, so one unseal covers the iterative work for one
landed change rather than only its first local cycle.

`make t ONLY=dev_platform` covers sealed-path classification, refusal fields,
exit status, persisted verdict, and token-authorized progression.

The durable ZVCS record lives under `.zvcs/`: `commits.log` is the append-only
self-verifying history and `objects/` holds content-addressed data. Read paths
are demonstrated in `lib/test/src/test_vcs_devloop.c`.
