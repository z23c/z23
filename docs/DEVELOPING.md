<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Developing Z23

Use this procedure to inspect existing code, make an owned change, check its
behavior, and prepare an exact, receipt-gated integration checkpoint. Start
with a checkout whose existing work you have identified and preserved. The
first-hour section checks the toolchain and builds the development binaries;
shared hosts also require their installed build scheduler.

C23 is the C language standard used by this project. A receipt records a
bound observation; it grants only the authority its receiving policy allows.
An action identifies work with exact inputs; a candidate identifies the
proposed source. The durable mission and authority
contract are in [`../AGENTS.md`](../AGENTS.md); current priorities are in
[`work/FORWARD_PLAN.md`](work/FORWARD_PLAN.md). Current state of the
maintainer's hosted node belongs only in [`HANDOFF.md`](HANDOFF.md).

Z23 is first a public ZClassic full node and second an optional
decentralized C23 software commons. Consensus, custody, synchronization, peer
health, and public-node reliability always outrank package computation and
development convenience.

## The normal loop

1. Orient in the current checkout and mission.
2. Inspect the exact source and runtime context.
3. Edit the smallest owned surface.
4. Receive fast local feedback and continue working.
5. Consume action-changing RED (failed-check) evidence when it arrives.
6. Run the focused proof selected by source impact.
7. Fetch and integrate current `origin/main`.
8. Run the integration gates and push a coherent slice.
9. Continue the mission while deeper proof runs asynchronously.

When you know WHAT you want to do and have forgotten HOW, do not re-read this
document: [`COOKBOOK.md`](COOKBOOK.md) is the lookup table — one question, one
answer, and every recipe in it is executed by `make check-cookbook`, so a
recipe that stopped working fails the build instead of costing you an hour.
This document is the ORDER; the cookbook is the incantations.

A push is a checkpoint, not completion. Remote proof must not block the
developer's ability to continue editing. Acceptance remains a local policy
decision over exact canonical task, candidate, action, and receipt objects.

## 0. First hour on a clean machine

Everything below is the whole path from `git clone` to an edit-build-test
turn. It is the path a new developer walks, in order, and nothing later in
this document works until it has been walked once. Every command here was run
against a cold checkout before it was written down; the wall times are from
that run, on a 28-CPU build slot.

```bash
git clone --recurse-submodules https://github.com/z23c/z23.git
cd z23
make doctor-env                        # toolchain: is this host capable at all
make doctor                            # packages: tools/scripts/vendor_prereqs.tsv
make setup                             # arm the clone: hooks, archives, compile db
make -j"$(nproc)" z23                  # the node binary      -> build/bin/z23
make -j"$(nproc)" z23-dev              # the developer binary -> build/bin/z23-dev
```

Measured on a cold checkout, 28 CPUs: `setup` 3m07, `z23` 1m46, `z23-dev`
1m38. `make doctor` and `make doctor-env` are seconds. For another fresh-clone
measurement, `make first-build-timing` times vendor preparation, setup, the
default build and the test suite; `make timings` reads that result. It does
not rerun the doctor checks or the separate `z23-dev` build above.

Those are the numbers with the host to yourself. Walked again on 2026-09-19
from an empty directory on the same 28-CPU slot while three other lanes were
building on the same machine: clone 12s, `doctor` 14s, `doctor-env` 5s,
`setup` 3m15, `z23` 5m42, `z23-dev` 3m54 — **13m23 to a working dev loop**,
and 17m30 including the first green test group and a full `make lint` (212
gates, 3m23). The compile steps are what stretches; `setup` and the doctors do
not. Budget for that before concluding a build has hung.

**Use `--recurse-submodules` to initialize `vendor/tor`.** A plain
`git clone` leaves that submodule empty. `make setup` does not establish the
Tor archives; the default `make z23` path establishes them before linking.
`make doctor-env` checks the empty submodule before that build and reports
`MISSING vendor/tor  empty (not initialized; the node would link stub Tor)`.
`make doctor` passes in that same tree, so the two doctors disagreeing is the
symptom. If you already cloned without it:

```bash
git submodule update --init vendor/tor
make tor-full                          # or `make tor-ready` beside a sibling checkout
```

**`make z23-dev` is a separate line on purpose.** `all` — what plain `make`
builds — is `test_zcl zclassic23 zcl-rpc zclassic23-package-verify` plus the
POSIX-only binaries (for the portable Unix interface) and the adapter
runner. `z23-dev` is not in it and never
has been. Every development command in this document is spelled
`build/bin/z23-dev ...`, so a developer who ran plain `make` and then reached
section 5 gets "No such file or directory" from a tree that built perfectly.
Build it explicitly, once, here.

`make setup` already armed this clone's Git hooks — it calls `install-hooks`
itself (`Makefile:15296`), and the hooks are what refuse an unproven push. Ask
what you ended up with, which is read-only and never writes config:

```bash
make hooks-status
```

It prints the effective `core.hooksPath`, the config file that set it, the
`pre-push` hook it resolves to, and what that hook actually runs. On a single
checkout that is the end of it. If you later add worktrees, run
`make install-hooks` again in each one — it writes that worktree's own config
scope and nobody else's. The second trap below says why the new worktree needs
it at all.

Now you can take a turn. The inner loop is three commands:

```bash
make -j"$(nproc)" dev                  # compiler-speed rebuild -> build/bin/z23.dev
make t-fast ONLY=<group>               # one test group
make lint-fast                         # the fast gate subset
```

`make -s print-CFLAGS` and `print-DEV-CFLAGS` show the two flag sets if you
want to know what those two builds differ by.

### On a shared build host: `devbuild`

If you are the only user of your machine, skip this; `make -j"$(nproc)"` is
complete and correct on its own.

On a host where several lanes, another project, and a live node share the
CPUs, every heavy build, proof, benchmark and test matrix goes through a host
scheduler named `devbuild`, and the form is:

```bash
devbuild --wait make -j"$(nproc)" lint
devbuild --plan                        # what a slot would grant; runs nothing
```

`devbuild` is **not installed by any repository target.** It is a shared host
program. Read `~/.config/dev-workers/OPERATIONS.md` and inspect
`devbuild --plan` for the installed host limits; reference defaults below do
not promise identical settings on every retained host. Each project gets a
slot admitting several concurrent lanes: Z23's
slot admits up to `DEVBUILD_Z23_LANES` concurrent jobs (default 3, max 4);
QEDC's slot admits up to `DEVBUILD_QEDC_LANES` concurrent jobs (default 2,
max 4); each is one per lane lock. `--wait` waiters are served
first-in, first-out (FIFO) through
enqueue-ordered tickets, so a long-queued job is never passed over by a
newer one; a `dev land` invocation, or `DEVBUILD_PRIORITY=land`, takes the
next free Z23 lane ahead of ordinary waiters. It refuses admission when the
host has under 24 GiB available, and runs commands inside a `systemd-run
--user --scope` with a CPU quota, a memory ceiling, CPU pinning that leaves
two physical cores outside the development slice, and a per-project
CPUWeight (Z23 20, QEDC `20 * DEVBUILD_Z23_LANES / DEVBUILD_QEDC_LANES`, so
QEDC's combined share across its lanes matches all concurrent Z23 lanes'
combined share). Each finished job
appends one JSON line (project, pid, cwd, queue/run timings, rc, lane,
mem/cpu use, tree — a 16-hex checkout fingerprint from HEAD, the
working-tree diff and untracked file names) to
`~/.local/state/development/devbuild.jobs.jsonl` for measuring slot
contention; a repeat of the same cwd + cmd on the identical tree that
previously exited 0 prints an advisory stderr note.
[`../platform/deploy/devbuild`](../platform/deploy/devbuild) is the reference
mirror of the installed script, with the exact contract in its header;
[`../platform/deploy/test-devbuild.sh`](../platform/deploy/test-devbuild.sh)
exercises lane overlap (Z23 and QEDC), FIFO order, landing priority, and
the accounting file against that mirror.
[`../platform/deploy/devbuild-broker`](../platform/deploy/devbuild-broker) is
a separate, not-yet-installed replacement candidate with finer-grained
processor, random-access memory (RAM), and input/output (I/O) classes; see
[`../platform/deploy/README.md`](../platform/deploy/README.md) for its status.
That README is the door to the rest of that directory: which units a host
runs, which of them a clone gets, and why the remainder stay host-local.

Read that file before working on a shared host, because three things in this
tree call `devbuild` by name and fail without it:
`tools/dev/node_lifecycle.sh`, `tools/dev/commons_journey_acceptance.sh`, and
`tools/scripts/qualify_fleet_gateway_front.sh`. Inside a `devbuild` scope
`nproc` already reports the granted CPUs, so `-j"$(nproc)"` is the right job
count there and not an over-subscription.

### Five things that will look like bugs and are not

These are the traps a newcomer hits in the first day. Each one is a real,
current behavior of this tree, not a defect waiting to be fixed.

**Plain `make` does not build `build/bin/z23-dev`.** Covered above. `make
z23-dev`, `make dev-bin` and `make zclassic23-dev` are the same target.

**A worktree you just added is not armed, and nothing says so.**
`core.hooksPath` is per-worktree configuration. `git worktree add` copies the
spawning checkout's `config.worktree` into the new worktree, so the new one
starts out naming `build/githooks` — a relative path Git resolves against
whichever worktree runs the hook, which is the new one, whose `build/` does
not exist yet. Git treats a missing hook file as "no hook" rather than an
error, so a push from there is silently equivalent to `--no-verify` until you
arm it:

```bash
cd ../my-new-worktree
make install-hooks                     # or make setup
make hooks-status                      # the path, and the config file that set it
```

Hook-path writes and unsets are `--worktree` scoped. If needed, the installer
first announces and enables the shared `extensions.worktreeConfig` setting
once. Measured on 2026-09-19 in a
three-worktree repository, installing in each of the three in turn: all three
stayed armed on their own `build/githooks`, `check-git-hooks-installed` was
clean in all three after every step, and the shared `.git/config` was never
written. Hiding one worktree's `build/githooks` stopped that worktree's hooks
and no other's, which is what "relative, per worktree" means in practice.

`ZCL_GIT_HOOK_ROOT` names the checkout to arm. Run `install-hooks` in each
worktree rather than following older instructions to arm only the main one.

`make hooks-status` is the read-only question and never writes config.

**`make t`, `t-fast`, `t-fast-exact` and `test-parallel` build the tools
their selected groups exec.** A few groups exec a binary no default test
prerequisite builds: the fleet gateway shards need
`build/bin/z23-fleet-gateway` and the node by its alias
`build/bin/zclassic23`, the CLI groups need that alias, `freebsd_sh` needs
`build/bin/fbsh`, and the semantic sensor groups need the libclang tool
`build/bin/z23-clang-manifest`. Each is declared once, as a BUILD need, in
`tools/dev/test_group_host_needs.def`. Before the run, the recipe asks the
runner for exactly its own selection with `--list-build-needs`, which prints
nothing for an ordinary selection, and starts a separate background
`make <target>` for each line. The recipe joins all builders before tests
start; a target that cannot be built or leaves its required output absent
stops the run with
`FAIL test_need_unbuildable_<target>`. A landing proof builds the same rows
in its generation, except the ones it already provides (the admitted node,
the prefork-built `fbsh`). Running the runner binary directly builds
nothing, so a fleet gateway shard started that way without its binaries
fails with `missing binary <path>`.

```bash
make t-fast ONLY=fleet_gateway_shard_01   # builds fleet-gateway and zclassic23 first
```

**An installed `z23-dev` on PATH is a content-addressed link, not your
build.** `~/.local/bin/z23-dev` is a symlink into
`~/.local/lib/z23/<sha256>/`, so its name stays put while its target names
the exact bytes that produced it. Its modification time tells you when the
link was repointed and nothing about which source it came from. To learn what
source it actually is:

1. Capture this checkout's source identity.
2. Ask the installed binary for its identity.
3. Compare their `source_id_sha256` values.

```bash
tools/dev/source-identity.sh capture-record
z23-dev agentbuild        # compare its source_id_sha256 to the captured one
```

Never conclude "it is current" from `ls -l`.

**Commits on `main` must be signed.** The push path refuses an unsigned
commit, and the check is not a warning:

```bash
git log --format='%G?' origin/main..HEAD   # every line must read G
```

`N` means unsigned. Configure signing before your first commit rather than
discovering it at push time.

### The names: `z23`, `zclassic23`, and `~/.local/state/zclassic23`

The product and every binary are **`z23`**. You will still see `zclassic23`
in three places, and all three are aliases or history, not a second thing:

- the `zclassic23` make target is a one-line alias for `z23`
  (`Makefile:6913`), and `ZCLASSIC23_BIN` already points at `build/bin/z23`;
- `build/bin/zclassic23` and `build/bin/zclassic23-dev` are migration
  symlinks to `build/bin/z23` and `build/bin/z23-dev`;
- the maintainer's host keeps state under `~/.local/state/zclassic23/` and
  the canonical checkout under a `zclassic23` path, both predating the rename.

Nothing is broken by this and nothing needs renaming to work. A full rename
is deliberately not attempted piecemeal: it would touch the make targets and
their aliases, the `ZCLASSIC23_*` variables, every tracked unit filename
under `platform/deploy/`, the state and datadir paths those units name, the
installed units on every host already running them, and the `docs/` pages
that cite those paths — so it is one coordinated change or it is a broken
fleet, never a lane's side errand.

## 1. Orient

On a new Linux, macOS, or Windows machine, run `make doctor-env` before
`make doctor`: of these two goals, only `doctor-env` skips the Makefile's
C23 toolchain gate. It compiles the check with `cc -std=c2x`:

```bash
make doctor-env
```

It reports the compiler (`-std=c23` capability, not a version parse), git,
`vendor/tor` submodule state, make, mingw/ccache/zcc, the stack soft limit,
CPU count, and free disk. MinGW is optional for an ordinary host `make z23`,
which is why doctor labels its absence optional, but it is required before
`make pre-push-ci`: that gate performs non-vacuous Windows compile/link
acceptance on Linux and macOS. Each failing required check prints the exact
fix command for this platform. `make doctor` remains the separate
package-prerequisite doctor (`tools/scripts/vendor_prereqs.tsv`).

Then identify the checkout and preserve existing work:

```bash
pwd
git status --short --branch
git fetch origin main
git rev-parse HEAD origin/main
```

Read [`work/FORWARD_PLAN.md`](work/FORWARD_PLAN.md), then consult:

- [`HOW_THE_NODE_WORKS.md`](HOW_THE_NODE_WORKS.md) for the state-machine mental
  model;
- [`CODEBASE_MAP.md`](CODEBASE_MAP.md) for source ownership and extension
  recipes;
- [`AGENT_TRAPS.md`](AGENT_TRAPS.md) before re-solving an intentional or
  completed behavior;
- [`SECURITY_AND_INTEGRITY.md`](SECURITY_AND_INTEGRITY.md) and
  [`CONSENSUS_PARITY_DOCTRINE.md`](CONSENSUS_PARITY_DOCTRINE.md) near security,
  custody, or consensus boundaries;
- [`HANDOFF.md`](HANDOFF.md) only when operating the maintainer's hosted node.

Do not infer a permanent coordinator or special agent role from a local
worktree layout. Maintain one primary writer per component, preserve unrelated
dirty work, and use committed identities on `origin/main` as the shared
integration blackboard.

For fleet optimization, follow the
[fleet speed north star](../AGENTS.md#fleet-speed-north-star).
Record the exact action inputs and receiving policy before spending CPU.
Check qualified peer work and in-flight duplicates first; compare the measured
cost of discovery, missing-byte transfer, verification, and binding with local
execution. Dispatch independent missing actions to authorized idle peers.
Keep fine-grained action identities separate from transfer packs and mappings.
Report duplicate CPU, bytes, hashes, copies, queue waits, and
compiler/linker/test launches, together with critical-path time. An unavailable
reuse qualifier
requires the existing cold path; it is a measured missing rail, not permission
to admit unsigned verdicts or bypass a gate. Capsules, distributed ThinLTO,
and QEDC-native emission are experiments until their exact receiving contracts
and real behavior qualify.

### Recover a verified orphaned file claim

Use `dev agent claim` to acquire or renew a bounded file scope. A silent
worker is not an orphan: preserve its live lease and check worktree ownership
before taking over. A legacy claim without a lease can be retired only when
its exact checkout path is absent and Git no longer registers that worktree:

```bash
build/bin/z23-dev dev agent claim --input='{"story":"Retire the verified orphaned checkout","files":[],"retire_worktree":"/absolute/path/to/absent-checkout"}'
```

The native command refuses an existing path, a symlink, a registered worktree,
any lease field, ambiguous records, or uncertain filesystem/registry evidence.
It saves the exact retired row and returns its evidence path and SHA-256
before replacing the ledger; every other ledger byte is preserved. Keep that
evidence. Do not delete the ledger, prune live worktrees, or treat retirement
as a claim: acquire a fresh scope afterward. A persistence failure can report
`mutated:true`; inspect the returned evidence before deciding what to do next.

## 2. Inspect exact context

**Before you build any capability, ask whether this tree already has it.**
`code find` searches symbol NAMES; `code have` searches what code *does*, by
stemming the query and matching it against symbol names, doc comments, file
purposes, paths, and groups. Run it first — it is the cheapest step in the
loop and the one that prevents the most expensive mistake:

```bash
build/bin/z23 code have --input='{"text":"validation"}'
```

Illustrative shape, abridged (warm: tens of milliseconds; exact counts rot as
the tree grows, so this is not a pinned fixture — re-run the command above to
see today's numbers):

```json
{"verdict":"ALREADY EXISTS","capabilities":[
 {"what":"validation (<n> matching symbols)",
  "header":"core/params/include/consensus/validation.h",
  "symbol_count":<n>,"used_by_files":<n>,
  "count_basis":"callers-of-matched-symbols"},
 {"what":"activerecord (<n> matching symbols)",
  "header":"engine/models/include/models/activerecord.h",
  "symbol_count":<n>,"used_by_files":<n>,
  "example_caller":"engine/controllers/src/store_controller.c"}]}
```

`used_by_files` is the field to read: it counts files holding a recorded CALL
SITE, so it separates a live capability from code somebody left behind. A
comment that merely names a symbol is not a use. `verdict` is derived from
those same numbers and is one of `ALREADY EXISTS` / `PARTIAL` / `NOT FOUND`;
`NOT FOUND` means the recorded names, docs and purposes do not say so — the
`searched` block reports exactly what was looked at. Usage through function
pointers or `dlopen` is not a recorded call site, so the count undercounts
those and never overcounts.

Then use the rest of the in-tree source navigator before broad text search:

```bash
build/bin/z23 code map
build/bin/z23 code sym --input='{"name":"<symbol>"}'
build/bin/z23 code refs --input='{"name":"<symbol>"}'
build/bin/z23 code capsule --input='{"name":"<symbol>"}'
build/bin/z23 code find --input='{"text":"<needle>","limit":20}'
```

`code capsule` combines identity, definition, direct callers/callees, includes,
and command routes within a bounded response. `code file` and `code group`
show a file or directory surface. Ask `discover schema <leaf>` for exact input
keys rather than guessing — and if you guess wrong anyway, the refusal names
the keys the leaf accepts, so a wrong key costs one call, not a source dive.

The first such query in a fresh worktree seeds its code index from the nearest
checkout registered in the same git worktree set instead of rescanning the
tree, rescanning only the files that differ and printing which — `index: seeded
from the main checkout (2 files refreshed, 1676 ms)` — while any donor it
cannot verify against this checkout's own source Merkle falls back to the full
`index: rebuilt` build.

Before creating a reusable helper or importing a library, search the generated
capability census in [`CAPABILITY_INVENTORY.jsonl`](CAPABILITY_INVENTORY.jsonl).
It includes package public headers that the interactive code index does not,
and records exposed symbols, verified direct-use file counts, registered-test
reachability, ranked normalized duplicate bodies, and untested declared header
invariants. Header prose and alpha-shape matches are explicitly `UNPROVEN`;
definition, use, and registered-test call edges are path-bound, and every
macro-generated or platform-ambiguous test root is emitted as a named
`test_root_gap` with the evidence needed to resolve it.
Regenerate the entire report from source with:

```bash
make docs-capability-inventory
```

Commit regenerated docs in the commit whose change caused them (`git commit
--amend`), never as a separate "Regenerate ..." commit. The lander folds any
drift it finds after rebasing into the candidate's tip commit in the same way.

When the navigator cannot answer a prose or non-symbol question, use `git grep`
or `git ls-files`; never recursively scan the repository root. Scratch
datadirs, test debris, and untracked worktrees can contain full duplicate trees.

For editor support, `make compdb` regenerates the gitignored
`compile_commands.json`. The root `.clangd` supplies C23 fallbacks for files
outside the compilation database.

Inspect and operate a running node through typed native commands:

```bash
build/bin/z23 status
build/bin/z23 ops state --subsystem=<name>
build/bin/z23 ops logs --pattern='<regex>'
build/bin/z23 core storage query --sql='SELECT ...'
build/bin/z23 discover help
build/bin/z23 discover search <query>
```

Normal source-development tools—Git, compiler, linker, `make`, and bounded
shell scripts—remain appropriate for repository work. Never Python: no `.py`
files, no `python3` invocations, no Python fallbacks. Flat JSON fields use
grep/sed/awk; nested documents use `build/bin/jsonq`; SQLite files use
`build/bin/sqlq`. Add a native command
only for a recurring operator or agent product need, not for every one-off
development inspection. Command registry extension details live in
[`CODEBASE_MAP.md`](CODEBASE_MAP.md) and
[`NATIVE_COMMAND_INTERFACE.md`](NATIVE_COMMAND_INTERFACE.md).

## 3. Edit within ownership boundaries

The physical source tree is the ownership contract:

- `core/` owns sealed consensus, math, cryptography, primitives, and proofs;
- `engine/` owns composition and generic execution;
- `engine/reducer/` is the sole authoritative chain-state advancement room;
- `contexts/<feature>/` keeps each product's controllers, services, models,
  jobs, views, domains, and reusable modules together;
- `cognition/` owns stories, ontology, predicates, focus, heuristics, evidence,
  and experience machinery;
- `platform/ports/` states outside-world needs and `platform/adapters/`
  implements them;
- reusable modules live under the authority that owns them in `modules/`.

Within an engine, cognition, or product room, `controllers/` parse and
authorize, `services/` orchestrate use cases, `models/` own persisted reads and
writes, `jobs/` run background work, `supervisors/` own liveness,
`conditions/` implement detect/remedy/witness loops, and `views/` render public
surfaces. `make check-architecture-tree` rejects an unknown room, legacy root,
duplicate module owner, module-manifest mismatch, or reducer-owned path outside
`engine/reducer/`.

The consensus core cannot be edited casually. `make lint` rejects drift from
`core/MANIFEST.sha3`; an authorized change uses:

```bash
make core-unseal REASON="<owner-reviewed reason>"
make core-seal
```

Read [`../core/UNSEAL.md`](../core/UNSEAL.md) first. A bounded validity change
requires full-history parity evidence against the real chain, not only a
comparison with reference source text.

Mandatory C rules are detailed in [`DEFENSIVE_CODING.md`](DEFENSIVE_CODING.md):
application writes use the ActiveRecord save lifecycle; allocations are
checked; error returns log context; native command failures set an explanatory
body; and custody-bearing models retain save hooks.

### Canonical naming

Version suffixes name wire/format compatibility ladders only
(`benchmark_result.v2`, `creation_claim.v2`); internal package or source
families carry no version
suffix (`zcode_commons`, never a numbered sibling) — extract shared helpers
instead of spawning a numbered copy. See the naming law in
[`DEFENSIVE_CODING.md`](DEFENSIVE_CODING.md#naming--role-based-not-birth-order).

Recovery changes are copy-proven on isolated datadirs before any owner-gated
production action. A successful boot is not liveness evidence; recovery
acceptance observes H* climb and parity. See [`TENACITY.md`](TENACITY.md).

## 4. Receive fast local feedback

The resident reflex loop is mature factory infrastructure. It classifies a
source edit, emits resumable events, and runs an exact affected proof without
making the developer wait for deeper work.

```bash
z23-dev dev begin
z23-dev dev loop events --after=<cursor> --format=jsonl
z23-dev dev status
```

Humans may use the bounded `dev drive` or `dev loop wait` command returned by
`dev begin`. Event-stream consumers should attach once and continue working.
`IMPACT_READY`, compile events, story events, and heartbeats are projections of
the exact source/action facts, not another development state authority.

A green story binds the candidate/source epoch, affected component,
action/proof inputs, and focused-evidence root before later proof receipts
arrive. A newer relevant edit cancels obsolete bounded process groups; stale
epochs do not publish verdicts. Never edit cache, cycle, failure, or receipt
files to influence a verdict.

`STORY_RED` contains a bounded diagnostic capsule. The current cycle's
`failure_id` is authoritative; inspect it with:

```bash
z23-dev dev diagnose show <failure_id>
```

Use `--view=full` only when the bounded capsule is insufficient. A changed
input, toolchain epoch, flags set, phase, or mutation token forces execution;
only an exact deterministic compiler diagnostic may be coalesced.

Do not expand HOT_FORK, hot-swap, or reflex machinery merely to improve
coverage or benchmark numbers. It changes only when a current public-node or
C23 Commons acceptance requires it. Architecture and measured evidence live in
[`work/REFLEX_REACTOR.md`](work/REFLEX_REACTOR.md) and
[`work/C23_DEV_LOOP_PERFORMANCE.md`](work/C23_DEV_LOOP_PERFORMANCE.md).

## 5. Build and focused proof

The build profiles keep iteration separate from release proof. LTO means
link-time optimization. A translation unit (TU) is a source file compiled
with its included headers; a build epoch identifies one input generation:

| Profile | Purpose |
| --- | --- |
| `DEV_LIVE` | Explicitly allowlisted read-only island |
| `DEV_RESTART` | Incremental isolated development executable |
| `INTEGRATION` | Static non-LTO combined proof |
| `RELEASE` | Clean whole-program LTO and reproducibility path |

`make check-dev-loop-profiles` inspects the enforced profile boundary. Source
records bind exact bytes, toolchain, flags, and mutation state. Never fabricate
or pass `BUILD_SOURCE_RECORD` or `ZCL_FAST_BUILD_SOURCE_RECORD`; the owning
build process captures and verifies them.

Every profile links the real embedded Tor. A build that would link a node
establishes the four `vendor/tor/` archives first — copied, with independent
inodes (a reflink where the filesystem allows), from the checkout your
worktree was created from when that one already has them (milliseconds),
compiled from the pinned submodule otherwise (about two minutes, once per
box). `make tor-ready` is that front door on its own and
`make tor-full` forces the rebuild. Tor-routed dialing and the onion service
are then ON at runtime with no flag; `-no-tor` opts out and is refused on a
canonical, soak or standby operator lane.

`make ZCL_TOR=stub …` is the dev-only escape: it links the offline stub,
prints one loud line, stamps `tor: stub` into `zclassic23 -version`, and
produces a binary that refuses `-tor`, the onion flags and onion-node mode
and that no ship or install step will package. Reach for it only when a box
genuinely cannot build Tor; `check-tor-full-default` is what keeps the
default honest.

`make check-tor-provenance` binds the four `vendor/tor/` archives to the
commit, configure flags, and *compiler* that produced them
(`tools/tor_provenance.c`, `<tor tree>/.provenance`). The compiler is
identified by its bytes alone — the resolved binary's own sha256, its
`--version` first line, and its target triple
(`tools/dev/build-epoch-key.sh compiler-bytes-id`, shared by the writer and
every reader via `zcl_tor_compiler_identity_for_cc` in
`tools/scripts/tor_provenance_lib.sh`) — deliberately not the ambient
environment (CPATH, LD_LIBRARY_PATH, COMPILER_PATH, CCACHE_*/SCCACHE_*, ...)
`build-epoch-key.sh compiler-id` binds for cached-object epochs elsewhere:
those vary between an interactive shell and a systemd unit running the exact
same toolchain, which used to make the gate disagree with itself for no
real reason.

A manifest written before this scheme has a `compiler_id` line with no
`sha256:` prefix. `make check-tor-provenance` on such a box fails with
`compiler_id MISMATCH manifest predates bytes-based compiler identity: run
make tor-full`. **You do not need to rebuild Tor to fix this** — the
archives themselves have not changed, only how the compiler is named. Run,
once, per box/worktree that hits it:

```
build/bin/z23-tor-provenance rewrite-compiler-id vendor/tor \
    "$(. tools/scripts/tor_provenance_lib.sh; \
       zcl_tor_compiler_identity_for_cc "$PWD" "$(zcl_tor_effective_cc "$PWD/vendor/tor" "")")"
```

This refuses (leaves the manifest untouched) unless every recorded
`archive_sha256` still matches the archive bytes on disk — if it refuses,
the archives are suspect and the real fix is `make tor-full`, not a
relabel.

### Fast dev builds

The compiler-speed loop is `make dev` or `ZCL_PROFILE=dev make`. It writes
`build/bin/z23.dev` — a name `make ship` and `make deploy` refuse — into its
own epoch under `build/dev-obj/`. Release objects stay in `build/node-obj/`
with `-flto` unchanged. The hyphenated `build/bin/z23-dev` remains a
watch-loop alias of that unsippable file, installed as a regular hard link —
never a symlink: the dev proof executor opens `z23-dev` with `O_NOFOLLOW`,
which refuses a symlinked proof executable with `ELOOP`.

On this host (32 cores, GCC 14.2, existing `~/.cache/zcc`, `make -j8`):

| Target | Kind | Wall | CPU (user+sys) | Compile | Link | zcc keyed hit rate |
|---|---|---:|---:|---:|---:|---:|
| `z23` (release, LTO) | cold objects | 66.4 s | 582 s | ~40 s | ~20–49 s | 10.2% (216/2123) |
| `z23` | warm, one `.c` touch | 44.6 s | 362 s | cache hit | ~45 s LTO | 2 hits / 2 misses (link miss) |
| `z23` | link only | 48.7 s | 371 s | none | ~49 s LTO | 0% (link is uncached LTO) |
| `dev` (non-LTO, gold) | warm, one real `.c` edit | 30–38 s | ~23 s | 1 TU (~18 s is identity, see below) | ~11 s incl. publish | 1 keyed miss (the edit) |
| `dev` | republish only (alias deleted) | 22.3 s | 21 s | none | none (candidate reused) | 0 |
| `t-fast ONLY=hex_codec` | cold harness, before `-MT` fix | 167.2 s | 980 s | ~164 s | ~3 s | **0.0%** (2/5385) |
| `t-fast ONLY=hex_codec` | warm, one test-file touch | 39.9–42.3 s | 49–51 s | 1 TU + identity | full harness | 12.5% (1/8) |
| `t-fast ONLY=build_profile` | new epoch after `-MT` fix | 77.4 s | 95 s | cache copy | ~3 s + identity | **99.8%** (5372/5383) |

What the numbers say:

- The release one-file edit is an LTO link, not a compile. `-g` vs `-g3` is
  not that link. The 78 MiB `.debug` sidecar is split off the 30 MiB
  stripped `z23`; debug info is not the warm path.
- The test-fast profile is already non-LTO, so its cold 167 s was 3239 TUs
  missing the compile cache. The top miss cause was `-MT` carrying the
  compile-epoch hash: a new epoch (Makefile/toolchain/flag change) invalidated
  every object even though `-ffile-prefix-map` already normalised cwd for
  non-LTO compiles. After the cache rewrites the depfile target, a comment-only
  Makefile epoch is a 99.8% hit. Remaining misses are identity
  (`clientversion.o`),
  the epoch-stamped `test_parallel.o`, links, and toolchain probes. Generated
  headers that rewrite identical bytes are already guarded by
  `templates-no-touch-selftest`.
- `make t-fast ONLY=<group>` still links the full harness (node sources plus
  121 `tools/command/*.c` objects). A per-group link set is not cheap: the
  runner includes the command registry. Module mode (`make t-hotswap`) is the
  existing skip-the-relink path; this lane does not own that loop.
- The dev link is selected by `tools/dev/dev-linker-select.sh`, which
  re-probes `cc -fuse-ld=<name>` with a tiny link on every parse (mold, lld,
  gold order). A cached selection once outlived an uninstalled mold and broke
  every dev link with `collect2: cannot find 'ld'`; the probe cannot go
  stale. On this host only gold is present.
- The remaining dev-loop wall time is not the compiler: a measured real
  one-`.c` edit spends ~18 s in three full-tree source hashes
  (`source-identity.sh capture-record` once at Makefile parse plus
  `verify-record` in the mutation and identity stamps, ~6 s each) before
  the epoch session even opens; compile + non-LTO link + publish is
  ~11 s. Collapsing the triple hash is the next compiler-side win, but it
  is identity-machinery surgery (this lane extends, never bypasses, the
  epoch identity contract) and is left open.

Use `make -s print-CFLAGS` / `print-DEV-CFLAGS` / `print-build-flags` to
inspect the two flag sets. `make t-fast ONLY=build_profile` pins that release
still has `-flto` and that the dev artifact cannot be shipped.

Ask the node for this loop; do not remember it:

```bash
z23 code guide
z23 code impact <file.c>
z23 code tests <file.c>
```

Use the narrowest honest loop:

```bash
make -j"$(nproc)" dev
make -j"$(nproc)" t-fast ONLY=<substring from code tests>
make lint-fast
```

`t-fast` resolves the substring against registered groups and refuses a missing
or unknown selector. `lint-fast` is the inner lint's fast gate subset.
Never run `test_zcl` directly. Do not run full `make lint` on an ordinary
slice.

`make -j28 agent-verify ONLY=<group,group>` is the one verification trip for an
edit. It runs `check-cyclomatic-complexity`, `t-fast-exact` on the named groups,
`docs-capability-inventory` and `lint-fast`, each in its own sub-make with a log
under `build/scratch/`. It does not stop at the first failure: it prints one
`agent-verify: <step> rc=<n>` line per step, then `agent-verify: OK` or
`agent-verify: FAILED (...)`, and writes the same lines to
`build/scratch/agent-verify.rc`. Run it through devbuild as one job, with
`devbuild --wait --class normal make -j28 agent-verify ONLY=<group,group>`. Full
`make lint` and the wide group list remain the landing step's job.
The last line of `build/scratch/agent-verify.rc` is `agent-verify: OK` or
`agent-verify: FAILED (<steps>)`. A file without that last line is an
interrupted run and is not a pass, whatever its `rc=` lines say.

A change under `tools/command/*.c`, `engine/composition/**/*.def`,
`contexts/**/*.def`, or a new `.c` file routinely passes `lint-fast` and then
fails only in the full `make lint`, because the gates that catch that class of
change (capability closure, API-reference drift, the wallclock and POSIX-ERE
ratchets) are not in `lint-fast`'s subset. Run `make lint-preflight` on that
kind of change before submitting — it selects those gates and capability-inventory
freshness from the full lint umbrella.

`lint-fast` also checks generated capability-inventory freshness and package
registry roots, including dependency pins. Both remain full-lint gates.

### Module mode — run a test group without relinking

Changing one file and running one group still recompiles that translation unit
and relinks the whole test harness. The link, not the compile, is the cost: the
harness is one binary over thousands of objects, and it is paid again for every
one-line edit.

For a translation unit on `engine/composition/hotswap_swappable.def`,
module mode skips the relink. It compiles that TU, or its declared island,
into a module `.so`
and loads it into the
already-linked harness through the hot-swap loader, then runs the real group:

```bash
make t-hotswap ONLY=<group> FILE=<path/to/tu.c>
make t-hotswap ONLY=<group> HANDLER=<leaf>      # same thing, addressed by leaf
```

The first run in a checkout needs a harness to load into, so build one once
with `make t-fast ONLY=<group>`; after that every edit to a swappable TU is a
module build only. `make hotswap-test-so FILE=<tu.c>` builds the module without
running anything and prints its path.

This is not a test-only shortcut. The module is loaded by
`hotswap_activate_local()` — the same function the development node runs for
`ZCL_HOTSWAP_PRELOAD`, with the same publish hooks — so a module that would be
refused in production is refused here, and the harness then exits rather than
quietly testing the resident code. Every gate applies: path confinement,
application binary interface (ABI)
version, the swappable allowlist, leaf uniqueness, the module self-test,
probe-before-publish against the leaf's declared output schema, and the
all-or-nothing registry batch that re-checks READY plus read-only per leaf.

Two things keep a module run from being mistaken for a real one:

- the module is compiled with the harness's exact flags and published under the
  harness's compile-epoch directory. A `.so` from any other epoch is refused by
  name, so "same source, same flags" is mechanical rather than a convention;
- the run is never served from the test cache and never stores one, and the
  mode is stamped on the banner, on the `SUITE VERDICT` line
  (`hotswap_module=<sha12> hotswap_source=<tu>`), and on the headline
  (`ALL TESTS PASSED (HOTSWAP MODULE <sha12>)`).

**Module mode is an edit loop, not a gate.** It re-points command leaves in the
registry, so it changes behavior only for what a group dispatches *through the
registry*; a group that calls the TU's functions directly still runs the linked
copy. Before you treat any verdict as proof, re-run `make t-fast ONLY=<group>`
(or `make t`) against the linked binary.

What it cannot cover, and why:

- **Anything not on `engine/composition/hotswap_swappable.def`.** That
  allowlist is
  restricted to controller/view/condition shape leaves; reducers, consensus,
  validation, storage, networking, wallet state and supervisors can never be
  swapped, so groups covering them are always a rebuild.
- **Leaves whose probe needs a running node.** Probe-before-publish dispatches
  the TU's declared probe leaf and requires a schema-valid reply. A leaf that is
  an RPC front door cannot answer inside a hermetic harness, so module mode
  refuses it at `stage=probe`. That refusal is the gate working; the fix is a
  swappable TU whose probe leaf is computable in-process, not a weaker probe.
- **Header and cross-TU changes.** A module is one translation unit. Editing a
  header, or anything that changes another TU, is a rebuild.

Every compile here goes through the in-tree compile cache (`tools/zcc.c`),
which the Makefile builds and wires in front of `$(CC)` by itself — there is
nothing to install and nothing to enable. `make cc-cache-stats` shows whether
you are getting hits; `ZCC_LOG=/tmp/zcc.log make …` says HIT, MISS or BYPASS
for each compile when a rebuild is slower than it should be. See
[`BUILD.md`](./BUILD.md#the-compile-cache-is-in-the-repository) for how a hit
is kept honest and how to clear or audit the cache.

### Measuring whether a group would NOTICE — mutation testing

Green tells you the tests pass. It does not tell you the tests would go red if
the code were wrong, and those are different facts. An audit of one 12,474-line
module found ~80 defects in code that compiled under
`-Wall -Wextra -Werror -pedantic` and whose suite was green — including a
declared validator whose body was `return true;`, a signature check that hashed
bytes nobody had written, and an index that silently held exactly 32 keys.
Nothing was wrong with those tests' assertions. Nothing in the suite ever
inserted a 33rd key.

`mutation-campaign` measures the second fact. It enumerates every realistic
one-token defect in a source file, compiles each one, runs ONLY the group that
covers it, and reports the fraction the group killed.

```bash
make mutation-campaign
build/bin/mutation-campaign --file=contexts/commons/modules/metaverse/src/node_character.c \
                            --group=test_node_character
build/bin/mutation-campaign --file=<any .c> --list   # enumerate only; no build
```

### Reading fleet truth

Run `z23 dev fleet truth` from any checkout to see `origin/main` and every
locally known `origin/agent/*` lane in one result. It reports exact remote
heads,
attached worktrees, each lane's remote/unpublished/dirty file union, and red
lint checks from current `.cache/agent-receipts` evidence. A missing receipt is
`unobserved`; a valid receipt for another HEAD or tree fingerprint is `stale`.
Neither is green. Core-seal and repository-hook failures are marked
`owner_only` so a worker does not waste a cycle attempting an owner ritual.

This command intentionally does not fetch. Run `git fetch origin` first when
you need newer remote-tracking refs. It reads Git metadata and self-sealed lint
receipt/log pairs only; it never opens a node datadir or contacts a live node.
The permanent acceptance is `make dev-fleet-selftest`, which constructs an
isolated origin with three worktrees and no node.

Run `z23 dev fleet start` when the question is not "what is one lane doing"
but "what is the whole fleet doing, and what do I do first". It answers in a
single packet whose size you set with `budget_bytes`: whether this checkout is
behind `origin/main`, the mission document pointers, every linked worktree
sharing this git common dir with its ahead, behind, dirty and modification
time newest first, the running executor units, each fleet host's last posted
offer, the board needs and problems no later claim or result answered,
`origin/main`'s head and this checkout's red lint gates, and the ordered next
actions as `{action, reason, command}`. Every section reports `state`, `count`,
`total` and `truncated`, so a section the budget cut says so and names how many
rows it had; nothing is dropped silently. Pass the `cursor` it returns back as
`since` to get only what changed. Like `truth`, it never fetches and never
reads a node or datadir.

`z23 code tests <file.c>` names the group that covers a file, which is the
`--group=` argument. `--limit=N` takes a sample instead of the whole file, and
`--target=` points the plan at a build other than `test_parallel`. A
`tests/harness/src/` file routes from its own `test_<group>.c`/`spec_<group>.c`
name or its row in the Windows-acceptance sources table rather than a
per-file rule, and a `tools/` file also picks up any harness or lint-gate
file that names it inside a string literal as a secondary `test_groups`
candidate.

**The survivors are the product, not the score.** Each survivor is a specific
line the group's assertions cannot see, printed as `file:line:col` with the
exact change. A score with no survivor list is a number nobody can act on.

Five buckets, and only two of them are the suite's business:

| bucket | meaning | in the score |
|---|---|---|
| `KILLED` | the group went red | yes (numerator) |
| `SURVIVED` | different machine code, group still green | yes (denominator) |
| `STILLBORN` | the mutant did not compile | **no** — `-Werror` caught it, not a test |
| `EQUIVALENT` | byte-identical object file | **no** — provably unkillable |
| `ERROR` | no usable `SUITE VERDICT`, or `groups_ran=0` | **no** — never silently a survivor |

`score = KILLED / (KILLED + SURVIVED)`.

Equivalent mutants are undecidable in general and this does not pretend
otherwise. Byte-identical object code is the cheap SOUND half: what it flags is
certainly equivalent (an ignored array bound in a parameter, an enum constant
that really is `0`). A semantically equivalent mutant whose machine code
differs still lands in `SURVIVED`, where it depresses the score. That is
another reason to read the list rather than the number.

**It never edits your checkout.** The mutant is compiled from a scratch copy
carrying a `#line` directive back to the real path, so `__FILE__` and `__LINE__`
are unchanged and the target file is never opened for writing on any path.
There is no restore step to get wrong: interrupt it at any moment and the file
is byte-identical. The report prints the source's SHA3-256 before and after so
that is checkable rather than promised. `dev.agent.mutate`, which edits in
place, is the single-mutation interactive tool; this is the campaign.

Cost, measured on this tree: about **5–8s per mutant** (one TU compile, one
link of the harness, one group run of ~70ms). `make` is deliberately not in the
loop — it runs once per campaign as `make -n -W <src> <target>` to learn the
exact compile and link argv — because `make`'s no-op dependency scan alone is
13s and a one-file incremental rebuild is 26s.

**This is a reporting tool. It is not on the default test path, not in
`make lint`, and not in the push gate.** A mutation-score threshold imposed
before the tree has measured scores would block everyone. Run it on the file
you are changing.

What mutation testing does NOT catch is in
[`tools/dev/mutation_harness.h`](../tools/dev/mutation_harness.h); read it
before treating any score as a quality claim.

### Measuring what the semantic facts plan saves — z23-sem-replay

`dev.change.plan` can narrow its compile and test-group sets with semantic
facts. `z23-sem-replay` measures that narrowing on real commits. For each
commit it checks out the parent and the commit in a dedicated worktree,
builds the test-fast objects with the real Makefile, reads the depfiles to
see which TUs make recompiled, and runs `dev.change.plan` twice, once plain
and once with the facts. It then counts TU compiles for make, for the objects
whose bytes changed, for the plain plan and for the facts plan, and test
groups for the plain and facts plans. `report` prints a headline, per-commit
rows and totals.

`report` refuses a result table with embedded NUL bytes, extra records,
unequal header and row widths, or more than 128 columns. It checks the header
width in each run against the first accepted header. A complete final row
without LF is accepted. Runs with an absent `result.tsv` are skipped; other
result read failures return exit 1 before report output.

A step exits 3 when an object make rebuilt has changed code and the facts
plan left it out: a code false negative. That object would have been stale if
the plan had been trusted. The step writes the TU to `MISSES.tsv` and stops
the run.

```bash
make sem-replay-bin clang-manifest dev-bin
build/bin/z23-sem-replay run --repo <dedicated worktree> --state build/sem-replay \
    --sensor build/bin/z23-clang-manifest --planner build/bin/z23-dev \
    --commits <file of SHAs, oldest first>
build/bin/z23-sem-replay report --state build/sem-replay
make t-fast ONLY=sem_replay        # the tool's own self-test
```

`run` replays one step per commit and resumes after the last finished one.
`--devbuild <path>` runs each step through that host scheduler command, and
`--jobs N` (at most 8) bounds each build. The worktree named by `--repo` is
checked out and rebuilt, so it must hold no other work.

**This is a reporting tool. No replay runs in `make ff`, `t-fast`,
`t-fast-exact`, the land path or the proof path, and nothing there reads its
output or depends on its exit code.** The test build only compiles the binary,
so that the `sem_replay` group, an ordinary test group, can run it. That
group proves the tool on a throwaway three-commit git repository with
stand-in sensor and planner programs. It checks that a facts reply that
leaves out the changed TU exits 3 and names the TU in `MISSES.tsv`, and that
a correct narrowing produces the exact hand-computed counts. The method and
its limits are in
[the replay method](./work/SEMANTIC_MANIFEST.md#replay-on-real-history).

### Proving a permissionless cold join

One claim gets asserted often enough in prose that it earned a single command:
that someone with no account, no domain name and no certificate authority can
install this node and have it start validating.

```bash
make prove-cold-join
```

It runs one test group, hermetically — no peer is dialled, no name is resolved,
no parameter file is read, and the datadir it starts from is wiped — so it
answers the same on an airgapped box as on a connected one. Read its two result
lines: `COLD_JOIN_VERDICT=JOINED` (every proposition asserted there holds),
`SLOW` (they all hold and this machine is slow), or `BROKEN` (a proposition is
false — the only red). Elapsed time never decides the exit status.

Read the `UNPROVEN` lines too. They are neither passes nor failures, and they
are the reason the target prints propositions instead of a checkmark: the
narrow, true form of each claim is asserted, and where the flattering form does
not hold the transcript says so instead of asserting it away. The propositions,
and which are narrower than the story, are enumerated at the top of
[the cold-join fixture](../tests/harness/src/test_cold_join_sovereign.c).

For an exact push checkpoint, commit first. The notification hook makes a
best-effort detached request to the checkout's development service and returns;
it does not wait for or confirm durable enqueue. Inspect or wait for the
commit/base receipt with:

```bash
build/bin/z23-dev dev proof status
build/bin/z23-dev dev proof wait
```

For a fresh worktree or a one-off agent session, use the foreground step —
the same bounded worker and signed
receipt lifecycle, run synchronously for one exact pair:

```bash
devbuild --wait build/bin/z23-dev dev proof step --local_commit=$(git rev-parse HEAD) \
    --remote_base=$(git rev-parse origin/main)
```

It takes several minutes (the full lint gate set plus the impacted test
groups inside one generation worktree); a push before its `passed` receipt
exists is refused by the pre-push hook. Two operational rules, both learned
from real failures: do not run other `make` builds in the same checkout
while a proof is in flight (a superseded source build invalidates the
attempt), and if the attempt fails on `check-git-hooks-installed` after a
hook rebuild, refresh the armed copy with `make install-hooks` in the lane
itself — it writes that worktree's own config scope only — then `dev proof
retry` and `dev proof step` again.

`dev.proof.ensure` is an explicit operator path that can arm a resident proof
watcher. A persistent `<root>/.cache/zcl-dev-watch.lock` file alone does not
establish a live owner or operator intent. The installed notification hook
requests `require_existing_watcher=true`: the controller verifies the existing
kernel lock, session and root before enqueueing work. With no qualified owner,
it refuses with `PROOF_EXISTING_WATCHER_REQUIRED` and leaves watcher state
unchanged; use the foreground step above. The hook does not activate a watcher.
Preserve live owners and use native status and stop commands for lifecycle work.
CAS means content-addressed store: objects are identified by their bytes.
The proof binds the local commit and advertised
remote base to exact source/CAS and mutation roots, changed-set and impact
policy, compiler/flags/environment/build graph, and complete generated,
compile, lint, and test accounting. A missing, stale, incomplete, skipped, or
tampered dimension cannot be admitted. `make pre-push-ci` remains an explicit
legacy parity oracle; it is not called by the installed push hook.

`make lint-ready` prepares a lane worktree for lint in one step. It runs
`make install-hooks` only when `check-git-hooks-installed` would fail, runs
the lander's regeneration targets (`docs-capability-inventory`,
`docs-api-reference`, `fix-doc-counts`, `docs-executor-routing`), and prints
`git status --short`. It exits non-zero while untracked non-ignored files
exist, because lint scans tracked files only: `git add -A`, run
`make lint-ready`, amend what it changed, then run `make lint`. It never commits.

Every publishable proof runs the whole lint gate set, `make lint` plus
`check-windows-acceptance`, including inventory-only changes. A scratch
directory's location or `queue.lock` cannot narrow publication evidence.
Policy 5 additionally requires the producer's compiler-injected complete source
identity to match the sealed candidate before planning, selection, or reuse.
It rejects older receipts as `receipt_schema_old`; missing mandatory lint
remains `receipt_lint_required`. The worker
clears inherited Make execution overrides and lint cache diagnostics, and
forces fresh lint using each gate's declared policy before building a
generation.
The test dimension is cold the same way: the runner starts with `--no-cache`,
the worker clears `ZCL_TEST_CACHE`, `ZCL_TEST_CACHE_DUMP` and
`ZCL_TESTCACHE_STORE_ROOT`, the checkout's `.zvcs/objects` verdict store is
never copied into the generation, and a log reporting any `groups_cached` is
refused, so the receipt's test dimension always records `reused=0`. Those PASS
records are unsigned and writable by the uid the candidate runs as; reuse
comes back only when a separate-uid verifier qualifies. `phases.txt` records
`test_reuse_admit=test-reuse: unqualified(no_verifier_account)` and an
`advisory` `test_preflight` probe count that admits nothing
([`work/test-result-cache.md`](work/test-result-cache.md)).
Automatic proof-worker per-group collection is deferred until every mandatory
input closure qualifies. The default exact cold whole-cycle proof and its signed
pair receipt remain the admission gate. Explicit runner diagnostics use
`--cold-audit --emit-observations` for strict complete-set emission, or
`--cold-audit --collect-observations` for narrowly partial collection. Only
already reviewed external-input denylisted groups report `UNQUALIFIED` with
missing coverage; other closure, execution, signing, serialization, CAS or
admission errors remain fatal. `OBSERVATION COVERAGE` reports eligible, emitted,
unqualified, refused and complete counts. Authenticated partial leaves do not
replace complete admission. Explicit callers keep unsigned verdict scratch
separate from durable signed observation CAS; fixture regressions cover cleanup,
retained bytes and interrupted retries. The output-store path is a control,
not part of the test input key.
The vendor builder retains `vendor/.build.lock` as a regular-file kernel lock
across runs; its inherited lock descriptor coordinates builders until process
exit. Preserve this inode. The root-anchored tracked ignore treats this
generated control as output, while unrelated untracked source still refuses
proof admission.

`make lint-fast` remains available for feedback while editing. The generation
is handed the built artifacts the
full gate set reads (the confined package verifier, `build/bin/z23-dev`,
and the `build/bin/zclassic23` alias) through the same content-checked
admission the test dimension uses, so it judges the same artifacts the
submitting checkout's own `make lint` judges. The measured lint wall time
lands in the receipt's phases file as `lint_wall_ms`, beside the
`lint_targets` line naming what ran.

The lint runtime itself (`build/bin/z23-lint`) is syntax-checked with clang
on every build when clang is on PATH, so Apple Clang's stricter diagnostics
(e.g. `-Wunused-but-set-variable`) are caught on Linux instead of only
surfacing on a macOS build; when clang is absent the build says the check
was unobserved rather than staying silent.

Both dimensions run inside one generation worktree, so everything either of
them builds or is handed happens once, before they start: the admitted
executables, the test runner, the depfile tree, then a single `make` that
builds the helper executables and -- for a landing -- `proof-lint-prebuild`,
which names the lint umbrella's own built prerequisites and links every
standalone tool the `check-standalone-tools-link` gate covers. After that
step the lint dimension's make has nothing left to link and the test
dimension runs no `make` at all, so neither can relink a binary the other is
reading. It has a `step=prefork` line of its own in the phases file, with
its budget and exit, and its log is `logs/prefork.log` in the attempt
directory. Without it a landing proof's lint-gate shard could exec a
build/bin/z23-lint that the lint dimension was relinking, and fail with
"No such file or directory".

The impact plan behind that policy can hit a capacity bound: a change whose
reverse-caller closure or reverse-include set reaches more test groups than the
plan can enumerate. That is not missing evidence, so it is not a refusal — the
plan reports `"closure_universal":true`, the bounded dimension is `complete`
with reason `closure-universal`, and the proof runs the entire test group
catalog instead of a group list. A changed set whose own paths name more groups
than the plan holds (a sweep over hundreds of test files) is the same capacity
fact: the plan reports `"path_universal":true`, the `opaque` dimension is
`complete` with reason `path-group-cap`, and the proof's
`test-selection.log` says `reason=path-group-cap`. Only a dimension the index
could not answer at all — no code index, no include graph, a query error —
stays `unavailable` and still makes `proof_admissible` false.

A universal selection subtracts exactly one thing: a group whose declared
**host need** the proof generation cannot meet. The needs are data, declared
once in `tools/dev/test_group_host_needs.def` — a `ZCL_HOST_NEED_FILE` row
names a path that must exist in the tree the runner execs in, a
`ZCL_HOST_NEED_ENV` row names an environment variable that must be set — and
`tools/dev/test_group_host_need.c` resolves them against that generation, never
against your own checkout. A need row naming an unregistered group, an unknown
need kind, or an empty value is a refusal, not a skipped row. This exists
because a proof generation deliberately builds no node runtime binaries and
carries no operator fixture, so `test_onion_pair_watch_live` can only report
`UNOBSERVED` (`PAIR_PROBE=ENV_MISSING_BINARY`) and
`test_self_folded_anchor_heavy`
can only `SKIP` there — verdicts the suite accounting refuses, which used to
fail every universal-closure proof with `test_accounting_incomplete` even when
zero groups failed. An omitted group is counted by the runner as gated and is
named in the attempt's `logs/*.test-selection.log`, which now carries a second
line, `host_gated=<group>:<kind>:<value>,…` (or `host_gated=-`), so nothing is
dropped quietly. Nothing else changes: the groups still run everywhere their
input exists — a dev box with `build/bin/z23`, an operator who exported
`ZCL_SELF_FOLD_ANCHOR_FIXTURE` — an exact impact plan that names one still
selects it, and a `SKIP` or `UNOBSERVED` from a selected group still refuses
the proof.

A `ZCL_TEST_GROUP_BUILD_NEED(group, path, target)` row declares the other
shape: an optional tool no default target builds, which the proof builds
itself. The live semantic-sensor groups (`test_semantic_sensor`,
`test_semantic_facts_live`, `test_semantic_consumer_live`) exec
`build/bin/z23-clang-manifest`, so a proof whose selection carries any of them
runs `make clang-manifest` in its generation (after removing any copy a warm
generation seeded), from the candidate's own
sources, before the fork (step `test-needs`, log `test-needs.log`), and folds
the built bytes into the test receipt's helper digest. A build that fails, or
exits 0 without producing the path, fails the proof as
`test_need_unbuildable_clang-manifest`; the group never self-skips. A BUILD
need never gates a group out of a universal selection, and a proof that
selects no such group runs no extra step.

On Linux x86_64, `make clang-manifest` recognizes root-controlled
`/usr/include/clang-c`, `/usr/lib/libclang.so.22.1`, and
`/usr/lib/clang/22/include` when no LLVM prefix or Debian libclang 18 was
selected. The sensor supplies that resource directory to libclang's parse
unless the caller supplied a resource directory. Its manifest names and hashes
the headers actually read. The proof worker checks the system paths and binds
the selected libclang and libLLVM bytes into the helper digest; an unknown or
writable runtime path refuses before proof execution.

Windows installs the same receipt policy as native PE hooks in an
immutable content-addressed generation. Admission launches no console window;
its bounded Git children use the parent Git-for-Windows image and a
kill-on-close Job Object. Updating `core.hooksPath` publishes a new generation
without replacing a possibly locked executable.

Current limitation: proof requests, running markers, leases, failures, and
receipts remain under each checkout's `.cache/zcl-dev-proof`. The resident
watcher still forks one worker per claimed commit/base pair, and that worker
initially checks the mutable submitting checkout before using its private proof
generation. The separate `tools/land` chainlog batches the legacy
`make pre-push-ci` path and stops at a local `land/ready` ref; it neither
produces the native exact receipt nor publishes `main`. These are duplicate
transitional lifecycle formats and neither is product evidence authority. Do
not translate between them or claim that either is the unfinished signed-commit
promoter.

Full `make lint` is the umbrella (every gate, including whole-node tool links).
A landing proof runs it for you inside its own generation, so main cannot go
red on a gate the fast subset excludes. Run it by hand when an impact rule
names such a gate, or at a sub-wave / release boundary. An uncached full
suite is:

```bash
make -j"$(getconf _NPROCESSORS_ONLN)" test-parallel TEST_PARALLEL_ARGS=--no-cache
```

An uncached suite is distinguished by its `SUITE VERDICT mode=cold` record and
nonzero executed-group count. Do not accept a cached summary as an uncached
proof. `tools/scripts/gate-and-report.sh <lintlog> <testlog>` verifies the
canonical verdict tokens when a mission requires the combined report.

The product front door is one command, and it is how you check that the whole
Commons journey still holds end to end — a person asks for behavior, the node
reuses C23 from a peer, creates only what is missing, a second node reproduces
the exact bytes, tampering is refused by name, the person accepts, and the
accepted application runs. The last step runs the same journey again against a
package that already existed and was written by somebody else, and measures the
behavior it was asked to change before and after:

```bash
make commons-demo        # three isolated datadirs; A is killed; C still fetches from B
make readme-svg-check    # the README figures still match what this binary prints
```

`commons-demo` is deliberately outside `make ci`: it spawns three real
regtest daemons, mines a regtest chain and runs confined package builds. The
README's
demo, proof and topology figures are rendered from a recording that same run
writes — `ZCL_COMMONS_DEMO_RECORD=1 make commons-demo` refreshes
`docs/assets/z23-commons-demo.{strip,facts}`, and `make readme-svg` redraws the
SVGs from it. Never hand-edit either file: the gate exists so a figure cannot
outlive the journey it describes.

Focused and deep proof receipts describe only their bound observations. A
passing compiler/test/reproduction receipt does not grant runtime publication
or establish general code safety.

## 6. Integrate and push a coherent slice

### Landing a stack of commits

Build a filtered stack from reviewed, locally available commits with
`devbuild --wait bash tools/scripts/stack_build.sh BASE COMMIT...`. It refuses
dirty source or an existing Git operation, detaches at `BASE`, and makes
signed picks in the supplied order. Conflicting, empty and merge picks are
skipped; a pick failing the base-built canonical complexity checker is also
skipped. Existing branch refs are not moved or published history rewritten.
The assembled tip must pass complexity even when every input is skipped.
The checker measures each candidate's C source and ratchet baseline. Changes
to checker implementation itself still require the assembled tip's full lint.
Both stack tools refuse inherited `GIT_*` variables before Git or generator
effects, except the output-only `GIT_PAGER` and `GIT_TERMINAL_PROMPT` settings.
They require Git's worktree root to match the script's physical root.
Run them from an ordinary shell without ambient Git routing or configuration.

For example, reconstruct the existing stack-refresh corrections in order:

```bash
devbuild --wait bash tools/scripts/stack_build.sh \
  7a4bc550504fc7a6dfb240fdf07b35373554bbcd \
  bc540938a5b6aa75bf2c49eaf162a2de6ff5813d \
  a515f51ce61df51ff8492add11e8ff9442330e72
```

Standard output has one `PICKED NEW_HASH input=INPUT_HASH` or
`SKIPPED REASON input=INPUT_HASH` line per input, then `TIP HASH` after refresh
succeeds. Diagnostics and retained receipt locations go to standard error.
Other Git, signing or checker failures stop without a success tip; signing
failure preserves the staged pick and never falls back to an unsigned commit.
The tool calls the refresh below once. Review its remaining generated changes
and commit them normally; its content display is not a staging allowlist.
This command prepares the stack, rather than replacing full landing gates.
Run `devbuild --wait bash tools/scripts/stack_build.sh --selftest` for isolated
real-Git fixtures using the existing `build/bin/z23-lint` checker. If missing,
build that checker with the normal scheduler first. A base checker build that
changes tracked source stops for inspection before any picks.

Authors leave generated package roots, dependency pins, registry projections,
and `docs/CAPABILITY_INVENTORY.jsonl` out of their commits. The integrator runs
`devbuild --wait bash tools/scripts/stack_tip_refresh.sh` once at the
assembled stack tip.
It rederives the registry and dependent pins, then runs the canonical
documented-count gate. If its only failures are numeric count mismatches,
it updates only those values in `docs/CODEBASE_MAP.md` and makes a signed
document-only commit naming each count and its old and measured values.
Other count failures stop with the gate output; a failed correction or
signature stops before inventory. It then regenerates the capability
inventory and checks counts again. It prints content changes and fails if
any step fails. Review and commit the remaining generated changes at the tip.
Source-owned count updates still belong to the author commit; the correction
handles residual assembled-stack drift. Check mode never repairs or commits
counts.

Both modes refuse a dirty checkout before invoking generators, including
ignored untracked package manifests discovered by the registry.
Run `devbuild --wait bash tools/scripts/stack_tip_refresh.sh --check` to compare
registry, inventory, and documented-count freshness. Stale evidence fails.
Helper builds may regenerate tracked view headers before checking; inspect
`git status` and `git diff` afterwards, including after a refusal. Check mode
does not report these prerequisite changes. The refresh display compares
content only; it is not a staging allowlist or a report of mode/link changes.
The script also provides a self-test:

```bash
devbuild --wait bash tools/scripts/stack_tip_refresh.sh --selftest
```

Before committing:

1. Review `git status`, `git diff`, and `git diff --check`.
2. Confirm every changed file is owned by the slice.
3. Run focused acceptance and required generated-document checks.
4. Fetch current `origin/main` and integrate without discarding upstream or
   unrelated local work.
5. Rerun the minimum gates affected by that integration.
6. Commit one coherent change with an evidence-backed message.
   Build the candidate-owned `z23-dev` producer after the final signed commit
   under `devbuild --wait`. A tool built before committing can identify a
   different working state; its build pass is not exact proof qualification.
7. On Linux and macOS, require `dev proof status` to report `passed` for the
   exact commit/base under current policy before publication. The native
   pre-push hook reads only the exact sealed receipt.
   Windows installs the same receipt-only native admission hook. Its native
   proof producer is not implemented yet, so a missing receipt refuses
   immediately; run the explicit `make windows-acceptance` parity gate while
   developing, but do not mistake that gate for an admissible receipt.
8. For shared worker publication, submit the exact candidate through native
   `dev land` tools under `devbuild --wait`. Their receipt gate and persisted
   outcome support replacement workers; no permanent lead approval is needed.
   Do not create a GitHub Issue or pull request for coordination.
9. Verify local HEAD, `origin/main`, and the remote branch SHA agree.

A resident loop lands the same way through the native async queue
(`z23-dev dev land submit|status|step|drive|cancel`,
`tools/command/native_dev_land.c`):
one driver steps that queue at a time, since `step` holds a per-queue lock for
its whole run and a second driver that finds it held gets `STEP_BUSY`
(retryable) and steps again shortly rather than racing the first driver's
rebase and lint against the shared landing worktree.

The queue codec reserves a strict, exact predecessor tuple and an internal
classifier distinguishes pending anchors from divergence. Submit and scheduler
waiting are not enabled yet; independent rows retain their existing lifecycle.

Before it starts an exact proof, a landing step runs `make lint-land` in the
landing worktree: `LINT_FAST_GATES` plus `LINT_LAND_EXTRA_GATES`, the cheap
(p50 at or under ~2.5 s) gates that historically failed only in the proof's
full lint. A doomed candidate therefore fails in seconds instead of after a
~7-minute proof. `lint-fast` itself is unchanged for the edit loop.

When a landing step queues an exact proof in an unarmed checkout, `dev land
status` exposes `in_flight.proof_step` with the exact `root`, `local_commit`
and `remote_base` inputs for `dev proof step`. Its short row detail names the
pair and points to that structured action, so even a long worktree path does
not truncate the handoff. Any worker with access to that checkout can run
the foreground step through `devbuild --wait`; the next landing step consumes
its signed receipt. Landing does not start a resident proof watcher by
default. An operator who explicitly wants the prior watcher path can set
`ZCL_LAND_START_PROOF_WATCHER=1` for that landing step.

`dev land` refuses a malformed or legacy queue record by record number on
status, submit and step. It preserves the queue bytes until an operator
repairs that record; a later valid row cannot make an earlier one disappear
through a rewrite. Status likewise names a malformed terminal outcome.

`dev land drive` runs a bounded foreground integrator session. It persists the
candidate commit, current base, prepared tree and exact proof intent before
proof execution, then tries publication immediately after a PASS. Proof holds
a shared step guard while using the landing worktree, so another step cannot
prepare that worktree until the proof settles; status remains available. A
changed main is reconciled on the next step. Another authorized driver can
resume the persisted pair after a worker stops. A changed `origin/main` creates
a successor from the original submitted tip. It retains the submission time
and claim priority across successor sequence changes. Each drive call is
bounded if main keeps moving. The prior receipt remains evidence only for its
original commit and base; the new pair requires its own full proof. A failed
exact pair is logged before a successor is prepared. A bounded drive session
can stop with the row still queued; rerun `dev land drive` to continue it.
A competing integrator receives `STEP_BUSY` during the short
publication slot and must inspect status before another attempt.

Use ordinary scheduler admission unless the job actually needs more than
24 GiB. Do not wrap a polling driver in an exclusive reservation or add a
nested CPU/memory scope that strands capacity. Preserve an already-running
driver and inspect its persisted state before replacement. An unknown push
outcome requires reconciliation: do not dispatch a different pair or push by
hand. The landing step reconciles it itself. When a fresh fetch shows main
still at the signed base, the head is absent and the earlier dispatch did not
apply, so the step sends the identical compare-and-swap again, once per
remaining attempt; when main has moved without the head it cuts a successor.

The proof producer must be built from the exact sealed candidate source before
selection, reuse, or dimensions run. `proof_producer_source_mismatch` refuses
before those stages. `dev land drive` recovers from it without help: it queues
the pair again, builds `dev-bin` in the landing worktree, and proves the pair
with that binary as a child. `dev land step` runs the same recovery, whether
the refusal reads as a failed or a no-verdict proof, once per row until main
moves (the mark is its own row field, independent of the `host_load` retry):
a second refusal, or a failed rebuild, settles the row failed with
`proof_producer_source_mismatch` instead of leaving it pending. Outside a
landing, use the candidate-owned producer
and its structured foreground recovery action. A proof step started outside a
user-manager scope that delegates the memory controller refuses at once with
`proof_host_memory_scope_unqualified`; run it through the build scheduler.
Policy 5 rejects old proof receipts. Preserve an
older receipt as evidence for its original policy instead of silently replacing
it or claiming that publication alone establishes current qualification.

Queued exact proofs take the same lock shared before claiming a request
and hold it until verification finishes. Requests created by checkout hooks
therefore remain queued while the landing step prepares the tree. A busy
preparation lock leaves the request bytes intact and creates no failed proof
observation. Before requesting proof, the landing step reruns the native
restart-plan target after lint and dependency preparation, so an existing
plan cannot retain an earlier source generation.

Proof worker crash semantics are qualified by acceptance, not assumed. All
pair state lives under `.cache/zcl-dev-proof/`: a request is claimed under
`queue.lock` into a per-attempt directory (`attempts/<pair>.XXXXXX`), a
lease (`leases/<pair>.lease`, carrying the attempt token, worker pid and
start time) gates every pair-state write, one `execution.lock` flock gives a
single worker execution authority, and a shared hold on the landing
`step.lock` defers landing preparation for the worker's whole lifetime.
Requester cancellation settles the bounded worker; requester hard death
leaves the guards owned by the surviving worker. Hard death of the
guard-owning worker itself is covered by the `impact_composition` acceptance
"proof step: worker SIGKILL frees guards, preserves evidence, admits no
completion", which kills the exact lease-named worker mid-execution and then
proves: the kernel releases both guards; no receipt and no `.failed` marker
appear, so no false PASS and no stale completion; the pair reads MISSING
with its consumed request bytes preserved inside the dead attempt; `dev
proof retry` refuses (`proof_retry_requires_settled_failure`) until a
failure settles; an unrelated queued request survives untouched; a held
execution guard still defers another consumer with `proof_execution_busy`;
and `dev proof ensure` requeues the pair so any eligible worker drains it
and the unrelated request to a settled failure under the same lease rules,
after which explicit retry is admitted again. Containment of descendants a
killed worker may have escaped remains a separate, unclaimed boundary.

Each attempt the queue steps proves against its own proof generation, a
private copy of the tree rooted at `<ram_root>/z23p/<tag>` when RAM scratch is
reserved or `<dirname(landing_worktree)>/.z23p/<tag>` on disk otherwise
(`tools/dev/dev_proof.c`). A generation is disposable: the leaf removes it
once its attempt lands, fails, or is superseded, keeping only generations
that are still in flight, and it also sweeps any generation left over from a
prior run at the next submit or step so a resident leaf never accumulates
finished generations across restarts. What a generation keeps past its own
lifetime is warm-start's own donor set of immutable build outputs, reaped
under the same existing newest-donor policy, not proof state. Whatever
outlives a killed leaf is the hourly host sweep's job: the `z23p` category of
`tools/scripts/host_gc.sh` reaps dead generations from the disk pool and from
the tmpfs twin alike.

Vendored dependencies a generation needs are materialized into it as private
copies, never as hard links to the submitting checkout, so no generation can
observe or corrupt another attempt's tree through a shared inode. Before an
attempt proceeds, `dl_wt_proof_deps_ensure` in `tools/command/native_dev_land.c`
scans the landing worktree for any dependency file whose link count exceeds
one and demands a full accounting of every extra name: a name that resolves
inside the leaf's own generation roots (either `z23p` parent) is a leftover
from an earlier generation's donor linking, not an external hazard, so the
leaf repairs it in place — materializing a private copy over that name and
verifying it now has a link count of exactly one before continuing. Any
extra name that does not resolve inside those roots is left alone and the
attempt refuses by the exact unexplained path
(`proof_generation_dependency_unexplained_links:<relative>`) rather than
guessing at its origin.

Every changed C path must map to focused proof through the repository's impact
rules. Unmapped or incomplete closure refuses receipt publication. A proof
covers a whole landing batch, so its changed set is heap-resident and holds
thousands of paths; a set past that ceiling, or a capture that could not be
read whole, refuses with a typed reason naming the observed count rather than
planning against a silently shortened list. On POSIX,
the native receipt hook never builds, tests, lints, waits, invokes a shell, or
fetches; a missing or
running receipt refuses within the bounded read path and prints the exact
`z23-dev dev proof wait` command for that commit/base pair. A normal
non-fast-forward race also refuses without deleting reusable child evidence.

A receipt is keyed by the toolchain that produced it, not by where the
checkout happened to sit. Its compiler root is the toolchain capsule — the
content of the compiler driver and backend, the assembler version, the
sysroot and ABI aggregates, and the target probe — the same value
`z23-dev zcode work toolchain` prints. Its flag and build-graph roots come
from the build plan with the checkout's absolute location written out of it,
using the constant the build already tells the compiler to record in its
place, and with the epoch name of the object directories reduced to a token,
because that name is derived from a compiler fingerprint that spells the
checkout out loud. Its environment root binds the variables that reach the
compiler without passing through a flag, and no longer binds the search path,
which resolves nothing this build compiles with. Two boxes with the same
capsule over the same tree therefore produce the same four roots and can
compare receipts; the same tree in two worktrees on one box does too. What a
receipt is keyed by is versioned apart from its layout, so a receipt written
under the previous meaning is refused by name (`receipt_schema_old`) rather
than compared against roots derived a different way — re-prove it.

A receipt is signed, not merely sealed. Each box keeps one Ed25519 keypair
under its owner-private development state root, created on first use by
whichever proof seals the first receipt and never by a verifier; the receipt
carries that public key and a signature over its whole sealed body, and
sealing fails by name rather than fall back to an unsigned record. Admission
verifies the signature and then asks whether it trusts the signer: this box's
own key is always trusted, and any other box's key is trusted only when its 64
hex characters appear on their own line in `signers.allow` beside the key
(`#` comments and blank lines are fine, malformed lines are counted and
skipped). To let another operator admit receipts proved here, run
`z23-dev dev proof signer`, which prints this box's public key, both paths and
the current trust counts, and paste the printed key into their `signers.allow`.
The refusals are named: `receipt_unsigned` (a record from before receipts were
signed — re-prove), `signature_invalid` (the record was edited after signing),
`signer_unknown` (a real signature from a box this one does not trust), and
`signer_key_unreadable` (this box has a key file that is not a private 32-byte
seed).

The source-identity capture that seals a proof's evidence
(`zcl_dev_source_cas_capture` / `zcl_dev_source_identity_capture` in
`tools/dev/dev_source_identity.c`) runs
under real host load and can legitimately take longer than one fixed budget.
Its evidence tokens name the exact failure rather than folding every case into
one undifferentiated string: `source_identity_timeout` (the capture exceeded
its budget), `source_identity_signal_<n>` (the capture child was killed by
signal `n`), `source_identity_runner_setup_failed` (the runner itself —
`zcl_devloop_process_run`'s forked child — failed before exec: `setsid`, the
ready-pipe write, `chdir`, or `dup2`; exit code
`ZCL_DEVLOOP_PROCESS_EXIT_SETUP_FAILED`, 126), `source_identity_exit_<n>`
(the capture tool itself exited nonzero for any other code — 127 stays "exec
failed"), `source_identity_output_truncated` (the captured record was cut
short), and `source_identity_output_invalid` (the tool completed and produced
output, but that output did not parse as a source record). Only the first
four are retried automatically: `zcl_dev_source_identity_capture` re-attempts
the capture up to three times with a growing timeout (30s / 90s / 180s)
before giving up, since those are the failure shapes host load can plausibly
cause — including the runner failing to even get the child started. A
nonzero exit from the capture tool or an unparsable record is a deterministic
tool or content defect a retry cannot fix, so those fail immediately with
their specific token. This retry lives inside the capture itself, so both the
pre-test identity seal and the mid-proof checkpoint capture benefit from it
without ever re-running the tests those captures gate.

Canonical deployment remains owner-gated. Development generation activation is
an explicit plan/commit transaction with source, resident-CAS, process, probe,
and rollback verification. A source identity or environment variable alone
grants no activation authority. See [`RUNBOOK.md`](RUNBOOK.md) and the current
command schema before any authorized deployment work.

## 7. Continue while deep proof runs

After a push, fetch current upstream and continue to the next unfinished item.
Deep decentralized proof consumes immutable candidate/action objects and emits
signed receipts later. The originating developer does not wait on peer work,
and no peer becomes a central scheduler or permanent coordinator.

The canonical ontology is one chain: task and candidate; candidate source root
and source-manifest identity; action input, action root, and work context;
REQUESTED build-proof event and durable action lease; work receipt and
proof-set root; PROVEN lane receipt and accepted-work root; then a versioned
publication job and its immutable outcome receipt. A Git commit is provenance
and user intent, never a source root, action root, or proof identity.

Reuse those existing CAS, package, task, candidate, action, lease, worker,
receipt, lane, and publication objects. Lifecycle labels such as requested,
running, ready-for-acceptance, or published are derived projections, never a
second source of truth. `zcl.dev_acceptance_receipt.v1` may remain a
fixed-width hook admission envelope, but it must derive from canonical proof
facts rather than become another proof ledger.

## Mission capsules

Use compact mission capsules for handoff and management:

```text
NORTH STAR
USER OUTCOME
CURRENT BASELINE
OWNED SURFACE
INVARIANTS
ACCEPTANCE
CONTINUATION QUEUE
ESCALATE ONLY IF
```

The capsule says what changes now; [`../AGENTS.md`](../AGENTS.md) supplies the
durable repository contract. Do not paste a vendor-specific fleet doctrine or
another full copy of the project rules into each prompt.

Escalation is appropriate for consensus or custody risk, destructive
production action, irreconcilable authority ambiguity, a missing human product
decision, an assertion that would need weakening, or genuine completion of the
mission. Otherwise continue through the ordered queue.

## Measuring the MVP experiment

MVP means minimum viable product. The 144-loop plan of record is also an
experiment: what does it cost, in wall
time and tokens, to take z23 from that plan to MVP? `build/bin/z23-mvp-ledger`
(sources `tools/dev/mvp_ledger*.c`, test group `mvp_ledger`) answers it from
evidence rather than from memory. It is built by `make dev-bin`.

```text
z23-mvp-ledger agents   --session <dir> --out <dir> [--lanes <dir>]
z23-mvp-ledger loops    --plan <file>  --out <dir> [--trains <dir>] [--ancestry <file>] [--groups <file>]
z23-mvp-ledger snapshot --plan <file>  --out <dir> [--origin-main <sha>] [--note <text>]
z23-mvp-ledger kpi      --plan <file>  --out <dir> --since <t0> [--session <dir>]... [--ancestry <file>] [--groups <file>] [--scratch <dir>]
z23-mvp-ledger xp       --plan <file>  --out <dir> [--session <dir>]... [--ancestry <file>] [--groups <file>] [--outcomes <file>] [--json]
z23-mvp-ledger progress --plan <file> [--session <dir>] [--ancestry <file>] [--groups <file>]
```

The two git inputs are files you produce, both from the SAME ref:

```sh
git rev-list origin/main > ancestry.txt
git show origin/main:tools/dev/test_group_catalog.def > catalog.def
```

- `agents` reads every `<session>/subagents/agent-*.jsonl`, every
  `<session>/subagents/workflows/*/agent-*.jsonl`, and the orchestrator's own
  `<session>.jsonl`, and writes `agents.tsv`: one row per agent with its lane,
  kind, model, wall, turns, tool uses, and the output / thinking / input /
  cache-creation / cache-read tokens it spent. An agent's lane comes from its
  description by seven rules (`Lane <name>`, `Resume <name> lane`,
  `Re-verify <name>`, `Verify <name>`, `Assemble train <n>`, and
  `Fix …`/`Resurrect …` which take the first word that names a lane that
  exists under `--lanes` or `--scratch`). Anything else is kind `other` with
  lane `-`: still summed into every total, simply not attributed to a loop.
- `loops` joins those agents to the plan's loops by lane name and writes
  `loops.tsv`. A train assembler is split evenly across the loops whose lane
  is on that train; `--trains` names the directory that holds one
  subdirectory per train, each with a late-pick list naming the lanes that
  train carries. A design workflow is split across the loops whose
  `evidence=` names it.
- `snapshot` and `kpi` each append one row to `snapshots.tsv` / `kpi.tsv`.
  The KPI is verified MVP progress per token: base loops verified after t0,
  over the ledger's weighted token count (TCU) for the whole system.
- `xp` scores that same KPI as a game and prints the leaderboard, writing
  `xp.tsv` and `xp_events.tsv` beside `kpi.tsv`; `--json` prints the same
  numbers as one JSON object for a board post. Every point traces to a
  commit on `origin/main`, a registered sweep group, a dev.land outcome row
  or an `INDEPENDENT REVIEW by <agent>` note, and XP is never hand-set. The
  rules, the milestone multiplier table and the `tokens_extra.tsv` format
  are stated once in [`docs/work/MVP_GAME_MAP.md`](./work/MVP_GAME_MAP.md)
  under "XP rules v1".
- `progress` prints the milestone bars. With `--session` it adds a cost line
  and the KPI line.

### What verifies a loop

A plan row's `evidence=` field is not free text: its **shape** decides what
it can prove, and the `verified_by` column of `loops.tsv` says which rule
fired. In the order the tool prefers them:

| `verified_by` | evidence shape | verified when |
| --- | --- | --- |
| `landed` | `<sha>`, `<sha>,<sha>,…`, or a range `a..b` | every sha — for a range, the `b` — is in `--ancestry` |
| `sweep` | `ONLY=<group>` | `<group>` is registered in the `--groups` catalog |
| `verdict` | anything | the row's lane has a `VERDICT` under `--scratch` starting with `LAND`, written at or after `--since` |
| `sweep_group_unregistered` | `ONLY=<group>` | never — the catalog at that ref does not register `<group>` |
| `sweep_not_asked` | `ONLY=<group>` | never — no `--groups` was given |
| `-` | a doc path, a workflow id, `file:line`, `-` | never |

A **sweep is part of the experiment's definition, not a hole in it**: some
loops verify a capability that already existed, and the evidence that it
works is that a named test group covers it and passes. That is why the group
must be registered *at the ancestry ref* — a group that has since been
renamed or deleted proves nothing about the tree the loop claims to be done
in. Such a row is reported as
`<plan>:<line>: sweep_group_unregistered: … counts as UNVERIFIED` and does
not stop the run: it is a fact about one plan row, not a malformed input.

A range is proved by its right-hand side alone. `a` is where the work
started; only `b` says where it ended up.

The KPI line and the `kpi.tsv` row carry the split, so nobody has to guess
which kind of verification a number is made of. MTCU means a million TCU:

```text
kpi: 19 verified loops (4 landed, 8 sweep, +4 sub-rows) for 123076043 TCU = 0.154 loops/MTCU, 6477686 TCU/loop
```

Three more things to know before reading a number it prints:

1. **Both git inputs are files, not subprocesses.** `landed` is decided
   against a `git rev-list` output passed as `--ancestry`, and `sweep`
   against a `git show <ref>:tools/dev/test_group_catalog.def` output passed
   as `--groups`. Without either, the answer is "not asked" (`-`,
   `sweep_not_asked`) and never a guessed no. Use the same ref for both.
2. **A ledger's header is a contract.** Appending to a `snapshots.tsv` or
   `kpi.tsv` whose first line is not this build's header is refused, because
   every earlier row would otherwise be read under the wrong column names.
   Migrate the file, do not force the append.
3. **`tokens_out` is what the transcript recorded.** Claude Code writes the
   usage snapshot taken when a message starts, so `tokens_out` is a lower
   bound on generated tokens; `harness_tokens` beside it is the harness's own
   per-agent accounting (the difference between the first and last
   `<total_tokens>` reminder it wrote), which is the quantity a task
   notification reports.

Every refusal names the file, the line number and the reason
(`mvl_bad_json`, `mvl_line_too_long`, `mvl_plan_field`, `mvl_tsv_header`,
`mvl_overflow`, …). Line length is capped and every table is a fixed size, so
no input can grow the reader without bound.

## Retired procedures

These procedures were last scripted in shell with no tracked caller and were
removed in 46a8af087. Nothing automated runs them today, and no entry below is
a current pass. Each entry records the method so it can be rebuilt as a native
tool or a registered test; `git show 46a8af087^:<path>` prints the exact text.

### tools/scripts/debug_bundle_triage.sh <!-- doc-path-ok: removed in 46a8af087 -->
Purpose: read-only, one-screen triage of a `zcl.debug_bundle.v1` JSON, to see
why the node is wedged. Inputs: a bundle file, or a directory (newest
`debug-bundle-*.json` by mtime); helper `build/bin/jsonq`, overridable by `JSONQ`.
Method: 1. refuse unless `format` is `zcl.debug_bundle.v1` and `subsystems` exists.
2. print `trigger`, `captured_at_utc`, `build.version`, 12-char `build_commit`.
3. `reducer_frontier`: H*, served floor and gap, H*+1 blocker, coins verdict.
4. `blocker`: `active_count`, class counts, first 5 blockers (`fire_count`,
`reason` cut at 72 chars). 5. `supervisor_stalls`: per child `stall_reason`,
`stall_fires`, `last_tick_age_us`. 6. `sovereignty`: `trust_mode`, if present.
Checks: no pass or fail; coins cover H* when `coins_best_height` >= H*-1.
Exit 1 on a bad format, 2 on usage. Writes: stdout only.

### tools/scripts/ux_join_drill.sh <!-- doc-path-ok: removed in 46a8af087 -->
Purpose: one stranger-join run in an isolated /tmp datadir (`iso_init`), joining
one operator-named peer over Tor. Inputs: built `z23`, `jsonq`, `zclassic23`,
`zcl-rpc`; the peer via `UX_JOIN_PEER_ONION` and `UX_JOIN_PEER_PORT`, or
`UX_JOIN_PEER_FILE`; no peer named exits 2.
Method: 1. start `zclassic23 -tor -onion-persist`. 2. poll `core network onion
status` for `bootstrap_state` `ready`. 3. `core network peers add --address=` must
return `dial_requested`; then RPC `addnode`. 4. Three clocks from t0: PEERED, a
`getpeerinfo` entry for the onion with a version; FIRST_MSG, `app messaging send`
(`plan`, then `confirm:true` gives `sent`) and the log text `delivery ack from
peer`; SYNCED, `getblockcount` >= the peer's `startingheight`, captured at verack
and not a live tip. 5. 60 s defect rule: a step over `UX_JOIN_STEP_BUDGET` (60)
prints `DEFECT=<token> seconds=<n>` and is never a pass.
Writes: one JSON line per run to `UX_JOIN_CLOCK`; pass needs all 3 clocks, 0 defects.

### tools/dev/core-section-dependency-graph.sh <!-- doc-path-ok: removed in 46a8af087 -->
Purpose: measure the directed dependency graph among the sealed core's
subsystems, to decide whether a section can be the swap unit. Subsystems are
SECTION directories with a `include` or `src` SECTION child. It reads
`core/MANIFEST.sha3` and changes nothing; it writes only its work directory.
Inputs: `make` (`CACHED_CFLAGS`, or `--cflags=STR`), `cc`, `nm`; `--work=DIR`.
Method: three axes, none inferred from names. INCLUDE-CLOSURE: `cc -MM` per
sealed file, filtered to sealed files. INCLUDE-DIRECT: each file's own
`#include`, resolved on the `-I` path and cross-checked against the closure.
SYMBOL: each sealed `.c` built with LTO off and read with `nm -P`; an undefined
symbol defined by another subsystem is an edge. Output: a union matrix (D, S,
i, (c) for closure-only), edge counts, leaves, 2- and 3-cycles, and interface
width. Writes: a work directory under TMPDIR or `build/tmp`, removed on exit
unless `--work`; the report goes to stdout.

### tools/dev/zcc-reuse-bench.sh <!-- doc-path-ok: removed in 46a8af087 -->
Purpose: Linux compile-reuse A/B of two ZCC binaries with isolated caches.
Inputs: two executables, BEFORE and AFTER (usage exit 2); `cc`, `realpath`,
`sha256sum`; unsets `ZCC_DISABLE` and `ZCC_AUDIT`.
Method: 1. generate `fixture.c` (1000 `fixture_N` functions). 2. five rounds; odd
rounds run BEFORE then AFTER, even rounds reversed. 3. per version, a cold batch
then a warm batch, each four concurrent `ZCC cc -std=c23 -O2 -Wall -Wextra -Werror
-pedantic` jobs with `ZCC_STRICT=1`. 4. assert the four outputs are `cmp`-equal to
each other and to the saved first output, and `hits + misses` is 4. 5. measure
batch `wall_ms`, `user_s`, `system_s`, and HIT, MISS, WAIT log counts.
Writes: a kept directory under TMPDIR with `results.csv` (columns `round,version,
state,wall_ms,user_s,system_s,hits,misses,waits`), `environment.txt`, `oracle.o`.
No speed threshold; the CSV is measurement only.

### tools/scripts/metaverse_site_smoke.sh <!-- doc-path-ok: removed in 46a8af087 -->
Purpose: smoke the `/metaverse` pages on an isolated node over its HTTPS listener.
Inputs: `iso_init`, `iso_spawn_node`, `iso_wait_rpc_ready 90`; `openssl`; `curl`.
Method: 1. mint a one-day self-signed `ssl/fullchain.pem` and `ssl/privkey.pem`
(the listener starts only when both exist). 2. spawn the node; sleep 2. 3. `curl -kfsS`
`/metaverse`, `/metaverse/property`, `/metaverse/space`, `/metaverse/commons` on
`ISO_HTTPSPORT`, expecting 200 (`SMOKE 200 <route> (<bytes> bytes)`). 4. markers,
verbatim: `nobody owns the world they build in` and `SIMULATION` on `/metaverse`,
`zcode_package` on `/metaverse/property`, `ZC23 Living Commons` on `/metaverse/commons`.
Writes: stdout; exit 1 when a route or marker check fails.

The two-node terminal acceptance procedure is the sixth retired one; it is
recorded in `docs/work/SOVEREIGN_MACHINE_MESH_PLAN.md`.
