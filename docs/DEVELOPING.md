<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Developing Z23

This is the detailed developer procedure. The durable mission and authority
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
5. Consume action-changing RED evidence when it arrives.
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

## 1. Orient

On a new Linux, macOS, or Windows machine, run this first — it compiles with
a plain `cc` and does not require a C23 toolchain:

```bash
make doctor-env
```

It reports the compiler (`-std=c23` capability, not a version parse), git,
`vendor/tor` submodule state, make, optional mingw/ccache/zcc, the stack
soft limit, CPU count, and free disk. Each failing required check prints the
exact fix command for this platform. `make doctor` remains the separate
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

## 2. Inspect exact context

**Before you build any capability, ask whether this tree already has it.**
`code find` searches symbol NAMES; `code have` searches what code *does*, by
stemming the query and matching it against symbol names, doc comments, file
purposes, paths, and groups. Run it first — it is the cheapest step in the
loop and the one that prevents the most expensive mistake:

```bash
build/bin/z23 code have --input='{"text":"validation"}'
```

Real output from this checkout, abridged (warm: ~85 ms):

```json
{"verdict":"ALREADY EXISTS","capabilities":[
 {"what":"validation (12 matching symbols)",
  "header":"core/params/include/consensus/validation.h",
  "symbol_count":12,"used_by_files":72,
  "count_basis":"callers-of-matched-symbols"},
 {"what":"activerecord (24 matching symbols)",
  "header":"app/models/include/models/activerecord.h",
  "symbol_count":24,"used_by_files":66,
  "example_caller":"app/controllers/src/store_controller.c"}]}
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

Every `.c` under `app/` has one lint-enforced shape:

- `controllers/` parse and authorize, then call a service;
- `services/` orchestrate use cases;
- `models/` own persisted reads and writes;
- `jobs/` advance reducer cursors or name blockers;
- `supervisors/` own liveness trees;
- `conditions/` contain detect/remedy/witness repair loops;
- `events/` is the event shape;
- `views/` renders public surfaces.

Consensus predicates and parameters live under byte-sealed `core/` paths.
Pure bounded contexts live under `domain/`, reusable primitives under `lib/`,
write ports and adapters under `ports/` and `adapters/`, boot composition under
`config/src/`, and repository tooling under `tools/`.

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

The build profiles keep iteration separate from release proof:

- `DEV_LIVE` — an explicitly allowlisted read-only island;
- `DEV_RESTART` — incremental isolated development executable;
- `INTEGRATION` — static non-LTO combined proof;
- `RELEASE` — clean whole-program LTO and reproducibility path.

`make check-dev-loop-profiles` inspects the enforced profile boundary. Source
records bind exact bytes, toolchain, flags, and mutation state. Never fabricate
or pass `BUILD_SOURCE_RECORD` or `ZCL_FAST_BUILD_SOURCE_RECORD`; the owning
build process captures and verifies them.

Ask the node for this loop; do not remember it:

```bash
z23 code guide
z23 code impact <file.c>
z23 code tests <file.c>
```

Use the narrowest honest loop:

```bash
make -j"$(nproc)" t-fast ONLY=<substring from code tests>
make lint-fast
```

`t-fast` resolves the substring against registered groups and refuses a missing
or unknown selector. `lint-fast` is the inner lint (~7s). Never run `test_zcl`
directly. Do not run full `make lint` on an ordinary slice.

### Module mode — run a test group without relinking

Changing one file and running one group still recompiles that translation unit
and relinks the whole test harness. The link, not the compile, is the cost: the
harness is one binary over thousands of objects, and it is paid again for every
one-line edit.

For a translation unit on `config/hotswap_swappable.def`, module mode skips the
relink. It compiles that one TU into a module `.so` and loads it into the
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
quietly testing the resident code. Every gate applies: path confinement, ABI
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

- **Anything not on `config/hotswap_swappable.def`.** That allowlist is
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
build/bin/mutation-campaign --file=lib/metaverse/src/node_character.c \
                            --group=test_node_character
build/bin/mutation-campaign --file=<any .c> --list   # enumerate only; no build
```

`z23 code tests <file.c>` names the group that covers a file, which is the
`--group=` argument. `--limit=N` takes a sample instead of the whole file, and
`--target=` points the plan at a build other than `test_parallel`.

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
[`lib/test/src/test_cold_join_sovereign.c`](../lib/test/src/test_cold_join_sovereign.c).

For an exact push checkpoint, commit first. The notification hook makes a
best-effort detached request to the checkout's development service and returns;
it does not wait for or confirm durable enqueue. Inspect or wait for the
commit/base receipt with:

```bash
build/bin/z23-dev dev proof status
build/bin/z23-dev dev proof wait
```

`dev.proof.ensure` is idempotent and normally runs from `post-commit`,
`post-merge`, or `post-checkout`. It binds the local commit and advertised
remote base to exact source/CAS and mutation roots, changed-set and impact
policy, compiler/flags/environment/build graph, and complete generated,
compile, lint, and test accounting. A missing, stale, incomplete, skipped, or
tampered dimension cannot be admitted. `make pre-push-ci` remains an explicit
legacy parity oracle; it is not called by the installed push hook.

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
Run it only when an impact rule names a gate that `lint-fast` excludes, or at
a sub-wave / release boundary. An uncached full suite is:

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
regtest daemons, mines a regtest chain and runs confined package builds. The README's
demo, proof and topology figures are rendered from a recording that same run
writes — `ZCL_COMMONS_DEMO_RECORD=1 make commons-demo` refreshes
`docs/assets/z23-commons-demo.{strip,facts}`, and `make readme-svg` redraws the
SVGs from it. Never hand-edit either file: the gate exists so a figure cannot
outlive the journey it describes.

Focused and deep proof receipts describe only their bound observations. A
passing compiler/test/reproduction receipt does not grant runtime publication
or establish general code safety.

## 6. Integrate and push a coherent slice

Before committing:

1. Review `git status`, `git diff`, and `git diff --check`.
2. Confirm every changed file is owned by the slice.
3. Run focused acceptance and required generated-document checks.
4. Fetch current `origin/main` and integrate without discarding upstream or
   unrelated local work.
5. Rerun the minimum gates affected by that integration.
6. Commit one coherent change with an evidence-backed message.
7. Wait for `dev proof status` to report `passed`, then push normally. The
   native pre-push hook reads only the exact sealed receipt.
8. Verify local HEAD, `origin/main`, and the remote branch SHA agree.

Every changed C path must map to focused proof through the repository's impact
rules. Unmapped or incomplete closure refuses receipt publication. The hook
never builds, tests, lints, waits, invokes a shell, or fetches; a missing or
running receipt refuses within the bounded read path and prints the exact
`z23-dev dev proof wait` command for that commit/base pair. A normal
non-fast-forward race also refuses without deleting reusable child evidence.

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
