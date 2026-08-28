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

A push is a checkpoint, not completion. Remote proof must not block the
developer's ability to continue editing. Acceptance remains a local policy
decision over exact canonical task, candidate, action, and receipt objects.

## 1. Orient

Start by identifying the checkout and preserving existing work:

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

Use the in-tree source navigator before broad text search:

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
keys rather than guessing.

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

Version suffixes name wire/format compatibility ladders only (`v2_transport`,
`creation_claim.v2`); internal package or source families carry no version
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

For a push checkpoint:

```bash
make pre-push-ci
```

It gates whatever your branch would actually push. When the working tree
has uncommitted edits it uses those; when the tree is clean — the normal
state at push time — it falls back to the commits between your upstream
(or `origin/main`) and `HEAD`. The log says which source it used and how
many files it found, so `count=0` is legible as "nothing to push" rather
than passing silently over untested commits.

Full `make lint` is the umbrella (every gate, including whole-node tool links).
Run it only when an impact rule names a gate that `lint-fast` excludes, or at
a sub-wave / release boundary. An uncached full suite is:

```bash
make -j"$(nproc)" test-parallel TEST_PARALLEL_ARGS=--no-cache
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
7. Push normally; the pre-push hook runs `make pre-push-ci`.
8. Verify local HEAD, `origin/main`, and the remote branch SHA agree.

Every changed C path must map to focused proof through the repository's impact
rules. The pre-push hook runs those mapped groups only; an unmapped code path
fails closed so it cannot expand to the full suite. If the pre-push hook reports a write/SIGPIPE failure after its underlying
gate genuinely completed, inspect the saved log and reproduce the gate
out-of-band before considering the documented verified bypass. Never bypass an
unknown or failing gate.

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

Reuse existing CAS, package, task, candidate, action, lease, worker, and receipt
objects. Lifecycle labels such as requested, running, or ready-for-acceptance
are derived projections, never a second source of truth.

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
