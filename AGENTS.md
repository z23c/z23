<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Z23 agent entry point

Read this model-neutral contract before changing the repository. It owns
durable principles, authority and the current work order (see *Priority and
evidence*); [DEVELOPING.md](docs/DEVELOPING.md) owns procedure;
[AGENT_FLEET.md](docs/work/AGENT_FLEET.md) owns the fleet operating model;
[FLEET.md](docs/FLEET.md) is the operator guide to the fleet's machines.
[HANDOFF.md](docs/HANDOFF.md) is maintainer-host live-state routing only.
[CODE_FEARLESSLY.md](docs/CODE_FEARLESSLY.md) explains the operating
disposition: act when the rails hold and build a missing rail.

## North Star

**Software made for you, not imposed on you.** A person describes what a device
should do; interchangeable workers reuse C23 parts, create only what is missing,
build quickly, show the real consequence, reproduce the exact result elsewhere,
and let the person accept and use that version.

Z23 is the durable layer: exact source identity, reusable packages, dependency
graphs, bounded builds, independent reproduction, local policy, distribution,
release history and preservation. The result must remain usable after the
agent, vendor, registry or company disappears. Keep complexity hidden but
inspectable, with one obvious next action.

Treat participating machines as one distributed C23 production computer.
Before computing, ask whether receiver-verified peer work can satisfy the
exact request. Derive action roots early, attach duplicate requests to existing
work, and distribute independent missing actions to qualified peers. Serialize
dependencies, conflicting writes and protected resources, not unrelated work.
Measure duplicate CPU, bytes, hashes, copies, queue waits and tool launches.
Optimize complete accepted-task cost, including failed attempts, repair and
review. Preserve unknown costs and conflicting evidence.

Use existing CAS, action, receipt, queue and transport authorities. Keep verified
components warm; transfer only missing content. Qualification precedes replacing
old computation or artifacts.
## Product and architecture

Z23 is a public ZClassic blockchain full node first. One self-contained C23
binary validates the chain, participates in P2P, holds transparent and shielded
wallet state, and can serve through embedded Tor. Consensus must remain
bit-for-bit compatible with `zclassicd`.

The optional C23 Commons lets ordinary nodes publish, discover, fetch, verify,
build, independently reproduce and serve exact packages without a central
registry. Keep the chain small and sovereign and the large software corpus
off-chain and content-addressed. Do not force ZCL as the sole payment method.
There is no live ZC23 token economics. Do not turn Z23 into a company, another
AI harness or a speculative token product.

Paths declare ownership:

- `core/` is sealed truth; `engine/` composes and runs the node.
  `engine/reducer/` alone owns chain-state advancement.
- `contexts/<feature>/` contains feature-first product rooms;
  `cognition/` contains software-understanding machinery.
- `platform/ports/` and `platform/adapters/` isolate outside systems.
  Reusable modules live beneath their owning authority; do not recreate
  legacy global roots or duplicate owners.
- `apps/` holds separate C23 programs that link neither `core/` nor
  `engine/`, currently including Skycombat. They retain strict warnings and
  portability gates; node architecture gates do not scan them.

After placement changes run `make check-architecture-tree`. It rejects legacy
or undeclared roots, unknown rooms, duplicate owners, manifest drift and
misplaced reducer paths. Use `build/bin/z23 code context-map` for the generated
view, not a hand-maintained ownership catalog.

## Priority and evidence

Owner-adopted reset of 2026-10-16, recorded on board ref
fleet-priorities-20261016. It supersedes earlier session rulings. The
numbered owner rulings (R1, R2, ...) live on the fleet wiki page
`fleet-rules`, read with `z23-dev fleet.wiki.read --slug=fleet-rules`; when
an older doc or note conflicts with that ledger, the ledger wins. Cite
rulings by number.

1. **P0 (always first):** consensus, wallet/custody and public-node
   correctness, and canonical node health. The blockchain wins resource
   and authority contention. Builds, telemetry, package traffic and AI
   workers may not delay chain advancement, block processing, transaction
   relay, synchronization, peer health or wallet custody.
2. **The fleet A+ scorecard** ([FLEET_SCORECARD.md](docs/work/FLEET_SCORECARD.md))
   orders all other work. Fleet tooling is first-class product.
   - Tier 1, the unblockers: G9 landing throughput, G13 agent
     productivity and review, G7 MCP harness, G4 wiki.
   - Tier 2, the sovereign fleet core: G11 zero spend, G1 post-quantum
     tunnel, G3 remote shell, G5 plugins and binary swarm, G6 seamless updates.
   - Tier 3: G2 post-quantum release signing, G8 telemetry, G12 Mac parity.
   Within a tier, the work closest to its A+ bar goes first; independent work
   may proceed in parallel. Public-node V1
   acceptance under [MVP.md](docs/MVP.md) C1–C8 and the product priorities in
   [FORWARD_PLAN.md](docs/work/FORWARD_PLAN.md) remain acceptance context.
3. **Zero spend.** No fleet feature may require ZCL, an anchored ZID or a fee.
   Work that needs a spend (such as the 1 ZCL payment rerun) waits for an
   explicit owner authorization.

Review and landing: every unit, including core, crypto, consensus and
custody, needs one reviewer who is not its author, of any model. Run full
`make lint` once at the exact candidate tip before `dev land submit`; any
lead may submit and drive its own reviewed work. Native C23 commands are
the target; small POSIX sh operator scripts are acceptable as interim tooling.
Commits are signed and authored by the repository owner; a commit an AI
model wrote ends with its `Co-Authored-By:` trailer naming that model
(owner ruling R12).

**VERIFY, DON'T TRUST.** Any agent may propose and any node may compute.
Receivers independently verify exact objects, signatures, roots and evidence
under their own policy. A hash identifies bytes; a signature identifies the
statement's signing key; a receipt binds an observation. None alone proves
safety, correctness, usefulness or acceptance.

Downloaded C is inert. Fetch/store, build/test, install/link and execute/deploy
are separate authority transitions. None grants canonical-datadir, wallet or
consensus authority. A unit test cannot replace acceptance of a real consensus
or custody invariant. Distinguish source review, fixtures, runtime observations,
platform qualification and production acceptance.

Every change should improve reuse, intent-to-working-software time, size,
speed, safety, customization, exact reproduction or preservation. Prefer
deletion, reuse and composition over new abstractions.
## First session

New to a fleet? Read [START_HERE.md](docs/agent/START_HERE.md) first.

Read the installed
`~/.config/dev-workers/OPERATIONS.md`, `STORAGE.md` and `WORKER.md`, then
run `devworker where z23`. Their current reserves supersede historical
floors. Managed Z23, QEDC and gate_computer development runs remotely through
existing `devon` routes; the laptop coordinates and reviews, without builds
or worker copies.

Reuse a sanctioned worktree and preserve owned dirty work. Route heavy builds,
proofs, benchmarks and matrices through `devbuild --wait`, preserving job
counts and native locks. On the managed Mac use one focused build, normally
two jobs. Do not launch services, watchers or workers automatically.

Inspect before editing:

```bash
pwd
git status --short --branch
git fetch origin main
git rev-parse HEAD origin/main
```

On a fresh clone, `devbuild --wait make setup` arms dependencies and hooks;
its suggested `make doctor` is an optional environment check. Build the public
binary on an admitted host:

```bash
devbuild --wait make -j"$(getconf _NPROCESSORS_ONLN)" z23
build/bin/z23 code guide
build/bin/z23 discover help
build/bin/z23 code map
```

Apply the installed host job limit to these generic examples. Descend through
`discover help <path>`, search with `discover search <query>`, and inspect
inputs with `discover schema <leaf>`. A command in a plan is a target until
the selected binary lists it. The generated full catalog is
[API_REFERENCE.md](docs/API_REFERENCE.md).

Use registered tests and the canonical runner, never direct `test_zcl`:

```bash
make t-list
devbuild --wait make -j"$(getconf _NPROCESSORS_ONLN)" t-fast-exact ONLY=<exact-group>
devbuild --wait make -j"$(getconf _NPROCESSORS_ONLN)" test-parallel TEST_PARALLEL_ARGS=--no-cache
```

`ONLY=` is mandatory for `t-fast`. Derive catalogs from the binary rather
than copying counts into entry documents.

<!-- claim: symbol-present t-fast Makefile # focused registered-test target -->
<!-- claim: symbol-present test-parallel Makefile # full registered-test target -->
<!-- claim: symbol-present discover.schema engine/composition/commands/root.def # live schema leaf -->
<!-- claim: symbol-present code.map engine/composition/commands/code.def # live source-map leaf -->
<!-- claim: file-present docs/API_REFERENCE.md # generated command catalog -->

## Verified platform baseline

Linux and arm64 macOS have native build paths; macOS does not require a Linux
VM. On 2026-08-26, an arm64 Mac16,10 with macOS 26.0.1 and Apple Clang 17
built the node, passed the dependency audit and recorded isolated startup and
platform tests. That evidence is not current-candidate chain-sync acceptance.
Intel macOS remains unverified. The detailed historical observations and
platform refusal boundaries belong in
[NATIVE_MACOS_RUNBOOK.md](docs/work/NATIVE_MACOS_RUNBOOK.md#historical-platform-baseline).
Use its native acceptance target for new qualification; Linux tests do not
qualify macOS.

## Orient before editing

Read [DEVELOPING.md](docs/DEVELOPING.md) before edits and
[AGENT_TRAPS.md](docs/AGENT_TRAPS.md) before repairing behavior that may be
intentional or complete. Use the native navigator before broad search.
Consult [CODEBASE_MAP.md](docs/CODEBASE_MAP.md) when ownership remains unclear.
Raw search must stay in the tracked tree with `git grep` or `git ls-files`;
never recursively scan a repository root containing scratch or worktrees.

Read [SECURITY_AND_INTEGRITY.md](docs/SECURITY_AND_INTEGRITY.md) and
[CONSENSUS_PARITY_DOCTRINE.md](docs/CONSENSUS_PARITY_DOCTRINE.md) when
approaching security, custody or consensus. Read [HANDOFF.md](docs/HANDOFF.md)
only for an explicit maintainer-host assignment, then verify against the
running node with `build/bin/z23 status` and
`build/bin/z23 dumpstate reducer_frontier`. Do not copy live height, soak or
deployment status into durable entry documents.

## Authority and safety boundaries

Source inspection, editing, builds and isolated tests do not implicitly permit:

- consensus predicate changes or changes to the byte-sealed core;
- spending funds, exporting keys or weakening custody;
- canonical-datadir mutation or live database surgery;
- production deployment, restart or promotion;
- weakened assertions, acceptance thresholds or fail-closed refusals;
- fetched-source execution outside the bounded build/test lifecycle;
- publication, signing or acceptance on another operator's behalf.

Consensus edits require the documented explicit unseal/reseal ritual.
Recovery is copy-first under [TENACITY.md](docs/TENACITY.md). Deployment and
custody remain owner-gated. Explicit scoped owner authorization persists;
do not repeatedly request the same authorization.

Escalate only for consensus/custody risk, destructive production action,
irreconcilable authority ambiguity, a missing human product decision, an
assertion that would need weakening, or genuine mission completion.

## Development contract

- **C23 is canonical. Never use Python:** no `.py` files, Python shebangs,
  invocations, heredocs, fallback or legacy exceptions. Operator/test glue is
  native C23, including small in-tree helpers such as `sqlq`/`jsonq`. Small
  POSIX sh scripts are acceptable interim tooling; retain the no-new-bash
  ratchet.
  Extract flat JSON with grep/sed/awk and nested JSON with `build/bin/jsonq`;
  use `build/bin/sqlq` for SQLite inspection.
- Preserve unrelated dirty work; never reset, overwrite or include it in
  your commit. Keep one primary writer per component and respect live leases.
  Silence alone does not establish an orphan.
- GitHub Issues and pull requests are not coordination authorities and must
  not be created. Use native tasks, candidates, actions and receipts;
  committed `origin/main` is the integration blackboard.
- Claim disjoint scopes through native tools. Obtain required independent
  review and persist handoffs so coordination survives replacement of any
  worker without a permanent privileged lead.
- Fetch current `origin/main` before work and every push. Integrate safely
  and rerun affected gates. Never rewrite others' history.
- Use typed native commands for a running node. Git, compilers, make and
  bounded shell remain repository tools. New native commands require a
  recurring operator/product need; reuse existing command families.
- Use existing CAS, task, candidate, action, receipt, queue and signature
  authorities. Do not create a competing source of truth.
- Tests use local fixtures, isolated datadirs and consenting peers.
  Every application write follows the ActiveRecord save lifecycle; retain
  custody-bearing before/after-save hooks. Check allocations, log contextual
  errors, and give native command failures explanatory response bodies.
  [DEFENSIVE_CODING.md](docs/DEFENSIVE_CODING.md) and lint enforce the rules.

Fleet access is a prerequisite for distributed work. Before dispatch verify
authenticated access, a bounded command and exact-object transfer in both
directions between each participating pair, directly or through tunnels.
Ping, stale status and board delivery do not qualify a route. Repair authorized
routes directly rather than using the human as a message relay. Reuse existing
SSH, tunnels and native transport; keep private credentials local and endpoints
out of public coordination messages.

Each receiver controls workspace, commands, concurrency, access lifetime and
revocation. Record readiness and missing access in native task/action/receipt
evidence with aliases and object roots. Transport does not expand execution,
production or custody authority. Recurring transport, access control, tunnels
and job execution belong in C23 node services; shell remains bootstrap/build/
test glue, not a new orchestration layer. Protected native execution,
hardware virtualization and emulated guests retain their separate qualification
boundaries under [AGENT_FLEET.md](docs/work/AGENT_FLEET.md).

## Completion and continuation

A coherent slice needs green focused acceptance, current generated files,
required lint, independent review where required and no unrelated changes.
Use native receipt-gated landing under `devbuild --wait`, as specified in
[DEVELOPING.md](docs/DEVELOPING.md). Independently fetch and verify the exact
remote SHA. Evidence applies only to its source, commit/base pair and policy;
reconcile an unknown push before retrying.

A push is a checkpoint. Fetch current main, integrate safely and continue
work in the fleet priority order until complete acceptance or a named
escalation condition.
A status report does not suspend work. Remove obsolete code/instructions only
after verifying ownership, callers and replacement acceptance. Update the
owning document in the same slice and regenerate derived references through
canonical targets. Preserve historical evidence and active work.

Use a compact mission capsule for substantial work:

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

## Source baseline and managed development

The owner authorized a one-time source-history baseline on 2026-10-12;
verified offline recovery history and unpublished work retain separate custody.
This grants no future rewrite authority. Start from current main and recover
needed old work as bounded reviewed patches; do not merge unrelated old
history. Detailed baseline provenance is in
[DEVELOPING.md](docs/DEVELOPING.md#managed-source-baseline).

Documentation map: [docs/README.md](docs/README.md).
