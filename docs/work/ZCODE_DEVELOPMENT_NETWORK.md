# ZCODE agentic development network

> User-facing entry point: [`../METAVERSE.md`](../METAVERSE.md); acceptance
> bar: [`../METAVERSE_MVP.md`](../METAVERSE_MVP.md). This is a scoped protocol
> specification, not a current-work queue. Current ordering lives only in
> [`FORWARD_PLAN.md`](./FORWARD_PLAN.md).

Status: active implementation contract, 2026-08-01. This document supersedes
the payout-first tail of [`ZCODE_PLAN.md`](./ZCODE_PLAN.md). The package-hosting
work remains the foundation; its old slice numbers are no longer the execution
order.

The owner-directed scientific-evidence, discovery-network, contribution,
committee, and custody extension is specified separately in
[`ZCODE_SCIENTIFIC_METAVERSE.md`](./ZCODE_SCIENTIFIC_METAVERSE.md). It composes
with the byte-stable objects in this document and may not duplicate their CAS,
worker, identity, transport, or authority owners.
The planned transferable asset, creation-backed issuance covenant, and
patronage boundary are separately authoritative in
[`ZC23_LIVING_COMMONS.md`](./ZC23_LIVING_COMMONS.md).

## Mission

> **Z23 is a metaverse where people and AI create real things together,
> and nobody owns the world they build in.**

ZCODE is a free, requester-coordinated P2P C23 development network: immutable
source discovery and fetch, model-neutral tasks, candidate trees, confined
build/test/fuzz work, independent review, local reproduction, explicit
acceptance, and publication back to the package swarm. No company, account,
payment, proprietary model, global scheduler, or trusted coordinator is a
protocol requirement.

Hashes are authority. ZNAM is an optional mutable name. Codex, Claude, Kimi,
local open models, and future harnesses are adapters selected by the user; an
adapter name never participates in source or proof authority.

People, AI agents, local tools, and presentation adapters use the same typed
native command tree and canonical object graph. An adapter may help create or
explain work; it cannot acquire protocol authority by doing so. Exact source,
authorship, licensing, tests, reproduction, review, acceptance, and lineage are
the mechanically checkable facts. The shared network is not owned by its node
operators, model providers, package indexes, patrons, or token holders.

Basic discovery, fetch, local development, and a bounded peer bootstrap quota
remain free. Optional reciprocity may expand a peer's local quota later only
through nontransferable ZCODE Credit or locally interpreted ZCODE Score.
Planned ZC23 is never an access key, and transferred balance never creates
score, proof weight, or quota authority on another node.

## One object graph, existing owners

There is no second package store, lock resolver, code index, sandbox, build
ledger, worker trust list, or P2P transport.

| Fact | Canonical owner reused by this program | Current truth |
|---|---|---|
| Source tree and chunks | `content.v2` in `lib/vcs/package_manifest.*` and the ZCODE CAS | Live |
| Published release | `lib/vcs/package_release.*` and package-add lifecycle | Live |
| Dependency lock | `vcs_package_lock` in `lib/vcs/package_deps.*` | Live, root-pinned DAG |
| Declarative C23 graph | `vcs_package_recipe` | Live for one library/test package; workspace executables and multi-package targets still need an extension |
| Source snapshot identity | existing path-sorted ZVCS manifest and domain-tagged blob CAS | Live local capture and task binding; content.v2 remains the P2P carrier |
| Code context | `lib/codeindex/` plus the existing ZCODE CAS | Live bounded `agent_context.v1` capture for an exact symbol or stable symbol ID; goal-to-symbol selection and adapter invocation remain |
| Fixed build action | `vcs_build_action_v1` | Live closed registry and identity for preprocessed-TU compile, exact-executable test, deterministic exact-executable fuzz, and review. Local execution is live for compile, test, and fuzz |
| Build coordinator ledger | `build_jobs`, `build_actions`, `build_workers`, `build_receipts`, `zcode_lane_receipts` | Live schema v45. Work receipt rows distinguish local acceptance, untrusted remote observation, local reproduction, and approved-signer quorum; lane rows are lookup projections of signed CAS receipts |
| Local package confinement | `zclassic23-package-verify` | Live: declarative recipe, Landlock/seccomp/rlimits, no network |
| ZBuild worker execution | existing build-fabric runtime | Live locally for fixed preprocessed-TU GCC, exact test-executable, and deterministic seeded fuzz actions when `-buildworker` is enabled: durable identity, bounded leases, full confinement, CAS evidence, signed pass/fail receipts, and local fallback |
| Package P2P | `package_swarm_node` and `zpkgswm` | Live for immutable package bytes |
| Work P2P | signed work frames over package swarm/CAS | Live `ZCWS` multiplex on existing `zpkgswm` sessions: canonical compile/test/fuzz context fetch, ZBuild admission, cancellation, signed pass/fail result return, durable untrusted observation, local reproduction, and per-proof-class approved distinct-signer quorum |
| Agent authority | metaverse grants and signed receipt chain | Live for scoped property operations; task work must never inherit wallet or canonical-node authority |
| Durability lanes | signed `lane_receipt.v1` over source/proof roots | Live local chain and typed promotion. Distributed long-duration actions and projection reconstruction tooling remain |

The control-plane distinction is load-bearing: a READY command or database row
does not prove an executor exists. `build.worker` now has an actual supervised
thread and fixed compile/test/fuzz actions. Review has a canonical, kind-bound
identity and proof evaluation, but review authorship/execution and remote agent
candidate generation remain missing.

## Canonical development objects

The first implementation lives in `lib/vcs/include/vcs/zcode_dev.h` and
`lib/vcs/src/zcode_dev.c`. Each object has one fixed-width, closed binary wire,
a version-specific magic, little-endian integers, a domain-separated SHA3-256
identity, exact-length parsing, and named rejection reasons. JSON is display
only.

The domains are:

- `zcl.zcode.task.v1\0`
- `zcl.zcode.candidate.v1\0`
- `zcl.zcode.proof_policy.v1\0`
- `zcl.zcode.review.v1\0`
- `zcl.zcode.work_receipt.v1\0`
- `zcl.zcode.lane_receipt.v1\0`
- `zcl.zcode.agent_context.v1\0`
- `zcl.zcode.write_scope.v1\0`
- `zcl.zcode.patch.v1\0`
- `zcl.zcode.action_input.v1\0`

The scientific extension in
[`ZCODE_SCIENTIFIC_METAVERSE.md`](./ZCODE_SCIENTIFIC_METAVERSE.md) adds these
separate domain tags without changing any wire above:

- `zcl.zcode.study_spec.v1\0`
- `zcl.zcode.benchmark_result.v1\0`
- `zcl.zcode.reproduction.v1\0`
- `zcl.zcode.science_findings.v1\0`
- `zcl.zcode.curation_vote.v1\0`
- `zcl.zcode.discovery_graph.v1\0`
- `zcl.zcode.discovery_seed_set.v1\0`
- `zcl.zcode.discovery_rank_result.v1\0`

Its fixed `c23.benchmark.v1` and `c23.benchmark.reproduce.v1` action
identities are registered beside `c23.review.v1`. The local worker still
fail-closes them as `fixed-action-executor-unavailable`; confined benchmark
and reproduction execution is a later landing unit, so an action identity is
not misreported as a live executor.

The deterministic discovery-only PageRank core is also live in
`lib/vcs/include/vcs/zcode_discovery_rank.h`. It ranks only study/package
property roots, never contributors, and binds its canonical graph, local seed
set, filter policy, exact returned mass coverage, and truncation. It has no
database, command, proof-acceptance, committee, wallet, or reward authority;
the rebuildable projection and `zcode.science.rank` adapter wait for the S3
science service slice.

<!-- claim: file-present lib/vcs/include/vcs/zcode_science.h # canonical scientific object contract -->
<!-- claim: symbol-present vcs_zcode_benchmark_result_validate_for_study lib/vcs/src/zcode_science.c # study/task/candidate cross-object gate -->
<!-- claim: symbol-present VCS_BUILD_ACTION_KIND_BENCHMARK_V1 lib/vcs/include/vcs/build_action.h # closed benchmark action identity -->
<!-- claim: symbol-present vcs_zcode_discovery_rank_compute lib/vcs/src/zcode_discovery_rank.c # deterministic discovery-only integer PageRank -->

The trailing NUL is part of each SHA3 preimage, matching the existing package
manifest, recipe, lock, release, and attestation convention.

### `proof_policy.v1`

The requester chooses the required proof set and quorum. The object binds:

- compile, test, fuzz, review, and local-reproduction requirements;
- minimum receipts for each required class and minimum matching receipts;
- independent-signer and release-byte-identity requirements;
- deterministic fuzz seed count, audit sample in basis points, and maximum
  proof age.

A class not required must carry a zero minimum. A required class must carry a
nonzero minimum. This gives every policy one encoding and prevents a display
adapter from inventing implied defaults.

### `task.v1`

A task binds exactly:

- source root, derived by scanning the tracked workspace twice, storing its
  existing ZVCS manifest/blobs, and verifying manifest readback;
- existing `vcs_package_lock` root;
- existing `vcs_toolchain_capsule_v1` root;
- immutable canonical `write_scope.v1` root;
- immutable `vcs_package_recipe` root as the declarative acceptance graph;
- `proof_policy.v1` root;
- user-selected model-policy root;
- immutable goal root;
- the only v1 agent capabilities: source read, candidate-tree write, and fixed
  action execution;
- changed-file, patch-byte, context-byte, CPU, memory, and output ceilings;
- expiry.

Wallet access, canonical-node mutation, arbitrary process execution, arbitrary
shell, package-provided capability escalation, and worker network access are
not values in the v1 capability vocabulary.

Plan and explicit admission do not accept the dependency-lock and acceptance
roots as unsupported assertions. The caller supplies `dependency_lock_hex`
and `acceptance_recipe_hex`; ZCODE parses the existing canonical
`vcs_package_lock` and `vcs_package_recipe` wires, derives their
domain-separated roots, stores them in the existing workspace CAS, reads them
back, and rejects any optional claimed root that differs. A lock must contain
at least its target node. Every recipe source, test source, public header, and
include directory must resolve in both the task's exact base ZVCS manifest and
the admitted candidate manifest. Missing, altered, trailing, root-mismatched,
or phantom recipe/lock authority is refused before ZBuild planning.

### `write_scope.v1`

The write scope is a closed variable-length wire containing 1–64 sorted,
unique canonical path prefixes. A prefix grants one exact path or descendants
at a component boundary: scope “src” admits “src/net.c”, but not
“src-old/net.c”.
Traversal, absolute paths, empty segments, duplicate entries, trailing bytes,
and oversized paths are refused. Its root is stored in the existing workspace
CAS and bound by `task.v1`; an explicit admit must rederive the same root from
the same `write_scope_csv`. The object grants candidate-tree writes only. It
cannot name wallet, node, process, or network authority.

### `candidate.v1`

A candidate binds the task, exact base source, patch object, complete candidate
source tree, user-selected adapter/model policy, author public key, sequence,
and creation time. Its author label establishes provenance only. Acceptance is
driven by proofs and an explicit user action, never by model brand.

Explicit admission does not trust candidate or patch roots supplied by the
adapter. `candidate_workspace` must resolve to a separate, non-overlapping
directory. ZVCS double-scans it, imports its path-sorted manifest and tagged
blobs into the requester’s existing CAS, then derives `patch.v1` by
merge-joining it with the task’s exact base manifest. Each change binds kind,
path, old mode/size/blob, and new mode/size/blob. Added and modified candidate
bytes count against `max_patch_bytes`; all changes count against
`max_changed_files` and must belong to `write_scope.v1`. Empty candidates,
out-of-scope paths, changed base workspaces, false root claims, malformed
wires, and CAS readback mismatches are refused before a ZBuild row exists. The
local worker repeats manifest-to-patch derivation before executing the action.

### `review.v1`

A review binds the task, candidate, proof policy, immutable proof set,
immutable findings, reviewer public key, verdict, sequence, and time. The
verdict is one of approve, request-changes, or reject. Authorship is supplied
by a signed `work_receipt.v1` whose output is the review root; the review object
does not create a second signature system.

### `work_receipt.v1`

A work receipt binds task, candidate, fixed action, exact input and output,
proof policy, toolchain capsule, lease, evidence manifest, achieved confinement
manifest, work kind, status, exit status, start/finish times, and signer key.
Ed25519 signs its domain-separated receipt ID. The verifier pins the expected
signer; trusting the embedded key alone is forbidden.

Cross-object validation refuses stale source, task, candidate, policy,
toolchain, output, or expiry state. A structurally valid old receipt therefore
cannot authorize a moved task.

### `action_input.v1`

Every agentic fixed action now consumes a canonical candidate-bound envelope,
not bytes selected from an unrelated host path. The envelope binds the task,
candidate, candidate source manifest, dependency lock, acceptance-test root,
work kind, canonical candidate-relative path, tagged ZVCS blob root, and exact
payload. Its domain-separated root is the ZBuild action's `input_root`.

`zcode improve mode=admit` treats `fixed_input_path` only as a selector and
requires it to resolve beneath `candidate_workspace`; it then reloads the
payload from the already-captured candidate CAS. Compile inputs must be `.i`
manifest members. Test and fuzz inputs must be executable manifest members.
The worker parses the envelope, rederives task/candidate roots, reloads the
candidate manifest, verifies the path/mode/size/tagged blob, and extracts the
payload only after every binding matches. It repeats that check before receipt
publication. An outside executable, altered payload, changed path, wrong work
kind, moved lock/test root, or stale candidate is a named local fallback.

This proves exactly which candidate-addressed bytes were compiled or run. The
separate fixed `package_action_input.v1` has no path or payload field: it binds
task, candidate, candidate/base source, dependency lock, and acceptance recipe
roots. `c23.package.recipe.v1` reconstructs every candidate file from ZVCS CAS,
verifies each installed locked dependency against its build report and actual
output bytes, and gives the external confined verifier only that tree plus the
canonical recipe. Its build report is source-derived build/test evidence; the
older exact-test/fuzz actions remain honestly labeled as executions of
candidate-manifest executable members.

### `proof_set.v1`

Reviews bind one immutable proof-set root. The canonical variable-length wire
contains 1–64 strictly ascending, unique `work_receipt.v1` roots and is
domain-separated as `zcl.zcode.proof_set.v1\0`. Receipt order, duplicates, or
display formatting therefore cannot change which evidence was evaluated.

### `lane_receipt.v1`

Every admitted candidate source gets an operator-signed FRONTIER receipt in
the existing workspace CAS before its ZBuild job is submitted. A receipt binds
the exact source, task, candidate, proof policy, evaluated proof set, previous
lane receipt, lane, creation time, and signer. FRONTIER has no prior or proof
root; CANDIDATE and PROVEN require both. The receipt ID is the authority. The
`zcode_lane_receipts` table is a model-owned lookup projection and is verified
field-for-field against the CAS object and Ed25519 signature on every read.

Transitions are sequential and signer-stable. CANDIDATE requires the proof
evaluator's compile bar plus any task-required test bar. PROVEN requires the
entire `proof_policy.v1`, including fuzz, review, local reproduction/quorum,
proof age, and release-byte identity when selected. A changed or expired task,
candidate, policy, source, proof set, signer, or prior receipt is a refusal.
CANDIDATE is proof readiness, not human acceptance. The expert `zcode accept`
route can only create CANDIDATE; only the ordinary explicit `zcode work accept`
lifecycle can create the PROVEN accepted-work root used by publication.

### `agent_context.v1`

`zcode improve` can resolve one exact code-index symbol name or stable symbol
ID and capture its definition/declaration, bounded callers, and known include
edges. The canonical variable-length wire binds the task, authoritative source
root, goal, an independently recomputed source-tree Merkle root, query, and up
to 16 sorted source excerpts. Every excerpt carries its canonical relative
path, starting line, full-file size, exact bytes, and SHA3 root. Each excerpt
is capped at 64 KiB and the complete wire is capped by the task's context-byte
limit.

Capture uses no downloaded scripts and grants no agent authority. It first
rederives the task's full ZVCS source snapshot, then opens
selected files without following symlinks, recomputes the source Merkle root
before and after capture, and rereads every selected byte range. A stale task,
rename, edit during capture, changed byte range, malformed wire, duplicate or
unsorted path, excess size, trailing byte, or CAS readback mismatch is a named
refusal. The exact wire is stored at its domain-separated root in the existing
workspace CAS. Model adapters consume that immutable object later; they do not
define its identity.

### `zcode-work-context.v1`

Remote execution adds no source store or transfer protocol. One fixed context
wire is carried as a normal multi-chunk `content.v2` package at the canonical
path `zcode-work-context.v1`. Its closed binary grammar binds the
existing `task.v1`, `candidate.v1`, and `proof_policy.v1` wires, the candidate
source SHA-256 oracle, build profile, and exact `action_input.v1` wire.

Requester-to-worker packages add two canonical authority files.
`zcode-candidate-authority.v1` contains the exact scope and patch wires,
base and candidate ZVCS manifests, and a hash-sorted, duplicate-free set of
every added or modified blob. The receiver validates the complete bundle,
rederives both manifest roots and the patch under task scope/limits, and checks
every tagged blob hash before writing anything. It then imports those objects
into the existing workspace CAS and repeats the same CAS verification used by
the local worker. A missing, truncated, reordered, altered, oversized, or
root-mismatched bundle refuses remote admission. The companion
`zcode-task-authority.v1` carries the exact canonical dependency-lock and
acceptance-recipe wires. A receiving peer derives both roots and validates both
wires before it imports candidate authority or creates a ZBuild row.

The same content.v2 manifest also carries every regular file in the exact
candidate ZVCS manifest under `candidate/`. These are ordinary existing
content.v2 chunks, not a new archive. On receipt, the peer requires a one-to-one
path/mode/size match, reassembles and rehashes every chunk, and rederives every
tagged ZVCS blob hash against the candidate manifest before admitting any tree
blob. This includes unchanged base files that are intentionally absent from
the patch-only authority bundle, so a fresh peer can reproduce the complete
candidate without a shared checkout.

The combined metadata and candidate tree remain under the package store's
existing 64 MiB anti-abuse cap and the task's smaller context ceiling. The
action envelope selects a candidate-manifest preprocessed TU, exact test
executable, or exact deterministic fuzz executable according to the action
kind. The package action instead carries the closed path-free package input;
the receiving peer derives that action kind from the input schema, reconstructs
the full tree, and applies the same recipe and dependency checks locally.

The receiving peer re-derives the task, candidate, policy, input, toolchain,
and `build_action.v1` roots and compares every one to the signed request before
writing the objects to the existing workspace CAS or planning the existing
ZBuild action. It never accepts a caller-supplied path or command.

<!-- claim: file-present lib/vcs/include/vcs/zcode_dev.h # the canonical object contract -->
<!-- claim: symbol-present vcs_zcode_work_receipt_verify lib/vcs/src/zcode_dev.c # signed receipt verification -->
<!-- claim: symbol-present vcs_zcode_work_receipt_validate_for_candidate lib/vcs/src/zcode_dev.c # cross-object staleness gate -->
<!-- claim: symbol-present vcs_zcode_proof_set_root lib/vcs/src/zcode_proof_set.c # immutable evaluated evidence set -->
<!-- claim: file-present lib/vcs/include/vcs/zcode_agent_context.h # bounded canonical agent context wire -->
<!-- claim: symbol-present zcode_agent_context_capture app/services/src/zcode_agent_context_service.c # source-stable context publication into existing CAS -->
<!-- claim: symbol-present vcs_tree_capture_path lib/vcs/src/vcs.c # verified task source snapshot in existing CAS -->
<!-- claim: symbol-present vcs_tree_capture_into lib/vcs/src/vcs.c # separate candidate workspace import into requester CAS -->
<!-- claim: symbol-present vcs_zcode_write_scope_contains lib/vcs/src/zcode_write_scope.c # component-bounded candidate write authority -->
<!-- claim: symbol-present vcs_zcode_patch_derive lib/vcs/src/zcode_patch.c # manifest-derived scoped patch authority -->
<!-- claim: symbol-present vcs_zcode_candidate_bundle_import lib/vcs/src/zcode_candidate_bundle.c # validate-before-write P2P candidate authority import -->
<!-- claim: symbol-present vcs_zcode_action_input_validate_for_candidate lib/vcs/src/zcode_action_input.c # fixed actions consume candidate-manifest bytes -->
<!-- claim: symbol-present vcs_zcode_task_authority_validate_for_candidate lib/vcs/src/zcode_task_authority.c # lock and recipe roots resolve against base and candidate trees -->
<!-- claim: symbol-present vcs_zcode_candidate_tree_import lib/vcs/src/zcode_candidate_tree.c # content.v2 reconstructs every candidate blob on a fresh peer -->

## Ordered delivery

### A. Canonical object foundation

- [x] Define the five v1 wires and domain-separated identities.
- [x] Bind task source, lock, toolchain, scope, tests, limits, model policy,
  proof policy, and expiry.
- [x] Sign and verify work receipts with pinned Ed25519 signers.
- [x] Add byte KATs, round trips, malformed-wire checks, and stale-root checks.
- [x] Store these wires through the existing ZCODE CAS and project a local task
  index from CAS objects rather than creating task tables as a second truth.
  CAS storage and the ZBuild projection were already live; the local
  search/index projection is now live too: `vcs_zcode_task_index` is rebuilt
  from the persisted task/candidate wires on every call and the typed
  `zcode tasks` surface lists it.

<!-- claim: file-present lib/vcs/include/vcs/zcode_task_index.h # rebuildable dev-task index projection over the workspace CAS -->
<!-- claim: symbol-present vcs_zcode_task_index_build lib/vcs/src/zcode_task_index.c # projection rebuilt from CAS wires on every call -->
<!-- claim: symbol-present zcl_native_handle_zcode_tasks tools/command/native_zcode_dev_command.c # typed task list/search surface -->
- [x] Publish a bounded code-index context capsule whose members resolve to
  the task's immutable source root. V1 uses an exact symbol/stable ID; semantic
  goal selection remains adapter policy rather than context authority.

### B. Complete the existing local ZBuild worker

- [x] Add lease owner, lease token, lease expiry, attempt count, heartbeat, and
  cancellation observation to the existing build action ledger through an
  idempotent migration and model-owned writes.
- [x] Claim `QUEUED` actions atomically. A restart requeues an expired lease; a
  live lease cannot be stolen.
- [x] Execute only registered fixed action kinds. Compile consumes one exact
  candidate-manifest preprocessed TU followed by fixed `cc -x cpp-output -c`.
  Package reconstructs the complete candidate tree from CAS, verifies the
  exact installed dependency closure, then compiles, links, and tests only the
  canonical recipe under the external verifier. Test executes one exact
  candidate-manifest Linux x86-64 executable with no arguments and emits a
  closed 84-byte verdict wire. Fuzz executes one exact executable for the
  policy's canonical seed range `[0,N)`, supplies only `--seed=N` plus the
  matching scrubbed environment value, stops on the first failure, and emits a
  closed 96-byte evidence wire. All three use the existing package verifier's
  Landlock/seccomp/rlimit/no-network confinement.
- [x] Establish Landlock, seccomp, rlimits, a scrubbed fixed environment
  allowlist, fixed virtual paths, no network, bounded stdout/stderr,
  cancellation publication checks, and a hard deadline before untrusted bytes
  run. The worker polls the durable cancel state at most every 100 ms and
  SIGKILLs the verifier's whole process group, so compiler/test/fuzz
  descendants cannot outlive a cancelled lease.
- [x] Fetch inputs only by immutable CAS root. Recheck task, candidate, policy,
  action input, source, toolchain, fixed flags/environment, signer, and lease
  before execution and again before receipt publication. Canonical dependency
  lock and acceptance-recipe bytes travel in the same bounded content.v2
  context and are root/readback/membership verified on both peers. Every
  candidate file travels as an ordinary content.v2 member and must reconstruct
  the exact candidate ZVCS manifest before remote ZBuild admission.
- [x] Store output chunks and a build-artifact manifest in the existing CAS,
  then sign `work_receipt.v1` and the existing ZBuild receipt projection. A
  package action stores the canonical build report and all declared outputs;
  dependency archives have fixed lock order and per-package lexical order.
  The database projection binds the canonical receipt root; the wire remains
  CAS authority.
- [x] On timeout, crash, cancellation, malformed output, stale state, or sandbox
  failure: record a named outcome and use the existing local fallback policy;
  bounded action deadlines prevent an indefinite wait.

### C. Typed local path

The first typed adapters now exist on the existing `zcode` branch; no
bash-only authority:

- [x] `zcode create` — plan or commit a declarative C23 package through the
  existing signed package publication lifecycle.
- [x] `zcode use` — resolve/fetch/plan/commit an exact root-pinned dependency,
  reusing `zcode package add` and its lock/install receipts.
- [x] `zcode evidence` — reconstruct and evaluate the candidate-wide immutable
  proof set from canonical receipts.
- [x] `zcode accept` — record CANDIDATE proof readiness after the corresponding
  task-owned fast proof bar passes; this expert route cannot create PROVEN.
- [x] `zcode work accept` — make the explicit human decision and sign the exact
  PROVEN accepted-work root after the complete proof policy passes.
- [x] `zcode lane` — verify and inspect the latest signed CAS lane receipt by
  authoritative source root.
- [ ] `zcode improve` — plan a task, build a bounded context, invoke a selected
  adapter, admit candidate trees, schedule proofs/reviews, reproduce, explicitly
  accept, and publish.

`zcode improve mode=plan` now admits canonical task/policy/goal objects in the
existing workspace CAS after deriving the source root from a stable,
readback-verified ZVCS tree capture, derives and stores canonical
`write_scope.v1`, parses/stores/readback-verifies the existing canonical
dependency lock and declarative acceptance recipe, and publishes a bounded
exact-symbol `agent_context.v1`. It returns only immutable task, context,
model-policy, proof-policy, and toolchain roots with state
`AWAITING_CANDIDATE`; it does not
launch a model, create a build database, or grant tools. The operator can give
those roots to Codex, Claude, Kimi, a local model, or a future P2P harness under
their own policy.

`zcode improve mode=admit` derives the candidate tree and patch from
`candidate_workspace`, admits the exact candidate-bound action input, captures
the GCC capsule, and queues a candidate-bound preprocessed compile,
recipe-derived package, exact-test, or deterministic-fuzz action. An explicit
admit must carry `planned_task_root`,
`planned_context_root`, and the same `write_scope_csv`; source, task, context,
scope, candidate, and patch are recomputed before ZBuild admission. Omitting
`mode` retains the legacy one-shot form. Reusing `candidate_created_unix` with
the same immutable inputs schedules additional proof actions for the exact same
candidate. Before submission it creates or re-verifies the exact candidate's
signed FRONTIER receipt; evidence aggregation follows task/candidate/policy roots across
their distinct durable jobs. A local worker emits the canonical signed work
receipt. It also records the exact compile/package/test/fuzz request intent.
It returns after the existing ZBuild action and a deterministic
`REQUESTED` event are durable. The ordinary full-node swarm tick later builds
the exact context package, discovers an eligible advertised peer under the
requester's local policy, and sends the already-frozen work frame. `remote_peer`
is only an optional hint; an unavailable package store, peer, or capability
leaves the request durably pending and preserves the local action. Adapter
invocation and fixed review execution remain separate missing stages. Explicit
lane acceptance is live through `zcode accept`; an accepted PROVEN lane can now
be planned and committed through the offline-signed publish workflow.

`zcode evidence` re-reads every canonical receipt from CAS, rechecks task,
candidate, fixed action kind, input, policy, toolchain, signature, expiry,
proof age, and worker approval, then emits the exact `proof_set.v1` root. A
remote receipt is stored as `REMOTE_OBSERVED`; it advances only to
`LOCAL_REPRODUCED` when a local accepted action has the same output, or to
`QUORUM_MATCHED` when that proof class meets the task's minimum with approved,
non-revoked signers. Compile outputs must match exactly. Test and deterministic
fuzz receipts are counted independently. An approving review counts only when
its `review.v1` reviewer key matches the receipt signer and its referenced
proof set consists entirely of trusted non-review evidence for this candidate.
The typed result reports every class separately and refuses to claim final
release-byte identity from a translation-unit object.

### D. Requester-coordinated P2P work

- [x] Freeze signed capability/request/result/cancel frames. Requests bind the
  semantic object roots plus one content.v2 context-package root; advertisements
  bind target, capsule, confinement, ceilings, slots, headroom, and expiry.
- [x] Verify exact result bindings and count only approved, distinct signers
  returning one matching output root toward quorum.
- [x] Dispatch those frames over the existing `zpkgswm` peer sessions. The
  bounded adapter authenticates capabilities, rejects replay/unrequested/
  altered frames, preserves requester-selected peers, and schedules the exact
  content.v2 context root through the existing package fetcher.
- [x] Drain a complete, canonical fetched context into the existing ZBuild
  ledger, propagate signed cancellation, and return the accepted action's
  canonical receipt/result. A requester retry after worker restart reattaches
  to the idempotent durable action; no in-memory request queue is authority.
- [x] Persist verified requester results in the same build-receipt ledger and
  workspace CAS as explicitly `REMOTE_OBSERVED`, then drive local reproduction
  or the task-selected distinct approved-signer compile quorum. The canonical
  proof-set root is stored for later `review.v1` binding.
- [x] Advertise bounded action kinds, toolchain capsule, target, confinement
  facts, resource ceilings, queue headroom, and expiry. The live worker
  advertises preprocessed compile, recipe-package, exact-test, and
  deterministic-fuzz execution. Review
  remains unadvertised until an executor can actually author a review.
- The requester owns job selection, leases, cancellation, quorum, and local
  fallback. There is no global scheduler.
- Reuse package swarm/CAS transfer for immutable task inputs and artifact
  manifests. Add strict work-request/cancel/result frames; never embed a shell
  command or mutable path.
- A peer result is untrusted until the requester either reproduces it locally
  or obtains the selected number of matching independent receipts.
- Replayed, duplicate, revoked, expired, wrong-action, wrong-toolchain, and
  stale-source receipts are named refusals.

The zero-wait lifecycle is an append-only projection inside that same build
ledger: `REQUESTED`, `PEER_DISCOVERED`, `CONTEXT_READY`, `RUNNING`,
`REMOTE_GREEN` or `REMOTE_RED`, `RECEIPT_VERIFIED`, `REPRODUCED`, and
`READY_FOR_ACCEPTANCE`. A newer candidate appends `SUPERSEDED` to older active
candidates without deleting their receipts. Each row has a deterministic event
root binding the authoritative source, task, candidate, policy, action,
context, receipt, peer, request, deadline, prior event, and timing. Executors
sign the `CONTEXT_READY` and `EXECUTION_STARTED` observations on the existing
work swarm; requester state never claims `RUNNING` merely because a request
was sent. The request ID is derived from the immutable action root, so an exact
repeat attaches to the first request rather than consuming another peer slot.
These rows are lifecycle projection only:
signed `work_receipt.v1` remains evidence, local reproduction remains trust,
and the signed lane transition remains human acceptance.

The architectural direction is one-way:

```text
REFLEX -> ASYNC PROOF -> ACCEPTANCE -> PUBLICATION / REPLICATION
```

Discovery, context packaging, package transfer, remote queueing, remote
execution, and receipt verification run after the foreground response. The
foreground result reports `local_submit_us` and `local_first_feedback_us`.
`zcode evidence` reports peer discovery, transfer, remote queue, remote
execution, receipt verification, and total background proof latency separately
from those two local measurements. A remote slowdown therefore cannot be
hidden inside local feedback, and no discovery, DHT, transfer, publication,
storage-ACK, or proof-completion path is a prerequisite of REFLEX.
`zcode work run` accepts the local full node's `datadir` as an optional ledger
location; without it, the existing isolated scratch ledger remains the local-
only default. The path is only a local locator: every dispatched byte and
receipt is still re-derived and checked against the event's immutable roots.

`make zcode-async-proof-acceptance` is the hermetic protocol gate. It runs the
user-facing work path plus the durable ledger and three interchangeable signed
work-node topology: B's expired lease is discarded, the same immutable request
is retried on C, B's stale result and duplicate C delivery are refused, and
after A disappears B originates fresh work to C. The existing frame tests in
the same exact group reject malformed signatures and root mismatches; the
no-Git gate proves this path has no GitHub/Git dependency.

### E. Durability lanes

Every source root is independently in one immutable lane:

```text
FRONTIER  ->  CANDIDATE  ->  PROVEN
```

- FRONTIER keeps moving under fast deterministic proof policy.
- CANDIDATE pins one exact source root for multi-node, restart, disruption,
  and chaos evidence.
- PROVEN contains only roots whose long-duration policy is complete.
- A durability failure attaches to and blocks promotion of that root only. It
  publishes a reproducible work receipt and seeds a new task. It never freezes
  unrelated FRONTIER work.

Promotion is a signed projection over immutable source and proof-set roots,
not a mutable branch name. Publication may name lanes for discovery, but names
never replace roots.

The local transition chain is live: `zcode improve` admits FRONTIER,
`zcode accept --lane=CANDIDATE` applies the fast compile/test bar, and
`zcode accept --lane=PROVEN` applies the full policy. The missing portion is
the fixed multi-node restart/disruption/chaos action set and automatic
failure-to-task conversion; no current command claims that evidence exists.

<!-- claim: file-present lib/vcs/include/vcs/zcode_lane.h # canonical signed lane receipt -->
<!-- claim: symbol-present zcode_lane_advance app/services/src/zcode_lane_service.c # sequential proof-gated promotion -->
<!-- claim: symbol-present zcl_native_handle_zcode_accept tools/command/native_zcode_dev_command.c # explicit operator acceptance -->

## Acceptance demonstrations

The first network proof uses independent nodes and no GitHub or central
service:

1. publish and fetch a declarative C23 package;
2. submit a seeded bug-fix `task.v1`;
3. obtain a remote candidate tree and signed work receipt;
4. obtain independent build and test receipts;
5. reproduce the selected candidate locally;
6. explicitly accept it and publish the new signed release;
7. restart every participant and prove the task, leases, candidate, evidence,
   acceptance, and release remain reconstructible from durable objects.

The self-hosting milestone repeats the path for a real Zclassic23 change.

## Creation-backed issuance ordering

Real ZC23 genesis, payouts, and decentralized custody remain owner-gated later
work. First make useful development produce trustworthy, reproducible receipts
and challenge-mature PROVEN lanes. Then `creation_attribution.v1` may assign
policy capacity to accepted public source, born-red defect tests, security
repairs, independent reproduction, structured negative findings,
compatibility maintenance, or demonstrated preservation. Exact epoch
attribution must equal actual MINT; unused capacity expires. Self-reported CPU
time, uploads, bandwidth, patronage, balance, votes, popularity, and storage
volume earn nothing by themselves. Full policy:
[`ZC23_LIVING_COMMONS.md`](./ZC23_LIVING_COMMONS.md).
