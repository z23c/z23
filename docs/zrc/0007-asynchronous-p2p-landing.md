<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# 0007: Asynchronous p2p landing

| Field | Value |
|---|---|
| ZRC | 0007 |
| Title | Asynchronous p2p landing |
| Status | draft |
| Owner | orchestrator |
| Created | 2026-09-05 |
| Supersedes | none |

## Problem

Landing a change on `main` today runs through a train: a node hand-assembles
at most four lanes into one stack worktree, rebases the stack onto the exact
current `origin/main` tip, proves the whole stack once, and pushes
(see [`../agent/TRAIN_PROTOCOL.md`](../agent/TRAIN_PROTOCOL.md)). Six
properties of that machine are the cost.

- **The proof is whole-tree and pair-keyed.** A receipt is named for the
  commit pair that produced it — the pre-push hook reads
  `.cache/zcl-dev-proof/receipts/<local>-<base>.receipt`
  (`tools/dev/z23_git_hook.c`, `admit_pair`) — so any rebase discards it even
  when every input byte is unchanged. Measured on this fleet, one proof takes
  about eighteen minutes for a three-file change, and the recorded proof
  duration per box is fifteen to forty-five minutes.
- **One red group refuses everything.** A dimension counts complete only with
  zero failed and zero skipped (`tools/dev/dev_proof_receipt.c`,
  `dimension_complete`), and the runner fails closed on the first dimension
  that failed before any receipt is written (`tools/dev/dev_proof.c`). There
  is no comparison against the base, so red gates already on `main` refuse
  every unrelated change until someone fixes them.
- **A failing lane blocks the batch.** `dev train build` cherry-picks lanes
  into one worktree and returns `conflict` for the whole stack on the first
  conflicting source (`tools/command/native_dev_train_command.c`); there is no
  per-lane isolation and no drop-and-continue, so the next train stacks on the
  blockage.
- **Landing is single-box and human-driven.** The native queue's state lives
  under one host's state root, its rows are unsigned and not content-addressed,
  its host-wide `slot.lock` is explicitly not a fleet-wide gate
  (`tools/command/native_dev_land.c`), and nothing calls `step` — a shell loop
  with a sleep does. Work moves between boxes as bundles over a side channel.
- **The same change is verified three or four times.** Lane gates, a verify
  pass, the proof, and a full lint pass each rebuild and re-run the same
  groups, because no verdict survives across a box or across a rebase.
- **Nothing waits on a row.** The only real condition wait in the tree is
  in-process (`engine/modules/event/src/event.c`), and the board exposes counts
  to poll rather than a row to block on
  (`engine/composition/commands/fleet_board.def`), so every driver is a poll
  loop.

The object vocabulary for the replacement is already frozen in
[`../work/CANONICAL_LIFECYCLE.md`](../work/CANONICAL_LIFECYCLE.md):
`NEED -> JOB -> CANDIDATE -> PROOF_SET -> PUBLICATION -> REMOTE_RECEIPT`. That
document defines the objects and the publication predicate. It does not define
how the objects reach another node, who proves what, or when two changes may
land without waiting for each other. This ZRC defines exactly that, and nothing
else.

## Design

### 1. Three objects, gossiped

Each object is a fixed-field record, canonically encoded, digested under its
own domain with SHA3-256, and signed with the node's durable Ed25519 online key
— the same key `boot_fleet_board_identity` already loads or creates for board
posts (`engine/composition/src/boot_fleet_board.c`), which needs no on-chain
identity and no fee.

**CANDIDATE.** `job_root`, `base_commit`, `head_commit`, `bundle_manifest_root`,
`changed_set_root`, `changed_paths` (sorted, repo-relative), `impact_groups`
(sorted routed group names), `impact_closure_root`, `author_pubkey`,
`signature`. `changed_set_root` is the digest `tools/dev/dev_proof.c` already
computes over the changed-files list under `zcl.dev_proof_changed_set.v1`;
`impact_closure_root` is the digest it already folds from
`cognition/controllers/include/controllers/agent_impact_rules.def` and the
rendered plan under `zcl.dev_proof_impact_plan.v1`. The sorted sets are carried
as well as sealed, because disjointness is a set test and a digest cannot
answer it.

**PROOF_SET.** A set of verdict rows for one candidate. Each row carries
`group`, `closure_digest`, `toolchain_fingerprint`, `verdict` (`pass` or
`fail`), `observed_unix`, `prover_pubkey`, `signature`. `closure_digest` is the
key the per-group test cache already computes: SHA3-256 over the group's
forward input closure plus the toolchain fingerprint plus the coverage-gating
environment (`tests/harness/include/test/testcache.h`). A row is keyed by its
inputs, not by a commit, so it outlives every rebase. Rows from different
provers combine into one set; a candidate's PROOF_SET is whichever rows cover
its routed groups, whoever produced them.

**PUBLICATION.** `candidate_root`, `proof_set_root`, `expected_base`,
`head_commit`, `outcome` (`accepted` or `rejected`), `attempt_unix`,
`author_pubkey`, `signature`. The chain field is `expected_base`: a PUBLICATION
extends another when its `expected_base` equals that one's `head_commit`, so
the publication ledger is `main`'s own history and any node verifies the chain
by fetching `main` rather than by trusting a gossiped sequence.

**How they move.** All three ride the frozen `zpkgswm` carrier the fleet board
already rides — no new P2P command, no new listener, no new port. Each gets a
frame magic and the same three frame types the board uses: INV ("I hold these
ids"), GET ("send me these ids"), POST (one whole signed row), with the same
id-list ceiling per frame and the same paging-cursor backfill and announce
period (`cognition/modules/session/include/session/fleet_board_proto.h`,
`engine/composition/include/config/boot_fleet_board.h`). Dispatch is three more
legs on the frame multiplexer chain in
`engine/composition/src/boot_zcode_swarm.c`, answered whether or not swarm
hosting is on, exactly as the board's leg is.

Bodies split by size. A verdict row and a PUBLICATION fit inside
`VCS_BLOB_MAX_BYTES` and ride `blob_store` verbatim. A candidate's git bundle
does not; it is published as an ordinary one-file `content.v2` package, keyed
by its manifest root, chunked at `VCS_PACKAGE_CHUNK_BYTES` and fetched over the
package swarm's existing manifest-then-chunk path. The gossiped CANDIDATE row
carries only the manifest root, so a candidate transfers between nodes with no
shared remote and no side channel.

### 2. The replicated signed table seam

Adding a row kind by copying the board costs roughly eleven hundred lines: a
schema def, a migration, a proto module with its own domains and its own
canonical/sign/verify/encode/decode, a composition adapter with its own peer
slot table and rate limiter, a model layer, an RPC registration, and a leaf —
none of it parameterized over a table.

Extract that once. A **replicated signed table** is a descriptor: table name,
schema `.def`, domain strings for id and signature, frame magic, size caps,
announce period, and rate-limit ceilings. One generic proto canonicalizes,
signs, verifies, encodes and decodes any descriptor's rows; one generic
composition adapter owns the peer slot table, the admit and flood limiter, the
announce tick and the INV/GET/POST handlers for any descriptor; one generic
model layer provides `have`, `ingest`, `ids_before` and `find`. The fleet board
becomes the first client of the seam with no wire change — same magic, same
body encoding, same caps — and CANDIDATE, PROOF_SET and PUBLICATION are three
more descriptors. The fourth kind then costs a descriptor and a field list, not
a fourth copy.

### 3. The prover market

Any node advertises spare capacity as an ordinary board `offer` post; the board
already carries that kind, so advertisement needs no new machinery. Provers
**pull**: a node reads the CANDIDATE rows it holds, picks one it has capacity
for, fetches the bundle from the package swarm, and proves. Duplicate proving
is legal and merely wasteful; it is never an error, and no lease, claim or
queue position grants the right to prove.

A **proof of a candidate is the routed groups whose closure digests lack a
trusted verdict row** — nothing more. When every routed group already has one,
the candidate needs no build at all.

Four changes in `tools/dev/dev_proof.c` and its neighbours make that skip real.
Today the group key is computed inside the test binary, which exists only after
the compile dimension has run `make build-only` and the bundle step has run
`make dev-proof-bundle`; the runner then sets the verdict store root to the
local checkout before probing. So:

1. **Move the keyer out of the test binary.** The closure walk and the depfile
   graph it depends on (`codeindex_forward_closure`,
   `codeindex_depfile_graph`, used by `tests/harness/src/testcache.c`) move into
   a module the prover links, so a group key is computable from a checkout and
   its depfiles with no freshly built test binary.
2. **Take the toolchain fingerprint from the receipt, not from a compiled-in
   string.** The key's toolchain half stops being `testcache_toolkey()` and
   becomes the `compiler_root` and `flags_root` pair that
   `zcl_dev_proof_build_identity_v1_capture` already captures before any
   dimension runs, from the deterministic capsule
   (`contexts/commons/modules/vcs/include/vcs/build_action.h`) — content of the
   compiler driver, backend, assembler version, sysroot, target probes and ABI
   files, with no mtime and no path.
3. **Unpin the verdict store.** `dev_proof.c` sets `ZCL_TESTCACHE_STORE_ROOT`
   to its own checkout root, which makes every verdict box-local. It points at
   the node's replicated verdict store instead, so a row another node signed is
   visible to this prover.
4. **Probe before the build, not inside the test dimension.** A probe pass runs
   as soon as the routed group set is known and before the compile branch. When
   every routed group has a trusted verdict at its key, the compile and test
   dimensions are marked reused the way whole-cycle reuse is marked today, and
   neither `make build-only` nor `make dev-proof-bundle` runs.

The skip stays fail-closed. A group the cache calls uncacheable — truncated
closure, unresolved entry symbol, external-input denylist, absent depfile
graph, an input newer than the graph's newest depfile — has no key, so it is
always routed and always runs. A missing verdict service admits nothing.

Policy version two already makes this sound across boxes: the receipt roots are
path-neutral by construction. The build-plan hasher drops `COMPILER_ID` and
rewrites the checkout's absolute root to a fixed virtual token before hashing,
and `PATH` is deliberately excluded from the environment root, so two boxes
with one toolchain compute identical roots for identical source.

### 4. Commuting: the queue is a DAG

Two candidates **commute** when their impact closures are disjoint — no shared
routed group and no shared changed path. Commuting candidates land in either
order, with no rebase and no re-proof, because a verdict row is keyed by a
group's forward input closure rather than by a tip: a change that cannot reach
a group cannot invalidate that group's verdict.

The queue is therefore a directed acyclic graph, not a train. There is an edge
from one candidate to another when their closures intersect; landing order is
any topological order of that graph. A candidate whose closure is disjoint from
everything landed since its base needs no rebase at all. A candidate that does
intersect rebases and re-proves **only the intersecting groups** — its other
verdict rows survive the rebase untouched.

Nothing compares two changes this way today: `changed_set_root` is a receipt
root, but no code path in `tools/dev` reads two of them and asks whether they
are disjoint. That comparison is the whole of what replaces train assembly.

### 5. No new red

Admissibility is a comparison against the base, not an absolute.

A candidate is **admissible** when, over its routed group set, no group is
`pass` at `base_commit` and `fail` at `head_commit`, and every group that is
`fail` at both is either untouched by the change or fixed by it. A group with
no signed verdict at the base is treated as `pass` at the base: absent evidence
is never read as a pre-existing failure, so a new red cannot hide behind a gap.

This needs one change in what the verdict store keeps. The per-group cache
stores only passes today, which makes a red at the base unrepresentable. The
replicated verdict table carries `fail` rows too, signed the same way; a fail
row is evidence about inputs, not a cached skip, and it is never consulted to
skip work.

`make lint` joins the same table. Each gate in the lint set becomes a named
group with its own closure key and its own verdict row, so a red gate is one
red row against one gate's inputs. Five red lint gates then block the five
candidates whose closures reach them and nothing else, instead of refusing
every push until someone fixes them.

### 6. Trust

Gossip is open; admission is not. The board accepts any correctly self-signed
post from any host key, and the replicated table keeps that property — a row
says only that this key made this statement. Landing adds a second, narrower
test on top.

A verdict row counts toward a candidate only when it carries a signature that
verifies, its signer is on the allowlist, and its `toolchain_fingerprint`
matches the candidate's. A group is covered when **K** such rows agree. `K` is
one for keys the owner controls; a higher `K` for keys the owner does not,
declared by policy rather than by code.

The allowlist becomes signed rows on the same seam instead of a file each box
edits by hand. The verification mechanism is already right — a pubkey is
trusted only when it is this box's own key or listed in the allowlist,
`zcl_dev_proof_signer_verify` — only the distribution is manual, and a fifth
descriptor fixes that.

Every refusal is named, never a boolean. The existing vocabulary is kept
(`signer_unknown`, `signature_invalid`, `receipt_schema_old`,
`remote-base-not-ancestor`, `child-receipt-missing-or-invalid`) and extended
with `verdict_quorum_short`, `verdict_toolchain_mismatch`, `verdict_new_red`,
`candidate_closure_conflict` and `publication_base_moved`. A refusal names the
asset it protects, so its next step is legible.

### 7. Publication

Any node holding a candidate with full verdict cover attempts an ordinary
fast-forward push with `expected_base` set to the `main` tip it observed. Git
decides the race; no lease, board row, queue position or host identity grants
the right to attempt it. Both outcomes emit a PUBLICATION, because losing a
race is a fact worth recording rather than an error to hide.

A node whose push is refused because the base moved re-fetches, then
**re-checks commutation** against what landed. When its closure is disjoint
from the landed change, it publishes again against the new `expected_base`
carrying the same verdict rows — it never re-proves what commutes. When the
closures intersect, it rebases and re-proves only the intersecting groups.

The public git remote is a mirror of this ledger, not its authority: the
PUBLICATION rows and `main`'s own history are the record, and the remote is
where the bytes go. The pre-push hook keeps its place as the last gate; its
local pair-keyed receipt read becomes the fallback behind a root-cover check
over the replicated verdict table, and a missing table admits nothing.

### 8. Wake

No leaf blocks on a row today, so every driver polls. Add a `--since` wait leaf
on each replicated table — `fleet.board.wait --since <seq>` and its siblings —
implemented on the engine's existing condition wait: the ingest path signals a
process-local condition variable and the handler blocks on it under a bounded
timeout, returning the rows that arrived. An agent waiting for a verdict, a
candidate or a publication blocks on the row it needs.

This is what lets the landing scheduler stop being a shell loop with a sleep:
`step` still returns immediately and still waits for nothing, and the thing
that calls it is woken by a row rather than by a timer.

### 9. What is deleted

- **The train.** At most four lanes per train, one train per base fleet-wide,
  and the box lock held from claim to result all exist only because a receipt
  is keyed by a commit pair. Per-group closure keys remove the pair key and the
  train with it. [`../agent/TRAIN_PROTOCOL.md`](../agent/TRAIN_PROTOCOL.md) is
  reduced to a note pointing at the lifecycle, as
  [`../work/CANONICAL_LIFECYCLE.md`](../work/CANONICAL_LIFECYCLE.md) already
  requires.
- **Train stacks as durable state.** `dev train build|check` and its stack
  worktrees, replaced by CANDIDATE bundles.
- **The in-tree shell landers.** `tools/dev/land.sh`, `tools/dev/land_lander.sh`
  and `tools/dev/land_bench.sh`.
- **The out-of-tree landing loops**, none of which is replaced by another
  script: `land_train_now.sh` (drives `step` on a sleep), `stack_land_loop.sh`,
  `stack_land_loop2.sh`, `stack_land_loop3.sh` (cherry-pick, conflict
  auto-resolve, a hand-held proof lock and the push), `relint_land.sh`,
  `land_chain.sh`, `land_when_admitted.sh`, `proof_stack.sh`, and the
  cross-box transports `remote_gate.sh`, `remote_unit.sh` and
  `remote_review.sh`.
- **The host-local slot lock as a landing gate.** It survives as scheduling
  scratch for one host's own worktree and never decides who may land.
- **The whole-tree generation build** for any candidate whose routed groups
  already carry trusted verdicts.

### 10. Migration order

Each stage lands on its own and leaves the tree working.

1. Extract the replicated signed table seam; the board becomes its first
   client with no wire change.
2. Land CANDIDATE, PROOF_SET and PUBLICATION as descriptors on that seam,
   with the bundle riding the package swarm.
3. Move the group keyer out of the test binary and unpin the verdict store.
4. Probe before the build in the prover, so a fully covered candidate skips
   the generation build.
5. Add the commutation test and turn the queue into a DAG.
6. Add the no-new-red comparison and per-gate lint rows.
7. Add the wait leaf and delete the loops and the train.

## Acceptance

Each stage is measured, not asserted. The token and wall figures come from the
fleet's own experiment rows; the rest are gate outcomes.

| Stage | Measurement | Pass |
|---|---|---|
| 1 | Lines added for the seam versus lines deleted from the board's per-table copies | net lines fall; the board's wire bytes are unchanged, proved by a round-trip test against captured frames |
| 2 | A candidate created on one node is fetched, verified and its bundle reconstructed on another with no shared remote | the reconstructed range digest equals `bundle_manifest_root` |
| 3 | A group key computed by the prover equals the key the test binary computes for the same group | equal for every routed group in the catalog |
| 4 | Median wall from CANDIDATE row to PUBLICATION row for a change whose routed groups are all covered | falls below the cost of one generation build; no `build-only` process is spawned |
| 5 | Two candidates with disjoint closures submitted against one base | both land, neither rebases, neither re-proves; a third with an intersecting closure re-proves only the intersecting groups |
| 6 | A candidate that touches nothing a pre-existing red group can reach, submitted while that group is red | admitted; a candidate that turns a green group red is refused as `verdict_new_red` |
| 7 | Proofs per hour per box, and tokens per landed line from the experiment rows | proofs per hour rise; tokens per landed line fall; no process sleeps in a landing path |

The whole-design measure is the median wall from a CANDIDATE row to its
PUBLICATION row, recorded per stage so the curve is visible rather than claimed
once at the end.

## Out of scope

This ZRC does not redefine the object vocabulary or the publication predicate;
both are fixed in
[`../work/CANONICAL_LIFECYCLE.md`](../work/CANONICAL_LIFECYCLE.md). It does not
add NEED, JOB, CLAIM or REMOTE_RECEIPT, which that document already owns. It
does not change what a gate checks, only how many times and where a gate's
verdict is checked. It does not propose a scheduler that assigns work to a
prover: provers pull, and matching a candidate to a prover by cost is a later
proposal. It does not change the deterministic build environment
([`0003-deterministic-build-environment.md`](0003-deterministic-build-environment.md)),
which it consumes as the toolchain fingerprint.

## Landing

Empty while this ZRC is `draft`.

## Discussion

Board rows carrying `zrc-0007`, per
[`../agent/NATIVE_CHANNEL.md`](../agent/NATIVE_CHANNEL.md), until the native
wiki in
[`0004-wiki-daily-board-public-page.md`](0004-wiki-daily-board-public-page.md)
carries the page for it.
