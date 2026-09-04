<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# One canonical landing lifecycle

Z23 has more than one machine for getting work onto `main`. This document
defines a single one: `NEED -> JOB -> CANDIDATE -> PROOF_SET -> PUBLICATION ->
REMOTE_RECEIPT`. Every durable object in it is immutable, signed,
content-addressed, and reachable from a root. Local databases and JSONL files
become rebuildable projections of that object log. Workers are replaceable
executors that never publish `main`.

It is written against the code that exists today. Each stage section names what
already produces the object and what must change. New fleet features are frozen
until this convergence lands.

## 1. The six stages

Common shape. Every object is a fixed-field record, serialized in one canonical
encoding, digested under its own domain string with SHA3-256, and signed with an
Ed25519 key held by its producer. The object's ROOT is that digest. An object
references another object only by root, never by file path, sequence number, or
host name. The existing precedent for the encoding-plus-domain discipline is
`tools/dev/dev_proof_receipt.c`, which seals a fixed 664-byte wire record under
`zcl.dev_proof_receipt.v1`; the existing precedent for Ed25519 signing of
evidence is the receipts lane's per-unit receipt module (dev_proof_unit_receipt.c,
not yet on `main`), which signs a receipt root with `vcs_signed_evidence_seal_root`.

### NEED

Fields: `need_root` (self), `statement` (the outcome sought), `acceptance` (the
predicate that closes it), `created_unix`, `author_pubkey`, `signature`.
Root: SHA3-256 over all fields except `signature`.
Created by: any node. A NEED grants nothing; it only names an outcome.
References: nothing. It is a lifecycle origin.

Today: nothing produces this object. The closest surfaces are prose items in
`docs/work/FORWARD_PLAN.md` and the story string passed to `dev.agent.claim`
(`engine/composition/commands/dev.def`), neither of which is durable, addressed,
or signed. Change: add the object and a `dev.need.*` leaf that emits it. No
existing code is re-keyed.

### JOB

Fields: `job_root` (self), `need_root`, `base_commit` (40-hex `main` tip the job
is cut from), `base_source_root` (tree digest at that commit), `scope` (the file
set the job intends to touch), `created_unix`, `author_pubkey`, `signature`.
Root: SHA3-256 over all fields except `signature`.
Created by: any node. Two JOBs may reference one NEED. That is legal.
References: a NEED root and a base commit.

Today: the nearest object is the land-queue row `struct dl_row` in
`tools/command/native_dev_land.c`, which already carries `tip`, `base`,
`worktree`, `note`, `state`, `phase`, `attempt`. It is a JSONL line keyed by an
incrementing `seq`, unsigned and not content-addressed. Change: re-key the row
from `seq` to `job_root`, drop `worktree` and `note` from the durable record
(they are local scratch, see section 3), add `need_root`, `base_source_root`,
`author_pubkey`, `signature`.

### CANDIDATE

Fields: `candidate_root` (self), `job_root`, `base_commit`, `head_commit`,
`bundle_digest` (SHA3-256 of a `git bundle` carrying `base_commit..head_commit`),
`closure_digest` (the input closure of the change, as `dev.agent.ticketkey`
already computes per group), `created_unix`, `author_pubkey`, `signature`.
Root: SHA3-256 over all fields except `signature`.
Created by: a worker. A worker may produce a CANDIDATE; it may not publish one.
References: a JOB root; carries the commit range as a signed bundle digest, so a
candidate is transferable without a shared remote.

Today: a candidate is an unaddressed side effect — a detached stack worktree at
`z23-stack<name>` built by `tools/command/native_dev_train_command.c`, or the
`tip` string in a land-queue row. Nothing digests the range and nothing signs it.
Change: add the object; teach the train builder to emit one instead of leaving a
worktree as the only record.

### PROOF_SET

Fields: `proof_set_root` (self), `candidate_root`, `ticket_roots` (the sorted set
of mandatory ticket roots), `policy_digest` (the digest of the policy that
declares which tickets are mandatory), `created_unix`, `author_pubkey`,
`signature`.
Root: SHA3-256 over the sorted `ticket_roots` plus `candidate_root` and
`policy_digest`.
Each TICKET is itself an immutable signed object keyed by
`SHA3-256(kind, unit, closure_digest, toolchain_digest, harness_digest,
policy_digest)`, carrying `verdict`, `host_id`, `ts`, `signature`. The verdict is
deliberately outside the key, so a pass and a fail for identical inputs collide
and are visible rather than silently coexisting.
Created by: any worker, for any ticket. A PROOF_SET is an assertion about which
tickets exist, not a permission.
References: a CANDIDATE root and a set of ticket roots.

Today: `tools/dev/dev_proof.c` and `tools/dev/dev_proof_receipt.c` produce one
whole-cycle acceptance receipt per run. It is close in spirit and wrong in three
ways.

- It is PAIR-KEYED. Receipt files are named `<local>-<base>` and stored under
  `.cache/zcl-dev-proof/receipts/`, and `zcl_dev_proof_receipt_validate` compares
  the raw commit bytes of that pair. A receipt is therefore addressable only by
  the two commits that happened to produce it, and any rebase discards it even
  when every input is unchanged. The pair key must be removed and replaced by the
  closure key.
- It is SEALED, NOT SIGNED. `zcl_dev_proof_receipt_seal` is a SHA3-256 over the
  record with the seal field zeroed. That detects local corruption and proves
  nothing about the producer, so a receipt cannot cross a host boundary. The
  receipts-lane per-unit receipt already fixes this with an Ed25519 signature and
  a `signers.allow` list; that design is the one to adopt.
- It is COARSE. The record carries four fixed dimensions (generated, compile,
  lint, test), each with one aggregate `receipt_root`. A ticket set must be
  per-unit, so an unchanged unit costs nothing.

Change: keep the field vocabulary — `source_root`, `changed_set_root`,
`compiler_root`, `flags_root`, `environment_root`, `build_graph_root` are all
useful — and re-key the object from the commit pair to the input closure, sign
it, and split the four dimensions into a set of per-unit tickets.

### PUBLICATION

Fields: `publication_root` (self), `candidate_root`, `proof_set_root`,
`expected_base` (the `main` tip the push asserts as the old value), `head_commit`,
`attempt_unix`, `outcome` (`accepted` or `rejected`), `author_pubkey`,
`signature`.
Root: SHA3-256 over all fields except `signature`.
Created by: the node that attempted the push, whether it won or lost. A rejected
PUBLICATION is a first-class object; losing the race is not an error to hide.
References: a CANDIDATE root and a PROOF_SET root.

Today: `tools/command/native_dev_land.c` runs `git push origin HEAD:main` with no
expected old value, relying on the server's default fast-forward refusal, and
records nothing addressable about the attempt. `tools/ship.sh` runs
`git push --no-verify origin main`, which bypasses the hook entirely.
`tools/lint/check_no_unattended_publish.sh` already forbids every other file from
publishing, so the allowlist is small and the change is contained. Change: use an
explicit expected-old-value push, and emit this object for both outcomes.

### REMOTE_RECEIPT

Fields: `remote_receipt_root` (self), `publication_root`, `fetched_main_tip`,
`fetched_main_source_root`, `observer_pubkey`, `observed_unix`, `signature`.
Root: SHA3-256 over all fields except `signature`.
Created by: any node, including one that did not attempt the push. This is the
only object that closes a cycle, and it is deliberately produced by re-fetching
and re-verifying rather than by trusting the pushing node's own report.
References: a PUBLICATION root.

Today: nothing produces this. The nearest behaviour is in `tools/githooks/pre-push`,
which fetches the remote ref when the advertised old value is missing locally and
then requires `git merge-base --is-ancestor`. That is a pre-flight check, not a
post-publication observation, and it is discarded. Change: add the object and
have `dev land` emit one after every push attempt, its own and any other node's.

## 2. The one publication rule

Let `C` be a CANDIDATE, `P` its PROOF_SET, `B` the observed `main` tip, and
`M(policy_digest)` the set of ticket keys the policy declares mandatory.

A push may be attempted if and only if all of the following hold.

1. `C.base_commit == B`. The candidate is cut from the tip being replaced.
2. `P.candidate_root == C.candidate_root`.
3. `P.policy_digest == policy_digest`, the digest of the policy in effect at `B`.
4. For every key `k` in `M(policy_digest)`, there exists a ticket `t` with
   `t.key == k`, `t.verdict == pass`, a signature that verifies against a key in
   the signer allow list, and `t.closure_digest` equal to the closure the
   candidate presents for that unit.
5. `root_cover(P) == M(policy_digest)`: the ticket set covers the mandatory set
   exactly. A missing key is a refusal; an extra key is allowed.

If the predicate holds, any node may attempt an ordinary fast-forward push with
`expected_base = B`. Git decides the race. The loser re-fetches, re-evaluates the
predicate against the new `B` — which changes `C.base_commit` and therefore the
closures — rebases, and re-enters at CANDIDATE. Nothing else grants the right to
push, and nothing else withholds it. No lease, no board entry, no queue position,
no host identity is consulted.

What the hook checks today. `tools/githooks/pre-push` rejects any ref other than
`refs/heads/main`, requires the remote tip to be an ancestor of the pushed tip,
computes the changed-file set between them, and then runs `make pre-push-ci`
scoped to those files. It does not look up a single receipt. It re-runs a local
CI pass for whatever `HEAD` is being pushed, every time. It therefore enforces
condition 1 and nothing else, and it enforces it by cost rather than by evidence.

What the hook must check. Conditions 2 through 5, by reading the signed ticket
set and comparing roots. Running work is the fallback for a missing ticket, not
the mechanism. A hook that finds full root cover exits without building anything.

What `dev land` checks today. It rebases, runs the queue, and pushes; the queue
row records `state`, `phase` and `attempt` but no roots. What it must check: the
same predicate, before the push, and it must record the PUBLICATION object
whether the push is accepted or rejected.

## 3. Projections

Rule: if it cannot be rebuilt from signed objects, it is not authority. Every
path below is a cache that may be deleted at any moment without losing a fact.

| Local state | Path | Rebuilt from |
| --- | --- | --- |
| Proof receipts | `.cache/zcl-dev-proof/receipts/` | the ticket objects |
| Dimension children | `.cache/zcl-dev-proof/children/` | the PROOF_SET root |
| Requests, attempts, leases, logs | `.cache/zcl-dev-proof/` subtrees | nothing; pure scheduling scratch |
| Land queue rows | `<state>/land/queue.jsonl` | JOB and CANDIDATE objects |
| Land outcomes | `<state>/land/outcomes.jsonl` | PUBLICATION and REMOTE_RECEIPT objects |
| Land chainlog verdicts | the `z23-land` record store, `tools/land/land_record.c` | the ticket objects |
| File-claim ledger | `<git_common_dir>/z23-agent-claims.jsonl` | CLAIM objects; advisory either way |
| Lane and stack worktrees | `z23-stack<name>`, lane checkouts | the CANDIDATE bundle |
| Flash unit receipts | each unit's `--state-dir`, `tools/engine_unit.c` | ticket objects, once units emit tickets |

Two consequences. First, `zcl_dev_proof_receipt_validate` stops being the
authority on whether work is proved; it becomes the integrity check of one cache
entry. Second, a node that loses `.cache` entirely loses time, not safety: it
re-derives the ticket keys from the candidate and asks the object store.

## 4. Workers

A worker claims, builds, tests, and produces candidates and tickets. It never
runs `git push origin main`.

Claims are objects, not locks. A CLAIM carries `claim_root`, `job_root`,
`worker_pubkey`, `expires_unix`, `signature`. Two claims for one JOB root are
legal and are not an error to report. A claim reduces duplicate work by making
duplication visible; it confers no right to land and no protection from being
overtaken. The later CANDIDATE with full root cover wins, by push.

This is a real change to `tools/command/native_devagent_claim.c`, which today
REFUSES a claim when any named file is live in another worktree's claim. Refusal
is authority. The command must report the overlap and proceed.

Stale results fail closed for free. A worker that finishes against an old base
produces a CANDIDATE whose `base_commit` no longer equals the observed `main`
tip, so condition 1 of the publication rule fails before anything else is
consulted. A stale lease needs no reaper: an expired CLAIM stops being
interesting, and the work behind it is judged only by whether its roots still
match. Crash of a worker mid-build loses a worktree and nothing else.

Worktrees are per-job scratch and are disposable. Nothing durable may live only
in a worktree. The train builder's `<stack_dir>/build/train-check.state` and
`train-check.log` are the current counterexample: they are the sole record of a
check result, and they die with the worktree.

## 5. Competing state machines to remove

| Name | Where it lives | Replaced by | Delete after |
| --- | --- | --- | --- |
| Bash stack landers | `tools/dev/land.sh`, `tools/dev/land_lander.sh`, `tools/dev/land_bench.sh` | PUBLICATION, driven by `dev land` | `dev land` emits PUBLICATION and REMOTE_RECEIPT objects and passes the acceptance harness |
| Human relay at the end of the lander | `publish_ready` in `tools/dev/land_lander.sh`, which leaves a gated `land/ready` branch for a person to push | the publication predicate, evaluated by the node that built the candidate | no path to `main` requires a person |
| `z23-land` chainlog queue | `tools/land/land_main.c`, `land_queue.c`, `land_record.c` | JOB, CANDIDATE, PROOF_SET | the ticket object carries the verdict digest `land_verdict_digest` computes today |
| Land JSONL queue as authority | `<state>/land/queue.jsonl` via `tools/command/native_dev_land.c` | JOB and CANDIDATE objects; the file stays as a projection | rows are re-keyed from `seq` to `job_root` |
| Train stacks as durable state | `tools/command/native_dev_train_command.c`, `z23-stack<name>` worktrees | CANDIDATE bundles | the train builder emits a CANDIDATE per stack |
| Board as a queue | the claim/result board `docs/agent/TRAIN_PROTOCOL.md` specifies (no code implements it), and the DHT projection `zcode task board` in `tools/command/native_zcode_task_transport_command.c` | NEED and CLAIM objects; board output stays advisory | the doc-only board is deleted rather than built, and no code path reads a board to decide whether to build or land |
| Claim ledger as a lock | `tools/command/native_devagent_claim.c`, `<git_common_dir>/z23-agent-claims.jsonl` | advisory CLAIM objects | an overlapping claim is reported, not refused |
| Artifact shipping over ssh | `tools/ship.sh` tar-over-ssh staging and its `git push --no-verify origin main` | CANDIDATE bundle plus ordinary git transport | deploys consume a REMOTE_RECEIPT instead of pushing |
| Proof pair-keying | `<local>-<base>` file naming in `tools/dev/dev_proof.c` | ticket keys over the input closure | no `.cache/zcl-dev-proof` path contains a commit pair |
| Per-host proof locks and leases | `queue.lock`, `<key>.running`, `<key>.lease` in `tools/dev/dev_proof.c`; the host-wide landing slot `slot.lock` in `tools/command/native_dev_land.c`; the lander's own box lock in `tools/dev/land_lander.sh` | nothing; scheduling scratch only | no code path treats a lock or a lease as permission to write a verdict or to push |
| Fleet receipt projection | `tools/command/native_dev_fleet_receipts.c` self-hash chain | signed ticket objects | it verifies signatures instead of `receipt_sha3=` self-hashes |
| Flash unit queue | `tools/engine_unit.c`, per-unit `--state-dir` receipts, `docs/agent/FLASH_UNIT.md` | JOB, CANDIDATE, ticket | a unit's `receipt.json` is derived from a signed ticket |
| Commuting tickets and train protocol as separate machines | `docs/agent/COMMUTING_TICKETS.md`, `docs/agent/TRAIN_PROTOCOL.md` | this document | both are reduced to explanatory notes pointing here |

`tools/lint/check_no_unattended_publish.sh` is retained and tightened: after this
convergence, exactly one call site may push `main`.

Retained unchanged, because they coordinate nothing: `tools/scripts/fleet_sync.sh`
fast-forwards one box to `origin/main` and restarts its unit, never committing or
pushing; the evidence-ledger append locks under `tools/scripts/` serialize writes
to local ledgers and decide no landing.

## 6. Acceptance harness

Target: three nodes, twenty consecutive cycles, exactly one landing per cycle, no
lost work, no human relay, `main` qualified at every observed tip. The first
form of every condition below runs on one host with three datadirs and three
checkouts against a local bare repository standing in for the remote; only the
partition and crash conditions need real hosts afterwards.

| Condition | Test | Pass criterion |
| --- | --- | --- |
| Three nodes | `lifecycle_three_node` group, three datadirs, one bare remote | all three complete a cycle |
| Duplicate jobs | `lifecycle_duplicate_job`: two nodes claim one JOB root | both produce candidates; one PUBLICATION accepted |
| Duplicate candidates | `lifecycle_candidate_race`: two candidates, same base | exactly one accepted; the other emits a rejected PUBLICATION |
| Partition | `lifecycle_partition`: block one node's remote access mid-cycle | the isolated node lands nothing and loses no candidate |
| Worker crash | `lifecycle_worker_crash`: kill a worker mid-build | its worktree is removed; no ticket with a partial verdict exists |
| Publisher crash | `lifecycle_publisher_crash`: kill between push and receipt | a later node emits the REMOTE_RECEIPT for that PUBLICATION |
| Stale lease | `lifecycle_stale_claim`: expire a claim, let the holder finish | the stale candidate fails condition 1 and is refused |
| Reordered events | `lifecycle_reorder`: deliver objects out of order | every object still resolves by root; no ordering assumption fires |
| Twenty cycles | `lifecycle_soak`: run the loop twenty times | twenty landings, twenty REMOTE_RECEIPTs |
| Exactly one landing | assert over the bare remote's reflog per cycle | one `main` advance per cycle |
| Main always qualified | `lifecycle_qualified`: replay every observed `main` tip | the publication predicate holds at each |

Each group is registered in `tools/dev/test_group_catalog.def` so a run that
executes nothing is visible as such. The harness asserts on objects, not on log
lines: a condition passes when the roots say so.

## 7. Order of work

Each lane owns a disjoint file set.

1. FULL LINT GREEN ON MAIN — in flight. Files: `tools/lint/`, `Makefile`.
   Done when `make lint` is green and the push proof covers the whole gate set.
2. RECEIPTS LAND — bring the receipts lane onto `main`. Files:
   `tools/dev/dev_proof.c` and the new per-unit receipt and lint-unit modules.
   Done when a ticket is signed, keyed by closure, and admissible across hosts.
3. HOOK CHECKS ROOT COVER — Files: `tools/githooks/pre-push`.
   Done when a push with full root cover builds nothing and a push with a missing
   mandatory ticket is refused by name.
4. `dev land` REPLACES THE BASH LANDERS — Files:
   `tools/command/native_dev_land.c`, `engine/composition/commands/dev.def`,
   `tools/lint/check_no_unattended_publish.sh`, and deletion of `tools/dev/land.sh`,
   `tools/dev/land_lander.sh`, `tools/dev/land_bench.sh`.
   Done when the expected-base push is the only push to `main` in the tree and
   both push outcomes emit a PUBLICATION.
5. CANDIDATES AS SIGNED BUNDLES — Files:
   `tools/command/native_dev_train_command.c`, the new candidate module.
   Done when a candidate transfers between checkouts by bundle digest alone.
6. ACCEPTANCE HARNESS — Files: the new lifecycle test groups and
   `tools/dev/test_group_catalog.def`.
   Done when the eleven conditions of section 6 pass twenty consecutive cycles.

NEED and CLAIM objects, and the retirement of the board, train, and flash
machines in section 5, follow lane 6. Until then those surfaces stay, marked
advisory, and no code path may read them to decide whether to build or to land.
