<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# One canonical landing lifecycle

Z23 has more than one machine for getting work onto `main`. This document
defines a single one: `NEED -> JOB -> CANDIDATE -> PROOF_SET -> PUBLICATION ->
REMOTE_RECEIPT`. Every durable object in it is immutable, signed,
content-addressed, and reachable from a root. Local databases and JSONL files
become rebuildable projections of that object log. Workers are replaceable
executors that never publish `main`.

This is the scoped foundation design for the first milestone in
[`FORWARD_PLAN.md`](./FORWARD_PLAN.md), which owns the full mission and ordered
continuation. Stage records below define target interfaces, not a claim that
all producers, transfer paths or admission rules are wired. Reuse existing
Commons objects and version their adapters instead of creating a second ledger.

## 1. The six stages

Common shape. Every object is a fixed-field record, serialized in one canonical
encoding, digested under its own domain string with SHA3-256, and signed with an
Ed25519 key held by its producer. A self root is derived, never recursively
included in its own digest. Distinguish a reusable input key, a domain-separated
signing message, and the root of the full immutable signed wire; new lifecycle
object roots bind the signature and producer as well as the payload. Preserve
existing versioned Commons root/signature contracts when adapting their objects.
References use object roots; Git IDs and local locators are separate provenance
or scratch. An input key is a lookup key, never an observation identity.

`tools/dev/dev_proof_receipt.c` already implements a signed pair receipt: a
664-byte body plus a 96-byte Ed25519 signer trailer. Its signed per-group verdict
leaf codec separately hashes all 328 signed wire bytes under
`zcl.dev_verdict_leaf_root.v1`. Reuse the existing signing and codec machinery.

### NEED

Fields: `need_root` (self), `statement` (the outcome sought), `acceptance` (the
predicate that closes it), `created_unix`, `author_pubkey`, `signature`.
Root: domain-separated SHA3-256 of the canonical signed wire, excluding self.
Created by: any node. A NEED grants nothing; it only names an outcome.
References: nothing. It is a lifecycle origin.

Historical landing-only gap: prose items in
`docs/work/FORWARD_PLAN.md` and the story string passed to `dev.agent.claim`
(`engine/composition/commands/dev.def`) do not establish this immutable object.
Change: map the outcome and acceptance into the existing signed task authority;
add a recurring native entry point only if existing task/story surfaces cannot
express it. A new lifecycle label does not require a new task system.

### JOB

Fields: `job_root` (self), `need_root`, `base_commit` (40-hex `main` tip the job
is cut from), `base_source_root` (tree digest at that commit), `scope` (the file
set the job intends to touch), `created_unix`, `author_pubkey`, `signature`.
Root: domain-separated SHA3-256 of the canonical signed wire, excluding self.
Created by: any node. Two JOBs may reference one NEED. That is legal.
References: a NEED root and a base commit.

The landing adapter currently uses the queue row `struct dl_row` in
`tools/command/native_dev_land.c`, which already carries `tip`, `base`,
`worktree`, `note`, `state`, `phase`, `attempt`. It is a JSONL line keyed by an
incrementing `seq`, unsigned and not content-addressed. Change: re-key the row
from `seq` to `job_root`, drop `worktree` and `note` from the durable record
(they are local scratch, see section 3), add `need_root`, `base_source_root`,
`author_pubkey`, `signature`, by binding existing task/action authority. Keep
sequence numbers only as local projection cursors.

### CANDIDATE

Fields: `candidate_root` (self), `job_root`, `base_commit`, `head_commit`,
`bundle_digest` (exact transferable candidate authority), `closure_digest`
(verified source/dependency closure manifest), `created_unix`, `author_pubkey`,
`signature`. A Git bundle may carry commit provenance; it does not replace
the canonical source and patch authority.
Root: domain-separated SHA3-256 of the canonical signed wire, excluding self.
Created by: a worker. A worker may produce a CANDIDATE; it may not publish one.
References: a JOB root; carries the commit range as a signed bundle digest, so a
candidate is transferable without a shared remote.

Existing Commons authority: `vcs_zcode_candidate_v1` in
`contexts/commons/modules/vcs/include/vcs/zcode_dev.h` has a candidate root.
`contexts/commons/modules/vcs/src/zcode_candidate_bundle.c` exports the exact
scope, patch, base/candidate manifests and changed blobs through existing
`content.v2`; import validates the closed wire before CAS writes and independently
rederives patch authority. Connect this to signed task and landing provenance.
The train builder in `tools/command/native_dev_train_command.c` and queue `tip`
remain landing projections to converge, not evidence that candidate transfer
must be invented. Navigator ticket keys are advisory until their full input
closure is independently established.

### PROOF_SET

Fields: `proof_set_root` (self), `candidate_root`, sorted `observation_roots`,
`policy_digest`, `coverage_root`, `created_unix`, `author_pubkey`, `signature`.
Root: domain-separated SHA3-256 of the complete canonical signed wire,
excluding self. Coverage binds the mandatory input keys derived for this
candidate and the receiver's eligibility/coverage basis.

A TICKET is an immutable signed observation with two distinct identities:

- `input_key`: domain-separated hash of actual kind, unit, source closure,
  dependency closure, compiler, flags, environment, build graph, harness and
  policy inputs. It excludes verdict, timestamp, elapsed time, producer and
  signature. Commit IDs are provenance, not substitutes for these inputs.
- `observation_root`: domain-separated hash of the full canonical signed
  observation, including the input key, verdict, time, producer, signature and
  any log/evidence bindings. Changing an observation creates another root.

PASS and FAIL for the same input key must coexist as different immutable
objects. Index the key to a set of observation roots; never overwrite, collapse
or choose the newest one to hide a contradiction. Receiver policy verifies
signatures, input identity, freshness and required coverage before classifying
eligibility. An unresolved conflict among eligible observations refuses
publication. An invalid or ineligible observation is retained with its reason;
a forged FAIL must not acquire authority merely by existing. A proof-set
producer cannot suppress a known eligible conflict by omitting its root.

Any worker may produce an observation or assemble a proof-set proposal. A
PROOF_SET grants no publication authority. Unchanged units may reuse eligible
observations when every required input matches; changed, missing or incomplete
closures require proof or a named refusal.

Current implementation: `tools/dev/dev_proof.c` produces signed whole-cycle
pair receipts through `tools/dev/dev_proof_receipt.c`, with generated, compile,
lint and test child dimensions. Pair naming remains an exact local push
admission envelope, not the reusable per-unit evidence key. The verdict-leaf
codec in the same module already separates its exact test-cache key from the
root of all signed observation bytes. Codec coverage is registered in
`tests/harness/src/test_dev_proof_signer.c`; runner emission, durable CAS/index
storage, conflict admission and canonical proof-set publication are separate
integration work. A codec alone does not establish a complete input closure.

The existing Commons evaluator in
`engine/services/src/build_fabric_evidence.c` now retains verified failures
through conflict inspection. Eligible PASS/FAIL disagreements and different
successful build outputs for the same action/input refuse with
`proof_observation_conflict` before proof-set materialization or trust promotion.
The registered `build_fabric` tests cover signed compile and package observations,
ineligible/forged failures, repeated successes and failure-only nonadmission.
This does not complete cross-candidate unit reuse or Git publication convergence.

Keep existing `source_root`, `changed_set_root`, `compiler_root`, `flags_root`,
`environment_root` and `build_graph_root` vocabulary. Wire per-unit observations
into canonical proof facts before deriving the compatibility pair envelope from
them; preserve exact-pair checks until that replacement is qualified.

### PUBLICATION

PUBLICATION is a durable intent recorded **before any remote ref mutation**.
Fields: `publication_root` (self), `candidate_root`, `proof_set_root`, target
repository identity/ref, `expected_base`, `head_commit`, `authority_root`,
`created_unix`, `author_pubkey`, `signature`. Root: domain-separated SHA3-256 of
the canonical signed wire, excluding self. Persist and verify the exact intent
in the existing action/CAS lifecycle before dispatch; failure to persist refuses
the push. Bind a receiver-approved target locator separately from public data.

Record each attempt as a separate immutable result referencing the intent:
`publication_result_root`, `publication_root`, attempt identity/time, observed
outcome (`accepted`, `rejected` or `unknown`), diagnostics/evidence roots,
producer and signature. Never rewrite the intent to add an outcome. Rejections
and uncertain acknowledgements remain first-class results. Duplicate dispatch
reconciles the existing intent and results before any further mutation.

Current landing adapter: `tools/command/native_dev_land.c` persists local queue
progress and pushes the exact prepared commit through its installed hook. It
checks the proven base is an ancestor of that commit with Git replacement
objects disabled, then binds the remote update to that exact expected base.
The expected-base lease cannot authorize non-fast-forward history replacement.
Its crash reconciliation is not the immutable intent/result/remote-receipt
chain defined here.
`tools/ship.sh` still contains `git push --no-verify origin main`; retire that
publication path without granting deployment authority. Retain the existing
publish-callsite gate. Use both verified fast-forward ancestry and a server-side
expected-base comparison; a compare-and-swap must never authorize history
replacement that ordinary fast-forward policy forbids.

### REMOTE_RECEIPT

Fields: `remote_receipt_root` (self), `publication_root`, target identity/ref,
`fetched_main_tip`, `fetched_main_source_root`, verified ancestry/evidence roots,
`observer_pubkey`, `observed_unix`, `signature`.
Root: domain-separated SHA3-256 of the canonical signed wire, excluding self.
Created by: any node, including one that did not attempt the push. This is the
only object that closes a cycle, and it is deliberately produced by re-fetching
and re-verifying rather than by trusting the pushing node's own report.
References: a PUBLICATION root.

Recovery does not require the publisher or its result to survive. Another
authorized observer resolves the persisted intent, fetches the exact target,
verifies source and ancestry, and emits a receipt. If the remote advanced again,
prove that the intended head is in its verified history rather than inferring
success from a different tip. An unavailable or ambiguous observation leaves
the operation unresolved; do not blindly repeat the push. The observer verifies
the remote independently even when it is also the publisher.

The native hook's preflight ancestry/receipt checks and the landing queue's
local recovery are not this post-publication object. Connect reconciliation to
the persisted canonical intent, including a crash after the push but before
any result record exists.

## 2. The one publication rule

Let `C` be a CANDIDATE, `P` its PROOF_SET, `B` the observed `main` tip, and
`M(C, policy_digest)` the set of input keys the policy derives from the
candidate's complete actual input closures.

A push may be attempted if and only if all of the following hold.

1. `C.base_commit == B`. The candidate is cut from the tip being replaced.
2. `P.candidate_root == C.candidate_root`.
3. `P.policy_digest == policy_digest`, the digest of the policy in effect at `B`.
4. Every mandatory key has eligible PASS observations with the required
   independently verified closure, signer and reproduction coverage. No key
   has an unresolved eligible contradiction. A signature proves its stated
   observation and signer, not arbitrary code correctness.
5. `M(C, policy_digest)` is a subset of the verified input keys covered by `P`.
   A missing key or unavailable required coverage is a refusal; additional
   observations are allowed and do not hide conflicts.
6. The current receiver policy grants publication to this exact target, the
   intended head descends from `B`, and the immutable publication intent has
   been durably recorded. Object correctness does not grant signing, custody
   or production deployment authority.

If the predicate holds, any node may attempt an ordinary fast-forward push with
`expected_base = B` under its current scoped grant. Git decides the race. The
loser records a result, re-fetches, safely integrates the new base and emits a
new immutable candidate. Recompute actual unit inputs; the changed Git base
does not automatically invalidate unchanged unit observations. Do not mutate
the old candidate or proof-set. No lease, board entry or queue position grants
publication authority. Preserve competing P2P heads under receiver policy.

Current native hook: `tools/dev/z23_git_hook.c` verifies main-ref ancestry,
the exact signed local/base pair receipt and its child receipts. Admission
does not compile, lint, test, fetch, wait, or invoke Make/shell. The historical
shell oracle `tools/githooks/pre-push` still contains CI execution; it is not
the native receipt-admission implementation. Inspect the installed hook before
making a statement about a particular checkout.

Target hook: verify the canonical evidence predicate through its bounded
admission envelope, retaining exact local/base binding. Missing evidence is a
named refusal; asynchronous workers produce it outside the hook. Root-cover
integration must preserve the existing no-build admission property.

Target landing adapter: apply the same predicate before mutation, persist the
PUBLICATION intent before the push, then append results and independent remote
observations. Reconcile uncertain outcomes through that intent.

## 3. Projections

Target rule: local projections rebuild from canonical signed objects. The table
describes retirement requirements, not permission to delete present caches or
worktrees. Before removing anything, prove the required durable objects exist;
preserve live ownership and scheduling locks that bound actual execution.

| Local state | Path | Rebuilt from |
| --- | --- | --- |
| Proof receipts | `.cache/zcl-dev-proof/receipts/` | verified proof-set and observation objects; exact-pair admission binding retained |
| Dimension children | `.cache/zcl-dev-proof/children/` | the PROOF_SET root |
| Requests, attempts, leases, logs | `.cache/zcl-dev-proof/` subtrees | nothing; pure scheduling scratch |
| Land queue rows | `<state>/land/queue.jsonl` | JOB and CANDIDATE objects |
| Land outcomes | `<state>/land/outcomes.jsonl` | PUBLICATION intent, immutable attempt results and REMOTE_RECEIPT objects |
| Land chainlog verdicts | the `z23-land` record store, `tools/land/land_record.c` | the ticket objects |
| File-claim ledger | `<git_common_dir>/z23-agent-claims.jsonl` | CLAIM objects; advisory either way |
| Lane and stack worktrees | `z23-stack<name>`, lane checkouts | the CANDIDATE bundle |
| Flash unit receipts | each unit's `--state-dir`, `tools/engine_unit.c` | ticket objects, once units emit tickets |

The pair validator remains mandatory until its envelope is verifiably derived
from canonical facts. After convergence, missing local projections trigger
reconstruction or refusal. Loss of receiver authority state additionally
requires a fresh authenticated policy head; cached proof never restores a lost
grant by itself.

## 4. Workers

A worker claims, builds, tests, and produces candidates and tickets. It never
runs `git push origin main`.

Claims are objects, not locks. A CLAIM carries `claim_root`, `job_root`,
`worker_pubkey`, `expires_unix`, `signature`. Two claims for one JOB root are
legal and are not an error to report. A claim reduces duplicate work by making
duplication visible; it confers no right to land and no protection from being
overtaken. The later CANDIDATE with full root cover wins, by push.

Overlapping proposals may exist, but preserve one primary writer per component.
The overlap protection in `tools/command/native_devagent_claim.c` is not
permission to remove writer safety. Coordinate ownership or use isolated
proposal workspaces; an advisory claim never overrides receiver execution policy.

Stale results fail closed for free. A worker that finishes against an old base
produces a CANDIDATE whose `base_commit` no longer equals the observed `main`
tip, so condition 1 of the publication rule fails before anything else is
consulted. A stale lease needs no reaper: an expired CLAIM stops being
interesting, and the work behind it is judged only by whether its roots still
match. Crash of a worker mid-build loses a worktree and nothing else.

Target worktrees are per-job scratch once their candidate and evidence objects
are durable. Never discard owned or unfinished work. The train builder's
`<stack_dir>/build/train-check.state` and `train-check.log` are historical
examples of local records that must be checked for canonical preservation
before retirement.

## 5. Competing state machines to remove

| Name | Where it lives | Replaced by | Delete after |
| --- | --- | --- | --- |
| Bash stack landers | `tools/dev/land.sh`, `tools/dev/land_lander.sh`, `tools/dev/land_bench.sh` | PUBLICATION, driven by `dev land` | `dev land` emits PUBLICATION and REMOTE_RECEIPT objects and passes the acceptance harness |
| Human relay at the end of the lander | `publish_ready` in `tools/dev/land_lander.sh`, leaving a gated `land/ready` branch | canonical publication predicate under a scoped grant | authorized publication reconciles without human message relay; owner authority remains |
| `z23-land` chainlog queue | `tools/land/land_main.c`, `land_queue.c`, `land_record.c` | JOB, CANDIDATE, PROOF_SET | the ticket object carries the verdict digest `land_verdict_digest` computes today |
| Land JSONL queue as authority | `<state>/land/queue.jsonl` via `tools/command/native_dev_land.c` | JOB and CANDIDATE objects; the file stays as a projection | rows are re-keyed from `seq` to `job_root` |
| Train stacks as durable state | `tools/command/native_dev_train_command.c`, `z23-stack<name>` worktrees | CANDIDATE bundles | the train builder emits a CANDIDATE per stack |
| Board as a queue | `docs/agent/TRAIN_PROTOCOL.md` and the DHT projection `zcode task board` in `tools/command/native_zcode_task_transport_command.c` | existing signed task/action facts; board output stays a projection | board position cannot grant build, execution or publication authority |
| Claim ledger as publication authority | `tools/command/native_devagent_claim.c`, `<git_common_dir>/z23-agent-claims.jsonl` | advisory CLAIM objects and explicit component ownership | claims never admit publication; writer and execution safety remain |
| Artifact shipping over ssh | `tools/ship.sh` tar-over-ssh staging and its `git push --no-verify origin main` | CANDIDATE bundle plus ordinary git transport | deploys consume a REMOTE_RECEIPT instead of pushing |
| Proof pair-keying as reusable evidence identity | `<local>-<base>` file naming in `tools/dev/dev_proof.c` | per-unit input keys and immutable observation roots | reusable evidence survives unchanged inputs across candidates; pair envelopes remain projections |
| Per-host proof locks and leases | `queue.lock`, `<key>.running`, `<key>.lease` in `tools/dev/dev_proof.c`; the queue's step lock `step.lock` in `tools/command/native_dev_land.c`; the lander's own box lock in `tools/dev/land_lander.sh` | nothing; scheduling scratch only | no code path treats a lock or a lease as permission to write a verdict or to push |
| Fleet receipt projection | `tools/command/native_dev_fleet_receipts.c` | signed observation objects | independently verified signatures, roots and receiver eligibility back the view |
| Flash unit queue | `tools/engine_unit.c`, per-unit `--state-dir` receipts, `docs/agent/FLASH_UNIT.md` | JOB, CANDIDATE, ticket | a unit's `receipt.json` is derived from a signed ticket |
| Commuting tickets and train protocol as separate machines | `docs/agent/COMMUTING_TICKETS.md`, `docs/agent/TRAIN_PROTOCOL.md` | this document | both are reduced to explanatory notes pointing here |

`tools/lint/check_no_unattended_publish.sh` is retained and tightened: after this
convergence, exactly one call site may push `main`.

Fleet synchronization and service restarts retain their separate grants; this
design does not authorize `tools/scripts/fleet_sync.sh` operations. Evidence
append locks remain ordinary write-safety mechanisms and decide no publication.

## 6. Acceptance harness

Target: three nodes, twenty consecutive cycles, exactly one landing per cycle, no
lost work, no human relay, `main` qualified at every observed tip. The first
form of every condition below runs on one host with three datadirs and three
checkouts against a local bare repository standing in for the remote. The
full release demonstration additionally requires three consenting physical
hosts. Names below are proposed registered cases until present in the canonical
catalog; their presence in this table is not passing evidence.

| Condition | Test | Pass criterion |
| --- | --- | --- |
| Three nodes | `lifecycle_three_node` group, three datadirs, one bare remote | all three complete a cycle |
| Duplicate jobs | `lifecycle_duplicate_job`: two nodes claim one JOB root | both produce candidates; one PUBLICATION accepted |
| Duplicate candidates | `lifecycle_candidate_race`: two candidates, same base | exactly one accepted; the other emits a rejected PUBLICATION |
| Partition | `lifecycle_partition`: block one node's remote access mid-cycle | the isolated node lands nothing and loses no candidate |
| Worker crash | `lifecycle_worker_crash`: kill a worker mid-build | its worktree is removed; no ticket with a partial verdict exists |
| Publisher crash | `lifecycle_publisher_crash`: kill before push and after push before result/receipt | persisted intent survives; another node reconciles without blind reexecution |
| Contradictory proofs | `lifecycle_conflicting_observations`: deliver eligible PASS and FAIL for one key in both orders | distinct roots survive; publication refuses the unresolved conflict |
| Unchanged input reuse | `lifecycle_input_reuse`: change candidate provenance and then one real unit input | unchanged eligible units reuse evidence; changed/incomplete closures require proof |
| Stale lease | `lifecycle_stale_claim`: expire a claim and separately advance the base | claim expiry grants nothing; changed-base candidate is refused and current execution authority is checked |
| Reordered events | `lifecycle_reorder`: deliver objects out of order | every object still resolves by root; no ordering assumption fires |
| Twenty cycles | `lifecycle_soak`: run the loop twenty times | twenty landings, twenty REMOTE_RECEIPTs |
| Exactly one landing | assert over the bare remote's reflog per cycle | one `main` advance per cycle |
| Main always qualified | `lifecycle_qualified`: replay every observed `main` tip | the publication predicate holds at each |

Register implemented groups in `tools/dev/test_group_catalog.def` so a run that
executes nothing is visible as such. Assert complete object bindings and the
observed remote transition; a hash alone does not establish an unobserved
behavior. Forged observations cannot supply either a pass or an authoritative
conflict. Missing policy coverage and missing receipts remain non-PASS.

## 7. Order of work

This is the dependency order inside milestone 1 of the forward plan. Freeze
the interfaces above first; runner, lifecycle and federation implementation
then proceed with disjoint ownership.

1. Wire actual runner observations through the existing signed verdict-leaf
   codec. Prove exact input derivation, root stability, crash-safe persistence
   and contradictory-observation retention before enabling evidence reuse.
2. Derive mandatory coverage and proof sets from canonical observations. Keep
   signed pair-receipt compatibility and no-build native hook admission;
   missing coverage or an unresolved eligible conflict must refuse by name.
3. Bind existing task/candidate bundle authority to landing provenance. Prove
   root-addressed transfer, missing-chunk fetch and duplicate-work attachment
   without introducing a second candidate format or task authority.
4. Persist publication intent, implement expected-base fast-forward mutation,
   append immutable results and reconcile independent remote receipts. Exercise
   crashes on both sides of mutation before retiring legacy publication paths.
5. Qualify every section 6 scenario across twenty cycles, then the physical-host
   release evidence. Run required lint/build and independent review. Retire
   competing state only after reconstruction and acceptance pass.

NEED and CLAIM use existing task/action objects throughout this journey. No
board, queue, claim or local cache can substitute for verified evidence and a
fresh receiver grant. Continue through `FORWARD_PLAN.md` after this milestone.
