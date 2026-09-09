<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# MVP work map: implementation contract

This is the scoped design for the MVP game/map, not a second task queue or a
completion ledger. `FORWARD_PLAN.md` orders work; `MVP.md` defines public-node
launch acceptance; `CANONICAL_LIFECYCLE.md` defines publication evidence.
The requested 12 milestones, 48 features and 144 loops are the intended map
size, not measured completion or permission to invent duplicate work. The
supplemental planning ZIP is not a prerequisite. Start with real acceptance
loops from those repository contracts and expand coverage without manufacturing
splits to fill a count.

## User outcome and owned surface

A worker can inspect milestone → feature → loop → dependencies → acceptance →
evidence → reviewer, and receive one highest-value eligible next action.
The map belongs to the existing Commons work and cognition views. It does not
schedule workers, hold a signing key, mutate an execution lease, authorize
publication, or operate a node. P0 consensus and custody always take priority.

Implement within existing `zcode.work.*` and task-detail surfaces. Reuse the
workspace CAS, task index, canonical candidate/action/receipt objects, and the
existing proof evaluator. The public API and CLI must render the same bounded
projection. A new database, board-derived status, shell scheduler, or hand-edited
completion counter is outside this contract.

## Definition and evidence are separate inputs

A map definition is inert, content-addressed metadata stored and transferred
through the existing CAS/content transport. It references existing task roots;
it never copies their acceptance predicates or overwrites their state. Labels,
parent/child relations, dependency edges and repository priority describe the
requested work. The map's exact root identifies which definition is being read.
An edit produces another root. Definitions do not confer acceptance authority.

Use explicit milestone, feature and loop kinds. A loop has no children. A
feature has loop children; a milestone has feature children. Each parent also
references its own integration-acceptance task. Child completion alone cannot
close the parent. Reject duplicate node identifiers, repeated children,
self-dependencies, cycles and out-of-range references. Two nodes referencing
the same task cannot earn two units of credit. Missing objects or incomplete
coverage are reported, never silently omitted.

Bound a first complete map to 204 nodes and 16 dependency edges per node.
Exceeding admission bounds produces a named refusal; it does not truncate the
graph and then claim a complete critical path. Response pagination is separate
from admission: every page identifies the map root, evaluated source/policy
context, observation time, coverage and continuation cursor.

For each task, resolve its exact goal, acceptance-test, policy, candidate,
action, receipt and review roots through the existing authorities. Task-detail
already exposes these pointers. Their presence alone does not qualify a loop.
In particular, the task index's `PROVEN` state and accepted-work reconstruction
are insufficient for fresh credit: policy eligibility, observation freshness,
required coverage and known eligible conflicts must be checked by the existing
evidence owner at the time of evaluation. A board result and a Git commit are
pointers, not acceptance evidence.

## Projection rules

Keep observation knowledge separate from execution status. `VERIFY_FIRST`
means unknown. A missing ledger cannot establish either unfinished work or a
running proof. Render the reason and a bounded verification action.

- DONE: exact loop acceptance qualifies under current receiver policy. For a
  parent, all children and its integration acceptance qualify.
- DOING: current scoped execution/lease evidence establishes active work. A
  queued request or an old process record alone cannot establish this.
- READY: required dependencies qualify, prerequisites are observed satisfied,
  and no current execution owns the work.
- BLOCKED: a specific observed prerequisite, authority or acceptance failure
  prevents the next stage. Include its evidence and corrective action.

Unknown observations must be visible alongside those categories, not forced
into READY or BLOCKED. Unknown dependency state cannot unlock dependent work.
Expired or invalidated evidence removes active credit on reevaluation. Immutable
observations remain history; a new result never erases a conflicting old one.

Award one loop flag per unique qualified acceptance, one feature star per
qualified parent and one milestone trophy per qualified milestone. Builder,
verifier and unblocker attribution must point to the corresponding verified
candidate, independent observation or prerequisite-resolution evidence. Do not
infer identity from a board agent name. Do not reward LOC, commits, messages,
CPU time, repeated observations or artificial task splits.

A useful-closure streak counts distinct qualifying closures in the declared
observation window. Accepted loops/hour names the window, its actual duration,
coverage and unique qualifying task roots. Invalidation removes active credit;
retain the earlier observation as history. Without a complete window, rate and
streak are unknown. Never divide a current total by process uptime.

The reviewer queue contains exact candidates with a currently unmet review
requirement and otherwise eligible prerequisite evidence. It must not repeat
an already-qualified review or recommend review of an obsolete candidate.

The next action follows repository priority, then dependency impact, then a
stable task-root tie break. Use the full admitted graph to report a dependency
critical path; do not invent duration estimates. A duration-based critical path
requires explicit measured/estimated costs with provenance. Emit exactly one
recommended action with its reason, exact inputs and authority boundary. A
verification action is valid when the next fact is unknown. Recommendation
never dispatches work or grants execution authority.

## First end-to-end proof and continuation

Use one real first-foundation loop from `FORWARD_PLAN.md`: expose and qualify
canonical candidate proof evidence without changing consensus or custody.
Bind a concrete failing witness, owned files, exact base, acceptance command,
candidate and independent reviewer through existing task/action objects. Carry
it through NEED → JOB → CANDIDATE → PROOF_SET → PUBLICATION → REMOTE_RECEIPT.
Show the map before qualification, after qualification, after evidence
invalidation and after a fresh qualifying observation. Rebuild the view from
retained canonical objects and obtain the same result.

A fixture proves projection behavior only. The first real loop additionally
requires actual independent proof and publication/remote-observation evidence.
A local green commit does not satisfy this demonstration. Missing remote access
is a named prerequisite; continue local implementation and qualification.

Required implementation tests (acceptance targets, not existing pass claims):

1. Missing task, ledger, receipt and policy each remain unknown with no credit.
2. Exact qualifying evidence closes one unique loop; duplicate references and
   repeated receipts do not increase credit.
3. Forged, stale, wrong-source, wrong-candidate and policy-ineligible evidence
   cannot close work. An eligible conflict removes active credit.
4. Parent integration evidence is mandatory even when every child is DONE.
5. Dependency cycles refuse admission; unknown or invalidated dependencies
   cannot yield READY. Current execution prevents duplicate recommendations.
6. Review completion removes only the exact candidate from the reviewer queue.
7. A full 204-node definition paginates within the declared command budget,
   while critical-path and next-action results use complete admitted coverage.
8. Missing history makes rate/streak unknown; a complete window deduplicates
   closures and handles invalidation without deleting history.
9. CLI and API agree; rebuilding after projection loss preserves the verdict.
10. The real loop has independently verified canonical lifecycle roots through
    REMOTE_RECEIPT, followed by the next highest-priority eligible loop.

Register implemented tests in the canonical runner, prove RED before repair,
run focused acceptance, required architecture/generated-interface gates, public
build and lint, and obtain non-author review before integration. Keep the full
map and launch acceptance unfinished until their actual requirements qualify.
