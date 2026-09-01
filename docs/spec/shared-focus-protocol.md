<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Shared focus protocol

## Purpose

The shared focus protocol gives independent workers one bounded, immutable
situation to inspect. It composes existing ZCODE task, source, context,
write-scope, proof-policy, action, and receipt identities with the current
StoryGraph root. It does not define a queue, lease, event log, scheduler,
acceptance policy, or execution authority.

The protocol separates five roles:

- ontology defines the meaning and status of relations;
- StoryGraph binds causal observations;
- focus selects the exact bounded situation under examination;
- claims state proposed non-overlapping work without granting ownership;
- reports and handoffs carry rooted evidence without a prose transcript.

Every status is one of `PROVED`, `DISPROVED`, `BOTH`, `UNKNOWN`, or
`INCOMPLETE`. Missing, ambiguous, stale, malformed, over-budget, or
unverifiable evidence never becomes `PROVED` by omission.

## Canonical identities

`focus.v1` binds:

- the existing task and goal roots;
- the governed source-universe root;
- the reverified `agent_context.v1` root;
- the current StoryGraph root;
- a canonical snapshot of active claim roots;
- required-evidence and authority-limit roots derived from the task; and
- the task's exact change, context, CPU, memory, and output budgets.

A focus has two related identities. `situation_root` excludes the claim-set
snapshot. `focus_root` includes it. This split is required because a claim must
identify the situation it concerns while the final focus must bind the set of
claims. Making claims hash the final focus while the focus hashes those claims
would create an unsatisfiable hash cycle.

`focus_claim.v1` therefore binds `situation_root`, claimant identity,
`write_scope.v1`, intent, evidence plan, and a bounded validity interval. A
claim is an immutable proposal. It does not prove assignment, ownership,
liveness, or execution. Active overlap is evaluated by revalidating both
write-scope objects and applying the existing component-aware overlap rule.
Malformed, missing, differently rooted, or expired inputs yield
`INCOMPLETE`, never a clear result.

`focus_claim_set.v1` is a strictly sorted, duplicate-free list of claim roots.
The empty set has a stable nonzero root. A focus records both its set root and
count so silent truncation is detectable.

`specialist_report.v1` binds the final focus root, one claim root, specialist
identity and role, one ontology status, exact evidence/result/evaluator roots,
the proposed next experiment, and measured context, latency, file, tool,
duplicate-action, and proof-reuse counts. The wire contains no prose and
grants no authority.

`focus_handoff.v1` binds the final focus, source claim, specialist report,
successor identity, successor claim, required evidence, continuation root, and
ontology status. A receiver resumes only after re-rooting every supplied wire
and validating the complete chain. The structural root-chain check is not a
resume gate by itself. The admitted-work gate additionally requires the full
canonical claim snapshot and scopes, proves every claim was simultaneously
active, disjoint, and within task authority at the deterministic snapshot
witness, proves the source claim and signed admission at its authenticated
receipt-completion time, proves the successor claim and signed admission at
the current resume time, and binds the source report to its signed request and
work receipt. The witness is the later of source completion and every
immutable claim's creation time. Expired historical authority never becomes
current successor authority. A handoff does not accept results or permit
execution.

`attention_bid.v1` binds one final `focus_root`, so changing the active claim
snapshot changes the bid's identity even when a reusable heuristic is
unchanged. Cross-object validation re-roots the focus and heuristic, requires
their task, source, context, and StoryGraph identities to agree, and refuses a
heuristic whose requested CPU, memory, context, or output budget exceeds the
focus. Priority classes and Pareto projection remain non-authoritative.

## Storage and transport

All protocol wires are inert content-addressed objects in the existing ZVCS
CAS. Addressed writes must be followed by bounded reads, parse, root
rederivation, and exact address comparison. Existing `content.v2` transport
may carry the same bytes between peers. SQLite indexes, if added, are
rebuildable projections only.

The registered `zcode_swarm_net` integration fixture carries canonical task,
write-scope, focus, claim-set, claim, signed request/admission/receipt, report,
and handoff wires between two independent node stores and swarm engines through
the unchanged `zpkgswm` framing and dispatch seam. The receiver re-parses and
re-roots each semantic wire after the content carrier verifies its bytes. This
is an in-process wire proof, not physical-host or independent-agent evidence.
No focus-specific network message or mutable transport state exists.

The existing ZCODE task index remains the duplicate-work authority. Focus
claims add a bounded disjoint-scope observation for workers already examining
the same situation; they do not replace task collision checks, action
deduplication, leases, signed receipts, or local acceptance.

## Existing work authority

Focus composes the existing signed work objects instead of defining another
assignment or evidence ledger. For a claim about admitted work,
`intent_root` is the exact signed `work_request.v1` identity and
`evidence_plan_root` is that request's proof-policy root. A `PROVED` active-work
relation requires the claim root to occur in the focus's complete canonical
claim set, a current `GRANTED` or `ATTACHED` admission signed by the claimant,
and task, policy, toolchain, budget, and deadline agreement. Missing set
evidence is `INCOMPLETE`; an absent claim, expired admission, refusal, or
contradictory binding is `DISPROVED`.

For a completed observation, a specialist report's `evidence_root` is the
exact signed `work_receipt.v1` identity and its `result_root` is the receipt's
output root. Cross-object validation requires the supplied claim to belong to
the focus's committed claim set and binds the receipt's task, candidate,
action, input, work kind, policy, toolchain, signer, and output back to the
request, claim, and report. Receipt status maps to ontology status; it does
not grant acceptance, installation, execution, or deployment authority.

At handoff, the authenticated source receipt is a historical observation. Its
claim and admission therefore need to cover the signed receipt-completion
time, not remain live forever. The successor's claim and admission are a
different relation: they must remain live at the current resume time before
new work can proceed. The receiver authenticates and binds the source receipt
before using its timestamp.

## Required pre-edit observation

Before a write, a worker must have reverified:

1. the exact task and governed source generation;
2. the goal and bounded agent context;
3. the current StoryGraph and required evidence;
4. the task's authority and resource limits;
5. the complete active claim snapshot and proposed write scope; and
6. the existing task/action projections for duplicate work.

Any missing dimension makes the pre-edit result `INCOMPLETE`. An overlapping
active scope blocks the proposed claim. A disjoint result is only evidence
that the two supplied canonical scopes do not overlap; it does not appoint an
owner.

## Acceptance

The protocol is accepted when two independent workers rederive the same
`focus_root`, create active claims whose exact write scopes are disjoint,
exchange compact rooted reports, and a successor reconstructs and validates a
handoff from CAS without reading a prose transcript. The proof must use a real
C23 application or platform task and must record context bytes, files opened,
tool calls, duplicate actions, scope overlap, proof reuse, retries, conflicts,
and edit-to-observation latency. Platform-unavailable dimensions remain named
`INCOMPLETE`.
