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

## XP rules v1

The owner's KPI is VERIFIED MVP PROGRESS PER TOKEN. `z23-mvp-ledger xp`
scores that KPI as a game so the most important work is also the
highest-scoring work. Every point is derived from evidence a stranger can
recheck — a commit reachable from `origin/main`, a registered sweep group, a
`dev.land` outcome row, or an `INDEPENDENT REVIEW by <agent>` note in the
plan of record. **XP is never hand-set**, never awarded for lines, commits,
messages or CPU time, and never read from a `state=` a worker typed about
its own work. A rule with no signal pays nothing and says so in the report
rather than guessing.

The agent identity is the LANE this ledger already attributes work by: a
plan row's `loop=`, an outcome row's worktree name (`…/trains/<n>` reads as
`train<n>`), an `agents.tsv` row's lane, a review note's named reviewer.

1. **LOOP XP** — 100 per base plan loop (an `L<nn>` row, not a letter-suffixed
   sub-row) whose `state=LANDED` and whose evidence is verified: every sha of
   the row reachable from `origin/main`, or `ONLY=<group>` naming a group the
   catalog at that same ref registers. Multiplied by the milestone
   multiplier below. A verifier's LAND verdict counts toward the KPI but not
   toward XP: it is not recheckable from the two files this tool was handed.
2. **REVIEW XP** — a loop is REVIEWED when its plan row carries the exact
   phrase `INDEPENDENT REVIEW by <agent>`. The reviewer earns 25% of that
   loop's base × multiplier. An unreviewed loop pays its author only 50%,
   and the event is marked `provisional` in `xp_events.tsv` until a review
   note lands.
3. **FEATURE XP** — 500 × multiplier, and ONLY when every loop under the
   feature is verified AND the feature's own plan line carries
   `state=ACCEPTED`. Child completion alone never closes a parent. The pot
   is split evenly over the distinct authors under the feature.
4. **MILESTONE XP** — 2000 × multiplier under the identical rule: every child
   loop verified AND the milestone's own line carrying `state=ACCEPTED`.
5. **SPEED BONUS** — +50% of base × multiplier on a loop closed in less wall
   time than the median close of all scored loops. The clock comes from the
   loop's joined agents, so it exists only when an `agents.tsv` was measured;
   without it the bonus is reported NOT ASKED and nobody is paid one.
6. **PENALTIES** — −50 per `failed` row of the `dev.land` outcome ledger whose
   `detail` does NOT contain `head_changed` or `origin/main moved`: a base
   that moved under a landing is not a mistake anyone made. `cancelled` rows
   cost and pay nothing. A −200 "put origin/main red" penalty is DEFINED but
   NOT SCORED in v1: no input this tool reads carries a red-main signal, so
   no such row is ever written, and the leaderboard says so.
7. **COMBO** — +100 for every 3 consecutive `landed` outcome rows by the same
   agent, in timestamp order, with no `failed` row between them.
8. **TOKEN-EFFICIENCY LEAGUE** — `xp_per_mtcu = XP / (TCU / 1e6)`, carried in
   thousandths with integer arithmetic, over the same per-agent TCU the
   `kpi` mode prices (out × 5 + in × 1 + cache_write × 1.25 + cache_read ×
   0.1). An agent with no measured tokens prints as
   `unranked (no TOKENS rows)` and takes no rank: a ratio with a zero
   denominator is not a worse ratio.

### The milestone multiplier table

The multiplier is read from the plan's own milestone TITLE, by two keyword
sets, and is printed with every leaderboard so it can be audited:

- **×3** when the title names `consensus`, `wallet`, `custody`, `payment`,
  `shielded`, `node`, `sync`, `store` or `reaches tip` — consensus, custody,
  the money, and the node's own state.
- **×2** when it names `proof`, `publication`, `receipt`, `evidence`,
  `lifecycle` or `candidate` — the machinery correctness depends on.
- **×1** otherwise.

Against the 2026-09-08 plan of record that is:

| id | multiplier | title |
| --- | --- | --- |
| M00 | ×1 | One launch contract and one work map |
| M01 | ×2 | One canonical proposal and worker lifecycle |
| M02 | ×2 | Exact, reusable proof without false green |
| M03 | ×2 | Crash-safe publication and independent receipts |
| M04 | ×3 | A stranger installs, connects, and reaches tip |
| M05 | ×3 | Consensus-compatible state and fault recovery |
| M06 | ×3 | A real shielded payment buys the exact file |
| M07 | ×1 | Describe → reuse → create → see → keep → share |
| M08 | ×1 | Private fleet Insight |
| M09 | ×1 | Native platforms and transactional Control |
| M10 | ×2 | Integrated proof under races, attacks, and load |
| M11 | ×2 | Protected seven-day evidence and an unaided launch |

A milestone renamed in the plan changes its own multiplier and nothing else.

### Artifacts and inputs

`xp` writes two files beside `kpi.tsv` in the `--out` directory:

- `xp.tsv` — `agent loops reviewed xp tcu xp_per_mtcu rank`, one row per agent.
- `xp_events.tsv` — `agent kind subject xp multiplier provisional evidence`,
  one row per credited or penalized event, so every XP total walks back to
  the commit, sweep group, outcome sequence or review note that produced it.

`--json` prints the same numbers as one JSON object for a board post.

Agents whose transcripts this box never held (Agent B, Grok, Codex) post
their spend as TOKENS mail rows, folded from `<out>/tokens_extra.tsv`. Its
header is exactly, and a different first line is refused by line number
(`mvl_tsv_header`) rather than guessed at:

```text
agent	loop	in	out	cache_write	cache_read	utc
```

A missing plan, agents table, outcome ledger or `tokens_extra.tsv` is a
reported gap contributing zero — never a crash, and never a guessed number.
A malformed plan row is refused by its line number, and a malformed outcome
row is named on stderr and skipped rather than silently dropped.
