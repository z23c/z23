# Train protocol

This document defines how fleet nodes land lanes on main one train at a time without a human, and specifies that process as a state machine.

## Purpose

Main moves one train at a time. A node orders finished lanes into a train of at most 4 lanes. It rebases the train onto the exact current origin/main tip. lint-fast is green before the train goes further. The push-hook proof runs once. Then the node pushes.

Every push to main moves the base and invalidates every in-flight proof on every box. Because of this, trains stay small and results are posted the moment a push succeeds.

See also: `AGENTS.md`, `docs/DEVELOPING.md`, `docs/work/agent-protocol.md`.

## Definitions

| Term | Meaning |
| --- | --- |
| lane | One unit of finished work queued for main. For lane launch and reporting, see `docs/agent/LANE_LAUNCH.md` and `docs/agent/LANE_REPORT.md`. |
| train | An ordered batch of at most 4 lanes. |
| base | The exact current origin/main tip a train is rebased onto. One train per base, fleet-wide. |
| proof | The push-hook proof. It runs once per train, before the push. |
| box | One machine in the fleet. One proof per box at a time; this is the box lock. |
| board | Where claim and result rows are posted. |

## The state machine

```text
IDLE ─────claim────▶ PROVING ─────push ok────▶ LANDED ─────result────▶ IDLE

PROVING ─────base moved────▶ REBASE ─▶ PROVING
                                REBASE rebases the train onto the exact current
                                origin/main tip; the train then proves again.

PROVING ──gate red or too large──▶ WITHDRAWN ─────result────▶ IDLE
```

A node in IDLE posts a claim and enters PROVING. PROVING ends in exactly one of three ways: the push succeeds (LANDED), the base moves (REBASE, then PROVING again), or a gate is red or the train is too large (WITHDRAWN). LANDED and WITHDRAWN each end with a result row and a return to IDLE. The box lock is held from the claim until the result.

## Board rows

| Event | Row posted |
| --- | --- |
| The node starts proving | `claim train <name> base=<tip> commits=<n> lanes: <names>` |
| The push succeeded | `result train <name> <new tip>` |
| The node gave up | `result train <name> WITHDRAWN <reason>` |

| Field | Meaning |
| --- | --- |
| `<name>` | Train name. |
| `<tip>` | The base: the origin/main tip the train is proven against. |
| `<n>` | Commit count of the train. |
| `<names>` | Lane names, in train order. |
| `<new tip>` | The origin/main tip after the push. |
| `<reason>` | Why the train was withdrawn. |

No node starts a proof against a base another node has claimed and not resolved. A claim is resolved by either form of result row. A claim names a box and can be transferred: when the claiming box is overloaded, bundle the train (`git bundle create <f> origin/main..HEAD`), copy it to an idle box, and post that the claim moved; the idle box proves and pushes.

## Rules

- A train carries at most 4 lanes, in a fixed order, rebased onto the exact current origin/main tip.
- lint-fast is green before the proof runs.
- One proof per box at a time. One train per base, fleet-wide.
- Never push while another node's claim is live.
- Post the result the moment the push succeeds.
- A withdrawn train posts why.
- Land generated files (capability inventory, API reference) by regenerating them once on the train. Do not cherry-pick each lane's copy.
- Every commit is signed.
- Never `git stash`.
- Never force-push. Fast-forward only.

The table below is the measured record behind the size cap and the timeout override. The values are fleet observations dated 2026-09-04, not properties of this checkout.

| Observation (2026-09-04) | Value |
| --- | --- |
| Withdrawn train | 135 commits, 1,036 files |
| Why withdrawn | Impact planning alone took about an hour, and every push to main invalidated it. |
| Change since | The same lanes land as trains of at most 4 lanes. |
| Proof duration | 15 to 45 minutes per box. |
| Release build inside a proof | About 20 minutes. |
| Loaded box | Load 450, disk-bound. Every proof child exited 124 until the timeout became an environment override. |

## The landing service: `dev land`

The shell loop makes an agent wait for the whole train: rebase, lint, proof,
push. `dev land` splits that in two so no agent waits for any of it.

| Verb | What it does | What it waits for |
| --- | --- | --- |
| `dev land submit --tip <sha> [--worktree <dir>] [--note <text>]` | Checks the tip exists, is signed, and shares history with origin/main, then appends one request row to `<state>/land/queue.jsonl` and returns `{seq, tip, state: "queued"}`. | Nothing. It is a file append. |
| `dev land status [--json]` | One screen: what is queued, the one request in flight with its phase, elapsed time and attempt, and the last ten outcomes with the tip that was pushed or the failing dimension and its log path. | Nothing. It reads files. |
| `dev land step` | One scheduler beat, for a resident loop or timer to call. | Nothing that is another host's work. |
| `dev land cancel --seq N` | Drops one request and records the cancellation. | Nothing. |

`step` is the only verb that does work, and it never waits for a proof. It
takes the host-wide landing slot (`<state>/land/slot.lock`) **non-blocking**,
returning `busy` rather than queueing behind another step, and it releases
the slot before it returns — the lock is never held across steps. With
nothing in flight it takes the oldest queued request, rebases the tip onto
origin/main in the private landing worktree at `<state>/land/wt`, runs
`make lint-fast`, ASKS for the exact commit/base proof through the existing
`dev proof ensure` machinery, and returns. A later step reads the proof's own
state: passed fast-forwards `origin/main` and records `landed`; failed
records the failing dimension, the log path, and the first actionable line
from that log. A rebase conflict is terminal and names the conflicting paths,
with one exception described under "Conflicts on generated artifacts" below.
If origin/main moved while the proof ran, the receipt describes a base nobody
is on, so the request re-rebases with `attempt+1` instead of landing stale
evidence. A host-load failure — a source-identity race, a timeout — retries
up to three times; a red dimension does not.

Every state change also appends a row to `<state>/mail/outbox.jsonl` when
that mailbox exists, so an agent learns what happened by **pulling its mail**,
never by waiting on this queue.

The landing worktree is created once from the submitting checkout and reused.
Run `tools/scripts/worktree_init.sh` in it once so `make lint-fast` there has
its vendor prerequisites.

### Conflicts on generated artifacts

`docs/CAPABILITY_INVENTORY.jsonl`, `docs/API_REFERENCE.md` and the
`<!-- DOC-COUNTS -->` block of `docs/CODEBASE_MAP.md` are generated from the
code, so tips landing in the same window collide on them by construction and
a textual merge of two generated files settles nothing — the code is what is
authoritative. When **every** conflicted path is one of those three,
`dev land` takes the upstream side of each, finishes the rebase, and re-runs
the generator that owns the file: `make docs-capability-inventory`,
`make docs-api-reference`, and `make fix-doc-counts` (the repair half of
`check-doc-counts`, which runs `tools/scripts/check_doc_counts.sh --fix` to
rewrite the declared counts from the code-measured ones). It then runs
`make check-generated-artifact-contradictions` and `make check-doc-counts` in
the landing worktree; a gate that still refuses fails the row with
`dimension=rebase` and that gate's own line, never a landing. On success the
regenerated content is committed with a subject naming what was regenerated
and the base it was rebased onto — signed by ambient `commit.gpgsign`
configuration, with no signing flag of its own — and the row's `detail`
carries `rebase: regenerated <paths>`.

The table is closed. A conflict touching any other path — even alongside
these — stays an ordinary conflict, reported exactly as before, because
nothing mechanical can settle it.

### vendor/tor in the landing worktree

The proof's generation copies the vendored Tor archives out of the landing
worktree, so `dev land` primes them there. Where the tip records `vendor/tor`
as a real submodule gitlink, the landing worktree's own submodule is
initialised first and its checked-out commit must equal the commit the tip
pins.

Two things follow. When the landing worktree is already standing on the tip's
pinned commit and still holds `vendor/tor/libtor.a` from an earlier train,
that is accepted directly and the submitting checkout is never consulted —
the archive persists across trains, so re-deriving the pin from a fresh
checkout every time is what made an unrelated checkout's state able to refuse
a sound tip. Otherwise the submitting checkout's own `vendor/tor` must be
checked out; when it is not, the refusal says so and says what fixes it:

```
proof_generation_dependency_unavailable:vendor/tor (submodule uninitialised in <checkout>; run git submodule update --init vendor/tor)
```

That refusal replaces a misleading one. Running `git rev-parse HEAD` inside an
uninitialised gitlink directory walks up to the enclosing superproject and
answers with the superproject's own HEAD, which is not a submodule commit at
all — so the check used to report a pin mismatch against a commit that meant
nothing.

Commuting tickets plug in at one named seam. Per-group tickets (node2's
`dev.proof.tickets`) name the groups a proof may skip because the change
cannot affect them; `dl_tickets_admit()` in
`tools/command/native_dev_land.c` is where that admission belongs, between
"the base is fixed" and "ask for the proof". With no ticket service on the
host it admits nothing and the proof runs whole — fail-closed, because a
missing ticket service must never read as a ticket that admits everything.

## What replaces the shell loop

The shell loop that drives these transitions today is interim. The C23 leaf `zcode land` (node2's lane) replaces it. `zcode land` posts the claim and result rows itself and drives the same state machine. Until it lands, the loop remains the operator, and every rule in this document binds it unchanged.

Related tooling in the tree: `tools/scripts/worktree_init.sh`, `tools/scripts/worktree_gc.sh`.
