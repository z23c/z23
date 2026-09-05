<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# The orchestrator's opening packet

**Question.** An orchestrator session — the one that dispatches lanes rather
than working in one — has to answer the same questions before its first
decision every time it starts: is this checkout stale, which worktrees carry
work, which executor units are running, what is each fleet host offering, which
board rows did nobody answer, what is on `main`, what do I do first. Every one
of those facts is local and already on this disk. What does it cost to answer
them by hand, and what does it cost to answer them in one call?

**What was measured.** `z23 dev fleet start` run on the maintainer host's
checkout, which shares its git common directory with 283 linked worktrees and
reads a real board directory of 2,194 posted rows. Five consecutive runs at the
default budget, then one run per budget across the declared range, then one
cursor round trip. The binary is `build/bin/z23-dev` built from this lane.

## What one call costs

| Budget asked for | Packet bytes | Worktree rows | Board rows |
|---|---|---|---|
| 1024 | 890 | 0 (cut, `total` 283) | 0 (cut) |
| 2048 | 1883 | 0 (cut) | 1 |
| 4096 | 3898 | 7 | 2 |
| 6144 (default) | 5673 | 13 | 3 |
| 8192 | 7516 | 20 | 5 |
| 15360 (maximum) | 13666 | 44 | 13 |

The packet never exceeds the budget it was given, and every section that was
cut reports `truncated` with the `total` it had. At 1024 bytes only `checkout`
survives — deliberately: it is the one section every other answer is relative
to, so it is the only one that reserves nothing for the sections after it.

## What one call takes

Five consecutive runs at the default budget: **602, 575, 540, 565, 513 ms**.
The declared class is `LATENCY_FOREGROUND` (750 ms), not the `LATENCY_FAST`
(250 ms) its single-lane sibling `dev.agent.start` declares. The cost is eight
fixed Git invocations plus one `git --no-optional-locks status --porcelain` per
row the packet actually emits; 13 rows at the default budget is 13 of them. A
`FAST` declaration would have been a promise this leaf cannot keep on a
fleet-sized checkout, and the packet reports its own `elapsed_ms`,
`latency_budget_ms` and `budget_exceeded` so a caller never has to guess.

Every emitted worktree row was fully measured — no row came back with
`dirty: -1` — so the per-section wall (550 ms) was never the binding
constraint at the default budget. It exists for the case where it is.

## What one call answers

The default-budget packet from the last run:

| Section | State | Rows | Total |
|---|---|---|---|
| `checkout` | observed | 1 | 1 |
| `mission` | observed | 1 | 1 |
| `worktrees` | observed | 13 | 283 |
| `units` | observed | 1 | 1 |
| `hosts` | observed | 3 | 4 |
| `board` | observed | 3 | 2194 |
| `main` | observed | 1 | 1 |
| `next` | observed | 2 | 2 |

`board` additionally reported `unanswered: 82` — needs and problems across
every host file with no later `claim` or `result` naming them, excluding the
two automated posters. That number is the single most useful thing in the
packet and nothing else on this box computes it.

`next` returned two ordered actions, each with the fact that produced it and
the command that acts on it:

- answer the newest unanswered board row — *82 board needs or problems have no
  later claim or result*
- triage the worktrees that carry work — *5 worktrees are dirty and 10 are
  ahead of `origin/main`*

## What the second call costs

Passing the returned `cursor` back as `since` on the next call: **2639 bytes**,
zero worktree rows and zero board rows, because nothing had changed in between.
Steady-state polling therefore costs under half of a first call and shrinks to
almost nothing when the fleet is quiet.

## The comparison

Estimated from this session's own transcript, not instrumented: the manual
orientation that preceded this lane took roughly twenty shell commands and on
the order of 60 KB of document, memory and board text before the first
decision. The packet above is 5,673 bytes for a strictly larger set of facts,
and it names the next action instead of leaving it to be inferred.

Two honest caveats. The manual pass read prose an agent may still want —
`AGENTS.md`, the forward plan, the handoff — and the packet deliberately does
not copy any of it; it returns pointers and lets the reader choose. And the
20-command figure is a recollection of one session, not a measured population:
treat it as the right order of magnitude, not a benchmark.

## Three defects the fixture found

The acceptance group `dev_fleet_start` builds its own repository and board, and
each of these was a real bug the fixture exposed before any of it was believed:

1. **The checkout was resolved by walking up for Z23 markers.** That walk
   climbs *past* a repository that carries no marker into whatever ancestor
   does — so a caller pointed at one checkout was silently answered about
   another. `git rev-parse --show-toplevel` names the checkout now, and a `cwd`
   input says which one.
2. **`git status` rewrites the index** whenever a stat-cache entry moved, and
   the index modification time is exactly the signal the cursor uses to decide
   what changed. The first call stamped every worktree it read with "now", and
   the next call — using that call's own cursor — reported worktrees nobody had
   touched. `--no-optional-locks` stops the write.
3. **A file modification time has one-second granularity.** A strict cursor
   comparison hid a worktree touched later in the same second the previous call
   started, permanently. The cursor second is inclusive instead: repeating at
   most one second of rows is a failure an orchestrator absorbs; never seeing a
   lane move is not.

## What is still a bridge

`units` reports which executor units are *running*, in minutes. That is
activity, and the row schema says so in as many words. It is not a verdict:
whether a unit produced anything is a question for its receipt, and receipts
are a later increment. The board is read through exactly one function, so the
signed, gossiped native board can replace the source without any section
changing.
