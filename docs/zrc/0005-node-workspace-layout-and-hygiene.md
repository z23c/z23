<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# 0005: Node workspace layout and hygiene

| Field | Value |
|---|---|
| ZRC | 0005 |
| Title | Node workspace layout and hygiene |
| Status | accepted |
| Owner | orchestrator |
| Created | 2026-09-05 |
| Supersedes | none |

## Problem

Every lane, train, and short-lived unit dispatched on a node has been
creating its own worktree beside the real checkouts under `~/github/`,
named however the dispatcher felt like naming it that day. Nothing reclaims
one when its lane lands or is withdrawn, so they accumulate: a node
accretes an ever-growing scatter of directories that are indistinguishable,
by name alone, from a real repository someone is actively developing in. An
agent that reconnects to a node cannot tell, from `ls ~/github/`, which
directories are the durable checkouts it should keep and which are stale
lane debris it should ignore or reclaim — every session pays tokens
re-discovering the same layout by re-deriving it from `git worktree list`
and directory timestamps, and a directory count alone has already been
called out as telemetry, never permission to delete
(see [`../agent/LANE_LAUNCH.md`](../agent/LANE_LAUNCH.md)). The same sprawl
applies to shell helpers: each new need has tended to grow another
standalone script rather than a leaf on the node's own command tree, which
the project has already committed to shrinking in favor of C23 (see
[`../agent/NATIVE_CHANNEL.md`](../agent/NATIVE_CHANNEL.md)).

This is a standing rule every fleet member needs, not a one-node fix: any
AI executor picking up work on any node should find the same shape, so it
can orient in one directory listing instead of relearning the layout each
time.

## Design

One hidden workspace tree per node, rooted at `~/.z23/`, holds everything
that exists only because work is in flight. Nothing else is created ad
hoc beside it or beside `~/github/`.

- `~/.z23/lanes/<name>` — one worktree per currently running lane, on
  branch `agent/<name>-<date>`, exactly as
  [`../agent/LANE_QUICKSTART.md`](../agent/LANE_QUICKSTART.md) already
  creates it. There is never a second checkout of the same lane; a lane
  name is claimed once.
- `~/.z23/trains/<n>` — landing stacks, detached at the current `origin/main`
  ref rather than carrying their own branch, matching the parallel-assignment
  worktrees described in
  [`../agent/LANE_LAUNCH.md`](../agent/LANE_LAUNCH.md).
- `~/.z23/units/<name>` — short-lived worker units that finish in one
  sitting and do not need a lane's full lifecycle.
- `~/.z23/pool/` — warm, primed worktrees kept ready so a new lane or unit
  can start from an already-built tree instead of paying a cold prime.
- `~/.z23/candidates/` — incoming bundles from other nodes, held here until
  they are reviewed and either landed or discarded.
- `~/.z23/state` — a link to the node's existing state directory (the
  board, scratch space, and any local helpers), so a worker finds them at
  one fixed path regardless of what that state directory is named
  underneath.

Real repositories — the checkouts a person or agent actually develops
in day to day — stay under `~/github/`, exactly where they are today. This
proposal does not move them or rename them; it only stops new ad hoc
directories from appearing beside them.

Rules that keep the tree meaning what it says:

1. A lane's directory is reclaimed when the lane lands or is withdrawn, and
   only by the reclaim leaf (see Out of scope) — never by an agent deciding
   by hand that a directory looks stale and removing it.
2. A lane name is never checked out twice; before creating
   `~/.z23/lanes/<name>`, a dispatcher checks whether it already exists.
3. Build artifacts belong inside the lane's own worktree or the shared
   build cache, never scattered elsewhere on the node.
4. Scratch output belongs under `~/.z23/state`'s scratch path, never `/tmp`
   and never the home directory root.
5. A worker reports, in its own report, what it created under `~/.z23/`
   and what it reclaimed — the same way a lane report already states its
   baseline and head commit.
6. The orientation a reconnecting agent reads at the start of a session
   lists lanes, trains, and units by their directory under `~/.z23/`,
   rather than by re-deriving them from `git worktree list` or directory
   timestamps each time.
7. A shell helper is a bridge, not a destination: where a typed leaf
   already exists for a task, the shell helper is retired in the same
   change that adds the leaf, never left running alongside it.

## Acceptance

- A node set up by following
  [`../agent/LANE_QUICKSTART.md`](../agent/LANE_QUICKSTART.md) from a fresh
  checkout ends up with exactly this tree under `~/.z23/`: `lanes/`,
  `trains/`, `units/`, `pool/`, `candidates/`, and `state` — nothing else,
  and nothing resembling a lane worktree left beside `~/github/`.
- The reclaim leaf's dry run (see Out of scope) reports zero directories
  under `~/.z23/` that it does not recognize as a lane, train, unit, pool
  entry, or candidate.
- No shell helper is added anywhere in the tree for a task a typed leaf
  already performs; a lane review that finds one treats it as a defect in
  the change, not a style preference.

## Out of scope

The reclaim leaf itself — the typed command that walks `~/.z23/`, decides
which lane, train, and unit directories are safe to remove, and removes
them — is its own ZRC. This proposal only defines the tree the reclaim
leaf operates on and the rule that hand deletion is not how reclamation
happens. Also out of scope: migrating any worktree that exists today under
`~/github/` into this layout (a one-time cleanup, not a standing rule), and
any change to what `~/github/` itself holds.

## Landing

Not yet landed.

## Discussion

Opened and accepted directly in the commit that adds this file, per the
owner's directive that every node keep contained, organized workspace
directories instead of ad hoc worktrees sprawled beside the real
checkouts. Further discussion happens the same way as any other ZRC: board
rows carrying `zrc-0005` (see
[`../agent/NATIVE_CHANNEL.md`](../agent/NATIVE_CHANNEL.md) for how the
interim board works today), until
[`0004-wiki-daily-board-public-page.md`](0004-wiki-daily-board-public-page.md)
lands and the wiki page for this ZRC becomes the index.
