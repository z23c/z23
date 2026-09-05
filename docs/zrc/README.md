<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# The ZRC process

ZRC stands for Z23 Request for Comments. A ZRC is a numbered, written proposal
for a new subsystem, protocol, or standing rule in Z23. It exists so that any
AI executor or the human owner can put a design in front of everyone working
on the project, get it reviewed, and land it with a durable, auditable
history — before the implementation work starts, not after.

This directory is the durable record. [`0001-zrc-process.md`](0001-zrc-process.md)
is this process itself, written as the first ZRC.

## How a ZRC differs from an ADR

[`../adr/`](../adr/) records decisions already made about the existing
architecture. A ZRC is a proposal for something that does not exist yet. A
ZRC that lands may later be worth summarizing as an ADR once the decision is
history rather than plan; that is a separate, optional act, not part of this
process.

## File naming

One file per proposal: `NNNN-<slug>.md`, a four-digit number followed by a
short hyphenated slug. `NNNN` is the next number after the highest one
already used in this directory — list the directory to find it; there is no
separate registry to update.

## Header fields

Every ZRC file opens with these fields, in this order:

| Field | Meaning |
|---|---|
| `ZRC` | The four-digit number, matching the filename. |
| `Title` | A short name for the proposal. |
| `Status` | One of `draft`, `review`, `accepted`, `landed`, `superseded`. |
| `Owner` | The agent or person driving the proposal, by name — never a machine name. |
| `Created` | The date the draft was opened. |
| `Supersedes` | The ZRC number this replaces, or `none`. |

## Status lifecycle

Status moves forward only: `draft` → `review` → `accepted` → `landed` →
`superseded`. A ZRC that is accepted or landed is never edited back to
`draft`; a change of mind opens a new ZRC that supersedes it and points back
with `Supersedes`. Every status change is committed on its own — a ZRC's git
log is its status history, with no separate changelog to keep in sync. This
follows the same "landed means pushed to `origin/main`" meaning used
elsewhere in the project's own doctrine
(see [`../agent/EVIDENCE_LADDER.md`](../agent/EVIDENCE_LADDER.md)).

## Required sections

Every ZRC body has these sections, in this order:

- **Problem** — what is missing or broken, and why it matters now.
- **Design** — the proposal, stated plainly enough that an implementer needs
  no further interpretation of intent.
- **Acceptance** — exact and testable: a gate name, a command, or an
  observable behavior. Never a feeling, and never left vague.
- **Out of scope** — what this ZRC deliberately does not decide, usually
  because it belongs to a different proposal.
- **Landing** — empty while the ZRC is `draft`, `review`, or `accepted`.
  Filled in with the commit(s) and any receipt that shows the acceptance
  criteria hold once the ZRC moves to `landed`.
- **Discussion** — where the live conversation about this ZRC happens. Today
  that is board rows carrying the ZRC id
  (see [`../agent/NATIVE_CHANNEL.md`](../agent/NATIVE_CHANNEL.md)); once the
  native signed board and wiki exist (see
  [`0004-wiki-daily-board-public-page.md`](0004-wiki-daily-board-public-page.md)),
  the wiki page for the ZRC becomes the index and this section just points to
  it.

## Rules

1. **Anyone may open a draft.** Any AI executor or the human owner may add a
   new `NNNN-<slug>.md` with `Status: draft` in one commit. No permission is
   required to start a proposal.
2. **There is a review window.** Once a ZRC's status moves to `review`, it
   stays open for comment before it can be accepted, so other agents and the
   owner have a real chance to read it and object.
3. **Acceptance needs the owner or two reviewers, and no open objection.** A
   ZRC becomes `accepted` when either the ZRC's own `Owner` marks it accepted,
   or two reviewers other than the `Owner` do, and in either case only when
   no open objection is on record. An open objection blocks acceptance until
   it is withdrawn or the design changes to answer it.
4. **A ZRC never contains fleet machine details.** No hostnames, no IP or
   onion addresses, no datadir paths, no key material, and no per-machine
   capacity or load numbers. A ZRC describes a design that should read the
   same regardless of which machines run it; operational specifics for one
   node belong in [`../HANDOFF.md`](../HANDOFF.md) or the board, never here.
   This directory is written to be safe to publish.
5. **The project's docs gates apply.** `make lint` runs the same documentation
   gates over `docs/zrc/` as over every other document — link targets must
   resolve, and claims must stay true.
6. **Status changes are commits.** A status change is not complete until it
   is committed; there is no other place a ZRC's current status is recorded.

## Proposals

Numbers are assigned by listing this directory, not by editing a registry;
the lines below are a reading aid, and a ZRC's own header is what its status
means.

- [`0007-asynchronous-p2p-landing.md`](0007-asynchronous-p2p-landing.md) —
  candidates, per-group verdicts and publications as gossiped signed rows, so
  landing is asynchronous, decentralized, and pays only for what a change can
  reach.
- [`0008-process-story-graph.md`](0008-process-story-graph.md) — every
  process step is a passage with entry and exit predicates; evidence carries a
  grade from measured to rumour; a story next leaf deduces the next passage and
  cites what it used; the graph and the wiki replicate across the fleet.
- [`0009-private-fleet-on-a-public-network.md`](0009-private-fleet-on-a-public-network.md) —
  private fleet rooms, chat, presence, and membership ride mesh streams between
  paired members only; the public board, block relay, and DHT never carry a
  private row, room name, or post id that would reveal a private room exists.
- [`0010-composable-proofs.md`](0010-composable-proofs.md) —
  a signed Merkle tree of per-group verdict leaves, so a receiver admits a
  tip when trusted producers' union covers the required closure; covered
  work is never re-proven.
- [`0011-fast-sync-over-the-peer-link.md`](0011-fast-sync-over-the-peer-link.md) —
  signed state offers and a resumable chunked bundle transfer over the
  existing peer link, with sublinear FlyClient-style verification, so a
  fresh node no longer needs an operator-configured file-service host or
  onion catalog address to sync fast.
