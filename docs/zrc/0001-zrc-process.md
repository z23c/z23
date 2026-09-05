<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# 0001: The ZRC process

| Field | Value |
|---|---|
| ZRC | 0001 |
| Title | The ZRC process |
| Status | accepted |
| Owner | orchestrator |
| Created | 2026-09-05 |
| Supersedes | none |

## Problem

Several AI executors and the human owner work on Z23 at the same time. The
project already has [`../adr/`](../adr/) for decisions made about the
existing architecture, and `docs/work/` for the one current plan, but neither
gives an ownerless, numbered way to open a proposal for a new subsystem or
standing rule, invite review from whoever is working on the project, and
carry an auditable acceptance record before the implementation starts. A
proposal that only lives in one agent's working notes or one lane's branch is
invisible to everyone else and disappears when that lane ends.

## Design

Adopt the ZRC process described in [`README.md`](README.md): a directory of
numbered files, `NNNN-<slug>.md`, each carrying the header fields `ZRC`,
`Title`, `Status`, `Owner`, `Created`, `Supersedes`, and the body sections
Problem, Design, Acceptance, Out of scope, Landing, Discussion, in that order.

Status moves forward only, through `draft`, `review`, `accepted`, `landed`,
`superseded`. Anyone may open a draft. A draft becomes accepted when its
owner or two other reviewers agree with no open objection on record. A ZRC
never names a fleet machine. Every status change is its own commit. The
project's existing documentation gates (`make lint`) apply to this directory
exactly as they apply everywhere else in `docs/`.

This ZRC is itself the first document written under the process it defines,
so `README.md` and this file are accepted together in the same commit that
establishes the directory.

## Acceptance

- `docs/zrc/README.md` states the file-naming rule, the six header fields,
  the five-state status lifecycle, the six required body sections, and the
  six rules (open, review, acceptance, no machine details, gates apply,
  status changes are commits).
- A ZRC file that is missing a required header field or a required section is
  not itself machine-checked by this ZRC — that is future tooling's job — but
  every ZRC landed alongside this one (0002 through 0004) follows the shape
  exactly, demonstrating the process on its own first proposals.
- `make lint` passes on this directory the same way it passes on the rest of
  `docs/`.

## Out of scope

This ZRC does not build any tooling that machine-checks a ZRC's shape, does
not define a rejection status beyond `superseded`, and does not convert any
existing ADR into a ZRC. It also does not define the native signed board or
wiki that a later ZRC's `Discussion` section points to — see
[`0004-wiki-daily-board-public-page.md`](0004-wiki-daily-board-public-page.md).

## Landing

This ZRC defines a process, not a subsystem; there is no further
implementation for it to land beyond adopting the process, which happens in
the commit that adds this directory.

## Discussion

Opened and accepted directly in the commit that creates `docs/zrc/`, per the
owner's directive to establish a lightweight proposal process for Z23. Future
discussion of the process itself happens the same way as for any other ZRC:
board rows carrying `zrc-0001` until the native board and wiki in
[`0004-wiki-daily-board-public-page.md`](0004-wiki-daily-board-public-page.md)
land, and the wiki page for this ZRC afterward.
