<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Development system vision

The [North Star](../../AGENTS.md#north-star) says what Z23 is for: software
made for you, not imposed on you. This page says how Z23 is built and grown by
people and AI agents together, and what the development system is converging
on. Each section states the target and what exists on `main` today.

Commands: `discover.wiki`, `lab.run`, `lab.test`, `code.kpi`

## The idea

Every piece of work is **one file and an oracle**. The file runs against
reality in milliseconds, and the result is kept as a signed receipt that any
node can reuse. Everything else follows from that.

The repository measured this before it was a principle:
[FLASH_UNIT.md](FLASH_UNIT.md) recorded agents finishing 0 of 10 multi-file
tasks and 2 of 2 single-file tasks with a pinned test. Small context, one
oracle and immediate ground truth are what make an agent reliable and cheap.

## Three verbs

An agent arriving at any node needs three verbs:

| Verb | Question it answers | Today |
|---|---|---|
| `z23 wiki` | Where is it? One nested tree of docs topics, commands and lessons. | `discover.wiki`, `discover.read` |
| `z23 lab` | Does it work? One C23 file, compiled and run confined, JSON result and receipt. | `lab.run`, `lab.test`, `lab.show` |
| `z23 card` | What should I do next? A task sized to the model taking it. | `work.list`, `work.show`: the board cards (`z23 card`, `z23 card show <id>`); lab cards are not yet native |

The CLI and the MCP server are two views of one command registry with one
JSON envelope. Claude Code, Codex or a person at a terminal receive identical
answers; harness adapters stay thin and replaceable.

## One file is the unit

New capability grows along one path, not into the core binary:

```text
lab file  ->  plugin  ->  commons package  ->  reproduced result
```

- A file that passes its oracle becomes a signed plugin without a rewrite.
  Target: a one-shot plugin kind (interface 2) that runs the installed,
  signed executable once per call through the same confined runner as the
  lab, so a plain `main` reading stdin and writing stdout is already a plugin.
- A product is a set of one-file plugins, each with its own cases.
- The core (consensus, custody, network) stays small and sealed; the
  repository's capability grows while the core does not.

## Receipts are shared memory

Every lab run, test group and landing yields a receipt keyed by the hash of
its exact inputs. An agent looks up a result before computing it, first on its
own node, then on peers. This is how agents share work without a central
server: Z23 is peer to peer and permissionless, with no signup, and each node
runs its own Z23.

## Cards sized to the model

A card names one file, its cases and a budget. Most cards should be small
enough for the fastest, cheapest model to finish. For a lab card the oracle is
the reviewer; changes to the sealed core keep independent review. Volunteers
take cards from any node and return receipts.

## The binary always improves

No command tier is frozen or hidden. Every leaf has a quality measure on the
scoreboard (`z23 code kpi`), and the weakest leaves become the next cards.
Floors in `tools/lint/kpi_floor.txt` only tighten. Deleting code while every
oracle still passes counts as progress.

## Nothing private in the loop

Every step a maintainer performs (landing, release, cleanup) is a `z23`
command, not a host script. A release ships the command-line binary and its
documentation together, so `z23 wiki` and `z23 lab` work on any installed
node, not only inside a checkout.

## How progress is measured

| Measure | Target | Today |
|---|---|---|
| New agent to first useful result | under 1 minute, three commands | not measured |
| Lab compile and run, warm | under 300 ms | 135 ms on a build host |
| Small-model card completion | above 80% | not measured |
| Tokens per landed card | falling | not measured |
| Duplicate helper bodies | falling | tracked by `check-kpi-floor` |

## Next steps

1. One-shot plugins (`plugin.call`), then `lab.promote`: a passing lab file
   becomes a signed plugin unchanged.
2. MCP `z23_lab` tool, so every harness gets the same loop natively.
3. Lab cards on the board, with per-card cost and completion recorded.
4. Releases ship documentation; landing and release become `z23` commands.
5. An experiment comparing lab cards with in-tree edits on completion rate
   and tokens.
