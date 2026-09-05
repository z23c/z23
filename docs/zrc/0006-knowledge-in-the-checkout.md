<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# 0006: Knowledge in the checkout

| Field | Value |
|---|---|
| ZRC | 0006 |
| Title | Knowledge in the checkout |
| Status | accepted |
| Owner | orchestrator |
| Created | 2026-09-05 |
| Supersedes | none |

## Problem

Every AI reader that needs to know how the landing path works, how a lint
gate is wired, how a file routes to its test groups, or how a board post is
signed, derives that map by reading source. The derivation is long — tens of
thousands of tokens of reading to produce a few dozen sentences — and the
result lives only in that reader's context. When the reader finishes, the map
is gone. The next reader, often on the same day and on the same node, pays
the same bill for the same answer.

The repository is full of durable writing, but almost none of it is written
in a shape a machine can check. A paragraph in a design document that says
"the receipt carries ten content roots" is indistinguishable, to every tool
in the tree, from a paragraph that said that two years ago and is now wrong.
So a reader who finds the paragraph still has to go and confirm it against
the code — which is the whole derivation again. Prose that cannot be
mechanically re-proved does not remove the cost; it only relocates it.

The owner named this directly on 2026-09-05: "always be building things you
need to know into z23 so you don't have to burn tokens to learn in the
future." That is a demand for a surface, not a document: verified facts must
live in the tree, be queryable in milliseconds, and go red the moment one
stops being true.

## Design

### The rule

1. **Readers are one-time.** A map derived by reading source is a bill paid
   once and thrown away. Landing that map as rows is what makes it an asset.
2. **Every map lands as rows.** When a lane or a reader derives how some part
   of this tree works, the durable output is rows in
   `engine/composition/facts/`, not only a report.
3. **A claim without a path and an anchor is not a fact.** It is an opinion,
   and it does not go in the table. The path says where the claim was read
   from; the anchor is the literal text in that file that made it true.

### The row

Facts live in `engine/composition/facts/`, one file per topic, in the same
X-macro `.def` style the rest of `engine/composition/` uses. Each row is:

```
ZCL_FACT(topic, key, claim, path, anchor)
```

| Field | Rule |
|---|---|
| `topic` | Dotted id, e.g. `landing.proof`. Identical on every row in its file, so a row read alone still says what it is about. |
| `key` | `snake_case`, unique within the topic, at most 48 characters. |
| `claim` | ONE sentence, at most 160 characters, no tab and no quote character. What is true, in the words the next reader needs. |
| `path` | Repo-relative path to the file the claim was read from. |
| `anchor` | A literal substring of that file, at most 80 characters. This is what makes the row a fact rather than an opinion. |

`index.def` lists the topics and includes their files. Adding a topic is two
lines there plus the new file — no reader anywhere keeps a second list.

The first topics are the maps that were being re-derived most often:
`landing.proof`, `landing.queue`, `lint.gates`, `tests.routing`,
`fleet.board`, `fleet.swarm`, and `naming` — the last because short names in
this tree read like families that they are not (`zfc` names exactly two
FlyClient snapshot-sync messages, and `.zfctmp` is an unrelated temp-file
suffix). Run `z23-dev dev agent orient` for the current list and counts;
this paragraph names the starting set, not the authority.

The anchor is the load-bearing field. It is chosen to be the thing that would
have to change for the claim to stop being true: a symbol name, a `#define`,
an exact string literal, a `CREATE TABLE` line. An anchor picked because it
is easy to match — a common word, a shebang line — proves nothing, and
weakening an anchor to keep a failing row is the one move this design cannot
survive.

### The leaf

`z23-dev dev agent orient` renders the table. Three forms, and nothing else
to learn:

```
z23-dev dev agent orient                     # every topic, with a row count
z23-dev dev agent orient <topic>             # that topic's rows
z23-dev dev agent orient --query=<substring> # matching rows, across topics
```

`--query` matches case-insensitively against each row's key, claim and path,
and composes with a topic. The reply is the ordinary `zcl.result.v1` envelope
plus a `lines` array — the human view, one line per fact, shaped
`key  claim  - path @anchor`. The table is compiled into the binary, so the
answer costs no file IO and no process: the whole query is a table scan over
constant strings.

An undeclared topic is refused by name and the refusal lists the topics that
do exist, so a typo costs one call rather than two. An empty `--query` result
is reported as a true count of zero — "nothing is known about this yet" is a
useful answer and is not the same as a bad topic.

The leaf nests under `dev.agent` rather than becoming a new `dev` child
because the top-level `dev` menu already renders 3045 of its 3072
`ZCL_COMMAND_BRANCH_BUDGET` bytes; that budget is raised for nobody (see
`tools/lint/check_describe_budget.sh`), and the same nesting precedent is
already recorded for `ops.debug.rom_seed` in
[`../ROM_DELIVERY.md`](../ROM_DELIVERY.md). It also belongs there: this is a
checkout question answered natively, next to `dev agent rules` and
`dev agent start`.

Both opening leaves — `dev fleet start` and `dev agent start` — carry one
line naming the row count and how to query it, counted from the compiled
table rather than typed, so an agent does not have to discover that the table
exists.

### The gate

`make check-orient-facts` (`tools/lint/check_orient_facts.sh`) re-proves the
whole table on every commit. For every row: the `path` must exist, and the
`anchor` must be found in it by `grep -a -F -q`. It also enforces key
uniqueness within a topic, the length caps, no tab in any field, and that
every row's topic is one the index declared. A row that scans zero rows —
a missing index, an empty topic file — is a failure, not a pass.

**There is no baseline file and no exemption list, deliberately.** Both are
ways to keep a false row. When the gate goes red, the fix is to rewrite the
row against what the code now says, or to delete it. Never to soften the
anchor until it matches again.

### Adding a topic

1. Write `engine/composition/facts/<topic>.def` with its rows. Verify each
   anchor as you write it: `grep -a -F -q -- "<anchor>" <path>`.
2. Add two lines to `engine/composition/facts/index.def` — the
   `ZCL_FACT_TOPIC` row and the `#include`.
3. Run `make check-orient-facts`. Drop any row it rejects.

Nothing else changes: no reader, no test, no Makefile.

### How an agent should orient

Query first; read only the gap.

```
z23-dev dev agent orient --query=<the file or subsystem you are about to touch>
```

If the table answers, that is the answer — the anchor was re-proved by the
last commit's gate. Read source only for what the table does not cover, and
when that reading produces a map worth having, land it as rows in the same
lane. That is the loop: the cost of learning something in this tree is paid
once by whoever learns it first.

## Acceptance

- `engine/composition/facts/index.def` exists, declares every topic, and is
  the only list of topic files in the tree.
- `z23-dev dev agent orient` lists topics with per-topic row counts;
  `... orient <topic>` returns that topic's rows; `... --query=<substring>`
  filters across topics; an undeclared topic is refused with `UNKNOWN_TOPIC`
  naming the declared topics.
- `make check-orient-facts` passes on a true table, fails when any row's path
  is missing or its anchor is not in that path, and fails when zero rows were
  scanned. It carries no baseline file.
- `check-orient-facts` is in both `LINT_GATES` and `LINT_FAST_GATES` in
  `Makefile` and in `gate_command()` in `tools/lint/run_lint.sh`, so
  `make check-lint-gate-wiring` reports exact parity.
- The `test_dev_orient` group proves the three query forms, the refusal, and
  that the checker rejects a fixture row whose anchor has moved.
- `dev fleet start` and `dev agent start` each report the row count from the
  compiled table.

## Out of scope

This ZRC does not replace `docs/adr/`, `docs/work/`, or any prose
documentation: a fact row is one checkable sentence, not an explanation, and
the two are complements. It does not make the table replicable across the
fleet — every node compiles its own checkout's rows, and a signed, gossiped
fact table is a later proposal if one is wanted. It does not automate row
extraction: rows are written by whoever did the reading, because the claim is
the part a machine cannot check and a human or an agent must stand behind.
It also does not touch the cognition-layer code index, which answers a
different question (where is this symbol) from a different source.

## Landing

Landed with the commits that add `engine/composition/facts/`,
`tools/command/native_dev_orient.c`, `tools/lint/check_orient_facts.sh`, and
`tests/harness/src/test_dev_orient.c`. The receipt that the acceptance holds
is `make check-orient-facts` plus the `test_dev_orient` group; both run in
the ordinary umbrella, so the acceptance is re-proved on every commit rather
than once at landing.

## Discussion

Opened under the owner's 2026-09-05 directive, quoted in Problem above.
Board rows carrying `zrc-0006` until the native signed board and wiki in
[`0004-wiki-daily-board-public-page.md`](0004-wiki-daily-board-public-page.md)
land, and the wiki page for this ZRC afterward.
