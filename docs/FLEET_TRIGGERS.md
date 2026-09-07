<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Fleet triggers

z23 owning its own reactions to local events, instead of a human watching
them by hand.

Today the fleet's reactions to events are hand-run watchers OUTSIDE z23: a
human-side monitor on GitHub discussion comments, another on fleet board
rows, a person noticing a train landed and fast-forwarding checkouts. This
is the first slice of z23 owning that job itself: a declared, closed
registry of triggers over its own local sources, evaluated by one command
that can later run under the resident mind service.

## What this slice is, and is not

- **Is**: a closed registry (`engine/composition/triggers.def`) plus a
  run-once evaluator (`z23-dev fleet triggers check`) that reads whatever is
  new in four local sources and performs one of three actions, including
  posting to the fleet board.
- **Is not**: a daemon. Nothing here polls, sleeps, or stays resident.
  `check` is one call that reads what changed since its last call and
  returns.
- **Is not**: itself networked. Every source is a local file; `print` and
  `ledger` write to a local file or stdout. `board_post` is the one
  exception, and it reaches only the local running node over the same
  `fleet_board` RPC method `fleet board post` uses — never a peer, never a
  shell-out. z23 still has no outbound HTTP seam of its own, which is why
  the GitHub source below is fed, not fetched.

## The registry

`engine/composition/triggers.def` is the one declaration, in the same
X-macro style as `engine/composition/fleet_vitals.def`:

```
Z23_TRIGGER(id_, source_, field_, op_, value_, action_, why_)
```

- `source_` — one of four closed sources:
  - `landing_outcomes` — `<platform_state_root>/land/outcomes.jsonl`, the
    same file `dev.land` itself appends one row to per terminal outcome
    (`tools/command/native_dev_land.c`).
  - `board_rows` — this box's own board file, the per-host JSONL the
    interim `board.sh` tool reads and writes
    (`~/.local/lib/z23/tools/board.sh`), at
    `<state>/zclassic23/board/<hostname>.jsonl`.
  - `experiment_rows` — the interim experiment ledger `exp.sh` appends to
    (`~/.local/lib/z23/tools/exp.sh`), a 22-column TSV at
    `<state>/zclassic23/experiments/rows.tsv`.
  - `github_comments` — `<state>/zclassic23/triggers/github_comments.jsonl`,
    fed by `fleet triggers ingest` (see below), never fetched by z23
    itself.
- `field_` — a field name looked up in the row: a JSON top-level string key
  for the three JSONL sources, a named TSV column (read from the file's own
  header line) for the experiment source. A row that does not carry the
  field is treated as **absent**, never as an empty string — and an absent
  field never matches, for any `op_`, "ne" included.
- `op_` — `eq`, `ne`, `prefix`, `contains`.
- `action_` — `print` (one line on stdout: `TRIGGER <id> <source>
  <field>=<value>`); `ledger` (append one JSON row —
  `{ts,id,source,seq,summary}` — to
  `<state>/zclassic23/triggers/fired.jsonl`); or `board_post` (post one
  `note` to the fleet board, over the same `fleet_board` RPC method `fleet
  board post` uses). `board_post`'s text templates the row's own `body`
  field when present, else `summary`, else `why_`, followed by `(<id>
  <field>=<value>)` so a reader always sees which trigger fired.
- `why_` — one plain sentence: the reason the reaction exists.

An id, source, or field not written down here cannot fire — the same
closed-vocabulary discipline `engine/composition/fleet_vitals.def` and
`engine/modules/fleetledger/src/fleet_ledger_catalog.c` already use for the
fleet ledger's own subjects.

## `<state>`, precisely

Both `<state>` above and `<platform_state_root>` above come from exactly
one resolver, `platform_state_root()`
(`platform/modules/platform/src/state_root.c`), which always returns
`<base>/z23/dev` (base = `XDG_STATE_HOME`, or `~/.local/state`). Triggers'
own state — cursors and the fired ledger — sits beside the interim board
and experiment tools under `<base>/zclassic23`, derived by stripping that
fixed `/z23/dev` suffix rather than reading `HOME`/`XDG_STATE_HOME` a
second time. See `tools/command/native_fleet_triggers_eval.c`.

## Running it

```
z23-dev fleet triggers list
z23-dev fleet triggers check
z23-dev fleet triggers check --since=3600
z23-dev fleet triggers check --dry-run
```

`list` prints the compiled-in registry: every id, source, field, op, value,
action, and why. It reads no file.

`check` reads each source from its own saved byte cursor
(`<state>/zclassic23/triggers/cursors/<source>`: inode, size, offset, and
rows already counted), evaluates every trigger whose source matches
against every row that is new since last time, performs the matched
action, and — unless `--dry-run` — advances the cursor past what it read.
A source file that shrinks or changes inode (rotated, replaced, or
truncated) restarts its cursor at byte zero rather than trusting a stale
offset into different content. `--since=<seconds>` additionally skips
evaluating a row whose own `ts` field is older than that many seconds ago.
`--dry-run` performs the same actions — including a `ledger` append — but
never moves the cursor, so a re-run sees the same rows again; use it to
preview what a real run would do.

A matched trigger whose action returns false (no disk, no node answering a
`board_post`) is fail-closed, not counted as fired: **a failed action holds
the cursor before that row**, so the next `check` retries the exact same
row instead of skipping it, and every later row from the same source waits
behind it until it clears. `check` reports `checked N rows, fired F,
failed M` and exits non-zero with a refusal naming the trigger and the
action's own reason whenever `M` is greater than zero.

All three leaves are bound in `engine/composition/commands/fleet.def` under
`fleet.triggers`, alongside the owner's private fleet ledger.

## The GitHub comment source, and why it is fed, not fetched

z23 has no outbound HTTP seam today (checked at
`grep -a -rln 'https://api.github.com\|gh_api\|http_get' engine tools
contexts cognition --include='*.c'`, which returns nothing): nothing in the
tree can reach out to `api.github.com` on its own. Rather than add one,
`github_comments` is fed by a tiny external adapter — a shell script
calling `gh api` or curl, outside this tree, holding whatever GitHub token
it needs in its own secret store — that writes one JSON object per line and
hands the file to:

```
z23-dev fleet triggers ingest --source=github --file=/path/to/comments.jsonl
```

Every line must carry `kind` (`"comment"`), `owner`, `repo`, `number`,
`comment_id`, `author`, `url`, `body`, and `ts`, all non-empty strings. A
line missing one is skipped, not fatal — re-feeding an overlapping fetch
(the adapter's own since-cursor on the GitHub side, not z23's) costs
nothing. What actually stops a restart from re-firing is the same
per-source byte cursor `check` already keeps for every other source
(`<state>/zclassic23/triggers/cursors/github_comments`): once `check` has
read a row, it stays read across a process restart, same as
`landing_outcomes` or `board_rows` today.

`github_comment_to_board` (in `engine/composition/triggers.def`) matches
every ingested comment row (`kind=comment`) and posts it to the fleet board
with `board_post`, replacing the maintainer's own ad-hoc poll of a GitHub
discussion.

## What comes next

- **The GitHub adapter itself.** This slice defines the ingest leaf and the
  source it feeds; the shell script that actually calls `gh api` for a
  specific discussion (owner/repo/number) and a since-cursor on the GitHub
  side is a separate, small piece of fleet tooling, not part of this tree's
  gated C.
- **Running under the resident mind service**, on the same evaluator this
  document describes: `check` is already safe to call from a loop, because
  every source read is bounded by its own cursor and every action is
  idempotent-by-cursor except a repeated `--dry-run`.
