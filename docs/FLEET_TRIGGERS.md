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
  new in three local sources and performs one of two actions.
- **Is not**: a daemon. Nothing here polls, sleeps, or stays resident.
  `check` is one call that reads what changed since its last call and
  returns.
- **Is not**: networked. Every source is a local file; every action writes
  to a local file or stdout. No trigger posts to the fleet board, and no
  trigger reads a GitHub discussion — those are named below as what comes
  next.

## The registry

`engine/composition/triggers.def` is the one declaration, in the same
X-macro style as `engine/composition/fleet_vitals.def`:

```
Z23_TRIGGER(id_, source_, field_, op_, value_, action_, why_)
```

- `source_` — one of three closed sources:
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
- `field_` — a field name looked up in the row: a JSON top-level string key
  for the two JSONL sources, a named TSV column (read from the file's own
  header line) for the experiment source. A row that does not carry the
  field is treated as **absent**, never as an empty string — and an absent
  field never matches, for any `op_`, "ne" included.
- `op_` — `eq`, `ne`, `prefix`, `contains`.
- `action_` — `print` (one line on stdout: `TRIGGER <id> <source>
  <field>=<value>`) or `ledger` (append one JSON row —
  `{ts,id,source,seq,summary}` — to
  `<state>/zclassic23/triggers/fired.jsonl`).
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

Both leaves are bound in `engine/composition/commands/fleet.def` under
`fleet.triggers`, alongside the owner's private fleet ledger.

## What comes next

- **A board-post action.** The native board leaf itself is changing in
  train 44 (see `tools/command/native_fleet_board_command.c`); a trigger
  that posts to the board waits for that leaf to settle rather than
  binding to an interface about to move.
- **A GitHub source**, read through whatever relay ends up carrying GitHub
  discussion comments into z23, so a trigger can react to an owner comment
  the same way it reacts to a landing outcome today.
- **Running under the resident mind service**, on the same evaluator this
  document describes: `check` is already safe to call from a loop, because
  every source read is bounded by its own cursor and every action is
  idempotent-by-cursor except a repeated `--dry-run`.
