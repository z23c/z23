<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Local data-source index

Z23 produces several local data sources — the fleet board, the experiment
ledger, the landing outcomes ledger, and free-text logs — and until now
nothing indexed them: every question meant a manual grep. `z23-dev dev
index` ingests them incrementally into one sqlite+FTS5 database and answers
questions from that index instead.

## What is indexed

The CLOSED source registry is `engine/composition/sources.def` (an X-macro,
same idiom as the sibling `.def` files under `engine/composition/`). Each
row is `Z23_SOURCE(id_, kind_, root_, path_, format_, why_)`. Today it
declares four sources:

| id | kind | path | format |
| --- | --- | --- | --- |
| `board` | `board_rows` | `board/*.jsonl` under the zclassic23 state root | jsonl |
| `experiments` | `experiment_rows` | `experiments/rows.tsv` under the zclassic23 state root | tsv |
| `landing` | `landing_outcomes` | `land/outcomes.jsonl` under the native dev-state root | jsonl |
| `logs` | `log_lines` | every `*.log` under the zclassic23 state root | text_kv (free text + extracted `key=value` tokens) |

A source id not declared in `sources.def` cannot be ingested, filtered by
`--source=`, or reported by `status`. Adding a fifth source means adding one
row there — nothing else hand-derives a path a second time.

## The three leaves

- `z23-dev dev index ingest [--source=<id>]` — read each declared source (or
  just one) from its saved byte-offset cursor to the last complete line,
  insert one row per new line, and advance the cursor.
- `z23-dev dev index status [--source=<id>]` — per source: row count, newest
  ts seen, seconds since that ts, and bytes not yet ingested. Read-only.
- `z23-dev dev index search <query> [--source=<id>] [--limit=N]` — one FTS5
  `MATCH` query, newest-first. A log line's `key=value` tokens (and every
  structured source's short fields) are flattened into `key:value` search
  terms at ingest time, so `z23-dev dev index search 'kind:result'` matches
  the flattened term the same way a bare word matches free text.

All three write to and read from one file:
`~/.local/state/zclassic23/index/index.db` (override the zclassic23 root
with `ZCL_INDEX_STATE_DIR`, same convention as the sibling evidence-ledger
paths). It holds a `rows` table (source_id, seq, ts, kind, three generic
field columns, the raw line), a `cursors` table (one row per file:
inode/size/byte-offset), and an FTS5 virtual table over the flattened text.

## The incremental rule

Ingest never re-reads what it already saw. Per file, `cursors` keeps the
inode, size, and byte offset consumed so far; the next ingest seeks there
and reads only new complete lines (a trailing line with no final newline
yet is left for the next ingest, never partially indexed). If the file's
inode changed or its size dropped below the saved offset — rotated or
truncated — ingest restarts that file from byte 0 rather than seeking past
data that is no longer there. Every file of one source ingests inside a
single transaction: an earlier version committing one row at a time forced
one fsync-adjacent WAL commit per row, measured making the real
`host_gc/tmp_gc.log` file (256 log files' worth in one ingest call) take
minutes instead of seconds.

## What is NOT indexed yet

- GitHub (issues, PRs, Actions) — this project does not use GitHub issues
  for work tracking (see the fleet board instead), so this was never in
  scope.
- The chainlog / consensus state (node.db, consensus.db) — a different
  question (chain data, not operational logs) with its own tooling
  (`z23 core storage query`, the explorer projections).
- Other hosts' state roots — `dev index ingest` only ever reads this box's
  own `~/.local/state/zclassic23` and dev-state root; a fleet-wide index
  would need the rows replicated here first (the board's own sync path),
  not a new remote-read capability in this leaf.

## Known limits

- The `logs` source caps a single ingest at 256 matched files (a directory
  walk bound, not a per-file line limit); a state root with more `*.log`
  files needs a second `--source=logs` pass after the first files' cursors
  advance, or a narrower source declaration.
- A log line's leading token is trusted as a timestamp only when it looks
  like `YYYY-MM-DDTHH:MM:SS`; anything else leaves that row's `ts` column
  empty (still searchable in the raw text, just not orderable by time).
- `search` scores nothing beyond FTS5's default ranking and returns at most
  50 hits per query.
