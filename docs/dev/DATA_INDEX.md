<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Local data-source index

Search the local fleet board, experiment ledger, landing outcomes, and logs
with `z23-dev dev index`. You need the development binary (`z23-dev`) on
your command search path and local source files first. Ingest before
searching: these commands use a SQLite database with FTS5, SQLite's
full-text search extension.

## What is indexed

The closed source registry (the complete list of accepted sources) is
`engine/composition/sources.def`. Its X-macro rows are expanded by the
source catalog; each row is
`Z23_SOURCE(id_, kind_, root_, path_, format_, why_)`. It declares four
sources. The zclassic23 state root is `~/.local/state/zclassic23`; the
native dev-state root is resolved by `platform_state_root()`. JSONL stores
one JSON object per line; TSV stores tab-separated values.

| id | kind | path | format |
| --- | --- | --- | --- |
| `board` | `board_rows` | `board/*.jsonl` under the zclassic23 state root | jsonl |
| `experiments` | `experiment_rows` | `experiments/rows.tsv` under the zclassic23 state root | tsv | <!-- doc-path-ok: a runtime path under the state root, not a repo path -->
| `landing` | `landing_outcomes` | `land/outcomes.jsonl` under the native dev-state root | jsonl |
| `logs` | `log_lines` | every `*.log` under the zclassic23 state root | text_kv (free text + extracted `key=value` tokens) |

A source id not declared in `sources.def` cannot be ingested, filtered by
`--source=`, or reported by `status`. Source paths are derived from
that registry.

## The three leaves

A leaf is a command at the end of the command tree. To index and search:

1. Read the new complete lines into the index:

   ```sh
   z23-dev dev index ingest
   ```

2. Check row counts and how far ingestion is behind:

   ```sh
   z23-dev dev index status
   ```

3. Search the indexed rows:

   ```sh
   z23-dev dev index search 'kind:result'
   ```

- `z23-dev dev index ingest [--source=<id>]` — read each declared source
  (or just one) from its cursor (the saved byte offset) to the last complete
  line. Insert each new line once, then advance the cursor; identical rows
  are ignored (see "Identity, not just a cursor" below). Reports
  `rows_added` and `rows_skipped` per source. Skipped rows include parse
  failures and format headers. This maintenance leaf has a 5000 ms latency
  budget; the read leaves have a 250 ms budget.
- `z23-dev dev index status [--source=<id>]` — per source: row count, newest
  timestamp (`ts`), seconds since that timestamp, bytes not yet ingested,
  and cumulative `rows_skipped`. Read-only; a missing index is not created.
  It reports `index_exists: 0` with no per-source data instead.
- `z23-dev dev index search <query> [--source=<id>] [--limit=N]` — full-text
  search, newest first. Each whitespace-separated word is quoted for FTS5
  `MATCH`; multiple words must all match. The default limit is 20, capped
  at 50. Log `key=value` tokens and structured sources' short fields are
  flattened into `key:value` search terms during ingest. For example,
  `z23-dev dev index search 'kind:result'` matches the flattened term in the
  same way a bare word matches free text. A missing index is not created.

Every leaf accepts two explicit command-line overrides:

| Flag | Effect |
| --- | --- |
| `--index=<path>` | Use this SQLite file location verbatim. |
| `--state-root=<dir>` | Read every declared source relative to this root. |

`--index` changes only the database location. Without `--index`,
`--state-root` also places the database at `<dir>/index/index.db`. With
neither flag set, the default index path is
`~/.local/state/zclassic23/index/index.db`. The database holds a `rows`
table (source_id, seq, ts, kind, three generic field columns, the raw line,
and `row_key`), a `cursors` table (one row per file: inode/size/byte-offset/
prefix hash/cumulative rows_skipped), and an FTS5 virtual table over the
flattened text.

## Identity, not just a cursor

A `rows` row is only ever inserted once for a given (source_id, row_key)
pair, where `row_key` is a SHA3-256 content hash of the source id, a `0x1f`
separator, and the line text with its trailing line feed (LF)
or carriage return plus LF (CRLF) removed. A `UNIQUE` index and
`INSERT ... ON CONFLICT DO NOTHING` enforce this identity.
Row identity prevents duplicates even when a replaced file must be read
again:

- **A rename onto identical bytes** (`mv` with the same content) does not
  duplicate anything: even restarting from 0 and re-reading every line, the
  identical (source_id, row_key) pairs are rejected by the `UNIQUE` index.
- **A rename onto grown content** (the common case — a writer builds a temp
  file with the old lines plus new ones, then `mv`s it into place) ingests
  exactly the new lines: the old ones conflict and are ignored.
- **A same-size in-place rewrite** (content changes, inode and size do not)
  is not missed. Each cursor also stores a SHA3-256 hash of the file's own
  first `byte_offset` bytes as of the last successful ingest. The next
  ingest re-hashes those same bytes off whatever is on disk now and only
  trusts the saved offset when the two hashes still match — a saved offset
  larger than the current file size is rejected before hashing. An inode
  change alone does not determine whether the saved offset is trustworthy.

## The incremental rule

Ingest resumes reading lines at the saved offset when the prefix hash still
matches (see above). Prefix verification re-reads the earlier bytes.
A trailing line with no final newline yet is left for the next ingest,
never partially indexed. Every file of one source ingests inside a single
transaction, including its cursor updates.

## What is NOT indexed yet

- GitHub (issues, PRs, Actions) — this project does not use GitHub issues
  for work tracking (see the fleet board instead), so these are outside
  the source registry.
- The chainlog / consensus state (node.db, consensus.db) — a different
  question (chain data, not operational logs) with its own tooling
  (`z23 core storage query`, the explorer projections).
- Other hosts' state roots — by default, `dev index ingest` reads this box's
  own `~/.local/state/zclassic23` and dev-state root; a fleet-wide index
  would need the rows replicated here first (the board's own sync path),
  not a new remote-read capability in this leaf.

## Known limits

- The `logs` source caps a single ingest at 256 matched files (a directory
  walk bound, not a per-file line limit); a state root with more `*.log`
  files needs a narrower source declaration; another `--source=logs` pass
  selects the same bounded file list when the directory tree is unchanged,
  even after those cursors advance.
- A log line's leading token is trusted as a timestamp only when it looks
  like `YYYY-MM-DDTHH:MM:SS`; anything else leaves that row's `ts` column
  empty (still searchable in the raw text, just not orderable by time).
- `search` orders by newest timestamp, then newest row id, and returns at most
  50 hits per query.
