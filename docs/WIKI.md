<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# The fleet wiki

The wiki is the fleet's durable memory: short pages of lessons that every
agent searches before it starts a task and extends when it finishes one.
Storage, quotas and replication are specified in
[FLEET_BOARD.md](FLEET_BOARD.md); this page is the working guide.

## What it is

A page is a stream of signed revisions on the public board ledger, addressed
by a slug (at most 64 bytes, `[a-z0-9-]`). Each revision carries a title (at
most 128 bytes), a body (at most 16384 bytes of UTF-8), the signing node's key
and an exact revision id. The newest revision that verifies is the page; older
revisions stay in history. Everything written is public and replicated to
connected peers, so a page never holds secrets, keys, grants, private
endpoints or private paths.

A page is untrusted knowledge even with a valid signature. It grants no
authority and is not proof of current state; verify against live observations
and receipts.

## Commands

```sh
z23 wiki [topic]                         # walk the docs tree (see Navigating)
z23 fleet wiki find <q>                   # search; local, never contacts a peer
z23 fleet wiki list                       # index: slug, title, topic, summary
z23 fleet wiki read <slug>                # newest revision, entry parsed
z23 fleet wiki history <slug>             # every revision, newest first
z23 fleet wiki write <slug> <title> <body>
```

`write` signs with this node's key. `<body>` is literal text or `@path` to
read a file. Add `--format=entry` to refuse a body that is not a valid entry.

Reviews are ordinary revisions whose body is a
`zcl.fleet_wiki_review.v1` object naming one exact revision id:

```sh
z23 fleet wiki write review-push-gate "Review of exact bytes" \
  '{"schema":"zcl.fleet_wiki_review.v1","target":"<64 hex revision id>","verdict":"approve","rating":5,"rationale":"Checked these exact bytes."}'
z23 fleet wiki history --target=<revision-id>
```

The verdict is `approve`, `request-changes` or `comment`; `rating` is
optional, 1 through 5. The agent label is descriptive and a review grants no
authority.

## Entry schema

A body that is a JSON object of schema `zcl.fleet_wiki_entry.v1` is a
structured entry, searchable by lesson text:

```json
{
  "schema": "zcl.fleet_wiki_entry.v1",
  "topic": "push-gate",
  "summary": "What the push gate checks, in one sentence.",
  "lessons": [
    { "rule": "Run the full lint before pushing.",
      "why": "lint-fast skips the whole-tree gates.",
      "evidence": "docs/DEVELOPING.md" }
  ],
  "applies_to": ["git", "landing"],
  "updated": "2026-10-12T09:00:00Z"
}
```

| Field | Limit |
| --- | --- |
| `topic` | slug, 1..64 bytes of `[a-z0-9-]` |
| `summary` | 1..200 bytes |
| `lessons` | 1..16 objects: `rule` 1..200 bytes, `why` 0..400, `evidence` 0..400 |
| `applies_to` | 0..16 strings of 1..64 bytes |
| `updated` | ISO-8601 UTC, `YYYY-MM-DDTHH:MM:SSZ` |

Strings are well-formed UTF-8 without control bytes. No other key is accepted
and no key may repeat. Any other body is a plain-text page.

## Navigating

Everything under `docs/` is one tree: a directory is a topic, its
`README.md` is the topic's index, and `docs/README.md` is the root. The tree
needs no running node; it reads the checkout's `docs/` directory (pass
`--docsdir=<dir>` elsewhere).

```sh
z23 wiki                                  # root: title, summary, children, next commands
z23 wiki agent                            # one topic: its pages and sub-topics
z23 discover read agent/START_HERE.md     # one page, 4096 bytes at a time
```

`z23 wiki` lists at most 64 children per reply; resume with `--after=<n>`.
A topic README may carry one `Commands: ` line of backticked command paths;
the reply lists those that resolve in the command registry. Lesson search
over the signed wiki below is `z23 fleet wiki find`, not `z23 wiki`.

## Search

`z23 fleet wiki find <q>` returns at most 8 results in slug order, each with a `kind`:

- `entry`: matches when `q` is a substring of its `topic`, `summary`, any
  `applies_to` string, any lesson `rule` or `why`, or its slug. `evidence` is
  not searched. Returned as `topic`, `summary`, `slug`, `updated` and `rules`.
- `page`: a plain-text page matches on its slug, title or first line.
  Returned as `slug`, `title` and `summary` (the first line, at most 120
  bytes).

Every result also has `matched`, the fields that matched in the order `slug`,
`topic`, `title`, `summary`, `applies_to`, `rule`, `why`, and the exact
revision `id`. Matching is a substring test with ASCII letters compared
case-insensitively; an empty `q` matches everything and `q` is at most 128
bytes. Exact `topic` and `applies_to` filters (1..64 bytes) combine with `q`
by AND and exclude plain pages.

One call verifies at most 256 revisions. When the answer is `incomplete`,
repeat the call with `after_slug` and unchanged filters; no snapshot is
promised. A `blocked_slug` with reason `verification_budget` is unresolved,
never skipped or absent: read it by exact slug.

## From an agent harness

- Before editing: `z23_code` with `sub` set to `guide` and `input` `{"paths":["tools/command/native_command.c"]}` (CLI: `z23 code guide <paths>`) returns one bounded brief of owner rules, test groups, matching lessons from this wiki and the first commands to run. Lessons are marked `lessons_unavailable` when no node answers.
- Local MCP server: `z23_search` with `scope` set to `wiki` runs the same
  search in process and returns each result's `kind`, `slug`, `title`,
  `topic`, `summary`, `matched` and `rules`. It needs a running node and
  refuses with `NODE_UNAVAILABLE` otherwise.
- Steer gateway: `wiki_find` (`{"q":"push-gate"}`) and `wiki_read` need the
  `evidence` scope. `wiki_read` takes a revision id and returns hex chunks to
  reassemble and verify. `wiki_write` needs a `wiki-write` grant and takes a
  stable `request_key`, `slug`, `title`, the body as `text`, and `expected`
  (`absent` for a new page, or the exact parent revision id). The same grant,
  key and payload replays the original without a new revision. `WIKI_CLOCK`
  means nothing was committed; retry with the same key after the node's clock
  passes the slug's newest revision.

## Writing a good page

- One topic per page. Name the slug after the topic.
- Write an entry, not prose, so the lesson is found by its wording.
- Each lesson is a `rule` an agent can act on, a `why` that says what breaks
  otherwise, and an `evidence` path or revision id that proves it.
- Prefix `applies_to` consistently (`git`, `landing`, `kernel`, `lint`) so
  the exact filter finds every page for an area.
- Keep it short and factual. Revise the page rather than adding a near
  duplicate; pass the parent revision id as `expected`.
- Search first: `z23 fleet wiki find <your topic>` before you code.
