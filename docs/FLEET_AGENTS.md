<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# The fleet agent dashboard

Copyright 2026 Rhett Creighton. Licensed under the Apache License, Version 2.0.

Several AI executors work this repository at the same time — subagents in
their own lane worktrees, single scoped units, landing trains, the native
landing worktree — each under a different harness. One command says who is
working, on what, and how good each of them has been:

```
build/bin/z23-dev fleet agents
```

Plain, it reads only this machine and writes nothing. Two flags reach past
this box, both through the local node's fleet board:

```
build/bin/z23-dev fleet agents --publish
build/bin/z23-dev fleet agents --fleet
```

`--publish` posts this box's RUNNING-NOW and GRADES rows as one fleet-scoped
`agents` board post; `--fleet` reads the newest such post per host and merges
it with this box's own live rows. Neither talks to any host directly and
neither is a second board: both call the same `fleet_board` RPC method
`fleet board post`/`fleet board list` already use, and both fail closed with
`NODE_UNAVAILABLE` when no local node answers.

## What it prints

Three sections, always in this order.

**RUNNING NOW** — one row per agent workspace, with the name, the kind
(`lane`, `unit`, `train`, `landing`), the short HEAD, the number of files Git
reports dirty, how long ago the newest source file changed, how long ago the
Git state changed, the live processes whose working directory is inside the
tree, and the tip sha in the workspace's `READY` marker when it has written
one. Then this box's loaded `z23-*` systemd user services.

**GRADES** — one row per executor, or per lane or task class with `--by`,
read from the delegation ledger described below.

**OTHER HOSTS** — by default, one honest line saying no other machine is
collected yet. With `--fleet`, it instead reads the local board's `agents`
posts (see below) and becomes a merged table.

## `--publish`: this box's rows, posted

The post body is a compact, line-based text (not the JSON `--json` prints):
a header naming this box (`v1|host=<name>|now=<unix>`), one `R|name|kind|
head|dirty|process_count` line per RUNNING-NOW row, and one
`G|key|tasks|success|failure|success_rate_bp|grade` line per GRADES row.
Trimmed to stay under the board's per-post text ceiling. `agent` on the post
is this box's name; `kind` is `agents`; `scope` is `fleet`.

Publishing the same body twice inside one minute is a no-op: `--publish`
first reads its own newest `agents` post back (`fleet board list --kind
agents --scope fleet --host <this box>`) and skips the RPC write when the
text is unchanged and that post landed in the same 60-second window. The
reply carries `{posted, id, host}` (`posted:false` on a skip).

There is no node service that calls `--publish` on a timer today: the rows
it posts (Git worktrees under `~/.z23`, the delegation ledger) are checkout
state a running node process does not have visibility into, so wiring this
into a node-side periodic job would mean teaching the node about dev-lane
layout it otherwise never touches. Publishing stays a command an agent (or
a cron/systemd timer in the checkout) runs, not a node service.

## `--fleet`: the newest post per host, merged

Reads up to 32 `agents` posts (`fleet board list --kind agents --scope
fleet`), keeps the newest one per host (the list is already newest-first),
and merges those with this box's own live RUNNING-NOW/GRADES counts into one
`hosts` array — self first, then every other host, each row's `name` taken
from that host's own post header (the only name a host has told the board;
no seam in this tree maps a board key to an operator-assigned name today),
its `age_s` since the post's signed `created_at`, `stale:true` past 15
minutes, and `running_rows`/`grade_rows` counted from its body. The text
render adds `hosts reporting: N of M known (stale > 15m marked)`; `M` is the
fleet machine roster's admitted-box count when this box has one to read,
else the same as `N`.

## Options

| Flag | Meaning |
| --- | --- |
| `--since=<hours>` | Grade only the result rows inside this window. `0` grades the whole ledger. Default 168 (seven days). Maximum 8760. |
| `--by=executor\|lane\|class` | Group the grades by executor (default), by the lane or story name, or by task class. |
| `--root=<dir>` | Scan `<dir>/lanes`, `<dir>/units`, `<dir>/trains`, `<dir>/land` and read markers from `<dir>/scratch` instead of the real locations. This exists for the tests. |
| `--ledger=<path>` | Read a different ledger file. |
| `--include_units=false` | Skip the systemd read. |
| `--publish=true` | Post this box's rows to the local node's fleet board (mutates). |
| `--fleet=true` | Merge the board's `agents` posts into OTHER HOSTS. |
| `--json` | Print the machine object instead of the table. |

The plain table and `--json` are rendered from the same data object, so the
two can never report different numbers.

## Where "running" comes from, and what it does not mean

A workspace is listed when a live process is working inside it, or when its
Git state moved in the last twelve hours. Both counts are printed, along with
how many workspaces were scanned in total and how many are idle, so a short
list is never mistaken for a complete survey.

A running process is evidence of **activity** and never of a result. So is a
running systemd unit, and so is a `READY` marker: it is the tip sha an
executor wrote when it believed its work was done, reported verbatim and
never interpreted. Verdicts come from gate receipts. No gate may cite this
command.

This box carries a couple of hundred workspaces. Asking Git about each costs a
process, and walking each source tree costs thousands of metadata reads, so
every workspace is priced at two cheap metadata reads (its Git `HEAD` and
`index`) and the expensive reads are spent only on the ones that are actually
live. Past a short internal wall the remaining rows report `-` rather than a
number nobody waited for.

## The ledger it reads

By default `~/.local/state/zclassic23/experiments/rows.tsv`. Every delegation
writes two rows there: a `predict` row before the work starts and a `result`
row after it finishes, sharing one `task_id`. The file is tab separated with
twenty-two columns, in this order:

```
ts  kind  box  task_id  task_class  story  executor  harness  model  effort
tokens_in  tokens_out  tokens_cache  tokens_reasoning  tool_uses  turns
wall_s  outcome  lines_added  lines_removed  defects  note
```

`ts` is UTC, `YYYY-MM-DDTHH:MM:SSZ`. `kind` is `predict` or `result`. A
`predict` row carries its estimate in `tokens_in` and `wall_s`. A line with
fewer than twenty-two columns, an unparseable timestamp, or a `kind` that is
neither word is reported **by line number** and skipped; it never fails the
command and is never guessed at.

## How a grade is computed

Outcome words are read three ways:

- **Success** — `LAND`, `READY`, `landed`, `PASS`.
- **Failure** — `HOLD`, `FAIL`, `failed`, `timeout`.
- **Other** — anything else, including `unknown`. These are counted and
  reported separately and are kept **out** of the rate: a denominator that
  includes rows nobody scored is a rate nobody can act on.

The success rate is successes over successes plus failures. The ratio is the
median of actual `wall_s` over the `wall_s` a `predict` row promised, paired
by `task_id` and taking the latest prediction that is not newer than the
result. Medians take the lower of the two middle values on an even count, so
every number printed is a value the ledger actually recorded.

| Grade | Requires |
| --- | --- |
| A | success ≥ 90% **and** median ratio ≤ 1.50 |
| B | success ≥ 80% **and** median ratio ≤ 2.00 |
| C | success ≥ 65% |
| D | success ≥ 50% |
| F | below that |

Two cases earn no letter at all. Fewer than three result rows prints
`n/a (n<3)`: three points is already generous, and a letter over one sample
would be read as a fact. And an executor whose results were never predicted
has no ratio, so it cannot reach A or B — its grade is capped at C, because
"always lands, four times slower than promised" is not an A and the ledger
cannot tell the two apart without a prediction.

## What is not collected yet

- **Every other machine.** Local only, by design, until the fleet board
  carries these rows between hosts.
- **Cost in money.** The ledger records tokens, not spend; `z23 fleet usage`
  owns per-provider spend.
- **What an agent is actually doing.** The command reports that a process is
  alive in a tree, not what it is working on.
- **Whether a `READY` marker is true.** It is reported, never checked.

## Where the code is

- `tools/command/native_dev_agents_command.c` — the leaf and its refusals.
- `tools/command/native_dev_agents_ledger.c` — the ledger reader and grades.
- `tools/command/native_dev_agents_scan.c` — the workspace, process and unit
  scan.
- `tools/command/native_dev_agents_render.c` — the aligned-column rendering.
- `tools/command/native_dev_agents_publish.c` — `--publish` and `--fleet`:
  the post body, the dedupe check, and the RPC round trip to the local node.
- `engine/composition/commands/fleet_agents.def` — the registry row.
- `cognition/modules/session/include/session/fleet_board_proto.h` — the
  `agents` post kind.
- `tests/harness/src/test_fleet_agents.c` — the acceptance bar, proved against
  its own fixtures with an injected clock and a faked local node (see
  `node_rpc_client_set_test_hook`).
- `tests/harness/src/test_fleet_board.c` — proves the `agents` kind signs,
  stores, and lists like any other kind.
