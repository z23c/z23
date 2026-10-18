<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# New-agent front door

Date: 2026-10-18. Compiler: gcc 14.2.0. CPU: AMD Ryzen 9 7950X3D 16-Core
Processor.

## Question

How many commands does a new agent need, starting at the bare `z23`, to reach a
passing lab test, and where does the path dead-end?

## Before (installed release, measured as a new agent)

Six commands to the first passing lab test, two dead ends:

| Step | Result |
|---|---|
| `z23` | Status line `node=blocked ... next_action=z23 core sync blockers`; points a newcomer at sync blockers. |
| `z23 card` | `UNKNOWN_COMMAND`. |
| `z23 discover search "first steps"` | Top 5: `dev.proof.step`, `zcode.package.rollback`, `core.wallet.recovery.restore`, `ops.telemetry.watch`, `zcode.package.add.plan`. |

`help` took 12 ms and a lab test 93 ms. The vision (`docs/agent/VISION.md`) names
three verbs, `z23 wiki`, `z23 lab` and `z23 card`; the bare command named none.

## Change

- Bare `z23` on a terminal prints `start: z23 wiki · z23 lab run hello.c · z23 card`
  after the status output (`zcl_cli_render_start_hint`). Pipes and
  `ZCL_HUMAN=0` output is unchanged.
- `card` is a bare root aliasing `work.list`; `card.show` aliases `work.show`,
  so `z23 card show <id>` resolves.
- `start, first, steps, begin, newcomer, onboarding` tags on `discover.wiki`,
  `lab.run`, `lab.test` and `work.list`; the phrase tags `getting started` and
  `new agent` on `discover.wiki`.

## After (lane build, development binary)

| Step | Result |
|---|---|
| `z23` | Status output, then the `start:` line naming the three verbs. |
| `z23 discover search "first steps"` | `discover.wiki`, `lab.run`, `lab.test`, `work.list`, `dev.proof.step`. |
| `z23 lab test tests/fixtures/lab/adder.c --cases=<json>` | `status` passed. |

The path is `z23` then `z23 lab test`: two commands, no dead end; the search is optional. `z23 card`
resolves to `work.list`; it answers `NODE_UNAVAILABLE` when no node runs, because
the cards are read from the node's board.

Timings on the development binary (three runs, wall clock): `discover help`
25 ms, `discover search` 19-28 ms, `lab test` 61 ms for the first run (compile)
and 14-26 ms on cache hits. The development binary is not the release binary,
so these figures are not comparable with the release timings above.

## Search ranking

`SEARCH_RANK_TUNING` hit@1/hit@5 21/25 and 23/25 before and after;
`SEARCH_RANK_HELD_OUT` 8/10 and 9/10 before and after. The new
`SEARCH_RANK_FRONT_DOOR` block (`first steps`, `start`, `getting started`,
`new agent`) places `discover.wiki`, `lab.run` or `work.list` in the top three
for all four queries, and `core.wallet.recovery.restore` is absent from the top
five for `first steps`.

## Limits

The `start:` line names `hello.c`; a newcomer outside a checkout has no such
file, so the line is a pointer to the verb, not a runnable command there.
`lab` runs on Linux only.
