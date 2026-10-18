<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Product health census

Date: 2026-10-18 (UTC). Revision: `d0a7aa0af`. Binary: `build/bin/z23-dev`
built from that revision with GCC 14.2.0 on an AMD Ryzen 9 7950X3D, Linux.
Method: read-only sweeps; every finding below was reproduced a second time
before a fix was written, and claims that did not reproduce are listed as
such.

## Question

Does every part of z23 work, carry tests and documentation, and present a
consistent interface? The answer sets the order of consolidation work.

## v1 acceptance

`z23 milestone` on a long-running node: **6 of 8** criteria pass. Open:
the seven-day soak (needs a clean 168-hour window) and consensus parity over
that window (needs the reference client reachable for comparison).

## Command surface

Every leaf was enumerated by walking `discover help <path> --format=json`
from the 16 roots: **759 leaves**, 723 ready, 30 planned (no handler), 1
compatibility-only.

| Check | Result |
| --- | --- |
| Crash on a no-argument run | 1 (`dev.agent.pace`, SIGSEGV) |
| Default output not a `zcl.result.v1` envelope | 7 (`ops.debug.explain`, `producer`, `profile`, `rom`; `fleet.objectives`; `fleet.triggers.list`; `dev.train.status`) |
| `--help` refused | 10 (`dev.train.*` 5, `ops.mesh.device.host.*` 4, `ops.mesh.terminal`) |
| Spec not parseable as JSON | 4 (`core.identity.anchor`, `rotate`, `revoke`; `dev.agent.worker`) |
| Spec over the describe budget | 1 (`zcode.endpoint.publish`) |
| Ready leaves named in no test | 217 (99 under `zcode`) |
| Paging that cannot continue | `core.sync.blockers` advertises `next_cursor` but accepts no cursor; `item_limit` alone is refused |

Not reproduced on recheck: six leaves first classified as invalid JSON parse
cleanly with `jq` 1.7, and `ops.debug.dash.kpi` / `milestone` already return
the envelope.

Flag syntax is inconsistent: a leaf that declares a `datadir` input accepts
`--datadir=DIR`; every other leaf refuses it and accepts only the
client-mode form `-datadir=DIR`. A value given as `--flag value` is read as a
positional argument.

## Code

| Measure | Value |
| --- | ---: |
| Files tracked | 10511 |
| C and header lines | 2.98 M (tests 1.06 M) |
| Native command files / lines | 254 / 180917 |
| Shell scripts / of which bash | 499 / 342 |
| Python files | 0 |

Bash scripts concentrate in `tools/dev` (139), `tools/scripts` (135) and
`tools/lint` (40). Two command trees duplicate others:
`fleet.steer.wiki-*` beside `fleet.wiki.*`, and `zcode.network.peers|status`
beside `core.network.peers|status`.

## Documentation

533 Markdown files (5.83 MB) outside vendored code and the commons corpus.
84 have no inbound reference. `docs/work` holds 85 files (1.64 MB) including
16 plan documents besides `FORWARD_PLAN.md`. Eleven groups cover overlapping
topics (fleet 13 files, `docs/agent` 12, `AGENT_*` 7, `ZCODE_*` 5).

## Work started from these results

| Finding | Change |
| --- | --- |
| Crash, paging, unparseable specs | fixes with regression tests |
| Non-envelope output, `--help` refusals | envelope by default, generic help, one table test over the listed leaves |
| Plan sprawl | live items folded into `FORWARD_PLAN.md`, finished plans removed |
| Flag inconsistency | queued after the current CLI change lands |
| Bash scripts, untested leaves | queued as small work cards |
