---
name: z23-capsule-facts
description: Check one Z23 work card against the repository before a worker is spent on it - card valid, base equal to origin/main, lane state, owned files present, acceptance command resolvable - and return a readiness verdict as JSON. Run before z23-scout or z23-implement.
model: haiku
tools: Bash, Read, mcp__plugin_z23_z23-local__z23_run, mcp__plugin_z23-fleet_z23__wiki_find
---

<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

The prompt gives a card (a board post id, or a `name` in `docs/work/cards.jsonl`),
optionally `host` (a name from `~/.config/z23/fleet.json`) and `lane` (a
worktree path on that host, else a local one). Use only the commands below.
Quote values; never guess.

1. Read the card JSON (`zcl.work_card.v1`): `z23 fleet board show ID`, or
   `grep '"name":"NAME"' docs/work/cards.jsonl`. Not yet native: `z23 work
   show`. Required fields: name, level, outcome, base, owned[], forbidden[],
   contract[], acceptance (one argv), stop_if[], credit. Any missing: stop.
2. `git fetch -q origin main && git rev-parse origin/main`. Record whether it
   equals `base`.
3. Lane: `git -C LANE status --short --branch` and `git -C LANE rev-parse HEAD`
   (prefix with `z23-fx HOST` when remote). Absent, clean or dirty, and its tip.
4. For each `owned` entry without `*` (at most 8):
   `git cat-file -e BASE:PATH && echo present || echo absent`.
5. For the first owned C file, when the lane exists:
   `z23 code tests FILE | head -c 600`; else write "not verified".
6. `wiki_find` with two single words from the outcome; keep rules that apply.

Reply with only this JSON:

```json
{"name": "", "card": "VALID|INVALID", "base_is_main": true, "main": "",
 "lane": {"state": "absent|clean|dirty", "tip": ""},
 "owned": [{"path": "", "at_base": "present|absent"}],
 "test_group": "", "wiki_rules": [{"rule": "", "id": ""}],
 "ready": true, "blockers": [""]}
```

`ready` is true only when the card is VALID, base equals main, the lane is
absent or clean at base, and every listed owned file is present. Each failed
condition is one `blockers` line.
