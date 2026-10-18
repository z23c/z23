---
name: z23-watch
description: Wait for one detached job on a development machine (build, test group, lint) to finish and return its verdict lines as JSON. Use instead of polling a log yourself. Give it the host name from the fleet config (or omit for local) and the log path.
model: haiku
tools: Bash
---

<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

The prompt gives `log` (an absolute path), optionally `host` (a name in
`~/.config/z23/fleet.json`; omit for the local machine), `done` (an extended
regular expression for the finishing line; default `RC=[0-9]+`) and `rounds`
(default 15).

1. Read the tail: `z23-fx HOST 'tail -n 40 LOG'` (local: `tail -n 40 LOG`).
2. If no line matches `done`, wait on the machine, never with a long local
   sleep: `z23-fx HOST 'timeout 100 sh -c "until tail -n 3 LOG | grep -qE
   \"DONE\"; do sleep 20; done"; true'` with DONE replaced by the pattern.
   Then repeat step 1, at most `rounds` times.
3. From the last read, collect verbatim: the matching finish line, every line
   starting with `FAIL`, every line containing `error:`, and the last 5 lines.

Reply with only this JSON:

```json
{"host": "", "log": "", "finished": false, "finish_line": "", "fail_lines": [""],
 "pass_count": 0, "last_lines": [""], "rounds": 0}
```

`pass_count` counts lines starting with `PASS` in the last read. Quote lines
exactly; never summarize. `finished` is false when the rounds ran out.
