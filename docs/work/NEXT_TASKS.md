<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Next tasks for any agent, small model or large

Read this first when told to "work on Z23". The mission is in
[the Ambition section](../THE_Z23_WAY.md#ambition): make Z23 the best
decentralized, open-source software factory for a mixed fleet of agents, one
measured step at a time. The loop is in [THE_Z23_WAY.md](../THE_Z23_WAY.md).
The plan behind tasks 1 to 3 is [LANDING_FLOW_PLAN.md](./LANDING_FLOW_PLAN.md).

## Rules that never change

- Work in your own lane, a separate worktree. One writer per worktree.
- Never touch `core/`, consensus, custody, a datadir or funds. If a task seems
  to need it, stop and write down why.
- Run `build/bin/z23 code guide <paths>` before editing, `make lint-fast` and
  the focused test group before committing (through `devbuild --wait`).
- Commit with a `Co-Authored-By:` line naming your model. Another agent reads
  the diff before it is submitted; do not submit your own work unless told to.
- Report what you measured, with numbers. If a gate fails, say which and why;
  never loosen a check to pass.
- Before you start, read the log for the files you will touch:
- At your first edit, claim the files: `build/bin/z23-dev dev agent claim --story=NAME --files=a,b`. The fleet probe G13 counts claims; no claim means nobody sees the lane. Release when done.
  `git log origin/main --oneline -8 -- <path>`. Other agents write here.

## Tasks, smallest first

1. **`dev lane new` writes a lease and the signing settings.** In
   `tools/command/native_dev_lane.c`: write a lease file in the new lane
   (owner, created, touched, ttl 6 h), set per-worktree `gpg.format=ssh` and
   `user.signingkey` from the repository's existing configuration (never copy a
   key), and report in the reply whether the precheck lint binary is present.
   Test in `tests/harness/src/test_dev_lane.c`. Done when a fresh lane can
   `git commit -S` with no extra steps and the reply names the lease path.
2. **`dev lane gc`.** A new verb that removes a lane whose lease expired and
   that has no queued or in-flight land row; it first saves any commit not on
   main as a git bundle in an archive folder. Dry run by default. Depends on 1.
3. **Name the lint failures.** Read the last 300 rows of the land outcomes
   ledger and the logs they point to; for each failed lint row list the gate
   that failed and whether `make lint-fast` includes it. Output a table and a
   proposal of gates to add to `lint-fast`. Read-only; no edits.
4. **Help text for every public flag.** Compare the parsed flags in
   `engine/composition/src/args.c` with the help text. Ask which are public
   before writing a line; write each help line from the code.
5. **Time a documentation-only land.** From submit to landed, three runs.
   Record the numbers; if the proof runs tests for a change with no code,
   propose how to skip them and show the time saved.
