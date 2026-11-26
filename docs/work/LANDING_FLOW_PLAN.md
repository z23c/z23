<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Landing flow: more code landed at lower cost

Goal ([Ambition](../THE_Z23_WAY.md#ambition)): every agent lands small, correct
changes with no cleanup work and as few retries as possible. Facts below were
measured on r1 on 2026-11-26 unless a line says "to measure".

## What the numbers say

- Last 300 land outcomes: 261 landed (87%). The 39 that did not: lint 15,
  test 11, proof producer mismatch 4, bundle 3, rebase conflict 2, worktree 1,
  push 1, empty change set 1, cancelled 1. Each failure costs one proof (about
  8 minutes) plus a resubmit.
- Lint and test failures are 26 of the 39. The lane runs `lint-fast`; the land
  proof runs the full set. Whatever the full set catches that `lint-fast`
  misses is the avoidable retry. To measure: which gates failed in those 15,
  and whether any fast subset would have caught them.
- Scratch under the Z23 development-scratch folder on r1: about 307 GB in 2381
  entries. Daily and host cleanup timers exist, yet it grows, because lanes are
  created by hand with no owner or expiry on record.
- Today an active lane's git metadata was removed while in use. Recovering took
  seven calls: a new worktree, signing settings (the first submit failed
  `TIP_UNSIGNED`), the precheck lint binary, and a resubmit.
- A failed land showed a passing selftest line as its detail (fixed in this
  change: the gate's own verdict now follows an uppercase SELFTEST PASS).

## The idea: a lane is a sandbox that cleans itself

One rule for every agent: work only inside your lane. Nothing outside it needs
cleaning, so cleanup costs the agent zero tokens.

1. **One root, one lease.** Every lane is a folder under one lanes root holding
   its worktree, test scratch, logs and temporary files. A small lease file
   records owner, created, last touched and a time to live (6 hours default).
2. **Created complete.** `dev lane new` (already creates the worktree and clones
   the proof's vendored files) also writes the lease, copies the signing
   settings per worktree from the repository's existing configuration (never a
   key), and builds or links the precheck lint binary. A new lane can submit on
   its first call.
3. **Touched for free.** `dev land submit` and `dev land status` with a
   `--worktree` refresh the lease. An active lane never expires.
4. **Collected by one timer.** The existing cleanup timer runs `dev lane gc`:
   a lane whose lease expired and that has no queued or in-flight land row is
   removed. If it holds commits not on main, they are first saved as a git
   bundle in an archive kept 30 days, so no work is lost and no agent has to
   decide.
5. **Never deletes a live lane.** A lane with a held lock, a queued or
   in-flight row, or a fresh lease is skipped, and the skip is logged.

Why not stricter rules for agents: rules cost tokens every session and fail
when an agent runs out of context. A lease costs nothing to follow.

## Order of work, smallest first

1. Lease file and signing settings in `dev lane new`; lease touch in land
   submit and status. Number to beat: recovery from "no lane" in 1 call, not 7.
2. `dev lane gc` with the archive step. Number to beat: scratch under 100 GB
   and zero live lanes removed over a week.
3. Measure the 15 lint failures and move the gates that catch them into
   `lint-fast`. Number to beat: lint failures under 2% of lands.
4. Measure a documentation-only land from submit to landed. If the full test
   proof runs for a change that touches no code, narrow it and record the time.
5. Report the same 300-row table weekly so the fleet sees the trend.
