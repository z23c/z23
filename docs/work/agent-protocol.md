# Agent Protocol — Worker Startup & Completion

**Every worker agent in a worktree MUST follow this protocol exactly.** It
is the contract between the orchestrator and the workers. Deviating breaks
coordination and risks data loss.

**Workflow:** each worker runs in its own worktree on its own branch —
`lane/<slug>` or `wf/<slug>`, named by the assignment doc. Workers never
commit on `main` and never push. The worker self-gates (build + focused
tests + `make lint`) and commits its green work on the lane branch. The
orchestrator (the main checkout) reviews the green branch, merges it into
`main`, and pushes. Every worktree shares the one local object store, so
"hand off to the orchestrator" is a branch name and a head SHA, not a push.
After the merge lands, the worker's worktree is stale and is reclaimed by
`tools/scripts/worktree_gc.sh` (dry-run by default; the owner applies).

---

## Startup ritual (run on EVERY fresh session)

```
1. Identify yourself
   $ pwd                                  # e.g. ~/github/zclassic23-2 or
                                          # .../.claude/worktrees/wf_<slug>
   → worktree ID = the directory name ("wt2", "wf_env-hygiene", ...)
   → if you are in the bare main checkout → you are the orchestrator; review
     in-flight lanes and merge green branches, do NOT take a worker assignment

2. Load the live state (docs, not just code)
   $ cat docs/HANDOFF.md                  # current live facts — read FIRST
   $ cat docs/work/FORWARD_PLAN.md        # THE plan
   $ cat docs/FRAMEWORK.md                # canonical architecture (reference)

3. Load your assignment
   $ ls docs/work/wt<N>-*.md docs/work/wt-*.md   # specific + cross-worker
   $ for f in docs/work/wt<N>-*.md docs/work/wt-*.md; do
       [ -e "$f" ] || continue
       echo "=== $f ==="; grep -A2 '^## Status$' "$f" | head -4
     done
   # Pick the assignment whose Status is **READY** (or IN PROGRESS (wt<N>) resumable).
   # `wt<N>-*.md` are worker-specific. `wt-*.md` are cross-worker — claim by
   # marking IN PROGRESS (wt<N>). First worker to mark wins; second worker
   # skips it and picks the next READY assignment.
   # SKIP any whose Status starts with "✅ DONE" — work is closed.
   # SKIP any whose Status starts with "QUEUED" — gated on prerequisite.
   $ cat docs/work/<chosen-file>           # full spec — branch name, scope, tasks

4. Verify the assignment doc's "Status" section: DONE → report to user;
   BLOCKED/FAILED → re-read, retry or escalate; READY/IN PROGRESS (wt<N>) → proceed.

5. Check out YOUR branch — the assignment's **Branch:** field is authoritative.
   $ git switch -c <lane>/<slug> main     # fresh lane off current main, or
   $ git switch <lane>/<slug>             # resume the existing lane branch
   Never commit on `main` itself. If the worktree is already on the right
   lane branch, stay on it.

6. Mark in-progress
   - Edit the assignment doc's Status section to "IN PROGRESS (wt<N>)"
   - $ git add docs/work/<file>
   - $ git commit -m "wt<N>: mark <slug> in progress"     # on YOUR lane branch
```

Then **execute the assignment's Tasks section in order**.

---

## Ask the checkout, do not grep it

The node binary answers questions about THIS checkout, offline, with no node
running and no datadir. Use it before reaching for `grep`, `find`, or a guess.
A document can drift from the tree; these answers are computed from the tree.

**Native mode needs no running node.** `build/bin/z23-dev <leaf>` runs the
command in-process. (`./build/bin/zclassic23-dev z23 <leaf>` is CLI-CLIENT mode
and requires a live node and an RPC cookie — that failure reads
`CONNECT_REFUSED ... no RPC cookie`, which is not a broken command, it is the
wrong mode. Note also that in that mode flags take a SINGLE dash:
`-datadir=DIR`, not `--datadir=DIR`.)

The four that pay for themselves immediately:

```
build/bin/z23-dev discover help                 # every command root, with risk
                                                # and latency; start here
build/bin/z23-dev code tests --input='{"path":"<file>"}'
                                                # which focused test group a
                                                # change to that file routes to
build/bin/z23-dev code room  --input='{"path":"<file>"}'
                                                # purpose, group, neighbours
build/bin/z23-dev agentmap --input=json         # where code, docs and tests live
build/bin/z23-dev agentimpact <files...>        # changed files -> tests + risk
```

`code tests` answers in ~10 ms. Deriving the same answer by reading a suite log
by hand takes an hour and can be got wrong. Measured today.

Two honest caveats, so nobody reports these as new bugs:

- `code room` currently blows its 250 ms budget badly on a cold index (17.5 s
  measured, and it says so: `"budget_exceeded": true`). It returns the right
  answer; it is not fast yet.
- `discover search` searches the COMMAND REGISTRY, not the source tree. A query
  for a source symbol legitimately returns `count: 0`. Use `code group` /
  `code room` for source.

**Before building anything, ask whether it already exists.** In one session this
repository nearly grew a second doc-path checker, a second task board, and a
second metaverse module — all three already existed. The cost of asking is one
command; the cost of not asking is a duplicate subsystem someone must later
delete.

---

## Per-task discipline

Each Task has a **scope** (exact files) and an **acceptance test** (concrete
check that proves done). For each task:

1. Implement — stay inside the assignment's file scope.
2. Run the acceptance test (`make test_parallel` / focused group, build, lint).
3. **Green:** `git add` the specific files, commit on the lane branch.
4. **Red:** debug; never commit a broken state. Stuck > 30 min → append a
   `BLOCKED` note to the assignment.

One commit per task — no megacommits.

On a long-lived lane, rebase onto `main` (or merge `main` in) between tasks
so the orchestrator's final merge stays small. Resolve conflicts in your
lane, never on `main`.

---

## Commit discipline

- **Subject < 70 chars, imperative:** "add CONDITION macro", not "added".
- **Body** explains the *why*; the *what* is in the diff.
- **No `--no-verify`** (hooks are load-bearing). **No `--amend` once the
  orchestrator has merged** — fix mistakes with a NEW commit.

---

## Integration discipline — branch + merge, not push-to-main

- Workers do **not** push — not `main`, not the lane branch, nothing. All
  worktrees share one local object store, so the orchestrator sees your lane
  branch and its head SHA the moment you commit. The orchestrator is the
  only pusher, and it pushes `main` only.
- Hand off with the exact branch name + head SHA + gate results in your
  completion report. The orchestrator reviews the diff (`git log main..<lane>`
  / `git diff main...<lane>`), merges green lanes into `main`, and pushes.
- If `main` moved while you worked, rebase/merge it into your lane and
  re-run the gates BEFORE reporting done — the orchestrator merges only
  lanes that are green against current `main`.

**Never `git push --force` or `--force-with-lease` to any branch.** Never
rebase another worker's lane.

---

## Completion ritual

When all tasks pass:

1. **Run the full suite once more —
   `tools/scripts/gate-and-report.sh <lintlog> <testlog>`.** This is the owning
   runbook for that script: it runs `make lint` → a full link build (`make
   build-only` does not link) → `make test-parallel`, then keys success on the
   `SUITE VERDICT … groups_ran=N groups_failed=N` line and **rejects a cached
   run**. A bare `grep "ALL TESTS PASSED"` also matches
   `ALL TESTS PASSED (CACHED)`, which can mean zero groups executed.

   **⚠️ A GREEN SUITE IS NOT A HEALTHY NODE (RESILIENCE DOCTRINE #1).** If your
   change touches sync, validation, header/block admit, a cutover, or anything
   on the chain-advance path, live forward progress is a required gate:
   ```bash
   build/bin/z23 agent
   build/bin/z23 dumpstate chain_advance_coordinator
   build/bin/z23 -bench-kill9       # benchmark rows
   ```
   If you can't show the live tip advancing past your change, it is NOT done —
   report it, don't ship it.

2. **Update the assignment doc:** set Status to
   `✅ DONE — ready for merge (branch <lane>, head <sha>)`, and append a
   `## Completion (wt<N>, YYYY-MM-DD)` section covering: summary, which TOP
   10 BENCHMARK (`docs/USER_BENCHMARKS.md`) it moved and by how much (or what it
   unblocks), commits, files added/modified, acceptance verification (incl.
   the live check), and any surprises/follow-ups. Commit that on the lane
   branch.

3. **Report to the user:** completed `<slug>`, lane branch `<lane>` at
   `<sha>`, gates green, ready for orchestrator merge.

4. **The orchestrator merges.** It reviews the lane, merges into `main`,
   pushes, and updates `docs/FRAMEWORK.md` §9 (the open-item debt board) if
   the merge changed the open-item list. A lane is not landed until the
   merge commit is on `main`.

5. **Self-clean after the merge.** Once your branch is merged, your worktree
   is stale: `tools/scripts/worktree_gc.sh` (dry-run) will classify it SAFE
   (merged + clean) and the owner reclaims it with `--apply`. Never delete a
   worktree or branch by hand — `rm -rf` leaves stale git admin state and
   bypasses the GC's protect list.

---

## Delegating to a cheaper worker

A second model (`tools/dev/grok-unit.sh`) can take work off you. Tokens are
not free and the owner has asked that cheaper capacity be used where it
genuinely helps. It does not help everywhere, and the shape of the task is
what decides.

**Delegate when the task is:** one file, one purpose, with an acceptance bar
that can be checked mechanically. Greppable sweeps, a well-specified addition
to an existing script, a rename with a clear rule. Measured 2026-08-29: a
~50-line addition to `tools/ship.sh` cost $0.08 and was kept essentially as
written, including comments it added unprompted.

**Do NOT delegate** work whose acceptance needs judgement. You have to do that
judging yourself either way, and the judging is the expensive half — so you
pay twice and save nothing.

How to write the task file:

- Give the FAILURE that motivated the work, not just the change you want.
- State constraints as prohibitions: what must NOT be weakened, removed, or
  baselined. These are honoured well.
- Include an explicit acceptance list of commands to RUN, and say that output
  must be shown.
- Add "leave it alone and list it as unsure" for anything ambiguous. A wrong
  edit costs far more than a missed one.
- Ask for the closing JSON report **in band**, at the end of the prompt.

### ⛔ Three ways a delegated unit exits 0 having written nothing

All three end with rc=0 and an empty diff, so an exit code proves nothing:

1. `--json-schema` — the schema is satisfied on turn one by a status object,
   which ends the turn. Never pass it.
2. `--permission-mode acceptEdits` — it plans, narrates, and exits without
   editing. `--always-approve` is the mode that acts.
3. A timeout mid-thought. Budget hours, not minutes, and say `timeout` returned
   124 out loud rather than reporting a partial file set as a result.

**Always check the diff yourself: `git -C <worktree> status --porcelain`.**

### ⛔ It cannot judge whether its own test is a test

This is the limit that matters. A delegated unit will write assertions that
look right, pass, and cannot fail — it inherits whatever idiom the file
already uses and has no way to notice the idiom is broken. Measured
2026-08-29: assertions written as `! check ...` are exempt from `set -e` AND
from the `ERR` trap, so ten of them in one file could never fail, under a
comment claiming they were assertions under `set -e`.

**Never accept a delegated assertion without mutating the code it guards and
watching it fail.** "The selftest passed" can be true and worthless — break the
thing the assertion protects, watch the check go red, then put it back. A test
file that exists is not coverage, and an assertion that cannot fail is not an
assertion.

---

## Memory discipline

**Your local memory does not reach the other agents.** It lives on one
machine, in one agent's state directory. Several agents work this repository
from different machines, so a lesson saved only to local memory is a lesson
the others will each rediscover the expensive way.

So decide by AUDIENCE, not by importance:

- **Anything another agent needs → the REPO.** A doctrine or a trap belongs in
  this file or the relevant `docs/`; a fact about the code belongs in a comment
  next to the code, where it cannot drift out of sight.
- **Local memory is for what is true of THIS machine and THIS operator** —
  host paths, which box is slow, what the owner said they wanted.

When in doubt, write it in the repo. A duplicated note costs nothing; a lesson
four agents each relearn costs four times.

After completing the assignment:

- **Save a project memory** if the work shipped a non-obvious primitive or surprising finding. Use `feedback_*` for guidance, `project_*` for things that shipped.
- **Do NOT save memory for routine completions** — the assignment doc + git log are the record.

---

## What to do if you're confused

In this priority order:

1. Re-read `docs/FRAMEWORK.md` for the architectural shape.
2. Re-read your assignment doc — it has a Tasks section in order.
3. Re-read `docs/HANDOFF.md` and `docs/FRAMEWORK.md` §9 (the open-item debt board) to see where you fit in the bigger picture.
4. Check the existing codebase for examples (e.g., for Job shape, look at `app/jobs/src/header_admit_stage.c` — the canonical stage adopter).
5. If still stuck > 30 min: append `BLOCKED: <reason>` to your assignment, commit it on your lane branch, report to user. Do NOT guess and ship questionable code.

---

## Forbidden moves

- ❌ Committing directly on `main` in a worker worktree — `main` is the orchestrator's.
- ❌ Committing on a non-`main` branch in the MAIN checkout — the symmetric trap: the main checkout stays on `main`, so the orchestrator's merges never surf onto lane refs. Lane work goes in a worktree: `git worktree add .claude/worktrees/wf_<name> -b lane/<name> main`. The tracked pre-commit hook refuses this; a truly deliberate main-checkout lane commit overrides once with `ZCL_LANE_COMMIT_OK=1`.
- ❌ **Pushing ANY branch to `origin`** — workers never push; the orchestrator pushes `main` only. **NEVER `git push --all` or `git push --mirror`** — those push every local branch (hundreds of stale lanes live locally).
- ❌ Merging your own lane into `main` — the orchestrator reviews and merges.
- ❌ Editing `docs/FRAMEWORK.md` §9 (the open-item debt board) directly (orchestrator only — exception: workers may update the mega-module roster when they DELETE a module).
- ❌ Touching files outside your assignment's scope.
- ❌ `git push --force` / `--force-with-lease` to ANY branch.
- ❌ Deleting another worker's commits via rebase-and-overwrite.
- ❌ `--no-verify`, `--amend` after the orchestrator's merge, skipping tests "just this once".
- ❌ Editing CLAUDE.md without orchestrator sign-off (it's auto-loaded into every session).
- ❌ Writing code that doesn't match one of the 8 framework shapes.
- ❌ Removing worktrees or branches by hand (`rm -rf`, `git branch -D`) — that is `tools/scripts/worktree_gc.sh`'s job, under its protect list, with the owner applying.

---

## End-of-session

Whether you finished or not:

1. `git status` — verify clean, or commit the known WIP on your lane branch
   (the shared object store is the backup; no push needed or wanted).
2. Update assignment Status: `✅ DONE — ready for merge (branch <lane>, head
   <sha>)` if finished, else `IN PROGRESS (wt<N>) — paused at task <X>`.
3. Report briefly to user: lane branch, head SHA, gate state.
