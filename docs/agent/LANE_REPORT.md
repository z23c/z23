<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Parallel worker report

Return these facts in the final message; do not create a second tracked status
ledger.

1. **User outcome:** what behavior or reliability changed.
2. **Identity:** absolute worktree path, baseline commit, head commit, and
   whether a signature is present. Record verified signer identity only when
   local trust policy actually verifies it; signature presence alone is not
   trusted authorship.
3. **Owned diff:** each changed or deleted path and why it belongs to the
   assignment.
4. **Evidence:** command, literal verdict, executed/reused/failed/skipped
   counts, and receipt path or root when one exists. State `not run` rather
   than paraphrasing an absent verdict.
5. **Unfinished or out-of-scope work:** exact blocker and affected paths.
6. **Contract corrections:** any instruction that contradicted current code
   and the evidence used instead.
7. **Handoff:** `head <sha>, base <sha>, acceptance <green|red|partial>, ready
   for review | needs <condition>`.

A branch name, worktree path, successful process exit, or `ALL TESTS PASSED
(CACHED)` line is not proof of the source, action, or publication outcome.
