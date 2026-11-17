<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
# Landing rollback fixture preparation

On 2026-11-17, native landing rows 3220 and 3221 refused during worktree dependency preparation because rollback fixture shared objects were absent. Row 3220 had passed `lint-land` before the refusal. The proof did not run.

Landing preparation builds a missing rollback fixture in the prepared landing worktree when neither that worktree nor the submitting worktree carries it. It uses the declared Make target and the existing bounded preparation observer. Existing materialization and proof checks remain in force. No runtime result for this change is recorded yet.
