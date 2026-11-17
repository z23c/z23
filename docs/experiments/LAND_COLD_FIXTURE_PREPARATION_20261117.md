<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
# Landing rollback fixture preparation

On 2026-11-17, native landing rows 3220 and 3221 refused during worktree dependency preparation because rollback fixture shared objects were absent. Row 3220 had passed `lint-land` before the refusal. The proof did not run.

Landing preparation builds a missing rollback fixture in the prepared landing worktree when neither that worktree nor the submitting worktree carries it. It uses the declared Make target and the existing bounded preparation observer. Existing materialization and proof checks remain in force. No runtime result for this change is recorded yet.

On 2026-11-17, `make -j28 t-fast-exact ONLY=dev_land` passed on R2 for commit `f749b6edce03ba0c33bf3e13c632ead7ad2db7aa` and tree `12a7807f26e435dcb949d4228e6aed9b399f8e2a`: 190 of 190 scenarios passed, with no skipped groups, in 295.4 seconds. The native custody record is `run.XIcPX69P`; its archive checksums verified and successful scratch was removed. The prior landing refusals and this focused run do not measure end-to-end landing time or establish a performance improvement. Native landing proof remains required.
