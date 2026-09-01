# engine/jobs/

**Shape:** Job — idempotent, cursor-stamped reducer stage.

Each source file in `src/` owns one bounded stepper or one narrow helper for
the staged reducer pipeline:

```
header_admit -> validate_headers -> body_fetch -> body_persist
             -> script_validate -> proof_validate -> utxo_apply -> tip_finalize
```

Jobs return `job_result_t` from `engine/jobs/include/jobs/job.h`:
`JOB_ADVANCED`, `JOB_BLOCKED`, `JOB_IDLE`, or `JOB_FATAL`. The generic stage
runner in `platform/modules/util/include/util/stage.h` handles cursor/replay mechanics; job files own the
stage-specific work and must advance a durable cursor or name a typed blocker.

Do not add macro-only job scaffold. If a helper is shared by stages, keep it
purpose-named (`stage_helpers.c`, `utxo_apply_delta.c`) and out of the hot path
unless it removes real duplicated stage mechanics.

See [`docs/FRAMEWORK.md`](../../docs/FRAMEWORK.md) for the contract and its
§9 debt board for active cleanup work.
