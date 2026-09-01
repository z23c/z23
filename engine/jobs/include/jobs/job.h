/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * job — the uniform Job contract (the fourth of the eight shapes).
 *
 * Why this exists
 * ----------------
 * A Job is a cursor-stamped reducer stage: it consumes the next durable
 * unit, commits its output and the new cursor in one transaction, and
 * returns exactly one of four results. This is the single shape every
 * engine/jobs/src reducer (the eight stages) conforms to.
 *
 * The Job result owns the reducer outcome vocabulary. Its enumerator
 * integer values intentionally match the kernel-local `stage_result_t`
 * values consumed by the generic stage runner:
 *
 *   STAGE_ADVANCED (0) -> JOB_ADVANCED
 *   STAGE_BLOCKED  (1) -> JOB_BLOCKED
 *   STAGE_IDLE     (2) -> JOB_IDLE
 *   STAGE_ERROR    (3) -> JOB_FATAL
 *
 * The generic stage runner (`platform/modules/util/stage.h`) consumes this type, so
 * the Job contract is the one source of truth for "what a step returns."
 *
 * Why the type lives in app/jobs and not platform/modules/util
 * ------------------------------------------------
 * The shape is an application concept (one of the eight). The kernel
 * stage runner is the mechanical executor; it depends on the contract,
 * not the other way round. Every build target that pulls the stage
 * runner already has `-Iengine/jobs/include` on its include path. */

#ifndef ZCL_JOB_H
#define ZCL_JOB_H

typedef enum {
    JOB_ADVANCED = 0, /* cursor moved; output committed */
    JOB_BLOCKED  = 1, /* typed blocker preventing progress; cursor unchanged */
    JOB_IDLE     = 2, /* no work available right now; cursor unchanged */
    JOB_FATAL    = 3, /* unexpected failure; cursor unchanged */
} job_result_t;

/* Define a stage's bounded drain entry point. Every stage's drain is the
 * same loop: step up to `max_steps` times, stopping at the first
 * non-JOB_ADVANCED result, returning the count of advances. This macro
 * defines `<prefix>_stage_drain(int)` calling `<prefix>_stage_step_once()`.
 * The prototype still lives in each stage header; only the .c body becomes
 * this invocation.
 *
 * One COMMIT per drain, not per block: the loop runs inside a single batch
 * transaction (stage_batch_begin/end) held under progress_store_tx_lock, so
 * up to `max_steps` advancing blocks flush together. Each step still wraps
 * its own work in a SAVEPOINT inside that batch (stage_run_once), so the
 * per-block co-commit invariant (coin write + stage cursor + *_log row in
 * one atomic unit) is unchanged — only the fsync cadence drops from once
 * per block to once per batch. If the batch fails to open, fall back to the
 * unbatched per-block path so a stage never silently stops advancing. */
#define STAGE_DRAIN_IMPL(prefix)                                  \
    int prefix##_stage_drain(int max_steps) {                     \
        if (max_steps <= 0) return 0;                             \
        sqlite3 *batch_db = progress_store_db();                  \
        bool batched = false;                                     \
        if (batch_db) {                                           \
            progress_store_tx_lock();                             \
            batched = stage_batch_begin(batch_db);                \
            if (!batched) progress_store_tx_unlock();             \
        }                                                         \
        int advanced = 0;                                         \
        for (int i = 0; i < max_steps; i++) {                     \
            job_result_t r = prefix##_stage_step_once();          \
            if (r != JOB_ADVANCED) break;                         \
            advanced++;                                           \
        }                                                         \
        if (batched) {                                            \
            /* COMMIT on forward advance OR durable non-advancing  \
             * work (a reorg unwind); else the unwind is rolled    \
             * back and the drain oscillates. */                   \
            stage_batch_end(batch_db,                             \
                            advanced > 0 || stage_batch_dirty());  \
            progress_store_tx_unlock();                           \
        }                                                         \
        return advanced;                                         \
    }

#endif /* ZCL_JOB_H */
