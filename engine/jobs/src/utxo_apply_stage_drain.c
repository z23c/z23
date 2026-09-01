/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_stage_drain — the outer batched-drain driver for the utxo_apply
 * Job, split out of utxo_apply_stage.c (per docs/FRAMEWORK.md §5's file-size
 * ceiling) alongside its existing dump/observe/lookup/accessors siblings.
 * Owns the one outer BEGIN IMMEDIATE .. COMMIT window a drain call opens
 * around up to max_steps single-height utxo_apply_stage_step_once() calls
 * (see util/stage.h's stage_batch_begin/stage_batch_end contract), plus the
 * H2 batch-commit telemetry (jobs/utxo_apply_batch_commit.h) that turns that
 * COMMIT's wall time into one greppable log line + rolling stats. */

#include "jobs/utxo_apply_batch_commit.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/reducer_commit_invariants.h"
#include "utxo_apply_created_outputs_prune.h"
#include "utxo_apply_stage_internal.h"

#include "core/utiltime.h"
#include "storage/coins_ram.h"
#include "storage/progress_store.h"
#include "util/stage.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>

#define STAGE_NAME "utxo_apply"

int utxo_apply_stage_drain(int max_steps)
{
    if (max_steps <= 0) return 0;
    sqlite3 *batch_db = progress_store_db();
    bool batched = false;
    if (batch_db) {
        progress_store_tx_lock();
        batched = stage_batch_begin(batch_db);
        if (!batched) progress_store_tx_unlock();
    }

    /* Open the batch-commit conservation window (invariants a/b/c). No-op
     * unless a batch is actually open, so the unbatched path stays untouched.
     * Invariant (a) requires the production coins_kv-backed lookup (found ⇔ a
     * deletable coins_kv row); a synthetic test lookup breaks that premise, so
     * disable (a) — (b)/(c) still run — when it is not installed. */
    if (batched) {
        reducer_commit_invariants_batch_begin(batch_db);
        utxo_apply_lookup_batch_begin(batch_db);
        if (!utxo_apply_stage_lookup_is_live())
            reducer_commit_invariants_disable_coins_check();
    }

    /* Read the durable pre-batch cursor directly. The observer atomic is an
     * advance event, so it is intentionally unset after a process restart. */
    int64_t h_before_batch =
        (int64_t)stage_cursor_persisted(batch_db, STAGE_NAME, STAGE_NAME) - 1;

    int advanced = 0;
    for (int i = 0; i < max_steps; i++) {
        job_result_t r = utxo_apply_stage_step_once();
        if (r != JOB_ADVANCED) break;
        advanced++;
    }

    bool committed = false;
    int64_t commit_us = 0;
    if (batched) {
        committed = advanced > 0 || stage_batch_dirty();
        /* Verify the conservation invariants BEFORE the outer COMMIT. A
         * violation REFUSES the commit (force ROLLBACK) after raising the
         * typed blocker naming the height + failed invariant — corruption
         * surfaces here, not at the next hour-long install verify. On the
         * no-commit path, drop the window without checking. */
        if (committed) {
            if (!reducer_commit_invariants_verify(batch_db))
                committed = false;
        } else {
            reducer_commit_invariants_reset();
        }
        /* Wall time of the outer COMMIT/ROLLBACK, including any pre-commit
         * fsync hook — the one IO cliff a batched drain still pays per
         * batch. Recorded below only on the successful-commit path. */
        int64_t commit_t0 = GetTimeMicros();
        if (!stage_batch_end(batch_db, committed)) {
            (void)stage_record_fatal(STAGE_NAME, "batch COMMIT/ROLLBACK failed");
            committed = false;
        }
        commit_us = GetTimeMicros() - commit_t0;
        utxo_apply_lookup_batch_end();
        progress_store_tx_unlock();
    }

    if (committed)
        utxo_apply_batch_commit_record(h_before_batch, advanced, commit_us);

    if (committed && !coins_ram_flush_due())
        (void)stage_record_fatal(STAGE_NAME, "coins_ram deferred flush failed");

    /* Post-commit, own-tx created_outputs prune (lane A1) — only after the
     * kernel batch durably committed at least one advance, and only once the
     * kernel tx lock has been released above (strictly sequential locks). */
    if (committed && advanced > 0)
        utxo_apply_created_outputs_prune_post_commit();

    return advanced;
}
