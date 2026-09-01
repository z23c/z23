/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * script_validate_stage_drain — the bounded drain entry point, split out of
 * script_validate_stage.c (file-size ceiling). It is hand-written rather than
 * STAGE_DRAIN_IMPL so the per-batch prepared-statement caches the stage's read/
 * write hot path builds (created_outputs bounded read, coins_kv prevout
 * fallback, the script_validate_log upsert + source-epoch blob) are finalized
 * once the outer batch closes — the same rule body_persist follows for
 * created_outputs_index. A prepared statement belongs to exactly one completed
 * outer batch, so no db/reorg generation inherits statement state from its
 * predecessor. */

#include "jobs/script_validate_stage.h"
#include "script_validate_stage_internal.h"
#include "script_validate_log_store.h"

#include "jobs/created_outputs_index.h"
#include "storage/progress_store.h"
#include "util/stage.h"

#include <sqlite3.h>

int script_validate_stage_drain(int max_steps)
{
    if (max_steps <= 0)
        return 0;
    sqlite3 *batch_db = progress_store_db();
    bool batched = false;
    if (batch_db) {
        progress_store_tx_lock();
        batched = stage_batch_begin(batch_db);
        if (!batched)
            progress_store_tx_unlock();
    }
    int advanced = 0;
    for (int i = 0; i < max_steps; i++) {
        job_result_t r = script_validate_stage_step_once();
        if (r != JOB_ADVANCED)
            break;
        advanced++;
    }
    if (batched) {
        stage_batch_end(batch_db, advanced > 0 || stage_batch_dirty());
        created_outputs_index_batch_reset();
        script_validate_prevout_batch_reset();
        script_validate_log_store_batch_reset();
        progress_store_tx_unlock();
    }
    return advanced;
}
