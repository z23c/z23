/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * tip_finalize batch drain. The generic stage drain opens one transaction for
 * max_steps; collapsing chain[] after every step forces the next step to
 * re-expand up to 8,192 retained ancestors. Keep that
 * cache window wide within the transaction and collapse it once before COMMIT.
 * Durable rows, cursor writes, reorg checks, and per-block validation remain
 * in tip_finalize_stage_step_once(). */

#include "tip_finalize_batch_drain.h"

#include "jobs/tip_finalize_stage.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/stage.h"
#include "validation/main_state.h"

#include <sqlite3.h>

/* Serialized by progress_store_tx_lock, the same lock that owns stage batches. */
static bool g_window_batch_active;
static struct main_state *g_window_batch_ms;
static struct block_index *g_window_batch_tip;

bool tip_finalize_batch_window_move(struct main_state *ms,
                                    struct block_index *tip)
{
    if (!ms || !tip)
        LOG_FAIL("tip_finalize", "batch window move missing state/tip");
    if (!g_window_batch_active)
        return active_chain_move_window_tip(&ms->chain_active, tip);
    g_window_batch_ms = ms;
    g_window_batch_tip = tip;
    return true;
}

static void window_batch_begin(void)
{
    g_window_batch_ms = NULL;
    g_window_batch_tip = NULL;
    g_window_batch_active = true;
}

static bool window_batch_finish(void)
{
    struct main_state *ms = g_window_batch_ms;
    struct block_index *tip = g_window_batch_tip;
    g_window_batch_active = false;
    g_window_batch_ms = NULL;
    g_window_batch_tip = NULL;
    return !tip || (ms && active_chain_move_window_tip(&ms->chain_active, tip));
}

int tip_finalize_stage_drain(int max_steps)
{
    if (max_steps <= 0)
        return 0;
    sqlite3 *db = progress_store_db();
    bool batched = false;
    if (db) {
        progress_store_tx_lock();
        batched = stage_batch_begin(db);
        if (!batched)
            progress_store_tx_unlock();
    }
    if (batched)
        window_batch_begin();

    int advanced = 0;
    for (int i = 0; i < max_steps; i++) {
        if (tip_finalize_stage_step_once() != JOB_ADVANCED)
            break;
        advanced++;
    }

    if (batched) {
        bool window_ok = window_batch_finish();
        bool commit = window_ok && (advanced > 0 || stage_batch_dirty());
        bool end_ok = stage_batch_end(db, commit);
        progress_store_tx_unlock();
        if (!window_ok || !end_ok) {
            LOG_WARN("tip_finalize",
                     "[tip_finalize] batch boundary failed window=%d txn=%d",
                     window_ok ? 1 : 0, end_ok ? 1 : 0);
            return 0;
        }
    }
    return advanced;
}
