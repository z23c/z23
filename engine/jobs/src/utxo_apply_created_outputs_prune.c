/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Lane A1 — created_outputs retention prune, decoupled from the utxo_apply
 * kernel co-commit tx. See utxo_apply_created_outputs_prune.h.
 *
 * The prune is a retention sweep with NO consensus value: created_outputs is
 * the forward-creation index body_persist builds for the replayable window
 * above the durable coin frontier (a resolver warm cache, not kernel state).
 * Lifting it out of the kernel co-commit BATCH (a separate post-commit tx on the
 * same kernel store) relaxes the atomicity coupling. A crash between the kernel
 * COMMIT and this prune leaves extra
 * created_outputs rows below the retention floor — harmless: the bounded
 * resolver height-ignores them and the next advancing drain re-prunes. */

#include "utxo_apply_created_outputs_prune.h"

#include "jobs/created_outputs_index.h"
#include "jobs/stage_helpers.h"          /* stage_cursor_persisted */
#include "jobs/utxo_apply_stage.h"       /* public test accessors declared here */
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "validation/main_constants.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>

#define STAGE_NAME "utxo_apply"

/* Keep a large margin over the IBD reorg allowance plus the block-download
 * lookahead, then prune a bounded number of old heights per drain. */
#define CREATED_OUTPUTS_PRUNE_RETAIN_BLOCKS \
    (MAX_IBD_REORG_LENGTH + BLOCK_DOWNLOAD_WINDOW + 1024)
#define CREATED_OUTPUTS_PRUNE_MAX_HEIGHTS_PER_STEP 32

/* Test observability: how many post-commit prune tx committed, and the
 * retention floor of the most recent one. */
static _Atomic uint64_t g_ua_post_prune_runs = 0;
static _Atomic int64_t  g_ua_post_prune_last_floor = -1;
/* -1 => use the compile-time retention window. A test lowers this so the prune
 * fires over a short synthetic chain (the production window is thousands deep). */
static _Atomic int      g_ua_created_outputs_retain_for_test = -1;

void utxo_apply_post_prune_stats(uint64_t *runs, int64_t *last_floor)
{
    if (runs) *runs = atomic_load(&g_ua_post_prune_runs);
    if (last_floor) *last_floor = atomic_load(&g_ua_post_prune_last_floor);
}

void utxo_apply_created_outputs_retain_set_for_test(int retain_blocks)
{
    atomic_store(&g_ua_created_outputs_retain_for_test, retain_blocks);
}

static int utxo_apply_created_outputs_retain(void)
{
    int t = atomic_load(&g_ua_created_outputs_retain_for_test);
    return t >= 0 ? t : CREATED_OUTPUTS_PRUNE_RETAIN_BLOCKS;
}

/* The prune is a retention sweep with NO consensus value, decoupled from the
 * kernel CO-COMMIT tx (a separate post-commit BEGIN IMMEDIATE). After the A3
 * flip created_outputs and stage_cursor both live in consensus.db (the kernel
 * store), so the prune runs on the kernel handle (progress_store) — the caller
 * has ALREADY released the kernel progress lock, so re-acquiring it here for a
 * bounded post-commit DELETE cannot stall an in-flight fold. The cursor it
 * snapshots for the floor is read inside this tx (a read, never a stage_cursor
 * write — the reducer stays the cursor's single writer). */
void utxo_apply_created_outputs_prune_post_commit(void)
{
    sqlite3 *db = progress_store_db();
    if (!db)
        return;
    progress_store_tx_lock();
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN(STAGE_NAME,
                 "[utxo_apply] created_outputs prune BEGIN failed: %s",
                 err ? err : "(no message)");
        if (err) sqlite3_free(err);
        progress_store_tx_unlock();
        return;
    }
    /* Snapshot the committed cursor INSIDE the tx for a consistent floor. */
    uint64_t cursor = stage_cursor_persisted(db, STAGE_NAME, STAGE_NAME);
    int retain = utxo_apply_created_outputs_retain();
    if (cursor <= (uint64_t)retain) {
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
        progress_store_tx_unlock();
        return;
    }
    int prune_floor = (int)cursor - retain;
    int pruned_rows = 0;
    bool ok = created_outputs_index_prune_below_limited(
        db, prune_floor, CREATED_OUTPUTS_PRUNE_MAX_HEIGHTS_PER_STEP,
        &pruned_rows);
    if (ok && sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK) {
        atomic_fetch_add(&g_ua_post_prune_runs, 1);
        atomic_store(&g_ua_post_prune_last_floor, (int64_t)prune_floor);
    } else {
        if (err) {
            LOG_WARN(STAGE_NAME,
                     "[utxo_apply] created_outputs prune COMMIT failed "
                     "floor=%d: %s", prune_floor, err);
            sqlite3_free(err);
        } else if (!ok) {
            LOG_WARN(STAGE_NAME,
                     "[utxo_apply] created_outputs prune failed floor=%d "
                     "retain=%d max_heights=%d", prune_floor, retain,
                     CREATED_OUTPUTS_PRUNE_MAX_HEIGHTS_PER_STEP);
        }
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    }
    progress_store_tx_unlock();
}
