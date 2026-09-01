/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* sync_controller: shared helpers + job-status book-keeping.
 *
 * The sync controller is split along functional boundaries:
 *
 *   sync_controller.c           — this file: init, job status,
 *                                 turbo-mode helpers, sync_run_write,
 *                                 atomic progress globals.
 *   sync_controller_blocks.c    — connect_block / disconnect_block.
 *   sync_controller_writers.c   — wallet_tx, mempool add/remove,
 *                                 sapling note/spend, peer, tip.
 *   sync_controller_catchup.c   — sapling_tree_rebuild, catchup,
 *                                 catchup/import job machinery,
 *                                 wallet-key copy, mempool save/load.
 *   sync_controller_import.c    — parallel LevelDB → SQLite UTXO import.
 *
 * Cross-file glue lives in sync_controller_internal.h. */

#include "platform/time_compat.h"
#include "controllers/sync_controller.h"
#include "sync_controller_internal.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "models/database.h"
#include "primitives/transaction.h"

#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "util/log_macros.h"

extern volatile sig_atomic_t g_shutdown_requested;

_Atomic bool g_sapling_rescan_active = false;
_Atomic bool g_sapling_tree_rebuilding = false;
_Atomic bool g_catchup_active = false;
_Atomic int g_catchup_height = -1;
_Atomic int g_catchup_target_height = -1;
_Atomic int64_t g_catchup_started_at = 0;
_Atomic int64_t g_catchup_last_progress_at = 0;
_Atomic bool g_import_active = false;
_Atomic int g_import_rows_written = 0;
_Atomic int64_t g_import_started_at = 0;
_Atomic int64_t g_import_last_progress_at = 0;

int64_t sync_job_now(void)
{
    return (int64_t)platform_time_wall_time_t();
}

void sync_job_catchup_begin(int start_height, int target_height)
{
    int64_t now = sync_job_now();

    atomic_store(&g_catchup_active, true);
    atomic_store(&g_catchup_height, start_height > 0 ? start_height - 1 : -1);
    atomic_store(&g_catchup_target_height, target_height);
    atomic_store(&g_catchup_started_at, now);
    atomic_store(&g_catchup_last_progress_at, now);
}

void sync_job_catchup_progress(int height)
{
    atomic_store(&g_catchup_height, height);
    atomic_store(&g_catchup_last_progress_at, sync_job_now());
}

void sync_job_catchup_finish(void)
{
    atomic_store(&g_catchup_active, false);
    atomic_store(&g_catchup_last_progress_at, sync_job_now());
}

void sync_job_import_begin(void)
{
    int64_t now = sync_job_now();

    atomic_store(&g_import_active, true);
    atomic_store(&g_import_rows_written, 0);
    atomic_store(&g_import_started_at, now);
    atomic_store(&g_import_last_progress_at, now);
}

void sync_job_import_progress(int total_rows)
{
    atomic_store(&g_import_rows_written, total_rows);
    atomic_store(&g_import_last_progress_at, sync_job_now());
}

void sync_job_import_finish(int total_rows)
{
    atomic_store(&g_import_rows_written, total_rows);
    atomic_store(&g_import_active, false);
    atomic_store(&g_import_last_progress_at, sync_job_now());
}

struct db_service *sync_db_service_for(struct node_db *ndb)
{
    struct db_service *dbsvc = app_runtime_db_service();

    if (!ndb)
        LOG_NULL("sync", "sync_db_service_for: node_db is NULL");
    /* Boot fixtures and deliberately unregistered runtimes use the direct
     * node_db fallback in every caller below. An absent service is therefore
     * a normal adapter choice, not an error worth flooding node.log with. */
    if (!dbsvc)
        return NULL;
    return db_service_node_db(dbsvc) == ndb ? dbsvc : NULL;
}

bool sync_db_enter_turbo_mode(struct node_db *ndb)
{
    struct db_service *dbsvc = sync_db_service_for(ndb);

    if (dbsvc)
        return db_service_ibd_turbo_mode(dbsvc);
    return node_db_ibd_turbo_mode(ndb);
}

bool sync_db_restore_normal_mode(struct node_db *ndb)
{
    struct db_service *dbsvc = sync_db_service_for(ndb);

    if (dbsvc)
        return db_service_normal_mode(dbsvc);
    return node_db_normal_mode(ndb);
}

bool sync_db_turbo_scope_begin(struct sync_db_turbo_scope *scope,
                               struct node_db *ndb,
                               bool enabled)
{
    if (!scope)
        LOG_FAIL("sync", "turbo scope is NULL");

    scope->ndb = (enabled ? ndb : NULL);
    scope->entered = false;
    if (!enabled)
        return true;

    if (!sync_db_enter_turbo_mode(ndb))
        LOG_FAIL("sync", "failed to enter turbo mode on ndb");

    scope->entered = true;
    return true;
}

bool sync_db_turbo_scope_end(struct sync_db_turbo_scope *scope)
{
    if (!scope || !scope->entered || !scope->ndb)
        return true;

    if (!sync_db_restore_normal_mode(scope->ndb))
        LOG_FAIL("sync", "failed to restore normal mode on ndb");

    scope->entered = false;
    scope->ndb = NULL;
    return true;
}

bool sync_run_write(struct node_db *ndb,
                    db_service_write_fn fn,
                    void *ctx)
{
    struct db_service *dbsvc = sync_db_service_for(ndb);

    if (!ndb || !fn)
        LOG_FAIL("sync", "sync_run_write: ndb=%p fn is NULL=%d", (void *)ndb, fn == NULL);
    if (dbsvc)
        return db_service_run_write(dbsvc, fn, ctx);
    return fn(ndb, ctx);
}

bool node_db_sync_wallet_tx_checked(struct node_db *ndb,
                                    const struct transaction *tx,
                                    const struct wallet *w,
                                    int block_height,
                                    bool *is_ours_out,
                                    bool *success_out)
{
    struct wallet_tx_sync_ctx ctx = {
        .tx = tx,
        .wallet = w,
        .block_height = block_height,
        .is_ours = false,
        .ok = false,
    };

    if (!ndb || !ndb->open || !tx || !w)
        LOG_FAIL("sync", "wallet_tx_checked: invalid args (ndb=%p, tx=%p, w=%p)",
                 (void *)ndb, (void *)tx, (void *)w);

    bool ok = sync_run_write(ndb, node_db_sync_wallet_tx_write, &ctx) && ctx.ok;
    if (is_ours_out)
        *is_ours_out = ctx.is_ours;
    if (success_out)
        *success_out = ok;
    return ok;
}

bool node_db_sync_init(struct node_db *ndb, const char *datadir)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/node.db", datadir);
    if (!node_db_open(ndb, path)) {
        LOG_FAIL("sync", "node_db_sync: failed to open %s", path);
    }
    printf("SQLite database opened: %s (schema v%d)\n",
           path, node_db_schema_version(ndb));
    return true;
}

bool node_db_sync_open_private_db_like(const struct node_db *src,
                                       struct node_db *out)
{
    const char *path;

    if (!src || !out || !src->open || !src->db)
        LOG_FAIL("sync", "open_private_db_like: invalid args (src=%p, out=%p)",
                 (void *)src, (void *)out);

    path = sqlite3_db_filename(src->db, "main");
    if (!path || !path[0] || strcmp(path, ":memory:") == 0)
        LOG_FAIL("sync", "open_private_db_like: no valid filename (path=%s)",
                 path ? path : "NULL");

    memset(out, 0, sizeof(*out));
    return node_db_open(out, path);
}

void node_db_sync_get_job_status(struct node_db_sync_job_status *out)
{
    struct node_db_sync_job_status empty = {0};

    if (!out)
        return;
    *out = empty;
    out->catchup_active = atomic_load(&g_catchup_active);
    out->catchup_height = atomic_load(&g_catchup_height);
    out->catchup_target_height = atomic_load(&g_catchup_target_height);
    out->catchup_started_at = atomic_load(&g_catchup_started_at);
    out->catchup_last_progress_at = atomic_load(&g_catchup_last_progress_at);
    out->import_active = atomic_load(&g_import_active);
    out->import_rows_written = atomic_load(&g_import_rows_written);
    out->import_started_at = atomic_load(&g_import_started_at);
    out->import_last_progress_at = atomic_load(&g_import_last_progress_at);
}
