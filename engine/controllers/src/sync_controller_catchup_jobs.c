/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sync_controller — catchup / import job lifecycle.
 *
 * Thin pthread job wrappers around the two long bulk operations: the
 * block-index catchup loop and the snapshot UTXO import. Each job exposes
 * init / start / join / is_started plus its thread entry point. The core
 * catchup algorithm is node_db_sync_catchup in sync_controller_catchup.c;
 * the job structs and public prototypes are declared in
 * controllers/sync_controller.h. */

#include "platform/time_compat.h"
#include "controllers/sync_controller.h"
#include "sync_controller_internal.h"
#include "config/runtime.h"
#include "chain/chain.h"
#include "wallet/wallet.h"
#include "storage/coins_db.h"
#include "validation/chainstate.h"
#include "util/thread_registry.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct catchup_args {
    struct node_db *ndb;
    const struct active_chain *chain;
    struct wallet *w;
    const char *datadir;
};

struct catchup_lane_ctx {
    const struct active_chain *chain;
    struct wallet *w;
    const char *datadir;
    int result;
};

#ifdef ZCL_TESTING
static _Atomic int g_catchup_test_lane_calls = 0;
static _Atomic int g_catchup_test_worker_lane_calls = 0;

void node_db_sync_catchup_test_reset_lane_stats(void)
{
    atomic_store(&g_catchup_test_lane_calls, 0);
    atomic_store(&g_catchup_test_worker_lane_calls, 0);
}

int node_db_sync_catchup_test_lane_calls(void)
{
    return atomic_load(&g_catchup_test_lane_calls);
}

int node_db_sync_catchup_test_worker_lane_calls(void)
{
    return atomic_load(&g_catchup_test_worker_lane_calls);
}
#endif

/* sync_wallet_inmemory removed: it passed height=0 for all wallet
 * transactions, causing INSERT OR REPLACE to overwrite correct heights
 * and clear spent_txid on already-spent UTXOs. The catchup block scan
 * already processes wallet transactions with correct heights. */

static struct db_service *catchup_job_db_service_for(struct node_db *ndb)
{
    struct db_service *dbsvc = app_runtime_db_service();

    if (!ndb || !ndb->open || !dbsvc || !db_service_is_started(dbsvc))
        return NULL;
    return db_service_node_db(dbsvc) == ndb ? dbsvc : NULL;
}

static bool node_db_sync_catchup_lane_write(struct node_db *ndb, void *ctx)
{
    struct catchup_lane_ctx *catchup = ctx;

    if (!catchup)
        LOG_FAIL("sync", "catchup_lane_write: ctx is NULL");
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_catchup_test_lane_calls, 1);
    {
        struct db_service *dbsvc = app_runtime_db_service();
        if (dbsvc && db_service_is_worker_thread(dbsvc))
            atomic_fetch_add(&g_catchup_test_worker_lane_calls, 1);
    }
#endif
    catchup->result = node_db_sync_catchup(ndb, catchup->chain,
                                           catchup->w, catchup->datadir);
    return catchup->result >= 0;
}

static void *node_db_sync_catchup_job_thread(void *arg)
{
    struct node_db_sync_catchup_job *job = arg;
    struct db_service *dbsvc = NULL;

    if (!job) {
        LOG_NULL("sync", "catchup_job_thread: job is NULL");
    }

    if (!job->args.ndb || !job->args.ndb->open) {
        fprintf(stderr, "catchup: no usable database handle\n");
        job->result = -1;
        atomic_store(&job->finished, true);
        return NULL;
    }

    dbsvc = catchup_job_db_service_for(job->args.ndb);
    if (dbsvc) {
        struct catchup_lane_ctx ctx = {
            .chain = job->args.chain,
            .w = job->args.w,
            .datadir = job->args.datadir,
            .result = -1,
        };

        if (!db_service_run_write(dbsvc, node_db_sync_catchup_lane_write,
                                  &ctx) && ctx.result >= 0) {
            LOG_WARN("sync", "catchup write lane failed without detail");
            ctx.result = -1;
        }
        job->result = ctx.result;
    } else {
        job->result = node_db_sync_catchup(job->args.ndb, job->args.chain,
                                           job->args.w, job->args.datadir);
    }

    atomic_store(&job->finished, true);
    return NULL;
}

void node_db_sync_catchup_job_init(struct node_db_sync_catchup_job *job)
{
    if (!job)
        return;
    memset(job, 0, sizeof(*job));
    job->result = -1;
    atomic_store(&job->finished, false);
}

bool node_db_sync_catchup_job_start(struct node_db_sync_catchup_job *job,
                                    struct node_db *ndb,
                                    const struct active_chain *chain,
                                    struct wallet *w,
                                    const char *datadir)
{
    if (!job || job->started || !ndb || !chain)
        LOG_FAIL("sync", "catchup_job_start: invalid args (job=%p, ndb=%p, chain=%p)",
                 (void *)job, (void *)ndb, (void *)chain);

    job->args.ndb = ndb;
    job->args.chain = chain;
    job->args.w = w;

    /* Retain the datadir BYTES, never the starter's pointer. This function
     * spawns a worker and returns immediately, so a caller that resolved the
     * network datadir into a local buffer (catchup_lifecycle_start) has its
     * frame torn down while the worker is still opening blk*.dat out of it.
     * A NULL datadir stays NULL — the worker reports it with catchup
     * context, exactly as before. */
    job->args.datadir = NULL;
    job->args.datadir_storage[0] = '\0';
    if (datadir) {
        int n = snprintf(job->args.datadir_storage,
                         sizeof(job->args.datadir_storage), "%s", datadir);
        if (n <= 0 || (size_t)n >= sizeof(job->args.datadir_storage)) {
            job->args.datadir_storage[0] = '\0';
            LOG_FAIL("sync", "catchup_job_start: datadir is empty or exceeds "
                     "%zu bytes", sizeof(job->args.datadir_storage) - 1u);
        }
        job->args.datadir = job->args.datadir_storage;
    }
    job->result = -1;
    atomic_store(&job->finished, false);
    job->started = true;
    if (thread_registry_spawn("zcl_catchup",
                                  node_db_sync_catchup_job_thread, job,
                                  &job->thread) != 0) {
        job->started = false;
        atomic_store(&job->finished, false);
        LOG_FAIL("sync", "catchup_job_start: thread_registry_spawn failed");
    }
    return true;
}

bool node_db_sync_catchup_job_join(struct node_db_sync_catchup_job *job,
                                   int *result_out)
{
    int join_rc;

    if (!job || !job->started)
        LOG_FAIL("sync", "catchup_job_join: invalid args (job=%p, started=%d)",
                 (void *)job, job ? job->started : 0);
    join_rc = pthread_join(job->thread, NULL);
    if (join_rc != 0)
        LOG_FAIL("sync", "catchup_job_join: pthread_join failed (rc=%d)", join_rc);
    job->started = false;
    atomic_store(&job->finished, false);
    if (result_out)
        *result_out = job->result;
    return true;
}

bool node_db_sync_catchup_job_is_started(
    const struct node_db_sync_catchup_job *job)
{
    return job && job->started;
}

static void *node_db_sync_import_job_thread(void *arg)
{
    struct node_db_sync_import_job *job = arg;

    if (!job) {
        LOG_NULL("sync", "import_job_thread: job is NULL");
    }

    job->result = node_db_sync_import_utxos(job->args.ndb, job->args.cvdb);
    return NULL;
}

void node_db_sync_import_job_init(struct node_db_sync_import_job *job)
{
    if (!job)
        return;
    memset(job, 0, sizeof(*job));
    job->result = -1;
}

bool node_db_sync_import_job_start(struct node_db_sync_import_job *job,
                                   struct node_db *ndb,
                                   struct coins_view_db *cvdb)
{
    if (!job || job->started || !ndb || !cvdb)
        LOG_FAIL("sync", "import_job_start: invalid args (job=%p, ndb=%p, cvdb=%p)",
                 (void *)job, (void *)ndb, (void *)cvdb);

    job->args.ndb = ndb;
    job->args.cvdb = cvdb;
    job->result = -1;
    if (thread_registry_spawn("zcl_db_import",
                                  node_db_sync_import_job_thread, job,
                                  &job->thread) != 0)
        LOG_FAIL("sync", "import_job_start: thread_registry_spawn failed");
    job->started = true;
    return true;
}

bool node_db_sync_import_job_join(struct node_db_sync_import_job *job,
                                  int *result_out)
{
    int join_rc;

    if (!job || !job->started)
        LOG_FAIL("sync", "import_job_join: invalid args (job=%p, started=%d)",
                 (void *)job, job ? job->started : 0);
    join_rc = pthread_join(job->thread, NULL);
    if (join_rc != 0)
        LOG_FAIL("sync", "import_job_join: pthread_join failed (rc=%d)", join_rc);
    job->started = false;
    if (result_out)
        *result_out = job->result;
    return true;
}
