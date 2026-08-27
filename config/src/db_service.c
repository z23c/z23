/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "platform/time_compat.h"
#include "config/db_service.h"
#include "models/database.h"
#include "util/thread_liveness.h"
#include "util/thread_registry.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int64_t db_service_now(void)
{
    return (int64_t)platform_time_wall_time_t();
}

static void db_service_reset_queue(struct db_service *svc)
{
    size_t i;

    if (!svc)
        return;
    for (i = 0; i < DB_SERVICE_QUEUE_CAP; ++i)
        svc->queue[i] = NULL;
    svc->queue_head = 0;
    svc->queue_tail = 0;
    svc->queue_count = 0;
}

static bool db_service_perform_job(struct db_service *svc,
                                   const struct db_service_job *job)
{
    struct node_db *ndb;

    if (!svc || !job)
        return false;
    ndb = svc->node_db;
    if (!ndb)
        return false;

    switch (job->type) {
    case DB_SERVICE_JOB_EXEC_SQL:
        return job->sql && node_db_exec(ndb, job->sql);
    case DB_SERVICE_JOB_NONE:
        return job->fn && job->fn(ndb, job->ctx);
    case DB_SERVICE_JOB_BEGIN:
        return node_db_begin(ndb);
    case DB_SERVICE_JOB_COMMIT:
        return node_db_commit(ndb);
    case DB_SERVICE_JOB_ROLLBACK:
        return node_db_rollback(ndb);
    case DB_SERVICE_JOB_FLUSH:
        return node_db_sync_flush(ndb);
    case DB_SERVICE_JOB_CLOSE:
        node_db_close(ndb);
        return true;
    case DB_SERVICE_JOB_STOP:
        return true;
    default:
        return false;
    }
}

struct db_service_batch_size_ctx {
    int batch_size;
    bool ok;
};

static bool db_service_set_sync_batch_size_write(struct node_db *ndb, void *ctx)
{
    struct db_service_batch_size_ctx *batch = ctx;

    if (!ndb || !batch)
        return false;
    node_db_set_sync_batch_size(ndb, batch->batch_size);
    batch->ok = true;
    return true;
}

static bool db_service_ibd_turbo_mode_write(struct node_db *ndb, void *ctx)
{
    bool *ok = ctx;

    if (!ndb)
        return false;
    if (ok)
        *ok = node_db_ibd_turbo_mode(ndb);
    return ok ? *ok : node_db_ibd_turbo_mode(ndb);
}

static bool db_service_normal_mode_write(struct node_db *ndb, void *ctx)
{
    bool *ok = ctx;

    if (!ndb)
        return false;
    if (ok)
        *ok = node_db_normal_mode(ndb);
    return ok ? *ok : node_db_normal_mode(ndb);
}

static bool db_service_wal_checkpoint_write(struct node_db *ndb, void *ctx)
{
    bool *ok = ctx;

    if (!ndb)
        return false;
    if (ok)
        *ok = node_db_wal_checkpoint(ndb);
    return ok ? *ok : node_db_wal_checkpoint(ndb);
}

/* Supervisor liveness for the two DB-service threads (single global service,
 * so module-static children suffice). The worker is dormant-until-event (it
 * blocks on the queue condvar with no timeout), so it registers liveness-only
 * (deadline=0, no-progress=0): present in the tree and heartbeating per job,
 * never falsely flagged for legitimately idling. The WAL checkpointer wakes
 * every second (deadline=60 s); progress marker = checkpoint count, no-progress
 * gate disabled (checkpoints are 5 min apart and skip when the DB is closed).
 * See util/thread_liveness.h. */
static struct thread_liveness_child g_dbw_child  = { .id = SUPERVISOR_INVALID_ID };
static struct thread_liveness_child g_ckpt_child = { .id = SUPERVISOR_INVALID_ID };

static void *db_service_worker_main(void *arg)
{
    struct db_service *svc = arg;
    int64_t jobs_done = 0;

    while (true) {
        struct db_service_job *job = NULL;

        zcl_mutex_lock(&svc->queue_mutex);
        while (svc->queue_count == 0 && !svc->stop_requested)
            zcl_cond_wait(&svc->queue_cond, &svc->queue_mutex);

        if (svc->queue_count > 0) {
            job = svc->queue[svc->queue_head];
            svc->queue[svc->queue_head] = NULL;
            svc->queue_head =
                (svc->queue_head + 1) % DB_SERVICE_QUEUE_CAP;
            svc->queue_count--;
            zcl_cond_broadcast(&svc->queue_cond);
        } else if (svc->stop_requested) {
            zcl_mutex_unlock(&svc->queue_mutex);
            break;
        }
        zcl_mutex_unlock(&svc->queue_mutex);

        if (!job)
            continue;

        job->success = db_service_perform_job(svc, job);
        /* Heartbeat onto the supervisor tree (atomic-only; zero behavior
         * change). Job count is the progress marker. */
        thread_liveness_beat(&g_dbw_child, ++jobs_done);

        /* Capture before any free: the async branch frees `job`, so reading
         * job->type afterward for the STOP check would be a use-after-free. */
        bool is_stop = (job->type == DB_SERVICE_JOB_STOP);

        if (job->async) {
            if (job->free_ctx)
                job->free_ctx(job->ctx);
            free(job);
        } else {
            zcl_mutex_lock(&svc->queue_mutex);
            job->done = true;
            zcl_cond_signal(&job->done_cond);
            zcl_mutex_unlock(&svc->queue_mutex);
        }

        if (is_stop)
            break;
    }

    return NULL;
}

static bool db_service_submit_job(struct db_service *svc,
                                  struct db_service_job *job)
{
    bool queued = false;

    if (!svc || !job || !svc->started || !svc->worker_started)
        return false;
    if (db_service_is_worker_thread(svc))
        return db_service_perform_job(svc, job);

    zcl_mutex_lock(&svc->queue_mutex);
    while (!job->async && svc->queue_count >= DB_SERVICE_QUEUE_CAP &&
           !svc->stop_requested)
        zcl_cond_wait(&svc->queue_cond, &svc->queue_mutex);

    if (!svc->stop_requested && svc->queue_count < DB_SERVICE_QUEUE_CAP) {
        svc->queue[svc->queue_tail] = job;
        svc->queue_tail =
            (svc->queue_tail + 1) % DB_SERVICE_QUEUE_CAP;
        svc->queue_count++;
        queued = true;
        zcl_cond_signal(&svc->queue_cond);
    }

    while (queued && !job->async && !job->done)
        zcl_cond_wait(&job->done_cond, &svc->queue_mutex);

    if (queued && svc->queue_count < DB_SERVICE_QUEUE_CAP)
        zcl_cond_broadcast(&svc->queue_cond);

    zcl_mutex_unlock(&svc->queue_mutex);
    return job->async ? queued : (queued && job->success);
}

static bool db_service_submit_simple_job(struct db_service *svc,
                                         enum db_service_job_type type,
                                         const char *sql)
{
    struct db_service_job job;

    memset(&job, 0, sizeof(job));
    job.type = type;
    job.sql = sql;
    zcl_cond_init(&job.done_cond);
    job.success = db_service_submit_job(svc, &job);
    zcl_cond_destroy(&job.done_cond);
    return job.success;
}

static bool db_service_open_query_db(struct db_service *svc)
{
    if (!svc || !svc->node_db || !svc->node_db->db)
        return false;

    /* Keep one SQLite handle for node.db. A lifetime secondary read-only
     * connection can hold WAL read locks across the process lifetime and
     * starve the serialized write worker on live nodes. The main handle is
     * opened FULLMUTEX and all hot statements are per-call or DB-service
     * serialized, so bounded health reads can safely share it. */
    svc->query_db = svc->node_db->db;
    svc->query_db_owned = false;
    return true;
}

static void db_service_close_query_db(struct db_service *svc)
{
    if (!svc || !svc->query_db)
        return;
    if (svc->query_db_owned)
        sqlite3_close(svc->query_db);
    svc->query_db = NULL;
    svc->query_db_owned = false;
}

void db_service_init(struct db_service *svc)
{
    if (!svc)
        return;
    memset(svc, 0, sizeof(*svc));
    zcl_mutex_init(&svc->queue_mutex);
    zcl_cond_init(&svc->queue_cond);
    db_service_reset_queue(svc);
}

bool db_service_attach(struct db_service *svc, struct node_db *node_db)
{
    if (!svc || !node_db)
        return false;
    svc->node_db = node_db;
    return true;
}

/* WAL checkpoint thread.
 *
 * sqlite3 autocheckpoint can be silently deferred when a long-running
 * reader holds the WAL open — observed in practice as multi-GB
 * .db-wal files after a few hours of catch-up. The pthread below
 * forces SQLITE_CHECKPOINT_TRUNCATE every 5 minutes regardless of
 * autocheckpoint state. It uses the same node_db lock contract as
 * every other writer so it won't race with the worker thread. */

#define WAL_CHECKPOINT_INTERVAL_SECS 300

static void *db_service_ckpt_main(void *arg)
{
    struct db_service *svc = arg;
    int64_t ckpts = 0;
    while (true) {
        for (int slept = 0;
             slept < WAL_CHECKPOINT_INTERVAL_SECS && !svc->ckpt_stop_requested;
             slept++) {
            struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
            nanosleep(&ts, NULL);
            /* Heartbeat every second so the deadline gate stays honest
             * across the 5-min sleep between checkpoints (atomic-only). */
            thread_liveness_beat(&g_ckpt_child, ckpts);
        }
        if (svc->ckpt_stop_requested) break;

        struct node_db *ndb = svc->node_db;
        if (!ndb || !ndb->open) continue;
        if (!db_service_wal_checkpoint(svc)) {
            fprintf(stderr,
                "[wal-checkpoint] periodic checkpoint failed (db busy?)\n");
        } else {
            ckpts++;  /* progress marker advances on a real checkpoint */
        }
    }
    return NULL;
}

static bool db_service_start_impl(struct db_service *svc,
                                  bool start_checkpointer)
{
    if (!svc || !svc->node_db)
        return false;
    if (svc->started)
        return true;
    if (!db_service_open_query_db(svc))
        return false;
    svc->stop_requested = false;
    db_service_reset_queue(svc);
    // supervised:zcl_db_worker (thread_liveness_register below)
    if (thread_registry_spawn("zcl_db_worker", db_service_worker_main,
                                  svc, &svc->worker_thread) != 0) {
        db_service_close_query_db(svc);
        return false;
    }
    svc->worker_started = true;
    (void)thread_liveness_register(&g_dbw_child, "zcl_db_worker",
                                   /*deadline_secs=*/0,
                                   /*progress_quiet_us=*/0);

    /* Best-effort checkpointer; failure is non-fatal (autocheckpoint
     * still works in steady state, and the explicit fsync barrier in
     * chain_tip.c keeps tip durability independent). */
    svc->ckpt_stop_requested = false;
    // supervised:zcl_db_ckpt (thread_liveness_register below)
    if (start_checkpointer &&
        thread_registry_spawn("zcl_db_ckpt", db_service_ckpt_main,
                              svc, &svc->ckpt_thread) == 0) {
        svc->ckpt_started = true;
        (void)thread_liveness_register(&g_ckpt_child, "zcl_db_ckpt",
                                       /*deadline_secs=*/60,
                                       /*progress_quiet_us=*/0);
    } else if (start_checkpointer) {
        fprintf(stderr,
            "[wal-checkpoint] failed to start periodic checkpoint thread\n");
    }

    svc->started = true;
    svc->started_at = db_service_now();
    return true;
}

bool db_service_start(struct db_service *svc)
{
    return db_service_start_impl(svc, true);
}

#ifdef ZCL_TESTING
bool db_service_start_test_worker(struct db_service *svc)
{
    return db_service_start_impl(svc, false);
}
#endif

void db_service_stop(struct db_service *svc)
{
    if (!svc)
        return;
    if (svc->ckpt_started) {
        svc->ckpt_stop_requested = true;
        pthread_join(svc->ckpt_thread, NULL);
        svc->ckpt_started = false;
        thread_liveness_retire(&g_ckpt_child);
    }
    if (svc->worker_started) {
        zcl_mutex_lock(&svc->queue_mutex);
        svc->stop_requested = true;
        zcl_cond_broadcast(&svc->queue_cond);
        zcl_mutex_unlock(&svc->queue_mutex);
        pthread_join(svc->worker_thread, NULL);
        svc->worker_started = false;
        thread_liveness_retire(&g_dbw_child);
    }
    svc->started = false;
    svc->stop_requested = false;
    db_service_reset_queue(svc);
    db_service_close_query_db(svc);
    svc->node_db = NULL;
}

struct node_db *db_service_node_db(struct db_service *svc)
{
    if (!svc || !svc->started)
        return NULL;
    return svc->node_db;
}

sqlite3 *db_service_query_db(struct db_service *svc)
{
    if (!svc || !svc->started)
        return NULL;
    return svc->query_db;
}

bool db_service_is_started(const struct db_service *svc)
{
    return svc && svc->started;
}

void db_service_get_status(const struct db_service *svc,
                           struct db_service_status *out)
{
    struct db_service_status empty = {0};

    if (!out)
        return;
    *out = empty;
    if (!svc)
        return;

    out->started = svc->started;
    out->worker_started = svc->worker_started;
    out->started_at = svc->started_at;

    zcl_mutex_lock((zcl_mutex_t *)&svc->queue_mutex);
    out->stop_requested = svc->stop_requested;
    out->queue_depth = svc->queue_count;
    zcl_mutex_unlock((zcl_mutex_t *)&svc->queue_mutex);
}

bool db_service_exec_write(struct db_service *svc, const char *sql)
{
    return db_service_submit_simple_job(svc, DB_SERVICE_JOB_EXEC_SQL, sql);
}

bool db_service_begin_write(struct db_service *svc)
{
    return db_service_submit_simple_job(svc, DB_SERVICE_JOB_BEGIN, NULL);
}

bool db_service_commit_write(struct db_service *svc)
{
    return db_service_submit_simple_job(svc, DB_SERVICE_JOB_COMMIT, NULL);
}

bool db_service_rollback_write(struct db_service *svc)
{
    return db_service_submit_simple_job(svc, DB_SERVICE_JOB_ROLLBACK, NULL);
}

bool db_service_flush_write(struct db_service *svc)
{
    return db_service_submit_simple_job(svc, DB_SERVICE_JOB_FLUSH, NULL);
}

bool db_service_close_write(struct db_service *svc)
{
    return db_service_submit_simple_job(svc, DB_SERVICE_JOB_CLOSE, NULL);
}

bool db_service_set_sync_batch_size(struct db_service *svc, int batch_size)
{
    struct db_service_batch_size_ctx ctx = {
        .batch_size = batch_size,
        .ok = false,
    };

    return db_service_run_write(svc, db_service_set_sync_batch_size_write, &ctx)
        && ctx.ok;
}

bool db_service_ibd_turbo_mode(struct db_service *svc)
{
    bool ok = false;

    return db_service_run_write(svc, db_service_ibd_turbo_mode_write, &ok) && ok;
}

bool db_service_normal_mode(struct db_service *svc)
{
    bool ok = false;

    return db_service_run_write(svc, db_service_normal_mode_write, &ok) && ok;
}

bool db_service_wal_checkpoint(struct db_service *svc)
{
    bool ok = false;

    return db_service_run_write(svc, db_service_wal_checkpoint_write, &ok) && ok;
}

bool db_service_run_write(struct db_service *svc,
                          db_service_write_fn fn,
                          void *ctx)
{
    struct db_service_job job;

    if (!fn)
        return false;

    memset(&job, 0, sizeof(job));
    job.type = DB_SERVICE_JOB_NONE;
    job.fn = fn;
    job.ctx = ctx;
    zcl_cond_init(&job.done_cond);
    job.success = db_service_submit_job(svc, &job);
    zcl_cond_destroy(&job.done_cond);
    return job.success;
}

bool db_service_enqueue_write(struct db_service *svc,
                              db_service_write_fn fn,
                              void *ctx,
                              db_service_free_fn free_ctx)
{
    struct db_service_job *job;
    bool queued;

    /* Ownership of `ctx` transfers here on EVERY path, so a caller never has
     * to work out which refusal it is looking at. Three of these returns used
     * to drop it silently while a fourth freed it, which is how a caller ended
     * up freeing a pointer this function had already released. */
    if (!fn) {
        if (free_ctx)
            free_ctx(ctx);
        return false;
    }
    if (!svc || !svc->started || !svc->worker_started) {
        if (free_ctx)
            free_ctx(ctx);
        return false;
    }
    if (db_service_is_worker_thread(svc)) {
        bool ok = fn(svc->node_db, ctx);
        if (free_ctx)
            free_ctx(ctx);
        return ok;
    }

    job = malloc(sizeof(*job)); /* raw-alloc-ok:db-service-owns-heap-job */
    if (!job) {
        if (free_ctx)
            free_ctx(ctx);
        return false;
    }
    memset(job, 0, sizeof(*job));
    job->type = DB_SERVICE_JOB_NONE;
    job->fn = fn;
    job->ctx = ctx;
    job->free_ctx = free_ctx;
    job->async = true;
    queued = db_service_submit_job(svc, job);
    if (!queued) {
        if (free_ctx)
            free_ctx(ctx);
        free(job);
    }
    return queued;
}

bool db_service_is_worker_thread(const struct db_service *svc)
{
    if (!svc || !svc->started || !svc->worker_started)
        return false;
    return pthread_equal(pthread_self(), svc->worker_thread) != 0;
}
