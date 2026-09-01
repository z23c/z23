/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * validate_work_pool — implementation. See validate_work_pool.h. A dynamic-
 * width mirror of validate_headers_pool.c (the vh_pool). */

#include "validate_work_pool.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"
#include "util/util.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <string.h>

static void *vwp_worker_entry(void *arg)
{
    struct vwp_pool *pool = arg;
    for (;;) {
        pthread_mutex_lock(&pool->mu);
        while (!pool->stop && pool->next_to_take >= pool->n_jobs)
            pthread_cond_wait(&pool->cv_take, &pool->mu);
        if (pool->stop) {
            pthread_mutex_unlock(&pool->mu);
            break;
        }
        int my = pool->next_to_take++;
        void *job = pool->jobs + (pool->job_size * (size_t)my);
        vwp_job_fn run_job = pool->run_job;
        void *run_user = pool->run_user;
        pthread_mutex_unlock(&pool->mu);

        run_job(job, run_user);

        pthread_mutex_lock(&pool->mu);
        pool->n_done++;
        if (pool->n_done >= pool->n_jobs)
            pthread_cond_broadcast(&pool->cv_done);
        pthread_mutex_unlock(&pool->mu);
    }
    thread_registry_unregister_self();
    return NULL;
}

bool vwp_pool_start(struct vwp_pool *pool, vwp_job_fn run_job, int n_threads)
{
    if (!pool || !run_job)
        return false;

    if (n_threads <= 0)
        n_threads = GetNumCores();
    if (n_threads < 1)
        n_threads = 1;
    if (n_threads > VWP_MAX_THREADS)
        n_threads = VWP_MAX_THREADS;

    memset(pool, 0, sizeof(*pool));
    pool->run_job = run_job;
    pool->n_threads = n_threads;
    pool->threads = zcl_calloc((size_t)n_threads, sizeof(*pool->threads),
                               "vwp threads");
    pool->thread_started = zcl_calloc((size_t)n_threads,
                                      sizeof(*pool->thread_started),
                                      "vwp started");
    if (!pool->threads || !pool->thread_started) {
        free(pool->threads);
        free(pool->thread_started);
        memset(pool, 0, sizeof(*pool));
        LOG_FAIL("validate_pool", "[validate_pool] worker array alloc failed");
    }
    pthread_mutex_init(&pool->mu, NULL);
    pthread_cond_init(&pool->cv_take, NULL);
    pthread_cond_init(&pool->cv_done, NULL);

    for (int i = 0; i < n_threads; i++) {
        char name[32];
        snprintf(name, sizeof(name), "vwp.worker.%d", i);
        // thread-supervision-ok:bounded-worker-pool joined in vwp_pool_stop; idle-blocked on cv_take, runs bounded per-block batches
        int rc = thread_registry_spawn(name, vwp_worker_entry, pool,
                                        &pool->threads[i]);
        if (rc != 0) {
            LOG_WARN("validate_pool",
                     "[validate_pool] worker %d spawn failed: rc=%d", i, rc);
            pthread_mutex_lock(&pool->mu);
            pool->stop = true;
            pthread_cond_broadcast(&pool->cv_take);
            pthread_mutex_unlock(&pool->mu);
            for (int j = 0; j < i; j++)
                pthread_join(pool->threads[j], NULL);
            pthread_mutex_destroy(&pool->mu);
            pthread_cond_destroy(&pool->cv_take);
            pthread_cond_destroy(&pool->cv_done);
            free(pool->threads);
            free(pool->thread_started);
            memset(pool, 0, sizeof(*pool));
            return false;
        }
        pool->thread_started[i] = true;
    }
    pool->inited = true;
    return true;
}

void vwp_pool_run_batch(struct vwp_pool *pool, void *jobs, size_t job_size,
                        int n_jobs, void *user)
{
    vwp_pool_run_batch_profiled(pool, jobs, job_size, n_jobs, user, NULL, NULL);
}

void vwp_pool_run_batch_profiled(struct vwp_pool *pool, void *jobs,
                                 size_t job_size, int n_jobs, void *user,
                                 uint64_t *wakeup_us_out,
                                 uint64_t *wait_us_out)
{
    if (!pool || !pool->inited || !jobs || job_size == 0 || n_jobs <= 0)
        return;

    int64_t wake_started = platform_time_monotonic_us();
    pthread_mutex_lock(&pool->mu);
    pool->jobs = jobs;
    pool->job_size = job_size;
    pool->n_jobs = n_jobs;
    pool->next_to_take = 0;
    pool->n_done = 0;
    pool->run_user = user;
    pthread_cond_broadcast(&pool->cv_take);
    int64_t wait_started = platform_time_monotonic_us();
    if (wakeup_us_out)
        *wakeup_us_out = (uint64_t)(wait_started - wake_started);
    while (pool->n_done < pool->n_jobs)
        pthread_cond_wait(&pool->cv_done, &pool->mu);
    if (wait_us_out)
        *wait_us_out = (uint64_t)(platform_time_monotonic_us() - wait_started);
    pool->jobs = NULL;
    pool->job_size = 0;
    pool->n_jobs = 0;
    pool->run_user = NULL;
    pthread_mutex_unlock(&pool->mu);
}

void vwp_pool_stop(struct vwp_pool *pool)
{
    if (!pool || !pool->inited)
        return;

    pthread_mutex_lock(&pool->mu);
    pool->stop = true;
    pthread_cond_broadcast(&pool->cv_take);
    pthread_mutex_unlock(&pool->mu);
    for (int i = 0; i < pool->n_threads; i++) {
        if (pool->thread_started[i]) {
            pthread_join(pool->threads[i], NULL);
            pool->thread_started[i] = false;
        }
    }
    pthread_mutex_destroy(&pool->mu);
    pthread_cond_destroy(&pool->cv_take);
    pthread_cond_destroy(&pool->cv_done);
    free(pool->threads);
    free(pool->thread_started);
    memset(pool, 0, sizeof(*pool));
}
