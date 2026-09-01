/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * validate_work_pool — a fixed, thread-registry-supervised, batch-join worker
 * pool for order-independent per-item validation work inside a SINGLE block
 * (the script_validate ECDSA inputs and the proof_validate shielded proofs).
 *
 * It is a direct sibling of validate_headers_pool (the vh_pool used by
 * validate_headers_stage): same idle-blocked-on-cv_take / broadcast-and-join
 * lifecycle, same thread_registry_spawn supervision, same bounded-batch model.
 * The only differences over vh_pool are (a) the worker count is chosen at
 * start() from GetNumCores() instead of a compile-time constant, so the pool
 * scales to the host, and (b) vwp_pool_run_batch takes a per-batch `user`
 * pointer (block-level constants: script flags / branch id, or the proof
 * verifier + height) instead of a single start-time user.
 *
 * The pool NEVER decides validity — callers build an indexed job array, the
 * pool runs each job (order-independent), and the caller reduces the per-job
 * results back in original index order so the accept/reject verdict and the
 * first-failing-item are byte-identical to a serial in-order sweep. */

#ifndef ZCL_VALIDATE_WORK_POOL_H
#define ZCL_VALIDATE_WORK_POOL_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* run_job is handed one job slot (jobs + job_size*i) and the per-batch user
 * pointer. It runs to completion with no shared mutable state — the caller
 * guarantees each job touches only its own slot + read-only inputs. */
typedef void (*vwp_job_fn)(void *job, void *user);

struct vwp_pool {
    pthread_t      *threads;        /* n_threads, heap-owned */
    bool           *thread_started; /* n_threads, heap-owned */
    int             n_threads;

    unsigned char  *jobs;
    size_t          job_size;
    int             n_jobs;
    int             next_to_take;
    int             n_done;
    void           *run_user;       /* set per batch */

    bool            stop;
    bool            inited;

    vwp_job_fn      run_job;

    pthread_mutex_t mu;
    pthread_cond_t  cv_take;
    pthread_cond_t  cv_done;
};

/* Start `n_threads` supervised workers idle-blocked on cv_take. n_threads is
 * clamped to [1, VWP_MAX_THREADS]. Returns false (and leaves the pool zeroed,
 * so the caller can fall back to a serial sweep) on any spawn/alloc failure. */
#define VWP_MAX_THREADS 16
bool vwp_pool_start(struct vwp_pool *pool, vwp_job_fn run_job, int n_threads);

/* Run `n_jobs` jobs across the workers and block until every job has completed.
 * `user` is visible to run_job for the duration of this batch. No-op if the
 * pool is not inited or the arguments are degenerate. */
void vwp_pool_run_batch(struct vwp_pool *pool, void *jobs, size_t job_size,
                        int n_jobs, void *user);
void vwp_pool_run_batch_profiled(struct vwp_pool *pool, void *jobs,
                                 size_t job_size, int n_jobs, void *user,
                                 uint64_t *wakeup_us_out,
                                 uint64_t *wait_us_out);

/* Signal stop, join every worker, and release the pool's heap + sync objects. */
void vwp_pool_stop(struct vwp_pool *pool);

#endif /* ZCL_VALIDATE_WORK_POOL_H */
