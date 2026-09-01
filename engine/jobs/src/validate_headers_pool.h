/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * validate_headers_pool — sibling-private worker-pool helper for the
 * validate_headers reducer stage. */

#ifndef ZCL_VALIDATE_HEADERS_POOL_H
#define ZCL_VALIDATE_HEADERS_POOL_H

#include "jobs/validate_headers_stage.h"

#include "chain/chain.h"
#include "primitives/block.h"

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>

/* One height's work item. Stored in the pool's batch scratch and handed to
 * `vh_pool_job_fn` one per worker. */
struct vh_job {
    const struct block_index *bi;       /* in: validation input */
    struct block_index       *mark_bi;  /* in: real index to mark on pass */
    struct block_index        snapshot; /* in: optional repaired-header copy */
    unsigned char             solution[MAX_SOLUTION_SIZE];
    int                       height;   /* in: convenience for logging */
    bool                      had_repair_row; /* in: a hash-bound header_solution_repair
                                               * row backs this height — the
                                               * solutionless-backfill fingerprint that
                                               * proves a stale FAILED mask is the
                                               * serve-refusal (clearable) class */
    bool                      ok;       /* out */
    char                      reason[VH_MAX_REASON];
};

typedef void (*vh_pool_job_fn)(void *job, void *user);

struct vh_pool {
    /* Sized to the fold ceiling (VH_MAX_POOL) so the runtime width is one
     * int, not an allocation: `n_threads` of these slots are live. */
    pthread_t       threads[VH_MAX_POOL];
    bool            thread_started[VH_MAX_POOL];
    int             n_threads;

    /* Per-step job scratch owned by the pool: `batch_cap` slots allocated at
     * start, freed at stop. Heap, not stack — a fold-width batch of
     * Equihash-solution-carrying jobs is far too large for the drive thread's
     * stack. Filled only by the caller's step, on the stage drive thread. */
    struct vh_job  *batch;
    int             batch_cap;

    unsigned char  *jobs;
    size_t          job_size;
    int             n_jobs;
    int             next_to_take;
    int             n_done;

    bool            stop;
    bool            inited;

    vh_pool_job_fn  run_job;
    void           *run_user;

    pthread_mutex_t mu;
    pthread_cond_t  cv_take;
    pthread_cond_t  cv_done;
};

/* Start `n_threads` Equihash workers (clamped to [1, VH_MAX_POOL]) and
 * allocate the `batch_cap`-slot job scratch. */
bool vh_pool_start(struct vh_pool *pool, vh_pool_job_fn run_job,
                   void *run_user, int n_threads, int batch_cap);
void vh_pool_run_batch(struct vh_pool *pool, void *jobs, size_t job_size,
                       int n_jobs);
void vh_pool_stop(struct vh_pool *pool);

#endif /* ZCL_VALIDATE_HEADERS_POOL_H */
