/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * workpool.h — Fixed-size thread pool for parallel CPU-bound work.
 *
 * Design: N persistent worker threads drain a shared queue of work items.
 * The caller submits a batch, then waits for all items to complete.
 * One failure short-circuits remaining work (early-out). Thread-safe. */

#ifndef ZCL_UTIL_WORKPOOL_H
#define ZCL_UTIL_WORKPOOL_H

#include "util/sync.h"
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Maximum workers (clamped from GetNumCores) */
#define WORKPOOL_MAX_THREADS 64

/* Work function: returns true on success, false on failure.
 * Receives opaque item pointer. Must be thread-safe. */
typedef bool (*workpool_fn)(void *item);

struct workpool {
    /* Thread management */
    pthread_t threads[WORKPOOL_MAX_THREADS];
    int num_threads;
    bool shutdown;

    /* Work queue (ring buffer) */
    void **items;
    size_t head;       /* next read position */
    size_t tail;       /* next write position */
    size_t capacity;
    size_t pending;    /* items not yet completed */

    /* Synchronization */
    zcl_mutex_t mutex;
    zcl_cond_t cond_work;    /* workers wait here */
    zcl_cond_t cond_done;    /* master waits here */

    /* Results */
    bool all_ok;

    /* Function to call per item */
    workpool_fn fn;
};

/* Create a workpool with `num_threads` workers.
 * If num_threads <= 0, uses GetNumCores() clamped to [1, WORKPOOL_MAX_THREADS].
 * `queue_cap` is the ring buffer size (must be > 0). */
bool workpool_init(struct workpool *wp, int num_threads, size_t queue_cap,
                   workpool_fn fn);

/* Destroy the pool, joining all threads. */
void workpool_destroy(struct workpool *wp);

/* Submit `count` work items. Blocks if queue is full.
 * Items are NOT freed by the pool — caller manages memory. */
void workpool_submit(struct workpool *wp, void **items, size_t count);

/* Wait for all submitted items to complete.
 * Returns true if all succeeded, false if any failed. */
bool workpool_wait(struct workpool *wp);

/* Submit + wait in one call (convenience). */
bool workpool_run(struct workpool *wp, void **items, size_t count);

/* Query pool size. */
int workpool_num_threads(const struct workpool *wp);

#endif /* ZCL_UTIL_WORKPOOL_H */
