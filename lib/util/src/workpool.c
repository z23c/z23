/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * workpool.c — Fixed-size thread pool implementation. */

#include "util/workpool.h"
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"
#include "util/util.h"

static void workpool_teardown(struct workpool *wp);

static void *worker_thread(void *arg)
{
    struct workpool *wp = (struct workpool *)arg;

    for (;;) {
        zcl_mutex_lock(&wp->mutex);

        /* Wait for work or shutdown */
        while (wp->head == wp->tail && !wp->shutdown)
            zcl_cond_wait(&wp->cond_work, &wp->mutex);

        if (wp->shutdown && wp->head == wp->tail) {
            zcl_mutex_unlock(&wp->mutex);
            return NULL;
        }

        /* Early-out: if a previous item already failed, skip remaining */
        if (!wp->all_ok) {
            /* Still need to drain to decrement pending */
            void *item = wp->items[wp->head];
            wp->head = (wp->head + 1) % wp->capacity;
            (void)item;
            wp->pending--;
            if (wp->pending == 0)
                zcl_cond_signal(&wp->cond_done);
            zcl_mutex_unlock(&wp->mutex);
            continue;
        }

        /* Dequeue one item */
        void *item = wp->items[wp->head];
        wp->head = (wp->head + 1) % wp->capacity;

        zcl_mutex_unlock(&wp->mutex);

        /* Execute outside the lock */
        bool ok = wp->fn(item);

        zcl_mutex_lock(&wp->mutex);
        if (!ok)
            wp->all_ok = false;
        wp->pending--;
        if (wp->pending == 0)
            zcl_cond_signal(&wp->cond_done);
        zcl_mutex_unlock(&wp->mutex);
    }
}

bool workpool_init(struct workpool *wp, int num_threads, size_t queue_cap,
                   workpool_fn fn)
{
    if (!wp || !fn || queue_cap == 0)
        return false;

    memset(wp, 0, sizeof(*wp));

    if (num_threads <= 0)
        num_threads = GetNumCores();
    if (num_threads < 1)
        num_threads = 1;
    if (num_threads > WORKPOOL_MAX_THREADS)
        num_threads = WORKPOOL_MAX_THREADS;

    wp->fn = fn;
    wp->capacity = queue_cap + 1; /* ring buffer needs +1 slot */
    wp->items = zcl_calloc(wp->capacity, sizeof(void *), "workpool_items");
    if (!wp->items)
        return false;

    wp->head = 0;
    wp->tail = 0;
    wp->pending = 0;
    wp->all_ok = true;
    wp->shutdown = false;

    zcl_mutex_init(&wp->mutex);
    zcl_cond_init(&wp->cond_work);
    zcl_cond_init(&wp->cond_done);

    /* Spawn workers */
    wp->num_threads = 0;
    for (int i = 0; i < num_threads; i++) {
        /* raw-pthread-ok: workpool-primitive (registry-equivalent) */
        if (pthread_create(&wp->threads[i], NULL, worker_thread, wp) != 0)
            break;
        wp->num_threads++;
    }

    if (wp->num_threads == 0) {
        /* No workers spawned: tear down the sync primitives + queue we
         * already created (mutex/conds at init, plus any partially-started
         * threads) before failing, so init failure leaks nothing. */
        workpool_teardown(wp);
        return false;
    }

    return true;
}

/* Shared teardown: signal shutdown, join started threads, free the queue,
 * and destroy the sync primitives. Used by both workpool_destroy and the
 * workpool_init failure path. Safe when num_threads == 0 (join loop no-ops).
 * Requires mutex/conds to have been initialized. */
static void workpool_teardown(struct workpool *wp)
{
    zcl_mutex_lock(&wp->mutex);
    wp->shutdown = true;
    zcl_cond_broadcast(&wp->cond_work);
    zcl_mutex_unlock(&wp->mutex);

    for (int i = 0; i < wp->num_threads; i++)
        pthread_join(wp->threads[i], NULL);

    free(wp->items);
    zcl_cond_destroy(&wp->cond_work);
    zcl_cond_destroy(&wp->cond_done);
    zcl_mutex_destroy(&wp->mutex);
}

void workpool_destroy(struct workpool *wp)
{
    if (!wp)
        return;

    workpool_teardown(wp);
}

void workpool_submit(struct workpool *wp, void **items, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        zcl_mutex_lock(&wp->mutex);

        /* Wait if ring buffer is full */
        while (((wp->tail + 1) % wp->capacity) == wp->head && !wp->shutdown)
            zcl_cond_wait(&wp->cond_done, &wp->mutex);

        if (wp->shutdown) {
            zcl_mutex_unlock(&wp->mutex);
            return;
        }

        wp->items[wp->tail] = items[i];
        wp->tail = (wp->tail + 1) % wp->capacity;
        wp->pending++;

        zcl_cond_signal(&wp->cond_work);
        zcl_mutex_unlock(&wp->mutex);
    }
}

bool workpool_wait(struct workpool *wp)
{
    zcl_mutex_lock(&wp->mutex);
    while (wp->pending > 0)
        zcl_cond_wait(&wp->cond_done, &wp->mutex);
    bool result = wp->all_ok;
    wp->all_ok = true;  /* Reset for next batch */
    zcl_mutex_unlock(&wp->mutex);
    return result;
}

bool workpool_run(struct workpool *wp, void **items, size_t count)
{
    workpool_submit(wp, items, count);
    return workpool_wait(wp);
}

int workpool_num_threads(const struct workpool *wp)
{
    return wp ? wp->num_threads : 0;
}
