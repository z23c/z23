/* Copyright (c) 2016 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "rpc/async_rpc_queue.h"
#include "util/thread_liveness.h"
#include "util/thread_registry.h"
#include <string.h>
#include <stdatomic.h>
#include <stdio.h>

/* Supervisor liveness (root child — engine/modules/rpc cannot include the app-side
 * supervisors/domains.h, see util/thread_liveness.h). async_queue_add_worker
 * can spawn up to MAX_ASYNC_WORKERS threads that all share the name
 * "zcl_async_rpc"; rather than track per-worker isolation, ONE shared
 * contract answers the honest question "is at least one async_rpc worker
 * loop alive" — thread_liveness_register is idempotent, so every worker's
 * registration call after the first is a no-op that returns the existing
 * id, and any worker's loop iteration beats the shared contract.
 * Liveness-only: a condvar-blocked worker with an empty queue idles
 * indefinitely and legitimately. */
static struct thread_liveness_child g_async_rpc_liveness = { .id = SUPERVISOR_INVALID_ID };
static _Atomic uint64_t g_async_rpc_beat_count = 0;

void async_queue_init(struct async_rpc_queue *q)
{
    memset(q, 0, sizeof(*q));
    zcl_mutex_init(&q->lock);
    zcl_cond_init(&q->cond);
    atomic_store(&q->closed, false);
    atomic_store(&q->finishing, false);
}

static void wait_for_workers(struct async_rpc_queue *q)
{
    zcl_mutex_lock(&q->lock);
    size_t nw = q->num_workers;
    zcl_cond_broadcast(&q->cond);
    zcl_mutex_unlock(&q->lock);

    for (size_t i = 0; i < nw; i++)
        pthread_join(q->workers[i], NULL);

    if (nw > 0)
        thread_liveness_retire(&g_async_rpc_liveness);

    /* Clear so a second call (e.g. free after finish_and_wait) is safe */
    zcl_mutex_lock(&q->lock);
    q->num_workers = 0;
    zcl_mutex_unlock(&q->lock);
}

void async_queue_free(struct async_rpc_queue *q)
{
    async_queue_close_and_wait(q);
    zcl_cond_destroy(&q->cond);
    zcl_mutex_destroy(&q->lock);
}

static void *worker_thread(void *arg)
{
    struct async_rpc_queue *q = arg;

    while (true) {
        char key[ASYNC_OP_ID_SIZE] = {0};
        struct async_rpc_operation *operation = NULL;

        zcl_mutex_lock(&q->lock);
        while (q->queue_count == 0 &&
               !async_queue_is_closed(q) &&
               !async_queue_is_finishing(q)) {
            zcl_cond_wait(&q->cond, &q->lock);
        }
        thread_liveness_beat(&g_async_rpc_liveness,
                             (int64_t)atomic_fetch_add(&g_async_rpc_beat_count, 1) + 1);

        if (async_queue_is_finishing(q) && q->queue_count == 0) {
            zcl_mutex_unlock(&q->lock);
            break;
        }

        if (async_queue_is_closed(q)) {
            q->queue_count = 0;
            q->queue_head = 0;
            q->queue_tail = 0;
            zcl_mutex_unlock(&q->lock);
            break;
        }

        memcpy(key, q->op_queue[q->queue_head], ASYNC_OP_ID_SIZE);
        q->queue_head = (q->queue_head + 1) % MAX_ASYNC_OPS;
        q->queue_count--;

        for (size_t i = 0; i < q->num_ops; i++) {
            if (strcmp(q->ops[i]->id, key) == 0) {
                operation = q->ops[i];
                break;
            }
        }
        zcl_mutex_unlock(&q->lock);

        if (!operation || async_op_is_cancelled(operation))
            continue;

        if (operation->main_fn)
            operation->main_fn(operation);
    }
    return NULL;
}

bool async_queue_add_worker(struct async_rpc_queue *q)
{
    bool started = false;
    int rc = 0;

    if (!q)
        return false;
    zcl_mutex_lock(&q->lock);
    if (!async_queue_is_closed(q) && !async_queue_is_finishing(q) &&
        q->num_workers < MAX_ASYNC_WORKERS) {
        rc = thread_registry_spawn("zcl_async_rpc", worker_thread, q,
                                       &q->workers[q->num_workers]);
        if (rc == 0) {
            q->num_workers++;
            started = true;
            thread_liveness_register(&g_async_rpc_liveness, "zcl_async_rpc", 0, 0);
        } else {
            perror("async_queue_add_worker: thread_registry_spawn");
        }
    }
    zcl_mutex_unlock(&q->lock);
    return started;
}

size_t async_queue_num_workers(const struct async_rpc_queue *q)
{
    if (!q)
        return 0;
    zcl_mutex_lock((zcl_mutex_t *)&q->lock);
    size_t n = q->num_workers;
    zcl_mutex_unlock((zcl_mutex_t *)&q->lock);
    return n;
}

bool async_queue_is_closed(const struct async_rpc_queue *q)
{
    return atomic_load(&q->closed);
}

bool async_queue_is_finishing(const struct async_rpc_queue *q)
{
    return atomic_load(&q->finishing);
}

void async_queue_close(struct async_rpc_queue *q)
{
    atomic_store(&q->closed, true);
    async_queue_cancel_all(q);
}

void async_queue_finish(struct async_rpc_queue *q)
{
    atomic_store(&q->finishing, true);
}

void async_queue_close_and_wait(struct async_rpc_queue *q)
{
    async_queue_close(q);
    wait_for_workers(q);
}

void async_queue_finish_and_wait(struct async_rpc_queue *q)
{
    async_queue_finish(q);
    wait_for_workers(q);
}

void async_queue_cancel_all(struct async_rpc_queue *q)
{
    zcl_mutex_lock(&q->lock);
    for (size_t i = 0; i < q->num_ops; i++)
        async_op_cancel(q->ops[i]);
    zcl_cond_broadcast(&q->cond);
    zcl_mutex_unlock(&q->lock);
}

void async_queue_add_op(struct async_rpc_queue *q,
                        struct async_rpc_operation *op)
{
    zcl_mutex_lock(&q->lock);
    if (async_queue_is_closed(q) || async_queue_is_finishing(q)) {
        zcl_mutex_unlock(&q->lock);
        return;
    }
    if (q->num_ops >= MAX_ASYNC_OPS || q->queue_count >= MAX_ASYNC_OPS) {
        zcl_mutex_unlock(&q->lock);
        return;
    }

    q->ops[q->num_ops++] = op;
    memcpy(q->op_queue[q->queue_tail], op->id, ASYNC_OP_ID_SIZE);
    q->queue_tail = (q->queue_tail + 1) % MAX_ASYNC_OPS;
    q->queue_count++;
    zcl_cond_signal(&q->cond);
    zcl_mutex_unlock(&q->lock);
}

