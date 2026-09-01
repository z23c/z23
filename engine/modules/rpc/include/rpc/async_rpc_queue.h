/* Copyright (c) 2016 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_ASYNC_RPC_QUEUE_H
#define ZCL_ASYNC_RPC_QUEUE_H

#include "rpc/async_rpc_operation.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
#include <pthread.h>

#define MAX_ASYNC_OPS 256
#define MAX_ASYNC_WORKERS 8

struct async_rpc_queue {
    zcl_mutex_t lock;
    zcl_cond_t cond;
    _Atomic bool closed;
    _Atomic bool finishing;

    struct async_rpc_operation *ops[MAX_ASYNC_OPS];
    size_t num_ops;
    char op_queue[MAX_ASYNC_OPS][ASYNC_OP_ID_SIZE];
    size_t queue_head;
    size_t queue_tail;
    size_t queue_count;

    pthread_t workers[MAX_ASYNC_WORKERS];
    size_t num_workers;
};

/* Zero-init q and set up its mutex/cond; not closed, not finishing. Call once before use. */
void async_queue_init(struct async_rpc_queue *q);
/* Close-and-wait for all workers (see close_and_wait), then destroy the cond/mutex. Not reusable after. */
void async_queue_free(struct async_rpc_queue *q);

/* Spawn one more worker thread (up to MAX_ASYNC_WORKERS). Returns true if started; false if closed/finishing, at the cap, or spawn failed. Thread-safe. */
bool async_queue_add_worker(struct async_rpc_queue *q);
/* Current worker-thread count (mutex-guarded snapshot). */
size_t async_queue_num_workers(const struct async_rpc_queue *q);

/* True once async_queue_close has been called (hard stop, drop pending). Lock-free atomic read. */
bool async_queue_is_closed(const struct async_rpc_queue *q);
/* True once async_queue_finish has been called (drain pending, then stop). Lock-free atomic read. */
bool async_queue_is_finishing(const struct async_rpc_queue *q);

/* Hard close: mark closed, cancel all ops, wake workers; queued-but-unstarted ops are dropped. Non-blocking. */
void async_queue_close(struct async_rpc_queue *q);
/* Soft stop: mark finishing so workers exit only after the queue drains. Non-blocking; does not cancel. */
void async_queue_finish(struct async_rpc_queue *q);
/* async_queue_close then join every worker thread. Blocks; idempotent (workers cleared after join). */
void async_queue_close_and_wait(struct async_rpc_queue *q);
/* async_queue_finish then join every worker thread (workers drain pending first). Blocks; idempotent. */
void async_queue_finish_and_wait(struct async_rpc_queue *q);
/* Cancel every registered op and broadcast to wake workers. Thread-safe; does not remove ops or join. */
void async_queue_cancel_all(struct async_rpc_queue *q);

/* Register op and enqueue its id for execution. No-op if closed/finishing or at MAX_ASYNC_OPS. The queue does NOT take ownership of op (caller-owned; must outlive its run). Thread-safe. */
void async_queue_add_op(struct async_rpc_queue *q,
                        struct async_rpc_operation *op);

#endif
