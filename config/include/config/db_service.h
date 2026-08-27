/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_DB_SERVICE_H
#define ZCL_DB_SERVICE_H

#include "util/sync.h"
#include <sqlite3.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>

struct node_db;
typedef bool (*db_service_write_fn)(struct node_db *ndb, void *ctx);
typedef void (*db_service_free_fn)(void *ctx);

struct db_service_status {
    bool started;
    bool worker_started;
    bool stop_requested;
    size_t queue_depth;
    int64_t started_at;
};

enum db_service_job_type {
    DB_SERVICE_JOB_NONE = 0,
    DB_SERVICE_JOB_EXEC_SQL,
    DB_SERVICE_JOB_BEGIN,
    DB_SERVICE_JOB_COMMIT,
    DB_SERVICE_JOB_ROLLBACK,
    DB_SERVICE_JOB_FLUSH,
    DB_SERVICE_JOB_CLOSE,
    DB_SERVICE_JOB_STOP,
};

#define DB_SERVICE_QUEUE_CAP 64

struct db_service_job {
    enum db_service_job_type type;
    const char *sql;
    db_service_write_fn fn;
    void *ctx;
    db_service_free_fn free_ctx;
    bool async;
    bool done;
    bool success;
    zcl_cond_t done_cond;
};

struct db_service {
    struct node_db *node_db;
    /* Alias of node_db->db for bounded runtime reads; not an owned
     * secondary connection. */
    sqlite3 *query_db;
    bool query_db_owned;
    zcl_mutex_t queue_mutex;
    zcl_cond_t queue_cond;
    pthread_t worker_thread;
    bool worker_started;
    _Atomic bool stop_requested;
    struct db_service_job *queue[DB_SERVICE_QUEUE_CAP];
    size_t queue_head;
    size_t queue_tail;
    size_t queue_count;
    bool started;
    int64_t started_at;

    /* Periodic WAL checkpoint thread. Even with wal_autocheckpoint=1000
     * set, the autocheckpoint can be deferred indefinitely if a
     * long-running reader holds the WAL open. The background thread
     * forces SQLITE_CHECKPOINT_TRUNCATE every 5 min so the .db-wal
     * file stays bounded regardless of reader pressure. */
    pthread_t ckpt_thread;
    bool ckpt_started;
    _Atomic bool ckpt_stop_requested;
};

void db_service_init(struct db_service *svc);
bool db_service_attach(struct db_service *svc, struct node_db *node_db);
bool db_service_start(struct db_service *svc);
#ifdef ZCL_TESTING
/* Fixture owner: starts the serialized writer without a five-minute periodic
 * checkpoint thread. The fixture closes its private DB after every case. */
bool db_service_start_test_worker(struct db_service *svc);
#endif
void db_service_stop(struct db_service *svc);
struct node_db *db_service_node_db(struct db_service *svc);
sqlite3 *db_service_query_db(struct db_service *svc);
bool db_service_is_started(const struct db_service *svc);
void db_service_get_status(const struct db_service *svc,
                           struct db_service_status *out);

/* Initial write-side ownership helpers. These are stepping stones toward
 * a fuller queued single-writer model. */
bool db_service_exec_write(struct db_service *svc, const char *sql);
bool db_service_begin_write(struct db_service *svc);
bool db_service_commit_write(struct db_service *svc);
bool db_service_rollback_write(struct db_service *svc);
bool db_service_flush_write(struct db_service *svc);
bool db_service_close_write(struct db_service *svc);
bool db_service_set_sync_batch_size(struct db_service *svc, int batch_size);
bool db_service_ibd_turbo_mode(struct db_service *svc);
bool db_service_normal_mode(struct db_service *svc);
bool db_service_wal_checkpoint(struct db_service *svc);
bool db_service_run_write(struct db_service *svc,
                          db_service_write_fn fn,
                          void *ctx);
/* Queue an asynchronous write.
 *
 * OWNERSHIP: takes `ctx` on EVERY return path. On success the worker frees
 * it through `free_ctx` once the write has run; on failure this function
 * runs `free_ctx` before returning. The caller must never free `ctx`
 * itself, and must not read it after the call.
 *
 * The return value never reports ownership. It means "queued", except when
 * called ON the worker thread, where the write runs inline and the return is
 * the write's own result. Either way `ctx` is already disposed of.
 *
 * A false return is routine, not exceptional: the queue is bounded and an
 * async submit is refused immediately once it is full, which happens steadily
 * during sync. Treat the failure path as hot. */
bool db_service_enqueue_write(struct db_service *svc,
                              db_service_write_fn fn,
                              void *ctx,
                              db_service_free_fn free_ctx);
bool db_service_is_worker_thread(const struct db_service *svc);

#endif
