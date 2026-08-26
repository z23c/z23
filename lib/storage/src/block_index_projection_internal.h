/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * block_index_projection_internal — fields/state shared between
 * block_index_projection.c (open/close/catch_up driver + readers) and
 * block_index_projection_status.c (the EV_BLOCK_STATUS catch_up consumer,
 * split out to keep block_index_projection.c under the file-size ceiling —
 * the same "_internal.h" convention app/jobs/src/ already uses for its own
 * per-stage helper splits. Not a public API; nothing outside this
 * directory includes it. */

#ifndef ZCL_STORAGE_BLOCK_INDEX_PROJECTION_INTERNAL_H
#define ZCL_STORAGE_BLOCK_INDEX_PROJECTION_INTERNAL_H

#include "storage/block_index_projection.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

/* Commit periodically during a long catch_up so a single crash re-consumes
 * at most one batch's worth of events, not the whole backlog. */
#define BIP_BATCH_EVENTS 1000

struct block_index_projection {
    sqlite3       *db;
    event_log_t   *log;
    pthread_mutex_t mu;             /* protects sqlite handle */
    char           path[1024];
    int64_t        opened_at;       /* wall time, seconds */

    /* Counters (snapshotted under mu by dump_state). */
    uint64_t       last_consumed_offset;
    uint64_t       events_consumed_total;
    uint64_t       replace_collisions_total;
    int64_t        last_catch_up_ms;
};

struct catch_up_ctx {
    block_index_projection_t *p;
    sqlite3_stmt *ins_stmt;       /* prepared INSERT OR REPLACE */
    sqlite3_stmt *exists_stmt;    /* prepared SELECT 1 ... WHERE hash = ? */
    sqlite3_stmt *blob_stmt;      /* prepared SELECT blob ... WHERE hash = ? */
    sqlite3_stmt *dirty_stmt;     /* prepared INSERT block_index_dirty(hash) */
    uint64_t batch_count;          /* events in current txn */
    uint64_t total_consumed;       /* across all batches this call */
    uint64_t collisions;           /* INSERT OR REPLACE that found a prior row */
    uint64_t status_orphans;       /* EV_BLOCK_STATUS with no prior row — logged, skipped */
    uint64_t last_offset_after;    /* offset *after* the last consumed event */
    atomic_uint_least64_t *scan_ctr; /* boot O(delta) witness (util/boot_scan.h) */
    bool     error;
};

/* Defined in block_index_projection.c (the catch_up driver owns the
 * transaction boundary + durable counters). */
bool batch_begin(struct catch_up_ctx *c);
bool batch_commit(struct catch_up_ctx *c);
bool block_index_projection_prepare_dirty(struct catch_up_ctx *c);
bool block_index_projection_mark_dirty(struct catch_up_ctx *c,
                                       const uint8_t hash[32]);

/* Defined in block_index_projection_status.c — the EV_BLOCK_STATUS consumer.
 * See its doc comment for the full contract. */
bool catch_up_apply_status(struct catch_up_ctx *c, const void *payload,
                           size_t len);

#endif /* ZCL_STORAGE_BLOCK_INDEX_PROJECTION_INTERNAL_H */
