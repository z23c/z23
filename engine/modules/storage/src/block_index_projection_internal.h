/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * block_index_projection_internal — fields/state shared between
 * block_index_projection.c (open/close/catch_up driver + readers) and
 * block_index_projection_status.c (the EV_BLOCK_STATUS catch_up consumer,
 * split out to keep block_index_projection.c under the file-size ceiling —
 * the same "_internal.h" convention engine/jobs/src/ already uses for its own
 * per-stage helper splits. Not a public API; nothing outside this
 * directory includes it except the projection's own harness, which reads
 * the catch-up WAL stats fields. */

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

/* Mid-catch-up PASSIVE checkpoint bound. 32 MiB is ~10x under the 4.19 GB /
 * (13200/1000) ≈ 320 MB per-batch WAL growth measured on a 2-vCPU node
 * applying ~22 headers/s with no checkpoint until the stream ended. */
#define BIP_WAL_BUDGET_BYTES (32u * 1024u * 1024u)

/* Page cache for the hash-keyed WITHOUT ROWID block_index B-tree.
 *
 * Measured on a quiet HDD box (iostat): the consensus-state bundle
 * exporter sat >20 min at boot in block_index_projection_catch_up()
 * (called from engine/composition/src/boot_projections.c BEFORE the
 * BLOCK_INDEX_LOADED stage is recorded) doing 50-66 random reads/s of
 * 4-16 KB with 24-54 ms await, plus 15 MB/s write bursts at every
 * 1000-event batch commit — because create_schema() clusters
 * block_index on `hash BLOB PRIMARY KEY ... WITHOUT ROWID` (a B-tree
 * keyed on random bytes) and apply_pragmas() previously set only
 * journal_mode=WAL, synchronous=NORMAL, foreign_keys=ON,
 * busy_timeout=5000, temp_store=MEMORY. SQLite's default ~2 MB page
 * cache made every exists_stmt/ins_stmt lookup in catch_up_cb an
 * uncached random seek.
 *
 * PRAGMA cache_size is negative KiB. mmap stays 0: a hash-keyed table
 * gains nothing from mmap on a rotational disk and the process may be
 * memory-constrained. Operators on a low-RAM HDD box may lower the
 * cache with ZCL_BIP_PAGE_CACHE_KIB (decimal in [2048, 4194304]). */
#define BIP_PAGE_CACHE_KIB 262144
#define BIP_MMAP_BYTES     0

struct os_proc_mem;
/* Optional read-only warmup before catch-up; zero budget means no change. */
uint64_t block_index_projection_cache_budget(uint64_t bytes,
                                             const struct os_proc_mem *mem);
uint64_t block_index_projection_cache_warm(sqlite3_file *file, uint64_t bytes);
void block_index_projection_cache_prepare(sqlite3 *db);

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

    /* Catch-up WAL bound. `wal_budget_bytes` defaults to BIP_WAL_BUDGET_BYTES;
     * tests may lower it on the open handle. `max_wal_bytes_seen` is the
     * peak on-disk `-wal` size observed at a batch boundary this process. */
    uint64_t       wal_budget_bytes;
    uint64_t       max_wal_bytes_seen;
    uint64_t       wal_passive_checkpoints;
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
