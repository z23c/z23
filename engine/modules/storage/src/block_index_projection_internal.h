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

/* Small batch size (events). No longer the production commit cadence; the
 * WAL-budget tests pin it through commit_events. */
#define BIP_BATCH_EVENTS 1000

/* Replay commit cadence. One transaction carries the rows AND the consumed
 * offset; it commits at the first of: this many events, this many log bytes,
 * or this much wall time. A killed boot resumes from the last commit, so the
 * cost of a kill is bounded by these, while fewer and larger batches let
 * SQLite coalesce random B-tree page writes (the spinning-disk cost).
 * synchronous stays NORMAL and the journal stays WAL: no durability change. */
#define BIP_COMMIT_EVENTS    262144u
#define BIP_COMMIT_LOG_BYTES (64ull * 1024ull * 1024ull)
#define BIP_COMMIT_MS        10000

/* Progress line: at most once per 10 s AND once per 1 percent. */
#define BIP_PROGRESS_MS      10000
#define BIP_PROGRESS_PCT     1u

/* Mid-catch-up PASSIVE checkpoint bound. 32 MiB is ~10x under the 4.19 GB /
 * (13200/1000) ≈ 320 MB per-batch WAL growth measured on a 2-vCPU node
 * applying ~22 headers/s with no checkpoint until the stream ended. */
#define BIP_WAL_BUDGET_BYTES (32u * 1024u * 1024u)

/* Replay WAL bound: the 262144-event cadence would otherwise let one batch
 * grow the WAL far past the steady-state bound. The replay poll (every 256
 * events) stats the -wal and commits once it reaches this. Larger than the
 * steady-state budget so replay keeps most of its fsync saving. */
#define BIP_REPLAY_WAL_BUDGET_BYTES (128 * 1024ull * 1024ull)
/* Prior WAL bytes per log byte before the first commit reports a measure
 * (a 1.5 KiB header row dirties about 3 of the 4 KiB pages of its B-trees;
 * measured 3x). A dirty page set stays in the 256 MiB cache until commit, so
 * the file size alone cannot see a batch growing: the poll projects it. */
#define BIP_REPLAY_WAL_AMP_PRIOR 6.0
#define BIP_WAL_PAGE_BYTES       4096u

/* Page cache for the hash-keyed WITHOUT ROWID block_index B-tree.
 *
 * create_schema() clusters block_index on `hash BLOB PRIMARY KEY ... WITHOUT
 * ROWID` (a B-tree keyed on random bytes), so with SQLite's default ~2 MB
 * page cache every exists_stmt/ins_stmt lookup in catch_up_cb (called from
 * engine/composition/src/boot_projections.c before the BLOCK_INDEX_LOADED
 * stage is recorded) is an uncached random seek. On an HDD that dominates
 * boot time, so apply_pragmas() sizes the cache explicitly.
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
    unsigned       last_bind_threads;   /* threads of the last covered bind */
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
    uint64_t       replay_wal_budget_bytes;   /* replay commit trigger */
    int64_t        last_wal_frames;           /* WAL frames at the last commit, -1 unknown */

    /* Replay cadence (defaults above; tests override on the open handle). */
    uint64_t       commit_events;
    uint64_t       commit_bytes;
    int64_t        commit_ms;
    int64_t        progress_ms;
    uint64_t       progress_pct;
    uint64_t       batches_committed;   /* commits made by catch_up */
    uint64_t       progress_lines;      /* [boot-phase] lines printed */
    /* Test seam, NULL in production: called before each log event is
     * applied with the 1-based event number within this catch_up. */
    void         (*event_hook)(uint64_t event_no);
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
    uint64_t batch_start_offset;   /* cursor at the last commit */
    uint64_t start_offset;         /* cursor when this catch_up began */
    uint64_t total_bytes;          /* log size when this catch_up began */
    uint64_t events_seen;          /* every event delivered, any type */
    int64_t  t_start_ms;
    int64_t  last_commit_ms;
    int64_t  last_report_ms;
    uint64_t last_report_pct;
    atomic_uint_least64_t *scan_ctr; /* boot O(delta) witness (util/boot_scan.h) */
    double   wal_amp;              /* WAL bytes written per log byte, learned per commit */
    bool     error;
};

/* Defined in block_index_projection.c (the catch_up driver owns the
 * transaction boundary + durable counters). */
bool batch_begin(struct catch_up_ctx *c);
bool batch_commit(struct catch_up_ctx *c);
/* Replay cadence + progress (block_index_projection.c). */
void bip_replay_begin(struct catch_up_ctx *c);
void bip_replay_before_event(struct catch_up_ctx *c);
bool bip_replay_after_event(struct catch_up_ctx *c);
bool bip_replay_commit(struct catch_up_ctx *c);
void bip_replay_finish(struct catch_up_ctx *c);
bool block_index_projection_prepare_dirty(struct catch_up_ctx *c);
bool block_index_projection_mark_dirty(struct catch_up_ctx *c,
                                       const uint8_t hash[32]);

/* Defined in block_index_projection_status.c — the EV_BLOCK_STATUS consumer.
 * See its doc comment for the full contract. */
bool catch_up_apply_status(struct catch_up_ctx *c, const void *payload,
                           size_t len);

#endif /* ZCL_STORAGE_BLOCK_INDEX_PROJECTION_INTERNAL_H */
