/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * node_db_import_internal.h — shared declarations across the files that
 * make up the parallel LevelDB → SQLite UTXO import service:
 *
 *   node_db_import_service.c  — public entry node_db_import_service_run:
 *                               wipe gate, pipeline orchestration, the
 *                               single-threaded LevelDB reader loop
 *   node_db_import_pipeline.c — the decoder + writer worker threads that
 *                               drain the chunk ring
 *
 * NOT a public header. Only included by the two files above. The chunk
 * ring (struct import_chunk[IMPORT_NUM_CHUNKS]) is the handoff surface:
 * reader fills (state 0→1), decoders decode (1→2), the writer inserts and
 * recycles (2→0); a worker claims a chunk by CAS-ing its state to -1. */

#ifndef ZCL_NODE_DB_IMPORT_INTERNAL_H
#define ZCL_NODE_DB_IMPORT_INTERNAL_H

#include "services/utxo_import_pipeline.h"

#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>

struct coins_view_db;
struct node_db;

extern volatile sig_atomic_t g_shutdown_requested;

/* Controller-private job-status setter (sync_controller.c) the writer
 * thread and the orchestrator both report progress through. */
void sync_job_import_progress(int total_rows);

/* A chunk of raw LevelDB entries for decode workers */
#define IMPORT_CHUNK_ENTRIES 2048
/* Max outputs per chunk. Must be large enough to hold all outputs from
 * 2048 entries. Worst case: 2048 entries * 468 outputs = 958,464.
 * In practice ~5500 rows per chunk. Use 32768 for 4x safety margin. */
#define IMPORT_MAX_ROWS_PER_CHUNK 32768

struct import_chunk {
    struct utxo_import_raw_entry entries[IMPORT_CHUNK_ENTRIES];
    int num_entries;
    struct utxo_import_row rows[IMPORT_MAX_ROWS_PER_CHUNK];
    int num_rows;
    _Atomic int state; /* 0=free, 1=filled, 2=decoded, -1=claimed */
};

#define IMPORT_NUM_CHUNKS 64

struct import_context {
    struct import_chunk chunks[IMPORT_NUM_CHUNKS];
    _Atomic int total_txids;
    _Atomic int total_rows;
    _Atomic int decode_failures;
    _Atomic int skipped_outputs;
    _Atomic bool cancel_requested;
    _Atomic bool reader_done;
    _Atomic bool decoders_done;
    /* Set true by the reader if db_iter_check_error reports a LevelDB
     * iterator error (CRC / missing SST / mid-scan I/O). A set flag means the
     * iterated range is TRUNCATED, so the whole import MUST be rejected —
     * never accepted as a complete UTXO set. */
    _Atomic bool iter_error;
    _Atomic int chunks_produced;  /* total chunks filled by reader */
    _Atomic int chunks_consumed;  /* total chunks written by writer */
    /* LevelDB reader state (single-threaded) */
    struct coins_view_db *cvdb;
    /* Writer state */
    struct node_db *ndb;
    int write_next; /* next chunk index to write (in-order) */
};

static inline bool import_ctx_should_stop(const struct import_context *ctx)
{
    return (ctx && atomic_load(&ctx->cancel_requested)) || g_shutdown_requested;
}

static inline void import_ctx_request_stop(struct import_context *ctx)
{
    if (!ctx)
        return;
    atomic_store(&ctx->cancel_requested, true);
}

static inline void import_chunk_reset(struct import_chunk *chunk)
{
    if (!chunk)
        return;
    for (int ei = 0; ei < chunk->num_entries; ei++)
        free(chunk->entries[ei].value);
    for (int ri = 0; ri < chunk->num_rows; ri++)
        free(chunk->rows[ri].script_overflow);
    chunk->num_entries = 0;
    chunk->num_rows = 0;
    atomic_store(&chunk->state, 0);
}

/* Worker thread entry points (node_db_import_pipeline.c); arg is the
 * shared struct import_context. Decoders claim filled chunks and decode
 * them; the single writer bulk-inserts decoded chunks into the utxos
 * table inside ~100K-row transactions. */
void *node_db_import_decoder_thread(void *arg);
void *node_db_import_writer_thread(void *arg);

#endif /* ZCL_NODE_DB_IMPORT_INTERNAL_H */
