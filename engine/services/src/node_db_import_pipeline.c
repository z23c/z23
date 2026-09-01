/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */
// one-result-type-ok:pthread-entry-points-report-through-ctx-atomics

/* node_db_import_pipeline: the decoder + writer worker threads of the
 * parallel LevelDB → SQLite UTXO import (see node_db_import_internal.h
 * for the chunk-ring handoff protocol and node_db_import_service.c for
 * the orchestrator + reader loop that feeds them).
 * // supervisor-ok:bounded-import-pipeline — one-shot pool, pthread_join'd
 * by the orchestrator before it returns; the join is the liveness. */

#include "node_db_import_internal.h"

#include "models/database.h"
#include "models/utxo.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <time.h>

/* Decoder worker thread — picks filled chunks, decodes, marks decoded */
void *node_db_import_decoder_thread(void *arg)
{
    struct import_context *ctx = (struct import_context *)arg;

    for (;;) {
        if (import_ctx_should_stop(ctx))
            break;
        /* Find a filled chunk to decode */
        struct import_chunk *chunk = NULL;
        for (int i = 0; i < IMPORT_NUM_CHUNKS; i++) {
            int expected = 1; /* filled */
            if (atomic_compare_exchange_strong(&ctx->chunks[i].state,
                                              &expected, -1)) {
                atomic_thread_fence(memory_order_acquire);
                chunk = &ctx->chunks[i];
                break;
            }
        }
        if (!chunk) {
            if (atomic_load(&ctx->reader_done)) {
                /* Check once more for any remaining chunks */
                bool found = false;
                for (int i = 0; i < IMPORT_NUM_CHUNKS; i++) {
                    if (atomic_load(&ctx->chunks[i].state) == 1) {
                        found = true;
                        break;
                    }
                }
                if (!found) break;
            }
            /* Yield briefly — spin is fine on 32 cores */
            struct timespec ts = {0, 100000}; /* 100μs */
            nanosleep(&ts, NULL);
            continue;
        }

        if (import_ctx_should_stop(ctx)) {
            import_chunk_reset(chunk);
            break;
        }

        /* Decode all entries in this chunk */
        chunk->num_rows = 0;
        int skipped_in_chunk = 0;
        for (int i = 0; i < chunk->num_entries; i++) {
            if (import_ctx_should_stop(ctx))
                break;
            int space = IMPORT_MAX_ROWS_PER_CHUNK - chunk->num_rows;
            if (space <= 0) { skipped_in_chunk += chunk->num_entries - i; break; }
            int n = utxo_import_decode_entry(&chunk->entries[i],
                                             &chunk->rows[chunk->num_rows],
                                             space);
            if (n == 0) {
                atomic_fetch_add(&ctx->decode_failures, 1);
            }
            chunk->num_rows += n;
        }
        if (skipped_in_chunk > 0) {
            atomic_fetch_add(&ctx->skipped_outputs, skipped_in_chunk);
            LOG_WARN("sync", "UTXO import: chunk overflow! %d entries skipped " "(rows=%d, max=%d)", skipped_in_chunk, chunk->num_rows, IMPORT_MAX_ROWS_PER_CHUNK);
        }

        if (import_ctx_should_stop(ctx))
            import_chunk_reset(chunk);
        else
            atomic_store(&chunk->state, 2); /* decoded */
    }
    return NULL;
}

/* Writer thread — consumes decoded chunks, inserts into SQLite */
void *node_db_import_writer_thread(void *arg)
{
    struct import_context *ctx = (struct import_context *)arg;
    if (!ctx) LOG_NULL("sync", "import_writer_thread: ctx is NULL");
    struct node_db *ndb = ctx->ndb;
    if (!ndb || !ndb->open || !ndb->stmt_utxo_insert) {
        LOG_WARN("sync", "UTXO import writer: invalid node_db statement/db state");
        import_ctx_request_stop(ctx);
        return NULL;
    }
    sqlite3_stmt *ins = ndb->stmt_utxo_insert;
    int total_rows = 0;
    int next_chunk = 0;

    if (!node_db_begin(ndb)) {
        LOG_WARN("sync", "UTXO import writer: BEGIN failed");
        import_ctx_request_stop(ctx);
    }

    for (;;) {
        if (import_ctx_should_stop(ctx))
            break;
        /* Look for any decoded chunk to write */
        struct import_chunk *chunk = NULL;
        for (int i = 0; i < IMPORT_NUM_CHUNKS; i++) {
            int idx = (next_chunk + i) % IMPORT_NUM_CHUNKS;
            int expected = 2; /* decoded */
            if (atomic_compare_exchange_strong(&ctx->chunks[idx].state,
                                              &expected, -1)) {
                chunk = &ctx->chunks[idx];
                next_chunk = (idx + 1) % IMPORT_NUM_CHUNKS;
                break;
            }
        }
        if (!chunk) {
            if (atomic_load(&ctx->decoders_done)) {
                /* Decoders are done. Use definitive chunk count to
                 * know when we're truly finished — no race possible. */
                int produced = atomic_load(&ctx->chunks_produced);
                int consumed = atomic_load(&ctx->chunks_consumed);
                if (consumed >= produced) break;
                /* Still have chunks to consume — scan harder */
                atomic_thread_fence(memory_order_seq_cst);
            }
            struct timespec ts = {0, 100000}; /* 100μs */
            nanosleep(&ts, NULL);
            continue;
        }

        if (import_ctx_should_stop(ctx)) {
            import_chunk_reset(chunk);
            break;
        }

        /* Insert all rows from this chunk */
        for (int ri = 0; ri < chunk->num_rows; ri++) {
            if (import_ctx_should_stop(ctx))
                break;
            struct utxo_import_row *r = &chunk->rows[ri];
            const uint8_t *sc = r->script_overflow ?
                                r->script_overflow : r->script;
            bool row_ok = true;

            row_ok &= utxo_import_writer_bind_checked(ins, "sqlite3_reset",
                                                      sqlite3_reset(ins),
                                                      ndb, total_rows).ok;
            row_ok &= utxo_import_writer_bind_checked(ins,
                "sqlite3_bind_blob(txid)",
                sqlite3_bind_blob(ins, 1, r->txid, 32, SQLITE_STATIC),
                ndb, total_rows).ok;
            row_ok &= utxo_import_writer_bind_checked(ins,
                "sqlite3_bind_int(vout)",
                sqlite3_bind_int(ins, 2, (int)r->vout), ndb, total_rows).ok;
            row_ok &= utxo_import_writer_bind_checked(ins,
                "sqlite3_bind_int64(value)",
                sqlite3_bind_int64(ins, 3, r->value), ndb, total_rows).ok;
            row_ok &= utxo_import_writer_bind_checked(ins,
                "sqlite3_bind_blob(script)",
                sqlite3_bind_blob(ins, 4, sc, (int)r->script_len,
                                  SQLITE_STATIC), ndb, total_rows).ok;
            row_ok &= utxo_import_writer_bind_checked(ins,
                "sqlite3_bind_int(script_type)",
                sqlite3_bind_int(ins, 5, r->script_type), ndb,
                total_rows).ok;
            if (r->has_address)
                row_ok &= utxo_import_writer_bind_checked(ins,
                    "sqlite3_bind_blob(address_hash)",
                    sqlite3_bind_blob(ins, 6, r->address_hash, 20,
                                      SQLITE_STATIC), ndb, total_rows).ok;
            else
                row_ok &= utxo_import_writer_bind_checked(ins,
                    "sqlite3_bind_null(address_hash)",
                    sqlite3_bind_null(ins, 6), ndb, total_rows).ok;
            row_ok &= utxo_import_writer_bind_checked(ins,
                "sqlite3_bind_int(height)",
                sqlite3_bind_int(ins, 7, r->height), ndb, total_rows).ok;
            row_ok &= utxo_import_writer_bind_checked(ins,
                "sqlite3_bind_int(is_coinbase)",
                sqlite3_bind_int(ins, 8, r->is_coinbase), ndb,
                total_rows).ok;
            row_ok &= utxo_import_writer_step_checked(ins, ndb,
                                                      total_rows).ok;
            if (!row_ok) {
                import_ctx_request_stop(ctx);
                break;
            }
            total_rows++;
        }

        if (import_ctx_should_stop(ctx)) {
            import_chunk_reset(chunk);
            break;
        }

        /* Commit every ~100K rows */
        if (total_rows % 100000 < chunk->num_rows) {
            if (!node_db_commit(ndb)) {
                LOG_WARN("sync", "UTXO import writer: COMMIT failed");
                if (!node_db_rollback(ndb))
                    LOG_WARN("sync", "UTXO import writer: ROLLBACK failed after commit failure");
                import_ctx_request_stop(ctx);
                import_chunk_reset(chunk);
                break;
            }
            sync_job_import_progress(total_rows);
            printf("UTXO import: %d rows written...\n", total_rows);
            fflush(stdout);
            if (!node_db_begin(ndb)) {
                LOG_WARN("sync", "UTXO import writer: BEGIN restart failed");
                if (!node_db_rollback(ndb))
                    LOG_WARN("sync", "UTXO import writer: rollback after BEGIN restart failure failed");
                import_ctx_request_stop(ctx);
                import_chunk_reset(chunk);
                break;
            }
        }

        /* Free buffers and release chunk */
        for (int ei = 0; ei < chunk->num_entries; ei++) {
            free(chunk->entries[ei].value);
            chunk->entries[ei].value = NULL;
        }
        for (int ri = 0; ri < chunk->num_rows; ri++) {
            free(chunk->rows[ri].script_overflow);
            chunk->rows[ri].script_overflow = NULL;
        }
        chunk->num_entries = 0;
        chunk->num_rows = 0;
        atomic_fetch_add(&ctx->chunks_consumed, 1);
        atomic_store(&chunk->state, 0); /* free for reuse */
    }

    if (!import_ctx_should_stop(ctx)) {
        if (!node_db_commit(ndb))
            LOG_WARN("sync", "UTXO import writer: final COMMIT failed");
    } else {
        if (!node_db_rollback(ndb))
            LOG_WARN("sync", "UTXO import writer: rollback requested by stop flag failed");
    }
    sync_job_import_progress(total_rows);
    atomic_store(&ctx->total_rows, total_rows);
    return NULL;
}
