/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* node_db_import_service: parallel LevelDB → SQLite UTXO import.
 *
 * Reader thread feeds a ring buffer; N decoder threads deserialize
 * coins-format entries; a single writer thread bulk-inserts into the
 * utxos table.
 *
 * node_db_sync_import_utxos's orchestration. It is consensus-adjacent
 * (§3 coins-wedge recovery surface): the import-write path — what rows land
 * in the UTXO set — is byte-identical across callers.
 * Only the failure SIGNAL changed: this Service returns struct zcl_result
 * (Law 2) instead of a bare int; the thin controller wrapper maps it back to
 * the legacy `rows-or--1` int so every caller sees the same value as before.
 * // supervisor-ok:bounded-import-pipeline — the decoder/writer threads are a
 * one-shot pool pthread_join'd before return (import_job_join_*), so the join
 * is the liveness; a supervisor contract would be meaningless here. */

#include "services/node_db_import_service.h"

#include "node_db_import_internal.h"
#include "platform/logical_cpu.h"
#include "platform/time_compat.h"
#include "services/recovery_policy.h"
#include "services/utxo_import_pipeline.h"
#include "models/database.h"
#include "models/db_txn.h"
#include "models/utxo.h"
#include "storage/dbwrapper.h"
#include "storage/coins_db.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <signal.h>

/* db_iter_check_error is declared in storage/dbwrapper.h (included above) and
 * now returns bool (true = clean scan, false = LevelDB iterator error). */

/* ── Controller-private symbols this Service forward-declares ──────────
 * The job-status setters + turbo-mode scope are external-linkage functions
 * defined in app/controllers/src/sync_controller.c, declared only in the
 * controller-private sync_controller_internal.h (not includable from
 * app/services/src/). Forward-declared here to match their definitions, so
 * the relocation stays self-contained without injection. */
struct sync_db_turbo_scope {
    struct node_db *ndb;
    bool entered;
};

bool sync_db_turbo_scope_begin(struct sync_db_turbo_scope *scope,
                               struct node_db *ndb,
                               bool enabled);
bool sync_db_turbo_scope_end(struct sync_db_turbo_scope *scope);

void sync_job_import_begin(void);
void sync_job_import_finish(int total_rows);

/* Chunk-ring structs, constants, ctx helpers and the worker-thread entry
 * points live in node_db_import_internal.h / node_db_import_pipeline.c. */

struct import_job {
    struct import_context *ctx;
    pthread_t decoders[UTXO_IMPORT_NUM_DECODERS_MAX];
    int num_decoders;
    int decoder_threads_started;
    pthread_t writer_thread;
    bool writer_thread_started;
};

static void import_job_join_decoders(struct import_job *job);

static void import_context_release_chunks(struct import_context *ctx)
{
    if (!ctx)
        return;
    for (int i = 0; i < IMPORT_NUM_CHUNKS; i++)
        import_chunk_reset(&ctx->chunks[i]);
}

static void import_job_init(struct import_job *job,
                            struct import_context *ctx,
                            int num_decoders)
{
    if (!job)
        return;
    memset(job, 0, sizeof(*job));
    job->ctx = ctx;
    job->num_decoders = num_decoders;
}

static bool import_job_start_decoders(struct import_job *job)
{
    if (!job || !job->ctx)
        LOG_FAIL("sync", "import_start_decoders: invalid args (job=%p)", (void *)job);

    for (int i = 0; i < job->num_decoders; i++) {
        int rc = thread_registry_spawn("zcl_utxo_dec",
                                           node_db_import_decoder_thread,
                                           job->ctx, &job->decoders[i]);
        if (rc != 0) {
            LOG_WARN("sync", "UTXO import: thread_registry_spawn decoder[%d] failed: %d", i, rc);
            import_ctx_request_stop(job->ctx);
            import_job_join_decoders(job);
            return false;
        }
        job->decoder_threads_started++;
    }
    return job->decoder_threads_started > 0;
}

static bool import_job_start_writer(struct import_job *job)
{
    if (!job || !job->ctx)
        LOG_FAIL("sync", "import_start_writer: invalid args (job=%p)", (void *)job);
    if (thread_registry_spawn("zcl_utxo_wr",
                                  node_db_import_writer_thread, job->ctx,
                                  &job->writer_thread) != 0) {
        fprintf(stderr, "UTXO import: FATAL — writer thread failed to start\n");
        import_ctx_request_stop(job->ctx);
        return false;
    }
    job->writer_thread_started = true;
    return true;
}

static void import_job_join_decoders(struct import_job *job)
{
    if (!job)
        return;
    for (int i = 0; i < job->decoder_threads_started; i++)
        pthread_join(job->decoders[i], NULL);
    job->decoder_threads_started = 0;
}

static void import_job_join_writer(struct import_job *job)
{
    if (!job || !job->writer_thread_started)
        return;
    pthread_join(job->writer_thread, NULL);
    job->writer_thread_started = false;
}

static bool import_job_start(struct import_job *job)
{
    if (!import_job_start_decoders(job))
        LOG_FAIL("sync", "import_job_start: decoders failed to start");
    if (!import_job_start_writer(job)) {
        if (job && job->ctx)
            atomic_store(&job->ctx->reader_done, true);
        import_job_join_decoders(job);
        LOG_FAIL("sync", "import_job_start: writer failed to start");
    }
    return true;
}

struct zcl_result node_db_import_service_run(struct node_db *ndb,
                                             struct coins_view_db *cvdb,
                                             int *out_rows)
{
    struct import_job job;
    struct sync_db_turbo_scope turbo_mode = {0};
    bool restore_ok = true;

    if (!ndb || !ndb->open || !cvdb)
        return ZCL_ERR(-10, "import_utxos: invalid args (ndb=%p, cvdb=%p)",
                       (void *)ndb, (void *)cvdb);
    sync_job_import_begin();

    int num_decoders = utxo_import_num_decoders();
    printf("UTXO import: parallel pipeline (%d decoders, %d chunks, %u cores)...\n",
           num_decoders, IMPORT_NUM_CHUNKS, platform_logical_cpu_count());
    fflush(stdout);

    struct timespec ts_start;
    platform_time_monotonic_timespec(&ts_start);

    /* ── SQLite turbo mode — delegate to node_db layer ────────────── */
    if (!sync_db_turbo_scope_begin(&turbo_mode, ndb, true)) {
        fprintf(stderr, "UTXO import: failed to enter turbo mode\n");
        sync_job_import_finish(0);
        return ZCL_ERR(-1, "import: failed to enter SQLite turbo mode");
    }

    /* ── Recovery policy gate + scoped wipe ────────────────────────
     * The wipe below is a reimport prelude, not a reorg rollback — in
     * normal operation the table is empty or nearly empty. It
     * shares a primitive with every other destructive UTXO path, so it is
     * gated the same way: ask the policy, refuse if over cap, abort cleanly.
     * The cap is deliberately generous here (reimport is legitimate)
     * but an operator can still raise ZCL_MAX_UTXO_WIPE_ROWS if a
     * partial import is being resumed.
     *
     * The DELETE + initial state are wrapped in a DB_TXN_SCOPE so a
     * mid-wipe crash or early-return rolls back cleanly: the pipeline
     * below starts from a fully-wiped-and-committed table, not a
     * half-deleted one. */
    /* Skip the wipe if the table is already empty — the caller
     * (utxo_recovery_import_ldb) already wiped via the
     * "boot.ldb_import_prepare" wipe in utxo_recovery_restore.c.
     * This was the third redundant wipe that destroyed data. */
    int64_t existing = node_db_utxo_count(ndb);
    if (existing < 0) existing = 0;

    if (existing > 0) {
        struct recovery_policy rp;
        policy_load_from_env(&rp);
        enum policy_decision pd = policy_check_utxo_wipe(
            &rp, existing, "sync_controller.import_utxos_reimport");
        if (pd != POLICY_ALLOW) {
            LOG_INFO("sync", "UTXO import: recovery_policy refused wipe (code=%s, rows=%lld)", policy_decision_name(pd), (long long)existing);
            if (!sync_db_turbo_scope_end(&turbo_mode))
                fprintf(stderr, "UTXO import: failed to restore normal mode after policy refusal\n");
            sync_job_import_finish(0);
            return ZCL_ERR(-2, "import: recovery_policy refused utxo wipe "
                           "(existing_rows=%lld)", (long long)existing);
        }

        {
            DB_TXN_SCOPE(txn, ndb, "sync_controller.import_utxos_reimport");
            if (!txn) {
                LOG_WARN("sync", "UTXO import: failed to open db_txn for wipe");
                if (!sync_db_turbo_scope_end(&turbo_mode))
                    fprintf(stderr, "UTXO import: failed to restore normal mode after db_txn failure\n");
                sync_job_import_finish(0);
                return ZCL_ERR(-3, "import: failed to open db_txn for "
                               "utxo wipe");
            }
            if (!node_db_wipe_utxos(ndb)) {
                LOG_WARN("sync", "UTXO import: failed to wipe utxos table");
                /* leave scope → auto-rollback */
                if (!sync_db_turbo_scope_end(&turbo_mode))
                    fprintf(stderr, "UTXO import: failed to restore normal mode after wipe failure\n");
                sync_job_import_finish(0);
                return ZCL_ERR(-4, "import: failed to wipe utxos table");
            }
            if (!db_txn_commit(txn)) {
                LOG_WARN("sync", "UTXO import: commit of wipe failed");
                if (!sync_db_turbo_scope_end(&turbo_mode))
                    fprintf(stderr, "UTXO import: failed to restore normal mode after commit failure\n");
                sync_job_import_finish(0);
                return ZCL_ERR(-5, "import: commit of utxo wipe failed");
            }
        }
    }

    /* ── Initialize pipeline context ───────────────────────────────── */
    struct import_context *ctx = zcl_calloc(1, sizeof(struct import_context), "import context");
    if (!ctx) {
        if (!sync_db_turbo_scope_end(&turbo_mode))
            fprintf(stderr, "UTXO import: failed to restore normal mode after alloc failure\n");
        sync_job_import_finish(0);
        return ZCL_ERR(-6, "import: failed to allocate import context");
    }
    ctx->cvdb = cvdb;
    ctx->ndb = ndb;
    atomic_store(&ctx->cancel_requested, false);
    atomic_store(&ctx->reader_done, false);
    atomic_store(&ctx->decoders_done, false);
    for (int i = 0; i < IMPORT_NUM_CHUNKS; i++)
        atomic_store(&ctx->chunks[i].state, 0);
    import_job_init(&job, ctx, num_decoders);

    /* ── Start decoder + writer threads ────────────────────────────── */
    if (!import_job_start(&job)) {
        LOG_WARN("sync", "UTXO import: FATAL — worker pipeline failed to start");
        import_context_release_chunks(ctx);
        if (!sync_db_turbo_scope_end(&turbo_mode))
            LOG_WARN("sync", "UTXO import: failed to restore normal mode after worker startup failure");
        free(ctx);
        sync_job_import_finish(0);
        return ZCL_ERR(-7, "import: worker pipeline failed to start");
    }

    /* ── Reader (main thread): iterate LevelDB, fill chunks ────────── */
    /* Take a LevelDB snapshot so the iterator sees a consistent,
     * frozen view even if zclassicd is writing concurrently.
     * This prevents the random UTXO gaps caused by non-atomic reads. */
    db_wrapper_snapshot_begin(&cvdb->db);

    struct db_iterator it;
    db_iter_init(&it, &cvdb->db);
    char seek_key[33];
    seek_key[0] = 'c';
    memset(seek_key + 1, 0, 32);
    db_iter_seek(&it, seek_key, 33);

    int chunk_idx = 0;
    int total_entries = 0;
    int skipped_entries = 0;

    while (db_iter_valid(&it)) {
        if (import_ctx_should_stop(ctx))
            break;
        /* Find a free chunk */
        struct import_chunk *chunk = NULL;
        while (!chunk) {
            if (import_ctx_should_stop(ctx))
                goto reader_done;
            for (int i = 0; i < IMPORT_NUM_CHUNKS; i++) {
                int idx = (chunk_idx + i) % IMPORT_NUM_CHUNKS;
                int expected = 0;
                if (atomic_compare_exchange_strong(&ctx->chunks[idx].state,
                                                  &expected, -1)) {
                    chunk = &ctx->chunks[idx];
                    chunk_idx = (idx + 1) % IMPORT_NUM_CHUNKS;
                    break;
                }
            }
            if (!chunk) {
                struct timespec ts = {0, 50000}; /* 50μs */
                nanosleep(&ts, NULL);
            }
        }

        /* Fill chunk with raw entries from LevelDB */
        chunk->num_entries = 0;
        chunk->num_rows = 0;

        bool end_of_range = false;
        while (chunk->num_entries < IMPORT_CHUNK_ENTRIES &&
               db_iter_valid(&it)) {
            if (import_ctx_should_stop(ctx))
                goto reader_done;
            size_t key_len;
            const char *key_data = db_iter_key(&it, &key_len);
            if (key_len < 1 || key_data[0] != 'c') {
                /* Coins range ended: publish the in-fill chunk first —
                 * a goto here dropped the last ~1500 records (tail). */
                end_of_range = true;
                break;
            }
            if (key_len < 33) { db_iter_next(&it); continue; }

            struct utxo_import_raw_entry *e =
                &chunk->entries[chunk->num_entries];
            memcpy(e->txid, key_data + 1, 32);

            size_t val_len;
            const char *val_data = db_iter_value(&it, &val_len);
            uint32_t checked_len = 0;
            /* Replay-gated follow-up: older import code truncated CCoins
             * values through a 65535-byte length path.  This branch already
             * rejects only above the explicit 4 MiB cap and copies byte-for-
             * byte into a uint32_t-sized buffer.  Do not reintroduce or tighten
             * that boundary without full-history replay against real
             * chainstate. */
            struct zcl_result len_ok =
                utxo_import_value_len_checked(val_len, &checked_len);
            if (!len_ok.ok) {
                LOG_WARN("sync",
                         "UTXO import: rejecting LevelDB CCoins value after "
                         "%d txids: %s", total_entries, len_ok.message);
                atomic_store(&ctx->iter_error, true);
                import_ctx_request_stop(ctx);
                goto reader_done;
            }

            e->value = zcl_malloc(checked_len, "import entry value");
            if (e->value) {
                memcpy(e->value, val_data, checked_len);
                /* db_iter_value() already deobfuscates values using the
                 * obfuscation key (dbwrapper.c:370-372). Do NOT XOR
                 * again here — that would undo the deobfuscation. */
                e->value_len = checked_len;
                chunk->num_entries++;
                total_entries++;
            } else {
                LOG_WARN("sync",
                         "malloc failed for chunk entry value (%u bytes), "
                         "skipping entry", checked_len);
                skipped_entries++;
            }
            db_iter_next(&it);
        }

        if (chunk->num_entries > 0) {
            atomic_fetch_add(&ctx->chunks_produced, 1);
            atomic_thread_fence(memory_order_release);
            atomic_store(&chunk->state, 1); /* filled → decoders */
        } else {
            atomic_store(&chunk->state, 0); /* empty, release */
        }
        if (end_of_range)
            break;
    }
reader_done:
    /* Checksum failures (block-level CRC), a missing/torn SST, or any I/O
     * error can end iteration early, dropping entries — silently truncating
     * the UTXO set. Surface the iterator status and, on error, record it +
     * request stop so the writer/decoders wind down. We do NOT accept the
     * imported prefix: the post-join gate below converts this to a hard
     * ZCL_ERR return instead of a silently-short "complete" set. */
    if (!db_iter_check_error(&it)) {
        LOG_WARN("sync", "UTXO import: LevelDB iterator error mid-scan after "
                 "%d txids — set is TRUNCATED, rejecting import",
                 total_entries);
        atomic_store(&ctx->iter_error, true);
        import_ctx_request_stop(ctx);
    }
    db_iter_free(&it);
    db_wrapper_snapshot_end(&cvdb->db);
    atomic_store(&ctx->reader_done, true);

    printf("UTXO import: read %d txids from LevelDB (%d skipped)\n",
           total_entries, skipped_entries);
    fflush(stdout);

    /* ── Wait for decoders ────────────────────────────────────────── */
    import_job_join_decoders(&job);

    /* ── Wait for ALL chunks to be consumed by writer ──────────── */
    /* After decoders finish, remaining chunks are in state 2 (decoded).
     * We MUST wait for the writer to consume them ALL before signaling
     * decoders_done. Otherwise the writer sees decoders_done=true, does
     * a quick scan, misses state=2 chunks due to timing, and exits
     * early — dropping the last ~219 txids / ~520 UTXOs. */
    for (;;) {
        if (import_ctx_should_stop(ctx))
            break;
        bool any_pending = false;
        for (int i = 0; i < IMPORT_NUM_CHUNKS; i++) {
            int s = atomic_load_explicit(&ctx->chunks[i].state,
                                          memory_order_acquire);
            if (s == 1 || s == 2) { any_pending = true; break; }
        }
        if (!any_pending) break;
        struct timespec ts = {0, 1000000}; /* 1ms */
        nanosleep(&ts, NULL);
    }
    atomic_store(&ctx->decoders_done, true);

    /* ── Wait for writer ───────────────────────────────────────────── */
    import_job_join_writer(&job);
    int total_rows = atomic_load(&ctx->total_rows);
    sync_job_import_progress(total_rows);
    int decode_fail = atomic_load(&ctx->decode_failures);
    int skip_out = atomic_load(&ctx->skipped_outputs);
    if (decode_fail > 0 || skip_out > 0)
        printf("UTXO import: %d decode failures, %d skipped outputs\n",
               decode_fail, skip_out);

    /* Validation: verify all txids made it to SQLite */
    {
        int64_t sql_rows = 0;
        int64_t sql_txids = 0;
        if (db_utxo_count_rows_and_distinct_txids(ndb, &sql_rows,
                                                  &sql_txids)) {
            if (sql_rows != total_rows) {
                /* Row count mismatch = real data loss — pipeline bug */
                LOG_WARN("sync", "UTXO IMPORT ERROR: wrote %d rows but " "SQLite has %lld rows — data loss!", total_rows, (long long)sql_rows);
            } else if (sql_txids < total_entries) {
                /* Fewer distinct txids is expected: fully-pruned CCoins
                 * (all outputs spent) produce zero rows per txid.
                 * These exist in LevelDB as tombstones until compaction. */
                int pruned = total_entries - (int)sql_txids;
                printf("UTXO import: %d/%d LevelDB entries were "
                       "fully-pruned (all outputs spent)\n",
                       pruned, total_entries);
            }
        }
    }
    fflush(stdout);

    struct timespec ts_write;
    platform_time_monotonic_timespec(&ts_write);
    double pipe_ms = (ts_write.tv_sec - ts_start.tv_sec) * 1000.0 +
                     (ts_write.tv_nsec - ts_start.tv_nsec) / 1e6;
    printf("UTXO import: %d rows written in %.0fms\n", total_rows, pipe_ms);
    fflush(stdout);

    /* HARD-HALT on a torn/short read: if the reader hit a LevelDB iterator
     * error mid-scan, the iterated range is truncated and the imported rows
     * are NOT a complete UTXO set. Reject the import outright — never let a
     * silently-short prefix be accepted as authoritative. This gate precedes
     * the generic should_stop gate so the failure is named precisely (the
     * reader also requested stop, so should_stop would otherwise fire with a
     * misleading "aborted on shutdown" message). */
    if (atomic_load(&ctx->iter_error)) {
        /* LOG_WARN (not LOG_FAIL) — LOG_FAIL would `return false`, but this
         * function returns struct zcl_result and must clean up first. The
         * named ZCL_ERR below carries the failure context to the caller. */
        LOG_WARN("sync", "UTXO import: REJECTED — LevelDB iterator error left a "
                 "TRUNCATED set (%d txids, %d rows read before the error); "
                 "refusing to accept a partial UTXO set", total_entries,
                 total_rows);
        if (!sync_db_turbo_scope_end(&turbo_mode))
            LOG_WARN("sync", "UTXO import: failed to restore normal mode after iterator-error reject");
        restore_ok = false;
        import_context_release_chunks(ctx);
        free(ctx);
        sync_job_import_finish(total_rows);
        return ZCL_ERR(-10, "import: REJECTED — LevelDB iterator error left a "
                       "truncated UTXO set (%d txids read before error)",
                       total_entries);
    }

    if (import_ctx_should_stop(ctx)) {
        LOG_WARN("sync", "UTXO import: aborted%s", g_shutdown_requested ? " on shutdown" : "");
        if (!sync_db_turbo_scope_end(&turbo_mode))
            LOG_WARN("sync", "UTXO import: failed to restore normal mode after abort");
        restore_ok = false;
        import_context_release_chunks(ctx);
        free(ctx);
        sync_job_import_finish(total_rows);
        return ZCL_ERR(-8, "import: aborted%s",
                       g_shutdown_requested ? " on shutdown" : "");
    }

    /* ── Rebuild all indexes for power-node queries ────────────────── */
    printf("UTXO import: building indexes for fast queries...\n");
    fflush(stdout);

    struct timespec ts_idx;
    platform_time_monotonic_timespec(&ts_idx);

    /* Rebuild indexes and restore safe pragmas */
    if (!sync_db_turbo_scope_end(&turbo_mode)) {
        restore_ok = false;
        LOG_WARN("sync", "UTXO import: failed to restore normal mode");
    }
    if (!restore_ok) {
        import_context_release_chunks(ctx);
        free(ctx);
        sync_job_import_finish(total_rows);
        return ZCL_ERR(-9, "import: failed to restore normal db mode "
                       "after index build");
    }

    struct timespec ts_idx_done;
    platform_time_monotonic_timespec(&ts_idx_done);
    double idx_ms = (ts_idx_done.tv_sec - ts_idx.tv_sec) * 1000.0 +
                    (ts_idx_done.tv_nsec - ts_idx.tv_nsec) / 1e6;
    printf("UTXO import: indexes built in %.0fms\n", idx_ms);

    double total_ms = (ts_idx_done.tv_sec - ts_start.tv_sec) * 1000.0 +
                      (ts_idx_done.tv_nsec - ts_start.tv_nsec) / 1e6;
    printf("UTXO import complete: %d outputs from %d txids in %.1fs "
           "(pipeline %.0fms + index %.0fms)\n",
           total_rows, total_entries, total_ms / 1000.0,
           pipe_ms, idx_ms);
    fflush(stdout);

    import_context_release_chunks(ctx);
    free(ctx);
    sync_job_import_finish(total_rows);
    if (out_rows)
        *out_rows = total_rows;
    return ZCL_OK;
}
