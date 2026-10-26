/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * legacy_import_service — Service-grade orchestration for importing wallet
 * data from a legacy (C++) ZClassic node's raw block files.
 *
 * This is the orchestration core for the legacy block-file import. It is
 * Service/Job-grade work — a multi-pass mmap block-file scan plus a Sapling
 * trial-decryption walk that drives a multi-threaded import loop — so it
 * lives in the Service shape. The legacy_import Controller
 * (engine/controllers/src/legacy_import.c) is a thin shim that validates
 * arguments and delegates to legacy_import_service_run().
 *
 * No LevelDB, no chain index, no RPC. Reads block files directly:
 *   Pass 1: parallel mmap raw byte scan for P2PKH/P2SH wallet patterns
 *   Pass 2: walk matched files, deserialize blocks, extract transparent txns
 *   Pass 3: parallel filter + serial trial decryption for Sapling notes
 *
 * The legacy node should be stopped to avoid partial block reads.
 *
 * RECOVERY-PRIMITIVE NOTE: this path is the live cold-import / legacy-attach
 * recovery primitive. Do NOT alter the import logic — the cold-import /
 * legacy-attach byte format is a stable contract. */

// one-result-type-ok:legacy-import-int-contract
/* legacy_import_service_run keeps the legacy_import() int contract
 * (>=0 imported count, <0 on failure) that boot.c + the snapshot/wallet
 * controllers already consume; converting it to struct zcl_result would
 * ripple through that stable public API for no behavior gain. */

#include "platform/time_compat.h"
#include "platform/positioned_file.h"
#include "platform/read_mapping.h"
#include "services/legacy_import_service.h"
#include "models/wallet_tx.h"
#include "wallet/wallet.h"
#include "wallet/sapling_keys.h"
#include "primitives/block.h"
#include "core/serialize.h"
#include "core/amount.h" /* COIN — balance display, avoids a Service->View dep */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "services/scan_util.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"

/* The scan worker contract (struct layouts + thread entry points) is a
 * private header shared with the scan worker TU
 * (engine/controllers/src/legacy_import_scan.c). It is not on the public include
 * path, so it is referenced relatively. The orchestrator needs the full
 * struct definitions (sizeof + field access), not just forward declarations. */
#include "../../controllers/src/legacy_import_scan.h"

static bool legacy_import_begin_checked(struct node_db *ndb,
                                        const char *label)
{
    if (!ndb || !ndb->open || !node_db_begin(ndb)) {
        LOG_FAIL("legacy_import", "legacy_import: %s failed: %s",
                label, (ndb && ndb->db) ? sqlite3_errmsg(ndb->db)
                                        : "db unavailable");
    }
    return true;
}

static bool legacy_import_commit_checked(struct node_db *ndb,
                                         const char *label)
{
    if (!ndb || !ndb->open || !node_db_commit(ndb)) {
        LOG_FAIL("legacy_import", "legacy_import: %s failed: %s",
                label, (ndb && ndb->db) ? sqlite3_errmsg(ndb->db)
                                        : "db unavailable");
    }
    return true;
}

static bool legacy_import_rollback_checked(struct node_db *ndb,
                                           const char *label)
{
    if (!ndb || !ndb->open || !node_db_rollback(ndb)) {
        LOG_FAIL("legacy_import", "legacy_import: %s failed: %s",
                label, (ndb && ndb->db) ? sqlite3_errmsg(ndb->db)
                                        : "db unavailable");
    }
    return true;
}

static uint8_t *ser_tx(const struct transaction *tx, size_t *len)
{
    struct byte_stream s;
    stream_init(&s, 512);
    transaction_serialize(tx, &s);
    *len = s.size;
    return s.data;
}

static bool legacy_import_snapshot_equal(
    const struct platform_positioned_file_snapshot *a,
    const struct platform_positioned_file_snapshot *b)
{
    return a->size == b->size && a->volume == b->volume &&
           a->file_low == b->file_low && a->file_high == b->file_high &&
           a->modified_seconds == b->modified_seconds &&
           a->modified_nanoseconds == b->modified_nanoseconds &&
           a->changed_seconds == b->changed_seconds &&
           a->changed_nanoseconds == b->changed_nanoseconds;
}

static bool legacy_import_open_block(
    const char *legacy_datadir, int file_number,
    struct platform_positioned_file *file,
    struct platform_positioned_file_snapshot *snapshot)
{
    char blocks[512];
    char leaf[32];
    int blocks_length = snprintf(blocks, sizeof(blocks), "%s/blocks",
                                 legacy_datadir);
    int leaf_length = snprintf(leaf, sizeof(leaf), "blk%05d.dat", file_number);
    return blocks_length > 0 && (size_t)blocks_length < sizeof(blocks) &&
           leaf_length > 0 && (size_t)leaf_length < sizeof(leaf) &&
           platform_positioned_file_open_beneath(file, blocks, leaf) &&
           platform_positioned_file_snapshot(file, snapshot) &&
           snapshot->size > 0 && snapshot->size <= SIZE_MAX;
}

/* Process a single deserialized block for wallet txns. */
static bool scan_block_txs(const struct block *blk, int height,
                            const struct scan_addr_ht *ht,
                            struct scan_utxo_set *uset,
                            struct scan_wtx_list *wl)
{
    bool any_found = false;

    for (size_t ti = 0; ti < blk->num_vtx; ti++) {
        struct transaction *tx = &blk->vtx[ti];
        bool is_ours = false, from_me = false;
        int64_t debit = 0;

        for (size_t vi = 0; vi < tx->num_vout; vi++) {
            uint8_t ah[20];
            if (!scan_extract_addr(tx->vout[vi].script_pub_key.data,
                              tx->vout[vi].script_pub_key.size, ah))
                continue;
            if (!scan_aht_has(ht, ah)) continue;

            is_ours = true;
            struct scan_mem_utxo u;
            memset(&u, 0, sizeof(u));
            memcpy(u.txid, tx->hash.data, 32);
            u.vout = (uint32_t)vi;
            u.value = tx->vout[vi].value;
            memcpy(u.addr_hash, ah, 20);
            size_t sl = tx->vout[vi].script_pub_key.size;
            if (sl > sizeof(u.script)) sl = sizeof(u.script);
            memcpy(u.script, tx->vout[vi].script_pub_key.data, sl);
            u.script_len = (uint8_t)sl;
            u.height = height;
            u.is_coinbase = (ti == 0);
            scan_uset_add(uset, &u);
        }

        if (ti > 0) {
            for (size_t vi = 0; vi < tx->num_vin; vi++) {
                int ui = scan_uset_find(uset,
                    tx->vin[vi].prevout.hash.data,
                    tx->vin[vi].prevout.n);
                if (ui >= 0) {
                    is_ours = true;
                    from_me = true;
                    debit += uset->items[ui].value;
                    uset->items[ui].spent = true;
                    memcpy(uset->items[ui].spent_txid,
                           tx->hash.data, 32);
                    uset->items[ui].spent_vin = (int)vi;
                }
            }
        }

        if (is_ours) {
            any_found = true;
            struct scan_mem_wtx wt;
            memset(&wt, 0, sizeof(wt));
            memcpy(wt.txid, tx->hash.data, 32);
            wt.raw = ser_tx(tx, &wt.raw_len);
            wt.height = height;
            wt.time = blk->header.nTime;
            wt.from_me = from_me;
            if (from_me) {
                int64_t vout_total = transaction_get_value_out(tx);
                wt.fee = debit > vout_total ? debit - vout_total : 0;
            }
            scan_wl_add(wl, &wt);
        }
    }
    return any_found;
}

/* --- Pass 2 visitor: transparent scan --- */

struct transparent_ctx {
    const struct scan_addr_ht *ht;
    struct scan_utxo_set *uset;
    struct scan_wtx_list *wl;
    int found;
};

static bool transparent_visitor(const struct block *blk, int height,
                                 void *ctx)
{
    struct transparent_ctx *tc = (struct transparent_ctx *)ctx;
    if (scan_block_txs(blk, height, tc->ht, tc->uset, tc->wl))
        tc->found++;
    return true;
}

/* --- Service entry point --- */

/* Shutdown abort predicate. The registry flag is set once at process shutdown,
 * before the join of the zcl_snap_* import threads; the import polls it at
 * every batch/file boundary — never mid-statement — so a shutdown during the
 * multi-pass blk*.dat walk stops the import within the current batch (seconds)
 * instead of after the current pass (minutes to hours on a spinning disk).
 * An abort is not an import failure: it returns the contract's -1 with the
 * wallet DB untouched by any later pass (pass 2/3 reset+rewrite is idempotent
 * and simply re-runs on the next boot). */
static bool legacy_import_abort_requested(void)
{
    return thread_registry_shutdown_requested();
}

/* Persist the pass-2 transparent results (wallet UTXOs + wallet txs) in one
 * transaction. The model-owned reset runs first so a re-import is idempotent;
 * any failure rolls the transaction back — nothing half-written — and returns
 * false. */
static bool legacy_import_reset_wallet_rows(struct node_db *ndb)
{
    if (db_wallet_utxo_delete_all(ndb) &&
        db_wallet_tx_delete_all(ndb) &&
        db_sapling_note_delete_all(ndb))
        return true;
    LOG_WARN("legacy_import",
             "legacy_import: model-owned pass 2 reset failed");
    return false;
}

static bool legacy_import_persist_transparent(struct node_db *ndb,
                                              struct scan_utxo_set *uset,
                                              struct scan_wtx_list *wl)
{
    if (!legacy_import_begin_checked(ndb, "pass 2 begin"))
        return false; // raw-return-ok:callee-logged
    bool ok = legacy_import_reset_wallet_rows(ndb);
    for (int i = 0; ok && i < uset->count; i++) {
        struct scan_mem_utxo *u = &uset->items[i];
        struct db_wallet_utxo du;
        memset(&du, 0, sizeof(du));
        memcpy(du.txid, u->txid, 32);
        du.vout = u->vout;
        du.value = u->value;
        memcpy(du.address_hash, u->addr_hash, 20);
        du.script = u->script;
        du.script_len = u->script_len;
        du.height = u->height;
        du.is_coinbase = u->is_coinbase;
        if (!db_wallet_utxo_save(ndb, &du)) {
            LOG_WARN("legacy_import", "legacy_import: pass 2 wallet_utxo save failed");
            ok = false;
            break;
        }
        if (u->spent &&
            !db_wallet_utxo_mark_spent(ndb, u->txid, u->vout,
                                       u->spent_txid, u->spent_vin)) {
            LOG_WARN("legacy_import", "legacy_import: pass 2 wallet_utxo mark_spent failed");
            ok = false;
            break;
        }
    }
    for (int i = 0; ok && i < wl->count; i++) {
        struct scan_mem_wtx *t = &wl->items[i];
        struct db_wallet_tx dt;
        memset(&dt, 0, sizeof(dt));
        memcpy(dt.txid, t->txid, 32);
        dt.raw_tx = t->raw;
        dt.raw_tx_len = t->raw_len;
        dt.has_block = true;
        dt.block_height = t->height;
        dt.time_received = (int64_t)t->time;
        dt.from_me = t->from_me;
        dt.fee = t->fee;
        if (!db_wallet_tx_save(ndb, &dt)) {
            LOG_WARN("legacy_import", "legacy_import: pass 2 wallet_tx save failed");
            ok = false;
            break;
        }
    }
    if (ok)
        ok = legacy_import_commit_checked(ndb, "pass 2 commit");
    if (ok)
        return true;
    if (!legacy_import_rollback_checked(ndb, "pass 2 rollback"))
        LOG_WARN("legacy_import",
                 "legacy_import: pass 2 rollback failed after DB error");
    return false;
}

enum {
    LEGACY_IMPORT_OK = 0,
    LEGACY_IMPORT_OOM_FLAGS,
    LEGACY_IMPORT_ABORT_P1,
    LEGACY_IMPORT_THREAD_P1,
    LEGACY_IMPORT_ABORT_P2,
    LEGACY_IMPORT_UNSTABLE,
    LEGACY_IMPORT_PERSIST,
    LEGACY_IMPORT_FCTX_OOM,
    LEGACY_IMPORT_ABORT_P3A,
    LEGACY_IMPORT_THREAD_P3A,
    LEGACY_IMPORT_DCTX_OOM,
    LEGACY_IMPORT_RESULTS_OOM,
    LEGACY_IMPORT_ABORT_P3B,
    LEGACY_IMPORT_THREAD_P3B,
    LEGACY_IMPORT_BEGIN,
    LEGACY_IMPORT_SAVE_OPEN,
    LEGACY_IMPORT_COMMIT
};

struct legacy_import_thread_batch {
    pthread_t threads[8];
    int started;
};

struct legacy_import_run_state {
    struct scan_addr_ht aht;
    struct scan_utxo_set uset;
    struct scan_wtx_list wl;
    bool *file_has_match;
    struct legacy_import_filter_file_ctx *fctxs;
    struct legacy_import_decrypt_file_ctx *dctxs;
    int num_files;
    int matched;
    int unspent;
    int z_found;
    int total_blocks;
    int total_candidates;
    bool sapling_tx_open;
    struct timespec ts_start;
    struct timespec ts_p1;
    struct timespec ts_p2;
    /* Pass-1 thread arguments stay alive until run() joins a failed
     * spawn, so the log still happens before the join. */
    struct legacy_import_scan_file_arg pass1_args[8];
};

static bool legacy_import_args_ok(const char *legacy_datadir,
                                  const struct node_db *ndb,
                                  const struct wallet *w)
{
    return legacy_datadir && ndb && ndb->open && w;
}

static int legacy_import_batch_span(int num_files, int base, int batch)
{
    int n = num_files - base;
    if (n > batch)
        n = batch;
    return n;
}

static void legacy_import_join_started(pthread_t *threads, int count)
{
    for (int i = 0; i < count; i++)
        pthread_join(threads[i], NULL);
}

static void legacy_import_load_address_hashes(struct scan_addr_ht *aht,
                                              const struct wallet *w)
{
    /* Build address hash table from wallet keys. */
    scan_aht_init(aht);
    for (size_t i = 0; i < w->keystore.num_keys; i++)
        if (w->keystore.keys[i].used)
            scan_aht_insert(aht, w->keystore.keys[i].keyid.id.data);
    for (size_t i = 0; i < w->keystore.num_scripts; i++)
        if (w->keystore.scripts[i].used)
            scan_aht_insert(aht, w->keystore.scripts[i].script_id.data);
}

static int legacy_import_count_block_files(const char *legacy_datadir)
{
    /* Count block files. */
    int num_files = 0;
    for (int f = 0; f < 200; f++) {
        struct platform_positioned_file probe;
        struct platform_positioned_file_snapshot snapshot;
        platform_positioned_file_init(&probe);
        bool present = legacy_import_open_block(legacy_datadir, f, &probe,
                                                &snapshot);
        platform_positioned_file_close(&probe);
        if (!present)
            break;
        num_files = f + 1;
    }
    return num_files;
}

static int legacy_import_count_matched_files(const bool *file_has_match,
                                             int num_files)
{
    int matched = 0;
    for (int i = 0; i < num_files; i++)
        if (file_has_match[i])
            matched++;
    return matched;
}

static void legacy_import_tally_unspent(const struct scan_utxo_set *uset,
                                        int64_t *balance, int *unspent)
{
    *balance = 0;
    *unspent = 0;
    for (int i = 0; i < uset->count; i++) {
        if (!uset->items[i].spent) {
            *balance += uset->items[i].value;
            (*unspent)++;
        }
    }
}

static void legacy_import_tally_filter_hits(
    const struct legacy_import_filter_file_ctx *fctxs, int num_files,
    int *total_blocks, int *total_candidates, int *total_hfail)
{
    *total_blocks = 0;
    *total_candidates = 0;
    *total_hfail = 0;
    for (int f = 0; f < num_files; f++) {
        *total_blocks += fctxs[f].blocks_total;
        *total_candidates += fctxs[f].hit_count;
        *total_hfail += fctxs[f].height_failed;
    }
}

static void legacy_import_announce_pass3a(double p3a_ms, int total_blocks,
                                          int total_candidates,
                                          int total_hfail)
{
    printf("legacy_import: pass 3a done in %.1f ms — %d blocks, "
           "%d candidates (%.1f%%), %d height-fail\n",
           p3a_ms, total_blocks, total_candidates,
           total_blocks > 0 ?
               100.0 * (double)total_candidates / (double)total_blocks :
               0.0, total_hfail);
    fflush(stdout);
}

static void legacy_import_announce_pass3(const struct timespec *ts_p2,
                                         int total_blocks,
                                         int total_candidates,
                                         int shielded_outputs_seen,
                                         int z_found)
{
    struct timespec ts_p3;
    platform_time_monotonic_timespec(&ts_p3);
    double p3_ms = (double)(ts_p3.tv_sec - ts_p2->tv_sec) * 1000.0 +
                   (double)(ts_p3.tv_nsec - ts_p2->tv_nsec) / 1e6;
    printf("legacy_import: pass 3 done in %.1f ms — %d blocks, "
           "%d candidates, %d shielded outputs, %d notes\n",
           p3_ms, total_blocks, total_candidates,
           shielded_outputs_seen, z_found);
    fflush(stdout);
}

static void legacy_import_announce_complete(const struct timespec *ts_start,
                                            int unspent, int wallet_txs,
                                            int z_found, struct node_db *ndb)
{
    /* Wallet keys are persisted exclusively by the encryption-aware
     * wallet_sqlite writer (single-writer doctrine); the import above
     * only adds transactions and notes. */

    /* Report final results. */
    int64_t t_bal = db_wallet_utxo_balance(ndb);
    int64_t z_bal = db_sapling_note_balance(ndb);
    int64_t total = t_bal + z_bal;

    struct timespec ts_end;
    platform_time_monotonic_timespec(&ts_end);
    double elapsed = (double)(ts_end.tv_sec - ts_start->tv_sec) +
                     (double)(ts_end.tv_nsec - ts_start->tv_nsec) / 1e9;

    printf("legacy_import: COMPLETE in %.1f seconds\n", elapsed);
    printf("  transparent: %.8f ZCL (%d UTXOs, %d txs)\n",
           (double)t_bal / 1e8, unspent, wallet_txs);
    printf("  shielded:    %.8f ZCL (%d notes)\n",
           (double)z_bal / 1e8, z_found);
    printf("  total:       %.8f ZCL\n", (double)total / 1e8);
    fflush(stdout);
}

static void legacy_import_release_sapling_contexts(
    struct legacy_import_decrypt_file_ctx *dctxs,
    struct legacy_import_filter_file_ctx *fctxs,
    int num_files)
{
    if (dctxs) {
        for (int f = 0; f < num_files; f++) {
            free(dctxs[f].results);
            free(dctxs[f].tw.sapling_notes);
        }
        free(dctxs);
    }
    if (fctxs) {
        for (int f = 0; f < num_files; f++)
            free(fctxs[f].hits);
        free(fctxs);
    }
}

/* Returns 1 after a stable scan, 0 when the file cannot be mapped (the
 * caller skips it), and -1 when the file changed during the walk. */
static int legacy_import_scan_matched_block(
    const char *legacy_datadir, int file_number,
    struct transparent_ctx *tctx, int *walked)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    struct platform_read_mapping mapping;
    platform_positioned_file_init(&file);
    platform_read_mapping_init(&mapping);
    *walked = 0;
    if (!legacy_import_open_block(legacy_datadir, file_number, &file,
                                  &before) ||
        !platform_read_mapping_open_positioned(
            &mapping, &file, (size_t)before.size)) {
        platform_read_mapping_close(&mapping);
        platform_positioned_file_close(&file);
        return 0;
    }
    platform_read_mapping_advise_sequential(&mapping);

    *walked = legacy_import_walk_block_file(
        mapping.data, mapping.size, transparent_visitor, tctx);
    bool stable = platform_positioned_file_snapshot(&file, &after) &&
                  legacy_import_snapshot_equal(&before, &after);
    platform_read_mapping_close(&mapping);
    platform_positioned_file_close(&file);
    if (!stable)
        return -1;
    return 1;
}

static int legacy_import_pass1_raw_scan(
    const char *legacy_datadir, struct legacy_import_run_state *st,
    struct legacy_import_thread_batch *batch)
{
    /* ========== PASS 1: Parallel raw byte scan ========== */
    printf("legacy_import: pass 1 — parallel raw byte scan...\n");
    fflush(stdout);

    st->file_has_match = zcl_calloc((size_t)st->num_files, sizeof(bool),
                                    "legacy file match flags");
    if (!st->file_has_match)
        return LEGACY_IMPORT_OOM_FLAGS;

    int batch_n = 8;
    for (int base = 0; base < st->num_files; base += batch_n) {
        if (legacy_import_abort_requested())
            return LEGACY_IMPORT_ABORT_P1;
        int n = legacy_import_batch_span(st->num_files, base, batch_n);
        int started = 0;
        for (int i = 0; i < n; i++) {
            st->pass1_args[i].datadir = legacy_datadir;
            st->pass1_args[i].file_num = base + i;
            st->pass1_args[i].ht = &st->aht;
            st->pass1_args[i].result = false;
            /* raw-pthread-ok: short-burst-joined-immediately */
            if (pthread_create(&batch->threads[i], NULL,
                               legacy_import_scan_file_thread,
                               &st->pass1_args[i]) != 0) {
                batch->started = started;
                return LEGACY_IMPORT_THREAD_P1;
            }
            started++;
        }
        for (int i = 0; i < n; i++) {
            pthread_join(batch->threads[i], NULL);
            st->file_has_match[base + i] = st->pass1_args[i].result;
        }
    }

    platform_time_monotonic_timespec(&st->ts_p1);
    double p1_ms = (double)(st->ts_p1.tv_sec - st->ts_start.tv_sec) * 1000.0 +
                   (double)(st->ts_p1.tv_nsec - st->ts_start.tv_nsec) / 1e6;
    st->matched = legacy_import_count_matched_files(st->file_has_match,
                                                    st->num_files);
    printf("legacy_import: pass 1 done in %.1f ms — %d/%d files match\n",
           p1_ms, st->matched, st->num_files);
    fflush(stdout);
    return LEGACY_IMPORT_OK;
}

static int legacy_import_pass2_transparent(
    const char *legacy_datadir, struct legacy_import_run_state *st)
{
    /* ========== PASS 2: Walk matched files for transparent txns ========== */
    printf("legacy_import: pass 2 — transparent scan of %d files...\n",
           st->matched);
    fflush(stdout);

    struct transparent_ctx tctx = { &st->aht, &st->uset, &st->wl, 0 };
    int total_blocks_p2 = 0;
    for (int f = 0; f < st->num_files; f++) {
        if (legacy_import_abort_requested())
            return LEGACY_IMPORT_ABORT_P2;
        if (!st->file_has_match[f])
            continue;
        int walked = 0;
        int scan = legacy_import_scan_matched_block(legacy_datadir, f,
                                                    &tctx, &walked);
        if (scan < 0)
            return LEGACY_IMPORT_UNSTABLE;
        total_blocks_p2 += walked;
    }

    platform_time_monotonic_timespec(&st->ts_p2);
    double p2_ms = (double)(st->ts_p2.tv_sec - st->ts_p1.tv_sec) * 1000.0 +
                   (double)(st->ts_p2.tv_nsec - st->ts_p1.tv_nsec) / 1e6;

    int64_t balance = 0;
    legacy_import_tally_unspent(&st->uset, &balance, &st->unspent);

    printf("legacy_import: pass 2 done in %.1f ms — %d blocks, "
           "%d wallet txs, %d UTXOs, balance %.8f ZCL\n",
           p2_ms, total_blocks_p2, st->wl.count, st->unspent,
           (double)balance / (double)COIN);
    fflush(stdout);
    return LEGACY_IMPORT_OK;
}

static bool legacy_import_sapling_scan_wanted(bool sapling_scan,
                                              const struct wallet *w)
{
    return sapling_scan && w->sapling_keys.num_keys > 0;
}

static int legacy_import_filter_sapling_batches(
    const char *legacy_datadir, struct legacy_import_run_state *st,
    struct legacy_import_thread_batch *batch)
{
    int batch_n = 8;
    for (int base = 0; base < st->num_files; base += batch_n) {
        if (legacy_import_abort_requested())
            return LEGACY_IMPORT_ABORT_P3A;
        int n = legacy_import_batch_span(st->num_files, base, batch_n);
        int started = 0;
        for (int i = 0; i < n; i++) {
            st->fctxs[base + i].datadir = legacy_datadir;
            st->fctxs[base + i].file_num = base + i;
            /* raw-pthread-ok: short-burst-joined-immediately */
            if (pthread_create(&batch->threads[i], NULL,
                               legacy_import_sapling_filter_thread,
                               &st->fctxs[base + i]) != 0) {
                batch->started = started;
                return LEGACY_IMPORT_THREAD_P3A;
            }
            started++;
        }
        for (int i = 0; i < n; i++)
            pthread_join(batch->threads[i], NULL);
    }

    int total_hfail = 0;
    legacy_import_tally_filter_hits(st->fctxs, st->num_files,
                                    &st->total_blocks,
                                    &st->total_candidates, &total_hfail);
    struct timespec ts_p3a;
    platform_time_monotonic_timespec(&ts_p3a);
    double p3a_ms = (double)(ts_p3a.tv_sec - st->ts_p2.tv_sec) * 1000.0 +
                    (double)(ts_p3a.tv_nsec - st->ts_p2.tv_nsec) / 1e6;
    legacy_import_announce_pass3a(p3a_ms, st->total_blocks,
                                  st->total_candidates, total_hfail);
    return LEGACY_IMPORT_OK;
}

static int legacy_import_prepare_decrypt_slots(
    const char *legacy_datadir,
    struct legacy_import_decrypt_file_ctx *dctxs,
    const struct legacy_import_filter_file_ctx *fctxs,
    int num_files, const struct wallet *w)
{
    for (int f = 0; f < num_files; f++) {
        dctxs[f].datadir = legacy_datadir;
        dctxs[f].hits = fctxs[f].hits;
        dctxs[f].count = fctxs[f].hit_count;
        dctxs[f].file_num = f;
        wallet_init(&dctxs[f].tw);
        dctxs[f].tw.sapling_keys = w->sapling_keys;
        dctxs[f].result_cap = 64;
        dctxs[f].results = zcl_malloc(64 * sizeof(struct db_sapling_note),
                                      "sapling decrypt results");
        if (!dctxs[f].results)
            return LEGACY_IMPORT_RESULTS_OOM;
    }
    return LEGACY_IMPORT_OK;
}

static int legacy_import_decrypt_sapling_batches(
    struct legacy_import_decrypt_file_ctx *dctxs, int num_files,
    struct legacy_import_thread_batch *batch)
{
    int batch_n = 8;
    for (int base = 0; base < num_files; base += batch_n) {
        if (legacy_import_abort_requested())
            return LEGACY_IMPORT_ABORT_P3B;
        int n = legacy_import_batch_span(num_files, base, batch_n);
        int launched = 0;
        for (int i = 0; i < n; i++) {
            if (dctxs[base + i].count == 0)
                continue;
            /* raw-pthread-ok: short-burst-joined-immediately */
            if (pthread_create(&batch->threads[launched], NULL,
                               legacy_import_decrypt_thread,
                               &dctxs[base + i]) != 0) {
                batch->started = launched;
                return LEGACY_IMPORT_THREAD_P3B;
            }
            launched++;
        }
        for (int i = 0; i < launched; i++)
            pthread_join(batch->threads[i], NULL);
    }
    return LEGACY_IMPORT_OK;
}

static int legacy_import_save_sapling_notes(
    struct node_db *ndb,
    struct legacy_import_decrypt_file_ctx *dctxs,
    struct legacy_import_filter_file_ctx *fctxs,
    int num_files, int *shielded_outputs_seen, int *sapling_notes,
    bool *sapling_tx_open)
{
    /* Merge results and write to SQLite. */
    *shielded_outputs_seen = 0;
    *sapling_notes = 0;
    *sapling_tx_open = false;
    bool began = legacy_import_begin_checked(ndb, "pass 3 commit begin");
    if (!began)
        return LEGACY_IMPORT_BEGIN;
    *sapling_tx_open = true;
    for (int f = 0; f < num_files; f++) {
        *shielded_outputs_seen += dctxs[f].outputs_seen;
        *sapling_notes += dctxs[f].notes_found;
        for (int i = 0; i < dctxs[f].result_count; i++) {
            bool saved = db_sapling_note_save(ndb, &dctxs[f].results[i]);
            if (!saved)
                return LEGACY_IMPORT_SAVE_OPEN;
        }
        free(dctxs[f].results);
        dctxs[f].results = NULL;
        free(fctxs[f].hits);
        fctxs[f].hits = NULL;
        free(dctxs[f].tw.sapling_notes);
        dctxs[f].tw.sapling_notes = NULL;
    }
    bool committed = legacy_import_commit_checked(ndb, "pass 3 commit");
    if (!committed)
        return LEGACY_IMPORT_COMMIT;
    *sapling_tx_open = false;
    return LEGACY_IMPORT_OK;
}

static int legacy_import_pass3_sapling(
    const char *legacy_datadir, struct node_db *ndb, const struct wallet *w,
    bool sapling_scan, struct legacy_import_run_state *st,
    struct legacy_import_thread_batch *batch)
{
    /* ========== PASS 3: Sapling trial decryption ========== */
    /* Phase A: parallel filter (8 threads) — lightweight height + size
     *          filter to find candidate blocks without deserialization.
     * Phase B: serial trial decryption — only on candidate blocks. */
    bool wanted = legacy_import_sapling_scan_wanted(sapling_scan, w);
    if (!wanted)
        return LEGACY_IMPORT_OK;

    printf("legacy_import: pass 3a — parallel block filter "
           "(%d files, 8 threads)...\n", st->num_files);
    fflush(stdout);

    st->fctxs = zcl_calloc((size_t)st->num_files,
                           sizeof(struct legacy_import_filter_file_ctx),
                           "sapling filter contexts");
    if (!st->fctxs)
        return LEGACY_IMPORT_FCTX_OOM;

    int code = legacy_import_filter_sapling_batches(legacy_datadir, st,
                                                    batch);
    if (code != LEGACY_IMPORT_OK)
        return code;

    /* Phase B: parallel deserialize + trial decrypt.
     * Each thread gets its own wallet clone (sapling keys only)
     * to avoid shared-state races. Results merged after. */
    printf("legacy_import: pass 3b — parallel trial decryption of "
           "%d blocks (%zu keys, 8 threads)...\n",
           st->total_candidates, w->sapling_keys.num_keys);
    fflush(stdout);

    st->dctxs = zcl_calloc((size_t)st->num_files,
                           sizeof(struct legacy_import_decrypt_file_ctx),
                           "sapling decrypt contexts");
    if (!st->dctxs)
        return LEGACY_IMPORT_DCTX_OOM;

    code = legacy_import_prepare_decrypt_slots(legacy_datadir, st->dctxs,
                                               st->fctxs, st->num_files, w);
    if (code != LEGACY_IMPORT_OK)
        return code;

    code = legacy_import_decrypt_sapling_batches(st->dctxs, st->num_files,
                                                 batch);
    if (code != LEGACY_IMPORT_OK)
        return code;

    int shielded_outputs_seen = 0;
    int sapling_notes = 0;
    code = legacy_import_save_sapling_notes(
        ndb, st->dctxs, st->fctxs, st->num_files, &shielded_outputs_seen,
        &sapling_notes, &st->sapling_tx_open);
    if (code != LEGACY_IMPORT_OK)
        return code;

    st->z_found = sapling_notes;
    legacy_import_announce_pass3(&st->ts_p2, st->total_blocks,
                                 st->total_candidates,
                                 shielded_outputs_seen, st->z_found);
    free(st->dctxs);
    st->dctxs = NULL;
    free(st->fctxs);
    st->fctxs = NULL;
    return LEGACY_IMPORT_OK;
}

static int legacy_import_execute(const char *legacy_datadir,
                                 struct node_db *ndb, const struct wallet *w,
                                 bool sapling_scan,
                                 struct legacy_import_run_state *st,
                                 struct legacy_import_thread_batch *batch)
{
    platform_time_monotonic_timespec(&st->ts_start);
    legacy_import_load_address_hashes(&st->aht, w);
    printf("legacy_import: %d address hashes, %zu sapling keys\n",
           st->aht.count, w->sapling_keys.num_keys);
    fflush(stdout);

    st->num_files = legacy_import_count_block_files(legacy_datadir);
    printf("legacy_import: %d block files in %s\n",
           st->num_files, legacy_datadir);
    fflush(stdout);

    /* uset/wl are freed unconditionally at the cleanup: label, which is
     * reachable via the pass-1 thread-spawn-failure goto below — initialize
     * them HERE, before any goto, so cleanup never frees uninitialized
     * (garbage) structs. */
    scan_uset_init(&st->uset);
    scan_wl_init(&st->wl);

    int code = legacy_import_pass1_raw_scan(legacy_datadir, st, batch);
    if (code != LEGACY_IMPORT_OK)
        return code;

    code = legacy_import_pass2_transparent(legacy_datadir, st);
    if (code != LEGACY_IMPORT_OK)
        return code;

    /* Write transparent results to SQLite. */
    bool persisted = legacy_import_persist_transparent(ndb, &st->uset,
                                                       &st->wl);
    if (!persisted)
        return LEGACY_IMPORT_PERSIST;

    code = legacy_import_pass3_sapling(legacy_datadir, ndb, w, sapling_scan,
                                       st, batch);
    if (code != LEGACY_IMPORT_OK)
        return code;

    legacy_import_announce_complete(&st->ts_start, st->unspent, st->wl.count,
                                    st->z_found, ndb);
    return LEGACY_IMPORT_OK;
}

/* Status arms stay in legacy_import_service_run so each LOG_* call keeps
 * that function's name. The passes return a code; this switch only logs. */
int legacy_import_service_run(const char *legacy_datadir,
                              struct node_db *ndb,
                              struct wallet *w,
                              bool sapling_scan)
{
    int ret = -1;

    if (!legacy_import_args_ok(legacy_datadir, ndb, w))
        LOG_ERR("legacy_import", "invalid args: datadir=%p ndb=%p open=%d wallet=%p",
                (const void *)legacy_datadir, (const void *)ndb,
                (ndb ? ndb->open : 0), (const void *)w);

    struct legacy_import_run_state st = {0};
    struct legacy_import_thread_batch batch = {0};
    int code = legacy_import_execute(legacy_datadir, ndb, w, sapling_scan,
                                     &st, &batch);
    int num_files = st.num_files;
    bool sapling_tx_open = st.sapling_tx_open;

    switch (code) {
    case LEGACY_IMPORT_OK:
        goto legacy_import_run_ok;
    case LEGACY_IMPORT_OOM_FLAGS:
        goto legacy_import_run_oom_flags;
    case LEGACY_IMPORT_ABORT_P1:
        goto legacy_import_run_abort_p1;
    case LEGACY_IMPORT_THREAD_P1:
        goto legacy_import_run_thread_p1;
    case LEGACY_IMPORT_ABORT_P2:
        goto legacy_import_run_abort_p2;
    case LEGACY_IMPORT_UNSTABLE:
        goto legacy_import_run_unstable;
    case LEGACY_IMPORT_PERSIST:
        goto cleanup;
    case LEGACY_IMPORT_FCTX_OOM:
        goto legacy_import_run_fctx_oom;
    case LEGACY_IMPORT_ABORT_P3A:
        goto legacy_import_run_abort_p3a;
    case LEGACY_IMPORT_THREAD_P3A:
        goto legacy_import_run_thread_p3a;
    case LEGACY_IMPORT_DCTX_OOM:
        goto legacy_import_run_dctx_oom;
    case LEGACY_IMPORT_RESULTS_OOM:
        goto legacy_import_run_results_oom;
    case LEGACY_IMPORT_ABORT_P3B:
        goto legacy_import_run_abort_p3b;
    case LEGACY_IMPORT_THREAD_P3B:
        goto legacy_import_run_thread_p3b;
    case LEGACY_IMPORT_BEGIN:
        goto cleanup;
    case LEGACY_IMPORT_SAVE_OPEN:
        goto legacy_import_run_save_open;
    case LEGACY_IMPORT_COMMIT:
        goto cleanup;
    default:
        goto cleanup;
    }

legacy_import_run_oom_flags:
    LOG_WARN("legacy_import", "legacy_import: OOM allocating %d file-match flags", num_files);
    goto cleanup;
legacy_import_run_abort_p1:
    LOG_INFO("legacy_import",
             "legacy import aborted: shutdown requested (pass 1)");
    goto cleanup;
legacy_import_run_thread_p1:
    LOG_WARN("legacy_import", "legacy_import: failed to start pass-1 scan thread");
    legacy_import_join_started(batch.threads, batch.started);
    goto cleanup;
legacy_import_run_abort_p2:
    LOG_INFO("legacy_import",
             "legacy import aborted: shutdown requested (pass 2)");
    goto cleanup;
legacy_import_run_unstable:
    LOG_WARN("legacy_import",
             "legacy block file changed during immutable pass 2");
    goto cleanup;
legacy_import_run_fctx_oom:
    LOG_WARN("legacy_import", "legacy_import: failed to allocate sapling filter contexts");
    goto cleanup;
legacy_import_run_abort_p3a:
    LOG_INFO("legacy_import",
             "legacy import aborted: shutdown requested (pass 3a)");
    goto cleanup;
legacy_import_run_thread_p3a:
    LOG_WARN("legacy_import", "legacy_import: failed to start sapling filter thread");
    legacy_import_join_started(batch.threads, batch.started);
    goto cleanup;
legacy_import_run_dctx_oom:
    LOG_WARN("legacy_import", "legacy_import: failed to allocate sapling decrypt contexts");
    goto cleanup;
legacy_import_run_results_oom:
    LOG_WARN("legacy_import", "legacy_import: failed to allocate sapling decrypt results");
    goto cleanup;
legacy_import_run_abort_p3b:
    LOG_INFO("legacy_import",
             "legacy import aborted: shutdown requested (pass 3b)");
    goto cleanup;
legacy_import_run_thread_p3b:
    LOG_WARN("legacy_import", "legacy_import: failed to start sapling decrypt thread");
    legacy_import_join_started(batch.threads, batch.started);
    goto cleanup;
legacy_import_run_save_open:
    LOG_WARN("legacy_import", "legacy_import: pass 3 sapling note save failed");
    if (sapling_tx_open &&
        !legacy_import_rollback_checked(ndb,
            "pass 3 rollback")) {
        LOG_WARN("legacy_import", "legacy_import: pass 3 rollback failed after DB error");
    }
    goto cleanup;
legacy_import_run_ok:
    ret = st.wl.count;

cleanup:
    /* Cleanup. */
    legacy_import_release_sapling_contexts(st.dctxs, st.fctxs, st.num_files);
    scan_aht_free(&st.aht);
    scan_uset_free(&st.uset);
    scan_wl_free(&st.wl);
    free(st.file_has_match);
    return ret;
}
