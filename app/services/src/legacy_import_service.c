/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * legacy_import_service — Service-grade orchestration for importing wallet
 * data from a legacy (C++) ZClassic node's raw block files.
 *
 * This is the orchestration core for the legacy block-file import. It is
 * Service/Job-grade work — a multi-pass mmap block-file scan plus a Sapling
 * trial-decryption walk that drives a multi-threaded import loop — so it
 * lives in the Service shape. The legacy_import Controller
 * (app/controllers/src/legacy_import.c) is a thin shim that validates
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

/* The scan worker contract (struct layouts + thread entry points) is a
 * private header shared with the scan worker TU
 * (app/controllers/src/legacy_import_scan.c). It is not on the public include
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

int legacy_import_service_run(const char *legacy_datadir,
                              struct node_db *ndb,
                              struct wallet *w,
                              bool sapling_scan)
{
    int ret = -1;
    struct legacy_import_filter_file_ctx *fctxs = NULL;
    struct legacy_import_decrypt_file_ctx *dctxs = NULL;

    if (!legacy_datadir || !ndb || !ndb->open || !w)
        LOG_ERR("legacy_import", "invalid args: datadir=%p ndb=%p open=%d wallet=%p",
                (const void *)legacy_datadir, (const void *)ndb,
                (ndb ? ndb->open : 0), (const void *)w);

    struct timespec ts_start, ts_p1, ts_p2, ts_p3;
    platform_time_monotonic_timespec(&ts_start);

    /* Build address hash table from wallet keys. */
    struct scan_addr_ht aht;
    scan_aht_init(&aht);
    for (size_t i = 0; i < w->keystore.num_keys; i++)
        if (w->keystore.keys[i].used)
            scan_aht_insert(&aht, w->keystore.keys[i].keyid.id.data);
    for (size_t i = 0; i < w->keystore.num_scripts; i++)
        if (w->keystore.scripts[i].used)
            scan_aht_insert(&aht, w->keystore.scripts[i].script_id.data);

    printf("legacy_import: %d address hashes, %zu sapling keys\n",
           aht.count, w->sapling_keys.num_keys);
    fflush(stdout);

    /* Count block files. */
    int num_files = 0;
    for (int f = 0; f < 200; f++) {
        struct platform_positioned_file probe;
        struct platform_positioned_file_snapshot snapshot;
        platform_positioned_file_init(&probe);
        bool present = legacy_import_open_block(legacy_datadir, f, &probe,
                                                &snapshot);
        platform_positioned_file_close(&probe);
        if (!present) break;
        num_files = f + 1;
    }
    printf("legacy_import: %d block files in %s\n",
           num_files, legacy_datadir);
    fflush(stdout);

    /* uset/wl are freed unconditionally at the cleanup: label, which is
     * reachable via the pass-1 thread-spawn-failure goto below — initialize
     * them HERE, before any goto, so cleanup never frees uninitialized
     * (garbage) structs. */
    struct scan_utxo_set uset;
    scan_uset_init(&uset);
    struct scan_wtx_list wl;
    scan_wl_init(&wl);

    /* ========== PASS 1: Parallel raw byte scan ========== */
    printf("legacy_import: pass 1 — parallel raw byte scan...\n");
    fflush(stdout);

    bool *file_has_match = zcl_calloc((size_t)num_files, sizeof(bool), "legacy file match flags");
    if (!file_has_match) {
        LOG_WARN("legacy_import", "legacy_import: OOM allocating %d file-match flags", num_files);
        goto cleanup;
    }
    int batch = 8;

    for (int base = 0; base < num_files; base += batch) {
        int n = num_files - base;
        if (n > batch) n = batch;
        struct legacy_import_scan_file_arg args[8];
        pthread_t threads[8];
        int started = 0;
        for (int i = 0; i < n; i++) {
            args[i].datadir = legacy_datadir;
            args[i].file_num = base + i;
            args[i].ht = &aht;
            args[i].result = false;
            /* raw-pthread-ok: short-burst-joined-immediately */
            if (pthread_create(&threads[i], NULL,
                               legacy_import_scan_file_thread,
                               &args[i]) != 0) {
                LOG_WARN("legacy_import", "legacy_import: failed to start pass-1 scan thread");
                for (int j = 0; j < started; j++)
                    pthread_join(threads[j], NULL);
                goto cleanup;
            }
            started++;
        }
        for (int i = 0; i < n; i++) {
            pthread_join(threads[i], NULL);
            file_has_match[base + i] = args[i].result;
        }
    }

    platform_time_monotonic_timespec(&ts_p1);
    double p1_ms = (double)(ts_p1.tv_sec - ts_start.tv_sec) * 1000.0 +
                   (double)(ts_p1.tv_nsec - ts_start.tv_nsec) / 1e6;

    int matched = 0;
    for (int i = 0; i < num_files; i++)
        if (file_has_match[i]) matched++;
    printf("legacy_import: pass 1 done in %.1f ms — %d/%d files match\n",
           p1_ms, matched, num_files);
    fflush(stdout);

    /* ========== PASS 2: Walk matched files for transparent txns ========== */
    printf("legacy_import: pass 2 — transparent scan of %d files...\n",
           matched);
    fflush(stdout);

    struct transparent_ctx tctx = { &aht, &uset, &wl, 0 };

    int total_blocks_p2 = 0;
    for (int f = 0; f < num_files; f++) {
        if (!file_has_match[f]) continue;
        struct platform_positioned_file file;
        struct platform_positioned_file_snapshot before, after;
        struct platform_read_mapping mapping;
        platform_positioned_file_init(&file);
        platform_read_mapping_init(&mapping);
        if (!legacy_import_open_block(legacy_datadir, f, &file, &before) ||
            !platform_read_mapping_open_positioned(
                &mapping, &file, (size_t)before.size)) {
            platform_read_mapping_close(&mapping);
            platform_positioned_file_close(&file);
            continue;
        }
        platform_read_mapping_advise_sequential(&mapping);

        total_blocks_p2 += legacy_import_walk_block_file(
            mapping.data, mapping.size, transparent_visitor, &tctx);
        bool stable = platform_positioned_file_snapshot(&file, &after) &&
                      legacy_import_snapshot_equal(&before, &after);
        platform_read_mapping_close(&mapping);
        platform_positioned_file_close(&file);
        if (!stable) {
            LOG_WARN("legacy_import",
                     "legacy block file changed during immutable pass 2");
            goto cleanup;
        }
    }

    platform_time_monotonic_timespec(&ts_p2);
    double p2_ms = (double)(ts_p2.tv_sec - ts_p1.tv_sec) * 1000.0 +
                   (double)(ts_p2.tv_nsec - ts_p1.tv_nsec) / 1e6;

    int64_t balance = 0;
    int unspent = 0;
    for (int i = 0; i < uset.count; i++) {
        if (!uset.items[i].spent) {
            balance += uset.items[i].value;
            unspent++;
        }
    }

    printf("legacy_import: pass 2 done in %.1f ms — %d blocks, "
           "%d wallet txs, %d UTXOs, balance %.8f ZCL\n",
           p2_ms, total_blocks_p2, wl.count, unspent,
           (double)balance / (double)COIN);
    fflush(stdout);

    /* Write transparent results to SQLite. */
    {
        bool import_tx_open = false;
        if (!legacy_import_begin_checked(ndb, "pass 2 begin")) {
            goto cleanup;
        }
        import_tx_open = true;
        if (!db_wallet_utxo_delete_all(ndb) ||
            !db_wallet_tx_delete_all(ndb) ||
            !db_sapling_note_delete_all(ndb)) {
            LOG_WARN("legacy_import",
                     "legacy_import: model-owned pass 2 reset failed");
            goto pass2_db_fail;
        }

        for (int i = 0; i < uset.count; i++) {
            struct scan_mem_utxo *u = &uset.items[i];
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
                goto pass2_db_fail;
            }
            if (u->spent &&
                !db_wallet_utxo_mark_spent(ndb, u->txid, u->vout,
                                           u->spent_txid, u->spent_vin)) {
                LOG_WARN("legacy_import", "legacy_import: pass 2 wallet_utxo mark_spent failed");
                goto pass2_db_fail;
            }
        }

        for (int i = 0; i < wl.count; i++) {
            struct scan_mem_wtx *t = &wl.items[i];
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
                goto pass2_db_fail;
            }
        }
        if (!legacy_import_commit_checked(ndb, "pass 2 commit")) {
            goto pass2_db_fail;
        }
        import_tx_open = false;
        goto pass2_db_done;

pass2_db_fail:
        if (import_tx_open &&
            !legacy_import_rollback_checked(ndb, "pass 2 rollback")) {
            LOG_WARN("legacy_import", "legacy_import: pass 2 rollback failed after DB error");
        }
        goto cleanup;
pass2_db_done:
        ;
    }

    /* ========== PASS 3: Sapling trial decryption ========== */
    /* Phase A: parallel filter (8 threads) — lightweight height + size
     *          filter to find candidate blocks without deserialization.
     * Phase B: serial trial decryption — only on candidate blocks. */
    int z_found = 0;
    if (sapling_scan && w->sapling_keys.num_keys > 0) {
        printf("legacy_import: pass 3a — parallel block filter "
               "(%d files, 8 threads)...\n", num_files);
        fflush(stdout);

        fctxs = zcl_calloc((size_t)num_files,
                           sizeof(struct legacy_import_filter_file_ctx),
                           "sapling filter contexts");
        if (!fctxs) {
            LOG_WARN("legacy_import", "legacy_import: failed to allocate sapling filter contexts");
            goto cleanup;
        }
        for (int base = 0; base < num_files; base += batch) {
            int n = num_files - base;
            if (n > batch) n = batch;
            pthread_t thr[8];
            int started = 0;
            for (int i = 0; i < n; i++) {
                fctxs[base + i].datadir = legacy_datadir;
                fctxs[base + i].file_num = base + i;
                /* raw-pthread-ok: short-burst-joined-immediately */
                if (pthread_create(&thr[i], NULL,
                                   legacy_import_sapling_filter_thread,
                                   &fctxs[base + i]) != 0) {
                    LOG_WARN("legacy_import", "legacy_import: failed to start sapling filter thread");
                    for (int j = 0; j < started; j++)
                        pthread_join(thr[j], NULL);
                    goto cleanup;
                }
                started++;
            }
            for (int i = 0; i < n; i++)
                pthread_join(thr[i], NULL);
        }

        int total_blocks = 0, total_candidates = 0, total_hfail = 0;
        for (int f = 0; f < num_files; f++) {
            total_blocks += fctxs[f].blocks_total;
            total_candidates += fctxs[f].hit_count;
            total_hfail += fctxs[f].height_failed;
        }

        struct timespec ts_p3a;
        platform_time_monotonic_timespec(&ts_p3a);
        double p3a_ms = (double)(ts_p3a.tv_sec - ts_p2.tv_sec) * 1000.0 +
                        (double)(ts_p3a.tv_nsec - ts_p2.tv_nsec) / 1e6;
        printf("legacy_import: pass 3a done in %.1f ms — %d blocks, "
               "%d candidates (%.1f%%), %d height-fail\n",
               p3a_ms, total_blocks, total_candidates,
               total_blocks > 0 ?
                   100.0 * (double)total_candidates / (double)total_blocks :
                   0.0, total_hfail);
        fflush(stdout);

        /* Phase B: parallel deserialize + trial decrypt.
         * Each thread gets its own wallet clone (sapling keys only)
         * to avoid shared-state races. Results merged after. */
        printf("legacy_import: pass 3b — parallel trial decryption of "
               "%d blocks (%zu keys, 8 threads)...\n",
               total_candidates, w->sapling_keys.num_keys);
        fflush(stdout);

        dctxs = zcl_calloc((size_t)num_files,
                           sizeof(struct legacy_import_decrypt_file_ctx),
                           "sapling decrypt contexts");
        if (!dctxs) {
            LOG_WARN("legacy_import", "legacy_import: failed to allocate sapling decrypt contexts");
            goto cleanup;
        }
        for (int f = 0; f < num_files; f++) {
            dctxs[f].datadir = legacy_datadir;
            dctxs[f].hits = fctxs[f].hits;
            dctxs[f].count = fctxs[f].hit_count;
            dctxs[f].file_num = f;
            wallet_init(&dctxs[f].tw);
            dctxs[f].tw.sapling_keys = w->sapling_keys;
            dctxs[f].result_cap = 64;
            dctxs[f].results = zcl_malloc(64 * sizeof(struct db_sapling_note), "sapling decrypt results");
            if (!dctxs[f].results) {
                LOG_WARN("legacy_import", "legacy_import: failed to allocate sapling decrypt results");
                goto cleanup;
            }
        }

        pthread_t thr3[8];
        for (int base = 0; base < num_files; base += batch) {
            int n = num_files - base;
            if (n > batch) n = batch;
            int launched = 0;
            for (int i = 0; i < n; i++) {
                if (dctxs[base + i].count == 0) continue;
                /* raw-pthread-ok: short-burst-joined-immediately */
                if (pthread_create(&thr3[launched], NULL,
                                   legacy_import_decrypt_thread,
                                   &dctxs[base + i]) != 0) {
                    LOG_WARN("legacy_import", "legacy_import: failed to start sapling decrypt thread");
                    for (int j = 0; j < launched; j++)
                        pthread_join(thr3[j], NULL);
                    goto cleanup;
                }
                launched++;
            }
            for (int i = 0; i < launched; i++)
                pthread_join(thr3[i], NULL);
        }

        /* Merge results and write to SQLite. */
        int shielded_outputs_seen = 0;
        int sapling_notes = 0;
        {
            bool sapling_tx_open = false;
            if (!legacy_import_begin_checked(ndb, "pass 3 commit begin")) {
                goto cleanup;
            }
            sapling_tx_open = true;
            for (int f = 0; f < num_files; f++) {
                shielded_outputs_seen += dctxs[f].outputs_seen;
                sapling_notes += dctxs[f].notes_found;
                for (int i = 0; i < dctxs[f].result_count; i++) {
                    if (!db_sapling_note_save(ndb, &dctxs[f].results[i])) {
                        LOG_WARN("legacy_import", "legacy_import: pass 3 sapling note save failed");
                        if (sapling_tx_open &&
                            !legacy_import_rollback_checked(ndb,
                                "pass 3 rollback")) {
                            LOG_WARN("legacy_import", "legacy_import: pass 3 rollback failed after DB error");
                        }
                        goto cleanup;
                    }
                }
                free(dctxs[f].results);
                dctxs[f].results = NULL;
                free(fctxs[f].hits);
                fctxs[f].hits = NULL;
                free(dctxs[f].tw.sapling_notes);
                dctxs[f].tw.sapling_notes = NULL;
            }
            if (!legacy_import_commit_checked(ndb, "pass 3 commit")) {
                sapling_tx_open = false;
                goto cleanup;
            }
            sapling_tx_open = false;
        }

        z_found = sapling_notes;
        platform_time_monotonic_timespec(&ts_p3);
        double p3_ms = (double)(ts_p3.tv_sec - ts_p2.tv_sec) * 1000.0 +
                       (double)(ts_p3.tv_nsec - ts_p2.tv_nsec) / 1e6;
        printf("legacy_import: pass 3 done in %.1f ms — %d blocks, "
               "%d candidates, %d shielded outputs, %d notes\n",
               p3_ms, total_blocks, total_candidates,
               shielded_outputs_seen, z_found);
        fflush(stdout);

        free(dctxs);
        dctxs = NULL;
        free(fctxs);
        fctxs = NULL;
    }

    /* Wallet keys are persisted exclusively by the encryption-aware
     * wallet_sqlite writer (single-writer doctrine); the import above
     * only adds transactions and notes. */

    /* Report final results. */
    int64_t t_bal = db_wallet_utxo_balance(ndb);
    int64_t z_bal = db_sapling_note_balance(ndb);
    int64_t total = t_bal + z_bal;

    struct timespec ts_end;
    platform_time_monotonic_timespec(&ts_end);
    double elapsed = (double)(ts_end.tv_sec - ts_start.tv_sec) +
                     (double)(ts_end.tv_nsec - ts_start.tv_nsec) / 1e9;

    printf("legacy_import: COMPLETE in %.1f seconds\n", elapsed);
    printf("  transparent: %.8f ZCL (%d UTXOs, %d txs)\n",
           (double)t_bal / 1e8, unspent, wl.count);
    printf("  shielded:    %.8f ZCL (%d notes)\n",
           (double)z_bal / 1e8, z_found);
    printf("  total:       %.8f ZCL\n", (double)total / 1e8);
    fflush(stdout);

    ret = wl.count;

cleanup:
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

    /* Cleanup. */
    scan_aht_free(&aht);
    scan_uset_free(&uset);
    scan_wl_free(&wl);
    free(file_has_match);

    return ret;
}
