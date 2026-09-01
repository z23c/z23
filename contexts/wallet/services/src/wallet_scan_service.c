/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * wallet_scan_service — Pass 2 of the fast wallet block scanner.
 *
 * Extracted verbatim from the wallet_scan Controller
 * (contexts/wallet/controllers/src/wallet_scan.c). The Controller parses/validates and
 * runs Pass 1 (the parallel raw-byte pattern scan); this Service runs Pass 2:
 *   - selective deserialization of the blocks Pass 1 flagged
 *   - the in-memory UTXO/balance compute
 *   - the SQLite transaction scope that writes the results.
 *
 * The recovery-primitive callers of wallet_scan_blocks
 * (wallet_rescan_controller, wallet_diagnostic_repair) consume a bare int and
 * are explicitly locked, so this Pass-2 entry deliberately keeps the int
 * contract rather than migrating to struct zcl_result. */

// one-result-type-ok:locked-int-recovery-primitive — wallet_scan_blocks and
// its recovery-primitive callers (wallet_rescan_controller,
// wallet_diagnostic_repair) consume a bare int and are explicitly locked;
// this Pass-2 entry keeps the same int contract (number of wallet txns, or
// -1 on error) so the Controller can return it verbatim.

#include "services/wallet_scan_service.h"
#include "platform/read_mapping.h"
#include "platform/time_compat.h"
#include "models/wallet_tx.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "validation/chainstate.h"
#include "core/serialize.h"
#include "services/scan_util.h"
#include "views/format_helpers.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static void wallet_scan_rollback_best_effort(struct node_db *ndb,
                                             const char *label)
{
    if (!ndb || !ndb->open)
        return;
    if (!node_db_rollback(ndb)) {
        LOG_WARN("wallet_scan", "wallet_scan: %s failed: %s", label, ndb->db ? sqlite3_errmsg(ndb->db) : "db unavailable");
    }
}

static uint8_t *ser_tx(const struct transaction *tx, size_t *len)
{
    struct byte_stream s;
    stream_init(&s, 512);
    transaction_serialize(tx, &s);
    *len = s.size;
    return s.data;
}

/* --- Pass 2: Selective deserialization --- */

/* Process a single block: check outputs for ownership, inputs for spends */
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

/* The sole durable write path for a completed transparent wallet scan.
 * An empty result uses the same transaction and model-owned table APIs as a
 * populated result, so Controllers never need table knowledge or a second
 * commit/rollback policy. */
static int wallet_scan_store_results(struct node_db *ndb,
                                     struct scan_utxo_set *uset,
                                     struct scan_wtx_list *wl)
{
    bool write_tx_open = false;

    if (!ndb || !ndb->open || !node_db_begin(ndb))
        LOG_ERR("wallet_scan", "result write begin failed: %s",
                (ndb && ndb->db) ? sqlite3_errmsg(ndb->db)
                                 : "db unavailable");
    write_tx_open = true;
    if (!db_wallet_utxo_delete_all(ndb) ||
        !db_wallet_tx_delete_all(ndb)) {
        LOG_WARN("wallet_scan",
                 "wallet_scan: model-owned result reset failed");
        goto write_fail;
    }

    for (int i = 0; i < uset->count; i++) {
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
            LOG_WARN("wallet_scan", "wallet_scan: wallet_utxo save failed");
            goto write_fail;
        }
        if (u->spent &&
            !db_wallet_utxo_mark_spent(ndb, u->txid, u->vout,
                                       u->spent_txid, u->spent_vin)) {
            LOG_WARN("wallet_scan",
                     "wallet_scan: wallet_utxo mark_spent failed");
            goto write_fail;
        }
    }

    for (int i = 0; i < wl->count; i++) {
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
            LOG_WARN("wallet_scan", "wallet_scan: wallet_tx save failed");
            goto write_fail;
        }
    }

    if (!node_db_commit(ndb)) {
        LOG_WARN("wallet_scan", "wallet_scan: result write commit failed: %s",
                 ndb->db ? sqlite3_errmsg(ndb->db) : "db unavailable");
        goto write_fail;
    }
    write_tx_open = false;
    return wl->count;

write_fail:
    if (write_tx_open)
        wallet_scan_rollback_best_effort(ndb, "result write rollback");
    LOG_ERR("wallet_scan",
            "result write failed; previous wallet projection retained");
}

static int wallet_scan_pass2_nonempty(struct node_db *ndb,
                                      const struct active_chain *chain,
                                      const char *datadir,
                                      int start_height,
                                      int end_height,
                                      const struct scan_addr_ht *aht,
                                      const bool *file_has_match,
                                      const struct timespec *ts_start,
                                      const struct timespec *ts_p1)
{
    struct timespec ts_p2;

    /* ========== PASS 2: Selective block deserialization ========== */
    struct scan_utxo_set uset;
    scan_uset_init(&uset);
    struct scan_wtx_list wl;
    scan_wl_init(&wl);

    /* We need to process blocks in height order for correct spend tracking.
     * Build a set of heights whose blocks are in matched files, then
     * iterate heights in order. */

    /* First, find which heights map to matched files */
    int blocks_deserialized = 0;
    int cached_file = -1;
    int cached_fd = -1;
    struct platform_read_mapping cached_mapping;
    platform_read_mapping_init(&cached_mapping);

    for (int h = start_height; h <= end_height; h++) {
        const struct block_index *pi = active_chain_at(chain, h);
        if (!pi) continue;
        if (!(pi->nStatus & BLOCK_HAVE_DATA)) continue;

        /* Skip files that pass 1 ruled out */
        if (!file_has_match[pi->nFile]) continue;

        if (pi->nFile != cached_file) {
            platform_read_mapping_close(&cached_mapping);
            if (cached_fd >= 0) {
                close(cached_fd);
                cached_fd = -1;
            }
            cached_file = -1;
            char path[512];
            snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat",
                     datadir, pi->nFile);
            int fd = open(path, O_RDONLY);
            if (fd < 0) continue;
            struct stat st;
            if (fstat(fd, &st) != 0) { close(fd); continue; }
            if (st.st_size <= 0 ||
                (uintmax_t)st.st_size > (uintmax_t)SIZE_MAX) {
                close(fd);
                continue;
            }
            if (!platform_read_mapping_open(&cached_mapping, fd,
                                            (size_t)st.st_size)) {
                close(fd);
                continue;
            }
            cached_fd = fd;
            cached_file = pi->nFile;
            platform_read_mapping_advise_sequential(&cached_mapping);
        }
        if (!cached_mapping.data ||
            pi->nDataPos >= cached_mapping.size) continue;

        struct block blk;
        block_init(&blk);
        size_t rem = cached_mapping.size - pi->nDataPos;
        struct byte_stream bs;
        stream_init_from_data(&bs,
                              cached_mapping.data + pi->nDataPos, rem);
        if (!block_deserialize(&blk, &bs)) {
            block_free(&blk);
            continue;
        }
        blocks_deserialized++;

        (void)scan_block_txs(&blk, h, aht, &uset, &wl);

        block_free(&blk);
    }
    platform_read_mapping_close(&cached_mapping);
    if (cached_fd >= 0)
        close(cached_fd);

    platform_time_monotonic_timespec(&ts_p2);
    double p2_ms = (double)(ts_p2.tv_sec - ts_p1->tv_sec) * 1000.0 +
                   (double)(ts_p2.tv_nsec - ts_p1->tv_nsec) / 1e6;
    double total_ms = (double)(ts_p2.tv_sec - ts_start->tv_sec) * 1000.0 +
                      (double)(ts_p2.tv_nsec - ts_start->tv_nsec) / 1e6;

    /* Compute balance */
    int64_t balance = 0;
    int unspent = 0;
    for (int i = 0; i < uset.count; i++) {
        if (!uset.items[i].spent) {
            balance += uset.items[i].value;
            unspent++;
        }
    }

    printf("wallet_scan: pass 2 done in %.1f ms — %d blocks deserialized, "
           "%d wallet txs\n", p2_ms, blocks_deserialized, wl.count);
    printf("wallet_scan: TOTAL %.1f ms — %d unspent UTXOs, "
           "balance %.8f ZCL\n",
           total_ms, unspent, (double)balance / (double)ZATOSHI_PER_ZCL);
    fflush(stdout);

    int result = wallet_scan_store_results(ndb, &uset, &wl);

    /* Cleanup */
    scan_uset_free(&uset);
    scan_wl_free(&wl);

    return result;
}

int wallet_scan_pass2_execute(struct node_db *ndb,
                              const struct active_chain *chain,
                              const char *datadir,
                              int start_height,
                              int end_height,
                              const struct scan_addr_ht *aht,
                              const bool *file_has_match,
                              int matched_files,
                              const struct timespec *ts_start,
                              const struct timespec *ts_p1)
{
    if (matched_files < 0)
        LOG_ERR("wallet_scan", "negative matched-file evidence: %d",
                matched_files);

    /* Keep the empty replacement outside the nonempty worker's large stack
     * frame and heap working sets on every compiler/profile. */
    if (matched_files == 0) {
        struct scan_utxo_set empty_uset = {0};
        struct scan_wtx_list empty_wl = {0};
        return wallet_scan_store_results(ndb, &empty_uset, &empty_wl);
    }

    return wallet_scan_pass2_nonempty(ndb, chain, datadir,
                                      start_height, end_height,
                                      aht, file_has_match,
                                      ts_start, ts_p1);
}
