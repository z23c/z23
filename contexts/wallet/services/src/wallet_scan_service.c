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

int wallet_scan_block_file_open(const char *path)
{
    if (!path)
        LOG_ERR("wallet_scan", "block file open: NULL path");
    int flags = O_RDONLY;
#ifdef O_BINARY
    flags |= O_BINARY;
#endif
#ifdef _WIN32
    flags |= _O_NOINHERIT;
#else
    flags |= O_CLOEXEC;
#endif
    int fd = open(path, flags);
    if (fd < 0)
        LOG_ERR("wallet_scan", "block file open failed: %s", path);
    return fd;
}

int wallet_scan_block_file_map(const char *path,
                               struct platform_read_mapping *mapping)
{
    platform_read_mapping_init(mapping);
    if (!mapping)
        LOG_ERR("wallet_scan", "block file map: NULL mapping");
    int fd = wallet_scan_block_file_open(path);
    if (fd < 0)
        LOG_ERR("wallet_scan", "block file map: open refused");
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0 ||
        (uintmax_t)st.st_size > (uintmax_t)SIZE_MAX ||
        !platform_read_mapping_open(mapping, fd, (size_t)st.st_size)) {
        close(fd);
        LOG_ERR("wallet_scan", "block file map failed: %s", path);
    }
    return fd;
}

const char *wallet_scan_hole_text(enum wallet_scan_hole_kind kind)
{
    switch (kind) {
    case WALLET_SCAN_HOLE_NO_BODY:
        return "has no block body";
    case WALLET_SCAN_HOLE_NO_FILE:
        return "block file is absent or cannot be mapped";
    case WALLET_SCAN_HOLE_BEYOND_FILE:
        return "block data position lies beyond its block file";
    case WALLET_SCAN_HOLE_UNPARSED:
        return "block data does not parse";
    case WALLET_SCAN_HOLE_HASH_MISMATCH:
        return "block data does not hash to the block its index entry names";
    case WALLET_SCAN_HOLE_NONE:
        break;
    }
    return "is readable";
}

bool wallet_scan_height_has_data(const struct block_index *pi)
{
    return pi && (pi->nStatus & BLOCK_HAVE_DATA);
}

bool wallet_scan_range_coverage(const struct active_chain *chain,
                                int start_height, int end_height,
                                struct wallet_scan_coverage *out)
{
    if (!out)
        LOG_FAIL("wallet_scan", "range coverage: NULL output");
    out->start_height = start_height;
    out->end_height = end_height;
    out->blocks_missing = 0;
    out->first_missing = -1;
    for (int64_t h = start_height; h <= (int64_t)end_height; h++) {
        const struct block_index *pi =
            chain ? active_chain_at(chain, (int)h) : NULL;
        if (wallet_scan_height_has_data(pi))
            continue;
        if (out->first_missing < 0)
            out->first_missing = (int)h;
        out->blocks_missing++;
    }
    return out->blocks_missing == 0;
}

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

/* Process a single block: check outputs for ownership, inputs for spends.
 * block_hash is the hash of `blk` itself, checked against its index entry;
 * every wallet transaction found carries it. */
static bool scan_block_txs(const struct block *blk, int height,
                            const uint8_t block_hash[32],
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
            memcpy(wt.block_hash, block_hash, 32);
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

/* Begin the SQLite write transaction that scopes a result write. */
static bool wallet_scan_begin_write_tx(struct node_db *ndb)
{
    return ndb && ndb->open && node_db_begin(ndb);
}

/* Clear both model-owned result tables inside the open write transaction. */
static bool wallet_scan_delete_result_rows(struct node_db *ndb)
{
    return db_wallet_utxo_delete_all(ndb) &&
           db_wallet_tx_delete_all(ndb);
}

/* Save one scanned output as a wallet_utxo row (INSERT OR REPLACE). */
static bool wallet_scan_save_utxo_row(struct node_db *ndb,
                                      struct scan_mem_utxo *u)
{
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
    return db_wallet_utxo_save(ndb, &du);
}

/* A stored coin (pre_existing) that a block of the range spends: mark the
 * row spent with that spend's txid and input index, unless the row is gone
 * or already spent, whose mark is never changed. The row itself is never
 * saved. Returns 0, or the store_utxo_rows code 2 or 3. */
static int wallet_scan_mark_stored_spent(struct node_db *ndb,
                                         const struct scan_mem_utxo *u)
{
    if (!u->spent)
        return 0;
    struct db_wallet_utxo have;
    memset(&have, 0, sizeof(have));
    bool exists = db_wallet_utxo_find(ndb, u->txid, u->vout, &have);
    bool already_spent = exists && have.is_spent;
    if (exists)
        db_wallet_utxo_free(&have);
    else if (sqlite3_errcode(ndb->db) != SQLITE_OK)
        return 3;
    if (!exists || already_spent)
        return 0;
    return db_wallet_utxo_mark_spent(ndb, u->txid, u->vout, u->spent_txid,
                                     u->spent_vin) ? 0 : 2;
}

/* Write the in-memory UTXO set as wallet_utxo rows, marking spends. A delta
 * scan (keep_existing) leaves a row that already exists as it is: the save
 * replaces the whole row and would clear its spent mark. A spend the scan
 * read from a block is marked either way; a stored coin loaded for a delta
 * only takes a spend mark. find answers false both for no row and for a
 * failed read; a failed read leaves the connection's error code set and
 * refuses, so a read error never turns into a replace. Returns 0 on
 * success, 1 when a wallet_utxo save failed, 2 when a mark_spent failed, 3
 * when the existing-row read failed; the caller logs and owns the rollback
 * path. */
static int wallet_scan_store_utxo_rows(struct node_db *ndb,
                                       struct scan_utxo_set *uset,
                                       bool keep_existing)
{
    for (int i = 0; i < uset->count; i++) {
        struct scan_mem_utxo *u = &uset->items[i];
        if (u->pre_existing) {
            int marked = wallet_scan_mark_stored_spent(ndb, u);
            if (marked != 0)
                return marked;
            continue;
        }
        struct db_wallet_utxo have;
        memset(&have, 0, sizeof(have));
        bool exists = keep_existing &&
                      db_wallet_utxo_find(ndb, u->txid, u->vout, &have);
        if (exists)
            db_wallet_utxo_free(&have);
        else if (keep_existing && sqlite3_errcode(ndb->db) != SQLITE_OK)
            return 3;
        if (!exists && !wallet_scan_save_utxo_row(ndb, u))
            return 1;
        if (u->spent &&
            !db_wallet_utxo_mark_spent(ndb, u->txid, u->vout,
                                       u->spent_txid, u->spent_vin))
            return 2;
    }
    return 0;
}

/* Save one scanned wallet transaction as a wallet_tx row. */
static bool wallet_scan_save_wtx_row(struct node_db *ndb,
                                     const struct scan_mem_wtx *t)
{
    struct db_wallet_tx dt;
    memset(&dt, 0, sizeof(dt));
    memcpy(dt.txid, t->txid, 32);
    dt.raw_tx = t->raw;
    dt.raw_tx_len = t->raw_len;
    dt.has_block = true;
    memcpy(dt.block_hash, t->block_hash, 32);
    dt.block_height = t->height;
    dt.time_received = (int64_t)t->time;
    dt.from_me = t->from_me;
    dt.fee = t->fee;
    return db_wallet_tx_save(ndb, &dt);
}

/* Write the in-memory wallet transaction list as wallet_tx rows. A delta
 * scan (keep_existing) skips a txid that already has a row: its from_me and
 * fee see only the outputs inside the delta, so its row would carry less.
 * Returns NULL on success, else the failure text; the caller logs and owns
 * the rollback path. */
static const char *wallet_scan_store_wtx_rows(struct node_db *ndb,
                                              struct scan_wtx_list *wl,
                                              bool keep_existing)
{
    for (int i = 0; i < wl->count; i++) {
        struct scan_mem_wtx *t = &wl->items[i];
        enum db_wallet_tx_presence have = keep_existing
            ? db_wallet_tx_presence_checked(ndb, t->txid)
            : DB_WALLET_TX_ABSENT;
        if (have == DB_WALLET_TX_ERROR)
            return "wallet_tx presence read failed";
        if (have == DB_WALLET_TX_ABSENT && !wallet_scan_save_wtx_row(ndb, t))
            return "wallet_tx save failed";
    }
    return NULL;
}

static void wallet_scan_free_utxo_rows(struct db_wallet_utxo *rows, int n)
{
    for (int i = 0; i < n; i++)
        db_wallet_utxo_free(&rows[i]);
    free(rows);
}

/* Every stored wallet_utxos row (unspent_only: the unspent ones), read
 * through the model listing, which takes a fixed maximum: the read grows
 * until it returns fewer rows than it asked for, so no row is cut off. The
 * listing answers 0 rows for a failed read too, so the connection's error
 * code decides. NULL (and *count -1) on a read or allocation failure. */
static struct db_wallet_utxo *wallet_scan_read_utxo_rows(struct node_db *ndb,
                                                        bool unspent_only,
                                                        int *count)
{
    *count = -1;
    for (size_t cap = 256; cap <= (size_t)INT32_MAX; cap *= 2) {
        struct db_wallet_utxo *rows =
            zcl_calloc(cap, sizeof(*rows), "wallet scan stored rows");
        if (!rows)
            return NULL; // raw-return-ok:zcl_calloc-logged
        int n = unspent_only ? db_wallet_utxo_list_unspent(ndb, rows, cap)
                             : db_wallet_utxo_list_all(ndb, rows, cap);
        bool read_ok = n >= 0 && sqlite3_errcode(ndb->db) == SQLITE_OK;
        if (read_ok && (size_t)n < cap) {
            *count = n;
            return rows;
        }
        wallet_scan_free_utxo_rows(rows, n > 0 ? n : 0);
        if (!read_ok)
            return NULL; // raw-return-ok:caller logs the refusal
    }
    return NULL; // raw-return-ok:caller logs the refusal
}

/* A stored wallet_utxos row the full replace writes back as it is: the scan
 * found its outpoint and, when it is stored spent, the same spend. */
static bool wallet_scan_utxo_rediscovered(const struct scan_utxo_set *uset,
                                          const struct db_wallet_utxo *row)
{
    int i = scan_uset_find(uset, row->txid, row->vout);
    if (i < 0)
        return false;
    const struct scan_mem_utxo *u = &uset->items[i];
    return !row->is_spent ||
           (u->spent && u->spent_vin == row->spent_vin &&
            memcmp(u->spent_txid, row->spent_txid, 32) == 0);
}

/* Stored wallet_utxos rows the scan did not rediscover; -1 when they cannot
 * be read. */
static int wallet_scan_count_underived_utxos(struct node_db *ndb,
                                             const struct scan_utxo_set *uset)
{
    int n = 0;
    struct db_wallet_utxo *rows = wallet_scan_read_utxo_rows(ndb, false, &n);
    if (!rows)
        return -1; // raw-return-ok:caller logs the refusal
    int underived = 0;
    for (int i = 0; i < n; i++)
        if (!wallet_scan_utxo_rediscovered(uset, &rows[i]))
            underived++;
    wallet_scan_free_utxo_rows(rows, n);
    return underived;
}

static int wallet_scan_txid_cmp(const void *a, const void *b)
{
    return memcmp(a, b, 32);
}

/* Stored wallet_transactions rows whose txid the scan did not find: the
 * stored count less the distinct found txids that have a row. -1 when a
 * read fails. */
static int wallet_scan_count_underived_txs(struct node_db *ndb,
                                           const struct scan_wtx_list *wl)
{
    int stored = db_wallet_tx_count(ndb);
    if (stored < 0 || sqlite3_errcode(ndb->db) != SQLITE_OK)
        return -1; // raw-return-ok:caller logs the refusal
    uint8_t (*ids)[32] = zcl_calloc((size_t)wl->count, 32,
                                    "wallet scan found txids");
    if (!ids)
        return -1; // raw-return-ok:zcl_calloc-logged
    for (int i = 0; i < wl->count; i++)
        memcpy(ids[i], wl->items[i].txid, 32);
    qsort(ids, (size_t)wl->count, 32, wallet_scan_txid_cmp);
    int rediscovered = 0;
    for (int i = 0; i < wl->count && rediscovered >= 0; i++) {
        if (i > 0 && memcmp(ids[i], ids[i - 1], 32) == 0)
            continue;
        enum db_wallet_tx_presence have =
            db_wallet_tx_presence_checked(ndb, ids[i]);
        if (have == DB_WALLET_TX_ERROR)
            rediscovered = -1;
        else if (have == DB_WALLET_TX_PRESENT)
            rediscovered++;
    }
    free(ids);
    return rediscovered < 0 ? -1 : stored - rediscovered;
}

/* A full replace that found a wallet transaction deletes every stored row
 * and writes back only what the scan derived. Rows a transparent block scan
 * cannot derive exist (shielded-only and unconfirmed transactions, watch-only
 * imports, a spend mark set by an unconfirmed spend), so the replace goes on
 * only when the scan rediscovered every stored row. Returns NULL to go on,
 * else the refusal text; the count is logged here, never a txid. */
static const char *wallet_scan_full_replace_check(
    struct node_db *ndb, const struct scan_utxo_set *uset,
    const struct scan_wtx_list *wl)
{
    int utxos = wallet_scan_count_underived_utxos(ndb, uset);
    int txs = utxos < 0 ? -1 : wallet_scan_count_underived_txs(ndb, wl);
    if (utxos < 0 || txs < 0)
        return "stored-row read before the full replace failed";
    if (utxos == 0 && txs == 0)
        return NULL;
    LOG_WARN("wallet_scan",
             "wallet_scan: full replace refused: %d stored rows (%d "
             "wallet_utxos, %d wallet_transactions) are not derivable from "
             "the block scan; wallet rows kept", utxos + txs, utxos, txs);
    return "full replace refused: stored rows are not derivable from the "
           "block scan";
}

/* Every write of one result, inside the open write transaction. A full scan
 * (from height 0) replaces both tables; one that found a wallet transaction
 * first proves the replace drops no row it cannot derive. A delta scan only
 * adds what it found and marks the stored coins its blocks spend. Returns
 * NULL on success, else the failure text for the caller to log before its
 * rollback. */
static const char *wallet_scan_write_result_rows(struct node_db *ndb,
                                                 bool delta,
                                                 struct scan_utxo_set *uset,
                                                 struct scan_wtx_list *wl)
{
    if (!delta && wl->count > 0) {
        const char *refused = wallet_scan_full_replace_check(ndb, uset, wl);
        if (refused)
            return refused;
    }
    if (!delta && !wallet_scan_delete_result_rows(ndb))
        return "model-owned result reset failed";
    int utxo_store = wallet_scan_store_utxo_rows(ndb, uset, delta);
    if (utxo_store == 1)
        return "wallet_utxo save failed";
    if (utxo_store == 2)
        return "wallet_utxo mark_spent failed";
    if (utxo_store == 3)
        return "wallet_utxo existing-row read failed";
    return wallet_scan_store_wtx_rows(ndb, wl, delta);
}

/* The sole durable write path for a completed transparent wallet scan.
 * A scan from height 0 replaces both tables with what it found, an empty
 * result included, in one transaction through the model-owned table APIs,
 * so Controllers never need table knowledge or a second commit/rollback
 * policy; a result that found a wallet transaction replaces them only when
 * no stored row would be lost. A scan that starts above 0 covers only a
 * delta (the boot catch-up above its cursor): it deletes no row, an empty
 * result writes nothing, a found row is added without replacing one that
 * already exists, and a stored coin a block of the delta spends is marked
 * spent. */
/* True when a delta result has anything to write: a found row, or a block's
 * spend of a stored coin. */
static bool wallet_scan_delta_has_writes(const struct scan_utxo_set *uset,
                                         const struct scan_wtx_list *wl)
{
    if (wl->count > 0)
        return true;
    for (int i = 0; i < uset->count; i++)
        if (!uset->items[i].pre_existing || uset->items[i].spent)
            return true;
    return false;
}

static int wallet_scan_store_results(struct node_db *ndb, int start_height,
                                     struct scan_utxo_set *uset,
                                     struct scan_wtx_list *wl)
{
    bool write_tx_open = false;
    bool delta = start_height > 0;

    if (delta && !wallet_scan_delta_has_writes(uset, wl)) {
        printf("wallet_scan: delta from height %d found no wallet rows; "
               "existing rows kept\n", start_height);
        fflush(stdout);
        return 0;
    }
    if (!wallet_scan_begin_write_tx(ndb))
        LOG_ERR("wallet_scan", "result write begin failed: %s",
                (ndb && ndb->db) ? sqlite3_errmsg(ndb->db)
                                 : "db unavailable");
    write_tx_open = true;
    const char *write_failed =
        wallet_scan_write_result_rows(ndb, delta, uset, wl);
    if (write_failed) {
        LOG_WARN("wallet_scan", "wallet_scan: %s", write_failed);
        goto write_fail;
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

/* The one block file Pass 2 holds mapped while it walks the range. */
struct wallet_scan_pass2_file {
    int file; /* mapped block file number, -1 when none */
    int fd;
    struct platform_read_mapping mapping;
};

static void wallet_scan_pass2_file_close(struct wallet_scan_pass2_file *f)
{
    platform_read_mapping_close(&f->mapping);
    if (f->fd >= 0)
        close(f->fd);
    f->fd = -1;
    f->file = -1;
}

/* Map block file `nfile` unless it is the one already mapped. False when it
 * cannot be mapped; nothing is then mapped. */
static bool wallet_scan_pass2_file_select(struct wallet_scan_pass2_file *f,
                                          const char *datadir, int nfile)
{
    if (f->file == nfile)
        return true;
    wallet_scan_pass2_file_close(f);
    char path[512];
    int n = snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat",
                     datadir, nfile);
    if (n < 0 || (size_t)n >= sizeof(path))
        return false; // raw-return-ok:caller logs the hole with its height
    int fd = wallet_scan_block_file_map(path, &f->mapping);
    if (fd < 0)
        return false; // raw-return-ok:caller logs the hole with its height
    f->fd = fd;
    f->file = nfile;
    platform_read_mapping_advise_sequential(&f->mapping);
    return true;
}

/* The per-height checks that need no file read: a hole when the height has
 * no body or its file lies outside the counted files. NONE otherwise, with
 * *matched telling whether Pass 1 matched its file (unmatched: skip unread).
 * A NULL file_has_match reads every file. */
static enum wallet_scan_hole_kind wallet_scan_pass2_locate(
    const struct block_index *pi, const bool *file_has_match, int num_files,
    bool *matched)
{
    *matched = false;
    if (!wallet_scan_height_has_data(pi))
        return WALLET_SCAN_HOLE_NO_BODY;
    if (pi->nFile < 0 || pi->nFile >= num_files)
        return WALLET_SCAN_HOLE_NO_FILE;
    *matched = !file_has_match || file_has_match[pi->nFile];
    return WALLET_SCAN_HOLE_NONE;
}

/* Read and parse the block of one height whose file Pass 1 matched. `blk` is
 * initialized first on every path. WALLET_SCAN_HOLE_NONE: `blk` holds the
 * block (caller frees it) and `hash` its hash, which equals the hash the
 * index entry names. Any other kind is a hole and `blk` holds nothing to
 * free: bytes that parse as some other block, or under an entry that names
 * no hash, are not the block of this height. */
static enum wallet_scan_hole_kind wallet_scan_pass2_read(
    const struct block_index *pi, const char *datadir,
    struct wallet_scan_pass2_file *f, struct block *blk, uint8_t hash[32])
{
    block_init(blk);
    if (!wallet_scan_pass2_file_select(f, datadir, pi->nFile))
        return WALLET_SCAN_HOLE_NO_FILE;
    if (!f->mapping.data || pi->nDataPos >= f->mapping.size)
        return WALLET_SCAN_HOLE_BEYOND_FILE;
    struct byte_stream bs;
    stream_init_from_data(&bs, f->mapping.data + pi->nDataPos,
                          f->mapping.size - pi->nDataPos);
    if (!block_deserialize(blk, &bs)) {
        block_free(blk);
        return WALLET_SCAN_HOLE_UNPARSED;
    }
    struct uint256 parsed;
    block_get_hash(blk, &parsed);
    if (!pi->phashBlock ||
        memcmp(pi->phashBlock->data, parsed.data, 32) != 0) {
        block_free(blk);
        return WALLET_SCAN_HOLE_HASH_MISMATCH;
    }
    memcpy(hash, parsed.data, 32);
    return WALLET_SCAN_HOLE_NONE;
}

/* Where Pass 2 stopped, when it stopped at a hole. */
struct wallet_scan_pass2_hole {
    int height;
    int file;
    enum wallet_scan_hole_kind kind;
};

/* Walk [start_height, end_height] in height order (spend tracking needs it)
 * and fold into uset/wl every block of a Pass-1-matched file (every file
 * when file_has_match is NULL), and every block at or after the first height
 * where uset holds a coin. Returns -1 having stopped at the
 * first hole, which it stores in *hole; otherwise the number of blocks
 * deserialized. Every height is checked before the file filter, so this is
 * also the scan-time recheck of the caller's coverage guard. */
static int wallet_scan_pass2_walk(const struct active_chain *chain,
                                  const char *datadir,
                                  int start_height, int end_height,
                                  const struct scan_addr_ht *aht,
                                  const bool *file_has_match, int num_files,
                                  struct scan_utxo_set *uset,
                                  struct scan_wtx_list *wl,
                                  struct wallet_scan_pass2_hole *hole)
{
    int blocks_deserialized = 0;
    struct wallet_scan_pass2_file f = {.file = -1, .fd = -1};
    platform_read_mapping_init(&f.mapping);

    for (int h = start_height; h <= end_height; h++) {
        const struct block_index *pi = active_chain_at(chain, h);
        struct block blk;
        uint8_t block_hash[32];
        bool matched = false;
        enum wallet_scan_hole_kind kind = wallet_scan_pass2_locate(
            pi, file_has_match, num_files, &matched);
        /* Skip files that pass 1 read and ruled out, unparsed, only while
         * no wallet coin is held: Pass 1 matches output scripts, so a block
         * that spends a held coin and pays no wallet key sits in a file it
         * ruled out. From the first coin on, every height is parsed. */
        if (kind == WALLET_SCAN_HOLE_NONE && !matched && uset->count == 0)
            continue;
        if (kind == WALLET_SCAN_HOLE_NONE)
            kind = wallet_scan_pass2_read(pi, datadir, &f, &blk, block_hash);
        if (kind != WALLET_SCAN_HOLE_NONE) {
            *hole = (struct wallet_scan_pass2_hole){
                .height = h, .file = pi ? pi->nFile : -1, .kind = kind,
            };
            blocks_deserialized = -1;
            break;
        }
        blocks_deserialized++;
        (void)scan_block_txs(&blk, h, block_hash, aht, uset, wl);
        block_free(&blk);
    }
    wallet_scan_pass2_file_close(&f);
    return blocks_deserialized;
}

/* Log the hole Pass 2 stopped at and record it in the caller's coverage. */
static int wallet_scan_pass2_refuse(const struct wallet_scan_pass2_hole *hole,
                                    int start_height, int end_height,
                                    struct wallet_scan_coverage *cov)
{
    LOG_WARN("wallet_scan",
             "wallet_scan: height %d (block file %d) %s; scan of %d..%d "
             "refused, wallet rows kept", hole->height, hole->file,
             wallet_scan_hole_text(hole->kind), start_height, end_height);
    if (cov) {
        cov->first_missing = hole->height;
        if (cov->blocks_missing < 1)
            cov->blocks_missing = 1;
    }
    return WALLET_SCAN_REFUSED_MISSING_DATA;
}

/* A delta given Pass-1 file results rereads the stored unspent coins before
 * its walk. The zero-key and empty-range paths read no block. */
static bool wallet_scan_delta_reads_stored(int start_height, int end_height,
                                           const bool *file_has_match,
                                           int num_files)
{
    return start_height > 0 && start_height <= end_height &&
           file_has_match && num_files > 0;
}

/* One stored unspent wallet_utxos row as a pre-existing coin of uset. Its
 * script is not kept: the row is never saved again. */
static bool wallet_scan_add_stored(struct scan_utxo_set *uset,
                                   const struct db_wallet_utxo *row)
{
    struct scan_mem_utxo u;
    memset(&u, 0, sizeof(u));
    memcpy(u.txid, row->txid, 32);
    u.vout = row->vout;
    u.value = row->value;
    memcpy(u.addr_hash, row->address_hash, 20);
    u.height = row->height;
    u.is_coinbase = row->is_coinbase;
    u.pre_existing = true;
    return scan_uset_add(uset, &u);
}

/* Load the stored unspent wallet_utxos rows into uset, so an input in a
 * block of the delta that spends one is seen even though the coin was made
 * below the delta. Returns the number loaded, or -1 (logged) when they
 * cannot be read or held: the scan then refuses with every row and the
 * cursor unchanged. */
static int wallet_scan_load_stored_unspent(struct node_db *ndb,
                                           struct scan_utxo_set *uset)
{
    int n = 0;
    struct db_wallet_utxo *rows = wallet_scan_read_utxo_rows(ndb, true, &n);
    if (!rows) {
        LOG_ERR("wallet_scan", "wallet_scan: delta: stored unspent "
                "wallet_utxos read failed: %s; scan refused, wallet rows kept",
                ndb->db ? sqlite3_errmsg(ndb->db) : "db unavailable");
        return -1; // raw-return-ok:logged-above
    }
    int held = 0;
    for (int i = 0; i < n; i++)
        held += wallet_scan_add_stored(uset, &rows[i]) ? 1 : 0;
    wallet_scan_free_utxo_rows(rows, n);
    if (held != n) {
        LOG_ERR("wallet_scan", "wallet_scan: delta: held %d of %d stored "
                "unspent wallet_utxos rows; scan refused, wallet rows kept",
                held, n);
        return -1; // raw-return-ok:logged-above
    }
    return n;
}

static int wallet_scan_pass2_nonempty(struct node_db *ndb,
                                      const struct active_chain *chain,
                                      const char *datadir,
                                      int start_height,
                                      int end_height,
                                      const struct scan_addr_ht *aht,
                                      const bool *file_has_match,
                                      int num_files,
                                      const struct timespec *ts_start,
                                      const struct timespec *ts_p1,
                                      struct wallet_scan_coverage *cov)
{
    struct timespec ts_p2;

    /* ========== PASS 2: Selective block deserialization ========== */
    struct scan_utxo_set uset;
    scan_uset_init(&uset);
    struct scan_wtx_list wl;
    scan_wl_init(&wl);

    /* A delta holding stored unspent coins parses every height (the walk
     * parses every height once uset holds a coin): a block that only spends
     * one pays no wallet key, so Pass 1 cannot match its file. */
    int stored = wallet_scan_delta_reads_stored(start_height, end_height,
                                                file_has_match, num_files)
                 ? wallet_scan_load_stored_unspent(ndb, &uset) : 0;
    if (stored < 0) {
        scan_uset_free(&uset);
        scan_wl_free(&wl);
        return -1; // raw-return-ok:logged-in-wallet_scan_load_stored_unspent
    }

    struct wallet_scan_pass2_hole hole = {.height = -1, .file = -1};
    int blocks_deserialized = wallet_scan_pass2_walk(
        chain, datadir, start_height, end_height, aht,
        file_has_match, num_files, &uset, &wl, &hole);
    if (blocks_deserialized < 0) {
        scan_uset_free(&uset);
        scan_wl_free(&wl);
        return wallet_scan_pass2_refuse(&hole, start_height, end_height, cov);
    }
    if (uset.dropped > 0) {
        LOG_ERR("wallet_scan", "wallet_scan: %d wallet outputs of %d..%d "
                "could not be held in memory; scan refused, wallet rows kept",
                uset.dropped, start_height, end_height);
        scan_uset_free(&uset);
        scan_wl_free(&wl);
        return -1; // raw-return-ok:logged-above
    }

    platform_time_monotonic_timespec(&ts_p2);
    double p2_ms = (double)(ts_p2.tv_sec - ts_p1->tv_sec) * 1000.0 +
                   (double)(ts_p2.tv_nsec - ts_p1->tv_nsec) / 1e6;
    double total_ms = (double)(ts_p2.tv_sec - ts_start->tv_sec) * 1000.0 +
                      (double)(ts_p2.tv_nsec - ts_start->tv_nsec) / 1e6;

    int unspent = 0;
    for (int i = 0; i < uset.count; i++) {
        if (!uset.items[i].spent && !uset.items[i].pre_existing) {
            unspent++;
        }
    }

    printf("wallet_scan: pass 2 done in %.1f ms — %d blocks deserialized, "
           "%d wallet txs\n", p2_ms, blocks_deserialized, wl.count);
    printf("wallet_scan: TOTAL %.1f ms — %d unspent UTXOs\n",
           total_ms, unspent);
    fflush(stdout);

    int result = wallet_scan_store_results(ndb, start_height, &uset, &wl);

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
                              int num_files,
                              int matched_files,
                              const struct timespec *ts_start,
                              const struct timespec *ts_p1,
                              struct wallet_scan_coverage *cov)
{
    if (matched_files < 0)
        LOG_ERR("wallet_scan", "negative matched-file count: %d",
                matched_files);

    /* Keep the empty replacement outside the nonempty worker's large stack
     * frame and heap working sets on every compiler/profile. A delta that
     * rereads stored coins walks its range even with no matched file. */
    if (matched_files == 0 &&
        !wallet_scan_delta_reads_stored(start_height, end_height,
                                        file_has_match, num_files)) {
        struct scan_utxo_set empty_uset = {0};
        struct scan_wtx_list empty_wl = {0};
        return wallet_scan_store_results(ndb, start_height,
                                         &empty_uset, &empty_wl);
    }

    return wallet_scan_pass2_nonempty(ndb, chain, datadir,
                                      start_height, end_height,
                                      aht, file_has_match, num_files,
                                      ts_start, ts_p1, cov);
}
