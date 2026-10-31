/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Read-only wallet fact rows for the summary and history commands, built
 * with the typed query builder. A reader returns every row or fails; it never
 * returns the rows it managed to read before an error. */

#include "models/wallet_activity.h"
#include "models/query_builder.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WA_NCOLS(a) (sizeof(a) / sizeof((a)[0]))

typedef void (*wa_fill_fn)(sqlite3_stmt *s, void *row);

static void wa_blob(sqlite3_stmt *s, int col, uint8_t *dst, size_t len)
{
    const void *p = sqlite3_column_blob(s, col);
    if (p && (size_t)sqlite3_column_bytes(s, col) == len)
        memcpy(dst, p, len);
}

/* A spend marker is any non-NULL value, the test every other wallet query
 * applies (spent_txid IS NULL). A marker that is not a 32-byte id still
 * means spent. */
static bool wa_is_marked(sqlite3_stmt *s, int col)
{
    return sqlite3_column_type(s, col) != SQLITE_NULL;
}

static bool wa_is_blob32(sqlite3_stmt *s, int col)
{
    return sqlite3_column_type(s, col) == SQLITE_BLOB &&
           sqlite3_column_bytes(s, col) == 32;
}

static bool wa_memo_present(const void *p, int len)
{
    const uint8_t *b = p;
    for (int i = 0; b && i < len; i++)
        if (b[i] != 0x00 && b[i] != 0xf6)
            return true;
    return false;
}

/* Run q to completion into a heap array of `elem`-byte rows. Returns the row
 * count with *out set (NULL when empty), or -1 on a prepare, step or
 * allocation failure with *out NULL. */
static int wa_read_all(struct node_db *ndb, struct qb *q, size_t elem,
                       wa_fill_fn fill, void **out, const char *label)
{
    sqlite3_stmt *s = NULL;
    size_t cap = 0, n = 0;
    uint8_t *rows = NULL;
    int rc;

    *out = NULL;
    if (!ndb || !ndb->open || !qb_prepare_db(ndb->db, q, &s))
        return -1; // raw-return-ok:callee-logged
    while ((rc = AR_STEP_ROW_READONLY(s)) == SQLITE_ROW) {
        if (n == cap) {
            size_t ncap = cap ? cap * 2 : 64;
            uint8_t *grown = zcl_realloc(rows, ncap * elem, label);
            if (!grown) {
                free(rows);
                sqlite3_finalize(s);
                return -1; // raw-return-ok:callee-logged
            }
            rows = grown;
            cap = ncap;
        }
        memset(rows + n * elem, 0, elem);
        fill(s, rows + n * elem);
        n++;
    }
    if (rc != SQLITE_DONE)
        LOG_ERROR("wallet_activity", "%s read failed: %s", label,
                  sqlite3_errmsg(ndb->db));
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE || n > (size_t)INT_MAX) {
        free(rows);
        return -1;
    }
    *out = rows;
    return (int)n;
}

/* ── notes ───────────────────────────────────────────────────────── */

static const enum qb_column k_note_cols[] = {
    QB_C_wallet_sapling_notes_txid, QB_C_wallet_sapling_notes_output_index,
    QB_C_wallet_sapling_notes_value, QB_C_wallet_sapling_notes_ivk,
    QB_C_wallet_sapling_notes_block_height,
    QB_C_wallet_sapling_notes_spent_txid, QB_C_wallet_sapling_notes_memo,
    QB_C_wallet_sapling_notes_nullifier,
};

static void wa_fill_note(sqlite3_stmt *s, void *row)
{
    struct db_wallet_note_fact *f = row;
    wa_blob(s, 0, f->txid, 32);
    f->output_index = (uint32_t)sqlite3_column_int64(s, 1);
    f->value = sqlite3_column_int64(s, 2);
    wa_blob(s, 3, f->ivk, 32);
    f->block_height = (int)sqlite3_column_int64(s, 4);
    f->spent = wa_is_marked(s, 5);
    f->spent_txid_ok = wa_is_blob32(s, 5);
    if (f->spent_txid_ok)
        wa_blob(s, 5, f->spent_txid, 32);
    f->memo_present = wa_memo_present(sqlite3_column_blob(s, 6),
                                      sqlite3_column_bytes(s, 6));
    wa_blob(s, 7, f->nullifier, 32);
}

int db_wallet_note_facts_alloc(struct node_db *ndb,
                               struct db_wallet_note_fact **out)
{
    struct qb q;
    qb_select(&q, QB_T_wallet_sapling_notes);
    qb_select_columns(&q, k_note_cols, WA_NCOLS(k_note_cols));
    qb_order_by(&q, QB_C_wallet_sapling_notes_txid, QB_ASC);
    qb_order_by(&q, QB_C_wallet_sapling_notes_output_index, QB_ASC);
    return wa_read_all(ndb, &q, sizeof(**out), wa_fill_note, (void **)out,
                       "wallet note facts");
}

/* ── coins ───────────────────────────────────────────────────────── */

static const enum qb_column k_coin_cols[] = {
    QB_C_wallet_utxos_txid, QB_C_wallet_utxos_vout, QB_C_wallet_utxos_value,
    QB_C_wallet_utxos_height, QB_C_wallet_utxos_spent_txid,
    QB_C_wallet_utxos_is_coinbase,
};

static void wa_fill_coin(sqlite3_stmt *s, void *row)
{
    struct db_wallet_coin_fact *f = row;
    wa_blob(s, 0, f->txid, 32);
    f->vout = (uint32_t)sqlite3_column_int64(s, 1);
    f->value = sqlite3_column_int64(s, 2);
    f->height = (int)sqlite3_column_int64(s, 3);
    f->spent = wa_is_marked(s, 4);
    f->spent_txid_ok = wa_is_blob32(s, 4);
    if (f->spent_txid_ok)
        wa_blob(s, 4, f->spent_txid, 32);
    f->coinbase = sqlite3_column_int64(s, 5) != 0;
}

int db_wallet_coin_facts_alloc(struct node_db *ndb,
                               struct db_wallet_coin_fact **out)
{
    struct qb q;
    qb_select(&q, QB_T_wallet_utxos);
    qb_select_columns(&q, k_coin_cols, WA_NCOLS(k_coin_cols));
    qb_order_by(&q, QB_C_wallet_utxos_txid, QB_ASC);
    qb_order_by(&q, QB_C_wallet_utxos_vout, QB_ASC);
    return wa_read_all(ndb, &q, sizeof(**out), wa_fill_coin, (void **)out,
                       "wallet coin facts");
}

/* ── transactions ────────────────────────────────────────────────── */

static const enum qb_column k_tx_cols[] = {
    QB_C_wallet_transactions_txid, QB_C_wallet_transactions_block_height,
    QB_C_wallet_transactions_time_received, QB_C_wallet_transactions_from_me,
    QB_C_wallet_transactions_fee,
};

static void wa_fill_tx(sqlite3_stmt *s, void *row)
{
    struct db_wallet_tx_fact *f = row;
    wa_blob(s, 0, f->txid, 32);
    f->block_height = (int)sqlite3_column_int64(s, 1);
    f->time_received = sqlite3_column_int64(s, 2);
    f->from_me = sqlite3_column_int64(s, 3) != 0;
    f->fee = sqlite3_column_int64(s, 4);
}

int db_wallet_tx_facts_alloc(struct node_db *ndb,
                             struct db_wallet_tx_fact **out)
{
    struct qb q;
    qb_select(&q, QB_T_wallet_transactions);
    qb_select_columns(&q, k_tx_cols, WA_NCOLS(k_tx_cols));
    qb_order_by(&q, QB_C_wallet_transactions_txid, QB_ASC);
    return wa_read_all(ndb, &q, sizeof(**out), wa_fill_tx, (void **)out,
                       "wallet tx facts");
}

/* ── memos of one transaction ────────────────────────────────────── */

static const enum qb_column k_memo_cols[] = {
    QB_C_wallet_sapling_notes_output_index, QB_C_wallet_sapling_notes_ivk,
    QB_C_wallet_sapling_notes_memo, QB_C_wallet_sapling_notes_address,
};

static void wa_fill_memo(sqlite3_stmt *s, struct db_wallet_note_memo *m)
{
    m->output_index = (uint32_t)sqlite3_column_int64(s, 0);
    wa_blob(s, 1, m->ivk, 32);
    int len = sqlite3_column_bytes(s, 2);
    m->memo_len = len > 512 ? 512 : (size_t)(len > 0 ? len : 0);
    if (m->memo_len)
        memcpy(m->memo, sqlite3_column_blob(s, 2), m->memo_len);
    const char *addr = (const char *)sqlite3_column_text(s, 3);
    snprintf(m->address, sizeof(m->address), "%s", addr ? addr : "");
}

int db_wallet_note_memos_for_tx(struct node_db *ndb, const uint8_t txid[32],
                                struct db_wallet_note_memo *out, size_t max)
{
    struct qb q;
    sqlite3_stmt *s = NULL;
    size_t n = 0;
    int rc;
    if (!ndb || !ndb->open || !txid || !out || max == 0)
        return -1;
    qb_select(&q, QB_T_wallet_sapling_notes);
    qb_select_columns(&q, k_memo_cols, WA_NCOLS(k_memo_cols));
    qb_where_blob(&q, QB_C_wallet_sapling_notes_txid, QB_EQ, txid, 32);
    qb_order_by(&q, QB_C_wallet_sapling_notes_output_index, QB_ASC);
    qb_limit(&q, (int64_t)max);
    if (!qb_prepare_db(ndb->db, &q, &s))
        return -1; // raw-return-ok:callee-logged
    while ((rc = AR_STEP_ROW_READONLY(s)) == SQLITE_ROW && n < max) {
        memset(&out[n], 0, sizeof(out[n]));
        wa_fill_memo(s, &out[n]);
        n++;
    }
    sqlite3_finalize(s);
    return rc == SQLITE_ROW || rc == SQLITE_DONE ? (int)n : -1;
}
