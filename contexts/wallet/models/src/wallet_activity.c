/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Read-only wallet fact rows for the summary and history commands, built
 * with the typed query builder. */

#include "models/wallet_activity.h"
#include "models/query_builder.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WA_NCOLS(a) (sizeof(a) / sizeof((a)[0]))

static void wa_blob(sqlite3_stmt *s, int col, uint8_t *dst, size_t len)
{
    const void *p = sqlite3_column_blob(s, col);
    if (p && (size_t)sqlite3_column_bytes(s, col) == len)
        memcpy(dst, p, len);
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

static int wa_count(struct node_db *ndb, enum qb_table table)
{
    struct qb q;
    qb_select(&q, table);
    qb_select_count_star(&q);
    QB_QUERY_COUNT(ndb, &q, s);
}

/* ── notes ───────────────────────────────────────────────────────── */

static const enum qb_column k_note_cols[] = {
    QB_C_wallet_sapling_notes_txid, QB_C_wallet_sapling_notes_output_index,
    QB_C_wallet_sapling_notes_value, QB_C_wallet_sapling_notes_ivk,
    QB_C_wallet_sapling_notes_block_height,
    QB_C_wallet_sapling_notes_spent_txid, QB_C_wallet_sapling_notes_memo,
};

static void wa_fill_note(sqlite3_stmt *s, struct db_wallet_note_fact *f)
{
    memset(f, 0, sizeof(*f));
    wa_blob(s, 0, f->txid, 32);
    f->output_index = (uint32_t)sqlite3_column_int64(s, 1);
    f->value = sqlite3_column_int64(s, 2);
    wa_blob(s, 3, f->ivk, 32);
    f->block_height = (int)sqlite3_column_int64(s, 4);
    f->spent = wa_is_blob32(s, 5);
    if (f->spent)
        wa_blob(s, 5, f->spent_txid, 32);
    f->memo_present = wa_memo_present(sqlite3_column_blob(s, 6),
                                      sqlite3_column_bytes(s, 6));
}

static int wa_read_notes(struct node_db *ndb, struct db_wallet_note_fact *out,
                         size_t max)
{
    struct qb q;
    qb_select(&q, QB_T_wallet_sapling_notes);
    qb_select_columns(&q, k_note_cols, WA_NCOLS(k_note_cols));
    qb_order_by(&q, QB_C_wallet_sapling_notes_txid, QB_ASC);
    qb_order_by(&q, QB_C_wallet_sapling_notes_output_index, QB_ASC);
    QB_QUERY_LIST(ndb, &q, s, out, max, wa_fill_note(s, &out[count]));
}

int db_wallet_note_facts_alloc(struct node_db *ndb,
                               struct db_wallet_note_fact **out)
{
    *out = NULL;
    if (!ndb || !ndb->open)
        return -1;
    int n = wa_count(ndb, QB_T_wallet_sapling_notes);
    if (n <= 0)
        return n;
    struct db_wallet_note_fact *buf =
        zcl_calloc((size_t)n, sizeof(*buf), "wallet note facts");
    if (!buf)
        return -1;
    int got = wa_read_notes(ndb, buf, (size_t)n);
    *out = buf;
    return got;
}

/* ── coins ───────────────────────────────────────────────────────── */

static const enum qb_column k_coin_cols[] = {
    QB_C_wallet_utxos_txid, QB_C_wallet_utxos_vout, QB_C_wallet_utxos_value,
    QB_C_wallet_utxos_height, QB_C_wallet_utxos_spent_txid,
    QB_C_wallet_utxos_is_coinbase,
};

static void wa_fill_coin(sqlite3_stmt *s, struct db_wallet_coin_fact *f)
{
    memset(f, 0, sizeof(*f));
    wa_blob(s, 0, f->txid, 32);
    f->vout = (uint32_t)sqlite3_column_int64(s, 1);
    f->value = sqlite3_column_int64(s, 2);
    f->height = (int)sqlite3_column_int64(s, 3);
    f->spent = wa_is_blob32(s, 4);
    if (f->spent)
        wa_blob(s, 4, f->spent_txid, 32);
    f->coinbase = sqlite3_column_int64(s, 5) != 0;
}

static int wa_read_coins(struct node_db *ndb, struct db_wallet_coin_fact *out,
                         size_t max)
{
    struct qb q;
    qb_select(&q, QB_T_wallet_utxos);
    qb_select_columns(&q, k_coin_cols, WA_NCOLS(k_coin_cols));
    qb_order_by(&q, QB_C_wallet_utxos_txid, QB_ASC);
    qb_order_by(&q, QB_C_wallet_utxos_vout, QB_ASC);
    QB_QUERY_LIST(ndb, &q, s, out, max, wa_fill_coin(s, &out[count]));
}

int db_wallet_coin_facts_alloc(struct node_db *ndb,
                               struct db_wallet_coin_fact **out)
{
    *out = NULL;
    if (!ndb || !ndb->open)
        return -1;
    int n = wa_count(ndb, QB_T_wallet_utxos);
    if (n <= 0)
        return n;
    struct db_wallet_coin_fact *buf =
        zcl_calloc((size_t)n, sizeof(*buf), "wallet coin facts");
    if (!buf)
        return -1;
    int got = wa_read_coins(ndb, buf, (size_t)n);
    *out = buf;
    return got;
}

/* ── transactions ────────────────────────────────────────────────── */

static const enum qb_column k_tx_cols[] = {
    QB_C_wallet_transactions_txid, QB_C_wallet_transactions_block_height,
    QB_C_wallet_transactions_time_received, QB_C_wallet_transactions_from_me,
    QB_C_wallet_transactions_fee,
};

static void wa_fill_tx(sqlite3_stmt *s, struct db_wallet_tx_fact *f)
{
    memset(f, 0, sizeof(*f));
    wa_blob(s, 0, f->txid, 32);
    f->block_height = (int)sqlite3_column_int64(s, 1);
    f->time_received = sqlite3_column_int64(s, 2);
    f->from_me = sqlite3_column_int64(s, 3) != 0;
    f->fee = sqlite3_column_int64(s, 4);
}

static int wa_read_txs(struct node_db *ndb, struct db_wallet_tx_fact *out,
                       size_t max)
{
    struct qb q;
    qb_select(&q, QB_T_wallet_transactions);
    qb_select_columns(&q, k_tx_cols, WA_NCOLS(k_tx_cols));
    qb_order_by(&q, QB_C_wallet_transactions_txid, QB_ASC);
    QB_QUERY_LIST(ndb, &q, s, out, max, wa_fill_tx(s, &out[count]));
}

int db_wallet_tx_facts_alloc(struct node_db *ndb,
                             struct db_wallet_tx_fact **out)
{
    *out = NULL;
    if (!ndb || !ndb->open)
        return -1;
    int n = wa_count(ndb, QB_T_wallet_transactions);
    if (n <= 0)
        return n;
    struct db_wallet_tx_fact *buf =
        zcl_calloc((size_t)n, sizeof(*buf), "wallet tx facts");
    if (!buf)
        return -1;
    int got = wa_read_txs(ndb, buf, (size_t)n);
    *out = buf;
    return got;
}

/* ── memos of one transaction ────────────────────────────────────── */

static const enum qb_column k_memo_cols[] = {
    QB_C_wallet_sapling_notes_output_index, QB_C_wallet_sapling_notes_ivk,
    QB_C_wallet_sapling_notes_memo, QB_C_wallet_sapling_notes_address,
};

static void wa_fill_memo(sqlite3_stmt *s, struct db_wallet_note_memo *m)
{
    memset(m, 0, sizeof(*m));
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
    if (!ndb || !ndb->open || !txid || !out || max == 0)
        return 0;
    qb_select(&q, QB_T_wallet_sapling_notes);
    qb_select_columns(&q, k_memo_cols, WA_NCOLS(k_memo_cols));
    qb_where_blob(&q, QB_C_wallet_sapling_notes_txid, QB_EQ, txid, 32);
    qb_order_by(&q, QB_C_wallet_sapling_notes_output_index, QB_ASC);
    qb_limit(&q, (int64_t)max);
    QB_QUERY_LIST(ndb, &q, s, out, max, wa_fill_memo(s, &out[count]));
}
