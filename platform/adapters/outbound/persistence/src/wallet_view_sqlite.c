/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * wallet_view_sqlite — sqlite implementation of wallet_view_port.
 *
 * This adapter is the only place that names sqlite for the wallet_view
 * surface. The SQL text and column order are fixed so the explorer /
 * wallet UI surface is byte-for-byte identical.
 */

#include "adapters/outbound/persistence/wallet_view_sqlite.h"

#include "util/ar_step_readonly.h"

#include <stdio.h>

/* `self` aliases the sqlite3* directly — there is no wrapper struct. */
static inline sqlite3 *db_of(void *self) { return (sqlite3 *)self; }

static int wv_list_receive_addresses_sqlite(
    void *self, struct wallet_view_receive_address *out, size_t max)
{
    sqlite3 *db = db_of(self);
    sqlite3_stmt *s = NULL;
    size_t count = 0;

    if (!db || !out || max == 0)
        return 0;

    if (sqlite3_prepare_v2(db,
            "SELECT address FROM wallet_sapling_keys "
            "WHERE address IS NOT NULL AND length(address) > 0 "
            "ORDER BY rowid",
            -1, &s, NULL) != SQLITE_OK || !s)
        return 0;

    while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW && count < max) {
        const char *raw = (const char *)sqlite3_column_text(s, 0);
        if (!raw || !raw[0])
            continue;
        snprintf(out[count].address, sizeof(out[count].address), "%s", raw);
        count++;
    }
    sqlite3_finalize(s);
    return (int)count;
}

static int wv_list_held_tokens_sqlite(
    void *self, struct wallet_view_held_token *out, size_t max)
{
    sqlite3 *db = db_of(self);
    sqlite3_stmt *s = NULL;
    size_t count = 0;

    if (!db || !out || max == 0)
        return 0;

    if (sqlite3_prepare_v2(db,
            "SELECT hex(t.token_id), t.ticker, t.decimals "
            "FROM zslp_tokens t "
            "JOIN zslp_transfers tr ON tr.token_id = t.token_id "
            "WHERE tr.to_addr IN (SELECT pubkey_hash FROM wallet_keys) "
            "  AND tr.tx_type IN ('GENESIS','MINT','SEND') "
            "GROUP BY t.token_id HAVING SUM(tr.amount) > 0 "
            "ORDER BY SUM(tr.amount) DESC LIMIT 10",
            -1, &s, NULL) != SQLITE_OK || !s)
        return 0;

    while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW && count < max) {
        const char *tid = (const char *)sqlite3_column_text(s, 0);
        const char *ticker = (const char *)sqlite3_column_text(s, 1);
        int decimals = sqlite3_column_int(s, 2);

        if (!tid || !ticker)
            continue;
        snprintf(out[count].token_id, sizeof(out[count].token_id), "%s", tid);
        snprintf(out[count].ticker, sizeof(out[count].ticker), "%s", ticker);
        out[count].decimals = decimals;
        count++;
    }
    sqlite3_finalize(s);
    return (int)count;
}

/* ── Page-projection queries ──────────────────────────────────
 * Byte-exact SQL for the wallet_view page projections; this adapter is
 * the only place that names sqlite. Column order is preserved so the
 * rendered pages stay identical. */

static int wv_list_token_cards_sqlite(
    void *self, struct wallet_view_token_balance *out, size_t max)
{
    sqlite3 *db = db_of(self);
    sqlite3_stmt *s = NULL;
    size_t count = 0;

    if (!db || !out || max == 0)
        return 0;

    /* Dashboard token cards: ticker + name + decimals + balance. */
    if (sqlite3_prepare_v2(db,
            "SELECT t.ticker, t.name, t.decimals, SUM(tr.amount) as bal "
            "FROM zslp_tokens t "
            "JOIN zslp_transfers tr ON tr.token_id = t.token_id "
            "WHERE tr.to_addr IN (SELECT pubkey_hash FROM wallet_keys) "
            "  AND tr.tx_type IN ('GENESIS','MINT','SEND') "
            "GROUP BY t.token_id HAVING bal > 0 "
            "ORDER BY bal DESC LIMIT 5",
            -1, &s, NULL) != SQLITE_OK || !s)
        return 0;

    while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW && count < max) {
        const char *ticker = (const char *)sqlite3_column_text(s, 0);
        out[count].token_id[0] = '\0';
        snprintf(out[count].ticker, sizeof(out[count].ticker), "%s",
                 ticker ? ticker : "");
        out[count].name[0] = '\0';
        out[count].decimals = sqlite3_column_int(s, 2);
        out[count].balance = sqlite3_column_int64(s, 3);
        count++;
    }
    sqlite3_finalize(s);
    return (int)count;
}

static int wv_list_token_balances_sqlite(
    void *self, struct wallet_view_token_balance *out, size_t max)
{
    sqlite3 *db = db_of(self);
    sqlite3_stmt *s = NULL;
    size_t count = 0;

    if (!db || !out || max == 0)
        return 0;

    /* Coins page token table: hex(token_id) + ticker + name + decimals +
     * balance. */
    if (sqlite3_prepare_v2(db,
            "SELECT hex(t.token_id), t.ticker, t.name, t.decimals, "
            "  SUM(tr.amount) as balance "
            "FROM zslp_tokens t "
            "JOIN zslp_transfers tr ON tr.token_id = t.token_id "
            "WHERE tr.to_addr IN (SELECT pubkey_hash FROM wallet_keys) "
            "  AND tr.tx_type IN ('GENESIS','MINT','SEND') "
            "GROUP BY t.token_id "
            "HAVING balance > 0 "
            "ORDER BY balance DESC LIMIT 50",
            -1, &s, NULL) != SQLITE_OK || !s)
        return 0;

    while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW && count < max) {
        const char *tid = (const char *)sqlite3_column_text(s, 0);
        const char *ticker = (const char *)sqlite3_column_text(s, 1);
        const char *name = (const char *)sqlite3_column_text(s, 2);
        snprintf(out[count].token_id, sizeof(out[count].token_id), "%s",
                 tid ? tid : "");
        snprintf(out[count].ticker, sizeof(out[count].ticker), "%s",
                 ticker ? ticker : "");
        snprintf(out[count].name, sizeof(out[count].name), "%s",
                 name ? name : "");
        out[count].decimals = sqlite3_column_int(s, 3);
        out[count].balance = sqlite3_column_int64(s, 4);
        count++;
    }
    sqlite3_finalize(s);
    return (int)count;
}

static int wv_list_unspent_coins_sqlite(
    void *self, struct wallet_view_coin *out, size_t max)
{
    sqlite3 *db = db_of(self);
    sqlite3_stmt *s = NULL;
    size_t count = 0;

    if (!db || !out || max == 0)
        return 0;

    if (sqlite3_prepare_v2(db,
            "SELECT hex(wu.txid), wu.vout, wu.value, wu.height, "
            "  CASE WHEN wu.is_coinbase THEN 'Coinbase' ELSE 'Standard' END "
            "FROM wallet_utxos wu "
            "WHERE wu.spent_txid IS NULL "
            "ORDER BY wu.value DESC",
            -1, &s, NULL) != SQLITE_OK || !s)
        return 0;

    while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW && count < max) {
        const char *txid = (const char *)sqlite3_column_text(s, 0);
        if (!txid)
            continue;
        snprintf(out[count].txid, sizeof(out[count].txid), "%s", txid);
        out[count].vout = sqlite3_column_int(s, 1);
        out[count].value = sqlite3_column_int64(s, 2);
        out[count].height = sqlite3_column_int(s, 3);
        const char *stype = (const char *)sqlite3_column_text(s, 4);
        snprintf(out[count].type, sizeof(out[count].type), "%s",
                 stype ? stype : "Standard");
        count++;
    }
    sqlite3_finalize(s);
    return (int)count;
}

static int wv_list_note_groups_sqlite(
    void *self, struct wallet_view_note_group *out, size_t max)
{
    sqlite3 *db = db_of(self);
    sqlite3_stmt *s = NULL;
    size_t count = 0;

    if (!db || !out || max == 0)
        return 0;

    if (sqlite3_prepare_v2(db,
            "SELECT n.value, n.address, COUNT(*) as cnt, "
            "  MIN(n.block_height) as min_h, MAX(n.block_height) as max_h "
            "FROM wallet_sapling_notes n"
            " WHERE NOT EXISTS ("
            "   SELECT 1 FROM sapling_spends ss"
            "   WHERE ss.nullifier = n.nullifier)"
            " GROUP BY n.value, n.address"
            " ORDER BY n.value DESC",
            -1, &s, NULL) != SQLITE_OK || !s)
        return 0;

    while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW && count < max) {
        out[count].value = sqlite3_column_int64(s, 0);
        const char *addr = (const char *)sqlite3_column_text(s, 1);
        snprintf(out[count].address, sizeof(out[count].address), "%s",
                 addr ? addr : "");
        out[count].count = sqlite3_column_int(s, 2);
        out[count].min_height = sqlite3_column_int(s, 3);
        out[count].max_height = sqlite3_column_int(s, 4);
        count++;
    }
    sqlite3_finalize(s);
    return (int)count;
}

/* History filter bind: ?1 restrict_mode, ?2 from_me, ?3 search. Mirrors
 * the controller's history_bind_filter_params exactly. */
static void wv_bind_filter(sqlite3_stmt *s, int restrict_mode, int from_me,
                           const char *search_hex)
{
    const char *search = (search_hex && search_hex[0]) ? search_hex : "";
    sqlite3_bind_int(s, 1, restrict_mode);
    sqlite3_bind_int(s, 2, from_me);
    sqlite3_bind_text(s, 3, search, -1, SQLITE_STATIC);
}

static int wv_list_ledger_rows_sqlite(
    void *self, struct wallet_view_ledger_row *out, size_t max,
    bool with_filter, int restrict_mode, int from_me,
    const char *search_hex, int limit, int offset)
{
    sqlite3 *db = db_of(self);
    sqlite3_stmt *s = NULL;
    size_t count = 0;

    if (!db || !out || max == 0)
        return 0;

    /* Dashboard query: no fee column, no filter, plain height DESC. */
    static const char *dash_sql =
        "SELECT hex(wt.txid), wt.block_height, COALESCE(b.time,0), "
        "wt.from_me, "
        "COALESCE("
        "  (SELECT SUM(wu.value) FROM wallet_utxos wu "
        "    WHERE wu.txid = wt.txid),"
        "  (SELECT SUM(o.value) FROM tx_outputs o "
        "    WHERE o.txid = wt.txid AND o.address_hash IN "
        "    (SELECT pubkey_hash FROM wallet_keys)),"
        "  0), "
        "COALESCE("
        "  (SELECT SUM(wu2.value) FROM wallet_utxos wu2 "
        "    WHERE wu2.spent_txid = wt.txid), 0) "
        "FROM wallet_transactions wt "
        "LEFT JOIN blocks b ON wt.block_height = b.height "
        "ORDER BY wt.block_height DESC LIMIT 20";

    /* History query: adds fee + UTXO-height fallback + filter + paging. */
    static const char *hist_sql =
        "SELECT hex(wt.txid), "
        "COALESCE(NULLIF(wt.block_height,0),"
        "  (SELECT MAX(wu0.height) FROM wallet_utxos wu0 WHERE wu0.txid = wt.txid),"
        "  0) as ht, "
        "COALESCE(b.time,"
        "  (SELECT b2.time FROM blocks b2 WHERE b2.height = "
        "    (SELECT MAX(wu0b.height) FROM wallet_utxos wu0b WHERE wu0b.txid = wt.txid)),"
        "  0), "
        "wt.from_me, wt.fee, "
        "COALESCE("
        "  (SELECT SUM(wu.value) FROM wallet_utxos wu WHERE wu.txid = wt.txid),"
        "  (SELECT SUM(o.value) FROM tx_outputs o "
        "    WHERE o.txid = wt.txid AND o.address_hash IN "
        "    (SELECT pubkey_hash FROM wallet_keys)),"
        "  0), "
        "COALESCE("
        "  (SELECT SUM(wu2.value) FROM wallet_utxos wu2 "
        "    WHERE wu2.spent_txid = wt.txid), 0) "
        "FROM wallet_transactions wt "
        "LEFT JOIN blocks b ON COALESCE(NULLIF(wt.block_height,0),"
        "  (SELECT MAX(wu0c.height) FROM wallet_utxos wu0c WHERE wu0c.txid = wt.txid)) "
        "  = b.height "
        "WHERE (?1 = 0 OR wt.from_me = ?2) "
        "AND (wt.from_me = 1 OR EXISTS ("
        "  SELECT 1 FROM wallet_utxos wu "
        "  WHERE wu.txid = wt.txid AND wu.value > 0"
        ")) "
        "AND (?3 = '' OR hex(wt.txid) LIKE '%' || ?3 || '%') "
        "ORDER BY ht DESC LIMIT ?4 OFFSET ?5";

    if (sqlite3_prepare_v2(db, with_filter ? hist_sql : dash_sql, -1, &s,
                           NULL) != SQLITE_OK || !s)
        return 0;

    if (with_filter) {
        wv_bind_filter(s, restrict_mode, from_me, search_hex);
        sqlite3_bind_int(s, 4, limit);
        sqlite3_bind_int(s, 5, offset);
    }

    while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW && count < max) {
        const char *txid = (const char *)sqlite3_column_text(s, 0);
        if (!txid)
            continue;
        snprintf(out[count].txid, sizeof(out[count].txid), "%s", txid);
        out[count].height = sqlite3_column_int(s, 1);
        out[count].block_time = sqlite3_column_int64(s, 2);
        out[count].from_me = sqlite3_column_int(s, 3);
        if (with_filter) {
            out[count].fee = sqlite3_column_int64(s, 4);
            out[count].wallet_output = sqlite3_column_int64(s, 5);
            out[count].wallet_input = sqlite3_column_int64(s, 6);
        } else {
            out[count].fee = 0;
            out[count].wallet_output = sqlite3_column_int64(s, 4);
            out[count].wallet_input = sqlite3_column_int64(s, 5);
        }
        count++;
    }
    sqlite3_finalize(s);
    return (int)count;
}

static int wv_count_ledger_rows_sqlite(
    void *self, int restrict_mode, int from_me, const char *search_hex)
{
    sqlite3 *db = db_of(self);
    sqlite3_stmt *s = NULL;
    int n = 0;

    if (!db)
        return 0;

    static const char *sql =
        "SELECT count(*) FROM wallet_transactions wt "
        "WHERE (?1 = 0 OR wt.from_me = ?2) "
        "AND (wt.from_me = 1 OR EXISTS ("
        "  SELECT 1 FROM wallet_utxos wu "
        "  WHERE wu.txid = wt.txid AND wu.value > 0"
        ")) "
        "AND (?3 = '' OR hex(wt.txid) LIKE '%' || ?3 || '%')";
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK || !s)
        return 0;
    wv_bind_filter(s, restrict_mode, from_me, search_hex);
    if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
        n = sqlite3_column_int(s, 0);
    sqlite3_finalize(s);
    return n;
}

static int wv_list_recent_notes_sqlite(
    void *self, struct wallet_view_note_row *out, size_t max,
    bool with_block_time, int limit)
{
    sqlite3 *db = db_of(self);
    sqlite3_stmt *s = NULL;
    size_t count = 0;

    if (!db || !out || max == 0)
        return 0;

    /* Dashboard variant: no block-time join, value/height/address only,
     * LIMIT bound. */
    static const char *dash_sql =
        "SELECT n.value, n.block_height, n.address "
        "FROM wallet_sapling_notes n "
        "WHERE NOT EXISTS ("
        "  SELECT 1 FROM sapling_spends ss"
        "  WHERE ss.nullifier = n.nullifier) "
        "ORDER BY n.block_height DESC LIMIT ?";

    /* History variant: joins blocks for time, requires value > 0. */
    static const char *hist_sql =
        "SELECT n.value, n.block_height, n.address, "
        "COALESCE(b.time, 0) "
        "FROM wallet_sapling_notes n "
        "LEFT JOIN blocks b ON n.block_height = b.height "
        "WHERE NOT EXISTS ("
        "  SELECT 1 FROM sapling_spends ss "
        "  WHERE ss.nullifier = n.nullifier) "
        "AND n.value > 0 "
        "ORDER BY n.block_height DESC LIMIT 10";

    if (sqlite3_prepare_v2(db, with_block_time ? hist_sql : dash_sql, -1, &s,
                           NULL) != SQLITE_OK || !s)
        return 0;

    if (!with_block_time)
        sqlite3_bind_int(s, 1, limit);

    while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW && count < max) {
        out[count].value = sqlite3_column_int64(s, 0);
        out[count].height = sqlite3_column_int(s, 1);
        const char *addr = (const char *)sqlite3_column_text(s, 2);
        snprintf(out[count].address, sizeof(out[count].address), "%s",
                 addr ? addr : "");
        out[count].block_time =
            with_block_time ? sqlite3_column_int64(s, 3) : 0;
        count++;
    }
    sqlite3_finalize(s);
    return (int)count;
}

static int wv_list_peers_sqlite(
    void *self, struct wallet_view_peer_row *out, size_t max)
{
    sqlite3 *db = db_of(self);
    sqlite3_stmt *s = NULL;
    size_t count = 0;

    if (!db || !out || max == 0)
        return 0;

    if (sqlite3_prepare_v2(db,
            "SELECT addr, subver, starting_height, inbound "
            "FROM peers ORDER BY starting_height DESC LIMIT 25",
            -1, &s, NULL) != SQLITE_OK || !s)
        return 0;

    while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW && count < max) {
        const char *addr = (const char *)sqlite3_column_text(s, 0);
        const char *subver = (const char *)sqlite3_column_text(s, 1);
        if (!addr)
            continue;
        snprintf(out[count].addr, sizeof(out[count].addr), "%s", addr);
        snprintf(out[count].subver, sizeof(out[count].subver), "%s",
                 subver ? subver : "unknown");
        out[count].starting_height = sqlite3_column_int(s, 2);
        out[count].inbound = sqlite3_column_int(s, 3);
        count++;
    }
    sqlite3_finalize(s);
    return (int)count;
}

static bool wv_first_sapling_address_sqlite(
    void *self, char *out, size_t outmax)
{
    sqlite3 *db = db_of(self);
    sqlite3_stmt *s = NULL;
    bool found = false;

    if (!db || !out || outmax == 0)
        return false;
    out[0] = '\0';

    if (sqlite3_prepare_v2(db,
            "SELECT address FROM wallet_sapling_keys "
            "WHERE address IS NOT NULL AND length(address) > 0 "
            "ORDER BY rowid LIMIT 1",
            -1, &s, NULL) != SQLITE_OK || !s)
        return false;

    if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
        const char *a = (const char *)sqlite3_column_text(s, 0);
        if (a) {
            snprintf(out, outmax, "%s", a);
            found = true;
        }
    }
    sqlite3_finalize(s);
    return found;
}

static bool wv_lookup_tx_header_sqlite(
    void *self, const char *upper_txid, struct wallet_view_tx_header *out)
{
    sqlite3 *db = db_of(self);
    sqlite3_stmt *s = NULL;
    bool found = false;

    if (!db || !upper_txid || !out)
        return false;

    if (sqlite3_prepare_v2(db,
            "SELECT wt.block_height, wt.from_me, wt.fee, "
            "COALESCE(b.time, 0) "
            "FROM wallet_transactions wt "
            "LEFT JOIN blocks b ON wt.block_height = b.height "
            "WHERE hex(wt.txid) = ?",
            -1, &s, NULL) != SQLITE_OK || !s)
        return false;

    sqlite3_bind_text(s, 1, upper_txid, -1, SQLITE_STATIC);
    if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
        out->block_height = sqlite3_column_int(s, 0);
        out->from_me = sqlite3_column_int(s, 1);
        out->fee = sqlite3_column_int64(s, 2);
        out->block_time = sqlite3_column_int64(s, 3);
        found = true;
    }
    sqlite3_finalize(s);
    return found;
}

static int wv_list_tx_outputs_sqlite(
    void *self, const char *upper_txid,
    struct wallet_view_tx_output *out, size_t max)
{
    sqlite3 *db = db_of(self);
    sqlite3_stmt *s = NULL;
    size_t count = 0;

    if (!db || !upper_txid || !out || max == 0)
        return 0;

    if (sqlite3_prepare_v2(db,
            "SELECT vout, value, hex(address_hash) "
            "FROM wallet_utxos WHERE hex(txid) = ? "
            "ORDER BY vout",
            -1, &s, NULL) != SQLITE_OK || !s)
        return 0;

    sqlite3_bind_text(s, 1, upper_txid, -1, SQLITE_STATIC);
    while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW && count < max) {
        out[count].vout = sqlite3_column_int(s, 0);
        out[count].value = sqlite3_column_int64(s, 1);
        count++;
    }
    sqlite3_finalize(s);
    return (int)count;
}

bool wallet_view_sqlite_bind(sqlite3 *db, struct wallet_view_port *out_port)
{
    if (!db || !out_port)
        return false;
    *out_port = (struct wallet_view_port){
        .self                   = db,
        .list_receive_addresses = wv_list_receive_addresses_sqlite,
        .list_held_tokens       = wv_list_held_tokens_sqlite,
        .list_token_cards       = wv_list_token_cards_sqlite,
        .list_token_balances    = wv_list_token_balances_sqlite,
        .list_unspent_coins     = wv_list_unspent_coins_sqlite,
        .list_note_groups       = wv_list_note_groups_sqlite,
        .list_ledger_rows       = wv_list_ledger_rows_sqlite,
        .count_ledger_rows      = wv_count_ledger_rows_sqlite,
        .list_recent_notes      = wv_list_recent_notes_sqlite,
        .list_peers             = wv_list_peers_sqlite,
        .first_sapling_address  = wv_first_sapling_address_sqlite,
        .lookup_tx_header       = wv_lookup_tx_header_sqlite,
        .list_tx_outputs        = wv_list_tx_outputs_sqlite,
    };
    return true;
}
