/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared macros and declarations for explorer subsystems. */

#ifndef ZCL_CONTROLLERS_EXPLORER_INTERNAL_H
#define ZCL_CONTROLLERS_EXPLORER_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <math.h>
#include <time.h>
#include <sqlite3.h>
#include "models/database.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "views/format_helpers.h"
#include "views/site_layout.h"

#define ZCL_EXPLORER_GENESIS_TIME 1478403829LL
/* INTERNAL == byte-reverse(DISPLAY): the little-endian value the `blocks`
 * table stores and the genesis-hash gate strcmp's against. The prior constant
 * was hand-corrupted (11/32 bytes off) and escaped notice only because the
 * missing-heights gate fires first. Guarded by a unit test (reverse(DISPLAY)). */
#define ZCL_EXPLORER_GENESIS_HASH_INTERNAL_HEX \
    "0206260143838b5ff52dc2eb7b4b8099d4e4c99dc3ef19794289a2cd4c100700"
#define ZCL_EXPLORER_GENESIS_HASH_DISPLAY_HEX \
    "0007104ccda289427919efc39dc9e4d499804b7bebc22df55f8b834301260602"

struct explorer_history_validation {
    bool usable;
    int64_t chain_height;
    int64_t block_rows;
    int64_t max_height;
    int64_t missing_heights;
    int64_t first_missing_height;
    int64_t duplicate_heights;
    int64_t tx_rows;
    int64_t tx_output_rows;
    int64_t integrity_rows;
    char reason[128];
};

/* ── Append helper ─────────────────────────────────────────── */
#define APPEND(off, buf, max, ...) \
    ((off) = site_appendf((char *)(buf), (max), (off), __VA_ARGS__))

/* ── Page template macros ──────────────────────────────────── */
#define EXPLORER_HEADER(title) \
    "HTTP/1.1 200 OK\r\n" \
    "Content-Type: text/html; charset=utf-8\r\n" \
    "Connection: close\r\n\r\n" \
    "<!DOCTYPE html><html><head><meta charset='utf-8'>" \
    "<meta name='viewport' content='width=device-width,initial-scale=1'>" \
    "<title>" title "</title>" \
    "<link rel='icon' type='image/png' href='/explorer/favicon.png'>" \
    "<link rel='stylesheet' href='/explorer/style.css'>" \
    "</head><body>"

/* Nav helper: emits the global site nav (active "explorer") followed by the
 * explorer section <nav> with active class on the matching link.
 * Pass NULL for active to highlight nothing in the section nav. */
static inline size_t explorer_emit_nav(char *buf, size_t max, const char *active)
{
    static const struct { const char *href; const char *label; const char *id; } links[] = {
        { "/explorer",          "Blocks",    "blocks"   },
        { "/explorer/stats",    "Stats",     "stats"    },
        { "/explorer/hodl",     "HODL Wave", "hodl"     },
        { "/explorer/tokens",   "Tokens",    "tokens"   },
        { "/explorer/events",   "Events",    "events"   },
        { "/explorer/factoids", "Factoids",  "factoids" },
        { "/explorer/names",    "Names",     "names"    },
        { "/explorer/network",  "Network",   "network"  },
        { "/explorer/market",   "Market",    "market"   },
        { "/explorer/swaps",    "Swaps",     "swaps"    },
    };
    size_t off = site_emit_global_nav(buf, max, "explorer");
    APPEND(off, buf, max, "<nav class='nav' aria-label='Explorer sections'>");
    for (size_t i = 0; i < sizeof(links)/sizeof(links[0]); i++) {
        bool act = active && strcmp(active, links[i].id) == 0;
        APPEND(off, buf, max, "<a href='%s'%s>%s</a>",
               links[i].href, act ? " class='active'" : "", links[i].label);
    }
    APPEND(off, buf, max,
        "<div class='search'>"
        "<form action='/explorer/search' method='get'>"
        "<label for='explorer-search' class='sr-only'>Search</label>"
        "<input id='explorer-search' name='q' placeholder='Search block, tx, or address...' "
        "aria-label='Search blocks, transactions, or addresses'>"
        "</form></div></nav>");
    return off;
}

/* Legacy EXPLORER_NAV macro — kept for error pages and one-shot snprintf.
 * Does not highlight any active link; use explorer_emit_nav() for that. */
#define EXPLORER_NAV \
    SITE_GLOBAL_NAV \
    "<nav class='nav' aria-label='Explorer sections'>" \
    "<a href='/explorer'>Blocks</a>" \
    "<a href='/explorer/stats'>Stats</a>" \
    "<a href='/explorer/hodl'>HODL Wave</a>" \
    "<a href='/explorer/tokens'>Tokens</a>" \
    "<a href='/explorer/events'>Events</a>" \
    "<a href='/explorer/factoids'>Factoids</a>" \
    "<a href='/explorer/names'>Names</a>" \
    "<a href='/explorer/network'>Network</a>" \
    "<a href='/explorer/market'>Market</a>" \
    "<a href='/explorer/swaps'>Swaps</a>" \
    "<div class='search'>" \
    "<form action='/explorer/search' method='get'>" \
    "<input name='q' placeholder='Search block, tx, or address...'>" \
    "</form></div></nav>"

#define EXPLORER_FOOTER \
    "<footer>Z23 Block Explorer &mdash; one binary, one onion, one stack</footer>" \
    "</body></html>"

/* ── SQLite query helpers (DRY — one definition for all controllers) ──
 *
 * These are read-only explorer projection helpers. Gate #20 permits a
 * documented marker while this mixed controller/projection header is split
 * into a dedicated service in Phase 1.
 */

static inline int64_t sql_query_i64(sqlite3 *db, const char *sql)
{
    int64_t val = 0;
    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &s, NULL);  // raw-controller-sql-ok:explorer-read-projection-helper
    if (rc != SQLITE_OK) {
        LOG_ERR("explorer", "sql_query_i64: prepare failed (%d): %s [%s]",
                rc, sqlite3_errmsg(db), sql);
    }
    if (s) {
        rc = sqlite3_step(s);  // raw-sql-ok:read-only-introspection
        if (rc == SQLITE_ROW)
            val = sqlite3_column_int64(s, 0);
        else if (rc != SQLITE_DONE)
            LOG_WARN("explorer", "sql_query_i64: step failed (%d): %s [%s]",
                    rc, sqlite3_errmsg(db), sql);
        sqlite3_finalize(s);
    }
    return val;
}

static inline int sql_query_int(sqlite3 *db, const char *sql)
{
    return (int)sql_query_i64(db, sql);
}

struct sql_row_i64_2 {
    int64_t v0;
    int64_t v1;
};

struct sql_row_i64_3 {
    int64_t v0;
    int64_t v1;
    int64_t v2;
};

struct explorer_token_stats {
    int64_t token_count;
    int64_t transfer_count;
};

struct explorer_address_stats {
    int64_t total;
    int64_t nonzero;
};

struct explorer_privacy_stats {
    int64_t joinsplits;
    int64_t sapling_spends;
    int64_t sapling_outputs;
    int64_t net_shielded_sat;
};

struct explorer_utxo_stats {
    int64_t count;
    int64_t dust_under_0001;
    int64_t total_value_sat;
};

struct explorer_op_return_stats {
    int64_t total;
    int64_t zslp;
};

struct explorer_transaction_stats {
    int64_t total;
    int64_t coinbase;
    int64_t inputs;
    int64_t outputs;
    int64_t empty_blocks;
};

struct explorer_chain_stats {
    int64_t height;
    int64_t blocks;
};

struct explorer_first_privacy_heights {
    int64_t joinsplit_height;
    int64_t sapling_height;
};

static inline bool sql_query_row_i64_2(sqlite3 *db, const char *sql,
                                       struct sql_row_i64_2 *out)
{
    sqlite3_stmt *s = NULL;

    if (out) {
        out->v0 = 0;
        out->v1 = 0;
    }
    if (!out)
        return false;

    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {  // raw-controller-sql-ok:explorer-read-projection-helper
        if (sqlite3_step(s) == SQLITE_ROW) {  // raw-sql-ok:read-only-introspection
            out->v0 = sqlite3_column_int64(s, 0);
            out->v1 = sqlite3_column_int64(s, 1);
            sqlite3_finalize(s);
            return true;
        }
        sqlite3_finalize(s);
    }
    return false;
}

static inline bool sql_query_row_i64_3(sqlite3 *db, const char *sql,
                                       struct sql_row_i64_3 *out)
{
    sqlite3_stmt *s = NULL;

    if (out) {
        out->v0 = 0;
        out->v1 = 0;
        out->v2 = 0;
    }
    if (!out)
        return false;

    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {  // raw-controller-sql-ok:explorer-read-projection-helper
        if (sqlite3_step(s) == SQLITE_ROW) {  // raw-sql-ok:read-only-introspection
            out->v0 = sqlite3_column_int64(s, 0);
            out->v1 = sqlite3_column_int64(s, 1);
            out->v2 = sqlite3_column_int64(s, 2);
            sqlite3_finalize(s);
            return true;
        }
        sqlite3_finalize(s);
    }
    return false;
}

static inline void explorer_query_token_stats(sqlite3 *db,
                                              struct explorer_token_stats *out)
{
    if (!out)
        return;

    out->token_count = sql_query_i64(db, "SELECT count(*) FROM zslp_tokens");
    out->transfer_count = sql_query_i64(db, "SELECT count(*) FROM zslp_transfers");
}

static inline void explorer_query_address_stats(sqlite3 *db,
                                                struct explorer_address_stats *out)
{
    if (!out)
        return;

    out->total = sql_query_i64(db, "SELECT count(*) FROM addresses");
    out->nonzero = sql_query_i64(db, "SELECT count(*) FROM addresses WHERE balance > 0");
}

static inline void explorer_query_privacy_stats(sqlite3 *db,
                                                struct explorer_privacy_stats *out)
{
    if (!out)
        return;

    out->joinsplits = sql_query_i64(db, "SELECT count(*) FROM joinsplits");
    out->sapling_spends = sql_query_i64(db, "SELECT count(*) FROM sapling_spends");
    out->sapling_outputs = sql_query_i64(db, "SELECT count(*) FROM sapling_outputs");
    /* blocks.sapling_value stores zclassicd's valueDelta convention:
     * positive = pool INCREASED (t→z shielding-in event),
     * negative = pool DECREASED (z→t unshielding-out event).
     * Verified by comparing block 1275039 (-29963.3742 ZCL) and block
     * 2670693 (+40380.0 ZCL) against zclassicd's getblock RPC.
     * Pool balance = cumulative SUM(valueDelta), no negation. */
    out->net_shielded_sat = sql_query_i64(db, "SELECT COALESCE(SUM(sapling_value), 0) FROM blocks");
}

static inline void explorer_query_utxo_stats(sqlite3 *db,
                                             struct explorer_utxo_stats *out)
{
    if (!out)
        return;

    out->count = sql_query_i64(db, "SELECT count(*) FROM utxos");
    out->dust_under_0001 = sql_query_i64(db, "SELECT count(*) FROM utxos WHERE value < 100000");
    out->total_value_sat = sql_query_i64(db, "SELECT COALESCE(SUM(value),0) FROM utxos");
}

static inline void explorer_query_op_return_stats(sqlite3 *db,
                                                  struct explorer_op_return_stats *out)
{
    if (!out)
        return;

    out->total = sql_query_i64(db, "SELECT count(*) FROM op_returns");
    out->zslp = sql_query_i64(db, "SELECT count(*) FROM op_returns WHERE is_slp = 1");
}

static inline void explorer_query_transaction_stats(sqlite3 *db,
                                                    struct explorer_transaction_stats *out)
{
    if (!out)
        return;

    out->total = sql_query_i64(db, "SELECT count(*) FROM transactions");
    out->coinbase = sql_query_i64(db, "SELECT count(*) FROM transactions WHERE is_coinbase = 1");
    out->inputs = sql_query_i64(db, "SELECT count(*) FROM tx_inputs");
    out->outputs = sql_query_i64(db, "SELECT count(*) FROM tx_outputs");
    out->empty_blocks = sql_query_i64(db, "SELECT count(*) FROM blocks WHERE num_tx <= 1");
}

static inline void explorer_query_chain_stats(sqlite3 *db,
                                              struct explorer_chain_stats *out)
{
    if (!out)
        return;

    out->height = sql_query_i64(db, "SELECT MAX(height) FROM blocks");
    out->blocks = sql_query_i64(db, "SELECT count(*) FROM blocks");
}

static inline void explorer_query_first_privacy_heights(
    sqlite3 *db, struct explorer_first_privacy_heights *out)
{
    if (!out)
        return;

    out->joinsplit_height = sql_query_i64(db,
        "SELECT MIN(block_height) FROM joinsplits");
    out->sapling_height = sql_query_i64(db,
        "SELECT MIN(block_height) FROM sapling_spends");
}

static inline bool explorer_open_readonly_db(const char *datadir, sqlite3 **db_out)
{
    char dbpath[1024];

    if (db_out)
        *db_out = NULL;
    if (!datadir || !db_out)
        return false;

    int written = snprintf(dbpath, sizeof(dbpath), "%s/node.db", datadir);
    if (written < 0 || (size_t)written >= sizeof(dbpath))
        return false;
    if (sqlite3_open_v2(dbpath, db_out, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (*db_out) {
            sqlite3_close(*db_out);
            *db_out = NULL;
        }
        return false;
    }

    (void)node_db_apply_readonly_tuning(*db_out);
    sqlite3_busy_timeout(*db_out, 30000);
    return true;
}

static inline bool sql_query_text(sqlite3 *db, const char *sql,
                                   char *out, size_t max)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {  // raw-controller-sql-ok:explorer-read-projection-helper
        if (sqlite3_step(s) == SQLITE_ROW) {  // raw-sql-ok:read-only-introspection
            const char *t = (const char *)sqlite3_column_text(s, 0);
            if (t) { snprintf(out, max, "%s", t); sqlite3_finalize(s); return true; }
        }
        sqlite3_finalize(s);
    }
    if (max > 0) out[0] = '\0';
    return false;
}

/* A live block projection can legitimately trail the chain tip by a block or
 * two mid-write, and a rare benign hole (a single height whose `blocks` row
 * missed a write on a snapshot re-fold) must not suppress the entire historian
 * page. The factoids are aggregates over millions of blocks plus specific-
 * height lookups that fall back gracefully (get_block_at), so a handful of
 * missing heights changes nothing material; a genuinely incomplete / still-
 * rebuilding projection (thousands missing) still degrades. Tolerate a small
 * bounded gap, reject a large one. */
#define EXPLORER_HISTORY_MAX_BLOCK_GAP 16

static inline void explorer_validate_block_history(
    sqlite3 *db, int64_t chain_height, struct explorer_history_validation *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    out->chain_height = chain_height;

    #define EXPLORER_HISTORY_BAD(msg) do { \
        snprintf(out->reason, sizeof(out->reason), "%s", (msg)); \
        out->usable = false; \
        return; \
    } while (0)

    out->first_missing_height = -1;
    if (!db)
        EXPLORER_HISTORY_BAD("sqlite database unavailable");

    out->max_height = sql_query_i64(db,
        "SELECT COALESCE(MAX(height),-1) FROM blocks");
    out->block_rows = sql_query_i64(db, "SELECT count(*) FROM blocks");
    if (out->max_height <= 0 || out->block_rows <= 0)
        EXPLORER_HISTORY_BAD("blocks projection is empty");
    int64_t raw_missing = out->max_height + 1 - out->block_rows;
    out->missing_heights = raw_missing > 0 ? raw_missing : 0;

    /* Once the cheap MAX/COUNT check proves the projection is outside the
     * bounded-hole tolerance, do not pay for an exact first-hole search.
     * On a multi-million-row live index that anti-join can run for minutes.
     * The caller already has the complete safety answer (degraded), and a
     * diagnostic must not monopolize the node's shared wallet DB just to add
     * a more precise height to an already-failed result. */
    if (out->missing_heights > EXPLORER_HISTORY_MAX_BLOCK_GAP)
        EXPLORER_HISTORY_BAD("blocks projection has missing heights");

    out->first_missing_height = sql_query_i64(db,
        "WITH first_missing(h) AS ("
        "SELECT 0 WHERE NOT EXISTS ("
        "SELECT 1 FROM blocks WHERE height=0 AND status>=3)"
        " UNION ALL "
        "SELECT b.height+1 FROM blocks b "
        "LEFT JOIN blocks n ON n.height=b.height+1 AND n.status>=3 "
        "WHERE b.status>=3 AND b.height>=0 "
        "AND b.height < (SELECT COALESCE(MAX(height),-1) "
        "FROM blocks WHERE status>=3) AND n.height IS NULL)"
        "SELECT COALESCE(MIN(h),-1) FROM first_missing");
    out->tx_rows = sql_query_i64(db, "SELECT count(*) FROM transactions");
    out->tx_output_rows = sql_query_i64(db, "SELECT count(*) FROM tx_outputs");
    out->integrity_rows = sql_query_i64(db, "SELECT count(*) FROM view_integrity");
    if (chain_height > 0 && out->max_height + 1 < chain_height)
        EXPLORER_HISTORY_BAD("blocks projection lags active chain");

    out->duplicate_heights = sql_query_i64(db,
        "SELECT count(*) FROM ("
        "SELECT height FROM blocks GROUP BY height HAVING count(*) > 1)");
    if (out->duplicate_heights > 0)
        EXPLORER_HISTORY_BAD("blocks projection has duplicate heights");

    int64_t genesis_time = sql_query_i64(db, "SELECT time FROM blocks WHERE height = 0");
    if (genesis_time != ZCL_EXPLORER_GENESIS_TIME)
        EXPLORER_HISTORY_BAD("genesis timestamp mismatch");

    char genesis_hash[128] = "";
    sql_query_text(db, "SELECT lower(hex(hash)) FROM blocks WHERE height = 0",
                   genesis_hash, sizeof(genesis_hash));
    if (strcmp(genesis_hash, ZCL_EXPLORER_GENESIS_HASH_INTERNAL_HEX) != 0)
        EXPLORER_HISTORY_BAD("genesis hash byte order/value mismatch");

    if (out->max_height > 10 && out->tx_rows <= 0)
        EXPLORER_HISTORY_BAD("transactions projection is empty");
    if (out->max_height > 10 && out->tx_output_rows <= 0)
        EXPLORER_HISTORY_BAD("tx_outputs projection is empty");
    if (out->max_height + 1 - out->integrity_rows > EXPLORER_HISTORY_MAX_BLOCK_GAP)
        EXPLORER_HISTORY_BAD("integrity receipts are incomplete");

    out->usable = true;
    snprintf(out->reason, sizeof(out->reason), "ok");
    #undef EXPLORER_HISTORY_BAD
}

static inline bool explorer_block_history_usable_for_height(sqlite3 *db,
                                                            int64_t chain_height)
{
    struct explorer_history_validation v;
    explorer_validate_block_history(db, chain_height, &v);
    return v.usable;
}

/* ── getblock JSON "tx":[...] element count ─────────────────
 *
 * Counts the transactions in a getblock RPC JSON response by locating
 * the `"tx":[` array and counting comma separators + 1. Returns 0 when
 * the array is absent. Used by the api/explorer block controllers to
 * report a block's tx count without a full JSON parse. */
static inline int explorer_count_json_tx_array(const char *json)
{
    const char *txarr = strstr(json, "\"tx\":[");
    if (!txarr)
        return 0;
    const char *end = strchr(txarr, ']');
    int n = 1;
    if (end)
        for (const char *p = txarr; p < end; p++)
            if (*p == ',') n++;
    return n;
}

/* ── Number formatting with comma separators ─────────────── */

static inline int format_with_commas(char *buf, size_t max, int64_t val)
{
    char tmp[32];
    int len = snprintf(tmp, sizeof(tmp), "%" PRId64, val);
    if (len <= 0 || (size_t)len >= sizeof(tmp)) { buf[0] = '\0'; return 0; }

    bool neg = (tmp[0] == '-');
    int digits_start = neg ? 1 : 0;
    int ndigits = len - digits_start;
    int ncommas = (ndigits - 1) / 3;
    int total = len + ncommas;

    if ((size_t)total >= max) { buf[0] = '\0'; return 0; }

    int src = len - 1;
    int dst = total;
    buf[dst--] = '\0';
    int count = 0;
    while (src >= digits_start) {
        buf[dst--] = tmp[src--];
        count++;
        if (count % 3 == 0 && src >= digits_start)
            buf[dst--] = ',';
    }
    if (neg) buf[dst] = '-';
    return total;
}

/* ── Shared formatting helpers (static inline for header-only use) ── */

static inline void explorer_format_time(char *buf, size_t max, uint32_t t)
{
    time_t ts = (time_t)t;
    struct tm tm;
    if (!platform_time_utc_tm(ts, &tm) ||
        strftime(buf, max, "%Y-%m-%d %H:%M:%S UTC", &tm) == 0)
        snprintf(buf, max, "1970-01-01 00:00:00 UTC");
}

/* Shared difficulty calculation — canonical version in chain/pow.h */
#include "chain/pow.h"
static inline double explorer_difficulty_from_bits(uint32_t bits)
{
    return difficulty_from_bits(bits);
}

static inline void explorer_format_y_label(char *buf, size_t max, double val)
{
    double av = val < 0 ? -val : val;
    if (av >= 1e9)       snprintf(buf, max, "%.1fG", val / 1e9);
    else if (av >= 1e6)  snprintf(buf, max, "%.1fM", val / 1e6);
    else if (av >= 1e4)  snprintf(buf, max, "%.0fK", val / 1e3);
    else if (av >= 1e3)  snprintf(buf, max, "%.1fK", val / 1e3);
    else if (av >= 100)  snprintf(buf, max, "%.0f", val);
    else if (av >= 10)   snprintf(buf, max, "%.1f", val);
    else if (av >= 1)    snprintf(buf, max, "%.2f", val);
    else if (av >= 0.01) snprintf(buf, max, "%.3f", val);
    else                 snprintf(buf, max, "%.4f", val);
}

/* ── Correct ZClassic supply calculation ───────────────────────
 *
 * Matches get_block_subsidy() + consensus_halving() from consensus code.
 * The chain has three subsidy eras:
 *   Block 0:          0 ZCL (slow-start first half, nSubsidySlowStartInterval=2)
 *   Block 1:          12.5 ZCL (slow-start second half)
 *   Blocks 2-706999:  12.5 ZCL (pre-Buttercup, 0 halvings)
 *   Blocks 707000+:   base/2 >> (era+3), where era = (h-1-707000)/1680000
 *
 * Post-Buttercup subsidy per block:
 *   Era 0 (707000-2387000):   0.78125 ZCL   (625000000>>3 = 78125000 zatoshi)
 *   Era 1 (2387001-4067000):  0.390625 ZCL  (625000000>>4 = 39062500 zatoshi)
 *   Era 2 (4067001-5747000):  0.1953125 ZCL (625000000>>5 = 19531250 zatoshi)
 *   ...
 *
 * Returns total supply in zatoshi (int64_t). Overflow-safe for all heights.
 */

/* Mainnet network-upgrade activation heights. Source of truth lives in
 * lib/chain/src/chainparams.c (the consensus params struct). These
 * are duplicated here so the explorer/factoids code can build static
 * tables and use them as compile-time constants without taking a
 * runtime dep on consensus_params; CI / a future test should pin them
 * to the chainparams values. */
#define OVERWINTER_ACTIVATION_HEIGHT 476969
#define SAPLING_ACTIVATION_HEIGHT    476969
#define BUBBLES_ACTIVATION_HEIGHT    585318
#define BUBBLY_ACTIVATION_HEIGHT     585322
#define BUTTERCUP_ACTIVATION_HEIGHT  707000
#define PRE_BC_HALVING   840000
#define POST_BC_HALVING  1680000
#define BASE_SUBSIDY_SAT 1250000000LL  /* 12.5 ZCL */

static inline int64_t zcl_total_supply_zatoshi(int64_t height)
{
    if (height <= 0) return 0;

    const int64_t base = 1250000000LL;   /* 12.5 ZCL in zatoshi */
    const int64_t buttercup = 707000;
    const int64_t post_interval = 1680000;
    const int64_t post_base = base / 2;  /* 625000000 (spacing ratio = 2) */

    int64_t total = 0;

    /* Block 0: slow-start -> 0 zatoshi. Block 1: full 12.5 ZCL. */
    total += base;
    if (height == 1) return total;

    /* Pre-Buttercup: blocks 2..min(height, 706999) at 12.5 ZCL each.
     * No halvings occur pre-Buttercup (first would be at block 840001). */
    int64_t pre_end = height < buttercup ? height : buttercup - 1;
    total += (pre_end - 1) * base;  /* count = pre_end - 2 + 1 = pre_end - 1 */
    if (height < buttercup) return total;

    /* Post-Buttercup: iterate through halving eras.
     * consensus_halving() returns (h-1-707000)/1680000 + 3.
     * Era 0: blocks 707000..2387000  (1680001 blocks)
     * Era k>0: blocks (707000+k*1680000+1)..(707000+(k+1)*1680000) (1680000 blocks) */
    for (int era = 0; era < 61; era++) {
        int64_t subsidy = post_base >> (era + 3);
        if (subsidy == 0) break;

        int64_t era_start = buttercup + (int64_t)era * post_interval
                            + (era > 0 ? 1 : 0);
        int64_t era_end   = buttercup + (int64_t)(era + 1) * post_interval;

        if (era_start > height) break;
        if (era_end > height) era_end = height;

        total += (era_end - era_start + 1) * subsidy;
    }

    return total;
}

/* ── Equihash solve-rate (NOT "hashrate") ──────────────────────────
 *
 * ZClassic is Equihash: miners produce *solutions*, not raw hashes, so the
 * network rate is measured in Sol/s. The (N,K) parameters are height-selected
 * (docs/EQUIHASH_PARAMS.md) and do not enter this estimate — only difficulty
 * and the target spacing do. The estimate is
 *   diff * 2^13 / target_block_spacing
 * where the target spacing switched 150s -> 75s at Buttercup
 * (BUTTERCUP_ACTIVATION_HEIGHT). Using the active spacing matters: the
 * pre-Buttercup hard-coded 150 under-reports the post-Buttercup rate ~2x. */
static inline int explorer_target_spacing(int height)
{
    return height >= BUTTERCUP_ACTIVATION_HEIGHT ? 75 : 150;
}

static inline double explorer_solrate_from_diff(double diff, int height)
{
    int spacing = explorer_target_spacing(height);
    if (spacing <= 0) spacing = 75; /* defensive: never divide by zero */
    return diff * 8192.0 / (double)spacing;
}

/* Format a solve rate (solutions/sec) with SI-style units. */
static inline void explorer_format_solrate(char *buf, size_t max, double sr)
{
    if (sr >= 1e9)      snprintf(buf, max, "%.2f GSol/s", sr / 1e9);
    else if (sr >= 1e6) snprintf(buf, max, "%.2f MSol/s", sr / 1e6);
    else if (sr >= 1e3) snprintf(buf, max, "%.2f KSol/s", sr / 1e3);
    else                snprintf(buf, max, "%.0f Sol/s", sr);
}

/* Height of the next subsidy halving at/after `tip` (Buttercup-aware:
 * pre-BC boundaries every PRE_BC_HALVING, post-BC every POST_BC_HALVING
 * starting one block after BUTTERCUP_ACTIVATION_HEIGHT). Mirrors the
 * inline calc in explorer_stats_view.c. */
static inline int explorer_next_halving_height(int tip)
{
    if (tip >= BUTTERCUP_ACTIVATION_HEIGHT) {
        int era = (int)(((int64_t)tip - 1 - BUTTERCUP_ACTIVATION_HEIGHT)
                        / POST_BC_HALVING);
        return (int)(BUTTERCUP_ACTIVATION_HEIGHT + 1
                     + (int64_t)(era + 1) * POST_BC_HALVING);
    }
    return (tip / PRE_BC_HALVING + 1) * PRE_BC_HALVING;
}

/* Asymptotic emission cap (total ZCL ever mintable). A large height
 * drives zcl_total_supply_zatoshi past the last non-zero subsidy era,
 * so the result is the true tail-summed cap (~11.46M ZCL), NOT 21M. */
static inline int64_t zcl_max_supply_zatoshi(void)
{
    return zcl_total_supply_zatoshi(100000000LL);
}

/* Aliases used by factoids, API, and stats code */
static inline int64_t compute_supply_at_height(int64_t height)
{
    return zcl_total_supply_zatoshi(height);
}

static inline double supply_zcl_at_height(int64_t height)
{
    return (double)zcl_total_supply_zatoshi(height) / (double)ZATOSHI_PER_ZCL;
}

/* SVG line chart — renders into buffer at *off, advances *off */
static inline void explorer_svg_line_chart(char *out, size_t max, size_t *off,
                            const char *title, const char *color,
                            double *values, const char labels[][20],
                            int count, const char *y_label)
{
    if (count < 2) return;

    double min_v = values[0], max_v = values[0];
    for (int i = 1; i < count; i++) {
        if (values[i] < min_v) min_v = values[i];
        if (values[i] > max_v) max_v = values[i];
    }
    if (max_v == min_v) max_v = min_v + 1;

    double pos_min = min_v > 0 ? min_v : 0.01;
    double pos_max = max_v > 0 ? max_v : 1;
    bool use_log = (pos_max / pos_min > 100);

    double range = max_v - min_v;
    double log_min = 0, log_range = 1;
    if (use_log) {
        log_min = log10(pos_min > 0 ? pos_min : 0.01);
        double log_max = log10(pos_max);
        log_range = log_max - log_min;
        if (log_range < 0.1) log_range = 0.1;
    }

    int w = 800, h = 300, pad_l = 90, pad_r = 20, pad_t = 40, pad_b = 60;
    int plot_w = w - pad_l - pad_r;
    int plot_h = h - pad_t - pad_b;

    APPEND(*off, out, max,
        "<svg viewBox='0 0 %d %d' style='width:100%%;max-width:%dpx;height:auto;"
        "background:#0c0c0c;border-radius:8px;margin:4px 0'>",
        w, h, w);

    if (title && title[0])
        APPEND(*off, out, max,
            "<text x='%d' y='25' fill='#33ff99' font-size='16' font-weight='600'>%s%s</text>",
            pad_l, title, use_log ? " (log scale)" : "");

    for (int i = 0; i <= 4; i++) {
        int y = pad_t + plot_h - (plot_h * i / 4);
        double val;
        if (use_log) {
            double log_val = log_min + log_range * i / 4.0;
            val = pow(10.0, log_val);
        } else {
            val = min_v + range * i / 4.0;
        }
        char lbl[32];
        explorer_format_y_label(lbl, sizeof(lbl), val);
        APPEND(*off, out, max,
            "<line x1='%d' y1='%d' x2='%d' y2='%d' stroke='#1a1a1a' stroke-width='1'/>"
            "<text x='%d' y='%d' fill='#666' font-size='13' text-anchor='end'>%s</text>",
            pad_l, y, w - pad_r, y,
            pad_l - 10, y + 5, lbl);
    }

    APPEND(*off, out, max,
        "<text x='14' y='%d' fill='#888' font-size='12' "
        "transform='rotate(-90,14,%d)' text-anchor='middle'>%s</text>",
        pad_t + plot_h / 2, pad_t + plot_h / 2, y_label);

    #define VAL_TO_Y(v) (use_log \
        ? (pad_t + plot_h - (int)(((log10((v) > 0 ? (v) : 0.01)) - log_min) / log_range * plot_h)) \
        : (pad_t + plot_h - (int)(((v) - min_v) / range * plot_h)))

    APPEND(*off, out, max, "<polyline fill='none' stroke='%s' stroke-width='2.5' "
        "stroke-linejoin='round' points='", color);

    for (int i = 0; i < count; i++) {
        int x = pad_l + plot_w * i / (count - 1);
        int y = VAL_TO_Y(values[i]);
        APPEND(*off, out, max, "%d,%d ", x, y);
    }
    APPEND(*off, out, max, "'/>");

    APPEND(*off, out, max,
        "<polyline fill='%s' fill-opacity='0.1' stroke='none' points='%d,%d ",
        color, pad_l, pad_t + plot_h);
    for (int i = 0; i < count; i++) {
        int x = pad_l + plot_w * i / (count - 1);
        int y = VAL_TO_Y(values[i]);
        APPEND(*off, out, max, "%d,%d ", x, y);
    }
    APPEND(*off, out, max, "%d,%d '/>", w - pad_r, pad_t + plot_h);

    #undef VAL_TO_Y

    int label_step = count > 10 ? count / 6 : 1;
    for (int i = 0; i < count; i += label_step) {
        int x = pad_l + plot_w * i / (count - 1);
        APPEND(*off, out, max,
            "<text x='%d' y='%d' fill='#666' font-size='11' text-anchor='middle'>%s</text>",
            x, h - 10, labels[i]);
    }

    APPEND(*off, out, max, "</svg>");
}

#endif
