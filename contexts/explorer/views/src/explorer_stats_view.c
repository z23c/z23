/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer stats VIEW: comprehensive blockchain statistics page. The
 * controller parses the request and delegates here; page assembly and
 * read-only projection queries live in this file.
 *
 * Performance: All aggregate data gathered in ~6 consolidated queries
 * (single-pass scans) instead of dozens of individual queries.
 * Chart data uses batch SELECT with height ranges. */

#include "platform/time_compat.h"
#include "views/explorer_stats_view.h"
#include "views/explorer_stats_internal.h"
#include "controllers/explorer_internal.h"
#include "chain/chainparams.h"
#include "keys/key_io.h"
#include "models/hodl_wave.h"
#include "script/standard.h"
#include <sqlite3.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

/* Data structs (stats_ctx/shielded_stats/stats_chart_data), the
 * stats_q_i64 alias, and the section emitters live in
 * views/explorer_stats_internal.h + explorer_stats_sections.c
 * (shared stats-view internals). */

/* Generate CSS for tab sections — each section needs unique IDs */
static void stats_tab_css(char *r, size_t max, size_t *off,
                            const char *prefix, const char *color,
                            int num_tabs, const char *tab_ids[])
{
    if (!r || !off || !prefix || !color || !tab_ids) return;
    for (int i = 0; i < num_tabs; i++) {
        APPEND(*off, r, max,
            "#%s%s:checked ~ .tab-bar label[for=%s%s]"
            "{background:#111;color:%s;border-bottom-color:#111}",
            prefix, tab_ids[i], prefix, tab_ids[i], color);
    }
    for (int i = 0; i < num_tabs; i++) {
        APPEND(*off, r, max,
            "#%s%s:checked ~ #p-%s%s{display:block}",
            prefix, tab_ids[i], prefix, tab_ids[i]);
    }
}

/* Single-pass query for all sprout or sapling stats */
static void query_shielded_stats(sqlite3 *db, const char *col,
                                  struct shielded_stats *out)
{
    memset(out, 0, sizeof(*out));
    char sql[1024];
    snprintf(sql, sizeof(sql),
        "SELECT count(*), "
        "COALESCE(SUM(CASE WHEN %s>0 THEN %s ELSE 0 END),0), "
        "COALESCE(SUM(CASE WHEN %s<0 THEN %s ELSE 0 END),0), "
        "MIN(height), MAX(height), "
        "MIN(time), MAX(time) "
        "FROM blocks WHERE %s != 0",
        col, col, col, col, col);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
        if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
            out->block_count    = sqlite3_column_int64(s, 0);
            out->sum_pos        = sqlite3_column_int64(s, 1);
            out->sum_neg        = sqlite3_column_int64(s, 2);
            out->first_height   = sqlite3_column_int64(s, 3);
            out->last_height    = sqlite3_column_int64(s, 4);
            out->first_time     = sqlite3_column_int64(s, 5);
            out->last_time      = sqlite3_column_int64(s, 6);
        }
        sqlite3_finalize(s);
    }
    /* Peak positive */
    snprintf(sql, sizeof(sql),
        "SELECT height, %s FROM blocks WHERE %s > 0 "
        "ORDER BY %s DESC LIMIT 1", col, col, col);
    s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
        if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
            out->peak_pos_height = sqlite3_column_int64(s, 0);
            out->peak_pos_value  = sqlite3_column_int64(s, 1);
        }
        sqlite3_finalize(s);
    }
    /* Peak negative */
    snprintf(sql, sizeof(sql),
        "SELECT height, %s FROM blocks WHERE %s < 0 "
        "ORDER BY %s ASC LIMIT 1", col, col, col);
    s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
        if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
            out->peak_neg_height = sqlite3_column_int64(s, 0);
            out->peak_neg_value  = sqlite3_column_int64(s, 1);
        }
        sqlite3_finalize(s);
    }
}

/* Render shielded section HTML (sprout or sapling).
 * pos_is_shielding: true for Sprout (positive sprout_value = shielding),
 *                   false for Sapling (positive value_balance = unshielding). */
static void render_shielded_section(char *r, size_t max, size_t *off,
    const char *title, const char *desc, const struct shielded_stats *ss,
    int64_t nullifier_count, /* -1 to skip */
    sqlite3 *db, const char *col, int start_year, bool pos_is_shielding)
{
    char in_str[32], out_str[32], peak_str[32], peak_neg_str[32], net_str[32];
    /* Sign conventions differ: Sprout pos=shielding, Sapling pos=unshielding */
    int64_t total_shielded, total_unshielded, peak_shield_val, peak_unshield_val;
    int64_t peak_shield_h, peak_unshield_h;
    if (pos_is_shielding) {
        /* Sprout: positive = shielding, negative = unshielding */
        total_shielded = ss->sum_pos;
        total_unshielded = ss->sum_neg < 0 ? -ss->sum_neg : ss->sum_neg;
        peak_shield_val = ss->peak_pos_value;
        peak_shield_h = ss->peak_pos_height;
        peak_unshield_val = ss->peak_neg_value < 0 ? -ss->peak_neg_value : ss->peak_neg_value;
        peak_unshield_h = ss->peak_neg_height;
    } else {
        /* Sapling: positive = unshielding, negative = shielding */
        total_shielded = ss->sum_neg < 0 ? -ss->sum_neg : ss->sum_neg;
        total_unshielded = ss->sum_pos;
        peak_shield_val = ss->peak_neg_value < 0 ? -ss->peak_neg_value : ss->peak_neg_value;
        peak_shield_h = ss->peak_neg_height;
        peak_unshield_val = ss->peak_pos_value;
        peak_unshield_h = ss->peak_pos_height;
    }
    zcl_format_zcl(in_str, sizeof(in_str), total_shielded);
    zcl_format_zcl(out_str, sizeof(out_str), total_unshielded);
    zcl_format_zcl(peak_str, sizeof(peak_str), peak_shield_val);
    zcl_format_zcl(peak_neg_str, sizeof(peak_neg_str), peak_unshield_val);
    int64_t net = (int64_t)total_shielded - (int64_t)total_unshielded;
    zcl_format_zcl(net_str, sizeof(net_str), net);

    char first_ts[32] = "N/A", last_ts[32] = "N/A";
    if (ss->first_time > 0) explorer_format_time(first_ts, sizeof(first_ts), (uint32_t)ss->first_time);
    if (ss->last_time > 0) explorer_format_time(last_ts, sizeof(last_ts), (uint32_t)ss->last_time);

    APPEND(*off, r, max,
        "<h2>%s</h2>"
        "<p style='color:#888;margin:-4px 0 12px;font-size:14px'>%s</p>"
        "<div class='stats-row'>"
        "<div class='stat'><div class='num'>%" PRId64 "</div>"
        "<div class='lbl'>Blocks with Activity</div></div>"
        "<div class='stat'><div class='num'>%s ZCL</div>"
        "<div class='lbl'>Net Pool Balance</div></div>",
        title, desc, ss->block_count, net_str);
    if (nullifier_count >= 0) {
        APPEND(*off, r, max,
            "<div class='stat'><div class='num'>%" PRId64 "</div>"
            "<div class='lbl'>Nullifiers</div></div>",
            nullifier_count);
    }
    APPEND(*off, r, max, "</div>");

    APPEND(*off, r, max,
        "<div class='card'><div class='grid'>"
        "<div class='label'>Total Shielded (t&rarr;z)</div>"
        "<div class='val amount'>%s ZCL</div>"
        "<div class='label'>Total Unshielded (z&rarr;t)</div>"
        "<div class='val amount'>%s ZCL</div>"
        "<div class='label'>First Active Block</div>"
        "<div class='val'><a href='/explorer/block/%" PRId64 "'>Block %" PRId64 "</a>"
        " &mdash; %s</div>"
        "<div class='label'>Last Active Block</div>"
        "<div class='val'><a href='/explorer/block/%" PRId64 "'>Block %" PRId64 "</a>"
        " &mdash; %s</div>",
        in_str, out_str,
        ss->first_height, ss->first_height, first_ts,
        ss->last_height, ss->last_height, last_ts);

    if (peak_shield_val > 0) {
        APPEND(*off, r, max,
            "<div class='label'>Largest Single Shielding</div>"
            "<div class='val'><a href='/explorer/block/%" PRId64 "'>Block %" PRId64 "</a>"
            " &mdash; %s ZCL</div>",
            peak_shield_h, peak_shield_h, peak_str);
    }
    if (peak_unshield_val > 0) {
        APPEND(*off, r, max,
            "<div class='label'>Largest Single Unshielding</div>"
            "<div class='val'><a href='/explorer/block/%" PRId64 "'>Block %" PRId64 "</a>"
            " &mdash; %s ZCL</div>",
            peak_unshield_h, peak_unshield_h, peak_neg_str);
    }
    APPEND(*off, r, max, "</div></div>");

    /* Yearly breakdown — single query with GROUP BY */
    APPEND(*off, r, max,
        "<h3>Activity by Year</h3>"
        "<table><tr><th>Year</th><th>Blocks</th>"
        "<th>Shielded (t&rarr;z)</th><th>Unshielded (z&rarr;t)</th>"
        "<th>Net Change</th></tr>");
    {
        char sql[512];
        snprintf(sql, sizeof(sql),
            "SELECT CAST(strftime('%%Y', time, 'unixepoch') AS INTEGER) AS yr, "
            "count(*), "
            "COALESCE(SUM(CASE WHEN %s>0 THEN %s ELSE 0 END),0), "
            "COALESCE(SUM(CASE WHEN %s<0 THEN %s ELSE 0 END),0) "
            "FROM blocks WHERE %s != 0 AND time > 0 "
            "GROUP BY yr ORDER BY yr",
            col, col, col, col, col);
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                int year = sqlite3_column_int(s, 0);
                int64_t cnt = sqlite3_column_int64(s, 1);
                int64_t shield = sqlite3_column_int64(s, 2);
                int64_t unshield = sqlite3_column_int64(s, 3);
                if (cnt > 0 && year >= start_year) {
                    char sh[32], un[32], nt[32];
                    int64_t yr_shield, yr_unshield;
                    if (pos_is_shielding) {
                        yr_shield = shield;
                        yr_unshield = unshield < 0 ? -unshield : unshield;
                    } else {
                        yr_shield = unshield < 0 ? -unshield : unshield;
                        yr_unshield = shield;
                    }
                    zcl_format_zcl(sh, sizeof(sh), yr_shield);
                    zcl_format_zcl(un, sizeof(un), yr_unshield);
                    zcl_format_zcl(nt, sizeof(nt), yr_shield - yr_unshield);
                    APPEND(*off, r, max,
                        "<tr><td>%d</td><td>%" PRId64 "</td>"
                        "<td class='amount'>%s</td>"
                        "<td class='amount'>%s</td>"
                        "<td class='amount'>%s</td></tr>",
                        year, cnt, sh, un, nt);
                }
            }
            sqlite3_finalize(s);
        }
    }
    APPEND(*off, r, max, "</table>");

    /* Top 20 by absolute value */
    APPEND(*off, r, max,
        "<h3>Top 20 Largest Transactions (by block)</h3>"
        "<table><tr><th>Block</th><th>Time</th><th>Value</th>"
        "<th>Direction</th></tr>");
    {
        char sql[256];
        snprintf(sql, sizeof(sql),
            "SELECT height, time, %s FROM blocks "
            "WHERE %s != 0 ORDER BY ABS(%s) DESC LIMIT 20",
            col, col, col);
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                int64_t h = sqlite3_column_int64(s, 0);
                int64_t t = sqlite3_column_int64(s, 1);
                int64_t v = sqlite3_column_int64(s, 2);
                char ts[32], vs[32];
                explorer_format_time(ts, sizeof(ts), (uint32_t)t);
                zcl_format_zcl(vs, sizeof(vs), v < 0 ? -v : v);
                APPEND(*off, r, max,
                    "<tr><td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>"
                    "<td>%s</td><td class='amount'>%s ZCL</td>"
                    "<td>%s</td></tr>",
                    h, h, ts, vs,
                    (pos_is_shielding ? v > 0 : v < 0)
                        ? "<span style='color:#33ff99'>Shielding</span>"
                        : "<span style='color:#ff6666'>Unshielding</span>");
            }
            sqlite3_finalize(s);
        }
    }
    APPEND(*off, r, max, "</table>");
}

/* Emit a tabbed chart set */
static void render_tabbed_chart(char *r, size_t max, size_t *off,
    const char *heading, const char *tab_name, const char *color,
    double data[5][40], char labels[5][40][20],
    const char *y_label, const char *range_ids[])
{
    APPEND(*off, r, max,
        "<h2>%s</h2><div class='tabs'>", heading);
    for (int i = 0; i < 5; i++)
        APPEND(*off, r, max,
            "<input type='radio' name='%stab' id='%s%s'%s>",
            tab_name, tab_name, range_ids[i], i == 2 ? " checked" : "");
    APPEND(*off, r, max, "<div class='tab-bar'>");
    const char *tab_labels[] = {"24h","7 Days","30 Days","1 Year","All Time"};
    for (int i = 0; i < 5; i++)
        APPEND(*off, r, max,
            "<label for='%s%s'>%s</label>",
            tab_name, range_ids[i], tab_labels[i]);
    APPEND(*off, r, max, "</div>");
    for (int ri = 0; ri < 5; ri++) {
        APPEND(*off, r, max, "<div class='panel' id='p-%s%s'>", tab_name, range_ids[ri]);
        explorer_svg_line_chart(r, max, off, "", color, data[ri], labels[ri], 40, y_label);
        APPEND(*off, r, max, "</div>");
    }
    APPEND(*off, r, max, "</div>");
}

static size_t explorer_stats_build_verified_summary(uint8_t *r, size_t max,
                                                    sqlite3 *db)
{
    size_t off = 0;
    /* Current Height = the chain tip (blocks projection tracks it), NOT the
     * UTXO-mirror max — the mirror can lag/freeze (cold-import restart), and
     * labeling its stale height as "Current Height" mis-states the chain and
     * mis-computes Consensus Supply (zcl_total_supply_zatoshi below). */
    int64_t chain_height = stats_q_i64(db, "SELECT COALESCE(MAX(height),0) FROM blocks");
    int64_t block_rows = stats_q_i64(db, "SELECT count(*) FROM blocks");
    int64_t tx_rows = stats_q_i64(db, "SELECT count(*) FROM transactions");
    int64_t utxo_count = stats_q_i64(db, "SELECT count(*) FROM utxos");
    int64_t utxo_value = stats_q_i64(db, "SELECT COALESCE(SUM(value),0) FROM utxos");
    int64_t dust = stats_q_i64(db, "SELECT count(*) FROM utxos WHERE value < 100000");
    int64_t addresses = stats_q_i64(db, "SELECT count(*) FROM addresses");
    int64_t nonzero_addresses = stats_q_i64(db,
        "SELECT count(*) FROM addresses WHERE balance > 0");
    int64_t supply = zcl_total_supply_zatoshi(chain_height);

    char supply_str[64], utxo_str[64];
    zcl_format_zcl(supply_str, sizeof(supply_str), supply);
    zcl_format_zcl(utxo_str, sizeof(utxo_str), utxo_value);

    APPEND(off, (char *)r, max, EXPLORER_HEADER("ZClassic Stats"));
    off += explorer_emit_nav((char *)r + off, max - off, "stats");
    APPEND(off, (char *)r, max,
        "<h1>ZClassic Stats</h1>"
        "<h2>Current State</h2>"
        "<div class='stats-row'>"
        "<div class='stat'><div class='num'>%" PRId64 "</div><div class='lbl'>Current Height</div></div>"
        "<div class='stat'><div class='num'>%s ZCL</div><div class='lbl'>Consensus Supply</div></div>"
        "<div class='stat'><div class='num'>%" PRId64 "</div><div class='lbl'>UTXOs</div></div>"
        "</div>"
        "<div class='stats-row'>"
        "<div class='stat'><div class='num'>%s ZCL</div><div class='lbl'>Transparent UTXO Value</div></div>"
        "<div class='stat'><div class='num'>%" PRId64 "</div><div class='lbl'>Dust UTXOs</div></div>"
        "<div class='stat'><div class='num'>%" PRId64 "</div><div class='lbl'>Nonzero Addresses</div></div>"
        "</div>"
        "<h2>Index Coverage</h2>"
        "<table class='txlist'>"
        "<tr><th>Table</th><th>Rows</th></tr>"
        "<tr><td>blocks</td><td>%" PRId64 "</td></tr>"
        "<tr><td>transactions</td><td>%" PRId64 "</td></tr>"
        "<tr><td>utxos</td><td>%" PRId64 "</td></tr>"
        "<tr><td>addresses</td><td>%" PRId64 "</td></tr>"
        "</table>"
        "<p style='color:#888;font-size:0.9em;margin-top:14px'>"
        "Some historical charts (per-year transactions, difficulty over "
        "time, empty-block ratio) require a fully populated block-history "
        "index. The current datadir has a partial index pending backfill; "
        "those charts will appear once the indexer completes."
        "</p>"
        EXPLORER_FOOTER,
        chain_height, supply_str, utxo_count,
        utxo_str, dust, nonzero_addresses,
        block_rows, tx_rows, utxo_count, addresses);
    return off;
}



/* ── Main stats builder ──────────────────────────────────── */

size_t explorer_stats_build(uint8_t *r, size_t buf_max, const char *datadir)
{
    if (!r || buf_max == 0 || !datadir)
        return 0;

    int64_t t_start_ms = (int64_t)platform_time_wall_time_t();
    size_t max = buf_max;
    size_t off = 0;

    sqlite3 *db = NULL;
    char db_path[1024];
    snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    if (!explorer_open_readonly_db(datadir, &db)) {
        /* explorer_open_readonly_db() already ran the real open attempt
         * and closed/NULLed db on failure; re-open here only to recover
         * the sqlite rc/errmsg for the diagnostic below. */
        int open_rc = sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL);
        LOG_WARN("explorer",
                 "Stats: failed to open %s: %s (rc=%d)",
                 db_path, db ? sqlite3_errmsg(db) : "null", open_rc);
        if (db) sqlite3_close(db);
        return 0;
    }
    sqlite3_exec(db, "PRAGMA query_only=ON", NULL, NULL, NULL);

    /* ════════════════════════════════════════════════════════
     *  PHASE 1: Gather all data with minimal queries
     * ════════════════════════════════════════════════════════ */

    LOG_INFO("explorer", "Stats: phase 1 — gathering data...");

    /* ── 1a: Tip block ── */
    int tip = 0;
    double diff = 0;
    int64_t tip_time = 0;
    {
        sqlite3_stmt *s = NULL;
        int prep_rc = sqlite3_prepare_v2(db,
                "SELECT height, bits, time FROM blocks ORDER BY height DESC LIMIT 1",
                -1, &s, NULL);
        if (prep_rc == SQLITE_OK && s) {
            int step_rc = AR_STEP_ROW_READONLY(s);
            if (step_rc == SQLITE_ROW) {
                tip = sqlite3_column_int(s, 0);
                uint32_t bits = (uint32_t)sqlite3_column_int(s, 1);
                tip_time = sqlite3_column_int64(s, 2);
                if (bits > 0)
                    diff = explorer_difficulty_from_bits(bits);
            } else {
                LOG_WARN("explorer",
                         "Stats: tip query step failed: rc=%d %s",
                         step_rc, sqlite3_errmsg(db));
            }
            sqlite3_finalize(s);
        } else {
            LOG_WARN("explorer",
                     "Stats: tip query prepare failed: rc=%d %s",
                     prep_rc, sqlite3_errmsg(db));
        }
    }
    if (tip <= 0) {
        LOG_WARN("explorer", "Stats: no blocks (tip=%d, db=%s)", tip, db_path);
        sqlite3_close(db);
        return 0;
    }
    if (!explorer_block_history_usable_for_height(db, tip)) {
        size_t len = explorer_stats_build_verified_summary(r, max, db);
        sqlite3_close(db);
        return len;
    }

    /* ── 1b: Single-pass block aggregates ── */
    int64_t total_blocks = 0, total_block_txs = 0, empty_blocks = 0;
    int64_t max_tx_count = 0, max_tx_block = 0;
    /* ZClassic genesis: Nov 6, 2016 00:03:49 UTC */
    int64_t genesis_time = 1478403829;
    uint32_t min_bits = 0, max_bits = 0;
    int64_t min_bits_height = 0, max_bits_height = 0;
    {
        sqlite3_stmt *s = NULL;
        /* Consolidated: count, sum(num_tx), count(empty), max(num_tx) */
        if (sqlite3_prepare_v2(db,
                "SELECT count(*), COALESCE(SUM(num_tx),0), "
                "SUM(CASE WHEN num_tx<=1 THEN 1 ELSE 0 END), "
                "MAX(num_tx) "
                "FROM blocks",
                -1, &s, NULL) == SQLITE_OK && s) {
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                total_blocks    = sqlite3_column_int64(s, 0);
                total_block_txs = sqlite3_column_int64(s, 1);
                empty_blocks    = sqlite3_column_int64(s, 2);
                max_tx_count    = sqlite3_column_int64(s, 3);
            }
            sqlite3_finalize(s);
        }
        /* Block with most txs */
        max_tx_block = stats_q_i64(db,
            "SELECT height FROM blocks ORDER BY num_tx DESC LIMIT 1");
        /* Difficulty extremes (bits DESC = lowest diff, bits ASC = highest diff) */
        s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT height, bits FROM blocks WHERE bits > 0 "
                "ORDER BY bits DESC LIMIT 1", -1, &s, NULL) == SQLITE_OK && s) {
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                min_bits_height = sqlite3_column_int64(s, 0);
                min_bits = (uint32_t)sqlite3_column_int(s, 1);
            }
            sqlite3_finalize(s);
        }
        s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT height, bits FROM blocks WHERE bits > 0 AND height > 0 "
                "ORDER BY bits ASC LIMIT 1", -1, &s, NULL) == SQLITE_OK && s) {
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                max_bits_height = sqlite3_column_int64(s, 0);
                max_bits = (uint32_t)sqlite3_column_int(s, 1);
            }
            sqlite3_finalize(s);
        }
    }
    double min_diff = explorer_difficulty_from_bits(min_bits);
    double max_diff = explorer_difficulty_from_bits(max_bits);
    double avg_tx_per_block = total_blocks > 0
        ? (double)total_block_txs / total_blocks : 0;

    /* ── 1c: UTXO consolidated aggregate ── */
    int64_t total_supply = 0, utxo_count_val = 0;
    int64_t utxo_dust = 0, utxo_small = 0, utxo_medium = 0;
    int64_t utxo_large = 0, utxo_whale = 0;
    int64_t utxo_max_value = 0, utxo_min_height = 0;
    int64_t utxo_coinbase_count = 0, utxo_coinbase_value = 0;
    double utxo_avg = 0;
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT count(*), COALESCE(SUM(value),0), "
                "AVG(value), MAX(value), MIN(height), "
                "SUM(CASE WHEN value < 100000 THEN 1 ELSE 0 END), "
                "SUM(CASE WHEN value >= 100000 AND value < 100000000 THEN 1 ELSE 0 END), "
                "SUM(CASE WHEN value >= 100000000 AND value < 1000000000 THEN 1 ELSE 0 END), "
                "SUM(CASE WHEN value >= 1000000000 AND value < 10000000000 THEN 1 ELSE 0 END), "
                "SUM(CASE WHEN value >= 10000000000 THEN 1 ELSE 0 END), "
                "SUM(CASE WHEN is_coinbase=1 THEN 1 ELSE 0 END), "
                "COALESCE(SUM(CASE WHEN is_coinbase=1 THEN value ELSE 0 END),0) "
                "FROM utxos",
                -1, &s, NULL) == SQLITE_OK && s) {
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                utxo_count_val      = sqlite3_column_int64(s, 0);
                total_supply        = sqlite3_column_int64(s, 1);
                utxo_avg            = sqlite3_column_double(s, 2);
                utxo_max_value      = sqlite3_column_int64(s, 3);
                utxo_min_height     = sqlite3_column_int64(s, 4);
                utxo_dust           = sqlite3_column_int64(s, 5);
                utxo_small          = sqlite3_column_int64(s, 6);
                utxo_medium         = sqlite3_column_int64(s, 7);
                utxo_large          = sqlite3_column_int64(s, 8);
                utxo_whale          = sqlite3_column_int64(s, 9);
                utxo_coinbase_count = sqlite3_column_int64(s, 10);
                utxo_coinbase_value = sqlite3_column_int64(s, 11);
            }
            sqlite3_finalize(s);
        }
    }

    /* ── 1d: Transaction count ── */
    int64_t total_txs = stats_q_i64(db, "SELECT count(*) FROM transactions");
    int64_t coinbase_txs = stats_q_i64(db,
        "SELECT count(*) FROM transactions WHERE is_coinbase=1");

    /* ── 1e: Sprout + Sapling — single-pass each ── */
    LOG_INFO("explorer", "Stats: querying shielded pools...");
    struct shielded_stats sprout, sapling;
    query_shielded_stats(db, "sprout_value", &sprout);
    query_shielded_stats(db, "sapling_value", &sapling);
    int64_t nullifier_count = stats_q_i64(db, "SELECT count(*) FROM sapling_nullifiers");

    /* ── 1f: Address stats ── */
    int64_t total_addresses = stats_q_i64(db, "SELECT count(*) FROM addresses");
    int64_t addr_nonzero = stats_q_i64(db,
        "SELECT count(*) FROM addresses WHERE balance > 0");
    int64_t top10_balance = stats_q_i64(db,
        "SELECT COALESCE(SUM(balance),0) FROM "
        "(SELECT balance FROM addresses ORDER BY balance DESC LIMIT 10)");
    int64_t top100_balance = stats_q_i64(db,
        "SELECT COALESCE(SUM(balance),0) FROM "
        "(SELECT balance FROM addresses ORDER BY balance DESC LIMIT 100)");

    /* ── 1g: ZSLP / OP_RETURN ── */
    int64_t opret_count = stats_q_i64(db, "SELECT count(*) FROM op_returns");
    int64_t slp_opret_count = stats_q_i64(db,
        "SELECT count(*) FROM op_returns WHERE is_slp=1");
    int64_t zslp_token_count = stats_q_i64(db, "SELECT count(*) FROM zslp_tokens");
    int64_t zslp_transfer_count = stats_q_i64(db, "SELECT count(*) FROM zslp_transfers");

    /* ── 1h + 1i ── filled into ctx / chart_data by helpers below.
     * Declare ctx + chart_data here so the gather helpers can write
     * directly into them; PHASE 2 builds on top of these structures. */
    struct stats_ctx ctx = {0};
    struct stats_chart_data chart_data;
    gather_deep_chain_data(db, &ctx);
    gather_chart_data(db, tip, diff, &chart_data);
    gather_economy_data(db, tip, tip_time, &ctx);

    /* ── Derived values ── */
    /* Equihash measures SOLUTIONS, not hashes, at every (N,K). The estimate uses
     * the ACTIVE target spacing (75s post-Buttercup, 150s before) — the old
     * hard-coded /150 under-reported the live rate ~2x. */
    double solrate = explorer_solrate_from_diff(diff, tip);
    char hr_str[64];
    explorer_format_solrate(hr_str, sizeof(hr_str), solrate);

    char supply_str[32];
    zcl_format_zcl(supply_str, sizeof(supply_str), total_supply);

    int64_t chain_age_days = 0;
    if (genesis_time > 0 && tip_time > genesis_time)
        chain_age_days = (tip_time - genesis_time) / 86400;

    /* Buttercup-aware halving calculation */
    int halvings;
    int next_halving;
    int blocks_until_halving;
    int64_t current_subsidy;
    if (tip >= BUTTERCUP_ACTIVATION_HEIGHT) {
        int era = (int)(((int64_t)tip - 1 - BUTTERCUP_ACTIVATION_HEIGHT) / POST_BC_HALVING);
        halvings = era + 3;
        current_subsidy = (BASE_SUBSIDY_SAT / 2) >> halvings;
        next_halving = (int)(BUTTERCUP_ACTIVATION_HEIGHT + 1 +
                             ((int64_t)(era + 1)) * POST_BC_HALVING);
        blocks_until_halving = next_halving - tip;
    } else {
        halvings = tip / PRE_BC_HALVING;
        next_halving = (halvings + 1) * PRE_BC_HALVING;
        blocks_until_halving = next_halving - tip;
        current_subsidy = BASE_SUBSIDY_SAT >> halvings;
    }
    /* Correct max supply using Buttercup-aware computation */
    int64_t max_supply_sat = zcl_total_supply_zatoshi(100000000LL);
    double pct_mined = (max_supply_sat > 0)
        ? (double)total_supply / (double)max_supply_sat * 100.0 : 0.0;

    /* ── Economy & emission derived factoids ── */
    int64_t mined_supply = zcl_total_supply_zatoshi(tip);
    double pct_of_cap = (max_supply_sat > 0)
        ? (double)mined_supply / (double)max_supply_sat * 100.0 : 0.0;
    double daily_issuance_zcl = (double)current_subsidy / 1e8
        * 86400.0 / (double)explorer_target_spacing(tip);
    double annual_inflation = mined_supply > 0
        ? daily_issuance_zcl * 365.25 / ((double)mined_supply / 1e8) * 100.0 : 0.0;
    int64_t halving_eta_secs =
        (ctx.recent_avg_interval > 0 && blocks_until_halving > 0)
            ? (int64_t)((double)blocks_until_halving * ctx.recent_avg_interval)
            : 0;
    int64_t now_wall = (int64_t)platform_time_wall_time_t();
    int64_t tip_age_secs = (now_wall > tip_time) ? now_wall - tip_time : 0;

    int64_t t_query_ms = (int64_t)platform_time_wall_time_t() - t_start_ms;
    LOG_INFO("explorer", "Stats: phase 1 complete in %llds, building HTML...",
        (long long)t_query_ms);

    /* ════════════════════════════════════════════════════════
     *  PHASE 2: Render HTML
     * ════════════════════════════════════════════════════════ */

    /* Populate the non-deep-chain ctx fields here. The deep-chain
     * group (tx I/O, joinsplits, sapling, integrity, firsts/records)
     * was filled in PHASE 1 by gather_deep_chain_data(). */
    ctx.tip = tip; ctx.diff = diff; ctx.tip_time = tip_time;
    ctx.genesis_time = genesis_time; ctx.chain_age_days = chain_age_days;
    ctx.total_blocks = total_blocks; ctx.total_block_txs = total_block_txs;
    ctx.empty_blocks = empty_blocks;
    ctx.max_tx_count = max_tx_count; ctx.max_tx_block = max_tx_block;
    ctx.min_bits = min_bits; ctx.max_bits = max_bits;
    ctx.min_bits_height = min_bits_height; ctx.max_bits_height = max_bits_height;
    ctx.min_diff = min_diff; ctx.max_diff = max_diff;
    ctx.avg_tx_per_block = avg_tx_per_block;
    ctx.total_supply = total_supply; ctx.utxo_count_val = utxo_count_val;
    ctx.utxo_dust = utxo_dust; ctx.utxo_small = utxo_small;
    ctx.utxo_medium = utxo_medium; ctx.utxo_large = utxo_large;
    ctx.utxo_whale = utxo_whale;
    ctx.utxo_max_value = utxo_max_value; ctx.utxo_min_height = utxo_min_height;
    ctx.utxo_coinbase_count = utxo_coinbase_count;
    ctx.utxo_coinbase_value = utxo_coinbase_value;
    ctx.utxo_avg = utxo_avg;
    ctx.total_txs = total_txs; ctx.coinbase_txs = coinbase_txs;
    ctx.sprout = sprout; ctx.sapling = sapling;
    ctx.nullifier_count = nullifier_count;
    ctx.total_addresses = total_addresses; ctx.addr_nonzero = addr_nonzero;
    ctx.top10_balance = top10_balance; ctx.top100_balance = top100_balance;
    ctx.opret_count = opret_count; ctx.slp_opret_count = slp_opret_count;
    ctx.zslp_token_count = zslp_token_count;
    ctx.zslp_transfer_count = zslp_transfer_count;
    ctx.halvings = halvings; ctx.next_halving = next_halving;
    ctx.blocks_until_halving = blocks_until_halving;
    ctx.current_subsidy = current_subsidy;
    ctx.pct_mined = pct_mined;
    ctx.t_query_ms = t_query_ms;
    /* Economy & emission (recent-window aggregates already gathered into
     * ctx by gather_economy_data; here we add the derived scalars). */
    ctx.mined_supply = mined_supply;
    ctx.max_supply_sat = max_supply_sat;
    ctx.pct_of_cap = pct_of_cap;
    ctx.solrate = solrate;
    ctx.daily_issuance_zcl = daily_issuance_zcl;
    ctx.annual_inflation = annual_inflation;
    ctx.halving_eta_secs = halving_eta_secs;
    ctx.tip_age_secs = tip_age_secs;
    snprintf(ctx.hr_str, sizeof(ctx.hr_str), "%s", hr_str);
    snprintf(ctx.supply_str, sizeof(ctx.supply_str), "%s", supply_str);

    off = emit_stats_header(r, max, off, &ctx);
    off = emit_section_1_network(r, max, off, &ctx);
    off = emit_section_1b_economy(r, max, off, &ctx);
    off = emit_section_2_chain_history(r, max, off, &ctx);
    off = emit_section_3_block_records(r, max, off, &ctx);

    /* Section 4: Sprout */
    render_shielded_section((char *)r, max, &off,
        "Sprout Pool (JoinSplit Privacy)",
        "Sprout was ZClassic's original shielded pool using JoinSplit proofs. "
        "vpub_old = value entering Sprout pool from transparent (shielding), "
        "vpub_new = value leaving Sprout pool to transparent (unshielding).",
        &sprout, -1, db, "sprout_value", 2016, true);

    /* Section 5: Sapling */
    render_shielded_section((char *)r, max, &off,
        "Sapling Pool (Modern Privacy)",
        "Sapling uses Groth16 proofs. Activated at block 382168. "
        "Positive value_balance = unshielding (z&rarr;t), "
        "negative = shielding (t&rarr;z).",
        &sapling, nullifier_count, db, "sapling_value", 2018, false);

    off = emit_section_6_utxo_distribution(r, max, off, &ctx, db);
    off = emit_section_7_address_distribution(r, max, off, &ctx, db);
    off = emit_section_8_zslp_opret(r, max, off, &ctx);
    off = emit_section_8b_tx_io(r, max, off, &ctx);
    off = emit_section_8c_shielded_detail(r, max, off, &ctx);
    off = emit_section_8d_integrity(r, max, off, &ctx);
    off = emit_section_8e_firsts(r, max, off, &ctx);
    off = emit_section_9_tx_volume_by_year(r, max, off, db);
    off = emit_section_10_utxo_age(r, max, off, &ctx, db);

    /* HODL link */
    APPEND(off, r, max,
        "<div class='card' style='text-align:center'>"
        "<a href='/explorer/hodl' style='font-size:20px;font-weight:700'>"
        "View HODL Wave &rarr;</a>"
        "<p style='color:#888;margin:4px 0 0;font-size:14px'>"
        "Current transparent UTXO age distribution</p></div>");

    /* Tab CSS */
    APPEND(off, r, max,
        "<style>"
        ".tabs input{display:none}"
        ".tabs .tab-bar{display:flex;gap:0;margin:12px 0 0}"
        ".tabs label{padding:10px 20px;background:#1a1a1a;color:#888;"
        "cursor:pointer;font-size:16px;font-weight:600;border:1px solid #222;"
        "border-bottom:none;border-radius:8px 8px 0 0;transition:all 0.2s}"
        ".tabs label:hover{color:#fff;background:#222}"
        ".tabs .panel{display:none;background:#111;border:1px solid #222;"
        "border-radius:0 8px 8px 8px;padding:16px}");
    {
        const char *ids[] = {"24h","7d","30d","1y","all"};
        stats_tab_css((char *)r, max, &off, "d", "#4db8ff", 5, ids);
        stats_tab_css((char *)r, max, &off, "h", "#33ff99", 5, ids);
        stats_tab_css((char *)r, max, &off, "sv", "#ff9933", 5, ids);
        stats_tab_css((char *)r, max, &off, "sp", "#aa66ff", 5, ids);
        stats_tab_css((char *)r, max, &off, "tx", "#ff6699", 5, ids);
    }
    APPEND(off, r, max, "</style>");

    /* Charts */
    const char *rids[] = {"24h","7d","30d","1y","all"};
    render_tabbed_chart((char *)r, max, &off,
        "Difficulty", "d", "#4db8ff", chart_data.diff_data, chart_data.labels, "Difficulty", rids);
    render_tabbed_chart((char *)r, max, &off,
        "Solve Rate", "h", "#33ff99", chart_data.hr_data, chart_data.labels, "Sol/s", rids);
    render_tabbed_chart((char *)r, max, &off,
        "Sprout Value Flow", "sv", "#ff9933", chart_data.sprout_c, chart_data.labels, "ZCL", rids);
    render_tabbed_chart((char *)r, max, &off,
        "Sapling Value Flow", "sp", "#aa66ff", chart_data.sapling_c, chart_data.labels, "ZCL", rids);
    render_tabbed_chart((char *)r, max, &off,
        "Transaction Volume", "tx", "#ff6699", chart_data.txcount, chart_data.labels, "Transactions", rids);

    APPEND(off, r, max, EXPLORER_FOOTER);

    sqlite3_close(db);
    LOG_INFO("explorer", "Stats: built %zu bytes (tip=%d) in %llds total",
        off, tip, (long long)((int64_t)platform_time_wall_time_t() - t_start_ms));
    return off;
}
