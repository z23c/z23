/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer factoids VIEW - block-time analysis section renderer.
 *
 * Owns section 13's display-only cadence analysis. Consensus timestamp and
 * difficulty validation live below the View layer. */

#include "views/explorer_factoids_internal.h"

size_t factoids_emit_section_13_blocktimes(uint8_t *buf, size_t cap, size_t off,
                                           sqlite3 *db, int64_t chain_height)
{
    char *r = (char *)buf;
    size_t max = cap;

    APPEND(off, r, max,
        "<h2 id='blocktimes'>13. Block Time Analysis</h2>"
        "<p style='color:#888'>Pre-Buttercup target: 150s. "
        "Post-Buttercup target: 75s. Actual times from chain data.</p>");

    char pre_bc_sql[512];
    snprintf(pre_bc_sql, sizeof(pre_bc_sql),
        "SELECT AVG(b.time - a.time), "
        "MIN(CASE WHEN b.time - a.time > 0 THEN b.time - a.time END), "
        "MAX(b.time - a.time), "
        "count(*) "
        "FROM blocks a JOIN blocks b ON b.height = a.height + 1 "
        "WHERE a.time > 0 AND b.time > 0 AND b.height < %d",
        BUTTERCUP_ACTIVATION_HEIGHT);
    {
        sqlite3_stmt *s = NULL;
        const char *sql = pre_bc_sql;
        if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                double avg = sqlite3_column_double(s, 0);
                int64_t mn = sqlite3_column_int64(s, 1);
                int64_t mx = sqlite3_column_int64(s, 2);
                int64_t cnt = sqlite3_column_int64(s, 3);
                char rcpt[32] = "";
                compute_receipt_i64(rcpt, sizeof(rcpt), (int64_t)avg, cnt,
                                    "blocktime_pre_bc");
                APPEND(off, r, max,
                    "<div class='card'>"
                    "<h3>Pre-Buttercup (blocks 0\xe2\x80\x93" "706,999, target 150s)</h3>"
                    "<table>"
                    "<tr><td><b>Mean block time:</b></td><td>%.1fs</td></tr>"
                    "<tr><td><b>Shortest gap:</b></td><td>%" PRId64 "s</td></tr>"
                    "<tr><td><b>Longest gap:</b></td><td>%" PRId64 "s (%.1f min)</td></tr>"
                    "<tr><td><b>Block pairs analyzed:</b></td><td>%" PRId64 "</td></tr>"
                    "<tr><td><b>SHA3:</b></td><td><code>%s</code></td></tr>"
                    "</table></div>",
                    avg, mn, mx, (double)mx / 60.0, cnt, rcpt);
            }
            sqlite3_finalize(s);
        }
    }

    char post_bc_sql[512];
    snprintf(post_bc_sql, sizeof(post_bc_sql),
        "SELECT AVG(b.time - a.time), "
        "MIN(CASE WHEN b.time - a.time > 0 THEN b.time - a.time END), "
        "MAX(b.time - a.time), "
        "count(*) "
        "FROM blocks a JOIN blocks b ON b.height = a.height + 1 "
        "WHERE a.time > 0 AND b.time > 0 AND a.height >= %d",
        BUTTERCUP_ACTIVATION_HEIGHT);
    if (chain_height > BUTTERCUP_ACTIVATION_HEIGHT) {
        sqlite3_stmt *s = NULL;
        const char *sql = post_bc_sql;
        if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                double avg = sqlite3_column_double(s, 0);
                int64_t mn = sqlite3_column_int64(s, 1);
                int64_t mx = sqlite3_column_int64(s, 2);
                int64_t cnt = sqlite3_column_int64(s, 3);
                char rcpt[32] = "";
                compute_receipt_i64(rcpt, sizeof(rcpt), (int64_t)avg, cnt,
                                    "blocktime_post_bc");
                APPEND(off, r, max,
                    "<div class='card'>"
                    "<h3>Post-Buttercup (blocks 707,000+, target 75s)</h3>"
                    "<table>"
                    "<tr><td><b>Mean block time:</b></td><td>%.1fs</td></tr>"
                    "<tr><td><b>Shortest gap:</b></td><td>%" PRId64 "s</td></tr>"
                    "<tr><td><b>Longest gap:</b></td><td>%" PRId64 "s (%.1f min)</td></tr>"
                    "<tr><td><b>Block pairs analyzed:</b></td><td>%" PRId64 "</td></tr>"
                    "<tr><td><b>SHA3:</b></td><td><code>%s</code></td></tr>"
                    "</table></div>",
                    avg, mn, mx, (double)mx / 60.0, cnt, rcpt);
            }
            sqlite3_finalize(s);
        }
    }

    {
        int64_t tip = fq_i64(db, "SELECT COALESCE(MAX(height),0) FROM blocks");
        int64_t tip_time = fq_i64(db,
            "SELECT time FROM blocks WHERE height = (SELECT MAX(height) FROM blocks)");
        double avg_all = tip > 0
            ? (double)(tip_time - ZCL_EXPLORER_GENESIS_TIME) / (double)tip : 0.0;
        double avg_recent = 0.0;
        {
            char sql[160];
            snprintf(sql, sizeof(sql),
                "SELECT time FROM blocks WHERE height = %" PRId64,
                tip > 10000 ? tip - 10000 : (int64_t)0);
            int64_t t10k = fq_i64(db, sql);
            int64_t span = tip > 10000 ? 10000 : tip;
            if (span > 0 && t10k > 0)
                avg_recent = (double)(tip_time - t10k) / (double)span;
        }

        int64_t fast10 = 0, slow1h = 0, pairs = 0;
        {
            sqlite3_stmt *s = NULL;
            const char *sql =
                "SELECT "
                "SUM(CASE WHEN d > 0 AND d < 10 THEN 1 ELSE 0 END), "
                "SUM(CASE WHEN d > 3600 THEN 1 ELSE 0 END), "
                "count(*) FROM ("
                "SELECT b.time - a.time AS d FROM blocks a "
                "JOIN blocks b ON b.height = a.height + 1 "
                "WHERE a.time > 0 AND b.time > 0)";
            if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
                if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                    fast10 = sqlite3_column_int64(s, 0);
                    slow1h = sqlite3_column_int64(s, 1);
                    pairs  = sqlite3_column_int64(s, 2);
                }
                sqlite3_finalize(s);
            }
        }

        double fast_pct = pairs > 0 ? (double)fast10 * 100.0 / (double)pairs : 0.0;
        char f_s[32], sl_s[32], rcpt[32] = "";
        fmt_comma(f_s, sizeof(f_s), fast10);
        fmt_comma(sl_s, sizeof(sl_s), slow1h);
        compute_receipt_i64(rcpt, sizeof(rcpt), fast10, slow1h, "blocktime_records");

        APPEND(off, r, max,
            "<div class='card'>"
            "<h3>Block Interval Records</h3>"
            "<table>"
            "<tr><td><b>All-time average interval:</b></td><td>%.1fs</td></tr>"
            "<tr><td><b>Recent (last 10k) average:</b></td><td>%.1fs</td></tr>"
            "<tr><td><b>Blocks within 10s of the previous:</b></td>"
            "<td>%s (%.1f%%)</td></tr>"
            "<tr><td><b>Blocks over 1 hour apart:</b></td><td>%s</td></tr>"
            "<tr><td><b>SHA3:</b></td><td><code>%s</code></td></tr>"
            "</table></div>",
            avg_all, avg_recent, f_s, fast_pct, sl_s, rcpt);
    }
    return off;
}
