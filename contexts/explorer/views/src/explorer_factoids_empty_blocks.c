/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer factoids VIEW - empty-block analysis section renderer.
 *
 * Kept out of explorer_factoids_chaindata.c so the oversized chain-data
 * section file owns broad activity/archaeology orchestration while this file
 * owns section 15's empty-block totals and records. Display-only; consensus
 * block validation lives below the View layer. */

#include "views/explorer_factoids_internal.h"

size_t factoids_emit_section_15_empty_blocks(uint8_t *buf, size_t cap, size_t off,
                                             sqlite3 *db)
{
    char *r = (char *)buf;
    size_t max = cap;

    APPEND(off, r, max,
        "<h2 id='empty'>15. Empty Blocks Analysis</h2>"
        "<p style='color:#888'>Blocks with only a coinbase transaction "
        "(num_tx = 1, no user transactions).</p>");

    {
        int64_t empty_total = fq_i64(db,
            "SELECT count(*) FROM blocks WHERE num_tx = 1");
        int64_t total_blocks_2 = fq_i64(db, "SELECT count(*) FROM blocks");
        double empty_pct = total_blocks_2 > 0
            ? (double)empty_total * 100.0 / (double)total_blocks_2 : 0.0;

        char em_str[32], tb_str[32], rcpt[32] = "";
        fmt_comma(em_str, sizeof(em_str), empty_total);
        fmt_comma(tb_str, sizeof(tb_str), total_blocks_2);
        compute_receipt_i64(rcpt, sizeof(rcpt), empty_total, total_blocks_2,
                            "empty_blocks");

        APPEND(off, r, max,
            "<div class='card'>"
            "<p><b>Empty blocks (coinbase only):</b> %s of %s (%.1f%%)</p>"
            "<p><b>SHA3:</b> <code>%s</code></p>"
            "</div>",
            em_str, tb_str, empty_pct, rcpt);
    }

    APPEND(off, r, max,
        "<h3>Empty Blocks Per Year</h3>"
        "<table class='txlist'>"
        "<tr><th>Year</th><th>Empty Blocks</th><th>Total Blocks</th><th>%%</th></tr>");
    {
        sqlite3_stmt *s = NULL;
        const char *sql =
            "SELECT CAST(strftime('%Y', time, 'unixepoch') AS INTEGER) AS yr, "
            "SUM(CASE WHEN num_tx = 1 THEN 1 ELSE 0 END) AS empty, "
            "count(*) AS total "
            "FROM blocks WHERE time > 0 GROUP BY yr ORDER BY yr";
        if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                int yr = sqlite3_column_int(s, 0);
                int64_t empty = sqlite3_column_int64(s, 1);
                int64_t total = sqlite3_column_int64(s, 2);
                double pct = total > 0 ? (double)empty * 100.0 / (double)total : 0.0;
                APPEND(off, r, max,
                    "<tr><td>%d</td><td>%" PRId64 "</td>"
                    "<td>%" PRId64 "</td><td>%.1f%%</td></tr>",
                    yr, empty, total, pct);
            }
            sqlite3_finalize(s);
        }
    }
    APPEND(off, r, max, "</table>");

    {
        int64_t max_ntx = fq_i64(db, "SELECT COALESCE(MAX(num_tx),0) FROM blocks");
        int64_t busiest_h = 0;
        {
            char sql[128];
            snprintf(sql, sizeof(sql),
                "SELECT height FROM blocks WHERE num_tx = %" PRId64 " LIMIT 1",
                max_ntx);
            busiest_h = fq_i64(db, sql);
        }

        /* Longest run of consecutive empty blocks. The gaps-and-islands
         * window over the 2.2M empty blocks times out; the budget-safe
         * inversion is the largest gap between consecutive NON-empty
         * (num_tx>1) blocks. One window pass returns the ending non-empty
         * block + that gap, from which the run bounds follow. */
        struct sql_row_i64_2 run = {0};
        sql_query_row_i64_2(db,
            "SELECT height, gap FROM ("
            "SELECT height, height - LAG(height) OVER (ORDER BY height) AS gap "
            "FROM blocks WHERE num_tx > 1) ORDER BY gap DESC LIMIT 1", &run);
        int64_t run_len = run.v1 > 0 ? run.v1 - 1 : 0;
        int64_t run_start = run.v0 - run.v1 + 1;
        int64_t run_end = run.v0 - 1;

        char bn_s[32], rl_s[32], rcpt[32] = "";
        fmt_comma(bn_s, sizeof(bn_s), max_ntx);
        fmt_comma(rl_s, sizeof(rl_s), run_len);
        compute_receipt_i64(rcpt, sizeof(rcpt), busiest_h, run_len,
                            "empty_block_records");

        APPEND(off, r, max,
            "<div class='card'>"
            "<h3>Records</h3>"
            "<p><b>Busiest block ever:</b> %s transactions at block "
            "<a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></p>"
            "<p><b>Longest run of consecutive empty blocks:</b> %s "
            "(heights %" PRId64 "\xe2\x80\x93%" PRId64 ")</p>"
            "<p><b>SHA3:</b> <code>%s</code></p>"
            "</div>",
            bn_s, busiest_h, busiest_h,
            rl_s, run_start, run_end, rcpt);
    }
    return off;
}
