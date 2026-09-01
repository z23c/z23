/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer factoids VIEW - transaction archaeology section renderer.
 *
 * Owns section 14's display-only transaction totals, yearly table, records,
 * and output-script split. Consensus transaction validation lives below the
 * View layer. */

#include "views/explorer_factoids_internal.h"

size_t factoids_emit_section_14_transactions(uint8_t *buf, size_t cap, size_t off,
                                             sqlite3 *db)
{
    char *r = (char *)buf;
    size_t max = cap;

    APPEND(off, r, max,
        "<h2 id='transactions'>14. Transaction Archaeology</h2>");

    {
        struct explorer_transaction_stats transaction_stats = {0};
        explorer_query_transaction_stats(db, &transaction_stats);
        struct explorer_op_return_stats op_return_stats = {0};
        explorer_query_op_return_stats(db, &op_return_stats);
        int64_t total_txs = fq_i64(db,
            "SELECT count(*) FROM transactions t "
            "JOIN blocks b ON t.block_hash = b.hash");
        int64_t coinbase_txs = fq_i64(db,
            "SELECT count(DISTINCT block_height) FROM transactions "
            "WHERE is_coinbase = 1");
        int64_t non_coinbase = total_txs - coinbase_txs;
        int64_t total_inputs = transaction_stats.inputs;
        int64_t total_outputs = transaction_stats.outputs;
        int64_t total_opret = op_return_stats.total;

        char tx_str[32], cb_str[32], nc_str[32], in_str[32], out_str[32], op_str[32];
        fmt_comma(tx_str, sizeof(tx_str), total_txs);
        fmt_comma(cb_str, sizeof(cb_str), coinbase_txs);
        fmt_comma(nc_str, sizeof(nc_str), non_coinbase);
        fmt_comma(in_str, sizeof(in_str), total_inputs);
        fmt_comma(out_str, sizeof(out_str), total_outputs);
        fmt_comma(op_str, sizeof(op_str), total_opret);

        char rcpt[32] = "";
        compute_receipt_i64(rcpt, sizeof(rcpt), total_txs, total_inputs, "tx_archaeology");

        APPEND(off, r, max,
            "<div class='card'>"
            "<table>"
            "<tr><td><b>Total transactions:</b></td><td>%s</td></tr>"
            "<tr><td><b>Coinbase transactions:</b></td><td>%s</td></tr>"
            "<tr><td><b>Non-coinbase transactions:</b></td><td>%s</td></tr>"
            "<tr><td><b>Total transparent inputs:</b></td><td>%s</td></tr>"
            "<tr><td><b>Total transparent outputs:</b></td><td>%s</td></tr>"
            "<tr><td><b>Total OP_RETURN outputs:</b></td><td>%s</td></tr>"
            "<tr><td><b>Avg outputs/tx:</b></td><td>%.2f</td></tr>"
            "<tr><td><b>SHA3:</b></td><td><code>%s</code></td></tr>"
            "</table></div>",
            tx_str, cb_str, nc_str, in_str, out_str, op_str,
            total_txs > 0 ? (double)total_outputs / (double)total_txs : 0.0,
            rcpt);
    }

    APPEND(off, r, max,
        "<h3>Transactions Per Year</h3>"
        "<table class='txlist'>"
        "<tr><th>Year</th><th>Total Tx</th><th>Coinbase</th>"
        "<th>Non-Coinbase</th><th>Avg Tx/Block</th></tr>");
    {
        sqlite3_stmt *s = NULL;
        const char *sql =
            "SELECT CAST(strftime('%Y', b.time, 'unixepoch') AS INTEGER) AS yr, "
            "count(*) AS total, "
            "SUM(CASE WHEN t.is_coinbase = 1 THEN 1 ELSE 0 END) AS cb "
            "FROM transactions t "
            "JOIN blocks b ON t.block_height = b.height "
            "WHERE b.time > 0 GROUP BY yr ORDER BY yr";
        if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                int yr = sqlite3_column_int(s, 0);
                int64_t total = sqlite3_column_int64(s, 1);
                int64_t cb = sqlite3_column_int64(s, 2);
                int64_t nc = total - cb;
                double avg = cb > 0 ? (double)total / (double)cb : 0.0;
                APPEND(off, r, max,
                    "<tr><td>%d</td><td>%" PRId64 "</td>"
                    "<td>%" PRId64 "</td><td>%" PRId64 "</td>"
                    "<td>%.2f</td></tr>",
                    yr, total, cb, nc, avg);
            }
            sqlite3_finalize(s);
        }
    }
    APPEND(off, r, max, "</table>");

    {
        struct sql_row_i64_2 moved = {0};
        sql_query_row_i64_2(db,
            "SELECT COALESCE(SUM(value),0), count(*) FROM tx_outputs", &moved);
        int64_t max_out_val = fq_i64(db, "SELECT COALESCE(MAX(value),0) FROM tx_outputs");
        int64_t max_vout = fq_i64(db, "SELECT COALESCE(MAX(vout),0) FROM tx_outputs");
        int64_t big_tx_height = 0;
        {
            char sql[160];
            snprintf(sql, sizeof(sql),
                "SELECT block_height FROM tx_outputs WHERE vout = %" PRId64 " LIMIT 1",
                max_vout);
            big_tx_height = fq_i64(db, sql);
        }
        int64_t big_tx_outputs = max_vout + 1;
        int64_t first_noncb = fq_i64(db,
            "SELECT MIN(block_height) FROM transactions WHERE is_coinbase = 0");
        int64_t n_inputs = fq_i64(db, "SELECT count(*) FROM tx_inputs");
        int64_t n_spending = fq_i64(db,
            "SELECT count(*) FROM transactions WHERE is_coinbase = 0");
        double avg_in = n_spending > 0 ? (double)n_inputs / (double)n_spending : 0.0;

        char mv_s[64], nout_s[32], mout_s[64], bo_s[32], rcpt[32] = "";
        fmt_zcl(mv_s, sizeof(mv_s), moved.v0);
        fmt_comma(nout_s, sizeof(nout_s), moved.v1);
        fmt_zcl(mout_s, sizeof(mout_s), max_out_val);
        fmt_comma(bo_s, sizeof(bo_s), big_tx_outputs);
        compute_receipt_i64(rcpt, sizeof(rcpt), moved.v0, moved.v1, "tx_records");

        APPEND(off, r, max,
            "<div class='card'>"
            "<h3>Records</h3>"
            "<table>"
            "<tr><td><b>Total transparent value ever moved:</b></td>"
            "<td>%s ZCL across %s outputs</td></tr>"
            "<tr><td><b>Largest tx by output count:</b></td>"
            "<td>%s outputs at block "
            "<a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td></tr>"
            "<tr><td><b>Largest single transparent output (all-time):</b></td>"
            "<td>%s ZCL</td></tr>"
            "<tr><td><b>First non-coinbase transaction:</b></td>"
            "<td>block <a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td></tr>"
            "<tr><td><b>Avg inputs per spending tx:</b></td><td>%.2f</td></tr>"
            "<tr><td><b>SHA3:</b></td><td><code>%s</code></td></tr>"
            "</table></div>",
            mv_s, nout_s,
            bo_s, big_tx_height, big_tx_height,
            mout_s,
            first_noncb, first_noncb,
            avg_in, rcpt);
    }

    APPEND(off, r, max,
        "<h3>Outputs by script type</h3>"
        "<table class='txlist'>"
        "<tr><th>Type</th><th>Outputs</th></tr>");
    {
        sqlite3_stmt *s = NULL;
        const char *sql =
            "SELECT script_type, count(*) FROM tx_outputs "
            "GROUP BY script_type ORDER BY count(*) DESC";
        if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                int st = sqlite3_column_int(s, 0);
                int64_t n = sqlite3_column_int64(s, 1);
                const char *label =
                    st == 0 ? "P2PKH" : st == 1 ? "P2SH" :
                    st == 2 ? "OP_RETURN" : st == 3 ? "MULTISIG" : "OTHER";
                char n_s[32];
                fmt_comma(n_s, sizeof(n_s), n);
                APPEND(off, r, max,
                    "<tr><td>%s</td><td>%s</td></tr>", label, n_s);
            }
            sqlite3_finalize(s);
        }
    }
    APPEND(off, r, max, "</table>");
    return off;
}
