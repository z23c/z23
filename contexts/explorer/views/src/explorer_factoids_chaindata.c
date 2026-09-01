/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer factoids VIEW — activity and archaeology sections (8-14).
 *
 * Owns the "what the chain carries and how it behaves" half of the historian
 * page: Privacy
 * Usage Over Time, ZSLP Token History, OP_RETURN Archaeology, Dust & UTXO
 * Analysis, and Checkpoint History. Block Time Analysis lives in
 * explorer_factoids_blocktimes.c; Transaction Archaeology lives in
 * explorer_factoids_transactions.c; Empty Blocks lives in
 * explorer_factoids_empty_blocks.c; Difficulty History lives in
 * explorer_factoids_difficulty.c; Data Integrity lives in
 * explorer_factoids_integrity.c. The structure sections (1-7) live in
 * explorer_factoids_history.c; the public entry points and JSON API live in
 * explorer_factoids_view.c. Shared SHA3/format/block helpers come from
 * views/explorer_factoids_internal.h. */

#include "views/explorer_factoids_internal.h"

size_t factoids_emit_section_8_privacy(uint8_t *buf, size_t cap, size_t off,
                                       sqlite3 *db)
{
    char *r = (char *)buf;
    size_t max = cap;

    APPEND(off, r, max,
        "<h2 id='privacy'>8. Privacy Usage Over Time</h2>");

    /* ── All-time shielded-pool summary (NEW) ─────────────────────── */
    {
        int64_t js  = fq_i64(db, "SELECT count(*) FROM joinsplits");
        int64_t ss  = fq_i64(db, "SELECT count(*) FROM sapling_spends");
        int64_t so  = fq_i64(db, "SELECT count(*) FROM sapling_outputs");
        int64_t shielded_total = js + ss + so;
        int64_t js_first = fq_i64(db,
            "SELECT COALESCE(MIN(block_height),0) FROM joinsplits");
        int64_t js_last  = fq_i64(db,
            "SELECT COALESCE(MAX(block_height),0) FROM joinsplits");
        /* SUM(blocks.sprout_value) is the CORRECT residual-pool column —
         * it cross-checks SUM(vpub_old)-SUM(vpub_new) exactly. Unlike
         * blocks.sapling_value (sign-buggy, suppressed below) it is safe
         * to publish. */
        int64_t sprout_pool = fq_i64(db,
            "SELECT COALESCE(SUM(sprout_value),0) FROM blocks");
        int64_t vpub_old = fq_i64(db,
            "SELECT COALESCE(SUM(vpub_old),0) FROM joinsplits");
        int64_t vpub_new = fq_i64(db,
            "SELECT COALESCE(SUM(vpub_new),0) FROM joinsplits");
        int64_t live_notes = so - ss;
        int64_t sprout_null = fq_i64(db, "SELECT count(*) FROM sprout_nullifiers");
        int64_t sapling_null = fq_i64(db, "SELECT count(*) FROM sapling_nullifiers");
        int64_t null_total = sprout_null + sapling_null;
        int64_t first_sapling_out = fq_i64(db,
            "SELECT COALESCE(MIN(block_height),0) FROM sapling_outputs");
        /* Distinct Sapling anchors MUST be derived from sapling_spends.anchor
         * — the dedicated sapling_anchors projection table is EMPTY on live
         * DBs (count(*) returns 0), so never read it here. */
        int64_t distinct_anchors = fq_i64(db,
            "SELECT count(DISTINCT anchor) FROM sapling_spends");

        struct sql_row_i64_2 busiest = {0};
        sql_query_row_i64_2(db,
            "SELECT block_height, count(*) AS n FROM sapling_outputs "
            "GROUP BY block_height ORDER BY n DESC LIMIT 1", &busiest);

        char tot_s[32], js_s[32], ss_s[32], so_s[32], live_s[32];
        char sn_s[32], spn_s[32], nt_s[32], anc_s[32], bcount_s[32];
        char pool_s[64], vin_s[64], vout_s[64], rcpt[32] = "";
        fmt_comma(tot_s, sizeof(tot_s), shielded_total);
        fmt_comma(js_s, sizeof(js_s), js);
        fmt_comma(ss_s, sizeof(ss_s), ss);
        fmt_comma(so_s, sizeof(so_s), so);
        fmt_comma(live_s, sizeof(live_s), live_notes);
        fmt_comma(spn_s, sizeof(spn_s), sprout_null);
        fmt_comma(sn_s, sizeof(sn_s), sapling_null);
        fmt_comma(nt_s, sizeof(nt_s), null_total);
        fmt_comma(anc_s, sizeof(anc_s), distinct_anchors);
        fmt_comma(bcount_s, sizeof(bcount_s), busiest.v1);
        fmt_zcl(pool_s, sizeof(pool_s), sprout_pool);
        fmt_zcl(vin_s, sizeof(vin_s), vpub_old);
        fmt_zcl(vout_s, sizeof(vout_s), vpub_new);
        compute_receipt_i64(rcpt, sizeof(rcpt), shielded_total, null_total,
                            "privacy_summary");

        APPEND(off, r, max,
            "<div class='card'>"
            "<p><b>All-time shielded operations:</b> %s "
            "(%s JoinSplits + %s Sapling spends + %s Sapling outputs)</p>"
            "<p><b>Sprout JoinSplits:</b> %s, first at block "
            "<a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a>, last at block "
            "<a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a> "
            "(Sprout effectively retired)</p>"
            "<p><b>Still locked in the Sprout pool:</b> %s ZCL "
            "(SUM(sprout_value); cross-checks SUM(vpub_old)\xe2\x88\x92SUM(vpub_new))</p>"
            "<p><b>Gross Sprout shielding:</b> %s ZCL shielded in / "
            "%s ZCL unshielded out (cumulative)</p>"
            "<p><b>Sapling:</b> activated at block %d, first shielded output at "
            "<a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a> "
            "(%s spends, %s outputs to date)</p>"
            "<p><b>Live Sapling note set (anonymity set):</b> %s unspent notes "
            "(outputs \xe2\x88\x92 spends)</p>"
            "<p><b>Double-spend protection:</b> %s nullifiers "
            "(%s Sprout + %s Sapling)</p>"
            "<p><b>Busiest shielded block:</b> "
            "<a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a> "
            "with %s Sapling outputs</p>"
            "<p><b>Distinct Sapling anchors referenced:</b> %s</p>"
            "<p><b>SHA3 Receipt:</b> <code>%s</code></p>"
            "</div>",
            tot_s, js_s, ss_s, so_s,
            js_s, js_first, js_first, js_last, js_last,
            pool_s, vin_s, vout_s,
            SAPLING_ACTIVATION_HEIGHT, first_sapling_out, first_sapling_out,
            ss_s, so_s,
            live_s,
            nt_s, spn_s, sn_s,
            busiest.v0, busiest.v0, bcount_s,
            anc_s, rcpt);
    }

    APPEND(off, r, max,
        "<p style='color:#888'>Shielded operations by calendar year "
        "(from actual block timestamps): Sprout JoinSplits, Sapling spends, "
        "and Sapling outputs. The per-year net-shielded column is shown only "
        "when the underlying per-block sapling_value series is reliable "
        "(see the note below the table).</p>"
        "<table class='txlist'>"
        "<tr><th>Year</th><th>Blocks</th><th>JoinSplits</th>"
        "<th>Sapling Spends</th><th>Sapling Outputs</th>"
        "<th>Net Shielded (ZCL)</th></tr>");

    {
        int64_t blk_yrs[20] = {0}, js_yrs[20] = {0};
        int64_t ss_yrs[20] = {0}, so_yrs[20] = {0};
        int64_t sv_yrs[20] = {0};  /* net sapling value */
        int max_yr = 2016;
        sqlite3_stmt *s = NULL;

        /* Blocks per year */
        if (sqlite3_prepare_v2(db,
                "SELECT CAST(strftime('%Y', time, 'unixepoch') AS INTEGER), "
                "count(*) FROM blocks WHERE time > 0 GROUP BY 1 ORDER BY 1",
                -1, &s, NULL) == SQLITE_OK && s) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                int yr = sqlite3_column_int(s, 0);
                int idx = yr - 2016;
                if (idx >= 0 && idx < 20) {
                    blk_yrs[idx] = sqlite3_column_int64(s, 1);
                    if (yr > max_yr) max_yr = yr;
                }
            }
            sqlite3_finalize(s); s = NULL;
        }

        /* JoinSplits per year */
        if (sqlite3_prepare_v2(db,
                "SELECT CAST(strftime('%Y', b.time, 'unixepoch') AS INTEGER), "
                "count(*) FROM joinsplits j "
                "JOIN blocks b ON j.block_height = b.height "
                "WHERE b.time > 0 GROUP BY 1 ORDER BY 1",
                -1, &s, NULL) == SQLITE_OK && s) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                int idx = sqlite3_column_int(s, 0) - 2016;
                if (idx >= 0 && idx < 20)
                    js_yrs[idx] = sqlite3_column_int64(s, 1);
            }
            sqlite3_finalize(s); s = NULL;
        }

        /* Sapling spends per year */
        if (sqlite3_prepare_v2(db,
                "SELECT CAST(strftime('%Y', b.time, 'unixepoch') AS INTEGER), "
                "count(*) FROM sapling_spends sp "
                "JOIN blocks b ON sp.block_height = b.height "
                "WHERE b.time > 0 GROUP BY 1 ORDER BY 1",
                -1, &s, NULL) == SQLITE_OK && s) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                int idx = sqlite3_column_int(s, 0) - 2016;
                if (idx >= 0 && idx < 20)
                    ss_yrs[idx] = sqlite3_column_int64(s, 1);
            }
            sqlite3_finalize(s); s = NULL;
        }

        /* Sapling outputs per year */
        if (sqlite3_prepare_v2(db,
                "SELECT CAST(strftime('%Y', b.time, 'unixepoch') AS INTEGER), "
                "count(*) FROM sapling_outputs so "
                "JOIN blocks b ON so.block_height = b.height "
                "WHERE b.time > 0 GROUP BY 1 ORDER BY 1",
                -1, &s, NULL) == SQLITE_OK && s) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                int idx = sqlite3_column_int(s, 0) - 2016;
                if (idx >= 0 && idx < 20)
                    so_yrs[idx] = sqlite3_column_int64(s, 1);
            }
            sqlite3_finalize(s); s = NULL;
        }

        /* Net shielding volume per year. Convention (verified against
         * running zclassicd valuePools): blocks.sapling_value stores
         * pool-balance deltas in "positive = into pool" sign, so
         * "Net Shielded" = SUM(sapling_value) directly — positive when
         * the year was a net shield-in, negative when net unshield. */
        if (sqlite3_prepare_v2(db,
                "SELECT CAST(strftime('%Y', time, 'unixepoch') AS INTEGER), "
                "SUM(sapling_value) FROM blocks "
                "WHERE sapling_value != 0 AND time > 0 GROUP BY 1 ORDER BY 1",
                -1, &s, NULL) == SQLITE_OK && s) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                int idx = sqlite3_column_int(s, 0) - 2016;
                if (idx >= 0 && idx < 20)
                    sv_yrs[idx] = sqlite3_column_int64(s, 1);
            }
            sqlite3_finalize(s); s = NULL;
        }

        /* Reliability gate for the Net Shielded column. The cumulative
         * whole-chain pool balance is SUM(blocks.sapling_value); a pool
         * BALANCE can never be negative. On this datadir it computes to a
         * negative value (~-38,928 ZCL), which means blocks.sapling_value
         * has a sign-convention / coverage bug. That is a data-layer fix
         * (out of scope here) — until it lands we must not render the
         * impossible per-year net-shielded figures as if authoritative. */
        int64_t net_shielded_total =
            fq_i64(db, "SELECT COALESCE(SUM(sapling_value),0) FROM blocks");
        bool net_shielded_unreliable = (net_shielded_total < 0);

        for (int yr = 2016; yr <= max_yr && yr < 2036; yr++) {
            int idx = yr - 2016;
            if (blk_yrs[idx] == 0) continue;
            char sv_str[64];
            if (net_shielded_unreliable)
                snprintf(sv_str, sizeof(sv_str), "n/a");
            else
                fmt_zcl(sv_str, sizeof(sv_str), sv_yrs[idx]);
            APPEND(off, r, max,
                "<tr><td>%d</td><td>%" PRId64 "</td>"
                "<td>%" PRId64 "</td><td>%" PRId64 "</td>"
                "<td>%" PRId64 "</td><td>%s</td></tr>",
                yr, blk_yrs[idx], js_yrs[idx], ss_yrs[idx],
                so_yrs[idx], sv_str);
        }
        APPEND(off, r, max, "</table>");
        if (net_shielded_unreliable) {
            APPEND(off, r, max,
                "<p style='color:#c80'>shielded pool: monitoring unavailable "
                "&mdash; the net-shielded column is suppressed because the "
                "cumulative pool balance computes negative (impossible). "
                "Pending a blocks.sapling_value sign/coverage fix in the data "
                "layer.</p>");
        }
    }
    return off;
}

size_t factoids_emit_section_9_zslp(uint8_t *buf, size_t cap, size_t off,
                                    sqlite3 *db)
{
    char *r = (char *)buf;
    size_t max = cap;

    APPEND(off, r, max,
        "<h2 id='zslp'>9. ZSLP Token History</h2>");

    struct explorer_token_stats token_stats = {0};
    explorer_query_token_stats(db, &token_stats);
    int64_t total_tokens = token_stats.token_count;
    int64_t total_transfers = token_stats.transfer_count;

    {
        char tk_str[32], xf_str[32], rcpt[32] = "";
        fmt_comma(tk_str, sizeof(tk_str), total_tokens);
        fmt_comma(xf_str, sizeof(xf_str), total_transfers);
        compute_receipt_i64(rcpt, sizeof(rcpt), total_tokens, total_transfers, "zslp_summary");

        APPEND(off, r, max,
            "<div class='card'>"
            "<p><b>Total tokens created:</b> %s</p>"
            "<p><b>Total transfers:</b> %s</p>"
            "<p><b>SHA3 Receipt:</b> <code>%s</code></p>"
            "</div>",
            tk_str, xf_str, rcpt);
    }

    /* ── ZSLP archaeology (NEW) ───────────────────────────────────── */
    {
        int64_t burns = fq_i64(db,
            "SELECT count(*) FROM zslp_transfers WHERE tx_type = 4");
        int64_t genesis_n = fq_i64(db,
            "SELECT count(*) FROM zslp_transfers WHERE tx_type = 1");
        int64_t mint_n = fq_i64(db,
            "SELECT count(*) FROM zslp_transfers WHERE tx_type = 2");
        int64_t send_n = fq_i64(db,
            "SELECT count(*) FROM zslp_transfers WHERE tx_type = 3");
        int64_t genesis_only = fq_i64(db,
            "SELECT count(*) FROM zslp_tokens t WHERE NOT EXISTS ("
            "SELECT 1 FROM zslp_transfers x WHERE x.token_id = t.token_id "
            "AND x.tx_type IN (2,3))");
        /* 21 tokens carry total_minted = INT64_MAX; NEVER SUM the column
         * (it overflows SQLite int64). Just count the saturated rows. */
        int64_t saturated = fq_i64(db,
            "SELECT count(*) FROM zslp_tokens "
            "WHERE total_minted = 9223372036854775807");
        int64_t last_xfer = fq_i64(db,
            "SELECT COALESCE(MAX(block_height),0) FROM zslp_transfers");
        int64_t tip = fq_i64(db, "SELECT COALESCE(MAX(height),0) FROM blocks");
        int64_t quiet_blocks = (tip > last_xfer) ? tip - last_xfer : 0;

        /* First token (WASS / "Whoopass Stew"); ticker+name are
         * attacker-controlled OP_RETURN bytes — HTML-escape before emit. */
        char first_ticker[64] = "?", first_name[256] = "?";
        int64_t first_genesis = 0;
        {
            sqlite3_stmt *s = NULL;
            if (sqlite3_prepare_v2(db,
                    "SELECT ticker, name, genesis_height FROM zslp_tokens "
                    "ORDER BY genesis_height ASC LIMIT 1",
                    -1, &s, NULL) == SQLITE_OK && s) {
                if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                    const char *tk = (const char *)sqlite3_column_text(s, 0);
                    const char *nm = (const char *)sqlite3_column_text(s, 1);
                    html_escape(first_ticker, sizeof(first_ticker), tk ? tk : "?");
                    html_escape(first_name, sizeof(first_name), nm ? nm : "?");
                    first_genesis = sqlite3_column_int64(s, 2);
                }
                sqlite3_finalize(s);
            }
        }

        double died_pct = total_tokens > 0
            ? (double)genesis_only * 100.0 / (double)total_tokens : 0.0;
        double quiet_weeks = (double)quiet_blocks * 75.0 / 604800.0;

        char g_s[32], m_s[32], se_s[32], b_s[32], go_s[32], tt_s[32];
        char sat_s[32], qb_s[32], rcpt[32] = "";
        fmt_comma(g_s, sizeof(g_s), genesis_n);
        fmt_comma(m_s, sizeof(m_s), mint_n);
        fmt_comma(se_s, sizeof(se_s), send_n);
        fmt_comma(b_s, sizeof(b_s), burns);
        fmt_comma(go_s, sizeof(go_s), genesis_only);
        fmt_comma(tt_s, sizeof(tt_s), total_tokens);
        fmt_comma(sat_s, sizeof(sat_s), saturated);
        fmt_comma(qb_s, sizeof(qb_s), quiet_blocks);
        compute_receipt_i64(rcpt, sizeof(rcpt), total_tokens, genesis_only,
                            "zslp_archaeology");

        APPEND(off, r, max,
            "<div class='card'>"
            "<h3>ZSLP Archaeology</h3>"
            "<p><b>First token:</b> %s &mdash; \"%s\", genesis at block "
            "<a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></p>"
            "<p><b>Operations by type:</b> %s GENESIS, %s MINT, %s SEND, "
            "%s BURN</p>"
            "<p><b>Burns ever recorded:</b> %s &mdash; the credit-only ledger "
            "never writes a BURN row</p>"
            "<p><b>Died at birth:</b> %s of %s tokens (%.1f%%) had no mint or "
            "send after genesis</p>"
            "<p><b>Declared (unvalidated) supplies:</b> %s tokens declare a "
            "saturated INT64_MAX supply &mdash; ZSLP supply is attacker-"
            "controlled OP_RETURN data with no consensus cap, never a real "
            "minted total</p>"
            "<p><b>Last ZSLP activity:</b> block "
            "<a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a> &mdash; "
            "%s blocks (~%.1f weeks) ago</p>"
            "<p><b>SHA3 Receipt:</b> <code>%s</code></p>"
            "</div>",
            first_ticker, first_name, first_genesis, first_genesis,
            g_s, m_s, se_s, b_s,
            b_s,
            go_s, tt_s, died_pct,
            sat_s,
            last_xfer, last_xfer, qb_s, quiet_weeks,
            rcpt);
    }

    /* First 10 tokens */
    APPEND(off, r, max,
        "<h3>First 10 Tokens</h3>"
        "<table class='txlist'>"
        "<tr><th>Ticker</th><th>Name</th><th>Decimals</th>"
        "<th>Genesis Block</th><th>Token ID</th></tr>");
    {
        sqlite3_stmt *s = NULL;
        const char *sql = "SELECT ticker, name, decimals, genesis_height, hex(token_id) "
                          "FROM zslp_tokens ORDER BY genesis_height ASC LIMIT 10";
        if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                const char *ticker = (const char *)sqlite3_column_text(s, 0);
                const char *name = (const char *)sqlite3_column_text(s, 1);
                int dec = sqlite3_column_int(s, 2);
                int64_t gh = sqlite3_column_int64(s, 3);
                const char *tid = (const char *)sqlite3_column_text(s, 4);
                /* ticker + name come from attacker-controlled OP_RETURN
                 * bytes; HTML-escape before emitting. */
                char esc_ticker[64], esc_name[256];
                html_escape(esc_ticker, sizeof(esc_ticker),
                            ticker ? ticker : "?");
                html_escape(esc_name, sizeof(esc_name), name ? name : "?");
                APPEND(off, r, max,
                    "<tr><td>%s</td><td>%s</td><td>%d</td>"
                    "<td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>"
                    "<td><code>%.16s...</code></td></tr>",
                    esc_ticker, esc_name, dec,
                    gh, gh, tid ? tid : "?");
            }
            sqlite3_finalize(s);
        }
    }
    APPEND(off, r, max, "</table>");

    /* Most active tokens */
    APPEND(off, r, max,
        "<h3>Most Active Tokens</h3>"
        "<table class='txlist'>"
        "<tr><th>Ticker</th><th>Name</th><th>Transfers</th></tr>");
    {
        sqlite3_stmt *s = NULL;
        const char *sql =
            "SELECT t.ticker, t.name, count(x.rowid) as cnt "
            "FROM zslp_tokens t "
            "LEFT JOIN zslp_transfers x ON x.token_id = t.token_id "
            "GROUP BY t.token_id ORDER BY cnt DESC LIMIT 10";
        if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                const char *ticker = (const char *)sqlite3_column_text(s, 0);
                const char *name = (const char *)sqlite3_column_text(s, 1);
                int64_t cnt = sqlite3_column_int64(s, 2);
                char esc_ticker[64], esc_name[256];
                html_escape(esc_ticker, sizeof(esc_ticker),
                            ticker ? ticker : "?");
                html_escape(esc_name, sizeof(esc_name), name ? name : "?");
                APPEND(off, r, max,
                    "<tr><td>%s</td><td>%s</td><td>%" PRId64 "</td></tr>",
                    esc_ticker, esc_name, cnt);
            }
            sqlite3_finalize(s);
        }
    }
    APPEND(off, r, max, "</table>");
    return off;
}

size_t factoids_emit_section_10_opreturn(uint8_t *buf, size_t cap, size_t off,
                                         sqlite3 *db)
{
    char *r = (char *)buf;
    size_t max = cap;

    APPEND(off, r, max,
        "<h2 id='opreturn'>10. OP_RETURN Archaeology</h2>");

    struct explorer_op_return_stats op_return_stats = {0};
    explorer_query_op_return_stats(db, &op_return_stats);
    int64_t total_opret = op_return_stats.total;
    int64_t slp_opret = op_return_stats.zslp;
    int64_t nonslp_opret = total_opret - slp_opret;
    int64_t first_opret = fq_i64(db, "SELECT MIN(block_height) FROM op_returns");
    /* The chain's very first OP_RETURN (375,159) is NOT a token, so
     * "First non-ZSLP OP_RETURN" would duplicate "First OP_RETURN".
     * Surface the (non-redundant, more informative) first ZSLP one instead. */
    int64_t first_slp = fq_i64(db,
        "SELECT MIN(block_height) FROM op_returns WHERE is_slp = 1");
    int64_t last_opret = fq_i64(db, "SELECT MAX(block_height) FROM op_returns");
    int64_t tip = fq_i64(db, "SELECT COALESCE(MAX(height),0) FROM blocks");
    int64_t since_last = (tip > last_opret) ? tip - last_opret : 0;

    /* Usage by upgrade era — one atomic scan so the buckets sum to total. */
    int64_t era_pre = 0, era_sap = 0, era_bc = 0;
    {
        sqlite3_stmt *s = NULL;
        const char *sql =
            "SELECT "
            "SUM(CASE WHEN block_height < 476969 THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN block_height >= 476969 AND block_height < 707000 "
            "    THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN block_height >= 707000 THEN 1 ELSE 0 END) "
            "FROM op_returns";
        if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                era_pre = sqlite3_column_int64(s, 0);
                era_sap = sqlite3_column_int64(s, 1);
                era_bc  = sqlite3_column_int64(s, 2);
            }
            sqlite3_finalize(s);
        }
    }

    {
        char tot_str[32], slp_str[32], non_str[32], rcpt[32] = "";
        fmt_comma(tot_str, sizeof(tot_str), total_opret);
        fmt_comma(slp_str, sizeof(slp_str), slp_opret);
        fmt_comma(non_str, sizeof(non_str), nonslp_opret);
        compute_receipt_i64(rcpt, sizeof(rcpt), total_opret, first_opret, "opreturn_stats");

        APPEND(off, r, max,
            "<div class='card'>"
            "<p><b>Total OP_RETURN outputs:</b> %s</p>"
            "<p><b>ZSLP OP_RETURNs:</b> %s</p>"
            "<p><b>Non-ZSLP OP_RETURNs:</b> %s</p>"
            "<p><b>First OP_RETURN at block:</b> "
            "<a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a> "
            "(not a token \xe2\x80\x94 is_slp=0)</p>",
            tot_str, slp_str, non_str, first_opret, first_opret);

        if (first_slp > 0) {
            APPEND(off, r, max,
                "<p><b>First ZSLP OP_RETURN:</b> "
                "<a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></p>",
                first_slp, first_slp);
        }
        APPEND(off, r, max,
            "<p><b>SHA3 Receipt:</b> <code>%s</code></p>"
            "</div>", rcpt);
    }

    /* ── OP_RETURN by upgrade era + dormancy (NEW) ────────────────── */
    {
        char pre_s[32], sap_s[32], bc_s[32], sl_s[32], rcpt[32] = "";
        fmt_comma(pre_s, sizeof(pre_s), era_pre);
        fmt_comma(sap_s, sizeof(sap_s), era_sap);
        fmt_comma(bc_s, sizeof(bc_s), era_bc);
        fmt_comma(sl_s, sizeof(sl_s), since_last);
        compute_receipt_i64(rcpt, sizeof(rcpt), last_opret, total_opret,
                            "opreturn_eras");

        APPEND(off, r, max,
            "<div class='card'>"
            "<h3>OP_RETURN by upgrade era</h3>"
            "<table class='txlist'>"
            "<tr><th>Era</th><th>OP_RETURNs</th></tr>"
            "<tr><td>Pre-Sapling (&lt;476,969)</td><td>%s</td></tr>"
            "<tr><td>Sapling era (476,969\xe2\x80\x93" "706,999)</td><td>%s</td></tr>"
            "<tr><td>Buttercup+ (&ge;707,000)</td><td>%s</td></tr>"
            "</table>"
            "<p><b>Last OP_RETURN on chain:</b> block "
            "<a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a> "
            "(%s blocks ago \xe2\x80\x94 none recent)</p>"
            "<p><b>SHA3 Receipt:</b> <code>%s</code></p>"
            "</div>",
            pre_s, sap_s, bc_s,
            last_opret, last_opret, sl_s, rcpt);
    }
    return off;
}

size_t factoids_emit_section_11_dust(uint8_t *buf, size_t cap, size_t off,
                                     sqlite3 *db)
{
    char *r = (char *)buf;
    size_t max = cap;

    APPEND(off, r, max,
        "<h2 id='dust'>11. Dust &amp; UTXO Analysis</h2>");

    /* Compute ALL UTXO aggregates in ONE atomic scan so every figure is a
     * single self-consistent snapshot. The live utxos projection drifts
     * between separate scans as the chain advances, so three independent
     * fq_i64() scans (the old code) could disagree with each other. */
    int64_t u_total = 0, u_value = 0, lt01 = 0, lt1 = 0, lt10 = 0;
    int64_t dust001 = 0, dust01 = 0, cb_count = 0, cb_value = 0;
    int64_t e_pre = 0, e_sap = 0, e_bub = 0, e_bc = 0, dorm_n = 0, dorm_v = 0;
    {
        sqlite3_stmt *s = NULL;
        const char *sql =
            "SELECT count(*), COALESCE(SUM(value),0), "
            "SUM(CASE WHEN value < 10000000 THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN value < 100000000 THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN value < 1000000000 THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN value < 100000 THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN value < 1000000 THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN is_coinbase = 1 THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN is_coinbase = 1 THEN value ELSE 0 END), "
            "SUM(CASE WHEN height < 476969 THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN height >= 476969 AND height < 585318 THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN height >= 585318 AND height < 707000 THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN height >= 707000 THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN height < 100000 THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN height < 100000 THEN value ELSE 0 END) "
            "FROM utxos";
        if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                u_total  = sqlite3_column_int64(s, 0);
                u_value  = sqlite3_column_int64(s, 1);
                lt01     = sqlite3_column_int64(s, 2);
                lt1      = sqlite3_column_int64(s, 3);
                lt10     = sqlite3_column_int64(s, 4);
                dust001  = sqlite3_column_int64(s, 5);
                dust01   = sqlite3_column_int64(s, 6);
                cb_count = sqlite3_column_int64(s, 7);
                cb_value = sqlite3_column_int64(s, 8);
                e_pre    = sqlite3_column_int64(s, 9);
                e_sap    = sqlite3_column_int64(s, 10);
                e_bub    = sqlite3_column_int64(s, 11);
                e_bc     = sqlite3_column_int64(s, 12);
                dorm_n   = sqlite3_column_int64(s, 13);
                dorm_v   = sqlite3_column_int64(s, 14);
            }
            sqlite3_finalize(s);
        }
    }

    /* Median is cheap thanks to the utxos(value) index; mean from the scan. */
    int64_t median = fq_i64(db,
        "SELECT value FROM utxos ORDER BY value LIMIT 1 "
        "OFFSET (SELECT count(*)/2 FROM utxos)");
    int64_t mean = u_total > 0 ? u_value / u_total : 0;

    /* Largest currently-unspent output (locatable cheaply on the small
     * utxos table; the all-time max over tx_outputs lives in section 14). */
    struct sql_row_i64_2 largest = {0};
    sql_query_row_i64_2(db,
        "SELECT value, height FROM utxos ORDER BY value DESC LIMIT 1", &largest);

    /* Immature coinbase outputs (within COINBASE_MATURITY=100 of the tip). */
    struct sql_row_i64_2 immature = {0};
    sql_query_row_i64_2(db,
        "SELECT count(*), COALESCE(SUM(value),0) FROM utxos "
        "WHERE is_coinbase = 1 AND height > (SELECT MAX(height) FROM utxos) - 100",
        &immature);

    {
        char u_s[32], v_s[64], med_s[64], mean_s[64];
        char l01_s[32], l1_s[32], l10_s[32], d001_s[32], d01_s[32];
        char cbc_s[32], cbv_s[64], rcpt[32] = "";
        fmt_comma(u_s, sizeof(u_s), u_total);
        fmt_zcl(v_s, sizeof(v_s), u_value);
        fmt_zcl(med_s, sizeof(med_s), median);
        fmt_zcl(mean_s, sizeof(mean_s), mean);
        fmt_comma(l01_s, sizeof(l01_s), lt01);
        fmt_comma(l1_s, sizeof(l1_s), lt1);
        fmt_comma(l10_s, sizeof(l10_s), lt10);
        fmt_comma(d001_s, sizeof(d001_s), dust001);
        fmt_comma(d01_s, sizeof(d01_s), dust01);
        fmt_comma(cbc_s, sizeof(cbc_s), cb_count);
        fmt_zcl(cbv_s, sizeof(cbv_s), cb_value);
        compute_receipt_i64(rcpt, sizeof(rcpt), u_total, u_value, "utxo_analysis");

        double pct01 = u_total > 0 ? (double)lt01 * 100.0 / (double)u_total : 0.0;
        double pct1  = u_total > 0 ? (double)lt1  * 100.0 / (double)u_total : 0.0;
        double pct10 = u_total > 0 ? (double)lt10 * 100.0 / (double)u_total : 0.0;
        double dust001_pct = u_total > 0 ? (double)dust001 * 100.0 / (double)u_total : 0.0;
        double cb_cnt_pct = u_total > 0 ? (double)cb_count * 100.0 / (double)u_total : 0.0;
        double cb_val_pct = u_value > 0 ? (double)cb_value * 100.0 / (double)u_value : 0.0;

        APPEND(off, r, max,
            "<div class='card'>"
            "<p><b>Total UTXOs:</b> %s</p>"
            "<p><b>Total UTXO value:</b> %s ZCL</p>"
            "<p><b>Median / mean output:</b> %s ZCL / %s ZCL</p>"
            "<p><b>Value ladder:</b> &lt;0.1 ZCL %s (%.1f%%), "
            "&lt;1 ZCL %s (%.1f%%), &lt;10 ZCL %s (%.1f%%)</p>"
            "<p><b>Dust (&lt;0.001 ZCL):</b> %s (%.1f%% of set)</p>"
            "<p><b>Dust (&lt;0.01 ZCL):</b> %s</p>"
            "<p><b>Unspent coinbase:</b> %s outputs (%.1f%% of UTXOs) holding "
            "%s ZCL (%.2f%% of value)</p>"
            "<p><b>SHA3 Receipt:</b> <code>%s</code></p>"
            "</div>",
            u_s, v_s, med_s, mean_s,
            l01_s, pct01, l1_s, pct1, l10_s, pct10,
            d001_s, dust001_pct, d01_s,
            cbc_s, cb_cnt_pct, cbv_s, cb_val_pct,
            rcpt);

        char lv_s[64], iv_s[64], ic_s[32];
        char ep_s[32], es_s[32], eb_s[32], ec_s[32], dn_s[32], dv_s[64], rcpt2[32] = "";
        fmt_zcl(lv_s, sizeof(lv_s), largest.v0);
        fmt_comma(ic_s, sizeof(ic_s), immature.v0);
        fmt_zcl(iv_s, sizeof(iv_s), immature.v1);
        fmt_comma(ep_s, sizeof(ep_s), e_pre);
        fmt_comma(es_s, sizeof(es_s), e_sap);
        fmt_comma(eb_s, sizeof(eb_s), e_bub);
        fmt_comma(ec_s, sizeof(ec_s), e_bc);
        fmt_comma(dn_s, sizeof(dn_s), dorm_n);
        fmt_zcl(dv_s, sizeof(dv_s), dorm_v);
        compute_receipt_i64(rcpt2, sizeof(rcpt2), largest.v0, largest.v1,
                            "largest_unspent_utxo");

        APPEND(off, r, max,
            "<div class='card'>"
            "<p><b>Largest unspent output:</b> %s ZCL at block "
            "<a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></p>"
            "<p><b>Immature coinbase:</b> %s outputs (%s ZCL) within 100 blocks "
            "of the tip</p>"
            "<p><b>UTXOs by upgrade era:</b> pre-Sapling %s, Sapling %s, "
            "Bubbles %s, Buttercup+ %s</p>"
            "<p><b>Dormant since the first 100k blocks:</b> %s outputs (%s ZCL) "
            "minted below height 100,000 and never moved</p>"
            "<p><b>SHA3 Receipt:</b> <code>%s</code></p>"
            "</div>",
            lv_s, largest.v1, largest.v1,
            ic_s, iv_s,
            ep_s, es_s, eb_s, ec_s,
            dn_s, dv_s,
            rcpt2);
    }

    /* Script-type split */
    APPEND(off, r, max,
        "<h3>UTXOs by script type</h3>"
        "<table class='txlist'>"
        "<tr><th>Type</th><th>UTXOs</th><th>Value (ZCL)</th></tr>");
    {
        sqlite3_stmt *s = NULL;
        const char *sql =
            "SELECT script_type, count(*), COALESCE(SUM(value),0) FROM utxos "
            "GROUP BY script_type ORDER BY count(*) DESC";
        if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                int st = sqlite3_column_int(s, 0);
                int64_t n = sqlite3_column_int64(s, 1);
                int64_t v = sqlite3_column_int64(s, 2);
                const char *label =
                    st == 0 ? "P2PKH" : st == 1 ? "P2SH" :
                    st == 2 ? "OP_RETURN" : st == 3 ? "MULTISIG" : "OTHER";
                char n_s[32], v_s2[64];
                fmt_comma(n_s, sizeof(n_s), n);
                fmt_zcl(v_s2, sizeof(v_s2), v);
                APPEND(off, r, max,
                    "<tr><td>%s</td><td>%s</td><td>%s</td></tr>",
                    label, n_s, v_s2);
            }
            sqlite3_finalize(s);
        }
    }
    APPEND(off, r, max, "</table>");
    return off;
}

size_t factoids_emit_section_12_checkpoints(uint8_t *buf, size_t cap, size_t off,
                                            sqlite3 *db, int64_t chain_height)
{
    char *r = (char *)buf;
    size_t max = cap;

    APPEND(off, r, max,
        "<h2 id='checkpoints'>12. Checkpoint History</h2>"
        "<p style='color:#888'>Hardcoded consensus checkpoints — "
        "blocks that all nodes must agree on.</p>"
        "<table class='txlist'>"
        "<tr><th>Height</th><th>Date</th><th>Block Hash</th><th>SHA3</th></tr>");

    off = factoids_emit_checkpoint_rows(buf, cap, off, db, chain_height);
    APPEND(off, r, max, "</table>");
    return off;
}
