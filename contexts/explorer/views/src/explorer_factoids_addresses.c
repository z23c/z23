/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer factoids VIEW - address statistics section renderer.
 *
 * Owns section 7's display-only transparent holder statistics. The section is
 * based on the explorer address projection; wallet/key logic is elsewhere. */

#include "views/explorer_factoids_internal.h"

size_t factoids_emit_section_7_addresses(uint8_t *buf, size_t cap, size_t off,
                                         sqlite3 *db)
{
    char *r = (char *)buf;
    size_t max = cap;

    APPEND(off, r, max,
        "<h2 id='addresses'>7. Address Statistics</h2>");

    struct explorer_address_stats address_stats = {0};
    explorer_query_address_stats(db, &address_stats);
    int64_t addr_total = address_stats.total;
    int64_t addr_nonzero = address_stats.nonzero;
    int64_t addr_over_1 = fq_i64(db, "SELECT count(*) FROM addresses WHERE balance >= 100000000");
    int64_t addr_over_100 = fq_i64(db, "SELECT count(*) FROM addresses WHERE balance >= 10000000000");
    int64_t addr_over_1000 = fq_i64(db, "SELECT count(*) FROM addresses WHERE balance >= 100000000000");
    int64_t addr_over_1m = fq_i64(db, "SELECT count(*) FROM addresses WHERE balance >= 100000000000000");

    {
        int64_t addr_zero = addr_total - addr_nonzero;
        if (addr_zero < 0) addr_zero = 0;

        char t_str[32], nz_str[32], z_str[32];
        char o1_str[32], o100_str[32], o1k_str[32], o1m_str[64];
        fmt_comma(t_str, sizeof(t_str), addr_total);
        fmt_comma(nz_str, sizeof(nz_str), addr_nonzero);
        fmt_comma(z_str, sizeof(z_str), addr_zero);
        fmt_comma(o1_str, sizeof(o1_str), addr_over_1);
        fmt_comma(o100_str, sizeof(o100_str), addr_over_100);
        fmt_comma(o1k_str, sizeof(o1k_str), addr_over_1000);
        if (addr_over_1m > 0)
            fmt_comma(o1m_str, sizeof(o1m_str), addr_over_1m);
        else
            snprintf(o1m_str, sizeof(o1m_str),
                     "None \xe2\x80\x94 no address holds a million ZCL");

        char rcpt[32] = "";
        compute_receipt_i64(rcpt, sizeof(rcpt), addr_total, addr_nonzero, "addr_stats");

        APPEND(off, r, max,
            "<div class='card'>"
            "<p style='color:#888'>The <code>addresses</code> table is the live "
            "transparent UTXO-holder index (one row per address that currently "
            "owns coins), not a full historical address census. Percentages in "
            "this section are shares of <b>transparent</b> coins held, not of "
            "total emission \xe2\x80\x94 much of the supply is shielded or already "
            "spent.</p>"
            "<p><b>Addresses currently holding coins:</b> %s "
            "<span style='color:#888'>(of %s in the index; %s carry a zero "
            "balance)</span></p>"
            "<p><b>Holding \xe2\x89\xa5 1 ZCL:</b> %s</p>"
            "<p><b>Holding \xe2\x89\xa5 100 ZCL:</b> %s</p>"
            "<p><b>Holding \xe2\x89\xa5 1,000 ZCL:</b> %s</p>"
            "<p><b>Holding \xe2\x89\xa5 1,000,000 ZCL:</b> %s</p>"
            "<p><b>SHA3 Receipt:</b> <code>%s</code></p>"
            "</div>",
            nz_str, t_str, z_str, o1_str, o100_str, o1k_str, o1m_str, rcpt);
    }

    {
        int64_t total_held = fq_i64(db, "SELECT COALESCE(SUM(balance),0) FROM addresses");
        int64_t top10 = fq_i64(db,
            "SELECT COALESCE(SUM(balance),0) FROM "
            "(SELECT balance FROM addresses ORDER BY balance DESC LIMIT 10)");
        int64_t top100 = fq_i64(db,
            "SELECT COALESCE(SUM(balance),0) FROM "
            "(SELECT balance FROM addresses ORDER BY balance DESC LIMIT 100)");
        int64_t richest = fq_i64(db, "SELECT COALESCE(MAX(balance),0) FROM addresses");
        int64_t median = fq_i64(db,
            "SELECT balance FROM addresses WHERE balance>0 ORDER BY balance "
            "LIMIT 1 OFFSET (SELECT COUNT(*) FROM addresses WHERE balance>0)/2");
        int64_t single_use = fq_i64(db,
            "SELECT COALESCE(SUM(CASE WHEN first_seen_height=last_seen_height "
            "THEN 1 ELSE 0 END),0) FROM addresses");
        int64_t oldest_funded = fq_i64(db,
            "SELECT MIN(first_seen_height) FROM addresses WHERE balance>0");
        int64_t newest = fq_i64(db, "SELECT MAX(first_seen_height) FROM addresses");
        int64_t tip = fq_i64(db, "SELECT MAX(height) FROM blocks");

        int64_t mean = addr_nonzero > 0 ? total_held / addr_nonzero : 0;
        double top10_pct   = total_held > 0 ? 100.0 * (double)top10   / (double)total_held : 0.0;
        double top100_pct  = total_held > 0 ? 100.0 * (double)top100  / (double)total_held : 0.0;
        double richest_pct = total_held > 0 ? 100.0 * (double)richest / (double)total_held : 0.0;
        double single_pct  = addr_total  > 0 ? 100.0 * (double)single_use / (double)addr_total : 0.0;
        int64_t newest_below = (tip > 0 && newest > 0 && tip >= newest) ? tip - newest : 0;
        int64_t oldest_time = oldest_funded > 0 ? get_block_time(db, oldest_funded) : 0;

        char total_str[64], richest_str[64], mean_str[64], median_str[64];
        char held_cnt[32], su_str[32], ots[64], rcpt[32] = "";
        fmt_zcl(total_str, sizeof(total_str), total_held);
        fmt_zcl(richest_str, sizeof(richest_str), richest);
        fmt_zcl(mean_str, sizeof(mean_str), mean);
        fmt_zcl(median_str, sizeof(median_str), median);
        fmt_comma(held_cnt, sizeof(held_cnt), addr_nonzero);
        fmt_comma(su_str, sizeof(su_str), single_use);
        fmt_time(ots, sizeof(ots), oldest_time);
        compute_receipt_i64(rcpt, sizeof(rcpt), top10, top100, "addr_concentration");

        APPEND(off, r, max,
            "<div class='card'>"
            "<h3>Distribution &amp; Concentration</h3>"
            "<p style='color:#888'>Shares are of the %s ZCL held across %s funded "
            "transparent addresses (the held-coin denominator, not total "
            "emission).</p>"
            "<table>"
            "<tr><td><b>Top 10 addresses hold</b></td><td>%.2f%% of held coins</td></tr>"
            "<tr><td><b>Top 100 addresses hold</b></td><td>%.2f%% of held coins</td></tr>"
            "<tr><td><b>Richest address</b></td>"
            "<td>%s ZCL (%.2f%% of held coins)</td></tr>"
            "<tr><td><b>Mean holder</b></td><td>%s ZCL</td></tr>"
            "<tr><td><b>Median holder</b></td><td>%s ZCL</td></tr>"
            "<tr><td><b>Single-use addresses</b></td>"
            "<td>%s (%.1f%%, first seen = last seen)</td></tr>"
            "<tr><td><b>Oldest still-funded address</b></td>"
            "<td>block <a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a> "
            "\xc2\xb7 %s</td></tr>"
            "<tr><td><b>Newest address</b></td>"
            "<td>block <a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a> "
            "(%" PRId64 " below tip)</td></tr>"
            "<tr><td><b>SHA3 Receipt</b></td><td><code>%s</code></td></tr>"
            "</table></div>",
            total_str, held_cnt,
            top10_pct, top100_pct,
            richest_str, richest_pct,
            mean_str, median_str,
            su_str, single_pct,
            oldest_funded, oldest_funded, ots,
            newest, newest, newest_below,
            rcpt);
    }

    APPEND(off, r, max,
        "<h3>Top 10 Richest Addresses</h3>"
        "<table class='txlist'>"
        "<tr><th>#</th><th>Address Hash</th><th>Balance</th>"
        "<th>UTXOs</th><th>First Seen</th></tr>");
    {
        sqlite3_stmt *s = NULL;
        const char *sql =
            "SELECT hex(address_hash), balance, utxo_count, first_seen_height "
            "FROM addresses ORDER BY balance DESC LIMIT 10";
        if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
            int rank = 1;
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                const char *ah = (const char *)sqlite3_column_text(s, 0);
                int64_t bal = sqlite3_column_int64(s, 1);
                int64_t uc = sqlite3_column_int64(s, 2);
                int64_t fsh = sqlite3_column_int64(s, 3);
                char bstr[64];
                fmt_zcl(bstr, sizeof(bstr), bal);
                APPEND(off, r, max,
                    "<tr><td>%d</td><td><code>%.16s...</code></td>"
                    "<td>%s ZCL</td><td>%" PRId64 "</td>"
                    "<td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td></tr>",
                    rank, ah ? ah : "?", bstr, uc, fsh, fsh);
                rank++;
            }
            sqlite3_finalize(s);
        }
    }
    APPEND(off, r, max, "</table>");
    return off;
}
