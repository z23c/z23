/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer stats VIEW: section emitters.
 *
 * Part of the deep-stats page split: this TU owns the per-section HTML
 * emitters (emit_stats_header + emit_section_*), each appending one
 * logical section of the stats page. Address encoding is delegated to
 * the shared wallet_encode_destination helper (controllers/wallet_helpers.h).
 * The public entry point (explorer_stats_build), the phase-1
 * data gather, the degraded verified-summary fallback, and the chart /
 * shielded render helpers live in explorer_stats_view.c. Shared data
 * structs + emitter declarations come from views/explorer_stats_internal.h. */

#include "views/explorer_stats_internal.h"
#include "controllers/wallet_helpers.h"

/* ── Section emit helpers ──────────────────────────────────────────
 *
 * Each helper appends one logical section of the stats HTML page.
 * The stats_ctx struct (defined at top of file) bundles every value
 * gathered during phase 1 so the render helpers don't need a fat
 * parameter list.
 */

size_t emit_stats_header(uint8_t *r, size_t max, size_t off,
                                const struct stats_ctx *c)
{
    APPEND(off, r, max, EXPLORER_HEADER("ZClassic Deep Stats"));
    off += explorer_emit_nav((char *)r + off, max - off, "stats");
    APPEND(off, r, max,
        "<h1>ZClassic Blockchain Deep Statistics</h1>"
        "<p style='color:#888;margin:-8px 0 16px;font-size:15px'>"
        "Every statistic from %d days of blockchain history "
        "(Genesis: Nov 6 2016). Computed in %llds from indexed SQLite.</p>",
        (int)c->chain_age_days, (long long)c->t_query_ms);
    return off;
}

size_t emit_section_1_network(uint8_t *r, size_t max, size_t off,
                                     const struct stats_ctx *c)
{
    APPEND(off, r, max,
        "<h2>Network Overview</h2>"
        "<div class='stats-row'>"
        "<div class='stat'><div class='num'>%d</div><div class='lbl'>Block Height</div></div>"
        "<div class='stat'><div class='num'>%.4f</div><div class='lbl'>Difficulty</div></div>"
        "<div class='stat'><div class='num'>%s</div><div class='lbl'>Est. Solve Rate</div></div>"
        "</div>"
        "<div class='stats-row'>"
        "<div class='stat'><div class='num'>%s ZCL</div><div class='lbl'>Transparent UTXO Pool</div></div>"
        "<div class='stat'><div class='num'>%.2f%%</div><div class='lbl'>Transparent %% of Cap</div></div>"
        "<div class='stat'><div class='num'>%" PRId64 "</div><div class='lbl'>Total UTXOs</div></div>"
        "</div>",
        c->tip, c->diff, c->hr_str,
        c->supply_str, c->pct_mined, c->utxo_count_val);
    return off;
}

/* Format zatoshi as a thousands-separated ZCL string with 2 decimals,
 * e.g. 1045337617187500 -> "10,453,376.17". Compact for headline cards. */
static void econ_fmt_zcl(char *buf, size_t max, int64_t zat)
{
    int64_t whole = zat / 100000000LL;
    int64_t frac  = zat % 100000000LL;
    if (frac < 0) frac = -frac;
    char wc[32];
    format_with_commas(wc, sizeof(wc), whole);
    snprintf(buf, max, "%s.%02lld", wc, (long long)(frac / 1000000LL));
}

/* Human-readable duration: years / days / minutes. */
static void econ_fmt_duration(char *buf, size_t max, int64_t secs)
{
    if (secs <= 0) { snprintf(buf, max, "n/a"); return; }
    double days = (double)secs / 86400.0;
    if (days >= 365.25)   snprintf(buf, max, "%.2f years", days / 365.25);
    else if (days >= 1.0) snprintf(buf, max, "%.1f days", days);
    else                  snprintf(buf, max, "%lld min", (long long)(secs / 60));
}

size_t emit_section_1b_economy(uint8_t *r, size_t max, size_t off,
                                      const struct stats_ctx *c)
{
    char mined_str[40], cap_str[40], subsidy_str[40], solrate_str[40];
    char daily_str[40], median_str[40], avg_str[40], cb_mat_str[40], cb_imm_str[40];
    char eta_str[40], age_str[40];
    econ_fmt_zcl(mined_str, sizeof(mined_str), c->mined_supply);
    econ_fmt_zcl(cap_str, sizeof(cap_str), c->max_supply_sat);
    zcl_format_zcl(subsidy_str, sizeof(subsidy_str), c->current_subsidy);
    explorer_format_solrate(solrate_str, sizeof(solrate_str), c->solrate);

    int64_t mature_cb_count = c->utxo_coinbase_count - c->immature_cb_count;
    int64_t mature_cb_value = c->utxo_coinbase_value - c->immature_cb_value;
    econ_fmt_zcl(cb_mat_str, sizeof(cb_mat_str), mature_cb_value);
    econ_fmt_zcl(cb_imm_str, sizeof(cb_imm_str), c->immature_cb_value);
    zcl_format_zcl(median_str, sizeof(median_str), c->median_utxo_value);
    zcl_format_zcl(avg_str, sizeof(avg_str), (int64_t)c->utxo_avg);
    econ_fmt_duration(eta_str, sizeof(eta_str), c->halving_eta_secs);
    econ_fmt_duration(age_str, sizeof(age_str), c->tip_age_secs);
    snprintf(daily_str, sizeof(daily_str), "%.2f", c->daily_issuance_zcl);

    char txd[24], txt[24], dust_c[24], imm_c[24], mat_c[24];
    char netg[24], so_str[24], blk_until[24];
    format_with_commas(txd, sizeof(txd), c->tx_per_day);
    format_with_commas(txt, sizeof(txt), c->total_txs);
    format_with_commas(dust_c, sizeof(dust_c), c->utxo_dust);
    format_with_commas(imm_c, sizeof(imm_c), c->immature_cb_count);
    format_with_commas(mat_c, sizeof(mat_c), mature_cb_count);
    format_with_commas(blk_until, sizeof(blk_until), c->blocks_until_halving);
    snprintf(netg, sizeof(netg), "%s%lld",
             c->net_daily_utxo >= 0 ? "+" : "", (long long)c->net_daily_utxo);

    double dust_pct = c->utxo_count_val > 0
        ? (double)c->utxo_dust / (double)c->utxo_count_val * 100.0 : 0.0;
    int64_t shielded_ops = c->total_joinsplits + c->total_sap_spends
                         + c->total_sap_outputs;
    format_with_commas(so_str, sizeof(so_str), shielded_ops);
    double shielded_ratio = c->total_txs > 0
        ? (double)shielded_ops / (double)c->total_txs * 100.0 : 0.0;
    double oldest_years =
        (double)hodl_wave_age_seconds(c->utxo_min_height, c->tip)
        / 86400.0 / 365.25;

    APPEND(off, r, max,
        "<h2>Economy &amp; Emission</h2>"
        "<p style='color:#888;margin:-4px 0 12px;font-size:14px'>"
        "Live supply, issuance, and network metrics. Solve rate is Equihash "
        "solutions/sec at the active target block spacing; supply caps at the "
        "true asymptotic %s ZCL (not 21M).</p>"
        "<div class='stats-row'>"
        "<div class='stat'><div class='num'>%s</div>"
        "<div class='lbl'>Circulating Supply (ZCL)</div></div>"
        "<div class='stat'><div class='num'>%.2f%%</div>"
        "<div class='lbl'>%% of Max Supply (cap)</div></div>"
        "<div class='stat'><div class='num'>%s</div>"
        "<div class='lbl'>Est. Network Solve Rate</div></div>"
        "</div>",
        cap_str, mined_str, c->pct_of_cap, solrate_str);

    APPEND(off, r, max,
        "<div class='card'><div class='grid'>"
        "<div class='label'>Asymptotic Cap</div><div class='val amount'>%s ZCL</div>"
        "<div class='label'>Current Block Subsidy</div><div class='val amount'>%s ZCL</div>"
        "<div class='label'>Blocks to Next Halving</div><div class='val'>%s (~%s)</div>"
        "<div class='label'>Daily Issuance</div><div class='val amount'>%s ZCL/day</div>"
        "<div class='label'>Annualized Inflation</div><div class='val'>%.2f%%</div>"
        "<div class='label'>Recent Avg Block Interval</div>"
        "<div class='val'>%.1f s (target %ds)</div>"
        "<div class='label'>Chain Tip Age</div><div class='val'>%s</div>"
        "<div class='label'>Total Transactions</div><div class='val'>%s</div>"
        "<div class='label'>Transactions / Day</div><div class='val'>%s</div>"
        "<div class='label'>UTXO Set Size</div><div class='val'>%" PRId64 "</div>"
        "<div class='label'>Net Daily UTXO Growth</div><div class='val'>%s</div>"
        "<div class='label'>Dust UTXOs (&lt; 0.001 ZCL)</div>"
        "<div class='val'>%s (%.2f%%)</div>"
        "<div class='label'>Mature Coinbase UTXOs</div>"
        "<div class='val'>%s &mdash; %s ZCL</div>"
        "<div class='label'>Immature Coinbase UTXOs</div>"
        "<div class='val'>%s &mdash; %s ZCL</div>"
        "<div class='label'>Median UTXO Value</div><div class='val amount'>%s ZCL</div>"
        "<div class='label'>Average UTXO Value</div><div class='val amount'>%s ZCL</div>"
        "<div class='label'>Oldest Live Coin</div>"
        "<div class='val'>Block %" PRId64 " (~%.1f yr)</div>"
        "<div class='label'>Shielded Ops vs Total Tx</div>"
        "<div class='val'>%s (%.1f%%)</div>"
        "<div class='label'>Cumulative Chainwork</div>"
        "<div class='val' style='font-family:monospace;font-size:12px'>0x%s</div>"
        "</div></div>",
        cap_str, subsidy_str,
        blk_until, eta_str,
        daily_str, c->annual_inflation,
        c->recent_avg_interval, explorer_target_spacing(c->tip),
        age_str,
        txt, txd,
        c->utxo_count_val, netg,
        dust_c, dust_pct,
        mat_c, cb_mat_str,
        imm_c, cb_imm_str,
        median_str, avg_str,
        c->utxo_min_height, oldest_years,
        so_str, shielded_ratio,
        c->chainwork_hex[0] ? c->chainwork_hex : "n/a");
    return off;
}

size_t emit_section_2_chain_history(uint8_t *r, size_t max, size_t off,
                                           const struct stats_ctx *c)
{
    char genesis_ts[32], tip_ts[32], subsidy_str[32];
    explorer_format_time(genesis_ts, sizeof(genesis_ts), (uint32_t)c->genesis_time);
    explorer_format_time(tip_ts, sizeof(tip_ts), (uint32_t)c->tip_time);
    zcl_format_zcl(subsidy_str, sizeof(subsidy_str), c->current_subsidy);
    APPEND(off, r, max,
        "<h2>Chain History</h2><div class='card'><div class='grid'>"
        "<div class='label'>Genesis Block</div><div class='val'>"
        "<a href='/explorer/block/0'>Block 0</a> &mdash; %s</div>"
        "<div class='label'>Latest Block</div><div class='val'>"
        "<a href='/explorer/block/%d'>Block %d</a> &mdash; %s</div>"
        "<div class='label'>Chain Age</div><div class='val'>%d days (%.1f years)</div>"
        "<div class='label'>Total Blocks</div><div class='val'>%" PRId64 "</div>"
        "<div class='label'>Total Transactions</div><div class='val'>%" PRId64 "</div>"
        "<div class='label'>Coinbase / Non-Coinbase</div><div class='val'>%" PRId64 " / %" PRId64 "</div>"
        "<div class='label'>Avg Txs/Block</div><div class='val'>%.2f</div>"
        "<div class='label'>Halvings Occurred</div><div class='val'>%d</div>"
        "<div class='label'>Current Block Reward</div><div class='val'>%s ZCL</div>"
        "<div class='label'>Next Halving</div><div class='val'>"
        "<a href='/explorer/block/%d'>Block %d</a> (%d blocks away)</div>"
        "</div></div>",
        genesis_ts, c->tip, c->tip, tip_ts,
        (int)c->chain_age_days, (double)c->chain_age_days / 365.25,
        c->total_blocks, c->total_txs, c->coinbase_txs, c->total_txs - c->coinbase_txs,
        c->avg_tx_per_block, c->halvings, subsidy_str,
        c->next_halving, c->next_halving, c->blocks_until_halving);
    return off;
}

size_t emit_section_3_block_records(uint8_t *r, size_t max, size_t off,
                                           const struct stats_ctx *c)
{
    APPEND(off, r, max,
        "<h2>Block Records</h2><div class='card'><div class='grid'>"
        "<div class='label'>Most Transactions in Block</div>"
        "<div class='val'><a href='/explorer/block/%" PRId64 "'>Block %" PRId64 "</a>"
        " &mdash; %" PRId64 " txs</div>"
        "<div class='label'>Empty Blocks (coinbase only)</div>"
        "<div class='val'>%" PRId64 " (%.1f%%)</div>"
        "<div class='label'>Lowest Difficulty</div>"
        "<div class='val'>%.6f at <a href='/explorer/block/%" PRId64 "'>Block %" PRId64 "</a></div>"
        "<div class='label'>Highest Difficulty</div>"
        "<div class='val'>%.6f at <a href='/explorer/block/%" PRId64 "'>Block %" PRId64 "</a></div>"
        "</div></div>",
        c->max_tx_block, c->max_tx_block, c->max_tx_count,
        c->empty_blocks, c->total_blocks > 0 ? (double)c->empty_blocks / c->total_blocks * 100.0 : 0,
        c->min_diff, c->min_bits_height, c->min_bits_height,
        c->max_diff, c->max_bits_height, c->max_bits_height);
    return off;
}

size_t emit_section_6_utxo_distribution(uint8_t *r, size_t max, size_t off,
                                               const struct stats_ctx *c, sqlite3 *db)
{
    char max_val[32], avg_val[32], cb_val[32];
    zcl_format_zcl(max_val, sizeof(max_val), c->utxo_max_value);
    zcl_format_zcl(avg_val, sizeof(avg_val), (int64_t)c->utxo_avg);
    zcl_format_zcl(cb_val, sizeof(cb_val), c->utxo_coinbase_value);

    APPEND(off, r, max,
        "<h2>UTXO Set Distribution</h2>"
        "<div class='stats-row'>"
        "<div class='stat'><div class='num'>%" PRId64 "</div>"
        "<div class='lbl'>Total UTXOs</div></div>"
        "<div class='stat'><div class='num'>%s</div>"
        "<div class='lbl'>Largest UTXO</div></div>"
        "<div class='stat'><div class='num'>%s</div>"
        "<div class='lbl'>Average UTXO</div></div>"
        "</div>",
        c->utxo_count_val, max_val, avg_val);

    APPEND(off, r, max,
        "<div class='card'><h3 style='color:#4db8ff;margin:0 0 12px'>Size Breakdown</h3>"
        "<table><tr><th>Range</th><th>Count</th><th>%% of UTXOs</th></tr>"
        "<tr><td>Dust (&lt; 0.001 ZCL)</td><td>%" PRId64 "</td><td>%.1f%%</td></tr>"
        "<tr><td>Small (0.001 - 1 ZCL)</td><td>%" PRId64 "</td><td>%.1f%%</td></tr>"
        "<tr><td>Medium (1 - 10 ZCL)</td><td>%" PRId64 "</td><td>%.1f%%</td></tr>"
        "<tr><td>Large (10 - 100 ZCL)</td><td>%" PRId64 "</td><td>%.1f%%</td></tr>"
        "<tr><td>Whale (100+ ZCL)</td><td>%" PRId64 "</td><td>%.1f%%</td></tr>"
        "</table></div>",
        c->utxo_dust,   c->utxo_count_val > 0 ? (double)c->utxo_dust / c->utxo_count_val * 100 : 0,
        c->utxo_small,  c->utxo_count_val > 0 ? (double)c->utxo_small / c->utxo_count_val * 100 : 0,
        c->utxo_medium, c->utxo_count_val > 0 ? (double)c->utxo_medium / c->utxo_count_val * 100 : 0,
        c->utxo_large,  c->utxo_count_val > 0 ? (double)c->utxo_large / c->utxo_count_val * 100 : 0,
        c->utxo_whale,  c->utxo_count_val > 0 ? (double)c->utxo_whale / c->utxo_count_val * 100 : 0);

    /* Oldest UTXOs */
    APPEND(off, r, max,
        "<h3>Oldest Unspent UTXOs</h3>"
        "<table><tr><th>Block</th><th>Time</th><th>Value</th><th>TXID</th></tr>");
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT u.height, b.time, u.value, hex(u.txid) "
                "FROM utxos u LEFT JOIN blocks b ON u.height = b.height "
                "ORDER BY u.height ASC LIMIT 20",
                -1, &s, NULL) == SQLITE_OK && s) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                int64_t h = sqlite3_column_int64(s, 0);
                int64_t t = sqlite3_column_int64(s, 1);
                if (t == 0 && h == 0) t = 1478403829; /* genesis */
                int64_t v = sqlite3_column_int64(s, 2);
                const char *txhex = (const char *)sqlite3_column_text(s, 3);
                char ts[32], vs[32], txid[65] = "", short_tx[18] = "";
                explorer_format_time(ts, sizeof(ts), (uint32_t)t);
                zcl_format_zcl(vs, sizeof(vs), v);
                if (txhex && strlen(txhex) == 64) {
                    for (int i = 0; i < 32; i++) {
                        txid[i*2]   = txhex[62-i*2];
                        txid[i*2+1] = txhex[63-i*2];
                    }
                    txid[64] = '\0';
                    snprintf(short_tx, sizeof(short_tx), "%.8s...", txid);
                }
                APPEND(off, r, max,
                    "<tr><td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>"
                    "<td>%s</td><td class='amount'>%s ZCL</td>"
                    "<td class='hash'><a href='/explorer/tx/%s'>%s</a></td></tr>",
                    h, h, ts, vs, txid, short_tx);
            }
            sqlite3_finalize(s);
        }
    }
    APPEND(off, r, max, "</table>");

    /* Top 20 largest UTXOs */
    APPEND(off, r, max,
        "<h3>Top 20 Largest Unspent Outputs</h3>"
        "<table><tr><th>Value</th><th>Block</th><th>TXID</th></tr>");
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT value, height, hex(txid) FROM utxos "
                "ORDER BY value DESC LIMIT 20",
                -1, &s, NULL) == SQLITE_OK && s) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                int64_t v = sqlite3_column_int64(s, 0);
                int64_t h = sqlite3_column_int64(s, 1);
                const char *txhex = (const char *)sqlite3_column_text(s, 2);
                char vs[32], txid[65] = "", short_tx[18] = "";
                zcl_format_zcl(vs, sizeof(vs), v);
                if (txhex && strlen(txhex) == 64) {
                    for (int i = 0; i < 32; i++) {
                        txid[i*2]   = txhex[62-i*2];
                        txid[i*2+1] = txhex[63-i*2];
                    }
                    txid[64] = '\0';
                    snprintf(short_tx, sizeof(short_tx), "%.8s...", txid);
                }
                APPEND(off, r, max,
                    "<tr><td class='amount'>%s ZCL</td>"
                    "<td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>"
                    "<td class='hash'><a href='/explorer/tx/%s'>%s</a></td></tr>",
                    vs, h, h, txid, short_tx);
            }
            sqlite3_finalize(s);
        }
    }
    APPEND(off, r, max, "</table>");

    APPEND(off, r, max,
        "<div class='card'><div class='grid'>"
        "<div class='label'>Unspent Coinbase UTXOs</div><div class='val'>%" PRId64 "</div>"
        "<div class='label'>Unspent Coinbase Value</div><div class='val amount'>%s ZCL</div>"
        "<div class='label'>Oldest UTXO From</div>"
        "<div class='val'><a href='/explorer/block/%" PRId64 "'>Block %" PRId64 "</a></div>"
        "</div></div>",
        c->utxo_coinbase_count, cb_val, c->utxo_min_height, c->utxo_min_height);
    return off;
}

size_t emit_section_7_address_distribution(uint8_t *r, size_t max, size_t off,
                                                  const struct stats_ctx *c, sqlite3 *db)
{
    char top10_str[32], top100_str[32];
    zcl_format_zcl(top10_str, sizeof(top10_str), c->top10_balance);
    zcl_format_zcl(top100_str, sizeof(top100_str), c->top100_balance);

    APPEND(off, r, max,
        "<h2>Address Distribution</h2>"
        "<div class='stats-row'>"
        "<div class='stat'><div class='num'>%" PRId64 "</div>"
        "<div class='lbl'>Addresses with UTXOs</div></div>"
        "<div class='stat'><div class='num'>%" PRId64 "</div>"
        "<div class='lbl'>Non-Zero Balances</div></div>"
        "</div>"
        "<div class='card'><div class='grid'>"
        "<div class='label'>Top 10 Hold</div>"
        "<div class='val amount'>%s ZCL (%.1f%%)</div>"
        "<div class='label'>Top 100 Hold</div>"
        "<div class='val amount'>%s ZCL (%.1f%%)</div>"
        "</div></div>",
        c->total_addresses, c->addr_nonzero,
        top10_str, c->total_supply > 0 ? (double)c->top10_balance / c->total_supply * 100 : 0,
        top100_str, c->total_supply > 0 ? (double)c->top100_balance / c->total_supply * 100 : 0);

    /* Top 20 richest */
    APPEND(off, r, max,
        "<h3>Top 20 Richest Addresses</h3>"
        "<table><tr><th>#</th><th>Address</th><th>Balance</th>"
        "<th>UTXOs</th><th>%% of Supply</th></tr>");
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT address_hash, balance, utxo_count, script_type "
                "FROM addresses ORDER BY balance DESC LIMIT 20",
                -1, &s, NULL) == SQLITE_OK && s) {
            int rank = 0;
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                rank++;
                const void *ah = sqlite3_column_blob(s, 0);
                int ah_len = sqlite3_column_bytes(s, 0);
                int64_t bal = sqlite3_column_int64(s, 1);
                int64_t uc = sqlite3_column_int64(s, 2);
                int st = sqlite3_column_int(s, 3);
                char bs[32], addr[64] = "unknown";
                zcl_format_zcl(bs, sizeof(bs), bal);
                if (ah && ah_len == 20) {
                    struct tx_destination dest;
                    memset(&dest, 0, sizeof(dest));
                    if (st == 2) {
                        dest.type = DEST_SCRIPT_ID;
                        memcpy(dest.id.script.hash.data, ah, 20);
                    } else {
                        dest.type = DEST_KEY_ID;
                        memcpy(dest.id.key.id.data, ah, 20);
                    }
                    wallet_encode_destination(&dest, addr, sizeof(addr));
                }
                APPEND(off, r, max,
                    "<tr><td>%d</td>"
                    "<td class='hash'><a href='/explorer/address/%s'>%s</a></td>"
                    "<td class='amount'>%s ZCL</td><td>%" PRId64 "</td>"
                    "<td>%.2f%%</td></tr>",
                    rank, addr, addr, bs, uc,
                    c->total_supply > 0 ? (double)bal / c->total_supply * 100 : 0);
            }
            sqlite3_finalize(s);
        }
    }
    APPEND(off, r, max, "</table>");
    return off;
}

size_t emit_section_8_zslp_opret(uint8_t *r, size_t max, size_t off,
                                        const struct stats_ctx *c)
{
    APPEND(off, r, max,
        "<h2>ZSLP Tokens &amp; OP_RETURN Data</h2>"
        "<div class='stats-row'>"
        "<div class='stat'><div class='num'>%" PRId64 "</div>"
        "<div class='lbl'>OP_RETURN Outputs</div></div>"
        "<div class='stat'><div class='num'>%" PRId64 "</div>"
        "<div class='lbl'>ZSLP OP_RETURNs</div></div>"
        "<div class='stat'><div class='num'>%" PRId64 "</div>"
        "<div class='lbl'>Token Types</div></div>"
        "<div class='stat'><div class='num'>%" PRId64 "</div>"
        "<div class='lbl'>ZSLP Transfers</div></div>"
        "</div>",
        c->opret_count, c->slp_opret_count, c->zslp_token_count, c->zslp_transfer_count);
    if (c->zslp_token_count > 0)
        APPEND(off, r, max,
            "<p style='text-align:center'>"
            "<a href='/explorer/tokens' style='font-size:18px;font-weight:700'>"
            "View All ZSLP Tokens &rarr;</a></p>");
    return off;
}

size_t emit_section_8b_tx_io(uint8_t *r, size_t max, size_t off,
                                    const struct stats_ctx *c)
{
    char max_out_str[32], total_moved_str[32];
    zcl_format_zcl(max_out_str, sizeof(max_out_str), c->max_output_value);
    zcl_format_zcl(total_moved_str, sizeof(total_moved_str), c->total_value_moved);
    double io_ratio = c->total_inputs > 0 ? (double)c->total_outputs / c->total_inputs : 0;

    APPEND(off, r, max,
        "<h2>Transaction I/O Deep Stats</h2>"
        "<p style='color:#888;margin:-4px 0 12px;font-size:14px'>"
        "Per-output and per-input data from the full chain index.</p>"
        "<div class='stats-row'>"
        "<div class='stat'><div class='num'>%" PRId64 "</div>"
        "<div class='lbl'>Total Outputs Ever</div></div>"
        "<div class='stat'><div class='num'>%" PRId64 "</div>"
        "<div class='lbl'>Total Inputs Ever</div></div>"
        "<div class='stat'><div class='num'>%.2f</div>"
        "<div class='lbl'>Output/Input Ratio</div></div>"
        "</div>",
        c->total_outputs, c->total_inputs, io_ratio);

    APPEND(off, r, max,
        "<div class='card'><div class='grid'>"
        "<div class='label'>P2PKH Outputs</div>"
        "<div class='val'>%" PRId64 " (%.1f%%)</div>"
        "<div class='label'>P2SH Outputs</div>"
        "<div class='val'>%" PRId64 " (%.1f%%)</div>"
        "<div class='label'>Other Output Types</div>"
        "<div class='val'>%" PRId64 "</div>"
        "<div class='label'>Largest Output Ever</div>"
        "<div class='val amount'>%s ZCL</div>"
        "<div class='label'>Total Value Ever Moved</div>"
        "<div class='val amount'>%s ZCL</div>"
        "</div></div>",
        c->p2pkh_outputs, c->total_outputs > 0 ? (double)c->p2pkh_outputs / c->total_outputs * 100 : 0,
        c->p2sh_outputs, c->total_outputs > 0 ? (double)c->p2sh_outputs / c->total_outputs * 100 : 0,
        c->total_outputs - c->p2pkh_outputs - c->p2sh_outputs,
        max_out_str, total_moved_str);
    return off;
}

size_t emit_section_8c_shielded_detail(uint8_t *r, size_t max, size_t off,
                                              const struct stats_ctx *c)
{
    char vpub_old_str[32], vpub_new_str[32];
    zcl_format_zcl(vpub_old_str, sizeof(vpub_old_str), c->total_vpub_old);
    zcl_format_zcl(vpub_new_str, sizeof(vpub_new_str), c->total_vpub_new);
    double sap_ratio = c->total_sap_outputs > 0
        ? (double)c->total_sap_spends / c->total_sap_outputs : 0;

    APPEND(off, r, max,
        "<h2>Shielded Operations Detail</h2>"
        "<p style='color:#888;margin:-4px 0 12px;font-size:14px'>"
        "Per-transaction shielded data from joinsplits, sapling_spends, "
        "sapling_outputs, and sprout_nullifiers tables.</p>"
        "<div class='stats-row'>"
        "<div class='stat'><div class='num'>%" PRId64 "</div>"
        "<div class='lbl'>Total JoinSplits</div></div>"
        "<div class='stat'><div class='num'>%" PRId64 "</div>"
        "<div class='lbl'>Total Sapling Spends</div></div>"
        "<div class='stat'><div class='num'>%" PRId64 "</div>"
        "<div class='lbl'>Total Sapling Outputs</div></div>"
        "</div>",
        c->total_joinsplits, c->total_sap_spends, c->total_sap_outputs);

    APPEND(off, r, max,
        "<div class='card'><div class='grid'>"
        "<div class='label'>Sprout Nullifiers</div>"
        "<div class='val'>%" PRId64 "</div>"
        "<div class='label'>Total vpub_old (t&rarr;z via Sprout)</div>"
        "<div class='val amount'>%s ZCL</div>"
        "<div class='label'>Total vpub_new (z&rarr;t via Sprout)</div>"
        "<div class='val amount'>%s ZCL</div>"
        "<div class='label'>Unique Sapling Anchors</div>"
        "<div class='val'>%" PRId64 "</div>"
        "<div class='label'>Sapling Spend/Output Ratio</div>"
        "<div class='val'>%.4f</div>"
        "</div></div>",
        c->total_sprout_nulls,
        vpub_old_str, vpub_new_str,
        c->unique_sap_anchors, sap_ratio);
    return off;
}

size_t emit_section_8d_integrity(uint8_t *r, size_t max, size_t off,
                                        const struct stats_ctx *c)
{
    char hash_short[20] = "N/A";
    if (c->integrity_latest_hash[0] != 'N') {
        snprintf(hash_short, sizeof(hash_short), "%.16s...", c->integrity_latest_hash);
    }

    APPEND(off, r, max,
        "<h2>SHA3-256 Integrity Chain</h2>"
        "<p style='color:#888;margin:-4px 0 12px;font-size:14px'>"
        "Cryptographic chain of block data hashes for tamper detection.</p>"
        "<div class='stats-row'>"
        "<div class='stat'><div class='num'>%" PRId64 "</div>"
        "<div class='lbl'>Total Checkpoints</div></div>"
        "<div class='stat'><div class='num'>%" PRId64 " &ndash; %" PRId64 "</div>"
        "<div class='lbl'>Chain Coverage (Height)</div></div>"
        "</div>",
        c->integrity_count, c->integrity_min_h, c->integrity_max_h);

    APPEND(off, r, max,
        "<div class='card'><div class='grid'>"
        "<div class='label'>Latest SHA3 Hash</div>"
        "<div class='val' style='font-family:monospace;font-size:13px'>%s</div>"
        "</div>"
        "<p style='color:#888;margin:12px 0 0;font-size:13px;line-height:1.5'>"
        "Every block's data is chained via SHA3-256 hash. The integrity chain covers "
        "H(prev_hash || height || block_hash || sprout_value || sapling_value || num_tx "
        "|| num_joinsplits || num_sapling_spends || num_sapling_outputs). "
        "Verify any block by recomputing from genesis.</p></div>",
        c->integrity_latest_hash[0] != 'N' ? c->integrity_latest_hash : "N/A");
    return off;
}

size_t emit_section_8e_firsts(uint8_t *r, size_t max, size_t off,
                                     const struct stats_ctx *c)
{
    APPEND(off, r, max,
        "<h2>Chain Firsts &amp; Records</h2>"
        "<p style='color:#888;margin:-4px 0 12px;font-size:14px'>"
        "Milestones and extremes from the full chain index.</p>"
        "<table><tr><th>Milestone</th><th>Block</th><th>Detail</th></tr>");

    if (c->first_noncoinbase > 0)
        APPEND(off, r, max,
            "<tr><td>First Non-Coinbase Transaction</td>"
            "<td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>"
            "<td>First user-to-user transfer</td></tr>",
            c->first_noncoinbase, c->first_noncoinbase);

    if (c->first_joinsplit_h > 0)
        APPEND(off, r, max,
            "<tr><td>First JoinSplit (Sprout Shielding)</td>"
            "<td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>"
            "<td>First shielded transaction</td></tr>",
            c->first_joinsplit_h, c->first_joinsplit_h);

    if (c->first_sapling_h > 0)
        APPEND(off, r, max,
            "<tr><td>First Sapling Spend</td>"
            "<td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>"
            "<td>First Groth16 shielded spend</td></tr>",
            c->first_sapling_h, c->first_sapling_h);

    if (c->first_opreturn_h > 0)
        APPEND(off, r, max,
            "<tr><td>First OP_RETURN</td>"
            "<td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>"
            "<td>First data-carrying output</td></tr>",
            c->first_opreturn_h, c->first_opreturn_h);

    if (c->first_zslp_h > 0)
        APPEND(off, r, max,
            "<tr><td>First ZSLP Token</td>"
            "<td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>"
            "<td>First token genesis</td></tr>",
            c->first_zslp_h, c->first_zslp_h);

    if (c->most_js_count > 0)
        APPEND(off, r, max,
            "<tr><td>Most JoinSplits in Block</td>"
            "<td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>"
            "<td>%" PRId64 " JoinSplit operations</td></tr>",
            c->most_js_block, c->most_js_block, c->most_js_count);

    if (c->most_sap_out_count > 0)
        APPEND(off, r, max,
            "<tr><td>Most Sapling Outputs in Block</td>"
            "<td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>"
            "<td>%" PRId64 " Sapling notes created</td></tr>",
            c->most_sap_out_block, c->most_sap_out_block, c->most_sap_out_count);

    if (c->fastest_block_gap > 0)
        APPEND(off, r, max,
            "<tr><td>Fastest Block Time</td>"
            "<td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>"
            "<td>%" PRId64 " seconds</td></tr>",
            c->fastest_block_h, c->fastest_block_h, c->fastest_block_gap);

    if (c->slowest_block_gap > 0)
        APPEND(off, r, max,
            "<tr><td>Slowest Block Time</td>"
            "<td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>"
            "<td>%" PRId64 " seconds (%.1f hours)</td></tr>",
            c->slowest_block_h, c->slowest_block_h, c->slowest_block_gap,
            (double)c->slowest_block_gap / 3600.0);

    APPEND(off, r, max, "</table>");
    return off;
}

size_t emit_section_9_tx_volume_by_year(uint8_t *r, size_t max, size_t off,
                                               sqlite3 *db)
{
    APPEND(off, r, max,
        "<h2>Transaction Volume by Year</h2>"
        "<table><tr><th>Year</th><th>Blocks</th><th>Total Txs</th>"
        "<th>Avg Tx/Block</th></tr>");
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT CAST(strftime('%Y', time, 'unixepoch') AS INTEGER) AS yr, "
                "count(*), COALESCE(SUM(num_tx),0) "
                "FROM blocks WHERE time > 0 GROUP BY yr ORDER BY yr",
                -1, &s, NULL) == SQLITE_OK && s) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                int year = sqlite3_column_int(s, 0);
                int64_t blks = sqlite3_column_int64(s, 1);
                int64_t txs = sqlite3_column_int64(s, 2);
                if (blks > 0)
                    APPEND(off, r, max,
                        "<tr><td>%d</td><td>%" PRId64 "</td><td>%" PRId64 "</td>"
                        "<td>%.2f</td></tr>",
                        year, blks, txs, (double)txs / blks);
            }
            sqlite3_finalize(s);
        }
    }
    APPEND(off, r, max, "</table>");
    return off;
}

size_t emit_section_10_utxo_age(uint8_t *r, size_t max, size_t off,
                                       const struct stats_ctx *c, sqlite3 *db)
{
    APPEND(off, r, max,
        "<h2>UTXO Age Distribution</h2>"
        "<p style='color:#888;margin:-4px 0 12px;font-size:14px'>"
        "Grouped by creation block range.</p>"
        "<table><tr><th>Block Range</th><th>Age</th><th>UTXOs</th>"
        "<th>Value (ZCL)</th><th>%% of Supply</th></tr>");
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT (height / 100000) * 100000 AS band, "
                "count(*), COALESCE(SUM(value),0) "
                "FROM utxos GROUP BY band ORDER BY band",
                -1, &s, NULL) == SQLITE_OK && s) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                int64_t band = sqlite3_column_int64(s, 0);
                int64_t cnt = sqlite3_column_int64(s, 1);
                int64_t val = sqlite3_column_int64(s, 2);
                if (cnt == 0) continue;
                char vs[32];
                zcl_format_zcl(vs, sizeof(vs), val);
                int64_t band_end = band + 100000;
                int mid = (int)((band + (band_end < c->tip ? band_end : c->tip)) / 2);
                int days = (int)(hodl_wave_age_seconds(mid, c->tip) / 86400);
                char age[32];
                if (days > 365) snprintf(age, sizeof(age), "~%.1fy", (double)days/365.25);
                else if (days > 30) snprintf(age, sizeof(age), "~%dmo", days/30);
                else snprintf(age, sizeof(age), "~%dd", days);

                APPEND(off, r, max,
                    "<tr><td>%" PRId64 "K-%" PRId64 "K</td><td>%s</td>"
                    "<td>%" PRId64 "</td><td class='amount'>%s</td>"
                    "<td>%.2f%%</td></tr>",
                    band/1000, band_end/1000, age, cnt, vs,
                    c->total_supply > 0 ? (double)val / c->total_supply * 100 : 0);
            }
            sqlite3_finalize(s);
        }
    }
    APPEND(off, r, max, "</table>");
    return off;
}
