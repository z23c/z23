/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer factoids VIEW — comprehensive "historian nerd" page with
 * SHA3 data receipts for every single fact. Renders HTML/JSON from the
 * read-only explorer projection (node.db). View shape: the controller
 * parses the request and delegates here; all page assembly lives here.
 *
 * 17 Sections: Genesis Story, Network Upgrade History, Mining Era Analysis,
 * Network Milestones, All-Time Records, Supply Milestones, Address Stats,
 * Privacy Usage Over Time (Sprout + Sapling + Shielding Volume),
 * ZSLP Token History, OP_RETURN Archaeology, Dust & UTXO Analysis,
 * Checkpoint History, Block Time Analysis, Transaction Archaeology,
 * Empty Blocks, Difficulty History, Data Integrity.
 *
 * This file owns the public entry points + JSON API + the degraded
 * "verified summary" fallback. The 17 section emitters live in focused
 * sibling translation units sharing views/explorer_factoids_internal.h:
 *   - explorer_factoids_history.c   — sections 1-4 and 6 (origin/supply)
 *   - explorer_factoids_records.c   — section 5 (all-time records)
 *   - explorer_factoids_addresses.c — section 7 (address statistics)
 *   - explorer_factoids_chaindata.c — sections 8-12 (archaeology)
 *   - explorer_factoids_checkpoints.c / explorer_factoids_blocktimes.c /
 *     explorer_factoids_transactions.c / explorer_factoids_empty_blocks.c /
 *     explorer_factoids_difficulty.c / explorer_factoids_integrity.c own the
 *     larger row/receipt renderers for sections 12-17.
 *
 * Also provides explorer_factoids_build_json() for /api/factoids. */

#include "views/explorer_factoids_view.h"
#include "views/explorer_factoids_internal.h"
#include "util/log_macros.h"

/* ── Degraded fallback: verified summary when block history is unusable ── */

static size_t explorer_factoids_build_verified_summary(uint8_t *buf,
                                                       size_t buf_max,
                                                       sqlite3 *db,
                                                       int64_t chain_height,
                                                       const char *degraded_reason)
{
    size_t off = 0;
    char *r = (char *)buf;
    size_t max = buf_max;

    int64_t utxo_count = fq_i64(db, "SELECT count(*) FROM utxos");
    int64_t utxo_value = fq_i64(db, "SELECT COALESCE(SUM(value),0) FROM utxos");
    int64_t utxo_max_height = fq_i64(db, "SELECT COALESCE(MAX(height),0) FROM utxos");
    int64_t block_rows = fq_i64(db, "SELECT count(*) FROM blocks");
    int64_t tx_rows = fq_i64(db, "SELECT count(*) FROM transactions");
    int64_t supply = compute_supply_at_height(chain_height);

    char supply_fmt[64], utxo_fmt[64], rcpt[32] = "";
    fmt_zcl(supply_fmt, sizeof(supply_fmt), supply);
    fmt_zcl(utxo_fmt, sizeof(utxo_fmt), utxo_value);
    compute_receipt_i64(rcpt, sizeof(rcpt), chain_height, supply,
                        "verified_factoids_summary");

    APPEND(off, r, max, EXPLORER_HEADER("ZClassic Factoids"));
    off += explorer_emit_nav((char *)r + off, max - off, "factoids");
    APPEND(off, r, max,
        "<div class='content'>"
        "<h1>ZClassic Factoids</h1>"
        "<div class='card' style='border-color:#775522'>"
        "<h2>Explorer history index rebuilding</h2>"
        "<p style='color:#bbb'>The block-history table failed sanity checks, "
        "so this page is intentionally not serving archaeology facts derived "
        "from that table. This prevents impossible timestamps, bogus records, "
        "and misleading receipts from being published as verified data.</p>"
        "<p style='color:#888'>Reason: <code>%s</code></p>"
        "<p style='color:#888'>Verified live explorer data is shown below. "
        "Block-history sections will return after the explorer block index is "
        "rebuilt from canonical block data.</p>"
        "</div>"
        "<h2>Verified Current State</h2>"
        "<table class='txlist'>"
        "<tr><th>Field</th><th>Value</th></tr>"
        "<tr><td>Current chain height</td><td>%" PRId64 "</td></tr>"
        "<tr><td>Highest UTXO height</td><td>%" PRId64 "</td></tr>"
        "<tr><td>Consensus supply at height</td><td>%s ZCL</td></tr>"
        "<tr><td>Transparent UTXOs</td><td>%" PRId64 "</td></tr>"
        "<tr><td>Transparent UTXO value</td><td>%s ZCL</td></tr>"
        "<tr><td>Block rows in explorer index</td><td>%" PRId64 "</td></tr>"
        "<tr><td>Transaction rows in explorer index</td><td>%" PRId64 "</td></tr>"
        "<tr><td>SHA3 receipt</td><td><code>%s</code></td></tr>"
        "</table>",
        degraded_reason ? degraded_reason : "unknown",
        chain_height, utxo_max_height, supply_fmt, utxo_count, utxo_fmt,
        block_rows, tx_rows, rcpt);

    APPEND(off, r, max,
        "<h2>Consensus Constants</h2>"
        "<table class='txlist'>"
        "<tr><th>Fact</th><th>Value</th></tr>"
        "<tr><td>Genesis hash</td><td><code style='word-break:break-all'>"
        ZCL_EXPLORER_GENESIS_HASH_DISPLAY_HEX
        "</code></td></tr>"
        "<tr><td>Genesis timestamp</td><td>2016-11-06 03:43:49 UTC</td></tr>"
        "<tr><td>Mainnet P2P port</td><td>8033</td></tr>"
        "<tr><td>Equihash parameters</td><td>N=200, K=9</td></tr>"
        "<tr><td>Buttercup activation height</td><td>707000</td></tr>"
        "</table>"
        "</div>" EXPLORER_FOOTER);
    return off;
}

/* ── Build the factoids page (HTML) ──────────────────────── */

size_t explorer_factoids_build(uint8_t *buf, size_t buf_max, const char *datadir)
{
    return explorer_factoids_build_for_served_tip(buf, buf_max, datadir, -1);
}

size_t explorer_factoids_build_for_served_tip(uint8_t *buf, size_t buf_max,
                                              const char *datadir,
                                              int64_t served_height)
{
    if (!buf || buf_max < 1024 || !datadir) return 0;

    sqlite3 *db = NULL;
    if (!explorer_open_readonly_db(datadir, &db)) {
        return 0;
    }

    struct explorer_chain_stats chain_stats = {0};
    explorer_query_chain_stats(db, &chain_stats);
    int64_t chain_height = chain_stats.height;
    if (served_height >= 0 && chain_height > served_height)
        chain_height = served_height;

    struct explorer_history_validation history;
    explorer_validate_block_history(db, chain_height, &history);
    if (!history.usable) {
        size_t len = explorer_factoids_build_verified_summary(
            buf, buf_max, db, chain_height, history.reason);
        sqlite3_close(db);
        return len;
    }

    size_t off = 0;
    char *r = (char *)buf;
    size_t max = buf_max;

    /* ── HTTP header + HTML head ──────────────────────────── */
    APPEND(off, r, max, EXPLORER_HEADER("ZClassic Historian Factoids"));
    off += explorer_emit_nav((char *)r + off, max - off, "factoids");
    APPEND(off, r, max,
        "<div class='content' id='top'>"
        "<h1>ZClassic Historian Factoids</h1>"
        "<p style='color:#999'>Deep chain archaeology with SHA3-256 data receipts. "
        "Two receipt formats in use: "
        "<code title='Milestone receipt: SHA3-256 over the little-endian 64-bit "
        "height, the big-endian block-hash hex, and the fact name. Recompute it "
        "from raw chain data to verify the fact.'>"
        "SHA3(height_le64 || block_hash_hex || fact_name)</code> for "
        "milestones (sections 1, 2, 4, 12), and "
        "<code title='Record receipt: SHA3-256 over two little-endian 64-bit "
        "values and a label. Recompute it from raw chain data to verify the "
        "summary.'>SHA3(val1_le64 || val2_le64 || label)</code> for record "
        "summaries (sections 5-7, 9-11, 13-16). First 16 hex chars shown. "
        "Section 17 chains a SHA3 over the last 100 blocks and shows the "
        "full 64-hex digest. Independently verifiable from raw chain data.</p>"
        "<p style='color:#999;font-size:0.85em'>Chain height: %" PRId64
        " | All timestamps UTC | All hashes big-endian display order</p>"
        "<nav class='toc' aria-label='Section navigation'>"
        "<h3>Jump to section</h3>"
        "<a href='#genesis'>1. Genesis</a>"
        "<a href='#upgrades'>2. Upgrades</a>"
        "<a href='#mining-eras'>3. Mining Eras</a>"
        "<a href='#milestones'>4. Milestones</a>"
        "<a href='#records'>5. Records</a>"
        "<a href='#supply'>6. Supply</a>"
        "<a href='#addresses'>7. Addresses</a>"
        "<a href='#privacy'>8. Privacy</a>"
        "<a href='#zslp'>9. ZSLP</a>"
        "<a href='#opreturn'>10. OP_RETURN</a>"
        "<a href='#dust'>11. UTXO</a>"
        "<a href='#checkpoints'>12. Checkpoints</a>"
        "<a href='#blocktimes'>13. Block Times</a>"
        "<a href='#transactions'>14. Transactions</a>"
        "<a href='#empty'>15. Empty Blocks</a>"
        "<a href='#difficulty'>16. Difficulty</a>"
        "<a href='#integrity'>17. Integrity</a>"
        "</nav>",
        chain_height);

    off = factoids_emit_section_1_genesis(buf, buf_max, off, db);
    off = factoids_emit_section_2_upgrades(buf, buf_max, off, db);
    off = factoids_emit_section_3_mining_eras(buf, buf_max, off, chain_height);
    off = factoids_emit_section_4_milestones(buf, buf_max, off, db, chain_height);
    off = factoids_emit_section_5_records(buf, buf_max, off, db);
    off = factoids_emit_section_6_supply(buf, buf_max, off, db, chain_height);
    off = factoids_emit_section_7_addresses(buf, buf_max, off, db);
    off = factoids_emit_section_8_privacy(buf, buf_max, off, db);
    off = factoids_emit_section_9_zslp(buf, buf_max, off, db);
    off = factoids_emit_section_10_opreturn(buf, buf_max, off, db);
    off = factoids_emit_section_11_dust(buf, buf_max, off, db);
    off = factoids_emit_section_12_checkpoints(buf, buf_max, off, db, chain_height);
    off = factoids_emit_section_13_blocktimes(buf, buf_max, off, db, chain_height);
    off = factoids_emit_section_14_transactions(buf, buf_max, off, db);
    off = factoids_emit_section_15_empty_blocks(buf, buf_max, off, db);
    off = factoids_emit_section_16_difficulty(buf, buf_max, off, db);
    off = factoids_emit_section_17_integrity(buf, buf_max, off, db, chain_height,
                                             chain_stats.blocks);

    /* ── Floating back-to-top control (top TOC handles jump-nav) ── */
    APPEND(off, r, max,
        "<a href='#top' class='back-to-top' aria-label='Back to top'>&uarr; Top</a>");

    /* ── Close page ───────────────────────────────────────── */
    APPEND(off, r, max, "</div>" EXPLORER_FOOTER);

    sqlite3_close(db);

    printf("Factoids: built %zu bytes, 17 sections\n", off);
    fflush(stdout);
    return off;
}

/* ================================================================
 * JSON API: /api/factoids
 * ================================================================ */

size_t explorer_factoids_build_json(uint8_t *buf, size_t buf_max,
                                     const char *datadir)
{
    return explorer_factoids_build_json_for_served_tip(buf, buf_max, datadir,
                                                       -1);
}

size_t explorer_factoids_build_json_for_served_tip(uint8_t *buf,
                                                   size_t buf_max,
                                                   const char *datadir,
                                                   int64_t served_height)
{
    if (!buf || buf_max < 512 || !datadir) return 0;

    sqlite3 *db = NULL;
    if (!explorer_open_readonly_db(datadir, &db)) {
        return 0;
    }

    struct explorer_chain_stats chain_stats = {0};
    explorer_query_chain_stats(db, &chain_stats);
    int64_t indexed_height = chain_stats.height;
    int64_t utxo_tip = fq_i64(db, "SELECT COALESCE(MAX(height),0) FROM utxos");
    if (utxo_tip > indexed_height)
        indexed_height = utxo_tip;
    int64_t chain_height = indexed_height;
    bool index_capped = false;
    if (served_height >= 0 && indexed_height > served_height) {
        chain_height = served_height;
        index_capped = true;
    } else if (served_height < 0) {
        served_height = chain_height;
    }

    size_t off = 0;
    char *r = (char *)buf;
    size_t max = buf_max;

    APPEND(off, r, max,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: engine/application/json; charset=utf-8\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n");

    struct explorer_history_validation history;
    explorer_validate_block_history(db, chain_height, &history);
    if (!history.usable) {
        int64_t block_rows = fq_i64(db, "SELECT count(*) FROM blocks");
        int64_t tx_rows = fq_i64(db, "SELECT count(*) FROM transactions");
        int64_t utxo_count = fq_i64(db, "SELECT count(*) FROM utxos");
        int64_t utxo_value = fq_i64(db, "SELECT COALESCE(SUM(value),0) FROM utxos");
        int64_t supply = compute_supply_at_height(chain_height);
        APPEND(off, r, max,
            "{\"history_index_usable\":false,"
            "\"unsafe_sections_suppressed\":true,"
            "\"reason\":\"%s\","
            "\"chain_height\":%" PRId64 ","
            "\"served_height\":%" PRId64 ","
            "\"indexed_height\":%" PRId64 ","
            "\"index_capped\":%s,"
            "\"supply\":{\"total_sat\":%" PRId64 ",\"total_zcl\":%.8f},"
            "\"utxo\":{\"count\":%" PRId64 ",\"value_sat\":%" PRId64 ",\"value_zcl\":%.8f},"
            "\"index\":{\"blocks\":%" PRId64 ",\"transactions\":%" PRId64 "},"
            "\"consensus\":{\"genesis_hash\":\"%s\","
            "\"genesis_time\":%" PRId64 ",\"mainnet_port\":8033,\"buttercup_height\":707000}}",
            history.reason, chain_height,
            served_height, indexed_height, index_capped ? "true" : "false",
            supply, (double)supply / (double)ZATOSHI_PER_ZCL,
            utxo_count, utxo_value, (double)utxo_value / (double)ZATOSHI_PER_ZCL,
            block_rows, tx_rows, ZCL_EXPLORER_GENESIS_HASH_DISPLAY_HEX,
            (int64_t)ZCL_EXPLORER_GENESIS_TIME);
        sqlite3_close(db);
        return off;
    }

    struct explorer_token_stats token_stats = {0};
    explorer_query_token_stats(db, &token_stats);

    APPEND(off, r, max,
        "{\"chain_height\":%" PRId64
        ",\"served_height\":%" PRId64
        ",\"indexed_height\":%" PRId64
        ",\"index_capped\":%s",
        chain_height, served_height, indexed_height,
        index_capped ? "true" : "false");

    /* Genesis — height 0 may not be in SQLite, use constants as fallback */
    {
        char gh[128] = ZCL_EXPLORER_GENESIS_HASH_DISPLAY_HEX, gc[128] = "";
        fq_text(db, "SELECT hex(txid) FROM transactions WHERE block_height = 0 AND is_coinbase = 1 LIMIT 1",
                gc, sizeof(gc));
        if (!gc[0]) snprintf(gc, sizeof(gc),
            "427DBF0AE8E079C6527EA1CB308C6E3C98FA5435F4D715D31176EA00CF2B6119");
        char rcpt[32] = "";
        compute_receipt(rcpt, sizeof(rcpt), 0, gh, "Genesis");
        APPEND(off, r, max,
            ",\"genesis\":{\"hash\":\"%.64s\",\"timestamp\":%" PRId64 ","
            "\"coinbase_txid\":\"%.64s\",\"sha3\":\"%s\"}",
            gh, (int64_t)ZCL_EXPLORER_GENESIS_TIME, gc, rcpt);
    }

    /* Network upgrades */
    APPEND(off, r, max, ",\"upgrades\":[");
    {
        struct { const char *name; int64_t h; int proto; const char *bid; } ups[] = {
            {"Sprout",0,170002,"0x00000000"},
            {"Overwinter",476969,170005,"0x5ba81b19"},
            {"Sapling",476969,170007,"0x76b809bb"},
            {"Bubbles",585318,170009,"0x821a451c"},
            {"Bubbly",585322,170010,"0x930b540d"},
            {"Buttercup",707000,170011,"0x930b540d"},
        };
        for (int i = 0; i < 6; i++) {
            char bh[128] = ""; int64_t bt = 0;
            get_block_at(db, ups[i].h, bh, sizeof(bh), &bt);
            char rcpt[32] = "";
            compute_receipt(rcpt, sizeof(rcpt), ups[i].h, bh, ups[i].name);
            if (i > 0) APPEND(off, r, max, ",");
            APPEND(off, r, max,
                "{\"name\":\"%s\",\"height\":%" PRId64 ",\"time\":%" PRId64
                ",\"protocol\":%d,\"branch_id\":\"%s\",\"sha3\":\"%s\"}",
                ups[i].name, ups[i].h, bt, ups[i].proto, ups[i].bid, rcpt);
        }
    }
    APPEND(off, r, max, "]");

    /* Supply — mined-at-tip, asymptotic cap, transparent UTXO pool, and the
     * mined-minus-transparent gap (the only reliable shielded+burned proxy;
     * blocks.sapling_value is sign-buggy, so we never SUM it). Mirrors the
     * headline HTML supply factoids so /api/factoids stays in sync. */
    {
        int64_t supply = compute_supply_at_height(chain_height);
        int64_t cap = zcl_max_supply_zatoshi();
        int64_t transparent_pool =
            fq_i64(db, "SELECT COALESCE(SUM(value),0) FROM utxos");
        int64_t gap = supply - transparent_pool;
        double pct_of_cap = cap > 0 ? 100.0 * (double)supply / (double)cap : 0.0;
        char rcpt[32] = "", gap_rcpt[32] = "";
        compute_receipt_i64(rcpt, sizeof(rcpt), chain_height, supply, "total_supply");
        compute_receipt_i64(gap_rcpt, sizeof(gap_rcpt), chain_height, gap, "supply_gap");
        APPEND(off, r, max,
            ",\"supply\":{\"total_sat\":%" PRId64 ",\"total_zcl\":%.8f,\"sha3\":\"%s\""
            ",\"mined_sat\":%" PRId64 ",\"mined_zcl\":%.8f"
            ",\"cap_sat\":%" PRId64 ",\"cap_zcl\":%.8f,\"pct_of_cap\":%.3f"
            ",\"transparent_pool_sat\":%" PRId64 ",\"transparent_pool_zcl\":%.8f"
            ",\"gap_sat\":%" PRId64 ",\"gap_zcl\":%.8f,\"gap_sha3\":\"%s\"}",
            supply, (double)supply / (double)ZATOSHI_PER_ZCL, rcpt,
            supply, (double)supply / (double)ZATOSHI_PER_ZCL,
            cap, (double)cap / (double)ZATOSHI_PER_ZCL, pct_of_cap,
            transparent_pool, (double)transparent_pool / (double)ZATOSHI_PER_ZCL,
            gap, (double)gap / (double)ZATOSHI_PER_ZCL, gap_rcpt);
    }

    /* Address stats */
    {
        struct explorer_address_stats address_stats = {0};
        explorer_query_address_stats(db, &address_stats);
        APPEND(off, r, max,
            ",\"addresses\":{\"total\":%" PRId64 ",\"nonzero\":%" PRId64 "}",
            address_stats.total, address_stats.nonzero);
    }

    /* Privacy stats — plus the last on-chain Sprout JoinSplit height
     * (Sprout effectively retired; ~2,124,937 today). Read live from the
     * joinsplits projection so it self-corrects if a later one ever appears. */
    {
        struct explorer_privacy_stats privacy_stats = {0};
        explorer_query_privacy_stats(db, &privacy_stats);
        int64_t last_sprout_js = fq_i64(db,
            "SELECT COALESCE(MAX(block_height),0) FROM joinsplits");
        APPEND(off, r, max,
            ",\"privacy\":{\"joinsplits\":%" PRId64 ",\"sapling_spends\":%" PRId64
            ",\"sapling_outputs\":%" PRId64 ",\"net_shielded_sat\":%" PRId64
            ",\"last_sprout_joinsplit_height\":%" PRId64 "}",
            privacy_stats.joinsplits, privacy_stats.sapling_spends,
            privacy_stats.sapling_outputs, privacy_stats.net_shielded_sat,
            last_sprout_js);
    }

    /* ZSLP */
    {
        APPEND(off, r, max,
            ",\"zslp\":{\"tokens\":%" PRId64 ",\"transfers\":%" PRId64 "}",
            token_stats.token_count, token_stats.transfer_count);
    }

    /* UTXO stats */
    {
        struct explorer_utxo_stats utxo_stats = {0};
        explorer_query_utxo_stats(db, &utxo_stats);
        APPEND(off, r, max,
            ",\"utxo\":{\"count\":%" PRId64 ",\"dust_under_0001\":%" PRId64
            ",\"total_value_sat\":%" PRId64 "}",
            utxo_stats.count, utxo_stats.dust_under_0001,
            utxo_stats.total_value_sat);
    }

    /* OP_RETURN stats */
    {
        struct explorer_op_return_stats op_return_stats = {0};
        explorer_query_op_return_stats(db, &op_return_stats);
        APPEND(off, r, max,
            ",\"op_returns\":{\"total\":%" PRId64 ",\"zslp\":%" PRId64
            ",\"other\":%" PRId64 "}",
            op_return_stats.total, op_return_stats.zslp,
            op_return_stats.total - op_return_stats.zslp);
    }

    /* Transaction stats */
    {
        struct explorer_transaction_stats transaction_stats = {0};
        explorer_query_transaction_stats(db, &transaction_stats);
        APPEND(off, r, max,
            ",\"transactions\":{\"total\":%" PRId64 ",\"coinbase\":%" PRId64
            ",\"inputs\":%" PRId64 ",\"outputs\":%" PRId64
            ",\"empty_blocks\":%" PRId64 "}",
            transaction_stats.total, transaction_stats.coinbase,
            transaction_stats.inputs, transaction_stats.outputs,
            transaction_stats.empty_blocks);
    }

    /* Integrity hash */
    {
        char ih[128] = "";
        compute_integrity_hash(db, chain_height, ih, sizeof(ih));
        APPEND(off, r, max,
            ",\"integrity\":{\"blocks\":%" PRId64 ",\"hash\":\"%s\"}", chain_height, ih);
    }

    APPEND(off, r, max, "}");

    sqlite3_close(db);
    return off;
}
