/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer factoids VIEW — chain-structure sections (1-4 and 6).
 *
 * Owns Genesis Story, Network Upgrade History, Mining Era Analysis, Network
 * Milestones, and Supply Milestones. All-Time Records and Address Statistics
 * have their own private section renderers; activity, archaeology, and
 * integrity sections live in sibling factoids TUs. */

#include "views/explorer_factoids_internal.h"

/* Current per-block coinbase subsidy in zatoshi at `height`, mirroring the
 * schedule in zcl_total_supply_zatoshi() (pre-Buttercup 12.5 ZCL; post-
 * Buttercup post_base >> (era+3), era = (h-1-707000)/1,680,000). Display-only,
 * consensus-neutral — derives the number so the supply prose cannot go stale
 * across a halving. */
static int64_t current_block_subsidy_sat(int64_t height)
{
    if (height < 1) return 0;
    if (height < BUTTERCUP_ACTIVATION_HEIGHT) return BASE_SUBSIDY_SAT; /* 12.5 ZCL */
    int64_t post_base = BASE_SUBSIDY_SAT / 2; /* 625,000,000 zat (spacing ratio 2) */
    int era = (int)((height - 1 - BUTTERCUP_ACTIVATION_HEIGHT) / POST_BC_HALVING);
    int shift = era + 3;
    if (shift >= 63) return 0;
    return post_base >> shift;
}

size_t factoids_emit_section_1_genesis(uint8_t *buf, size_t cap, size_t off,
                                       sqlite3 *db)
{
    char *r = (char *)buf;
    size_t max = cap;

    APPEND(off, r, max,
        "<h2 id='genesis'>1. Genesis Story</h2>");

    int64_t genesis_time = ZCL_EXPLORER_GENESIS_TIME;

    /* Genesis (height 0) is not in the SQLite index — use known constants */
    char genesis_hash[128] =
        ZCL_EXPLORER_GENESIS_HASH_DISPLAY_HEX;
    char genesis_coinbase[128] = "";
    /* Try DB first, fall back to constant */
    fq_text(db, "SELECT hex(hash) FROM blocks WHERE height = 0",
            genesis_hash, sizeof(genesis_hash));
    if (!genesis_hash[0])
        snprintf(genesis_hash, sizeof(genesis_hash),
            ZCL_EXPLORER_GENESIS_HASH_DISPLAY_HEX);
    fq_text(db, "SELECT hex(txid) FROM transactions WHERE block_height = 0 AND is_coinbase = 1 LIMIT 1",
            genesis_coinbase, sizeof(genesis_coinbase));
    if (!genesis_coinbase[0])
        snprintf(genesis_coinbase, sizeof(genesis_coinbase),
            "427DBF0AE8E079C6527EA1CB308C6E3C98FA5435F4D715D31176EA00CF2B6119");

    char tstr[64];
    fmt_time(tstr, sizeof(tstr), genesis_time);

    char gen_receipt[32] = "";
    compute_receipt(gen_receipt, sizeof(gen_receipt), 0, genesis_hash, "Genesis");

    APPEND(off, r, max,
        "<div class='card'>"
        "<h3>Block 0: The Beginning</h3>"
        "<p style='color:#888'>ZClassic launched on November 6, 2016 as a fork of Zcash "
        "with no founder's reward tax and the same Equihash (200,9) proof-of-work. "
        "Community-driven from day one.</p>"
        "<table>"
        "<tr><td><b>Genesis Hash</b></td><td><code style='word-break:break-all'>"
        "<a href='/explorer/block/0'>%.64s</a></code></td></tr>"
        "<tr><td><b>Timestamp</b></td><td>%s (Unix: 1478403829)</td></tr>"
        "<tr><td><b>Genesis Coinbase</b></td><td><code style='word-break:break-all'>"
        "<a href='/explorer/tx/%.64s'>%.16s...</a></code></td></tr>"
        "<tr><td><b>Message Start</b></td><td><code>0x24 0xe9 0x27 0x64</code></td></tr>"
        "<tr><td><b>Default Port</b></td><td>8033 (mainnet), 18033 (testnet)</td></tr>"
        "<tr><td><b>BIP44 Coin Type</b></td><td>147</td></tr>"
        "<tr><td><b>Address Prefix (t1)</b></td><td><code>0x1C 0xB8</code></td></tr>"
        "<tr><td><b>Equihash Params</b></td><td>N=200, K=9 (memory-hard, ASIC-resistant) "
        "for blocks 0\xe2\x80\x93" "585,317 (1344-byte solution). The Bubbles upgrade at "
        "block 585,318 switches to N=192, K=7 (400-byte solution).</td></tr>"
        "<tr><td><b>PoW Limit</b></td><td><code>0x0007ffff...fff</code></td></tr>"
        "<tr><td><b>SHA3 Receipt</b></td><td><code>%s</code></td></tr>"
        "</table></div>",
        genesis_hash, tstr, genesis_coinbase, genesis_coinbase, gen_receipt);

    /* First 10 blocks table */
    APPEND(off, r, max,
        "<h3>First 10 Blocks</h3>"
        "<table class='txlist'>"
        "<tr><th>Height</th><th>Time</th><th>Block Hash</th><th>SHA3 Receipt</th></tr>");

    /* Genesis (height 0) is not in SQLite — add manually */
    {
        char rcpt0[32] = "";
        compute_receipt(rcpt0, sizeof(rcpt0), 0, genesis_hash, "first10");
        APPEND(off, r, max,
            "<tr><td><a href='/explorer/block/0'>0</a></td>"
            "<td>2016-11-06 03:43:49 UTC</td>"
            "<td><code style='word-break:break-all'>%.16s...</code></td>"
            "<td><code>%s</code></td></tr>",
            genesis_hash, rcpt0);
    }
    {
        sqlite3_stmt *s = NULL;
        const char *sql = "SELECT height, time, hex(hash) FROM blocks WHERE height >= 1 AND height < 10 ORDER BY height";
        if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                int64_t h = sqlite3_column_int64(s, 0);
                int64_t t = sqlite3_column_int64(s, 1);
                const char *hash = (const char *)sqlite3_column_text(s, 2);
                char ts[64], rcpt[32] = "";
                fmt_time(ts, sizeof(ts), t);
                compute_receipt(rcpt, sizeof(rcpt), h, hash ? hash : "", "first10");
                APPEND(off, r, max,
                    "<tr><td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>"
                    "<td>%s</td>"
                    "<td><code style='word-break:break-all'>%.16s...</code></td>"
                    "<td><code>%s</code></td></tr>",
                    h, h, ts, hash ? hash : "?", rcpt);
            }
            sqlite3_finalize(s);
        }
    }
    APPEND(off, r, max, "</table>");
    return off;
}

size_t factoids_emit_section_2_upgrades(uint8_t *buf, size_t cap, size_t off,
                                        sqlite3 *db)
{
    char *r = (char *)buf;
    size_t max = cap;

    APPEND(off, r, max,
        "<h2 id='upgrades'>2. Network Upgrade History</h2>"
        "<p style='color:#888'>Every consensus upgrade with activation height, "
        "protocol version, branch ID, and purpose. Each secured with SHA3 receipt.</p>"
        "<table class='txlist'>"
        "<tr><th>Upgrade</th><th>Height</th><th>Date</th>"
        "<th>Proto</th><th>Branch ID</th><th>Purpose</th><th>SHA3</th></tr>");

    struct {
        const char *name;
        int64_t height;
        int proto;
        const char *branch_id;
        const char *purpose;
    } upgrades[] = {
        { "Sprout (Base)", 0, 170002, "0x00000000",
          "Initial ZClassic network launch" },
        { "Overwinter", OVERWINTER_ACTIVATION_HEIGHT, 170005, "0x5ba81b19",
          "Transaction format v3, replay protection, expiry" },
        { "Sapling", SAPLING_ACTIVATION_HEIGHT, 170007, "0x76b809bb",
          "Shielded transactions (Groth16 proofs, 100x faster)" },
        { "Bubbles", BUBBLES_ACTIVATION_HEIGHT, 170009, "0x821a451c",
          "ZClassic-specific protocol enhancements" },
        /* Bubbly intentionally shares branch ID 0x930b540d with Buttercup
         * in consensus (lib/consensus/src/upgrades.c:16-17) — Buttercup
         * did not change transaction-binding format, so it reuses Bubbly's
         * branch ID. The duplicate is correct. */
        { "Bubbly (DiffAdj)", BUBBLY_ACTIVATION_HEIGHT, 170010, "0x930b540d",
          "Difficulty adjustment algorithm refinement" },
        { "Buttercup", BUTTERCUP_ACTIVATION_HEIGHT, 170011, "0x930b540d",
          "Block time 150s\xe2\x86\x92" "75s, halving doubled, subsidy adjusted" },
    };
    int n_upgrades = (int)(sizeof(upgrades) / sizeof(upgrades[0]));

    for (int i = 0; i < n_upgrades; i++) {
        char bhash[128] = "";
        int64_t btime = 0;
        get_block_at(db, upgrades[i].height, bhash, sizeof(bhash), &btime);

        char ts[64], rcpt[32] = "";
        fmt_time(ts, sizeof(ts), btime);
        compute_receipt(rcpt, sizeof(rcpt), upgrades[i].height, bhash, upgrades[i].name);

        if (btime > 0 || upgrades[i].height == 0) {
            APPEND(off, r, max,
                "<tr><td><b>%s</b></td>"
                "<td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>"
                "<td>%s</td><td>%d</td><td><code>%s</code></td>"
                "<td>%s</td><td><code>%s</code></td></tr>",
                upgrades[i].name, upgrades[i].height, upgrades[i].height,
                ts, upgrades[i].proto, upgrades[i].branch_id,
                upgrades[i].purpose, rcpt);
        } else {
            APPEND(off, r, max,
                "<tr><td><b>%s</b></td>"
                "<td>%" PRId64 "</td>"
                "<td style='color:#666'>Not yet reached</td>"
                "<td>%d</td><td><code>%s</code></td>"
                "<td>%s</td><td><code>--</code></td></tr>",
                upgrades[i].name, upgrades[i].height,
                upgrades[i].proto, upgrades[i].branch_id,
                upgrades[i].purpose);
        }
    }
    APPEND(off, r, max, "</table>");
    return off;
}

size_t factoids_emit_section_3_mining_eras(uint8_t *buf, size_t cap, size_t off,
                                           int64_t chain_height)
{
    char *r = (char *)buf;
    size_t max = cap;

    APPEND(off, r, max,
        "<h2 id='mining-eras'>3. Mining Era Analysis</h2>"
        "<p style='color:#888'>Block reward schedule showing the Buttercup transition "
        "at block 707,000 which halved block time and shifted the halving schedule.</p>"
        "<table class='txlist'>"
        "<tr><th>Era</th><th>Block Range</th><th>Subsidy/Block</th>"
        "<th>Target Spacing</th><th>Blocks</th><th>Total Emission</th><th>SHA3</th></tr>");

    /* Pre-Buttercup eras */
    {
        int64_t era_start = 0;
        int64_t pre_bc_end = chain_height < BUTTERCUP_ACTIVATION_HEIGHT
                           ? chain_height : BUTTERCUP_ACTIVATION_HEIGHT;
        int era_num = 0;
        int64_t subsidy = BASE_SUBSIDY_SAT;

        while (era_start < pre_bc_end && subsidy > 0 && era_num < 10) {
            int64_t next = ((era_start / PRE_BC_HALVING) + 1) * PRE_BC_HALVING;
            int64_t end = next < pre_bc_end ? next : pre_bc_end;
            int64_t count = end - era_start;

            char sub_str[64], emit_str[64], rcpt[32] = "";
            fmt_zcl(sub_str, sizeof(sub_str), subsidy);
            /* Genesis (block 0) has zero subsidy (slow-start), so the first
             * pre-BC era earns over (count - 1) blocks. Without this the era
             * emission over-counts by one full subsidy (e.g. 707000*12.5 vs
             * the correct 706999*12.5 = 8,837,487.5 ZCL pre-BC max). The
             * "0 - 706999" range label is unchanged. */
            int64_t emission = (count - (era_start == 0 ? 1 : 0)) * subsidy;
            fmt_zcl(emit_str, sizeof(emit_str), emission);
            char blk_str[32];
            fmt_comma(blk_str, sizeof(blk_str), count);
            compute_receipt_i64(rcpt, sizeof(rcpt), era_start, end, "mining_era");

            APPEND(off, r, max,
                "<tr><td>Pre-BC #%d</td>"
                "<td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a>"
                " \xe2\x80\x93 <a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>"
                "<td>%s ZCL</td><td>150s</td><td>%s</td><td>%s ZCL</td>"
                "<td><code>%s</code></td></tr>",
                era_num, era_start, era_start, end - 1, end - 1,
                sub_str, blk_str, emit_str, rcpt);

            era_start = end;
            era_num++;
            int halvings = (int)(era_start / PRE_BC_HALVING);
            subsidy = (halvings >= 64) ? 0 : (BASE_SUBSIDY_SAT >> halvings);
        }
    }

    /* Post-Buttercup eras */
    if (chain_height > BUTTERCUP_ACTIVATION_HEIGHT) {
        int64_t era_offset = 0;
        int64_t remaining = chain_height - BUTTERCUP_ACTIVATION_HEIGHT;
        int64_t bc_base = BASE_SUBSIDY_SAT / 2;  /* 6.25 ZCL */
        int era_num = 0;

        while (remaining > 0 && era_num < 10) {
            int halvings_raw = (era_offset > 0)
                ? (int)((era_offset - 1) / POST_BC_HALVING) : 0;
            int halvings = halvings_raw + 3;
            if (halvings >= 64) break;
            int64_t era_subsidy = bc_base >> halvings;
            if (era_subsidy <= 0) break;

            int64_t next_boundary = ((int64_t)(halvings_raw + 1)) * POST_BC_HALVING + 1;
            int64_t blocks_in_era = next_boundary - era_offset;
            if (blocks_in_era > remaining) blocks_in_era = remaining;

            int64_t abs_start = BUTTERCUP_ACTIVATION_HEIGHT + era_offset;
            int64_t abs_end = abs_start + blocks_in_era;

            char sub_str[64], emit_str[64], rcpt[32] = "";
            fmt_zcl(sub_str, sizeof(sub_str), era_subsidy);
            int64_t emission = blocks_in_era * era_subsidy;
            fmt_zcl(emit_str, sizeof(emit_str), emission);
            char blk_str[32];
            fmt_comma(blk_str, sizeof(blk_str), blocks_in_era);
            compute_receipt_i64(rcpt, sizeof(rcpt), abs_start, abs_end, "mining_era_bc");

            APPEND(off, r, max,
                "<tr><td>Post-BC #%d (halv=%d)</td>"
                "<td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a>"
                " \xe2\x80\x93 <a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>"
                "<td>%s ZCL</td><td>75s</td><td>%s</td><td>%s ZCL</td>"
                "<td><code>%s</code></td></tr>",
                era_num, halvings, abs_start, abs_start, abs_end - 1, abs_end - 1,
                sub_str, blk_str, emit_str, rcpt);

            remaining -= blocks_in_era;
            era_offset += blocks_in_era;
            era_num++;
        }
    }

    /* Total supply row */
    {
        int64_t total_supply = compute_supply_at_height(chain_height);
        char total_str[64], rcpt[32] = "";
        fmt_zcl(total_str, sizeof(total_str), total_supply);
        compute_receipt_i64(rcpt, sizeof(rcpt), chain_height, total_supply, "total_supply");
        APPEND(off, r, max,
            "<tr style='border-top:2px solid #33ff99'>"
            "<td colspan='4'><b>Total Mined Supply</b></td>"
            "<td></td><td><b>%s ZCL</b></td>"
            "<td><code>%s</code></td></tr>",
            total_str, rcpt);
    }
    APPEND(off, r, max, "</table>");

    /* Proof-of-Work parameter eras. The Equihash (N,K) pair changed exactly
     * once — at the Bubbles upgrade (block 585,318) — which is observable in
     * the chain as the block solution field dropping from 1344 to 400 bytes.
     * Both byte sizes are consensus-immutable constants of the respective
     * Equihash parameters, so they are inlined (not a growing scalar). */
    {
        char rcpt[32] = "";
        compute_receipt_i64(rcpt, sizeof(rcpt),
                            BUBBLES_ACTIVATION_HEIGHT, 400, "equihash_param_era");
        APPEND(off, r, max,
            "<div class='card'>"
            "<h3>Proof-of-Work Parameter Eras</h3>"
            "<p style='color:#888'>ZClassic's Equihash parameters changed once, "
            "at the Bubbles upgrade (block 585,318). The switch is visible on-chain "
            "as the per-block solution field shrinking from 1344 to 400 bytes.</p>"
            "<table class='txlist'>"
            "<tr><th>Era</th><th>Block Range</th><th>Equihash (N,K)</th>"
            "<th>Solution Size</th></tr>"
            "<tr><td>Genesis \xe2\x80\x93 Bubbles</td>"
            "<td><a href='/explorer/block/0'>0</a> \xe2\x80\x93 "
            "<a href='/explorer/block/585317'>585,317</a></td>"
            "<td>N=200, K=9</td>"
            "<td>1344 bytes (2^9 indices \xc3\x97 21 bits)</td></tr>"
            "<tr><td>Bubbles \xe2\x80\x93 tip</td>"
            "<td><a href='/explorer/block/585318'>585,318</a> \xe2\x80\x93 present</td>"
            "<td>N=192, K=7</td>"
            "<td>400 bytes (2^7 indices \xc3\x97 25 bits)</td></tr>"
            "</table>"
            "<p style='color:#888'><b>SHA3 Receipt:</b> <code>%s</code></p>"
            "</div>",
            rcpt);
    }
    return off;
}
size_t factoids_emit_section_4_milestones(uint8_t *buf, size_t cap, size_t off,
                                          sqlite3 *db, int64_t chain_height)
{
    char *r = (char *)buf;
    size_t max = cap;

    APPEND(off, r, max,
        "<h2 id='milestones'>4. Network Milestones</h2>"
        "<p style='color:#888'>Key firsts in the chain's history.</p>"
        "<table class='txlist'>"
        "<tr><th>Milestone</th><th>Block</th><th>Time</th><th>SHA3 Receipt</th></tr>");

    struct milestone {
        const char *name;
        const char *sql;
        int64_t fixed_height;
        int64_t known_height;  /* authoritative fallback when SQL table is empty */
    };

    /* known_height values are immutable blockchain facts; the sapling/
     * op_return firsts are verified against the live node index
     * (MIN(block_height) of sapling_spends/sapling_outputs/op_returns).
     * They serve as fallbacks when
     * Phase B indexing tables (joinsplits, sapling_spends, sapling_outputs,
     * op_returns) haven't been populated yet. */
    struct milestone milestones[] = {
        { "Genesis (Nov 6, 2016)", NULL, 0, -1 },
        { "First non-coinbase tx",
          "SELECT MIN(block_height) FROM transactions WHERE is_coinbase = 0", -1, -1 },
        { "First Sprout JoinSplit",
          "SELECT MIN(block_height) FROM joinsplits", -1, 241 },
        { "Overwinter + Sapling activation", NULL,
          OVERWINTER_ACTIVATION_HEIGHT, -1 },
        { "First Sapling shielded spend",
          "SELECT MIN(block_height) FROM sapling_spends", -1, 476978 },
        { "First Sapling shielded output",
          "SELECT MIN(block_height) FROM sapling_outputs", -1, 476977 },
        { "First OP_RETURN",
          "SELECT MIN(block_height) FROM op_returns", -1, 375159 },
        { "Bubbles upgrade activation", NULL,
          BUBBLES_ACTIVATION_HEIGHT, -1 },
        { "Bubbly activation (DiffAdj)", NULL,
          BUBBLY_ACTIVATION_HEIGHT, -1 },
        { "First ZSLP token genesis",
          "SELECT MIN(genesis_height) FROM zslp_tokens", -1, -1 },
        { "Buttercup activation (75s blocks)", NULL,
          BUTTERCUP_ACTIVATION_HEIGHT, -1 },
        /* The pre-Buttercup halving at height 840000 never fired —
         * Buttercup activated at 707000 first and rolled the schedule
         * into the post-BC era. The previous "First halving (pre-
         * Buttercup)" milestone row was removed because it would
         * permanently render "Not yet reached." */
        { "Block 1,000,000", NULL, 1000000, -1 },
        { "Block 2,000,000", NULL, 2000000, -1 },
        /* Last on-chain Sprout JoinSplit (h=2,124,937, 2023-10-07): the
         * legacy Sprout shielded pool falls out of use. Data-derived
         * (MAX block_height over joinsplits), so no consensus assumption. */
        { "Last Sprout JoinSplit (old shielded pool retires)",
          "SELECT MAX(block_height) FROM joinsplits", -1, 2124937 },
        { "Block 3,000,000", NULL, 3000000, -1 },
    };

    int n_milestones = (int)(sizeof(milestones) / sizeof(milestones[0]));
    for (int i = 0; i < n_milestones; i++) {
        int64_t height = milestones[i].fixed_height;
        if (milestones[i].sql)
            height = fq_i64(db, milestones[i].sql);

        /* If SQL returned nothing (table empty), fall back to known height */
        if (height <= 0 && milestones[i].known_height > 0)
            height = milestones[i].known_height;

        if (height <= 0 && i > 0) {
            /* Distinguish "not yet reached" from "index not yet built" —
             * if chain is past Sapling activation and a table is empty,
             * the data exists on-chain but hasn't been indexed yet. */
            bool index_pending = (milestones[i].sql != NULL &&
                                  chain_height > 500000);
            APPEND(off, r, max,
                "<tr><td>%s</td><td colspan='3' style='color:#666'>%s</td></tr>",
                milestones[i].name,
                index_pending ? "Pending index rebuild" : "Not yet reached");
            continue;
        }
        if (height > chain_height && milestones[i].fixed_height >= 0) {
            APPEND(off, r, max,
                "<tr><td>%s</td>"
                "<td>%" PRId64 "</td>"
                "<td style='color:#666'>Not yet reached</td>"
                "<td><code>--</code></td></tr>",
                milestones[i].name, height);
            continue;
        }

        char bhash[128] = "";
        int64_t btime = 0;
        get_block_at(db, height, bhash, sizeof(bhash), &btime);

        char receipt[32] = "", ts[64];
        compute_receipt(receipt, sizeof(receipt), height, bhash, milestones[i].name);
        fmt_time(ts, sizeof(ts), btime);

        APPEND(off, r, max,
            "<tr><td>%s</td>"
            "<td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>"
            "<td>%s</td>"
            "<td><code>%s</code></td></tr>",
            milestones[i].name, height, height, ts, receipt);
    }
    APPEND(off, r, max, "</table>");
    return off;
}

size_t factoids_emit_section_6_supply(uint8_t *buf, size_t cap, size_t off,
                                      sqlite3 *db, int64_t chain_height)
{
    char *r = (char *)buf;
    size_t max = cap;

    char cur_sub_str[64];
    fmt_zcl(cur_sub_str, sizeof(cur_sub_str),
            current_block_subsidy_sat(chain_height));

    APPEND(off, r, max,
        "<h2 id='supply'>6. Supply Milestones</h2>"
        "<p style='color:#888'>Buttercup-aware emission: pre-707,000 at 12.5 ZCL/block; "
        "post-707,000 the subsidy halves every 1,680,000 blocks (6.25 &gt;&gt; (era+3)). "
        "Current block subsidy: <b>%s ZCL</b> (derived from the live tip, so it "
        "tracks each halving). ZClassic has no founders/dev tax \xe2\x80\x94 the "
        "entire coinbase goes to the miner.</p>"
        "<table class='txlist'>"
        "<tr><th>Milestone</th><th>Block</th><th>Date</th><th>SHA3</th></tr>",
        cur_sub_str);

    /* Find block heights where supply reaches milestones via binary search */
    struct { const char *label; int64_t target_sat; } supply_milestones[] = {
        { "1,000,000 ZCL mined",  ZATOSHI_PER_ZCL * 1000000LL },
        { "5,000,000 ZCL mined",  ZATOSHI_PER_ZCL * 5000000LL },
        /* Pre-Buttercup max: last pre-BC block is BUTTERCUP_ACTIVATION_HEIGHT-1
         * (= 706999), genesis (h=0) has zero subsidy in zcl_total_supply, so
         * the pre-BC supply is 706999 * 12.5 = 8,837,487.5 ZCL. */
        { "8,837,487.5 ZCL (pre-Buttercup max)",
          (BUTTERCUP_ACTIVATION_HEIGHT - 1) * BASE_SUBSIDY_SAT },
        { "10,000,000 ZCL mined", ZATOSHI_PER_ZCL * 10000000LL },
        { "10,500,000 ZCL mined", ZATOSHI_PER_ZCL * 10500000LL },
    };

    for (int i = 0; i < (int)(sizeof(supply_milestones)/sizeof(supply_milestones[0])); i++) {
        int64_t target = supply_milestones[i].target_sat;

        /* Binary search for the height where supply >= target */
        int64_t lo = 0, hi = 100000000LL; /* 100M blocks max */
        if (hi > chain_height + 50000000LL) hi = chain_height + 50000000LL;
        int64_t milestone_height = -1;

        while (lo <= hi) {
            int64_t mid = lo + (hi - lo) / 2;
            int64_t supply = compute_supply_at_height(mid);
            if (supply >= target) {
                milestone_height = mid;
                hi = mid - 1;
            } else {
                lo = mid + 1;
            }
        }

        if (milestone_height < 0 || milestone_height > 100000000LL) {
            APPEND(off, r, max,
                "<tr><td>%s</td><td colspan='3' style='color:#666'>Beyond max supply</td></tr>",
                supply_milestones[i].label);
            continue;
        }

        char bhash[128] = "";
        int64_t btime = 0;
        if (milestone_height <= chain_height) {
            get_block_at(db, milestone_height, bhash, sizeof(bhash), &btime);
        }

        char rcpt[32] = "";
        compute_receipt_i64(rcpt, sizeof(rcpt), milestone_height, target, "supply_milestone");

        if (btime > 0) {
            char ts[64];
            fmt_time(ts, sizeof(ts), btime);
            APPEND(off, r, max,
                "<tr><td>%s</td>"
                "<td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>"
                "<td>%s</td><td><code>%s</code></td></tr>",
                supply_milestones[i].label, milestone_height, milestone_height, ts, rcpt);
        } else {
            APPEND(off, r, max,
                "<tr><td>%s</td>"
                "<td>%" PRId64 "</td>"
                "<td style='color:#666'>Not yet reached</td>"
                "<td><code>%s</code></td></tr>",
                supply_milestones[i].label, milestone_height, rcpt);
        }
    }
    APPEND(off, r, max, "</table>");

    /* Live supply dashboard. Every figure derives from the in-binary emission
     * schedule (compute_supply_at_height / zcl_max_supply_zatoshi) + the live
     * UTXO projection, so it stays correct as the chain grows; only past-event
     * heights/dates are constants. */
    {
        int64_t mined_sat   = compute_supply_at_height(chain_height);
        int64_t cap_sat     = zcl_max_supply_zatoshi();
        int64_t sub_sat     = current_block_subsidy_sat(chain_height);
        int     spacing     = chain_height >= BUTTERCUP_ACTIVATION_HEIGHT ? 75 : 150;
        int64_t blocks_per_day = 86400 / spacing;
        int64_t daily_sat   = blocks_per_day * sub_sat;
        int64_t transparent_sat = fq_i64(db, "SELECT COALESCE(SUM(value),0) FROM utxos");
        int64_t utxo_count  = fq_i64(db, "SELECT count(*) FROM utxos");
        int64_t gap_sat     = mined_sat - transparent_sat;
        if (gap_sat < 0) gap_sat = 0;

        double pct_cap = cap_sat > 0
            ? 100.0 * (double)mined_sat / (double)cap_sat : 0.0;
        double annual_infl = mined_sat > 0
            ? 100.0 * ((double)daily_sat * 365.25) / (double)mined_sat : 0.0;
        double gap_pct = mined_sat > 0
            ? 100.0 * (double)gap_sat / (double)mined_sat : 0.0;

        /* First/only post-Buttercup halving (block 2,387,001, 2024-06-16). */
        int64_t halving_time   = get_block_time(db, 2387001);
        int64_t halving_supply = compute_supply_at_height(2387001);

        /* Next halving + ETA projected from the live tip at the target spacing. */
        int64_t next_h       = explorer_next_halving_height((int)chain_height);
        int64_t blocks_to_go = next_h - chain_height;
        if (blocks_to_go < 0) blocks_to_go = 0;
        int64_t days_to_go   = blocks_to_go * spacing / 86400;
        int64_t tip_time     = get_block_time(db, chain_height);
        int64_t eta_time     = tip_time + blocks_to_go * spacing;

        char mined_str[64], cap_str[64], sub_str2[64], daily_str[64];
        char transp_str[64], gap_str[64], hsup_str[64];
        char uc_str[32], btg_str[32], hts[64], etats[64], rcpt[32] = "";
        fmt_zcl(mined_str, sizeof(mined_str), mined_sat);
        fmt_zcl(cap_str, sizeof(cap_str), cap_sat);
        fmt_zcl(sub_str2, sizeof(sub_str2), sub_sat);
        fmt_zcl(daily_str, sizeof(daily_str), daily_sat);
        fmt_zcl(transp_str, sizeof(transp_str), transparent_sat);
        fmt_zcl(gap_str, sizeof(gap_str), gap_sat);
        fmt_zcl(hsup_str, sizeof(hsup_str), halving_supply);
        fmt_comma(uc_str, sizeof(uc_str), utxo_count);
        fmt_comma(btg_str, sizeof(btg_str), blocks_to_go);
        fmt_time(hts, sizeof(hts), halving_time);
        fmt_time(etats, sizeof(etats), eta_time);
        compute_receipt_i64(rcpt, sizeof(rcpt), mined_sat, cap_sat, "supply_dashboard");

        APPEND(off, r, max,
            "<div class='card'>"
            "<h3>Supply Dashboard (live)</h3>"
            "<table>"
            "<tr><td><b>Mined supply (at tip)</b></td><td>%s ZCL</td></tr>"
            "<tr><td><b>Asymptotic emission cap</b></td><td>%s ZCL "
            "<span style='color:#888'>(tail-summed schedule; NOT 21M)</span></td></tr>"
            "<tr><td><b>Percent of cap mined</b></td><td>%.3f%%</td></tr>"
            "<tr><td><b>Current block subsidy</b></td><td>%s ZCL</td></tr>"
            "<tr><td><b>Daily issuance (target)</b></td><td>~%s ZCL/day "
            "<span style='color:#888'>(%" PRId64 " blocks \xc3\x97 subsidy)</span></td></tr>"
            "<tr><td><b>Annualized inflation</b></td><td>~%.2f%% "
            "<span style='color:#888'>(disinflationary)</span></td></tr>"
            "<tr><td><b>First/only post-Buttercup halving</b></td>"
            "<td>block <a href='/explorer/block/2387001'>2,387,001</a> \xc2\xb7 %s "
            "\xc2\xb7 supply %s ZCL</td></tr>"
            "<tr><td><b>Next halving</b></td>"
            "<td>block <a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a> \xc2\xb7 "
            "~%s blocks (~%" PRId64 " days, est. %s) to go</td></tr>"
            "<tr><td><b>Transparent UTXO pool</b></td>"
            "<td>%s ZCL across %s UTXOs</td></tr>"
            "<tr><td><b>Shielded + burned (supply gap)</b></td>"
            "<td>%s ZCL (%.3f%% of mined)</td></tr>"
            "<tr><td><b>SHA3 Receipt</b></td><td><code>%s</code></td></tr>"
            "</table></div>",
            mined_str, cap_str, pct_cap, sub_str2,
            daily_str, blocks_per_day, annual_infl,
            hts, hsup_str,
            next_h, next_h, btg_str, days_to_go, etats,
            transp_str, uc_str,
            gap_str, gap_pct, rcpt);
    }
    return off;
}
