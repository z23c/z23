/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer stats VIEW: phase-1 data gathering.
 *
 * Part of the deep-stats page split: this TU owns the heavier phase-1
 * aggregate queries that fill a struct stats_ctx / struct stats_chart_data
 * (deep chain queries + 40-bucket chart aggregates over 5 time ranges).
 * The public entry point (explorer_stats_build) and the lighter inline
 * phase-1 queries live in explorer_stats_view.c; the section emitters live
 * in explorer_stats_sections.c. Shared data structs come from
 * views/explorer_stats_internal.h. */

#include "views/explorer_stats_internal.h"

static void gather_tx_output_stats(sqlite3 *db, struct stats_ctx *c)
{
    sqlite3_stmt *s = NULL;
    const char *sql =
        "SELECT COUNT(*),"
        "COALESCE(SUM(CASE WHEN script_type=0 THEN 1 ELSE 0 END),0),"
        "COALESCE(SUM(CASE WHEN script_type=1 THEN 1 ELSE 0 END),0),"
        "COALESCE(MAX(value),0),"
        "COALESCE(SUM(value),0) "
        "FROM tx_outputs";

    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK || !s) {
        printf("Stats: tx-output aggregate prepare failed: %s\n",
               sqlite3_errmsg(db));
        fflush(stdout);
        if (s)
            sqlite3_finalize(s);
        return;
    }

    if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
        c->total_outputs = sqlite3_column_int64(s, 0);
        c->p2pkh_outputs = sqlite3_column_int64(s, 1);
        c->p2sh_outputs = sqlite3_column_int64(s, 2);
        c->max_output_value = sqlite3_column_int64(s, 3);
        c->total_value_moved = sqlite3_column_int64(s, 4);
    }
    sqlite3_finalize(s);
}

/* Phase 1h: deep chain queries (tx_outputs, joinsplits, sapling_*,
 * sprout_nullifiers, view_integrity, firsts & records). Writes
 * directly into the supplied stats_ctx. */
void gather_deep_chain_data(sqlite3 *db, struct stats_ctx *c)
{
    printf("Stats: querying deep chain data...\n"); fflush(stdout);

    /* Transaction I/O */
    gather_tx_output_stats(db, c);
    c->total_inputs  = stats_q_i64(db, "SELECT count(*) FROM tx_inputs");

    /* Shielded deep dive (per-tx tables) */
    c->total_joinsplits   = stats_q_i64(db, "SELECT count(*) FROM joinsplits");
    c->total_vpub_old     = stats_q_i64(db, "SELECT COALESCE(SUM(vpub_old),0) FROM joinsplits");
    c->total_vpub_new     = stats_q_i64(db, "SELECT COALESCE(SUM(vpub_new),0) FROM joinsplits");
    c->total_sap_spends   = stats_q_i64(db, "SELECT count(*) FROM sapling_spends");
    c->total_sap_outputs  = stats_q_i64(db, "SELECT count(*) FROM sapling_outputs");
    c->total_sprout_nulls = stats_q_i64(db, "SELECT count(*) FROM sprout_nullifiers");
    c->unique_sap_anchors = stats_q_i64(db, "SELECT count(DISTINCT anchor) FROM sapling_spends");

    /* SHA3 integrity chain */
    c->integrity_count = stats_q_i64(db, "SELECT count(*) FROM view_integrity");
    c->integrity_min_h = stats_q_i64(db, "SELECT MIN(height) FROM view_integrity");
    c->integrity_max_h = stats_q_i64(db, "SELECT MAX(height) FROM view_integrity");
    snprintf(c->integrity_latest_hash, sizeof(c->integrity_latest_hash), "N/A");
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT hex(sha3_hash) FROM view_integrity ORDER BY height DESC LIMIT 1",
                -1, &s, NULL) == SQLITE_OK && s) {
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                const char *h = (const char *)sqlite3_column_text(s, 0);
                if (h) snprintf(c->integrity_latest_hash, sizeof(c->integrity_latest_hash), "%s", h);
            }
            sqlite3_finalize(s);
        }
    }

    /* Chain firsts & records */
    c->first_noncoinbase = stats_q_i64(db,
        "SELECT MIN(block_height) FROM transactions WHERE is_coinbase=0");
    struct explorer_first_privacy_heights first_privacy = {0};
    explorer_query_first_privacy_heights(db, &first_privacy);
    c->first_joinsplit_h = first_privacy.joinsplit_height;
    c->first_sapling_h = first_privacy.sapling_height;
    c->first_opreturn_h = stats_q_i64(db,
        "SELECT MIN(block_height) FROM op_returns");
    c->first_zslp_h = stats_q_i64(db,
        "SELECT MIN(genesis_height) FROM zslp_tokens");

    c->most_js_block = 0; c->most_js_count = 0;
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT block_height, count(*) as cnt FROM joinsplits "
                "GROUP BY block_height ORDER BY cnt DESC LIMIT 1",
                -1, &s, NULL) == SQLITE_OK && s) {
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                c->most_js_block = sqlite3_column_int64(s, 0);
                c->most_js_count = sqlite3_column_int64(s, 1);
            }
            sqlite3_finalize(s);
        }
    }
    c->most_sap_out_block = 0; c->most_sap_out_count = 0;
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT block_height, count(*) as cnt FROM sapling_outputs "
                "GROUP BY block_height ORDER BY cnt DESC LIMIT 1",
                -1, &s, NULL) == SQLITE_OK && s) {
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                c->most_sap_out_block = sqlite3_column_int64(s, 0);
                c->most_sap_out_count = sqlite3_column_int64(s, 1);
            }
            sqlite3_finalize(s);
        }
    }
    c->fastest_block_h = 0; c->fastest_block_gap = 0;
    c->slowest_block_h = 0; c->slowest_block_gap = 0;
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT b2.height, b2.time - b1.time as gap "
                "FROM blocks b1 JOIN blocks b2 ON b2.height = b1.height + 1 "
                "WHERE b1.time > 0 AND b2.time > b1.time "
                "ORDER BY gap ASC LIMIT 1",
                -1, &s, NULL) == SQLITE_OK && s) {
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                c->fastest_block_h   = sqlite3_column_int64(s, 0);
                c->fastest_block_gap = sqlite3_column_int64(s, 1);
            }
            sqlite3_finalize(s);
        }
        s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT b2.height, b2.time - b1.time as gap "
                "FROM blocks b1 JOIN blocks b2 ON b2.height = b1.height + 1 "
                "WHERE b1.time > 0 AND b2.time > b1.time "
                "ORDER BY gap DESC LIMIT 1",
                -1, &s, NULL) == SQLITE_OK && s) {
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                c->slowest_block_h   = sqlite3_column_int64(s, 0);
                c->slowest_block_gap = sqlite3_column_int64(s, 1);
            }
            sqlite3_finalize(s);
        }
    }
}

/* Phase 1h2: recent-window economy aggregates. Cheap range-bounded queries
 * (last ~1 day / 1000 blocks) plus median + chainwork. Writes into ctx. */
void gather_economy_data(sqlite3 *db, int tip, int64_t tip_time,
                                struct stats_ctx *c)
{
    printf("Stats: gathering economy data...\n"); fflush(stdout);

    /* Recent average block interval over the last 1000 blocks. */
    c->recent_avg_interval = 0.0;
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT MAX(time), MIN(time), COUNT(*) FROM "
                "(SELECT time FROM blocks ORDER BY height DESC LIMIT 1000)",
                -1, &s, NULL) == SQLITE_OK && s) {
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                int64_t tmax = sqlite3_column_int64(s, 0);
                int64_t tmin = sqlite3_column_int64(s, 1);
                int64_t n    = sqlite3_column_int64(s, 2);
                if (n > 1 && tmax > tmin)
                    c->recent_avg_interval = (double)(tmax - tmin) / (double)(n - 1);
            }
            sqlite3_finalize(s);
        } else {
            printf("Stats: recent-interval query prepare failed: %s\n",
                   sqlite3_errmsg(db)); fflush(stdout);
        }
    }

    /* Transactions confirmed in the last 24h (by block time). */
    {
        char sql[160];
        snprintf(sql, sizeof(sql),
            "SELECT COALESCE(SUM(num_tx),0) FROM blocks WHERE time > %lld",
            (long long)(tip_time - 86400));
        c->tx_per_day = stats_q_i64(db, sql);
    }

    /* Net daily UTXO growth ~= outputs created - inputs spent over the last
     * ~1 day of blocks (1152 blocks @ 75s target spacing). */
    {
        int64_t thresh = (int64_t)tip - 1152;
        if (thresh < 0) thresh = 0;
        char sql[160];
        snprintf(sql, sizeof(sql),
            "SELECT count(*) FROM tx_outputs WHERE block_height > %lld",
            (long long)thresh);
        int64_t outs = stats_q_i64(db, sql);
        snprintf(sql, sizeof(sql),
            "SELECT count(*) FROM tx_inputs WHERE block_height > %lld",
            (long long)thresh);
        int64_t ins = stats_q_i64(db, sql);
        c->net_daily_utxo = outs - ins;
    }

    /* Unspent coinbase still inside the COINBASE_MATURITY (=100) window. */
    c->immature_cb_count = 0;
    c->immature_cb_value = 0;
    {
        int64_t mat = (int64_t)tip - 100; /* COINBASE_MATURITY */
        if (mat < 0) mat = 0;
        char sql[200];
        snprintf(sql, sizeof(sql),
            "SELECT COUNT(*), COALESCE(SUM(value),0) FROM utxos "
            "WHERE is_coinbase=1 AND height > %lld", (long long)mat);
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                c->immature_cb_count = sqlite3_column_int64(s, 0);
                c->immature_cb_value = sqlite3_column_int64(s, 1);
            }
            sqlite3_finalize(s);
        } else {
            printf("Stats: immature-coinbase query prepare failed: %s\n",
                   sqlite3_errmsg(db)); fflush(stdout);
        }
    }

    /* Median UTXO value (offset to the middle row of a value-ordered scan). */
    c->median_utxo_value = stats_q_i64(db,
        "SELECT value FROM utxos ORDER BY value "
        "LIMIT 1 OFFSET (SELECT COUNT(*)/2 FROM utxos)");

    /* Cumulative chainwork at tip. Stored as a 32-byte little-endian blob;
     * render big-endian hex (matches getblockchaininfo), leading zeros
     * trimmed. */
    c->chainwork_hex[0] = '\0';
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT hex(chain_work) FROM blocks ORDER BY height DESC LIMIT 1",
                -1, &s, NULL) == SQLITE_OK && s) {
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                const char *le = (const char *)sqlite3_column_text(s, 0);
                if (le) {
                    size_t n = strlen(le);
                    if (n >= 2 && n <= 64 && (n % 2) == 0) {
                        char be[72];
                        size_t bo = 0;
                        for (size_t i = n; i >= 2 && bo + 2 < sizeof(be); i -= 2) {
                            be[bo++] = le[i - 2];
                            be[bo++] = le[i - 1];
                        }
                        be[bo] = '\0';
                        size_t z = 0;
                        while (be[z] == '0' && be[z + 1] != '\0') z++;
                        snprintf(c->chainwork_hex, sizeof(c->chainwork_hex),
                                 "%s", be + z);
                    }
                }
            }
            sqlite3_finalize(s);
        } else {
            printf("Stats: chainwork query prepare failed: %s\n",
                   sqlite3_errmsg(db)); fflush(stdout);
        }
    }
}

/* Phase 1i: 40-bucket aggregates over 5 time ranges (24h/7d/30d/1y/all).
 * Single batch query per range. */
void gather_chart_data(sqlite3 *db, int tip, double diff,
                              struct stats_chart_data *out)
{
    printf("Stats: computing chart data...\n"); fflush(stdout);
    struct { const char *label; const char *id; int blocks; } ranges[] = {
        {"24h", "24h", 576}, {"7d", "7d", 4032}, {"30d", "30d", 17280},
        {"1yr", "1y", 210240}, {"All", "all", tip},
    };

    for (int ri = 0; ri < 5; ri++) {
        int total = ranges[ri].blocks;
        if (total > tip) total = tip;
        int step = total / 40;
        if (step < 1) step = 1;
        int base = tip - total;
        if (base < 0) base = 0;

        /* Batch: get all 40 data points in one query using
         * (height - base) / step as bucket index */
        for (int i = 0; i < 40; i++) {
            int bh = base + (i + 1) * step;
            out->diff_data[ri][i] = diff;
            out->hr_data[ri][i] = explorer_solrate_from_diff(diff, bh);
            out->sprout_c[ri][i] = 0;
            out->sapling_c[ri][i] = 0;
            out->txcount[ri][i] = 0;
        }

        /* Single query: aggregate by bucket */
        char sql[512];
        snprintf(sql, sizeof(sql),
            "SELECT (height - %d) / %d AS bucket, "
            "MAX(bits), "
            "COALESCE(SUM(sprout_value),0), "
            "COALESCE(SUM(sapling_value),0), "
            "COALESCE(SUM(num_tx),0) "
            "FROM blocks WHERE height > %d AND height <= %d "
            "GROUP BY bucket ORDER BY bucket",
            base, step, base, tip);
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                int bucket = sqlite3_column_int(s, 0);
                if (bucket < 0 || bucket >= 40) continue;
                uint32_t bits = (uint32_t)sqlite3_column_int(s, 1);
                if (bits > 0) {
                    /* Representative height of this bucket -> active spacing. */
                    int bh = base + (bucket + 1) * step;
                    out->diff_data[ri][bucket] = explorer_difficulty_from_bits(bits);
                    out->hr_data[ri][bucket] =
                        explorer_solrate_from_diff(out->diff_data[ri][bucket], bh);
                }
                /* Sprout: positive=shielding, show as positive on chart (pool inflow)
                 * Sapling: negative=shielding, negate to show inflow as positive */
                out->sprout_c[ri][bucket]  = (double)sqlite3_column_int64(s, 2) / 1e8;
                out->sapling_c[ri][bucket] = -(double)sqlite3_column_int64(s, 3) / 1e8;
                out->txcount[ri][bucket]   = (double)sqlite3_column_int64(s, 4);
            }
            sqlite3_finalize(s);
        }
        for (int i = 0; i < 40; i++) {
            int h = base + (i + 1) * step;
            if (h > tip) h = tip;
            snprintf(out->labels[ri][i], sizeof(out->labels[ri][i]), "%d", h);
        }
    }
}
