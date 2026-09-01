/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer stats VIEW — shared internals for the multi-TU split.
 *
 * The deep-stats page is large (a dozen section emitters + a multi-query
 * phase-1 data gather), so the View is split across two translation units
 * that both live in contexts/explorer/views/src/ and share the data structs + emitter
 * declarations here:
 *
 *   - explorer_stats_view.c     — public entry point (explorer_stats_build),
 *                                 the degraded "verified summary" fallback,
 *                                 phase-1 data gathering, and the chart /
 *                                 shielded render helpers.
 *   - explorer_stats_sections.c — the section emitters (emit_stats_header
 *                                 + emit_section_*), each appending one
 *                                 logical section of HTML; address
 *                                 encoding uses the shared
 *                                 wallet_encode_destination helper.
 *
 * Each emitter appends one section starting at `off` and returns the new
 * offset. They take a const struct stats_ctx* (every phase-1 value bundled
 * so the render helpers don't need a fat parameter list). Project-internal
 * linkage so the orchestrator in explorer_stats_view.c can call them. This
 * is a private header for the stats view only — not part of the public
 * surface in views/explorer_stats_view.h. */

#ifndef ZCL_VIEWS_EXPLORER_STATS_INTERNAL_H
#define ZCL_VIEWS_EXPLORER_STATS_INTERNAL_H

#include "controllers/explorer_internal.h"
#include "models/hodl_wave.h"
#include "script/standard.h"
#include "keys/key_io.h"
#include "chain/chainparams.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include <sqlite3.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

/* sql_query_i64() provided by controllers/explorer_internal.h */
#define stats_q_i64 sql_query_i64

/* ── Consolidated data structures ────────────────────────── */

struct shielded_stats {
    int64_t block_count;
    int64_t sum_pos;        /* total unshielded (z->t), positive */
    int64_t sum_neg;        /* total shielded (t->z), negative */
    int64_t first_height;
    int64_t last_height;
    int64_t first_time;
    int64_t last_time;
    int64_t peak_pos_height;
    int64_t peak_pos_value;
    int64_t peak_neg_height;
    int64_t peak_neg_value; /* negative */
};

/* ── Shared structs for gather + emit helpers ── */

struct stats_ctx {
    /* Tip + difficulty */
    int     tip;
    double  diff;
    int64_t tip_time;
    int64_t genesis_time;
    int64_t chain_age_days;

    /* Block aggregates */
    int64_t total_blocks, total_block_txs, empty_blocks;
    int64_t max_tx_count, max_tx_block;
    uint32_t min_bits, max_bits;
    int64_t min_bits_height, max_bits_height;
    double  min_diff, max_diff;
    double  avg_tx_per_block;

    /* UTXO aggregates */
    int64_t total_supply, utxo_count_val;
    int64_t utxo_dust, utxo_small, utxo_medium, utxo_large, utxo_whale;
    int64_t utxo_max_value, utxo_min_height;
    int64_t utxo_coinbase_count, utxo_coinbase_value;
    double  utxo_avg;

    /* Tx counts */
    int64_t total_txs, coinbase_txs;

    /* Shielded pools */
    struct shielded_stats sprout, sapling;
    int64_t nullifier_count;

    /* Address stats */
    int64_t total_addresses, addr_nonzero;
    int64_t top10_balance, top100_balance;

    /* ZSLP / OP_RETURN */
    int64_t opret_count, slp_opret_count;
    int64_t zslp_token_count, zslp_transfer_count;

    /* Deep chain: tx I/O */
    int64_t total_outputs, total_inputs;
    int64_t p2pkh_outputs, p2sh_outputs;
    int64_t max_output_value, total_value_moved;

    /* Deep chain: shielded */
    int64_t total_joinsplits, total_vpub_old, total_vpub_new;
    int64_t total_sap_spends, total_sap_outputs;
    int64_t total_sprout_nulls, unique_sap_anchors;

    /* SHA3 integrity */
    int64_t integrity_count, integrity_min_h, integrity_max_h;
    char    integrity_latest_hash[130];

    /* Firsts & records */
    int64_t first_noncoinbase, first_joinsplit_h, first_sapling_h;
    int64_t first_opreturn_h, first_zslp_h;
    int64_t most_js_block, most_js_count;
    int64_t most_sap_out_block, most_sap_out_count;
    int64_t fastest_block_h, fastest_block_gap;
    int64_t slowest_block_h, slowest_block_gap;

    /* Derived */
    char    hr_str[64];          /* solve rate, formatted (Sol/s) */
    char    supply_str[32];      /* transparent UTXO pool, formatted */
    int     halvings, next_halving, blocks_until_halving;
    int64_t current_subsidy;
    double  pct_mined;           /* transparent pool / cap */
    int64_t t_query_ms;

    /* Economy & emission (factoid section) */
    int64_t mined_supply;        /* consensus mined/circulating supply at tip */
    int64_t max_supply_sat;      /* asymptotic emission cap (~11.46M ZCL) */
    double  pct_of_cap;          /* mined_supply / max_supply_sat * 100 */
    double  solrate;             /* estimated network solve rate (Sol/s) */
    double  daily_issuance_zcl;  /* current subsidy * 86400 / target spacing */
    double  annual_inflation;    /* daily_issuance annualized vs mined_supply (%) */
    double  recent_avg_interval; /* avg block interval, last 1000 blocks (s) */
    int64_t halving_eta_secs;    /* blocks_until_halving * recent_avg_interval */
    int64_t tx_per_day;          /* tx count in blocks over the last 24h */
    int64_t net_daily_utxo;      /* outputs created - inputs spent, last ~1d */
    int64_t immature_cb_count;   /* unspent coinbase within COINBASE_MATURITY */
    int64_t immature_cb_value;
    int64_t median_utxo_value;
    int64_t tip_age_secs;        /* wall_now - tip block time */
    char    chainwork_hex[72];   /* cumulative chainwork, big-endian hex */
};

struct stats_chart_data {
    double diff_data[5][40], hr_data[5][40];
    double sprout_c[5][40], sapling_c[5][40], txcount[5][40];
    char   labels[5][40][20];
};

/* ── Phase-1 data gather (defined in explorer_stats_gather.c) ─────────
 *
 * Heavier aggregate queries that fill the supplied stats_ctx /
 * stats_chart_data. */
void gather_deep_chain_data(sqlite3 *db, struct stats_ctx *c);
void gather_chart_data(sqlite3 *db, int tip, double diff,
                       struct stats_chart_data *out);
/* Recent-window economy aggregates (interval, tx/day, UTXO flow, immature
 * coinbase, median UTXO, chainwork) — needs the tip + tip block time. */
void gather_economy_data(sqlite3 *db, int tip, int64_t tip_time,
                         struct stats_ctx *c);

/* ── Section emitters (defined in explorer_stats_sections.c) ──────────
 *
 * Each appends one logical section of the stats HTML page starting at
 * `off` and returns the new offset. */
size_t emit_stats_header(uint8_t *r, size_t max, size_t off,
                         const struct stats_ctx *c);
size_t emit_section_1_network(uint8_t *r, size_t max, size_t off,
                              const struct stats_ctx *c);
size_t emit_section_1b_economy(uint8_t *r, size_t max, size_t off,
                               const struct stats_ctx *c);
size_t emit_section_2_chain_history(uint8_t *r, size_t max, size_t off,
                                    const struct stats_ctx *c);
size_t emit_section_3_block_records(uint8_t *r, size_t max, size_t off,
                                    const struct stats_ctx *c);
size_t emit_section_6_utxo_distribution(uint8_t *r, size_t max, size_t off,
                                        const struct stats_ctx *c, sqlite3 *db);
size_t emit_section_7_address_distribution(uint8_t *r, size_t max, size_t off,
                                           const struct stats_ctx *c, sqlite3 *db);
size_t emit_section_8_zslp_opret(uint8_t *r, size_t max, size_t off,
                                 const struct stats_ctx *c);
size_t emit_section_8b_tx_io(uint8_t *r, size_t max, size_t off,
                             const struct stats_ctx *c);
size_t emit_section_8c_shielded_detail(uint8_t *r, size_t max, size_t off,
                                       const struct stats_ctx *c);
size_t emit_section_8d_integrity(uint8_t *r, size_t max, size_t off,
                                 const struct stats_ctx *c);
size_t emit_section_8e_firsts(uint8_t *r, size_t max, size_t off,
                              const struct stats_ctx *c);
size_t emit_section_9_tx_volume_by_year(uint8_t *r, size_t max, size_t off,
                                        sqlite3 *db);
size_t emit_section_10_utxo_age(uint8_t *r, size_t max, size_t off,
                                const struct stats_ctx *c, sqlite3 *db);

#endif
