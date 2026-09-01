/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * HODL Wave analytics controller: UTXO age distribution, heatmaps, and
 * charts. */

#include "controllers/hodl_controller.h"
#include "controllers/strong_params.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "chain/subsidy.h"
#include "coins/coins.h"
#include "coins/coins_view.h"
#include "storage/coins_db.h"
#include "storage/dbwrapper.h"
#include "core/uint256.h"
#include "json/json.h"
#include "util/png_writer.h"
#include "models/database.h"
#include "models/hodl_wave.h"
#include "views/format_helpers.h"
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <inttypes.h>
#include <sqlite3.h>
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

struct hodl_context {
    struct main_state *main_state;
    struct coins_view_cache *coins_tip;
    struct node_db *node_db;
    const char *datadir;
};

static struct hodl_context g_hodl_ctx = {0};

static struct hodl_context *hodl_ctx(void)
{
    return &g_hodl_ctx;
}

static struct coins_view_db *hodl_coins_db(struct hodl_context *ctx)
{
    if (!ctx || !ctx->coins_tip)
        LOG_NULL("hodl", "hodl_coins_db: ctx or coins_tip is NULL");
    if (ctx->coins_tip->base.impl == NULL)
        LOG_NULL("hodl", "hodl_coins_db: coins_view base impl is NULL");
    return (struct coins_view_db *)ctx->coins_tip->base.impl;
}

void rpc_hodl_set_state(struct main_state *ms,
                         struct coins_view_cache *coins_tip,
                         struct node_db *ndb, const char *datadir)
{
    struct hodl_context *ctx = hodl_ctx();
    ctx->main_state = ms;
    ctx->coins_tip = coins_tip;
    ctx->node_db = ndb;
    ctx->datadir = datadir;
}

/* HODL Wave: UTXO age distribution across the persisted UTXO read model. */
static bool rpc_gethodlwave(const struct json_value *params, bool help,
                              struct json_value *result)
{
    struct hodl_context *ctx = hodl_ctx();
    (void)params;
    RPC_HELP(help, result,
        "gethodlwave\n"
        "\nScans the current transparent UTXO set and reports value distribution by age.\n"
        "The denominator is transparent UTXO value, not total issued supply.\n"
        "Inspired by Unchained Capital's Bitcoin HODL Waves analysis.\n"
        "\nBuckets: <1d, 1d-1w, 1w-1m, 1-3m, 3-6m, 6-12m, 1-2y, 2-3y, 3-5y, >5y\n"
        "\nResult: { buckets: [{label, value, pct, utxo_count}], summary }\n");

    if (!ctx->node_db || !ctx->node_db->open) {
        json_set_str(result, "Coins database not available");
        return false;
    }
    if (!ctx->main_state || !active_chain_tip(&ctx->main_state->chain_active)) {
        json_set_str(result, "Chain not loaded");
        return false;
    }

    int tip_height = active_chain_height(&ctx->main_state->chain_active);

    struct hodl_wave_snapshot hodl;
    if (!hodl_wave_scan_current_utxos(ctx->node_db->db, tip_height, &hodl)) {
        json_set_str(result, hodl.status);
        return false;
    }

    json_set_object(result);
    json_push_kv_int(result, "tip_height", tip_height);
    json_push_kv_str(result, "source", hodl.source);
    json_push_kv_str(result, "metric", hodl.metric);
    json_push_kv_str(result, "status", hodl.status);
    json_push_kv_int(result, "total_utxos", hodl.total_count);
    if (hodl.skipped_rows > 0)
        json_push_kv_int(result, "skipped_entries", hodl.skipped_rows);

    char amt[32];
    double total_zcl = (double)hodl.total_value / (double)ZATOSHI_PER_ZCL;
    snprintf(amt, sizeof(amt), "%.8f", total_zcl);
    json_push_kv_str(result, "denominator", "current_transparent_utxo_set");
    json_push_kv_str(result, "transparent_utxo_value_zcl", amt);
    json_push_kv_bool(result, "total_supply_zcl_legacy_alias", true);
    json_push_kv_str(result, "total_supply_zcl", amt);

    /* Build buckets with cumulative % (oldest-first accumulation).
     * "cumulative_pct" answers: what % of supply has been unmoved
     * for AT LEAST this long? Buckets go young→old, so accumulate
     * from the old end backwards. */
    int64_t cumul_value = 0;
    double cumul_pcts[HODL_WAVE_BUCKETS];
    for (int b = HODL_WAVE_BUCKETS - 1; b >= 0; b--) {
        cumul_value += hodl.buckets[b].value;
        cumul_pcts[b] = hodl.total_value > 0
            ? (double)cumul_value / (double)hodl.total_value * 100.0
            : 0.0;
    }

    struct json_value arr = {0};
    json_set_array(&arr);

    for (int b = 0; b < HODL_WAVE_BUCKETS; b++) {
        struct json_value entry = {0};
        json_set_object(&entry);
        json_push_kv_str(&entry, "age", hodl.buckets[b].label);

        double bval = (double)hodl.buckets[b].value / (double)ZATOSHI_PER_ZCL;
        snprintf(amt, sizeof(amt), "%.8f", bval);
        json_push_kv_str(&entry, "zcl", amt);

        json_push_kv_int(&entry, "utxos", hodl.buckets[b].count);

        double pct = hodl.total_value > 0
                   ? (double)hodl.buckets[b].value / (double)hodl.total_value * 100.0
                   : 0.0;
        json_push_kv_real(&entry, "pct", pct);
        json_push_kv_real(&entry, "cumulative_pct_unmoved", cumul_pcts[b]);

        /* Bar shows cumulative % */
        int bar_len = (int)(cumul_pcts[b] / 2.5);
        if (bar_len > 40) bar_len = 40;
        char bar[42];
        for (int i = 0; i < bar_len; i++) bar[i] = '#';
        bar[bar_len] = '\0';
        json_push_kv_str(&entry, "bar", bar);

        json_push_back(&arr, &entry);
        json_free(&entry);
    }

    json_push_kv(result, "buckets", &arr);
    json_free(&arr);

    return true;
}

/* ── Color mapping for heatmap ──────────────────────────────────── */

static void plasma_color(double t, uint8_t *r, uint8_t *g, uint8_t *b)
{
    /* 0=black, 0.15=dark blue, 0.35=purple, 0.55=red, 0.75=orange,
     * 0.9=yellow, 1.0=white */
    if (t <= 0.0) { *r = 0; *g = 0; *b = 0; return; }
    if (t >= 1.0) { *r = 255; *g = 255; *b = 255; return; }
    if (t < 0.15) {
        double s = t / 0.15;
        *r = 0; *g = 0; *b = (uint8_t)(s * 140);
    } else if (t < 0.35) {
        double s = (t - 0.15) / 0.20;
        *r = (uint8_t)(s * 160); *g = 0; *b = (uint8_t)(140 + s * 60);
    } else if (t < 0.55) {
        double s = (t - 0.35) / 0.20;
        *r = (uint8_t)(160 + s * 95); *g = (uint8_t)(s * 40); *b = (uint8_t)(200 - s * 200);
    } else if (t < 0.75) {
        double s = (t - 0.55) / 0.20;
        *r = 255; *g = (uint8_t)(40 + s * 180); *b = 0;
    } else if (t < 0.92) {
        double s = (t - 0.75) / 0.17;
        *r = 255; *g = (uint8_t)(220 + s * 35); *b = (uint8_t)(s * 100);
    } else {
        double s = (t - 0.92) / 0.08;
        *r = 255; *g = 255; *b = (uint8_t)(100 + s * 155);
    }
}

/* HODL wave age band colors (warm=young, cool=old) */
static const uint8_t hodl_colors[HODL_WAVE_BUCKETS][3] = {
    {255, 50,  30},   /* < 1 day    — bright red */
    {255, 120, 20},   /* 1d - 1w    — orange */
    {255, 200, 30},   /* 1w - 1m    — yellow */
    {180, 230, 40},   /* 1 - 3m     — yellow-green */
    {80,  210, 60},   /* 3 - 6m     — green */
    {30,  190, 150},  /* 6 - 12m    — teal */
    {30,  140, 220},  /* 1 - 2y     — blue */
    {60,  80,  200},  /* 2 - 3y     — indigo */
    {100, 50,  180},  /* 3 - 5y     — purple */
    {80,  30,  120},  /* > 5y       — dark purple */
};

/* gethodlwaveimage: Scan persisted chainstate, generate a PPM heatmap +
 * HODL wave bar, save to datadir/hodlwave.ppm. */
static bool rpc_gethodlwaveimage(const struct json_value *params, bool help,
                                  struct json_value *result)
{
    struct hodl_context *ctx = hodl_ctx();
    struct coins_view_db *coins_db = hodl_coins_db(ctx);
    (void)params;
    RPC_HELP(help, result,
        "gethodlwaveimage\n"
        "\nGenerates a HODL wave heatmap image from the current UTXO set.\n"
        "\nThe image shows:\n"
        "  Top: UTXO creation heatmap (X=block height, Y=value log scale)\n"
        "  Bottom: HODL wave age distribution bar\n"
        "\nSaves to <datadir>/hodlwave.ppm\n"
        "\nResult: { file, width, height, total_utxos, total_value }\n");

    if (!coins_db) {
        json_set_str(result, "Coins database not available");
        return false;
    }
    if (!ctx->main_state || !active_chain_tip(&ctx->main_state->chain_active)) {
        json_set_str(result, "Chain not loaded");
        return false;
    }

    int tip_height = active_chain_height(&ctx->main_state->chain_active);
    if (tip_height <= 0) {
        json_set_str(result, "No blocks");
        return false;
    }

    /* Image dimensions */
    const int IMG_W = 1920;
    const int IMG_H = 1080;
    const int HEATMAP_H = 860;   /* top portion: creation heatmap */
    const int WAVE_H = 160;      /* bottom portion: HODL wave bar */
    const int GAP_H = IMG_H - HEATMAP_H - WAVE_H; /* separator */

    /* Grid: height bins (columns) × value bins (rows) */
    int blocks_per_col = (tip_height + IMG_W - 1) / IMG_W;
    if (blocks_per_col < 1) blocks_per_col = 1;

    /* Value bins: log10 scale from 1 satoshi (0) to 100000 ZCL (13)
     * 1 sat = 10^0, 1 ZCL = 10^8, 100000 ZCL = 10^13 */
    const double LOG_MIN = 0.0;
    const double LOG_MAX = 13.0;

    /* Allocate grid: grid[row][col] = count of UTXOs */
    int64_t *grid = zcl_calloc((size_t)(HEATMAP_H * IMG_W), sizeof(int64_t), "heatmap_grid");
    if (!grid) {
        json_set_str(result, "Out of memory");
        return false;
    }

    int64_t hodl_values[HODL_WAVE_BUCKETS] = {0};
    int64_t total_value = 0;
    int64_t total_utxos = 0;

    /* Scan UTXO set */
    struct db_iterator it;
    db_iter_init(&it, &coins_db->db);
    char prefix = 'c';
    db_iter_seek(&it, &prefix, 1);

    while (db_iter_valid(&it)) {
        size_t keylen = 0;
        const char *key = db_iter_key(&it, &keylen);
        if (!key || keylen != 33 || key[0] != 'c')
            break;

        struct uint256 txid;
        memcpy(txid.data, key + 1, 32);

        struct coins c;
        coins_init(&c);
        if (coins_view_db_get_coins(coins_db, &txid, &c)) {
            int height = c.height;
            if (height < 0) height = 0;
            if (height > tip_height) height = tip_height;
            int64_t age_s = hodl_wave_age_seconds(height, tip_height);
            int bucket = hodl_wave_bucket_index(age_s);

            /* Heatmap column from creation height */
            int col = height / blocks_per_col;
            if (col >= IMG_W) col = IMG_W - 1;

            for (size_t i = 0; i < c.num_vout; i++) {
                if (!tx_out_is_null(&c.vout[i]) && c.vout[i].value > 0) {
                    double logval = log10((double)c.vout[i].value);
                    if (logval < LOG_MIN) logval = LOG_MIN;
                    if (logval > LOG_MAX) logval = LOG_MAX;
                    /* Map to row (bottom=small, top=large) */
                    int row = HEATMAP_H - 1 -
                        (int)((logval - LOG_MIN) / (LOG_MAX - LOG_MIN)
                              * (HEATMAP_H - 1));
                    if (row < 0) row = 0;
                    if (row >= HEATMAP_H) row = HEATMAP_H - 1;
                    grid[row * IMG_W + col]++;

                    hodl_values[bucket] += c.vout[i].value;
                    total_value += c.vout[i].value;
                    total_utxos++;
                }
            }
        }
        coins_free(&c);
        db_iter_next(&it);
    }
    db_iter_free(&it);

    /* Find max grid value for normalization */
    int64_t grid_max = 0;
    for (int i = 0; i < HEATMAP_H * IMG_W; i++)
        if (grid[i] > grid_max) grid_max = grid[i];

    /* Allocate pixel buffer */
    uint8_t *pixels = zcl_calloc((size_t)(IMG_W * IMG_H * 3), 1, "heatmap_pixels");
    if (!pixels) {
        free(grid);
        json_set_str(result, "Out of memory for image");
        return false;
    }

    /* Render heatmap (top portion) */
    for (int row = 0; row < HEATMAP_H; row++) {
        for (int col = 0; col < IMG_W; col++) {
            int64_t count = grid[row * IMG_W + col];
            if (count > 0 && grid_max > 0) {
                double t = log1p((double)count) / log1p((double)grid_max);
                uint8_t r, g, b;
                plasma_color(t, &r, &g, &b);
                int idx = (row * IMG_W + col) * 3;
                pixels[idx] = r;
                pixels[idx + 1] = g;
                pixels[idx + 2] = b;
            }
            /* else: stays black */
        }
    }

    /* Render separator gap (dark gray line) */
    for (int row = HEATMAP_H; row < HEATMAP_H + GAP_H; row++) {
        for (int col = 0; col < IMG_W; col++) {
            int idx = (row * IMG_W + col) * 3;
            pixels[idx] = 20;
            pixels[idx + 1] = 20;
            pixels[idx + 2] = 20;
        }
    }

    /* Render HODL wave bar (bottom portion) — stacked horizontal bands */
    if (total_value > 0) {
        int x_start = 0;
        for (int b = HODL_WAVE_BUCKETS - 1; b >= 0; b--) {
            int band_width = (int)((double)hodl_values[b]
                                   / (double)total_value * IMG_W);
            if (b == 0) band_width = IMG_W - x_start; /* fill remainder */

            for (int col = x_start; col < x_start + band_width && col < IMG_W;
                 col++) {
                for (int row = HEATMAP_H + GAP_H; row < IMG_H; row++) {
                    int idx = (row * IMG_W + col) * 3;
                    pixels[idx]     = hodl_colors[b][0];
                    pixels[idx + 1] = hodl_colors[b][1];
                    pixels[idx + 2] = hodl_colors[b][2];
                }
            }
            x_start += band_width;
        }
    }

    /* Draw consensus activation height markers on the heatmap */
    int markers[] = { 476969, 585318, 585322, 707000 };
    for (int m = 0; m < 4; m++) {
        int col = markers[m] / blocks_per_col;
        if (col >= 0 && col < IMG_W) {
            for (int row = 0; row < HEATMAP_H; row++) {
                int idx = (row * IMG_W + col) * 3;
                /* Cyan marker line */
                pixels[idx]     = (uint8_t)(pixels[idx] / 2 + 30);
                pixels[idx + 1] = (uint8_t)(pixels[idx+1] / 2 + 200);
                pixels[idx + 2] = (uint8_t)(pixels[idx+2] / 2 + 200);
            }
        }
    }

    free(grid);

    /* Write PNG file */
    char filepath[1024];
    snprintf(filepath, sizeof(filepath), "%s/hodlwave.png",
             ctx->datadir ? ctx->datadir : ".");

    if (!png_write_rgb(filepath, pixels, (uint32_t)IMG_W, (uint32_t)IMG_H)) {
        free(pixels);
        json_set_str(result, "Failed to write PNG file");
        return false;
    }
    free(pixels);

    /* Return result */
    json_set_object(result);
    json_push_kv_str(result, "file", filepath);
    json_push_kv_int(result, "width", IMG_W);
    json_push_kv_int(result, "height", IMG_H);
    json_push_kv_int(result, "total_utxos", total_utxos);
    json_push_kv_int(result, "blocks_per_column", blocks_per_col);

    char amt[32];
    snprintf(amt, sizeof(amt), "%lld.%08lld",
             (long long)(total_value / ZATOSHI_PER_ZCL),
             (long long)(total_value % ZATOSHI_PER_ZCL));
    json_push_kv_str(result, "total_value", amt);

    /* Also include the HODL wave percentages */
    const struct hodl_wave_bucket *defs = hodl_wave_bucket_defs();
    struct json_value wave = {0};
    json_set_array(&wave);
    for (int b = 0; b < HODL_WAVE_BUCKETS; b++) {
        struct json_value entry = {0};
        json_set_object(&entry);
        json_push_kv_str(&entry, "label", defs[b].label);
        double pct = total_value > 0
            ? (double)hodl_values[b] / (double)total_value * 100.0 : 0.0;
        json_push_kv_real(&entry, "percent", pct);

        snprintf(amt, sizeof(amt), "%lld.%08lld",
                 (long long)(hodl_values[b] / ZATOSHI_PER_ZCL),
                 (long long)(hodl_values[b] % ZATOSHI_PER_ZCL));
        json_push_kv_str(&entry, "value", amt);
        json_push_back(&wave, &entry);
        json_free(&entry);
    }
    json_push_kv(result, "hodl_wave", &wave);
    json_free(&wave);

    return true;
}

void register_hodl_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "blockchain", "gethodlwave",      rpc_gethodlwave,      true },
        { "blockchain", "gethodlwaveimage", rpc_gethodlwaveimage, true },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
