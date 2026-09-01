/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "controllers/api_controller.h"
#include "controllers/blockchain_controller.h"
#include "controllers/explorer_internal.h"
#include "controllers/file_controller.h"
#include "controllers/file_market_controller.h"
#include "controllers/game_controller.h"
#include "controllers/health_controller.h"
#include "controllers/messaging_controller.h"
#include "controllers/name_controller.h"
#include "controllers/swap_controller.h"
#include "api_controller_internal.h"
#include "chain/mmb.h"
#include "config/boot.h"
#include "config/runtime.h"
#include "encoding/utilstrencodings.h"
#include "event/event.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "keys/key_io.h"
#include "models/block.h"
#include "models/database.h"
#include "models/file_service.h"
#include "models/hodl_wave.h"
#include "models/onion_announcement.h"
#include "models/peer.h"
#include "models/zslp.h"
#include "net/download.h"
#include "views/explorer_factoids_view.h"
#include "sapling/incremental_merkle_tree.h"
#include "services/node_health_service.h"
#include "net/snapshot_sync_contract.h"
#include "services/zslp_service.h"
#include "validation/contextual_check_tx.h"
#include "validation/main_state.h"
#include "views/format_helpers.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "platform/time_compat.h"

#include <ctype.h>
#include <inttypes.h>
#include <math.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Cached endpoints: blocks, stats, supply, hodl, deep_stats. Called only from background refresh thread. */

enum { API_CACHE_SQLITE_PROGRESS_OPS = 1000 };

static int api_cache_sqlite_progress(void *ctx)
{
    const _Atomic int *running = ctx ? ctx : &g_api_cache_thread_running;
    return atomic_load(running) ? 0 : 1;
}

static void api_cache_sqlite_guard(sqlite3 *db, bool cancellable)
{
    if (db && cancellable)
        sqlite3_progress_handler(db, API_CACHE_SQLITE_PROGRESS_OPS,
                                 api_cache_sqlite_progress, NULL);
}

static void api_cache_sqlite_close(sqlite3 *db, bool cancellable)
{
    if (db && cancellable)
        sqlite3_progress_handler(db, 0, NULL, NULL);
    if (db)
        sqlite3_close(db);
}

#ifdef ZCL_TESTING
int api_cache_test_sqlite_progress(void *ctx)
{
    return api_cache_sqlite_progress(ctx);
}
#endif

static int64_t api_hodl_cap_to_served_tip(int64_t index_tip)
{
    if (index_tip < 0)
        return index_tip;
    int64_t served_tip = api_served_tip_height();
    if (served_tip >= 0 && index_tip > served_tip)
        return served_tip;
    return index_tip;
}

static int64_t api_hodl_tip_from_db(sqlite3 *db, int64_t *block_tip_out,
                                    int64_t *utxo_tip_out)
{
    int64_t block_tip;
    int64_t utxo_tip;

    if (!db) {
        if (block_tip_out)
            *block_tip_out = -1;
        if (utxo_tip_out)
            *utxo_tip_out = -1;
        LOG_RETURN(-1, "api", "api_hodl_tip_from_db: NULL db");
    }

    block_tip = sql_query_i64(db, "SELECT COALESCE(MAX(height),0) FROM blocks");
    utxo_tip = sql_query_i64(db, "SELECT COALESCE(MAX(height),0) FROM utxos");
    if (block_tip_out)
        *block_tip_out = block_tip;
    if (utxo_tip_out)
        *utxo_tip_out = utxo_tip;
    return block_tip > utxo_tip ? block_tip : utxo_tip;
}

int64_t api_hodl_index_tip_height(void)
{
    char db_path[1024];
    sqlite3 *db = NULL;
    int64_t tip;

    if (!g_api_ctx.datadir)
        LOG_RETURN(-1, "api", "api_hodl_index_tip_height: no datadir");

    snprintf(db_path, sizeof(db_path), "%s/node.db", g_api_ctx.datadir);
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        LOG_RETURN(-1, "api", "api_hodl_index_tip_height: open %s failed",
                   db_path);
    }
    tip = api_hodl_tip_from_db(db, NULL, NULL);
    sqlite3_close(db);
    return tip;
}

int64_t api_hodl_current_tip_height(void)
{
    int64_t index_tip = api_hodl_index_tip_height();
    return api_hodl_cap_to_served_tip(index_tip);
}

bool api_hodl_index_ahead_of_served(int64_t *index_tip_out,
                                    int64_t *served_tip_out)
{
    char db_path[1024];
    sqlite3 *db = NULL;
    int64_t index_tip;
    int64_t served_tip;

    if (!g_api_ctx.datadir)
        LOG_RETURN(false, "api", "api_hodl_index_ahead_of_served: no datadir");

    snprintf(db_path, sizeof(db_path), "%s/node.db", g_api_ctx.datadir);
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        LOG_RETURN(false, "api", "api_hodl_index_ahead_of_served: open %s failed",
                   db_path);
    }
    index_tip = api_hodl_tip_from_db(db, NULL, NULL);
    sqlite3_close(db);
    served_tip = api_hodl_cap_to_served_tip(index_tip);
    if (index_tip_out)
        *index_tip_out = index_tip;
    if (served_tip_out)
        *served_tip_out = served_tip;
    return index_tip >= 0 && served_tip >= 0 && index_tip > served_tip;
}

size_t compute_blocks(uint8_t *r, size_t max)
{
    char buf[65536];

    /* Get current height */
    if (api_rpc_call("getblockcount", "[]", buf, sizeof(buf)) <= 0)
        return api_json_error(r, max, JSON_500_HEADERS, "RPC unavailable");

    int64_t height = zcl_json_int(buf, "result");
    if (height < 0)
        return api_json_error(r, max, JSON_500_HEADERS, "Cannot get block count");

    int count = 25;
    if (height < count) count = (int)height + 1;

    struct json_value body;
    struct json_value blocks;
    json_init(&body);
    json_set_object(&body);
    json_push_kv_str(&body, "schema", "zcl.blocks.index.v1");
    api_json_add_freshness(&body, "served_height", height);
    json_push_kv_int(&body, "height", height);
    json_push_kv_int(&body, "limit", count);

    json_init(&blocks);
    json_set_array(&blocks);
    for (int i = 0; i < count; i++) {
        int64_t h = height - i;
        char params[64];
        snprintf(params, sizeof(params), "[%" PRId64 "]", h);
        if (api_rpc_call("getblockhash", params, buf, sizeof(buf)) <= 0)
            continue;

        char hash[65] = "";
        zcl_json_extract_str(buf, "result", hash, sizeof(hash));
        if (!hash[0]) continue;

        char params2[128];
        snprintf(params2, sizeof(params2), "[\"%s\", true]", hash);
        if (api_rpc_call("getblock", params2, buf, sizeof(buf)) <= 0)
            continue;

        int64_t blk_time = zcl_json_int(buf, "time");
        double diff = zcl_json_real(buf, "difficulty");

        /* Count transactions */
        int tx_count = explorer_count_json_tx_array(buf);

        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        json_push_kv_int(&item, "height", h);
        json_push_kv_str(&item, "hash", hash);
        json_push_kv_int(&item, "time", blk_time);
        json_push_kv_int(&item, "num_tx", tx_count);
        json_push_kv_real(&item, "difficulty", diff);
        json_push_back(&blocks, &item);
        json_free(&item);
    }

    json_push_kv(&body, "blocks", &blocks);
    json_push_kv_int(&body, "count", (int64_t)json_size(&blocks));
    json_free(&blocks);

    size_t n = api_json_ok(r, max, &body);
    json_free(&body);
    return n;
}
size_t compute_stats(uint8_t *r, size_t max)
{
    char buf[65536];

    /* Get blockchain info */
    if (api_rpc_call("getblockchaininfo", "[]", buf, sizeof(buf)) <= 0)
        return api_json_error(r, max, JSON_500_HEADERS, "RPC unavailable");

    int64_t height = zcl_json_int(buf, "blocks");
    double diff = zcl_json_real(buf, "difficulty");

    char chain[32] = "";
    zcl_json_extract_str(buf, "chain", chain, sizeof(chain));

    /* Get mining info for hashrate */
    char mbuf[8192];
    double hashrate = 0.0;
    if (api_rpc_call("getmininginfo", "[]", mbuf, sizeof(mbuf)) > 0)
        hashrate = zcl_json_real(mbuf, "networkhashps");

    double supply = (double)zcl_total_supply_zatoshi(height) / (double)ZATOSHI_PER_ZCL;

    /* UTXO count via gettxoutsetinfo — expensive, skip if too slow */
    int64_t utxo_count = -1;
    char ubuf[8192];
    if (api_rpc_call("gettxoutsetinfo", "[]", ubuf, sizeof(ubuf)) > 0)
        utxo_count = zcl_json_int(ubuf, "txouts");

    struct json_value body;
    json_init(&body);
    json_set_object(&body);
    json_push_kv_str(&body, "schema", "zcl.stats.v1");
    api_json_add_freshness(&body, "served_height", height);
    json_push_kv_int(&body, "height", height);
    json_push_kv_real(&body, "difficulty", diff);
    json_push_kv_real(&body, "networkhashps", hashrate);
    json_push_kv_real(&body, "supply", supply);
    json_push_kv_str(&body, "chain", chain);
    if (utxo_count >= 0)
        json_push_kv_int(&body, "utxo_count", utxo_count);

    size_t n = api_json_ok(r, max, &body);
    json_free(&body);
    return n;
}
size_t compute_supply(uint8_t *r, size_t max)
{
    char buf[8192];

    if (api_rpc_call("getblockcount", "[]", buf, sizeof(buf)) <= 0)
        return api_json_error(r, max, JSON_500_HEADERS, "RPC unavailable");

    int64_t height = zcl_json_int(buf, "result");
    if (height < 0)
        return api_json_error(r, max, JSON_500_HEADERS, "Cannot get height");

    int64_t supply_sat = zcl_total_supply_zatoshi(height);
    double supply = (double)supply_sat / (double)ZATOSHI_PER_ZCL;

    struct json_value body;
    json_init(&body);
    json_set_object(&body);
    json_push_kv_str(&body, "schema", "zcl.supply.v1");
    api_json_add_freshness(&body, "served_height", height);
    json_push_kv_int(&body, "height", height);
    json_push_kv_int(&body, "supply_zatoshi", supply_sat);
    json_push_kv_real(&body, "supply", supply);

    size_t n = api_json_ok(r, max, &body);
    json_free(&body);
    return n;
}

size_t compute_supply_legacy(uint8_t *r, size_t max)
{
    char buf[8192];

    if (api_rpc_call("getblockcount", "[]", buf, sizeof(buf)) <= 0)
        return api_json_error(r, max, JSON_500_HEADERS, "RPC unavailable");

    int64_t height = zcl_json_int(buf, "result");
    if (height < 0)
        return api_json_error(r, max, JSON_500_HEADERS, "Cannot get height");

    double supply = (double)zcl_total_supply_zatoshi(height) /
                    (double)ZATOSHI_PER_ZCL;

    /* Plain number -- CoinGecko expects just a number */
    return (size_t)snprintf((char *)r, max,
        "%s%.8f", JSON_HEADERS, supply);
}
static size_t compute_hodl_impl(uint8_t *r, size_t max, bool cancellable)
{
    if (!g_api_ctx.datadir)
        return api_json_error(r, max, JSON_503_HEADERS,
                              "HODL datadir unavailable");

    char db_path[1024];
    snprintf(db_path, sizeof(db_path), "%s/node.db", g_api_ctx.datadir);
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        return api_json_error(r, max, JSON_500_HEADERS, "Database unavailable");
    }
    api_cache_sqlite_guard(db, cancellable);

    int64_t block_tip = 0;
    int64_t utxo_tip = 0;
    int64_t index_tip = api_hodl_tip_from_db(db, &block_tip, &utxo_tip);
    int64_t tip = api_hodl_cap_to_served_tip(index_tip);

    struct hodl_wave_snapshot hodl;
    if (!hodl_wave_scan_current_utxos(db, tip, &hodl)) {
        api_cache_sqlite_close(db, cancellable);
        return api_json_error(r, max, JSON_503_HEADERS, hodl.status);
    }
    api_cache_sqlite_close(db, cancellable);

    double over_1y_pct = hodl_wave_older_than_1y_percent(&hodl);

    struct json_value body;
    struct json_value older;
    struct json_value buckets;
    json_init(&body);
    json_set_object(&body);
    json_push_kv_str(&body, "schema", "zcl.hodl_wave.v1");
    json_push_kv_int(&body, "generated_at",
                     (int64_t)platform_time_wall_time_t());
    api_json_add_freshness(&body, "utxo_projection", index_tip);
    json_push_kv_str(&body, "source", hodl.source);
    json_push_kv_str(&body, "metric", hodl.metric);
    json_push_kv_str(&body, "status", hodl.status);
    json_push_kv_int(&body, "height", hodl.tip_height);
    json_push_kv_int(&body, "served_tip_height", tip);
    json_push_kv_int(&body, "indexed_tip_height", index_tip);
    json_push_kv_int(&body, "block_tip_height", block_tip);
    json_push_kv_int(&body, "utxo_tip_height", utxo_tip);
    json_push_kv_int(&body, "total_utxos", hodl.total_count);
    json_push_kv_real(&body, "total_value",
                      (double)hodl.total_value / (double)ZATOSHI_PER_ZCL);

    json_init(&older);
    json_set_object(&older);
    json_push_kv_real(&older, "value",
                      (double)hodl.older_than_1y_value /
                      (double)ZATOSHI_PER_ZCL);
    json_push_kv_real(&older, "percent", over_1y_pct);
    json_push_kv(&body, "older_than_1y", &older);
    json_free(&older);

    json_push_kv_int(&body, "skipped_rows", hodl.skipped_rows);
    json_init(&buckets);
    json_set_array(&buckets);
    for (int i = 0; i < HODL_WAVE_BUCKETS; i++) {
        double value_zcl = (double)hodl.buckets[i].value / (double)ZATOSHI_PER_ZCL;
        double pct = hodl.total_value > 0
            ? (double)hodl.buckets[i].value / (double)hodl.total_value * 100.0 : 0.0;

        struct json_value bucket;
        json_init(&bucket);
        json_set_object(&bucket);
        json_push_kv_str(&bucket, "label", hodl.buckets[i].label);
        json_push_kv_int(&bucket, "utxos", hodl.buckets[i].count);
        json_push_kv_real(&bucket, "value", value_zcl);
        json_push_kv_real(&bucket, "percent", pct);
        json_push_back(&buckets, &bucket);
        json_free(&bucket);
    }
    json_push_kv(&body, "buckets", &buckets);
    json_free(&buckets);

    size_t n = api_json_ok(r, max, &body);
    json_free(&body);
    return n;
}

size_t compute_hodl(uint8_t *r, size_t max)
{
    return compute_hodl_impl(r, max, false);
}

size_t compute_hodl_cache_refresh(uint8_t *r, size_t max)
{
    return compute_hodl_impl(r, max, true);
}

static size_t compute_deep_stats_impl(uint8_t *r, size_t max,
                                      bool cancellable)
{
    if (!g_api_ctx.datadir)
        return api_json_error(r, max, JSON_500_HEADERS, "No datadir");

    sqlite3 *db = NULL;
    if (!explorer_open_readonly_db(g_api_ctx.datadir, &db)) {
        return api_json_error(r, max, JSON_500_HEADERS, "Cannot open database");
    }
    api_cache_sqlite_guard(db, cancellable);

    struct explorer_chain_stats chain_stats = {0};
    explorer_query_chain_stats(db, &chain_stats);
    int64_t current_height = sql_query_i64(db,
        "SELECT COALESCE(MAX(height),0) FROM utxos");
    if (current_height < chain_stats.height)
        current_height = chain_stats.height;
    struct explorer_history_validation history;
    explorer_validate_block_history(db, current_height, &history);
    if (cancellable && !atomic_load(&g_api_cache_thread_running)) {
        api_cache_sqlite_close(db, true);
        return api_json_error(r, max, JSON_503_HEADERS,
                              "Deep statistics refresh cancelled");
    }
    if (!history.usable) {
        int64_t block_rows = sql_query_i64(db, "SELECT count(*) FROM blocks");
        int64_t tx_rows = sql_query_i64(db, "SELECT count(*) FROM transactions");
        int64_t utxo_count = sql_query_i64(db, "SELECT count(*) FROM utxos");
        int64_t utxo_value = sql_query_i64(db,
            "SELECT COALESCE(SUM(value),0) FROM utxos");
        int64_t supply_sat = zcl_total_supply_zatoshi(current_height);
        if (cancellable && !atomic_load(&g_api_cache_thread_running)) {
            api_cache_sqlite_close(db, true);
            return api_json_error(r, max, JSON_503_HEADERS,
                                  "Deep statistics refresh cancelled");
        }
        api_cache_sqlite_close(db, cancellable);

        struct json_value body;
        struct json_value utxo;
        struct json_value index;
        json_init(&body);
        json_set_object(&body);
        json_push_kv_str(&body, "schema", "zcl.stats.deep.v1");
        api_json_add_freshness(&body, "served_height", current_height);
        json_push_kv_bool(&body, "history_index_usable", false);
        json_push_kv_bool(&body, "unsafe_sections_suppressed", true);
        json_push_kv_str(&body, "reason", history.reason);
        json_push_kv_int(&body, "height", current_height);
        json_push_kv_real(&body, "supply",
                          (double)supply_sat / (double)ZATOSHI_PER_ZCL);

        json_init(&utxo);
        json_set_object(&utxo);
        json_push_kv_int(&utxo, "count", utxo_count);
        json_push_kv_real(&utxo, "value",
                          (double)utxo_value / (double)ZATOSHI_PER_ZCL);
        json_push_kv(&body, "utxo", &utxo);
        json_free(&utxo);

        json_init(&index);
        json_set_object(&index);
        json_push_kv_int(&index, "blocks", block_rows);
        json_push_kv_int(&index, "transactions", tx_rows);
        json_push_kv(&body, "index", &index);
        json_free(&index);

        size_t n = api_json_ok(r, max, &body);
        json_free(&body);
        return n;
    }
    struct explorer_transaction_stats transaction_stats = {0};
    explorer_query_transaction_stats(db, &transaction_stats);
    struct explorer_utxo_stats utxo_stats = {0};
    explorer_query_utxo_stats(db, &utxo_stats);
    struct explorer_address_stats address_stats = {0};
    explorer_query_address_stats(db, &address_stats);

    /* Sprout stats */
    struct explorer_privacy_stats privacy_stats = {0};
    explorer_query_privacy_stats(db, &privacy_stats);
    struct explorer_first_privacy_heights first_privacy = {0};
    explorer_query_first_privacy_heights(db, &first_privacy);

    /* Sapling stats */
    /* ZSLP stats */
    struct explorer_token_stats token_stats = {0};
    explorer_query_token_stats(db, &token_stats);

    int64_t supply_sat = zcl_total_supply_zatoshi(chain_stats.height);

    /* Integrity: checkpoint count and latest block hash */
    char latest_hash[128] = "";
    sql_query_text(db,
        "SELECT hex(hash) FROM blocks WHERE height = (SELECT MAX(height) FROM blocks)",
        latest_hash, sizeof(latest_hash));

    if (cancellable && !atomic_load(&g_api_cache_thread_running)) {
        api_cache_sqlite_close(db, true);
        return api_json_error(r, max, JSON_503_HEADERS,
                              "Deep statistics refresh cancelled");
    }
    api_cache_sqlite_close(db, cancellable);

    struct json_value body;
    struct json_value sprout;
    struct json_value sapling;
    struct json_value utxo;
    struct json_value addresses;
    struct json_value zslp;
    struct json_value integrity;

    json_init(&body);
    json_set_object(&body);
    json_push_kv_str(&body, "schema", "zcl.stats.deep.v1");
    api_json_add_freshness(&body, "served_height", current_height);
    json_push_kv_bool(&body, "history_index_usable", true);
    json_push_kv_bool(&body, "unsafe_sections_suppressed", false);
    json_push_kv_int(&body, "height", chain_stats.height);
    json_push_kv_int(&body, "blocks", chain_stats.blocks);
    json_push_kv_int(&body, "transactions", transaction_stats.total);
    json_push_kv_real(&body, "supply",
                      (double)supply_sat / (double)ZATOSHI_PER_ZCL);
    json_push_kv_real(&body, "shielded_net",
                      (double)privacy_stats.net_shielded_sat /
                      (double)ZATOSHI_PER_ZCL);

    json_init(&sprout);
    json_set_object(&sprout);
    json_push_kv_int(&sprout, "joinsplits", privacy_stats.joinsplits);
    json_push_kv_int(&sprout, "first_height",
                     first_privacy.joinsplit_height);
    json_push_kv(&body, "sprout", &sprout);
    json_free(&sprout);

    json_init(&sapling);
    json_set_object(&sapling);
    json_push_kv_int(&sapling, "spends", privacy_stats.sapling_spends);
    json_push_kv_int(&sapling, "outputs", privacy_stats.sapling_outputs);
    json_push_kv_int(&sapling, "first_height",
                     first_privacy.sapling_height);
    json_push_kv(&body, "sapling", &sapling);
    json_free(&sapling);

    json_init(&utxo);
    json_set_object(&utxo);
    json_push_kv_int(&utxo, "count", utxo_stats.count);
    json_push_kv_int(&utxo, "dust_under_0001", utxo_stats.dust_under_0001);
    json_push_kv(&body, "utxo", &utxo);
    json_free(&utxo);

    json_init(&addresses);
    json_set_object(&addresses);
    json_push_kv_int(&addresses, "total", address_stats.total);
    json_push_kv_int(&addresses, "nonzero", address_stats.nonzero);
    json_push_kv(&body, "addresses", &addresses);
    json_free(&addresses);

    json_init(&zslp);
    json_set_object(&zslp);
    json_push_kv_int(&zslp, "tokens", token_stats.token_count);
    json_push_kv_int(&zslp, "transfers", token_stats.transfer_count);
    json_push_kv(&body, "zslp", &zslp);
    json_free(&zslp);

    json_init(&integrity);
    json_set_object(&integrity);
    json_push_kv_int(&integrity, "indexed_blocks", chain_stats.blocks);
    json_push_kv_str(&integrity, "latest_hash", latest_hash);
    json_push_kv(&body, "integrity", &integrity);
    json_free(&integrity);

    size_t n = api_json_ok(r, max, &body);
    json_free(&body);
    return n;
}

size_t compute_deep_stats(uint8_t *r, size_t max)
{
    return compute_deep_stats_impl(r, max, false);
}

size_t compute_deep_stats_cache_refresh(uint8_t *r, size_t max)
{
    return compute_deep_stats_impl(r, max, true);
}
