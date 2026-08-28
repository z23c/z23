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
#include "json/json.h"
#include "keys/key_io.h"
#include "models/block.h"
#include "models/database.h"
#include "models/file_service.h"
#include "models/hodl_wave.h"
#include "models/onion_announcement.h"
#include "models/peer.h"
#include "net/peer_lifecycle.h"
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

#include <arpa/inet.h>
#include <ctype.h>
#include <inttypes.h>
#include <math.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* REST resource collection handlers: zslp, onion, file-services, peers. Served directly from SQLite — no cache, no RPC. */

bool api_is_printable_ascii(const char *s)
{
    if (!s || !s[0])
        return false;
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        if (*p < 32 || *p > 126)
            return false;
    }
    return true;
}

struct node_db *api_node_db(void)
{
    return g_api_ctx.node_db ? g_api_ctx.node_db : app_runtime_node_db();
}

bool api_parse_zslp_limit(const char *path, size_t *limit_out)
{
    const char *q;
    const char *lp;
    char *end = NULL;
    long value;

    if (!limit_out)
        LOG_FAIL("api", "parse_zslp_limit: NULL limit_out");
    *limit_out = 50;
    q = strchr(path, '?');
    if (!q)
        return true;
    lp = strstr(q, "limit=");
    if (!lp)
        return true;
    value = strtol(lp + 6, &end, 10);
    if (!end || (*end != '\0' && *end != '&') || value <= 0 || value > 64)
        LOG_FAIL("api", "parse_zslp_limit: invalid limit value");
    *limit_out = (size_t)value;
    return true;
}

bool api_parse_collection_limit(const char *path,
                                       const char *query_key,
                                       size_t default_limit,
                                       size_t max_limit,
                                       size_t *limit_out)
{
    const char *q;
    const char *lp;
    char *end = NULL;
    long value;
    char needle[64];

    if (!path || !query_key || !limit_out || default_limit == 0 ||
        max_limit == 0 || default_limit > max_limit)
        LOG_FAIL("api", "parse_collection_limit: invalid parameters (key=%s)", query_key ? query_key : "NULL");
    *limit_out = default_limit;
    q = strchr(path, '?');
    if (!q)
        return true;
    snprintf(needle, sizeof(needle), "%s=", query_key);
    lp = strstr(q, needle);
    if (!lp)
        return true;
    value = strtol(lp + strlen(needle), &end, 10);
    if (!end || (*end != '\0' && *end != '&') || value <= 0 ||
        (size_t)value > max_limit)
        LOG_FAIL("api", "parse_collection_limit: invalid %s value (max=%zu)", query_key, max_limit);
    *limit_out = (size_t)value;
    return true;
}

size_t api_serve_zslp_tokens(const char *path, uint8_t *response,
                                    size_t response_max)
{
    struct node_db *ndb = api_node_db();
    struct db_zslp_token_info tokens[64];
    size_t limit = 50;
    int count;
    struct json_value root;
    struct json_value arr;

    if (!ndb || !ndb->db)
        return api_json_error(response, response_max, JSON_500_HEADERS, "No database");
    if (!api_parse_zslp_limit(path, &limit))
        return api_json_error(response, response_max, JSON_404_HEADERS,
                          "Invalid limit parameter");

    count = db_zslp_token_list(ndb, tokens, limit);
    json_init(&root);
    json_set_object(&root);
    json_push_kv_str(&root, "schema", "zcl.zslp_tokens.index.v1");
    api_json_add_freshness(&root, "zslp_projection",
                           db_zslp_max_height(ndb));
    json_push_kv_int(&root, "limit", (int64_t)limit);

    json_init(&arr);
    json_set_array(&arr);
    for (int i = 0; i < count; i++) {
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        json_push_kv_str(&item, "token_id", tokens[i].token_id);
        json_push_kv_str(&item, "ticker", tokens[i].ticker);
        json_push_kv_str(&item, "name", tokens[i].name);
        json_push_kv_int(&item, "decimals", tokens[i].decimals);
        json_push_kv_int(&item, "genesis_height",
                         tokens[i].genesis_height);
        json_push_kv_int(&item, "total_minted",
                         tokens[i].total_minted);
        json_push_back(&arr, &item);
        json_free(&item);
    }
    json_push_kv(&root, "tokens", &arr);
    json_free(&arr);

    size_t n = api_json_ok(response, response_max, &root);
    json_free(&root);
    return n;
}

size_t api_serve_zslp_token(const char *token_id, uint8_t *response,
                                   size_t response_max)
{
    struct node_db *ndb = api_node_db();
    struct db_zslp_token_info token;
    struct json_value root;

    if (!ndb || !ndb->db)
        return api_json_error(response, response_max, JSON_500_HEADERS, "No database");
    if (!api_is_printable_ascii(token_id) ||
        !zslp_service_validate_token_key(token_id).ok)
        return api_json_error(response, response_max, JSON_404_HEADERS,
                          "Invalid token id");
    if (!db_zslp_token_find(ndb, token_id, &token))
        return api_json_error(response, response_max, JSON_404_HEADERS,
                          "Token not found");

    json_init(&root);
    json_set_object(&root);
    json_push_kv_str(&root, "schema", "zcl.zslp_tokens.show.v1");
    api_json_add_freshness(&root, "zslp_projection",
                           db_zslp_max_height(ndb));
    json_push_kv_str(&root, "token_id", token.token_id);
    json_push_kv_str(&root, "ticker", token.ticker);
    json_push_kv_str(&root, "name", token.name);
    json_push_kv_int(&root, "decimals", token.decimals);
    json_push_kv_int(&root, "genesis_height", token.genesis_height);
    json_push_kv_int(&root, "total_minted", token.total_minted);

    size_t n = api_json_ok(response, response_max, &root);
    json_free(&root);
    return n;
}

size_t api_serve_zslp_token_transfers(const char *path,
                                             const char *token_id,
                                             uint8_t *response,
                                             size_t response_max)
{
    struct node_db *ndb = api_node_db();
    struct db_zslp_transfer_info transfers[64];
    size_t limit = 50;
    int count;
    struct json_value root;
    struct json_value arr;

    if (!ndb || !ndb->db)
        return api_json_error(response, response_max, JSON_500_HEADERS, "No database");
    if (!api_is_printable_ascii(token_id) ||
        !zslp_service_validate_token_key(token_id).ok)
        return api_json_error(response, response_max, JSON_404_HEADERS,
                          "Invalid token id");
    if (!api_parse_zslp_limit(path, &limit))
        return api_json_error(response, response_max, JSON_404_HEADERS,
                          "Invalid limit parameter");

    count = db_zslp_transfer_list_by_token(ndb, token_id, transfers, limit);
    json_init(&root);
    json_set_object(&root);
    json_push_kv_str(&root, "schema",
                     "zcl.zslp_token_transfers.index.v1");
    api_json_add_freshness(&root, "zslp_projection",
                           db_zslp_max_height(ndb));
    json_push_kv_str(&root, "token_id", token_id);
    json_push_kv_int(&root, "limit", (int64_t)limit);

    json_init(&arr);
    json_set_array(&arr);
    for (int i = 0; i < count; i++) {
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        json_push_kv_str(&item, "txid", transfers[i].txid);
        json_push_kv_str(&item, "token_id", transfers[i].token_id);
        json_push_kv_int(&item, "block_height", transfers[i].block_height);
        json_push_kv_int(&item, "tx_type", transfers[i].tx_type);
        json_push_kv_int(&item, "amount", transfers[i].amount);
        json_push_kv_int(&item, "vout", transfers[i].vout);
        if (transfers[i].to_addr_hex[0])
            json_push_kv_str(&item, "to_addr_hex",
                             transfers[i].to_addr_hex);
        json_push_back(&arr, &item);
        json_free(&item);
    }
    json_push_kv(&root, "transfers", &arr);
    json_free(&arr);

    size_t n = api_json_ok(response, response_max, &root);
    json_free(&root);
    return n;
}

size_t api_serve_onion_announcements(const char *path,
                                            uint8_t *response,
                                            size_t response_max)
{
    struct node_db *ndb = api_node_db();
    struct db_onion_announcement rows[32];
    size_t limit = 16;
    int count;
    struct json_value root;
    struct json_value arr;

    if (!ndb || !ndb->db)
        return api_json_error(response, response_max, JSON_500_HEADERS, "No database");
    if (!api_parse_collection_limit(path, "limit", 16, 32, &limit))
        return api_json_error(response, response_max, JSON_404_HEADERS,
                          "Invalid limit parameter");
    memset(rows, 0, sizeof(rows));
    count = db_onion_announcement_recent(ndb, rows, limit);
    json_init(&root);
    json_set_object(&root);
    json_push_kv_str(&root, "schema",
                     "zcl.onion_announcements.index.v1");
    api_json_add_freshness(&root, "onion_projection", -1);
    json_push_kv_int(&root, "limit", (int64_t)limit);

    json_init(&arr);
    json_set_array(&arr);
    for (int i = 0; i < count; i++) {
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        json_push_kv_str(&item, "onion_address", rows[i].onion_address);
        json_push_kv_int(&item, "announced_at", rows[i].announced_at);
        json_push_kv_str(&item, "script_hex", rows[i].script_hex);
        json_push_back(&arr, &item);
        json_free(&item);
    }
    json_push_kv(&root, "announcements", &arr);
    json_free(&arr);

    size_t n = api_json_ok(response, response_max, &root);
    json_free(&root);
    return n;
}

size_t api_serve_file_services(const char *path,
                                      uint8_t *response,
                                      size_t response_max)
{
    struct node_db *ndb = api_node_db();
    struct db_file_service rows[32];
    size_t limit = 16;
    int count;
    struct json_value root;
    struct json_value arr;

    if (!ndb || !ndb->db)
        return api_json_error(response, response_max, JSON_500_HEADERS, "No database");
    if (!api_parse_collection_limit(path, "limit", 16, 32, &limit))
        return api_json_error(response, response_max, JSON_404_HEADERS,
                          "Invalid limit parameter");
    memset(rows, 0, sizeof(rows));
    count = db_file_service_recent(ndb, rows, limit);
    json_init(&root);
    json_set_object(&root);
    json_push_kv_str(&root, "schema", "zcl.file_services.index.v1");
    api_json_add_freshness(&root, "file_service_projection", -1);
    json_push_kv_int(&root, "limit", (int64_t)limit);

    json_init(&arr);
    json_set_array(&arr);
    for (int i = 0; i < count; i++) {
        char ip_hex[33];
        for (int j = 0; j < 16; j++)
            snprintf(ip_hex + j * 2, 3, "%02x", rows[i].ip[j]);
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        json_push_kv_str(&item, "ip", ip_hex);
        json_push_kv_int(&item, "port", rows[i].port);
        json_push_kv_int(&item, "p2p_port", rows[i].p2p_port);
        json_push_kv_int(&item, "last_seen", rows[i].last_seen);
        json_push_kv_bool(&item, "is_zcl23", rows[i].is_zcl23);
        json_push_back(&arr, &item);
        json_free(&item);
    }
    json_push_kv(&root, "file_services", &arr);
    json_free(&arr);

    size_t n = api_json_ok(response, response_max, &root);
    json_free(&root);
    return n;
}

static bool api_peer_addr_key(const struct db_peer *peer,
                              char *out, size_t out_sz);

size_t api_serve_peers(const char *path,
                              uint8_t *response,
                              size_t response_max)
{
    struct node_db *ndb = api_node_db();
    struct db_peer rows[32];
    size_t limit = 16;
    int count;
    struct json_value root;
    struct json_value arr;

    if (!ndb || !ndb->db)
        return api_json_error(response, response_max, JSON_500_HEADERS, "No database");
    if (!api_parse_collection_limit(path, "limit", 16, 32, &limit))
        return api_json_error(response, response_max, JSON_404_HEADERS,
                          "Invalid limit parameter");
    memset(rows, 0, sizeof(rows));
    count = db_peer_recent(ndb, rows, limit);
    json_init(&root);
    json_set_object(&root);
    json_push_kv_str(&root, "schema", "zcl.peers.index.v1");
    api_json_add_freshness(&root, "peer_projection", -1);
    json_push_kv_int(&root, "limit", (int64_t)limit);

    json_init(&arr);
    json_set_array(&arr);
    for (int i = 0; i < count; i++) {
        char ip_hex[33];
        char src_hex[33];
        char addr_key[256] = {0};
        struct json_value live_lifecycle = {0};
        bool live_peer = false;
        bool live_zclassic23 = false;
        bool live_fast_sync_useful = false;
        const char *bootstrap_readiness = "unknown";
        const char *zclassic23_verified_by = "not_verified";

        for (int j = 0; j < 16; j++) {
            snprintf(ip_hex + j * 2, 3, "%02x", rows[i].ip[j]);
            snprintf(src_hex + j * 2, 3, "%02x", rows[i].source[j]);
        }
        json_init(&live_lifecycle);
        if (api_peer_addr_key(&rows[i], addr_key, sizeof(addr_key)))
            live_peer = peer_lifecycle_addr_json(addr_key, &live_lifecycle);
        if (live_peer) {
            live_zclassic23 =
                json_get_bool(json_get(&live_lifecycle, "zclassic23"));
            live_fast_sync_useful =
                json_get_bool(json_get(&live_lifecycle,
                                       "fast_sync_useful"));
            bootstrap_readiness =
                json_get_str(json_get(&live_lifecycle,
                                      "bootstrap_readiness"));
            if (live_zclassic23)
                zclassic23_verified_by = "live_handshake";
        }
        if (!live_zclassic23 && rows[i].is_zcl23)
            zclassic23_verified_by = "peer_projection";

        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        json_push_kv_str(&item, "ip", ip_hex);
        if (addr_key[0])
            json_push_kv_str(&item, "addr", addr_key);
        json_push_kv_int(&item, "port", rows[i].port);
        json_push_kv_int(&item, "services", (int64_t)rows[i].services);
        json_push_kv_int(&item, "last_seen", rows[i].last_seen);
        json_push_kv_int(&item, "last_try", rows[i].last_try);
        json_push_kv_int(&item, "attempts", rows[i].attempts);
        json_push_kv_int(&item, "bandwidth_score",
                         (int64_t)rows[i].bandwidth_score);
        json_push_kv_bool(&item, "projection_is_zcl23",
                          rows[i].is_zcl23);
        json_push_kv_bool(&item, "live_peer", live_peer);
        json_push_kv_bool(&item, "live_zclassic23", live_zclassic23);
        json_push_kv_bool(&item, "is_zcl23",
                          rows[i].is_zcl23 || live_zclassic23);
        json_push_kv_str(&item, "zclassic23_verified_by",
                         zclassic23_verified_by);
        json_push_kv_bool(&item, "zclassic23_projection_stale",
                          live_zclassic23 && !rows[i].is_zcl23);
        json_push_kv_str(&item, "bootstrap_readiness",
                         bootstrap_readiness);
        json_push_kv_bool(&item, "fast_sync_useful",
                          live_fast_sync_useful);
        if (live_peer)
            json_push_kv(&item, "live_lifecycle", &live_lifecycle);
        if (rows[i].has_source)
            json_push_kv_str(&item, "source", src_hex);
        json_push_back(&arr, &item);
        json_free(&item);
        json_free(&live_lifecycle);
    }
    json_push_kv(&root, "peers", &arr);
    json_free(&arr);

    size_t n = api_json_ok(response, response_max, &root);
    json_free(&root);
    return n;
}

static bool api_peer_addr_key(const struct db_peer *peer,
                              char *out, size_t out_sz)
{
    struct net_service svc;

    if (!peer || !out || out_sz == 0)
        return false;

    net_service_init(&svc);
    memcpy(svc.addr.ip, peer->ip, sizeof(svc.addr.ip));
    svc.port = peer->port;
    return net_service_to_string(&svc, out, out_sz) > 0 && out[0] != '\0';
}
