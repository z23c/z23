/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Fixed REST resource routes. The main router handles dynamic member paths;
 * this table owns exact resource/controller/action dispatch and /api/v1
 * canonicalization. */

#include "api_controller_internal.h"

#include "controllers/file_market_controller.h"
#include "controllers/game_controller.h"
#include "controllers/health_controller.h"
#include "controllers/messaging_controller.h"
#include "controllers/name_controller.h"
#include "controllers/network_controller.h"
#include "controllers/swap_controller.h"
#include "hotswap/hotswap.h"
#include "json/json.h"
#include "models/zslp.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#define API_ROUTE(method_, path_, resource_, action_, handler_, schema_, \
                  query_, freshness_, alias_, private_, command_path_) \
    { method_, path_, resource_, action_, handler_, schema_, query_, \
      freshness_, alias_, private_, command_path_ }

static const struct api_resource_route k_api_resource_routes[] = {
    API_ROUTE("GET", "/api", "api", "index", api_serve_api_index,
              ZCL_REST_INDEX_SCHEMA, "", "static", "", false,
              "none:rest-self-description-not-a-command-leaf"),
    API_ROUTE("GET", "/api/openapi", "openapi", "show", api_serve_openapi,
              ZCL_REST_OPENAPI_SCHEMA, "", "static", "", false,
              "none:openapi-self-description-not-a-command-leaf"),
    API_ROUTE("GET", "/api/agent", "agent", "show", api_serve_node_summary,
              ZCL_PUBLIC_STATUS_SCHEMA, "", "served_tip", "", false,
              "core.status"),
    API_ROUTE("GET", "/api/status", "agent", "show", api_serve_node_summary,
              ZCL_PUBLIC_STATUS_SCHEMA, "", "served_tip",
              "/api/v1/agent", false, "core.status"),
    API_ROUTE("GET", "/api/milestone", "milestone", "show",
              api_serve_milestone, ZCL_MILESTONE_STATUS_SCHEMA, "",
              "operator_status", "", false,
              "none:mvp-milestone-tracker-no-command-leaf"),
    API_ROUTE("GET", "/api/refold", "refold", "show",
              api_serve_refold_status, ZCL_REFOLD_STATUS_SCHEMA, "",
              "anchor_snapshot", "", false, "ops.recovery.status"),
    API_ROUTE("GET", "/api/node", "node", "show", api_serve_node_summary,
              ZCL_PUBLIC_STATUS_SCHEMA, "", "served_tip", "", false,
              "core.status"),
    API_ROUTE("GET", "/api/node/summary", "node", "summary",
              api_serve_node_summary, ZCL_PUBLIC_STATUS_SCHEMA, "",
              "served_tip", "", false, "core.status"),
    API_ROUTE("GET", "/api/node/status", "node", "status",
              api_serve_node_status, "zcl.node_status.v1", "",
              "served_tip", "", false,
              "none:composite-diagnostics-no-single-leaf-owns-this-shape"),
    API_ROUTE("GET", "/api/node/snapshot", "node", "snapshot",
              api_serve_node_snapshot, "zcl.node_snapshot.v1", "",
              "snapshot_sync_service", "", false,
              "none:snapshot-sync-service-no-command-leaf"),
    API_ROUTE("GET", "/api/node/mmb", "node", "mmb", api_serve_node_mmb,
              "zcl.node_mmb.v1", "", "mmb_projection", "", false,
              "core.consensus.mmb"),
    API_ROUTE("GET", "/api/health", "health", "show", api_serve_health,
              "zcl.health.v1", "", "served_tip", "", false, "ops.health"),
    API_ROUTE("GET", "/api/syncstate", "sync", "show", api_serve_syncstate,
              "zcl.syncstate.v1", "", "sync_projection", "", false,
              "core.sync.status"),
    API_ROUTE("GET", "/api/downloadstats", "downloads", "show",
              api_serve_downloadstats, "zcl.downloadstats.v1", "",
              "download_manager", "", false,
              "none:download-manager-projection-no-command-leaf"),
    API_ROUTE("GET", "/api/blocks", "blocks", "index", api_route_blocks,
              "zcl.blocks.index.v1", "", "served_height", "", false,
              "none:explorer-blocks-list-cache-no-command-leaf"),
    API_ROUTE("GET", "/api/stats", "stats", "index", api_route_stats,
              "zcl.stats.v1", "", "served_height", "", false,
              "none:explorer-stats-cache-no-command-leaf"),
    API_ROUTE("GET", "/api/stats/deep", "stats", "deep",
              api_route_deep_stats, "zcl.stats.deep.v1", "",
              "served_height", "", false,
              "none:explorer-deep-stats-cache-no-command-leaf"),
    API_ROUTE("GET", "/api/supply", "supply", "show", api_route_supply,
              "zcl.supply.v1", "", "served_height", "", false,
              "none:explorer-supply-cache-no-command-leaf"),
    API_ROUTE("GET", "/api/hodl", "hodl", "show", api_route_hodl,
              "zcl.hodl_wave.v1", "", "utxo_projection", "", false,
              "none:explorer-hodl-wave-cache-no-command-leaf"),
    API_ROUTE("GET", "/api/factoids", "factoids", "show",
              api_route_factoids, "zcl.factoids.v1", "",
              "served_height", "", false,
              "none:explorer-factoids-cache-no-command-leaf"),
    API_ROUTE("GET", "/api/wallet", "wallet", "show", api_serve_wallet,
              "zcl.wallet_status.v1", "", "wallet_projection", "", true,
              "core.wallet.status"),
    API_ROUTE("GET", "/api/builds", "builds", "index", api_serve_builds,
      "zcl.builds.index.v1", "", "build_ledger", "", true, "metaverse.build.status"),
    API_ROUTE("GET", "/api/build_workers", "build_workers", "index", api_serve_build_workers,
      "zcl.build_workers.index.v1", "", "build_ledger", "", true, "metaverse.build.worker.list"),
    API_ROUTE("GET", "/api/files/manifest", "files", "manifest",
              api_serve_files_manifest, "zcl.files_manifest.v1", "",
              "file_manifest", "", false,
              "none:file-market-manifest-no-command-leaf"),
};

typedef bool (*api_json_resource_handler)(struct json_value *result);

struct api_json_resource_route {
    const char *method;
    const char *path;
    const char *resource;
    const char *action;
    api_json_resource_handler handler;
    const char *response_schema;
    const char *query_params_csv;
    const char *freshness;
    const char *alias_of;
    bool private_route;
};

static const struct api_json_resource_route k_api_json_resource_routes[] = {
    { "GET", "/api/sync/detail", "sync", "detail", api_getsyncdetail,
      "zcl.sync.detail.v1", "", "sync_projection", "", false },
    { "GET", "/api/bootstrap", "bootstrap", "show",
      network_bootstrap_status_json, "zcl.bootstrap_status.v1", "",
      "network_bootstrap", "", false },
    { "GET", "/api/bootstrapstatus", "bootstrap", "show",
      network_bootstrap_status_json, "zcl.bootstrap_status.v1", "",
      "network_bootstrap", "/api/v1/bootstrap", false },
    { "GET", "/api/services", "services", "index", api_getservicehealth,
      "zcl.services.index.v1", "", "service_registry", "", false },
    { "GET", "/api/latency", "latency", "index", api_getpeerlatency,
      "zcl.latency.index.v1", "", "peer_projection", "", false },
    { "GET", "/api/games", "games", "index", api_gametypes,
      "zcl.games.index.v1", "", "static", "", false },
    { "GET", "/api/protocols", "protocols", "index",
      api_app_protocols_index_json, ZCL_APP_PROTOCOLS_INDEX_SCHEMA, "",
      "static", "", false },
    { "GET", "/api/transaction-types", "transaction_types", "index",
      zcl_transaction_types_index_json, ZCL_TRANSACTION_TYPES_INDEX_SCHEMA, "", "static", "", false },
    { "GET", "/api/service-catalog", "service_catalog", "show",
      api_service_catalog_json, ZCL_SERVICE_CATALOG_SCHEMA, "",
      "static", "", false },
    { "GET", "/api/names", "names", "index", api_name_list,
      "zcl.names.index.v1", "", "znam_projection", "", false },
    { "GET", "/api/market-contents", "market_contents", "index", api_market_content_list, "zcl.market_contents.index.v1", "", "market_content_registry", "", true },
    { "GET", "/api/swaps", "swaps", "index", api_swap_list,
      "zcl.swaps.index.v1", "", "swap_projection", "", true },
    { "GET", "/api/swaps/chains", "swaps", "chains", api_swap_chains,
      "zcl.swaps.chains.v1", "", "static", "", false },
    { "GET", "/api/swap_chains", "swaps", "chains", api_swap_chains,
      "zcl.swaps.chains.v1", "", "static", "/api/v1/swaps/chains", false },
    { "GET", "/api/messages", "messages", "index", api_msg_inbox, "zcl.messages.index.v1", "", "message_projection", "", true },
    { "GET", "/api/messages/index", "messages", "index_window", api_msg_inbox_index, "zcl.messages.index.v2", "", "message_projection", "", true },
};

enum api_dynamic_dispatch_kind {
    API_DYN_BLOCK_SHOW,
    API_DYN_TX_SHOW,
    API_DYN_ADDRESS_SHOW,
    API_DYN_ZSLP_TOKENS_INDEX,
    API_DYN_ZSLP_TOKEN_SHOW,
    API_DYN_ZSLP_TOKEN_TRANSFERS,
    API_DYN_ONION_ANNOUNCEMENTS_INDEX,
    API_DYN_FILE_SERVICES_INDEX,
    API_DYN_PEERS_INDEX,
    API_DYN_EVENTS_INDEX,
    API_DYN_FILE_SHOW,
    API_DYN_NAME_SERVICES,
    API_DYN_NAME_SHOW,
    API_DYN_PROTOCOL_SHOW, API_DYN_TRANSACTION_TYPE_SHOW,
    API_DYN_SERVICE_CATALOG_SHOW,
    API_DYN_SERVICE_OPERATIONS_INDEX,
    API_DYN_SERVICE_OPERATION_SHOW,
    API_DYN_BUILD_SHOW, API_DYN_BUILD_ACTIONS_INDEX, API_DYN_BUILD_RECEIPT_SHOW,
    API_DYN_MARKET_INDEX,
};

struct api_dynamic_resource_route {
    const char *method;
    const char *pattern;
    const char *resource;
    const char *action;
    const char *response_schema;
    const char *query_params_csv;
    const char *freshness;
    const char *alias_of;
    bool private_route;
    enum api_dynamic_dispatch_kind dispatch_kind;
};

static const struct api_dynamic_resource_route k_api_dynamic_resource_routes[] = {
    { "GET", "/api/blocks/{height_or_hash}", "blocks", "show",
      "zcl.blocks.show.v1", "", "served_height", "", false,
      API_DYN_BLOCK_SHOW },
    { "GET", "/api/block/{height_or_hash}", "blocks", "show",
      "zcl.blocks.show.v1", "", "served_height",
      "/api/v1/blocks/{height_or_hash}", false, API_DYN_BLOCK_SHOW },
    { "GET", "/api/transactions/{txid}", "transactions", "show",
      "zcl.transactions.show.v1", "", "served_height", "", false,
      API_DYN_TX_SHOW },
    { "GET", "/api/tx/{txid}", "transactions", "show",
      "zcl.transactions.show.v1", "", "served_height",
      "/api/v1/transactions/{txid}", false, API_DYN_TX_SHOW },
    { "GET", "/api/addresses/{address}", "addresses", "show",
      "zcl.addresses.show.v1", "", "utxo_projection", "", false,
      API_DYN_ADDRESS_SHOW },
    { "GET", "/api/address/{address}", "addresses", "show",
      "zcl.addresses.show.v1", "", "utxo_projection",
      "/api/v1/addresses/{address}", false, API_DYN_ADDRESS_SHOW },
    { "GET", "/api/zslp/tokens", "zslp_tokens", "index",
      "zcl.zslp_tokens.index.v1", "limit", "zslp_projection", "", false,
      API_DYN_ZSLP_TOKENS_INDEX },
    { "GET", "/api/zslp/tokens/{token_id}/transfers",
      "zslp_token_transfers", "index", "zcl.zslp_token_transfers.index.v1",
      "limit", "zslp_projection", "", false,
      API_DYN_ZSLP_TOKEN_TRANSFERS },
    { "GET", "/api/zslp/tokens/{token_id}", "zslp_tokens", "show",
      "zcl.zslp_tokens.show.v1", "", "zslp_projection", "", false,
      API_DYN_ZSLP_TOKEN_SHOW },
    { "GET", "/api/onion/announcements", "onion_announcements", "index",
      "zcl.onion_announcements.index.v1", "limit",
      "onion_projection", "", false, API_DYN_ONION_ANNOUNCEMENTS_INDEX },
    { "GET", "/api/file-services", "file_services", "index",
      "zcl.file_services.index.v1", "limit", "file_service_projection",
      "", false, API_DYN_FILE_SERVICES_INDEX },
    { "GET", "/api/peers", "peers", "index", "zcl.peers.index.v1",
      "limit", "peer_projection", "", false, API_DYN_PEERS_INDEX },
    { "GET", "/api/events", "events", "index", "zcl.events.index.v1",
      "limit,type", "event_projection", "", false, API_DYN_EVENTS_INDEX },
    { "GET", "/api/files/{sha3}", "files", "show", "zcl.files.show.v1",
      "", "file_service", "", false, API_DYN_FILE_SHOW },
    { "GET", "/api/names/{name}/services", "names", "index",
      ZCL_NAMES_SERVICE_DIRECTORY_SCHEMA,
      "service,service_contract,transport,endpoint_kind,valid,endpoint_only",
      "znam_projection", "", false,
      API_DYN_NAME_SERVICES },
    { "GET", "/api/names/{name}", "names", "show", "zcl.names.show.v1",
      "", "znam_projection", "", false, API_DYN_NAME_SHOW },
    { "GET", "/api/name/{name}", "names", "show", "zcl.names.show.v1",
      "", "znam_projection", "/api/v1/names/{name}", false,
      API_DYN_NAME_SHOW },
    { "GET", "/api/protocols/{name}", "protocols", "show",
      ZCL_APP_PROTOCOL_CONTRACT_SCHEMA, "", "static", "", false,
      API_DYN_PROTOCOL_SHOW },
    { "GET", "/api/transaction-types/{type}", "transaction_types", "show",
      ZCL_TRANSACTION_TYPE_SCHEMA, "", "static", "", false, API_DYN_TRANSACTION_TYPE_SHOW },
    { "GET", "/api/service-catalog/{service}", "service_catalog", "show",
      ZCL_SERVICE_CONTRACT_SCHEMA, "", "static", "", false,
      API_DYN_SERVICE_CATALOG_SHOW },
    { "GET", "/api/service-operations", "service_operations", "index",
      ZCL_SERVICE_OPERATIONS_INDEX_SCHEMA,
      "service,write_safety,preferred_interface,status,surface", "static",
      "", false, API_DYN_SERVICE_OPERATIONS_INDEX },
    { "GET", "/api/service-operations/{operation_id}", "service_operations",
      "show", ZCL_SERVICE_OPERATION_SCHEMA, "", "static", "", false,
      API_DYN_SERVICE_OPERATION_SHOW },
    { "GET", "/api/builds/{job_id}/actions", "build_actions", "index",
      "zcl.build_actions.index.v1", "", "build_ledger", "", true, API_DYN_BUILD_ACTIONS_INDEX },
    { "GET", "/api/builds/{job_id}", "builds", "show", "zcl.builds.show.v1",
      "", "build_ledger", "", true, API_DYN_BUILD_SHOW },
    { "GET", "/api/build_receipts/{receipt_id}", "build_receipts", "show",
      "zcl.build_receipts.show.v1", "", "build_ledger", "", true, API_DYN_BUILD_RECEIPT_SHOW },
    { "GET", "/api/market", "market", "index", "zcl.market.index.v1",
      "profile", "market_projection", "", false, API_DYN_MARKET_INDEX },
};

static size_t api_dynamic_resource_route_count_internal(void) {
    return sizeof(k_api_dynamic_resource_routes) / sizeof(k_api_dynamic_resource_routes[0]); }
static size_t api_resource_route_count_internal(void) {
    return sizeof(k_api_resource_routes) / sizeof(k_api_resource_routes[0]); }
static size_t api_json_resource_route_count_internal(void) {
    return sizeof(k_api_json_resource_routes) / sizeof(k_api_json_resource_routes[0]); }

size_t api_route_contract_count(void)
{
    return api_resource_route_count_internal() +
           api_json_resource_route_count_internal() +
           api_dynamic_resource_route_count_internal();
}

void api_route_registry_visit(api_route_contract_visit_fn visit, void *ctx)
{
    if (!visit)
        return;

    for (size_t i = 0; i < api_resource_route_count_internal(); i++) {
        const struct api_resource_route *r = &k_api_resource_routes[i];
        visit(ctx, r->method, r->path, r->resource, r->action,
              r->response_schema, r->query_params_csv, r->freshness,
              r->alias_of, r->private_route, r->command_path);
    }

    /* k_api_json_resource_routes / k_api_dynamic_resource_routes are not in
     * OS-B3b scope (task text scopes command_path to struct
     * api_resource_route only) — pass "" so the contract surface omits the
     * key rather than claiming a checked "none:" verdict for them. */
    for (size_t i = 0; i < api_json_resource_route_count_internal(); i++) {
        const struct api_json_resource_route *r = &k_api_json_resource_routes[i];
        visit(ctx, r->method, r->path, r->resource, r->action,
              r->response_schema, r->query_params_csv, r->freshness,
              r->alias_of, r->private_route, "");
    }

    for (size_t i = 0; i < api_dynamic_resource_route_count_internal(); i++) {
        const struct api_dynamic_resource_route *r =
            &k_api_dynamic_resource_routes[i];
        visit(ctx, r->method, r->pattern, r->resource, r->action,
              r->response_schema, r->query_params_csv, r->freshness,
              r->alias_of, r->private_route, "");
    }
}

static bool api_route_collection_match(const char *path, const char *base)
{
    size_t n;

    if (!path || !base)
        return false;
    n = strlen(base);
    return strcmp(path, base) == 0 ||
           (strncmp(path, base, n) == 0 && path[n] == '?');
}

static bool api_path_prefix_boundary(const char *path, const char *prefix)
{
    size_t n;

    if (!path || !prefix)
        return false; /* raw-return-ok:predicate-null-input */
    n = strlen(prefix);
    if (strncmp(path, prefix, n) != 0)
        return false; /* raw-return-ok:predicate-negative-match */
    return path[n] == '\0' || path[n] == '/' || path[n] == '?';
}

static bool api_dynamic_route_match(const char *pattern, const char *path,
                                    char *param, size_t param_len)
{
    if (!pattern || !path)
        return false;

    const char *open = strchr(pattern, '{');
    if (!open)
        return api_route_collection_match(path, pattern);

    const char *close = strchr(open + 1, '}');
    if (!close)
        return false;

    size_t prefix_len = (size_t)(open - pattern);
    if (strncmp(path, pattern, prefix_len) != 0)
        return false;

    const char *value_start = path + prefix_len;
    const char *suffix = close + 1;
    const char *value_end = NULL;

    if (suffix[0]) {
        const char *query = strchr(value_start, '?');
        value_end = strstr(value_start, suffix);
        if (!value_end)
            return false;
        if (query && value_end > query)
            return false;
        const char *after = value_end + strlen(suffix);
        if (*after != '\0' && *after != '?')
            return false;
    } else {
        value_end = value_start;
        while (*value_end && *value_end != '/' && *value_end != '?')
            value_end++;
        if (*value_end == '/')
            return false;
    }

    size_t value_len = (size_t)(value_end - value_start);
    if (value_len == 0)
        return false;
    if (param && param_len > 0) {
        if (value_len >= param_len)
            value_len = param_len - 1;
        memcpy(param, value_start, value_len);
        param[value_len] = '\0';
    }
    return true;
}

static bool api_route_pattern_under_prefix(const char *pattern,
                                           const char *prefix)
{
    return pattern && prefix && strlen(pattern) > strlen(prefix) &&
           api_path_prefix_boundary(pattern, prefix);
}

static bool api_public_route_overrides_private_prefix(const char *path,
                                                      const char *private_prefix)
{
    for (size_t i = 0; i < api_resource_route_count_internal(); i++) {
        const struct api_resource_route *r = &k_api_resource_routes[i];
        if (r->private_route ||
            !api_route_pattern_under_prefix(r->path, private_prefix))
            continue;
        if (api_path_prefix_boundary(path, r->path))
            return true;
    }

    for (size_t i = 0; i < api_json_resource_route_count_internal(); i++) {
        const struct api_json_resource_route *r = &k_api_json_resource_routes[i];
        if (r->private_route ||
            !api_route_pattern_under_prefix(r->path, private_prefix))
            continue;
        if (api_path_prefix_boundary(path, r->path))
            return true;
    }

    for (size_t i = 0; i < api_dynamic_resource_route_count_internal(); i++) {
        const struct api_dynamic_resource_route *r =
            &k_api_dynamic_resource_routes[i];
        if (r->private_route ||
            !api_route_pattern_under_prefix(r->pattern, private_prefix))
            continue;
        char param[512];
        if (api_dynamic_route_match(r->pattern, path, param, sizeof(param)))
            return true;
    }

    return false;
}

static bool api_route_fixed_private_match(const char *path,
                                          const char *route_path)
{
    if (!api_path_prefix_boundary(path, route_path))
        return false; /* raw-return-ok:predicate-negative-match */
    return !api_public_route_overrides_private_prefix(path, route_path);
}

bool api_route_registry_is_private(const char *path)
{
    char canonical_buf[512];
    const char *route_path;

    if (!path)
        return false;

    route_path = api_canonical_route_path(path, canonical_buf,
                                          sizeof(canonical_buf));
    if (!route_path)
        return false;

    for (size_t i = 0; i < api_resource_route_count_internal(); i++) {
        const struct api_resource_route *r = &k_api_resource_routes[i];
        if (!r->private_route)
            continue;
        if (api_route_fixed_private_match(route_path, r->path))
            return true;
    }

    for (size_t i = 0; i < api_json_resource_route_count_internal(); i++) {
        const struct api_json_resource_route *r = &k_api_json_resource_routes[i];
        if (!r->private_route)
            continue;
        if (api_route_fixed_private_match(route_path, r->path))
            return true;
    }

    for (size_t i = 0; i < api_dynamic_resource_route_count_internal(); i++) {
        const struct api_dynamic_resource_route *r =
            &k_api_dynamic_resource_routes[i];
        if (!r->private_route)
            continue;
        char param[512];
        if (api_dynamic_route_match(r->pattern, route_path, param,
                                    sizeof(param)))
            return true;
    }

    return false;
}

static size_t api_dynamic_route_dispatch(
    const struct api_dynamic_resource_route *route,
    const char *path,
    const char *param,
    uint8_t *response,
    size_t response_max)
{
    if (!route)
        return api_json_error(response, response_max, JSON_500_HEADERS,
                              "Internal error");

    switch (route->dispatch_kind) {
    case API_DYN_BLOCK_SHOW:
        return do_lookup(LOOKUP_BLOCK, param, response, response_max);
    case API_DYN_TX_SHOW:
        return do_lookup(LOOKUP_TX, param, response, response_max);
    case API_DYN_ADDRESS_SHOW:
        return do_lookup(LOOKUP_ADDRESS, param, response, response_max);
    case API_DYN_ZSLP_TOKENS_INDEX:
        return api_serve_zslp_tokens(path, response, response_max);
    case API_DYN_ZSLP_TOKEN_SHOW:
        return api_serve_zslp_token(param, response, response_max);
    case API_DYN_ZSLP_TOKEN_TRANSFERS: {
        size_t token_len = param ? strlen(param) : 0;
        if (token_len == 0 || token_len > ZSLP_TOKEN_KEY_MAX)
            return api_json_error(response, response_max, JSON_404_HEADERS,
                                  "Invalid token id");
        return api_serve_zslp_token_transfers(path, param, response,
                                              response_max);
    }
    case API_DYN_ONION_ANNOUNCEMENTS_INDEX:
        return api_serve_onion_announcements(path, response, response_max);
    case API_DYN_FILE_SERVICES_INDEX:
        return api_serve_file_services(path, response, response_max);
    case API_DYN_PEERS_INDEX:
        return api_serve_peers(path, response, response_max);
    case API_DYN_EVENTS_INDEX:
        return api_serve_events(path, response, response_max);
    case API_DYN_FILE_SHOW:
        if (!param || strlen(param) != 64)
            return api_json_error(response, response_max, JSON_404_HEADERS,
                                  "Invalid file hash");
        return api_serve_file_chunk(param, response, response_max);
    case API_DYN_NAME_SERVICES: {
        return api_serve_name_service_directory(param, path,
                                                route->freshness,
                                                response, response_max);
    }
    case API_DYN_NAME_SHOW: {
        struct json_value jr = {0};
        if (rpc_name_resolve_api(param, &jr)) {
            api_json_add_freshness(&jr, route->freshness, -1);
            size_t n = api_json_ok(response, response_max, &jr);
            json_free(&jr);
            return n;
        }
        json_free(&jr);
        return api_json_error(response, response_max, JSON_404_HEADERS,
                              "Name not found");
    }
    case API_DYN_PROTOCOL_SHOW: {
        return api_serve_protocol_member(param, route->freshness,
                                         response, response_max);
    }
    case API_DYN_TRANSACTION_TYPE_SHOW: {
        return api_serve_transaction_type_member(param, route->freshness,
                                                  response, response_max);
    }
    case API_DYN_SERVICE_CATALOG_SHOW: {
        struct json_value jr = {0};
        if (api_service_catalog_show_json(param, &jr)) {
            api_json_add_freshness(&jr, route->freshness, -1);
            size_t n = api_json_ok(response, response_max, &jr);
            json_free(&jr);
            return n;
        }
        json_free(&jr);
        return api_json_error(response, response_max, JSON_404_HEADERS,
                              "Service not found");
    }
    case API_DYN_SERVICE_OPERATIONS_INDEX:
        return api_serve_service_operations(path, response, response_max);
    case API_DYN_SERVICE_OPERATION_SHOW: {
        struct json_value jr = {0};
        if (api_service_operation_show_json(param, &jr)) {
            api_json_add_freshness(&jr, route->freshness, -1);
            size_t n = api_json_ok(response, response_max, &jr);
            json_free(&jr);
            return n;
        }
        json_free(&jr);
        return api_json_error(response, response_max, JSON_404_HEADERS,
                              "Service operation not found");
    }
    case API_DYN_BUILD_SHOW: return api_serve_build(param, response, response_max);
    case API_DYN_BUILD_ACTIONS_INDEX: return api_serve_build_actions(param, response, response_max);
    case API_DYN_BUILD_RECEIPT_SHOW: return api_serve_build_receipt(param, response, response_max);
    case API_DYN_MARKET_INDEX: {
        /* Per-node listing moderation: ?profile=open is the explicit
         * per-request view override; absent means the node's active
         * profile. Parsing mirrors api_parse_collection_limit. */
        char profile[40] = "";
        const char *q = path ? strchr(path, '?') : NULL;
        if (q) {
            const char *pp = strstr(q, "profile=");
            if (pp) {
                pp += 8;
                size_t n = 0;
                while (pp[n] && pp[n] != '&' && n < sizeof(profile) - 1) {
                    profile[n] = pp[n];
                    n++;
                }
                if (pp[n] && pp[n] != '&')
                    return api_json_error(response, response_max,
                                          JSON_404_HEADERS,
                                          "Invalid profile parameter");
                profile[n] = '\0';
            }
        }
        struct json_value jr = {0};
        if (api_market_list_profile(profile[0] ? profile : NULL, &jr)) {
            api_json_add_freshness(&jr, route->freshness, -1);
            size_t n = api_json_ok(response, response_max, &jr);
            json_free(&jr);
            return n;
        }
        json_free(&jr);
        return api_json_error(response, response_max, JSON_404_HEADERS,
                              "Invalid profile parameter");
    }
    }

    return api_json_error(response, response_max, JSON_500_HEADERS,
                          "Internal error");
}

static bool api_json_resource_route_find(const char *method, const char *path,
                                         const struct api_json_resource_route **out)
{
    size_t n;

    if (!method || !path || !out)
        return false;
    n = api_json_resource_route_count_internal();
    for (size_t i = 0; i < n; i++) {
        const struct api_json_resource_route *r = &k_api_json_resource_routes[i];
        if (strcmp(method, r->method) == 0 && strcmp(path, r->path) == 0) {
            *out = r;
            return true;
        }
    }
    return false;
}

static size_t api_serve_json_resource_route(
    const struct api_json_resource_route *route,
    uint8_t *response,
    size_t response_max)
{
    struct json_value jr = {0};

    if (!route || !route->handler)
        return api_json_error(response, response_max, JSON_500_HEADERS,
                              "Internal error");
    if (route->handler(&jr)) {
        api_json_add_freshness(&jr, route->freshness, -1);
        size_t n = api_json_ok(response, response_max, &jr);
        json_free(&jr);
        return n;
    }
    json_free(&jr);
    return api_json_error(response, response_max, JSON_500_HEADERS,
                          "Internal error");
}

const char *api_canonical_route_path(const char *path, char *buf,
                                     size_t buf_len)
{
    if (!path)
        return NULL;
    if (strcmp(path, ZCL_REST_API_BASE_PATH) == 0)
        return ZCL_REST_API_COMPAT_BASE_PATH;

    const char *prefix = ZCL_REST_API_BASE_PATH "/";
    size_t prefix_len = strlen(prefix);
    if (strncmp(path, prefix, prefix_len) == 0) {
        if (!buf || buf_len == 0)
            return path;
        int n = snprintf(buf, buf_len, "%s/%s",
                         ZCL_REST_API_COMPAT_BASE_PATH,
                         path + prefix_len);
        if (n < 0 || (size_t)n >= buf_len)
            return path;
        return buf;
    }
    return path;
}

bool api_path_has_unsupported_version(const char *path, char *version_out,
                                      size_t version_out_len)
{
    if (!path || strncmp(path, "/api/v", 6) != 0 ||
        !isdigit((unsigned char)path[6]))
        return false;

    size_t len = 1; /* include the leading 'v' */
    const char *p = path + 6;
    while (isdigit((unsigned char)*p)) {
        len++;
        p++;
    }

    if (*p != '\0' && *p != '/' && *p != '?')
        return false;

    char version[32];
    if (len >= sizeof(version))
        len = sizeof(version) - 1;
    memcpy(version, path + 5, len);
    version[len] = '\0';

    if (strcmp(version, ZCL_REST_API_VERSION) == 0)
        return false;

    if (version_out && version_out_len > 0) {
        snprintf(version_out, version_out_len, "%s", version);
    }
    return true;
}

const struct api_resource_route *
api_resource_route_find(const char *method, const char *path)
{
    if (!method || !path)
        return NULL;
    size_t n = api_resource_route_count_internal();
    for (size_t i = 0; i < n; i++) {
        const struct api_resource_route *r = &k_api_resource_routes[i];
        if (strcmp(method, r->method) == 0 && strcmp(path, r->path) == 0)
            return r;
    }
    return NULL;
}

size_t api_resource_route_dispatch_builtin(const char *method,
                                           const char *path,
                                           uint8_t *response,
                                           size_t response_max,
                                           bool *handled)
{
    const struct api_json_resource_route *json_route = NULL;
    char param[512];

    if (handled)
        *handled = false;
    if (!method || !path || !handled)
        return 0;
    if (strcmp(method, "GET") != 0)
        return 0;
    if (api_dynamic_resource_route_count_internal() == 0)
        return 0;

    for (size_t i = 0; i < api_dynamic_resource_route_count_internal(); i++) {
        const struct api_dynamic_resource_route *route =
            &k_api_dynamic_resource_routes[i];
        if (strcmp(method, route->method) != 0)
            continue;
        param[0] = '\0';
        if (!api_dynamic_route_match(route->pattern, path, param,
                                     sizeof(param)))
            continue;
        *handled = true;
        return api_dynamic_route_dispatch(route, path, param, response,
                                          response_max);
    }

    if (api_json_resource_route_find(method, path, &json_route)) {
        *handled = true;
        return api_serve_json_resource_route(json_route, response, response_max);
    }

    return 0;
}

#ifdef ZCL_TESTING
size_t api_resource_route_count(void)
{
    return api_resource_route_count_internal();
}

const char *api_resource_route_resource_at(size_t i)
{
    if (i >= api_resource_route_count())
        return NULL;
    return k_api_resource_routes[i].resource;
}

const char *api_resource_route_action_at(size_t i)
{
    if (i >= api_resource_route_count())
        return NULL;
    return k_api_resource_routes[i].action;
}

const char *api_resource_route_command_path_at(size_t i)
{
    if (i >= api_resource_route_count())
        return NULL;
    return k_api_resource_routes[i].command_path;
}

size_t api_dynamic_resource_route_count(void)
{
    return api_dynamic_resource_route_count_internal();
}

const char *api_dynamic_resource_route_pattern_at(size_t i)
{
    if (i >= api_dynamic_resource_route_count())
        return NULL;
    return k_api_dynamic_resource_routes[i].pattern;
}

const char *api_dynamic_resource_route_resource_at(size_t i)
{
    if (i >= api_dynamic_resource_route_count())
        return NULL;
    return k_api_dynamic_resource_routes[i].resource;
}

const char *api_dynamic_resource_route_action_at(size_t i)
{
    if (i >= api_dynamic_resource_route_count())
        return NULL;
    return k_api_dynamic_resource_routes[i].action;
}
#endif

/* ── Hot-swap generation entrypoint ─────────────────────────────────
 *
 * This TU is Tier-1 hot-swap eligible (config/hotswap_eligible.def). Under a
 * generation .so build (-DZCL_HOTSWAP_GEN) the macro emits zcl_hotswap_gen_init,
 * which re-points the resident REST dispatch provider at THIS TU's
 * freshly-compiled api_resource_route_dispatch_builtin (and its recompiled
 * static route tables). api_resource_dispatch_replace lives in the resident
 * trampoline TU, so it binds to the executable's copy and mutates the provider
 * the live read path reads. In the node build and in release the macro expands
 * to nothing (no trailing semicolon by design). */
ZCL_HOTSWAP_EXPORT_PROVIDER(
    api_resource_dispatch_replace(api_resource_route_dispatch_builtin))
