/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Resource directory for the self-describing REST index. Kept separate from
 * api_controller_index.c so OpenAPI generation and resource listing can evolve
 * independently. */

#include "api_controller_internal.h"

#include "json/json.h"

static void api_rest_index_push_resource(struct json_value *resources,
                                         const char *name,
                                         const char *collection,
                                         const char *item,
                                         bool private_resource)
{
    struct json_value obj;

    json_init(&obj);
    json_set_object(&obj);
    json_push_kv_str(&obj, "name", name);
    if (collection && collection[0])
        json_push_kv_str(&obj, "collection", collection);
    if (item && item[0])
        json_push_kv_str(&obj, "item", item);
    if (private_resource)
        json_push_kv_bool(&obj, "private", true);
    json_push_back(resources, &obj);
    json_free(&obj);
}

void api_rest_index_resources_json(struct json_value *resources)
{
    json_set_array(resources);

    api_rest_index_push_resource(resources, "openapi",
                                 "/api/v1/openapi", "", false);

    struct json_value node;
    json_init(&node);
    json_set_object(&node);
    json_push_kv_str(&node, "name", "node");
    json_push_kv_str(&node, "collection", "/api/v1/node");
    json_push_kv_str(&node, "summary", "/api/v1/node/summary");
    json_push_kv_str(&node, "status", "/api/v1/node/status");
    json_push_back(resources, &node);
    json_free(&node);

    api_rest_index_push_resource(resources, "milestone",
                                 "/api/v1/milestone", "", false);
    api_rest_index_push_resource(resources, "refold",
                                 "/api/v1/refold", "", false);
    api_rest_index_push_resource(resources, "bootstrap",
                                 "/api/v1/bootstrap", "", false);
    api_rest_index_push_resource(resources, "blocks",
                                 "/api/v1/blocks",
                                 "/api/v1/block/{height_or_hash}", false);
    api_rest_index_push_resource(resources, "transactions", "",
                                 "/api/v1/tx/{txid}", false);
    api_rest_index_push_resource(resources, "addresses", "",
                                 "/api/v1/address/{address}", false);
    api_rest_index_push_resource(resources, "peers",
                                 "/api/v1/peers", "", false);
    api_rest_index_push_resource(resources, "hodl",
                                 "/api/v1/hodl", "", false);
    api_rest_index_push_resource(resources, "factoids",
                                 "/api/v1/factoids", "", false);
    api_rest_index_push_resource(resources, "protocols",
                                 "/api/v1/protocols",
                                 "/api/v1/protocols/{name}", false);
    api_rest_index_push_resource(resources, "transaction_types",
                                 "/api/v1/transaction-types",
                                 "/api/v1/transaction-types/{type}", false);
    api_rest_index_push_resource(resources, "service_catalog",
                                 "/api/v1/service-catalog",
                                 "/api/v1/service-catalog/{service}", false);
    api_rest_index_push_resource(resources, "service_operations",
                                 "/api/v1/service-operations",
                                 "/api/v1/service-operations/{operation_id}",
                                 false);
    api_rest_index_push_resource(resources, "zslp_tokens",
                                 "/api/v1/zslp/tokens",
                                 "/api/v1/zslp/tokens/{token_id}", false);
    api_rest_index_push_resource(resources, "names",
                                 "/api/v1/names",
                                 "/api/v1/names/{name}", false);
    api_rest_index_push_resource(resources, "name_services", "",
                                 "/api/v1/names/{name}/services", false);
    api_rest_index_push_resource(resources, "market",
                                 "/api/v1/market", "", false);
    api_rest_index_push_resource(resources, "swaps",
                                 "/api/v1/swaps",
                                 "/api/v1/swaps/chains", true);
    api_rest_index_push_resource(resources, "messages",
                                 "/api/v1/messages", "", true);
    api_rest_index_push_resource(resources, "files",
                                 "/api/v1/files/manifest",
                                 "/api/v1/files/{sha3}", false);
    api_rest_index_push_resource(resources, "wallet",
                                 "/api/v1/wallet", "", true);
}
