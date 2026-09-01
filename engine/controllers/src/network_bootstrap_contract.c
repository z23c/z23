/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Z23-specific bootstrap UX contract. The generic bootstrap status
 * controller owns live P2P measurements; this module owns the fresh-node
 * route plan agents consume from REST/RPC/native. */

#include "controllers/network_controller.h"

#include "json/json.h"
#include "net/fast_sync.h"

const char *network_bootstrap_readiness_label(bool p2p_serving,
                                              bool addr_relay_ready)
{
    if (!p2p_serving)
        return "blocked";
    if (!addr_relay_ready)
        return "ready_p2p_addr_degraded";
    return "ready_p2p_and_addr";
}

const char *network_bootstrap_next_action(bool p2p_serving,
                                          bool node_zcl23,
                                          bool addr_relay_ready)
{
    if (!p2p_serving)
        return "fix_named_blockers_before_advertising_bootstrap";
    if (!node_zcl23)
        return "serve_legacy_p2p_but_do_not_claim_zclassic23_fast_sync";
    if (!addr_relay_ready)
        return "connect_direct_p2p_and_seed_addrman";
    return "connect_direct_p2p_and_request_headers_blocks";
}

static void push_str_item(struct json_value *arr, const char *value)
{
    struct json_value item = {0};

    json_set_str(&item, value);
    json_push_back(arr, &item);
    json_free(&item);
}

static void push_str_array(struct json_value *obj, const char *key,
                           const char *const *items, size_t count)
{
    struct json_value arr = {0};

    json_set_array(&arr);
    for (size_t i = 0; i < count; i++)
        push_str_item(&arr, items[i]);
    json_push_kv(obj, key, &arr);
    json_free(&arr);
}

void network_push_zclassic23_bootstrap_contract(struct json_value *result,
                                                bool p2p_serving,
                                                bool addr_relay_ready,
                                                bool node_zcl23,
                                                const char *ext_ip,
                                                uint16_t ext_port)
{
    struct json_value zcl23 = {0};
    static const char *const flow[] = {
        "read_bootstrapstatus",
        "connect_direct_p2p_endpoint",
        "request_headers_and_blocks",
        "resolve_znam_service_directory_if_direct_p2p_fails",
        "fallback_to_onion_endpoint",
        "validate_all_data_against_zclassic_l1_consensus"
    };

    json_set_object(&zcl23);
    json_push_kv_str(&zcl23, "schema", "zcl.bootstrap.zclassic23.v1");
    json_push_kv_int(&zcl23, "schema_version", 1);
    json_push_kv_bool(&zcl23, "serving", p2p_serving);
    json_push_kv_bool(&zcl23, "preferred_for_fresh_zclassic23",
                      p2p_serving && node_zcl23);
    json_push_kv_bool(&zcl23, "full_node_bootstrap", p2p_serving);
    json_push_kv_bool(&zcl23, "addr_relay_ready",
                      p2p_serving && addr_relay_ready);
    json_push_kv_bool(&zcl23, "fast_sync_service_bit_advertised",
                      node_zcl23);
    json_push_kv_int(&zcl23, "fast_sync_service_bit_value", NODE_ZCL23);
    json_push_kv_str(&zcl23, "route_preference",
                     "direct_p2p_then_znam_onion_fallback");
    json_push_kv_str(&zcl23, "endpoint_source",
                     "localaddresses_or_znam_service_directory");
    json_push_kv_str(&zcl23, "endpoint_record_schema",
                     "zcl.names.service_record.v1");
    json_push_kv_str(&zcl23, "name_resolution_schema",
                     "zcl.names.show.v1");
    json_push_kv_str(&zcl23, "service_catalog_member",
                     "/api/v1/service-catalog/bootstrap");
    json_push_kv_str(&zcl23, "bootstrap_api", "/api/v1/bootstrap");
    json_push_kv_str(&zcl23, "clearnet_address", ext_ip ? ext_ip : "");
    json_push_kv_int(&zcl23, "p2p_port", ext_port);
    json_push_kv_str(&zcl23, "onion_fallback",
                     "use_znam_service_record_transport_onion_when_direct_p2p_unreachable");
    json_push_kv_str(&zcl23, "next_action",
                     network_bootstrap_next_action(p2p_serving, node_zcl23,
                                                   addr_relay_ready));
    push_str_array(&zcl23, "fresh_node_flow", flow,
                   sizeof(flow) / sizeof(flow[0]));

    json_push_kv(result, "zclassic23_bootstrap", &zcl23);
    json_free(&zcl23);
}
