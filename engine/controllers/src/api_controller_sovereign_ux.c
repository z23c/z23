/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Machine-readable UX contract for agents and clients that compose Z23
 * services on top of the legacy-compatible ZCL base layer. */

#include "api_controller_internal.h"

#include "json/json.h"

void api_sovereign_ux_contract_json(struct json_value *out)
{
    struct json_value flow;
    struct json_value entities;
    struct json_value routes;

    if (!out)
        return;

    json_set_object(out);
    json_push_kv_str(out, "schema", "zcl.sovereign_ux_contract.v2");
    json_push_kv_str(out, "base_layer", "zclassic_l1");
    json_push_kv_str(out, "service_layer", "zclassic23_application_layer");
    json_push_kv_str(out, "verification_spine",
                     "served_zcl_frontier_then_chain_projected_names_then "
                     "verified_endpoint_or_contract_bytes");
    json_push_kv_str(out, "crud_semantics",
                     "public_rest_reads_projection_state_private_writes_are "
                     "operator_authorized_transaction_builders_or_local_state");
    json_push_kv_str(out, "preferred_operator_interface",
                     "native_json_then_public_rest_reads");

    json_init(&flow);
    api_app_protocol_csv_json(
        "read_agent_status,inspect_service_catalog,resolve_znam_name,"
        "read_name_service_directory,verify_service_records,"
        "prefer_direct_p2p_when_handshaked,"
        "fallback_to_onion_when_needed,use_versioned_crud_operation",
        &flow);
    json_push_kv(out, "flow", &flow);
    json_free(&flow);

    json_init(&entities);
    api_app_protocol_csv_json(
        "service_contract,service_operation,znam_name,endpoint_record,"
        "bootstrap_peer,onion_announcement,script_contract",
        &entities);
    json_push_kv(out, "primary_entities", &entities);
    json_free(&entities);

    json_init(&routes);
    json_set_object(&routes);
    json_push_kv_str(&routes, "status", "/api/v1/agent");
    json_push_kv_str(&routes, "service_catalog", "/api/v1/service-catalog");
    json_push_kv_str(&routes, "names", "/api/v1/names/{name}");
    json_push_kv_str(&routes, "name_services",
                     "/api/v1/names/{name}/services");
    json_push_kv_str(&routes, "bootstrap", "/api/v1/bootstrap");
    json_push_kv_str(&routes, "onion_directory",
                     "/api/v1/onion/announcements");
    json_push_kv_str(&routes, "protocols", "/api/v1/protocols/{name}");
    json_push_kv(out, "routes", &routes);
    json_free(&routes);
}
