/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Machine-readable boundary between ZClassic L1 consensus and the
 * zclassic23 application layer exposed through REST/OpenAPI. */

#include "api_controller_internal.h"

#include "json/json.h"

void api_rest_layer_model_json(struct json_value *layer_model)
{
    json_set_object(layer_model);
    json_push_kv_str(layer_model, "schema", "zcl.rest_layer_model.v1");
    json_push_kv_str(layer_model, "base_layer", "zclassic_l1");
    json_push_kv_str(layer_model, "service_layer",
                     "zclassic23_application_layer");
    json_push_kv_str(layer_model, "service_layer_alias",
                     "zclassic23_l2");
    json_push_kv_str(layer_model, "application_protocol_umbrella",
                     "zlsp");
    json_push_kv_str(layer_model, "consensus_authority",
                     "local_consensus_reducer");
    json_push_kv_str(layer_model, "read_rule",
                     "GET reads chain-derived projections at the served frontier");
    json_push_kv_str(layer_model, "mutation_rule",
                     "mutations construct or broadcast explicit ZCL transactions "
                     "or operator-gated actions; they do not directly write "
                     "chain-derived state");
    json_push_kv_str(layer_model, "crud_service_rule",
                     "application services expose noun-shaped REST resources; "
                     "writes are transaction-construction requests, never "
                     "direct projection mutations");
    json_push_kv_str(layer_model, "consensus_boundary",
                     "application protocols may interpret OP_RETURN, memo, and "
                     "script-contract data but must not change block, tx, PoW, "
                     "activation, or coin-accounting rules");

    struct json_value protocols;
    json_init(&protocols);
    api_app_protocols_json(&protocols);
    json_push_kv(layer_model, "application_protocols", &protocols);
    json_free(&protocols);
}
