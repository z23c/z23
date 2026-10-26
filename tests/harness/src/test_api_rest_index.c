/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * API REST index: the v1 discovery document that explains the first call and
 * the CRUD shape of every resource.
 */

#include "test/api_test_fixtures.h"

/* One former `ok = ok && ...` comparison. obj indexes focused_rest_objs.
 * parent is the intermediate object key when the original call nested
 * json_get; num selects the negated or counted form of a predicate. */
enum {
    FRI_ROOT = 0,
    FRI_LAYER,
    FRI_PROTOCOLS,
    FRI_ZLSP,
    FRI_ZSLP_PROTO,
    FRI_ZNAM,
    FRI_SCRIPT,
    FRI_SWAP_PROTO,
    FRI_RESOURCES,
    FRI_BOOT_RES,
    FRI_ZSLP_RES,
    FRI_PROTO_RES,
    FRI_CAT_RES,
    FRI_OPS_RES,
    FRI_NAMESVC_RES,
    FRI_ROUTES,
    FRI_HODL,
    FRI_BOOT,
    FRI_LEGACY_BOOT,
    FRI_WALLET,
    FRI_ZSLP,
    FRI_PROTO_ROUTE,
    FRI_CAT_ROUTE,
    FRI_CAT_SHOW,
    FRI_OPS_ROUTE,
    FRI_OP_SHOW,
    FRI_PROTO_SHOW,
    FRI_NAMES,
    FRI_NAMES_SVC,
    FRI_LEGACY_NAME,
    FRI_SWAP_CHAINS,
    FRI_LEGACY_SWAP,
    FRI_EVENTS,
    FRI_SUPPLY,
    FRI_BLOCK,
    FRI_LEGACY_BLOCK,
    FRI_TX,
    FRI_LEGACY_TX,
    FRI_ADDR,
    FRI_LEGACY_ADDR,
    FRI_BOOT_BIND,
    FRI_HODL_TEL,
    FRI_HODL_CRYPTO,
    FRI_OPS_FILTER,
    FRI_OPS_ALLOWED,
    FRI_NS_PATH,
    FRI_NS_PARAMS,
    FRI_NS_NAME,
    FRI_NS_FILTER,
    FRI_NS_ALLOWED,
    FRI_NS_BIND,
    FRI_NAMES_PATH,
    FRI_NAMES_PATH_NAME,
    FRI_LEGACY_PATH,
    FRI_LEGACY_PATH_NAME,
    FRI_N
};

struct focused_rest_check {
    unsigned char obj;
    const char *key;
    const char *parent;
    const char *val;
    int64_t num;
    bool (*pred)(const struct json_value *obj,
                 const struct focused_rest_check *check);
};

static bool focused_rest_field_equals(const struct json_value *obj,
                                      const struct focused_rest_check *check)
{
    const struct json_value *base = check->parent ? json_get(obj, check->parent)
                                                  : obj;
    if (check->parent)
        return strcmp(json_get_str(json_get(base, check->key)),
                      check->val) == 0;
    return base && strcmp(json_get_str(json_get(base, check->key)),
                          check->val) == 0;
}

static bool focused_rest_child_presence(const struct json_value *obj,
                                        const struct focused_rest_check *check)
{
    bool missing = json_get(json_get(obj, check->parent), check->key) == NULL;
    if (check->num != 0)
        return missing;
    return !missing;
}

static bool focused_rest_field_contains(const struct json_value *obj,
                                        const struct focused_rest_check *check)
{
    return obj &&
           strstr(json_get_str(json_get(obj, check->key)), check->val) != NULL;
}

static bool focused_rest_array_contains(const struct json_value *obj,
                                        const struct focused_rest_check *check)
{
    return obj &&
           api_test_array_has_str(json_get(obj, check->key), check->val);
}

static bool focused_rest_bool_field(const struct json_value *obj,
                                    const struct focused_rest_check *check)
{
    if (!obj)
        return false;
    bool bit = json_get_bool(json_get(obj, check->key));
    if (check->num != 0)
        return !bit;
    return bit;
}

static bool focused_rest_int_field(const struct json_value *obj,
                                   const struct focused_rest_check *check)
{
    return obj && json_get_int(json_get(obj, check->key)) == check->num;
}

static bool focused_rest_contract_param(const struct json_value *obj,
                                        const struct focused_rest_check *check)
{
    if (check->num != 0)
        return obj && api_test_contract_has_id_param(obj, check->key);
    return obj && api_test_contract_has_query(obj, check->key);
}

static bool focused_rest_protocol_list(const struct json_value *obj,
                                       const struct focused_rest_check *check)
{
    (void)check;
    return obj && obj->type == JSON_ARR && json_size(obj) >= 7;
}

static bool focused_rest_resource_list(const struct json_value *obj,
                                       const struct focused_rest_check *check)
{
    (void)check;
    return obj && json_size(obj) >= 4;
}

static bool focused_rest_route_list_len(const struct json_value *obj,
                                        const struct focused_rest_check *check)
{
    (void)check;
    return obj && json_size(obj) == api_route_contract_count();
}

static bool focused_rest_route_count_field(
    const struct json_value *obj, const struct focused_rest_check *check)
{
    return json_get_int(json_get(obj, check->key)) ==
           (int64_t)api_route_contract_count();
}

static const struct json_value *focused_rest_child(const struct json_value *obj,
                                                   const char *key)
{
    return obj ? json_get(obj, key) : NULL;
}

static const struct json_value *focused_rest_grandchild(
    const struct json_value *obj, const char *parent, const char *key)
{
    return obj ? json_get(json_get(obj, parent), key) : NULL;
}

#define FOCUSED_REST_ROW(obj, key, parent, val, num, pred) \
    { (obj), (key), (parent), (val), (num), (pred) }

static const struct focused_rest_check k_focused_rest_identity[] = {
    FOCUSED_REST_ROW(FRI_ROOT, "schema", NULL, "zcl.rest_index.v2", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "api_version", NULL, "v1", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "base_path", NULL, "/api/v1", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "compat_base_path", NULL, "/api", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "first_call", NULL, "/api/v1/agent", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "protocols", "aliases", "/api/v1/protocols", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "service_catalog", "aliases",
                     "/api/v1/service-catalog", 0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "service_operations", "aliases",
                     "/api/v1/service-operations", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "bootstrap", "aliases", "/api/v1/bootstrap", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "bootstrapstatus", "aliases",
                     "/api/v1/bootstrap", 0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "read_collection", "crud", NULL, 0,
                     focused_rest_child_presence),
    FOCUSED_REST_ROW(FRI_ROOT, "read_item", "crud", NULL, 0,
                     focused_rest_child_presence),
    FOCUSED_REST_ROW(FRI_ROOT, "read_singleton", "crud", NULL, 0,
                     focused_rest_child_presence),
    FOCUSED_REST_ROW(FRI_ROOT, "read_subcollection", "crud", NULL, 0,
                     focused_rest_child_presence),
    FOCUSED_REST_ROW(FRI_ROOT, "contract_fields", "crud", NULL, 0,
                     focused_rest_child_presence),
};

static const struct focused_rest_check k_focused_rest_layer[] = {
    FOCUSED_REST_ROW(FRI_LAYER, "schema", NULL, "zcl.rest_layer_model.v1", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_LAYER, "base_layer", NULL, "zclassic_l1", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_LAYER, "service_layer", NULL,
                     "zclassic23_application_layer", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_LAYER, "service_layer_alias", NULL, "zclassic23_l2",
                     0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_LAYER, "application_protocol_umbrella", NULL, "zlsp",
                     0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_LAYER, "consensus_authority", NULL,
                     "local_consensus_reducer", 0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_LAYER, "crud_service_rule", NULL,
                     "transaction-construction requests", 0,
                     focused_rest_field_contains),
    FOCUSED_REST_ROW(FRI_LAYER, "consensus_boundary", NULL,
                     "must not change block", 0, focused_rest_field_contains),
};

static const struct focused_rest_check k_focused_rest_protocols[] = {
    FOCUSED_REST_ROW(FRI_PROTOCOLS, NULL, NULL, NULL, 0,
                     focused_rest_protocol_list),
    FOCUSED_REST_ROW(FRI_ZLSP, "status", NULL, "design", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZLSP, "family", NULL,
                     "application_protocol_framework", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZLSP, "anchor_kind", NULL,
                     "base_layer_transaction_contract", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZLSP, "crud_capabilities", NULL,
                     "construct_transaction", 0, focused_rest_array_contains),
    FOCUSED_REST_ROW(FRI_ZLSP, "ux_surfaces", NULL, "agent_command_center", 0,
                     focused_rest_array_contains),
    FOCUSED_REST_ROW(FRI_ZSLP_PROTO, "schema", NULL,
                     "zcl.application_protocol_contract.v2", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZSLP_PROTO, "status", NULL, "active", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZSLP_PROTO, "base_layer", NULL, "zclassic_l1", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZSLP_PROTO, "family", NULL, "token", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZSLP_PROTO, "anchor_kind", NULL, "op_return", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZSLP_PROTO, "rest_resource", NULL,
                     "/api/v1/zslp/tokens", 0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZSLP_PROTO, "crud_capabilities", NULL, "read_item", 0,
                     focused_rest_array_contains),
    FOCUSED_REST_ROW(FRI_ZSLP_PROTO, "construction_status", NULL,
                     "transaction_builders_active", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZSLP_PROTO, "consensus_boundary", NULL,
                     "interprets_or_constructs_valid_zcl_transactions_only", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZSLP_PROTO, "object_types", NULL, "token_genesis", 0,
                     focused_rest_array_contains),
    FOCUSED_REST_ROW(FRI_ZSLP_PROTO, "projection_model", NULL,
                     "confirmed_op_return_projection_at_served_frontier", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZNAM, "object_types", NULL, "service_record", 0,
                     focused_rest_array_contains),
    FOCUSED_REST_ROW(FRI_ZNAM, "ux_surfaces", NULL, "identity_profile", 0,
                     focused_rest_array_contains),
    FOCUSED_REST_ROW(FRI_ZNAM, "crypto_model", NULL, "owner_authority", 0,
                     focused_rest_field_contains),
    FOCUSED_REST_ROW(FRI_SCRIPT, "crypto_model", NULL,
                     "legacy_valid_zclassic_script", 0,
                     focused_rest_field_contains),
    FOCUSED_REST_ROW(FRI_ZNAM, "status", NULL, "active", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZNAM, "anchor", NULL,
                     "OP_RETURN name registry transactions", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_SCRIPT, "status", NULL, "active", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_SCRIPT, "anchor_kind", NULL, "standard_script", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_SCRIPT, "mutation_authority", NULL,
                     "operator_wallet_transaction", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_SCRIPT, "anchor", NULL, "HTLC atomic swaps", 0,
                     focused_rest_field_contains),
    FOCUSED_REST_ROW(FRI_SWAP_PROTO, "status", NULL, "in_progress", 0,
                     focused_rest_field_equals),
};

static const struct focused_rest_check k_focused_rest_resources[] = {
    FOCUSED_REST_ROW(FRI_RESOURCES, NULL, NULL, NULL, 0,
                     focused_rest_resource_list),
    FOCUSED_REST_ROW(FRI_BOOT_RES, "collection", NULL, "/api/v1/bootstrap", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_PROTO_RES, "collection", NULL, "/api/v1/protocols", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_PROTO_RES, "item", NULL, "/api/v1/protocols/{name}",
                     0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_CAT_RES, "collection", NULL,
                     "/api/v1/service-catalog", 0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_CAT_RES, "item", NULL,
                     "/api/v1/service-catalog/{service}", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_OPS_RES, "collection", NULL,
                     "/api/v1/service-operations", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_OPS_RES, "item", NULL,
                     "/api/v1/service-operations/{operation_id}", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_NAMESVC_RES, "item", NULL,
                     "/api/v1/names/{name}/services", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZSLP_RES, "collection", NULL, "/api/v1/zslp/tokens",
                     0, focused_rest_field_equals),
};

static const struct focused_rest_check k_focused_rest_route_counts[] = {
    FOCUSED_REST_ROW(FRI_ROUTES, NULL, NULL, NULL, 0,
                     focused_rest_route_list_len),
    FOCUSED_REST_ROW(FRI_ROOT, "route_contract_count", NULL, NULL, 0,
                     focused_rest_route_count_field),
};

static const struct focused_rest_check k_focused_rest_bootstrap_head[] = {
    FOCUSED_REST_ROW(FRI_HODL, "response_schema", NULL, "zcl.hodl_wave.v1", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_BOOT, "response_schema", NULL,
                     "zcl.bootstrap_status.v1", 0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_BOOT, "crud_name", NULL, "read_singleton", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_BOOT, "freshness", NULL, "network_bootstrap", 0,
                     focused_rest_field_equals),
};

static const struct focused_rest_check k_focused_rest_bootstrap_bind[] = {
    FOCUSED_REST_ROW(FRI_BOOT, "service_contract", NULL, "bootstrap", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_BOOT, "service_catalog_route", NULL,
                     "/api/v1/service-catalog/bootstrap", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_BOOT, "service_operation_id", NULL,
                     "bootstrap.read_bootstrap_status", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_BOOT, "service_operation_route", NULL,
                     "/api/v1/service-operations/"
                     "bootstrap.read_bootstrap_status", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_BOOT_BIND, "operation_id", NULL,
                     "bootstrap.read_bootstrap_status", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_BOOT_BIND, "agent_preferred_interface", NULL, "rest",
                     0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_BOOT_BIND, "public_read", NULL, NULL, 0,
                     focused_rest_bool_field),
    FOCUSED_REST_ROW(FRI_BOOT, "private", NULL, NULL, 1,
                     focused_rest_bool_field),
    FOCUSED_REST_ROW(FRI_LEGACY_BOOT, "legacy_alias_of", NULL,
                     "/api/v1/bootstrap", 0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_LEGACY_BOOT, "service_operation_id", NULL,
                     "bootstrap.read_bootstrap_status", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_HODL, "error_schema", NULL, "zcl.rest_error.v1", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_HODL, "crud_operation", NULL, "read", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_HODL, "resource_scope", NULL, "singleton", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_HODL, "crud_name", NULL, "read_singleton", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_HODL, "freshness_scoped", NULL, NULL, 0,
                     focused_rest_bool_field),
    FOCUSED_REST_ROW(FRI_WALLET, "private", NULL, NULL, 0,
                     focused_rest_bool_field),
    FOCUSED_REST_ROW(FRI_WALLET, "auth", NULL, "operator_private", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_WALLET, "auth_policy", NULL, "operator_private", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_HODL, "gateway_auth_compatible", NULL, NULL, 0,
                     focused_rest_bool_field),
    FOCUSED_REST_ROW(FRI_HODL, "preferred_service_auth", NULL,
                     "hash512_sha3_gost_commitments", 0,
                     focused_rest_field_equals),
};

static const struct focused_rest_check k_focused_rest_telemetry[] = {
    FOCUSED_REST_ROW(FRI_HODL_TEL, "counter", NULL, "zcl_api_requests_total",
                     0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_HODL_TEL, "latency_histogram", NULL,
                     "zcl_api_request_duration_seconds", 0,
                     focused_rest_field_equals),
};

static const struct focused_rest_check k_focused_rest_crypto_ops[] = {
    FOCUSED_REST_ROW(FRI_HODL_CRYPTO, "service_auth_primary_digest", NULL,
                     "SHA3-512", 0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_HODL_CRYPTO, "service_auth_secondary_digest", NULL,
                     "GOST R 34.11-2012-512", 0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_HODL_CRYPTO, "hash_output_bits", NULL, NULL, 512,
                     focused_rest_int_field),
    FOCUSED_REST_ROW(FRI_HODL_CRYPTO, "requires_all_digests", NULL, NULL, 0,
                     focused_rest_bool_field),
    FOCUSED_REST_ROW(FRI_HODL_CRYPTO, "signature_scheme_claimed", NULL, NULL,
                     1, focused_rest_bool_field),
    FOCUSED_REST_ROW(FRI_ZSLP, "limit", NULL, NULL, 0,
                     focused_rest_contract_param),
    FOCUSED_REST_ROW(FRI_ZSLP, "pagination", NULL, NULL, 0,
                     focused_rest_bool_field),
    FOCUSED_REST_ROW(FRI_ZSLP, "crud_name", NULL, "read_collection", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZSLP, "application_protocol", NULL, "zslp", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZSLP, "base_layer", NULL, "zclassic_l1", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZSLP, "protocol_family", NULL, "token", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZSLP, "protocol_anchor_kind", NULL, "op_return", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZSLP, "protocol_crud", NULL, "read_collection", 0,
                     focused_rest_array_contains),
    FOCUSED_REST_ROW(FRI_ZSLP, "protocol_construction_status", NULL,
                     "transaction_builders_active", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZSLP, "mutation_authority", NULL,
                     "operator_wallet_transaction", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZSLP, "layer", NULL, "zclassic23_application_layer",
                     0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ZSLP, "source_anchor", NULL,
                     "OP_RETURN token transactions", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_PROTO_ROUTE, "response_schema", NULL,
                     "zcl.application_protocols.index.v2", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_PROTO_ROUTE, "application_protocol", NULL, "zlsp", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_PROTO_ROUTE, "protocol_family", NULL,
                     "application_protocol_framework", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_CAT_ROUTE, "response_schema", NULL,
                     "zcl.service_catalog.v2", 0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_CAT_ROUTE, "crud_name", NULL, "read_singleton", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_CAT_ROUTE, "freshness", NULL, "static", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_CAT_SHOW, "response_schema", NULL,
                     "zcl.service_contract.v2", 0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_CAT_SHOW, "crud_name", NULL, "read_item", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_CAT_SHOW, "service", NULL, NULL, 1,
                     focused_rest_contract_param),
    FOCUSED_REST_ROW(FRI_OPS_ROUTE, "response_schema", NULL,
                     "zcl.service_operations.index.v2", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_OPS_ROUTE, "crud_name", NULL, "read_collection", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_OPS_ROUTE, "service", NULL, NULL, 0,
                     focused_rest_contract_param),
    FOCUSED_REST_ROW(FRI_OPS_ROUTE, "write_safety", NULL, NULL, 0,
                     focused_rest_contract_param),
    FOCUSED_REST_ROW(FRI_OPS_ROUTE, "preferred_interface", NULL, NULL, 0,
                     focused_rest_contract_param),
    FOCUSED_REST_ROW(FRI_OPS_ROUTE, "status", NULL, NULL, 0,
                     focused_rest_contract_param),
    FOCUSED_REST_ROW(FRI_OPS_ROUTE, "surface", NULL, NULL, 0,
                     focused_rest_contract_param),
};

static const struct focused_rest_check k_focused_rest_catalog_names[] = {
    FOCUSED_REST_ROW(FRI_OPS_FILTER, "schema", NULL,
                     "zcl.query_filter_contract.v1", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_OPS_FILTER, "unknown_filters_error", NULL, NULL, 0,
                     focused_rest_bool_field),
    FOCUSED_REST_ROW(FRI_OPS_ALLOWED, "interface", NULL,
                     "alias_for_preferred_interface", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_OP_SHOW, "response_schema", NULL,
                     "zcl.service_operation.v2", 0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_OP_SHOW, "crud_name", NULL, "read_item", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_OP_SHOW, "operation_id", NULL, NULL, 1,
                     focused_rest_contract_param),
    FOCUSED_REST_ROW(FRI_PROTO_SHOW, "crud_name", NULL, "read_item", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_PROTO_SHOW, "name", NULL, NULL, 1,
                     focused_rest_contract_param),
    FOCUSED_REST_ROW(FRI_EVENTS, "limit", NULL, NULL, 0,
                     focused_rest_contract_param),
    FOCUSED_REST_ROW(FRI_EVENTS, "type", NULL, NULL, 0,
                     focused_rest_contract_param),
    FOCUSED_REST_ROW(FRI_EVENTS, "resource_scope", NULL, "collection", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_EVENTS, "freshness", NULL, "event_projection", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_SUPPLY, "response_schema", NULL, "zcl.supply.v1", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_SUPPLY, "compat_response_schema", NULL,
                     "zcl.supply_legacy_number.v1", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_BLOCK, "canonical", NULL, NULL, 0,
                     focused_rest_bool_field),
    FOCUSED_REST_ROW(FRI_BLOCK, "crud_name", NULL, "read_item", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_BLOCK, "height_or_hash", NULL, NULL, 1,
                     focused_rest_contract_param),
    FOCUSED_REST_ROW(FRI_LEGACY_BLOCK, "legacy_alias_of", NULL,
                     "/api/v1/blocks/{height_or_hash}", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_TX, "response_schema", NULL,
                     "zcl.transactions.show.v1", 0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_LEGACY_TX, "legacy_alias_of", NULL,
                     "/api/v1/transactions/{txid}", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ADDR, "freshness", NULL, "utxo_projection", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_LEGACY_ADDR, "legacy_alias_of", NULL,
                     "/api/v1/addresses/{address}", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_NAMES, "canonical", NULL, NULL, 0,
                     focused_rest_bool_field),
    FOCUSED_REST_ROW(FRI_NAMES, "resource_scope", NULL, "item", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_NAMES_SVC, "response_schema", NULL,
                     "zcl.names.service_directory.v1", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_NAMES_SVC, "crud_name", NULL, "read_subcollection",
                     0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_NAMES_SVC, "resource_scope", NULL, "subcollection",
                     0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_NAMES_SVC, "application_protocol", NULL, "znam", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_NAMES_SVC, "name", NULL, NULL, 1,
                     focused_rest_contract_param),
};

static const struct focused_rest_check k_focused_rest_name_path[] = {
    FOCUSED_REST_ROW(FRI_NS_PATH, "schema", NULL, "zcl.path_param_contract.v1",
                     0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_NS_NAME, "contract_name", NULL, "znam_name", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_NS_NAME, "validator", NULL, "znam_validate_name", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_NS_NAME, "max_length", NULL, NULL, 63,
                     focused_rest_int_field),
    FOCUSED_REST_ROW(FRI_NAMES_SVC, "service", NULL, NULL, 0,
                     focused_rest_contract_param),
    FOCUSED_REST_ROW(FRI_NAMES_SVC, "service_contract", NULL, NULL, 0,
                     focused_rest_contract_param),
    FOCUSED_REST_ROW(FRI_NAMES_SVC, "transport", NULL, NULL, 0,
                     focused_rest_contract_param),
    FOCUSED_REST_ROW(FRI_NAMES_SVC, "endpoint_kind", NULL, NULL, 0,
                     focused_rest_contract_param),
    FOCUSED_REST_ROW(FRI_NAMES_SVC, "valid", NULL, NULL, 0,
                     focused_rest_contract_param),
    FOCUSED_REST_ROW(FRI_NAMES_SVC, "endpoint_only", NULL, NULL, 0,
                     focused_rest_contract_param),
};

static const struct focused_rest_check k_focused_rest_name_filter[] = {
    FOCUSED_REST_ROW(FRI_NS_FILTER, "schema", NULL,
                     "zcl.query_filter_contract.v1", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_NS_FILTER, "unknown_filters_error", NULL, NULL, 0,
                     focused_rest_bool_field),
    FOCUSED_REST_ROW(FRI_NS_ALLOWED, "contract", NULL,
                     "alias_for_service_contract", 0,
                     focused_rest_field_equals),
};

static const struct focused_rest_check k_focused_rest_name_binding[] = {
    FOCUSED_REST_ROW(FRI_NAMES_SVC, "service_contract", NULL, "znam_names", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_NAMES_SVC, "service_catalog_route", NULL,
                     "/api/v1/service-catalog/znam_names", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_NAMES_SVC, "service_operation_id", NULL,
                     "znam_names.resolve_service_directory", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_NAMES_SVC, "service_operation_route", NULL,
                     "/api/v1/service-operations/"
                     "znam_names.resolve_service_directory", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_NS_BIND, "output_schema", NULL,
                     "zcl.names.service_directory.v1", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_NS_BIND, "authority", NULL,
                     "confirmed_chain_projection", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_NAMES, "application_protocol", NULL, "znam", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_NAMES, "protocol_object_types", NULL,
                     "service_record", 0, focused_rest_array_contains),
    FOCUSED_REST_ROW(FRI_NAMES, "protocol_ux_surfaces", NULL,
                     "identity_profile", 0, focused_rest_array_contains),
    FOCUSED_REST_ROW(FRI_NAMES, "reorg_model", NULL,
                     "rebuild_name_state_from_confirmed_chain_after_disconnect",
                     0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_NAMES, "privacy_model", NULL, "public", 0,
                     focused_rest_field_contains),
    FOCUSED_REST_ROW(FRI_NAMES, "name", NULL, NULL, 1,
                     focused_rest_contract_param),
};

static const struct focused_rest_check k_focused_rest_name_pattern[] = {
    FOCUSED_REST_ROW(FRI_NAMES_PATH, "schema", NULL,
                     "zcl.path_param_contract.v1", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_NAMES_PATH_NAME, "pattern", NULL,
                     "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_LEGACY_NAME, "canonical", NULL, NULL, 1,
                     focused_rest_bool_field),
};

static const struct focused_rest_check k_focused_rest_tail[] = {
    FOCUSED_REST_ROW(FRI_LEGACY_PATH_NAME, "validator", NULL,
                     "znam_validate_name", 0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_LEGACY_NAME, "legacy_alias_of", NULL,
                     "/api/v1/names/{name}", 0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_SWAP_CHAINS, "canonical", NULL, NULL, 0,
                     focused_rest_bool_field),
    FOCUSED_REST_ROW(FRI_SWAP_CHAINS, "application_protocol", NULL,
                     "script_contracts", 0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_SWAP_CHAINS, "source_anchor", NULL,
                     "HTLC atomic swaps", 0, focused_rest_field_contains),
    FOCUSED_REST_ROW(FRI_SWAP_CHAINS, "protocol_object_types", NULL,
                     "contract_template", 0, focused_rest_array_contains),
    FOCUSED_REST_ROW(FRI_SWAP_CHAINS, "crypto_model", NULL,
                     "hashlocks_timelocks", 0, focused_rest_field_contains),
    FOCUSED_REST_ROW(FRI_LEGACY_SWAP, "legacy_alias_of", NULL,
                     "/api/v1/swaps/chains", 0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "bootstrap", "drilldown", "/api/v1/bootstrap",
                     0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "service_catalog", "drilldown",
                     "/api/v1/service-catalog", 0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "service_operations", "drilldown",
                     "/api/v1/service-operations", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "api_command", "cli", "z23 api", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "app_protocols_command", "cli",
                     "z23 appprotocols", 0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "service_catalog_command", "cli",
                     "z23 servicecatalog", 0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "service_operations_command", "cli",
                     "z23 serviceoperations [operation_id|key=value...]", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "first_command", "cli", "z23 agent", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "drilldown_command", "cli", "z23 healthcheck",
                     0, focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "milestone_command", "cli", "z23 milestone", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "refold_command", "cli", "z23 refold", 0,
                     focused_rest_field_equals),
    FOCUSED_REST_ROW(FRI_ROOT, "compat_command", "cli", NULL, 1,
                     focused_rest_child_presence),
};

static bool focused_rest_eval_checks(const struct json_value *const *objs,
                                     const struct focused_rest_check *checks,
                                     size_t count)
{
    bool ok = true;
    for (size_t i = 0; ok && i < count; i++)
        ok = checks[i].pred(objs[checks[i].obj], &checks[i]);
    return ok;
}

static bool focused_rest_and_checks(bool ok,
                                    const struct json_value *const *objs,
                                    const struct focused_rest_check *checks,
                                    size_t count)
{
    return ok && focused_rest_eval_checks(objs, checks, count);
}

#define FOCUSED_REST_COUNT(table) (sizeof (table) / sizeof (table)[0])

/* Lookups that stood between checks always run. Checks stay in the original
 * order and stop at the first failure, the same way `ok = ok &&` did. */
static bool focused_rest_check_document(struct json_value *root, bool ok)
{
    const struct json_value *objs[FRI_N];

    memset(objs, 0, sizeof objs);
    objs[FRI_ROOT] = root;
    ok = focused_rest_and_checks(ok, objs, k_focused_rest_identity,
                                 FOCUSED_REST_COUNT(k_focused_rest_identity));
    objs[FRI_LAYER] = json_get(root, "layer_model");
    ok = focused_rest_and_checks(ok, objs, k_focused_rest_layer,
                                 FOCUSED_REST_COUNT(k_focused_rest_layer));
    objs[FRI_PROTOCOLS] = focused_rest_child(objs[FRI_LAYER],
                                             "application_protocols");
    objs[FRI_ZLSP] = api_test_find_named(objs[FRI_PROTOCOLS], "zlsp");
    objs[FRI_ZSLP_PROTO] = api_test_find_named(objs[FRI_PROTOCOLS], "zslp");
    objs[FRI_ZNAM] = api_test_find_named(objs[FRI_PROTOCOLS], "znam");
    objs[FRI_SCRIPT] = api_test_find_named(objs[FRI_PROTOCOLS],
                                           "script_contracts");
    objs[FRI_SWAP_PROTO] = api_test_find_named(objs[FRI_PROTOCOLS],
                                               "atomic_swaps");
    ok = focused_rest_and_checks(ok, objs, k_focused_rest_protocols,
                                 FOCUSED_REST_COUNT(k_focused_rest_protocols));
    objs[FRI_RESOURCES] = json_get(root, "resources");
    objs[FRI_BOOT_RES] = api_test_find_named(objs[FRI_RESOURCES], "bootstrap");
    objs[FRI_ZSLP_RES] = api_test_find_named(objs[FRI_RESOURCES],
                                             "zslp_tokens");
    objs[FRI_PROTO_RES] = api_test_find_named(objs[FRI_RESOURCES],
                                              "protocols");
    objs[FRI_CAT_RES] = api_test_find_named(objs[FRI_RESOURCES],
                                            "service_catalog");
    objs[FRI_OPS_RES] = api_test_find_named(objs[FRI_RESOURCES],
                                            "service_operations");
    objs[FRI_NAMESVC_RES] = api_test_find_named(objs[FRI_RESOURCES],
                                                "name_services");
    ok = focused_rest_and_checks(ok, objs, k_focused_rest_resources,
                                 FOCUSED_REST_COUNT(k_focused_rest_resources));
    objs[FRI_ROUTES] = json_get(root, "route_contracts");
    ok = focused_rest_and_checks(ok, objs, k_focused_rest_route_counts,
                                 FOCUSED_REST_COUNT(
                                     k_focused_rest_route_counts));
    objs[FRI_HODL] = api_test_find_contract(objs[FRI_ROUTES], "/api/v1/hodl");
    objs[FRI_BOOT] = api_test_find_contract(objs[FRI_ROUTES],
                                            "/api/v1/bootstrap");
    objs[FRI_LEGACY_BOOT] = api_test_find_contract(objs[FRI_ROUTES],
                                                   "/api/v1/bootstrapstatus");
    objs[FRI_WALLET] = api_test_find_contract(objs[FRI_ROUTES],
                                              "/api/v1/wallet");
    objs[FRI_ZSLP] = api_test_find_contract(objs[FRI_ROUTES],
                                            "/api/v1/zslp/tokens");
    objs[FRI_PROTO_ROUTE] = api_test_find_contract(objs[FRI_ROUTES],
                                                   "/api/v1/protocols");
    objs[FRI_CAT_ROUTE] = api_test_find_contract(objs[FRI_ROUTES],
                                                 "/api/v1/service-catalog");
    objs[FRI_CAT_SHOW] = api_test_find_contract(
        objs[FRI_ROUTES], "/api/v1/service-catalog/{service}");
    objs[FRI_OPS_ROUTE] = api_test_find_contract(objs[FRI_ROUTES],
                                                 "/api/v1/service-operations");
    objs[FRI_OP_SHOW] = api_test_find_contract(
        objs[FRI_ROUTES], "/api/v1/service-operations/{operation_id}");
    objs[FRI_PROTO_SHOW] = api_test_find_contract(objs[FRI_ROUTES],
                                                  "/api/v1/protocols/{name}");
    objs[FRI_NAMES] = api_test_find_contract(objs[FRI_ROUTES],
                                             "/api/v1/names/{name}");
    objs[FRI_NAMES_SVC] = api_test_find_contract(
        objs[FRI_ROUTES], "/api/v1/names/{name}/services");
    objs[FRI_LEGACY_NAME] = api_test_find_contract(objs[FRI_ROUTES],
                                                   "/api/v1/name/{name}");
    objs[FRI_SWAP_CHAINS] = api_test_find_contract(objs[FRI_ROUTES],
                                                   "/api/v1/swaps/chains");
    objs[FRI_LEGACY_SWAP] = api_test_find_contract(objs[FRI_ROUTES],
                                                   "/api/v1/swap_chains");
    objs[FRI_EVENTS] = api_test_find_contract(objs[FRI_ROUTES],
                                              "/api/v1/events");
    objs[FRI_SUPPLY] = api_test_find_contract(objs[FRI_ROUTES],
                                              "/api/v1/supply");
    objs[FRI_BLOCK] = api_test_find_contract(
        objs[FRI_ROUTES], "/api/v1/blocks/{height_or_hash}");
    objs[FRI_LEGACY_BLOCK] = api_test_find_contract(
        objs[FRI_ROUTES], "/api/v1/block/{height_or_hash}");
    objs[FRI_TX] = api_test_find_contract(objs[FRI_ROUTES],
                                          "/api/v1/transactions/{txid}");
    objs[FRI_LEGACY_TX] = api_test_find_contract(objs[FRI_ROUTES],
                                                 "/api/v1/tx/{txid}");
    objs[FRI_ADDR] = api_test_find_contract(objs[FRI_ROUTES],
                                            "/api/v1/addresses/{address}");
    objs[FRI_LEGACY_ADDR] = api_test_find_contract(objs[FRI_ROUTES],
                                                   "/api/v1/address/{address}");
    ok = focused_rest_and_checks(ok, objs, k_focused_rest_bootstrap_head,
                                 FOCUSED_REST_COUNT(
                                     k_focused_rest_bootstrap_head));
    objs[FRI_BOOT_BIND] = focused_rest_child(objs[FRI_BOOT],
                                             "service_binding");
    ok = focused_rest_and_checks(ok, objs, k_focused_rest_bootstrap_bind,
                                 FOCUSED_REST_COUNT(
                                     k_focused_rest_bootstrap_bind));
    objs[FRI_HODL_TEL] = json_get(objs[FRI_HODL], "telemetry");
    ok = focused_rest_and_checks(ok, objs, k_focused_rest_telemetry,
                                 FOCUSED_REST_COUNT(k_focused_rest_telemetry));
    objs[FRI_HODL_CRYPTO] = json_get(objs[FRI_HODL], "crypto_policy");
    ok = focused_rest_and_checks(ok, objs, k_focused_rest_crypto_ops,
                                 FOCUSED_REST_COUNT(k_focused_rest_crypto_ops));
    objs[FRI_OPS_FILTER] = focused_rest_child(objs[FRI_OPS_ROUTE],
                                              "filter_contract");
    objs[FRI_OPS_ALLOWED] = focused_rest_child(objs[FRI_OPS_FILTER],
                                               "allowed_filters");
    ok = focused_rest_and_checks(ok, objs, k_focused_rest_catalog_names,
                                 FOCUSED_REST_COUNT(
                                     k_focused_rest_catalog_names));
    objs[FRI_NS_PATH] = focused_rest_child(objs[FRI_NAMES_SVC],
                                           "path_param_contract");
    objs[FRI_NS_PARAMS] = focused_rest_child(objs[FRI_NS_PATH], "params");
    objs[FRI_NS_NAME] = focused_rest_child(objs[FRI_NS_PARAMS], "name");
    ok = focused_rest_and_checks(ok, objs, k_focused_rest_name_path,
                                 FOCUSED_REST_COUNT(k_focused_rest_name_path));
    objs[FRI_NS_FILTER] = focused_rest_child(objs[FRI_NAMES_SVC],
                                             "filter_contract");
    objs[FRI_NS_ALLOWED] = focused_rest_child(objs[FRI_NS_FILTER],
                                              "allowed_filters");
    ok = focused_rest_and_checks(ok, objs, k_focused_rest_name_filter,
                                 FOCUSED_REST_COUNT(
                                     k_focused_rest_name_filter));
    objs[FRI_NS_BIND] = focused_rest_child(objs[FRI_NAMES_SVC],
                                           "service_binding");
    ok = focused_rest_and_checks(ok, objs, k_focused_rest_name_binding,
                                 FOCUSED_REST_COUNT(
                                     k_focused_rest_name_binding));
    objs[FRI_NAMES_PATH] = focused_rest_child(objs[FRI_NAMES],
                                              "path_param_contract");
    objs[FRI_NAMES_PATH_NAME] = focused_rest_grandchild(objs[FRI_NAMES_PATH],
                                                        "params", "name");
    ok = focused_rest_and_checks(ok, objs, k_focused_rest_name_pattern,
                                 FOCUSED_REST_COUNT(
                                     k_focused_rest_name_pattern));
    objs[FRI_LEGACY_PATH] = focused_rest_child(objs[FRI_LEGACY_NAME],
                                               "path_param_contract");
    objs[FRI_LEGACY_PATH_NAME] = focused_rest_grandchild(
        objs[FRI_LEGACY_PATH], "params", "name");
    return focused_rest_and_checks(ok, objs, k_focused_rest_tail,
                                   FOCUSED_REST_COUNT(k_focused_rest_tail));
}

int api_rest_index_focused_tests(void)
{
    int failures = 0;

    printf("api: REST index explains v1 first call and CRUD shape... ");
    {
        static uint8_t index_resp[262144];
        size_t n = api_handle_request("GET", "/api/v1", NULL, 0,
                                      index_resp, sizeof(index_resp));
        const char *body = api_test_body(index_resp, n, sizeof(index_resp));
        struct json_value root;
        json_init(&root);
        bool ok = n > 0 && body && json_read(&root, body, strlen(body));
        ok = focused_rest_check_document(&root, ok);
        json_free(&root);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
