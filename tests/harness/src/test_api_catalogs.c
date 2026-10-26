/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * API catalog resources: bootstrap status, the protocol registry overlay
 * contracts, and the service catalog of sovereign UX operations.
 */

#include "test/api_test_fixtures.h"

enum {
    API_CATALOG_STR = 1,
    API_CATALOG_INT,
    API_CATALOG_BOOL,
    API_CATALOG_HAS,
    API_CATALOG_SUBSTR,
    API_CATALOG_ARRAY,
    API_CATALOG_NONEMPTY,
    API_CATALOG_BUILD,
    API_CATALOG_PRESENT,
    API_CATALOG_COUNT
};

enum {
    API_CATALOG_VIA_ROOT = 0,
    API_CATALOG_VIA_GET1,
    API_CATALOG_VIA_GET2,
    API_CATALOG_VIA_NAMED,
    API_CATALOG_VIA_NAMED_GET,
    API_CATALOG_VIA_FIND,
    API_CATALOG_VIA_NAMED_FIND
};

enum {
    API_CATALOG_F_TYPE = 1u,
    API_CATALOG_F_SIZES = 2u,
    API_CATALOG_F_INT_KEY = 4u,
    API_CATALOG_F_INT_ARR = 8u,
    API_CATALOG_F_SIZE_KEY = 16u
};

struct api_catalog_expect {
    uint8_t op;
    /* guard: 1 = the subject must exist; 2 = the first-level object
     * (json_get(root, k0)) must exist before the subject is read. */
    uint8_t guard;
    uint8_t via;
    int8_t rel;
    uint8_t flags;
    const char *k0;
    const char *k1;
    const char *k2;
    const char *k3;
    const char *match;
    const char *field;
    const char *text;
    int64_t num;
};

static bool api_catalog_int_rel(int64_t got, int64_t want, int rel)
{
    if (rel == 0)
        return got == want;
    if (rel > 0)
        return got > want;
    if (rel < -1)
        return got >= want;
    return got < want;
}

static bool api_catalog_str_nonempty(const char *str)
{
    return str && str[0] != '\0';
}

static bool api_catalog_guard_rejects(uint8_t guard,
                                      const struct json_value *subject)
{
    return guard == 1 && !subject;
}

static void api_catalog_terminate(uint8_t *buf, size_t n, size_t cap)
{
    buf[n < cap ? n : cap - 1] = '\0';
}

static bool api_catalog_parse(bool ok, struct json_value *root,
                              const char *body, size_t n)
{
    json_init(root);
    return ok && n > 0 && body && json_read(root, body, strlen(body));
}

static const struct json_value *api_catalog_subject(
    const struct json_value *root, const struct api_catalog_expect *row)
{
    const struct json_value *obj;

    switch (row->via) {
    case API_CATALOG_VIA_ROOT:
        return root;
    case API_CATALOG_VIA_GET1:
        return json_get(root, row->k0);
    case API_CATALOG_VIA_GET2:
        return json_get(json_get(root, row->k0), row->k1);
    case API_CATALOG_VIA_NAMED:
        return api_test_find_named(json_get(root, row->k0), row->k1);
    case API_CATALOG_VIA_NAMED_GET:
        return json_get(api_test_find_named(json_get(root, row->k0),
                                            row->k1),
                        row->k2);
    case API_CATALOG_VIA_FIND:
        return api_test_find_str_field(json_get(root, row->k0),
                                       row->k1, row->match);
    case API_CATALOG_VIA_NAMED_FIND:
        obj = api_test_find_named(json_get(root, row->k0), row->k1);
        return api_test_find_str_field(json_get(obj, row->k2),
                                       row->k3, row->match);
    default:
        return NULL;
    }
}

static bool api_catalog_count_ok(const struct json_value *root,
                                 const struct api_catalog_expect *row)
{
    const struct json_value *arr;
    const struct json_value *int_obj;
    const struct json_value *sized;

    if (row->op != API_CATALOG_COUNT)
        return false;
    arr = json_get(root, row->k0);
    if (!arr)
        return false;
    if ((row->flags & API_CATALOG_F_TYPE) != 0 &&
        arr->type != JSON_ARR)
        return false;
    if ((row->flags & API_CATALOG_F_SIZES) != 0)
        return json_size(arr) == json_size(json_get(root, row->k1));
    if (!row->field)
        return json_size(arr) == (size_t)row->num;
    if ((row->flags & API_CATALOG_F_INT_ARR) != 0)
        int_obj = arr;
    else if ((row->flags & API_CATALOG_F_INT_KEY) != 0)
        int_obj = json_get(root, row->k1);
    else
        int_obj = root;
    sized = arr;
    if ((row->flags & API_CATALOG_F_SIZE_KEY) != 0)
        sized = json_get(root, row->k1);
    return json_get_int(json_get(int_obj, row->field)) ==
           (int64_t)json_size(sized);
}

static bool api_catalog_expect_row(const struct json_value *root,
                                   const struct api_catalog_expect *row)
{
    const struct json_value *subject;
    const char *str;

    if (row->guard == 2 && !json_get(root, row->k0))
        return false;
    subject = api_catalog_subject(root, row);
    if (api_catalog_guard_rejects(row->guard, subject))
        return false;
    switch (row->op) {
    case API_CATALOG_STR:
        return strcmp(json_get_str(json_get(subject, row->field)),
                      row->text) == 0;
    case API_CATALOG_INT:
        return api_catalog_int_rel(
            json_get_int(json_get(subject, row->field)), row->num, row->rel);
    case API_CATALOG_BOOL:
        return json_get_bool(json_get(subject, row->field)) ==
               (row->num != 0);
    case API_CATALOG_HAS:
        return json_get(subject, row->field) != NULL;
    case API_CATALOG_SUBSTR:
        str = json_get_str(json_get(subject, row->field));
        return strstr(str, row->text) != NULL;
    case API_CATALOG_ARRAY:
        return api_test_array_has_str(json_get(subject, row->field),
                                      row->text);
    case API_CATALOG_NONEMPTY:
        return api_catalog_str_nonempty(
            json_get_str(json_get(subject, row->field)));
    case API_CATALOG_BUILD:
        return strcmp(json_get_str(json_get(subject, row->field)),
                      zcl_build_commit()) == 0;
    case API_CATALOG_PRESENT:
        return subject != NULL;
    default:
        return api_catalog_count_ok(root, row);
    }
}

static bool api_catalog_expect_all(bool ok, const struct json_value *root,
                                   const struct api_catalog_expect *rows,
                                   size_t n)
{
    for (size_t i = 0; i < n; i++)
        ok = ok && api_catalog_expect_row(root, &rows[i]);
    return ok;
}

static const struct api_catalog_expect k_bootstrap_status[] = {
    { .op = API_CATALOG_STR, .field = "schema",
      .text = "zcl.bootstrap_status.v1" },
    { .op = API_CATALOG_INT, .field = "schema_version", .num = 1 },
    { .op = API_CATALOG_BOOL, .field = "ok", .num = 0 },
    { .op = API_CATALOG_STR, .field = "readiness", .text = "blocked" },
    { .op = API_CATALOG_STR, .field = "fresh_node_next_action",
      .text = "fix_named_blockers_before_advertising_bootstrap" },
    { .op = API_CATALOG_BOOL, .field = "serving_p2p_bootstrap", .num = 0 },
    { .op = API_CATALOG_BOOL, .field = "zclassic23_fast_sync_compatible",
      .num = 0 },
    { .op = API_CATALOG_HAS, .field = "binary" },
    { .op = API_CATALOG_BUILD, .via = API_CATALOG_VIA_GET1,
      .k0 = "binary", .field = "build_commit" },
    { .op = API_CATALOG_NONEMPTY, .via = API_CATALOG_VIA_GET1,
      .k0 = "binary", .field = "advertised_subver" },
    { .op = API_CATALOG_INT, .rel = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "p2p", .field = "protocolversion" },
    { .op = API_CATALOG_STR, .via = API_CATALOG_VIA_GET1,
      .k0 = "legacy_p2p_bootstrap", .field = "schema",
      .text = "zcl.bootstrap.p2p.v1" },
    { .op = API_CATALOG_STR, .via = API_CATALOG_VIA_GET1,
      .k0 = "beta6_snapshot_bootstrap", .field = "schema",
      .text = "zclassicd.bootstrap.snapshot.v3" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "zclassic23_bootstrap", .field = "schema",
      .text = "zcl.bootstrap.zclassic23.v1" },
    { .op = API_CATALOG_BOOL, .via = API_CATALOG_VIA_GET1,
      .k0 = "zclassic23_bootstrap", .field = "serving", .num = 0 },
    { .op = API_CATALOG_BOOL, .via = API_CATALOG_VIA_GET1,
      .k0 = "zclassic23_bootstrap",
      .field = "preferred_for_fresh_zclassic23", .num = 0 },
    { .op = API_CATALOG_STR, .via = API_CATALOG_VIA_GET1,
      .k0 = "zclassic23_bootstrap", .field = "route_preference",
      .text = "direct_p2p_then_znam_onion_fallback" },
    { .op = API_CATALOG_STR, .via = API_CATALOG_VIA_GET1,
      .k0 = "zclassic23_bootstrap", .field = "endpoint_record_schema",
      .text = "zcl.names.service_record.v1" },
    { .op = API_CATALOG_ARRAY, .via = API_CATALOG_VIA_GET1,
      .k0 = "zclassic23_bootstrap", .field = "fresh_node_flow",
      .text = "resolve_znam_service_directory_if_direct_p2p_fails" },
    { .op = API_CATALOG_STR, .via = API_CATALOG_VIA_GET1,
      .k0 = "snapshot_loader", .field = "schema",
      .text = "zcl.snapshot_loader.v1" },
    { .op = API_CATALOG_STR, .via = API_CATALOG_VIA_GET2,
      .k0 = "snapshot_loader", .k1 = "authority", .field = "schema",
      .text = "zcl.snapshot_loader_authority.v1" },
    { .op = API_CATALOG_BOOL, .via = API_CATALOG_VIA_GET2,
      .k0 = "snapshot_loader", .k1 = "authority",
      .field = "progress_store_open", .num = 0 },
    { .op = API_CATALOG_ARRAY, .field = "blockers",
      .text = "p2p_not_initialized" },
    { .op = API_CATALOG_ARRAY, .field = "blockers",
      .text = "provable_tip_not_published" },
    { .op = API_CATALOG_STR, .field = "source_projection",
      .text = "network_bootstrap" },
};

static const struct api_catalog_expect k_bootstrap_alias[] = {
    { .op = API_CATALOG_STR, .field = "schema",
      .text = "zcl.bootstrap_status.v1" },
};

static const struct api_catalog_expect k_protocols_index[] = {
    { .op = API_CATALOG_STR, .field = "schema",
      .text = "zcl.application_protocols.index.v2" },
    { .op = API_CATALOG_STR, .field = "base_layer", .text = "zclassic_l1" },
    { .op = API_CATALOG_STR, .field = "service_layer",
      .text = "zclassic23_application_layer" },
    { .op = API_CATALOG_COUNT, .k0 = "protocols",
      .field = "protocol_count" },
    { .op = API_CATALOG_ARRAY, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "protocols", .k1 = "zslp", .field = "crud_capabilities",
      .text = "read_collection" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "protocols", .k1 = "zslp", .field = "anchor_kind",
      .text = "op_return" },
    { .op = API_CATALOG_ARRAY, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "protocols", .k1 = "zslp", .field = "object_types",
      .text = "token_transfer" },
    { .op = API_CATALOG_ARRAY, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "protocols", .k1 = "znam", .field = "ux_surfaces",
      .text = "node_service_directory" },
    { .op = API_CATALOG_ARRAY, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "protocols", .k1 = "market", .field = "object_types",
      .text = "content_descriptor" },
    { .op = API_CATALOG_SUBSTR, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "protocols", .k1 = "market", .field = "transport_model",
      .text = "direct_p2p" },
};

static const struct api_catalog_expect k_script_contracts[] = {
    { .op = API_CATALOG_STR, .field = "schema",
      .text = "zcl.application_protocol_contract.v2" },
    { .op = API_CATALOG_STR, .field = "name", .text = "script_contracts" },
    { .op = API_CATALOG_STR, .field = "anchor_kind",
      .text = "standard_script" },
    { .op = API_CATALOG_ARRAY, .field = "crud_capabilities",
      .text = "construct_contract" },
    { .op = API_CATALOG_STR, .field = "construction_status",
      .text = "htlc_builders_and_zcl_settlement_active" },
    { .op = API_CATALOG_ARRAY, .field = "object_types",
      .text = "contract_template" },
    { .op = API_CATALOG_ARRAY, .field = "ux_surfaces",
      .text = "script_preview" },
    { .op = API_CATALOG_SUBSTR, .field = "crypto_model",
      .text = "legacy_valid_zclassic_script" },
};

static const struct api_catalog_expect k_service_catalog[] = {
    { .op = API_CATALOG_STR, .field = "schema",
      .text = "zcl.service_catalog.v2" },
    { .op = API_CATALOG_STR, .field = "base_layer", .text = "zclassic_l1" },
    { .op = API_CATALOG_STR, .field = "service_layer",
      .text = "zclassic23_application_layer" },
    { .op = API_CATALOG_STR, .field = "runtime_health_route",
      .text = "/api/v1/services" },
    { .op = API_CATALOG_STR, .field = "application_protocols_route",
      .text = "/api/v1/protocols" },
    { .op = API_CATALOG_STR, .field = "member_route",
      .text = "/api/v1/service-catalog/{service}" },
    { .op = API_CATALOG_STR, .field = "operation_route",
      .text = "/api/v1/service-operations/{operation_id}" },
    { .op = API_CATALOG_STR, .field = "operation_collection_route",
      .text = "/api/v1/service-operations" },
    { .op = API_CATALOG_STR, .field = "operation_schema",
      .text = "zcl.service_operation.v2" },
    { .op = API_CATALOG_STR, .field = "runtime_probe_schema",
      .text = "zcl.service_runtime_probe.v1" },
    { .op = API_CATALOG_SUBSTR, .field = "consensus_boundary",
      .text = "legacy consensus" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "sovereign_ux", .field = "schema",
      .text = "zcl.sovereign_ux_contract.v2" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "sovereign_ux", .field = "base_layer", .text = "zclassic_l1" },
    { .op = API_CATALOG_ARRAY, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "sovereign_ux", .field = "flow", .text = "resolve_znam_name" },
    { .op = API_CATALOG_ARRAY, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "sovereign_ux", .field = "flow",
      .text = "read_name_service_directory" },
    { .op = API_CATALOG_ARRAY, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "sovereign_ux", .field = "flow",
      .text = "prefer_direct_p2p_when_handshaked" },
    { .op = API_CATALOG_STR, .guard = 2, .via = API_CATALOG_VIA_GET2,
      .k0 = "sovereign_ux", .k1 = "routes", .field = "service_catalog",
      .text = "/api/v1/service-catalog" },
    { .op = API_CATALOG_STR, .guard = 2, .via = API_CATALOG_VIA_GET2,
      .k0 = "sovereign_ux", .k1 = "routes", .field = "names",
      .text = "/api/v1/names/{name}" },
    { .op = API_CATALOG_STR, .guard = 2, .via = API_CATALOG_VIA_GET2,
      .k0 = "sovereign_ux", .k1 = "routes", .field = "name_services",
      .text = "/api/v1/names/{name}/services" },
    { .op = API_CATALOG_COUNT, .flags = API_CATALOG_F_TYPE,
      .k0 = "services", .field = "service_count" },
    { .op = API_CATALOG_COUNT, .flags = API_CATALOG_F_TYPE,
      .k0 = "runtime_probes", .field = "runtime_probe_count" },
    { .op = API_CATALOG_COUNT, .flags = API_CATALOG_F_SIZES,
      .k0 = "runtime_probes", .k1 = "services" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_FIND,
      .k0 = "runtime_probes", .k1 = "service", .match = "bootstrap",
      .field = "route", .text = "/api/v1/bootstrap" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_FIND,
      .k0 = "runtime_probes", .k1 = "service", .match = "bootstrap",
      .field = "operation_id", .text = "bootstrap.read_bootstrap_status" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_FIND,
      .k0 = "runtime_probes", .k1 = "service", .match = "bootstrap",
      .field = "service_catalog_route",
      .text = "/api/v1/service-catalog/bootstrap" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "services", .k1 = "bootstrap", .field = "rest_collection",
      .text = "/api/v1/bootstrap" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "services", .k1 = "bootstrap", .field = "schema",
      .text = "zcl.service_contract.v2" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "services", .k1 = "bootstrap", .field = "self_route",
      .text = "/api/v1/service-catalog/bootstrap" },
    { .op = API_CATALOG_ARRAY, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "services", .k1 = "bootstrap", .field = "transports",
      .text = "p2p" },
    { .op = API_CATALOG_ARRAY, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "services", .k1 = "bootstrap", .field = "depends_on_services",
      .text = "full_node" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "services", .k1 = "bootstrap", .field = "read_model",
      .text = "network_bootstrap_status_and_peer_projection" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_GET,
      .k0 = "services", .k1 = "bootstrap", .k2 = "runtime_probe",
      .field = "schema", .text = "zcl.service_runtime_probe.v1" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_GET,
      .k0 = "services", .k1 = "bootstrap", .k2 = "runtime_probe",
      .field = "route", .text = "/api/v1/bootstrap" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_GET,
      .k0 = "services", .k1 = "bootstrap", .k2 = "runtime_probe",
      .field = "operation_id", .text = "bootstrap.read_bootstrap_status" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_GET,
      .k0 = "services", .k1 = "bootstrap", .k2 = "runtime_probe",
      .field = "operation_route",
      .text = "/api/v1/service-operations/"
              "bootstrap.read_bootstrap_status" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_GET,
      .k0 = "services", .k1 = "bootstrap", .k2 = "runtime_probe",
      .field = "expected_schema", .text = "zcl.bootstrap_status.v1" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_GET,
      .k0 = "services", .k1 = "bootstrap", .k2 = "runtime_probe",
      .field = "freshness", .text = "network_bootstrap" },
    { .op = API_CATALOG_SUBSTR, .guard = 1, .via = API_CATALOG_VIA_NAMED_GET,
      .k0 = "services", .k1 = "bootstrap", .k2 = "runtime_probe",
      .field = "success_signal",
      .text = "zclassic23_fast_sync_compatible" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_GET,
      .k0 = "services", .k1 = "bootstrap", .k2 = "runtime_probe",
      .field = "failure_next_action",
      .text = "inspect_peer_bootstrap_readiness" },
    { .op = API_CATALOG_BOOL, .via = API_CATALOG_VIA_NAMED_GET,
      .k0 = "services", .k1 = "bootstrap", .k2 = "runtime_probe",
      .field = "operator_private", .num = 0 },
    { .op = API_CATALOG_INT, .guard = 1, .via = API_CATALOG_VIA_NAMED_GET,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operation_summary",
      .field = "operation_count", .num = 3 },
    { .op = API_CATALOG_INT, .guard = 1, .via = API_CATALOG_VIA_NAMED_GET,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operation_summary",
      .field = "public_read_count", .num = 2 },
    { .op = API_CATALOG_INT, .guard = 1, .via = API_CATALOG_VIA_NAMED_GET,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operation_summary",
      .field = "operator_private_count", .num = 1 },
    { .op = API_CATALOG_INT, .guard = 1, .via = API_CATALOG_VIA_NAMED_GET,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operation_summary",
      .field = "destructive_count", .num = 0 },
    { .op = API_CATALOG_INT, .guard = 1, .via = API_CATALOG_VIA_NAMED_GET,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operation_summary",
      .field = "preferred_rest_count", .num = 2 },
    { .op = API_CATALOG_INT, .guard = 1, .via = API_CATALOG_VIA_NAMED_GET,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operation_summary",
      .field = "preferred_rpc_count", .num = 1 },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operations",
      .k3 = "operation", .match = "read_bootstrap_status",
      .field = "schema", .text = "zcl.service_operation.v2" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operations",
      .k3 = "operation", .match = "read_bootstrap_status",
      .field = "operation_id", .text = "bootstrap.read_bootstrap_status" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operations",
      .k3 = "operation", .match = "read_bootstrap_status",
      .field = "self_route",
      .text = "/api/v1/service-operations/bootstrap.read_bootstrap_status" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operations",
      .k3 = "operation", .match = "read_bootstrap_status",
      .field = "service_catalog_route",
      .text = "/api/v1/service-catalog/bootstrap" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operations",
      .k3 = "operation", .match = "read_bootstrap_status",
      .field = "rest_route", .text = "/api/v1/bootstrap" },
    /* rpc_method is the native RPC/CLI surface for this operation. */
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operations",
      .k3 = "operation", .match = "read_bootstrap_status",
      .field = "rpc_method", .text = "bootstrapstatus" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operations",
      .k3 = "operation", .match = "read_bootstrap_status",
      .field = "execution_surface", .text = "rest" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operations",
      .k3 = "operation", .match = "read_bootstrap_status",
      .field = "write_safety", .text = "public_read_only" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operations",
      .k3 = "operation", .match = "read_bootstrap_status",
      .field = "agent_preferred_interface", .text = "rest" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operations",
      .k3 = "operation", .match = "read_bootstrap_status",
      .field = "agent_next_step",
      .text = "call_rest_route_and_validate_output_schema" },
    { .op = API_CATALOG_BOOL, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operations",
      .k3 = "operation", .match = "read_bootstrap_status",
      .field = "rest_callable", .num = 1 },
    { .op = API_CATALOG_BOOL, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operations",
      .k3 = "operation", .match = "read_bootstrap_status",
      .field = "rpc_callable", .num = 1 },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operations",
      .k3 = "operation", .match = "list_peer_projection",
      .field = "operation_id", .text = "bootstrap.list_peer_projection" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operations",
      .k3 = "operation", .match = "list_peer_projection",
      .field = "rest_route", .text = "/api/v1/peers" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operations",
      .k3 = "operation", .match = "list_peer_projection",
      .field = "output_schema", .text = "zcl.peers.index.v1" },
    { .op = API_CATALOG_BOOL, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operations",
      .k3 = "operation", .match = "list_peer_projection",
      .field = "rest_callable", .num = 1 },
    { .op = API_CATALOG_BOOL, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "bootstrap", .k2 = "operations",
      .k3 = "operation", .match = "list_peer_projection",
      .field = "rpc_callable", .num = 0 },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "services", .k1 = "znam_names",
      .field = "application_protocol", .text = "znam" },
    { .op = API_CATALOG_ARRAY, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "services", .k1 = "znam_names", .field = "crud_capabilities",
      .text = "construct_transaction" },
    { .op = API_CATALOG_ARRAY, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "services", .k1 = "znam_names", .field = "crud_capabilities",
      .text = "read_subcollection" },
    { .op = API_CATALOG_ARRAY, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "services", .k1 = "znam_names", .field = "depends_on_services",
      .text = "full_node" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "services", .k1 = "znam_names", .field = "write_model",
      .text = "construct_znam_op_return_transactions" },
    { .op = API_CATALOG_SUBSTR, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "services", .k1 = "znam_names", .field = "verified_by",
      .text = "op_return" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "znam_names", .k2 = "operations",
      .k3 = "operation", .match = "resolve_service_directory",
      .field = "operation_id",
      .text = "znam_names.resolve_service_directory" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "znam_names", .k2 = "operations",
      .k3 = "operation", .match = "resolve_service_directory",
      .field = "rest_route", .text = "/api/v1/names/{name}/services" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "znam_names", .k2 = "operations",
      .k3 = "operation", .match = "resolve_service_directory",
      .field = "crud_capability", .text = "read_subcollection" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "znam_names", .k2 = "operations",
      .k3 = "operation", .match = "resolve_service_directory",
      .field = "output_schema", .text = "zcl.names.service_directory.v1" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "znam_names", .k2 = "operations",
      .k3 = "operation", .match = "resolve_service_directory",
      .field = "agent_preferred_interface", .text = "rest" },
    { .op = API_CATALOG_BOOL, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "znam_names", .k2 = "operations",
      .k3 = "operation", .match = "resolve_service_directory",
      .field = "rest_callable", .num = 1 },
    { .op = API_CATALOG_BOOL, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "znam_names", .k2 = "operations",
      .k3 = "operation", .match = "resolve_service_directory",
      .field = "rpc_callable", .num = 0 },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "znam_names", .k2 = "operations",
      .k3 = "operation", .match = "construct_name_register",
      .field = "rpc_method", .text = "name_register" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "znam_names", .k2 = "operations",
      .k3 = "operation", .match = "construct_name_register",
      .field = "operation_id",
      .text = "znam_names.construct_name_register" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "znam_names", .k2 = "operations",
      .k3 = "operation", .match = "construct_name_register",
      .field = "self_route",
      .text = "/api/v1/service-operations/"
              "znam_names.construct_name_register" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "znam_names", .k2 = "operations",
      .k3 = "operation", .match = "construct_name_register",
      .field = "service_catalog_route",
      .text = "/api/v1/service-catalog/znam_names" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "znam_names", .k2 = "operations",
      .k3 = "operation", .match = "construct_name_register",
      .field = "write_safety", .text = "operator_private_destructive" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "znam_names", .k2 = "operations",
      .k3 = "operation", .match = "construct_name_register",
      .field = "agent_preferred_interface", .text = "rpc" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "znam_names", .k2 = "operations",
      .k3 = "operation", .match = "construct_name_register",
      .field = "agent_next_step",
      .text = "review_destructive_write_safety_then_call_rpc_method" },
    { .op = API_CATALOG_BOOL, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "znam_names", .k2 = "operations",
      .k3 = "operation", .match = "construct_name_register",
      .field = "rest_callable", .num = 0 },
    { .op = API_CATALOG_BOOL, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "znam_names", .k2 = "operations",
      .k3 = "operation", .match = "construct_name_register",
      .field = "rpc_callable", .num = 1 },
    { .op = API_CATALOG_BOOL, .guard = 1, .via = API_CATALOG_VIA_NAMED_FIND,
      .k0 = "services", .k1 = "znam_names", .k2 = "operations",
      .k3 = "operation", .match = "construct_name_register",
      .field = "destructive", .num = 1 },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "services", .k1 = "onion_directory", .field = "rest_collection",
      .text = "/api/v1/onion/announcements" },
    { .op = API_CATALOG_ARRAY, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "services", .k1 = "onion_directory", .field = "transports",
      .text = "onion" },
    { .op = API_CATALOG_ARRAY, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "services", .k1 = "onion_directory",
      .field = "depends_on_services", .text = "znam_names" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "services", .k1 = "file_services", .field = "rest_item",
      .text = "/api/v1/files/{sha3}" },
    { .op = API_CATALOG_ARRAY, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "services", .k1 = "file_services", .field = "object_types",
      .text = "chunk" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "services", .k1 = "script_contracts",
      .field = "application_protocol", .text = "script_contracts" },
    { .op = API_CATALOG_SUBSTR, .guard = 1, .via = API_CATALOG_VIA_NAMED,
      .k0 = "services", .k1 = "script_contracts", .field = "trust_model",
      .text = "no_consensus_extension" },
};

static const struct api_catalog_expect k_service_operations[] = {
    { .op = API_CATALOG_STR, .field = "schema",
      .text = "zcl.service_operations.index.v2" },
    { .op = API_CATALOG_STR, .field = "catalog_route",
      .text = "/api/v1/service-catalog" },
    { .op = API_CATALOG_STR, .field = "service_member_route",
      .text = "/api/v1/service-catalog/{service}" },
    { .op = API_CATALOG_STR, .field = "member_route",
      .text = "/api/v1/service-operations/{operation_id}" },
    { .op = API_CATALOG_STR, .field = "operation_schema",
      .text = "zcl.service_operation.v2" },
    { .op = API_CATALOG_COUNT, .flags = API_CATALOG_F_TYPE,
      .k0 = "operations", .field = "operation_count" },
    { .op = API_CATALOG_COUNT,
      .flags = API_CATALOG_F_INT_ARR | API_CATALOG_F_SIZE_KEY,
      .k0 = "summary", .k1 = "operations", .field = "operation_count" },
    { .op = API_CATALOG_COUNT,
      .flags = API_CATALOG_F_TYPE | API_CATALOG_F_INT_KEY,
      .k0 = "service_facets", .k1 = "summary", .field = "service_count" },
    { .op = API_CATALOG_INT, .rel = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "summary", .field = "rest_callable_count" },
    { .op = API_CATALOG_INT, .rel = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "summary", .field = "rpc_callable_count" },
    { .op = API_CATALOG_INT, .rel = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "summary", .field = "destructive_count" },
    { .op = API_CATALOG_INT, .guard = 1, .via = API_CATALOG_VIA_FIND,
      .k0 = "service_facets", .k1 = "service", .match = "znam_names",
      .field = "operation_count", .num = 4 },
    { .op = API_CATALOG_INT, .guard = 1, .via = API_CATALOG_VIA_FIND,
      .k0 = "service_facets", .k1 = "service", .match = "znam_names",
      .field = "public_read_count", .num = 3 },
    { .op = API_CATALOG_INT, .guard = 1, .via = API_CATALOG_VIA_FIND,
      .k0 = "service_facets", .k1 = "service", .match = "znam_names",
      .field = "destructive_count", .num = 1 },
    { .op = API_CATALOG_INT, .guard = 1, .via = API_CATALOG_VIA_FIND,
      .k0 = "service_facets", .k1 = "service", .match = "znam_names",
      .field = "preferred_rest_count", .num = 3 },
    { .op = API_CATALOG_INT, .guard = 1, .via = API_CATALOG_VIA_FIND,
      .k0 = "service_facets", .k1 = "service", .match = "znam_names",
      .field = "preferred_rpc_count", .num = 1 },
    { .op = API_CATALOG_INT, .guard = 1, .rel = 1,
      .via = API_CATALOG_VIA_NAMED, .k0 = "preferred_interface_facets",
      .k1 = "rest", .field = "operation_count" },
    { .op = API_CATALOG_INT, .guard = 1, .rel = 1,
      .via = API_CATALOG_VIA_NAMED, .k0 = "preferred_interface_facets",
      .k1 = "rpc", .field = "operation_count" },
    { .op = API_CATALOG_INT, .guard = 1, .rel = 1,
      .via = API_CATALOG_VIA_NAMED, .k0 = "write_safety_facets",
      .k1 = "operator_private_destructive", .field = "operation_count" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_FIND,
      .k0 = "operations", .k1 = "operation_id",
      .match = "znam_names.resolve_name", .field = "service",
      .text = "znam_names" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_FIND,
      .k0 = "operations", .k1 = "operation_id",
      .match = "znam_names.resolve_name",
      .field = "agent_preferred_interface", .text = "rest" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_FIND,
      .k0 = "operations", .k1 = "operation_id",
      .match = "znam_names.resolve_service_directory",
      .field = "rest_route", .text = "/api/v1/names/{name}/services" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_FIND,
      .k0 = "operations", .k1 = "operation_id",
      .match = "znam_names.resolve_service_directory",
      .field = "output_schema", .text = "zcl.names.service_directory.v1" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_FIND,
      .k0 = "operations", .k1 = "operation_id",
      .match = "znam_names.resolve_service_directory",
      .field = "agent_preferred_interface", .text = "rest" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_FIND,
      .k0 = "operations", .k1 = "operation_id",
      .match = "znam_names.construct_name_register",
      .field = "agent_preferred_interface", .text = "rpc" },
    { .op = API_CATALOG_BOOL, .guard = 1, .via = API_CATALOG_VIA_FIND,
      .k0 = "operations", .k1 = "operation_id",
      .match = "znam_names.construct_name_register",
      .field = "destructive", .num = 1 },
};

static const struct api_catalog_expect k_filtered_operations[] = {
    { .op = API_CATALOG_BOOL, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "filters", .field = "active", .num = 1 },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "filters", .field = "service", .text = "znam_names" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "filters", .field = "write_safety",
      .text = "public_read_only" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "filters", .field = "preferred_interface", .text = "rest" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "filters", .field = "surface", .text = "rest" },
    { .op = API_CATALOG_COUNT, .flags = API_CATALOG_F_TYPE,
      .k0 = "operations", .num = 3 },
    { .op = API_CATALOG_INT, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "summary", .field = "operation_count", .num = 3 },
    { .op = API_CATALOG_INT, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "summary", .field = "destructive_count", .num = 0 },
    { .op = API_CATALOG_PRESENT, .via = API_CATALOG_VIA_FIND,
      .k0 = "operations", .k1 = "operation_id",
      .match = "znam_names.list_names" },
    { .op = API_CATALOG_PRESENT, .via = API_CATALOG_VIA_FIND,
      .k0 = "operations", .k1 = "operation_id",
      .match = "znam_names.resolve_name" },
    { .op = API_CATALOG_PRESENT, .via = API_CATALOG_VIA_FIND,
      .k0 = "operations", .k1 = "operation_id",
      .match = "znam_names.resolve_service_directory" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "filter_contract", .field = "schema",
      .text = "zcl.query_filter_contract.v1" },
    { .op = API_CATALOG_BOOL, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "filter_contract", .field = "unknown_filters_error", .num = 1 },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_GET2,
      .k0 = "filter_contract", .k1 = "allowed_filters",
      .field = "preferred_interface",
      .text = "rest,rpc,native_or_planned" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_GET2,
      .k0 = "filter_contract", .k1 = "allowed_filters",
      .field = "interface", .text = "alias_for_preferred_interface" },
};

static const struct api_catalog_expect k_znam_member[] = {
    { .op = API_CATALOG_STR, .field = "schema",
      .text = "zcl.service_contract.v2" },
    { .op = API_CATALOG_STR, .field = "name", .text = "znam_names" },
    { .op = API_CATALOG_STR, .field = "catalog_route",
      .text = "/api/v1/service-catalog" },
    { .op = API_CATALOG_STR, .field = "operation_route",
      .text = "/api/v1/service-operations/{operation_id}" },
    { .op = API_CATALOG_STR, .field = "operation_collection_route",
      .text = "/api/v1/service-operations" },
    { .op = API_CATALOG_STR, .field = "self_route",
      .text = "/api/v1/service-catalog/znam_names" },
    { .op = API_CATALOG_ARRAY, .field = "crud_capabilities",
      .text = "construct_transaction" },
    { .op = API_CATALOG_ARRAY, .field = "crud_capabilities",
      .text = "read_subcollection" },
    { .op = API_CATALOG_ARRAY, .field = "depends_on_services",
      .text = "full_node" },
    { .op = API_CATALOG_INT, .rel = -2, .field = "operation_count",
      .num = 4 },
    { .op = API_CATALOG_INT, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "operation_summary", .field = "operation_count", .num = 4 },
    { .op = API_CATALOG_INT, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "operation_summary", .field = "public_read_count", .num = 3 },
    { .op = API_CATALOG_INT, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "operation_summary", .field = "operator_private_count",
      .num = 1 },
    { .op = API_CATALOG_INT, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "operation_summary", .field = "destructive_count", .num = 1 },
    { .op = API_CATALOG_INT, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "operation_summary", .field = "rest_callable_count", .num = 3 },
    { .op = API_CATALOG_INT, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "operation_summary", .field = "rpc_callable_count", .num = 3 },
    { .op = API_CATALOG_INT, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "operation_summary", .field = "preferred_rest_count",
      .num = 3 },
    { .op = API_CATALOG_INT, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "operation_summary", .field = "preferred_rpc_count", .num = 1 },
    { .op = API_CATALOG_STR, .field = "read_model",
      .text = "znam_projection_confirmed_chain_records" },
    { .op = API_CATALOG_STR, .field = "write_model",
      .text = "construct_znam_op_return_transactions" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "runtime_probe", .field = "schema",
      .text = "zcl.service_runtime_probe.v1" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "runtime_probe", .field = "route", .text = "/api/v1/names" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "runtime_probe", .field = "operation_id",
      .text = "znam_names.list_names" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "runtime_probe", .field = "expected_schema",
      .text = "zcl.names.index.v1" },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_GET1,
      .k0 = "runtime_probe", .field = "freshness",
      .text = "znam_projection" },
    { .op = API_CATALOG_BOOL, .via = API_CATALOG_VIA_GET1,
      .k0 = "runtime_probe", .field = "operator_private", .num = 0 },
    { .op = API_CATALOG_STR, .guard = 1, .via = API_CATALOG_VIA_FIND,
      .k0 = "operations", .k1 = "operation",
      .match = "construct_name_register", .field = "effect",
      .text = "construct_or_broadcast_znam_op_return_transaction" },
    { .op = API_CATALOG_SUBSTR, .field = "verified_by", .text = "op_return" },
};

static const struct api_catalog_expect k_resolve_name[] = {
    { .op = API_CATALOG_STR, .field = "schema",
      .text = "zcl.service_operation.v2" },
    { .op = API_CATALOG_STR, .field = "operation_id",
      .text = "znam_names.resolve_name" },
    { .op = API_CATALOG_STR, .field = "self_route",
      .text = "/api/v1/service-operations/znam_names.resolve_name" },
    { .op = API_CATALOG_STR, .field = "service_catalog_route",
      .text = "/api/v1/service-catalog/znam_names" },
    { .op = API_CATALOG_STR, .field = "service", .text = "znam_names" },
    { .op = API_CATALOG_STR, .field = "operation", .text = "resolve_name" },
    { .op = API_CATALOG_STR, .field = "rest_route",
      .text = "/api/v1/names/{name}" },
    { .op = API_CATALOG_STR, .field = "catalog_route",
      .text = "/api/v1/service-catalog" },
    { .op = API_CATALOG_STR, .field = "operation_route",
      .text = "/api/v1/service-operations/{operation_id}" },
    { .op = API_CATALOG_STR, .field = "execution_surface", .text = "rest" },
    { .op = API_CATALOG_STR, .field = "write_safety",
      .text = "public_read_only" },
    { .op = API_CATALOG_STR, .field = "agent_preferred_interface",
      .text = "rest" },
    { .op = API_CATALOG_STR, .field = "agent_next_step",
      .text = "call_rest_route_and_validate_output_schema" },
    { .op = API_CATALOG_BOOL, .field = "rest_callable", .num = 1 },
    { .op = API_CATALOG_BOOL, .field = "rpc_callable", .num = 1 },
    { .op = API_CATALOG_BOOL, .field = "public_read", .num = 1 },
    { .op = API_CATALOG_BOOL, .field = "destructive", .num = 0 },
};

static const struct api_catalog_expect k_resolve_directory[] = {
    { .op = API_CATALOG_STR, .field = "operation_id",
      .text = "znam_names.resolve_service_directory" },
    { .op = API_CATALOG_STR, .field = "operation",
      .text = "resolve_service_directory" },
    { .op = API_CATALOG_STR, .field = "crud_capability",
      .text = "read_subcollection" },
    { .op = API_CATALOG_STR, .field = "rest_route",
      .text = "/api/v1/names/{name}/services" },
    { .op = API_CATALOG_STR, .field = "output_schema",
      .text = "zcl.names.service_directory.v1" },
    { .op = API_CATALOG_STR, .field = "agent_preferred_interface",
      .text = "rest" },
    { .op = API_CATALOG_BOOL, .field = "rest_callable", .num = 1 },
    { .op = API_CATALOG_BOOL, .field = "rpc_callable", .num = 0 },
};

static bool api_catalog_bootstrap_matches(void)
{
    static uint8_t bootstrap_resp[262144];
    struct json_value root;
    const char *body;
    size_t n;
    bool ok;

    rpc_net_set_connman(NULL);
    rpc_net_set_boot_context(NULL, NULL);
    reducer_frontier_provable_tip_reset();

    n = api_handle_request("GET", "/api/v1/bootstrap", NULL, 0,
                           bootstrap_resp, sizeof(bootstrap_resp));
    body = api_test_body(bootstrap_resp, n, sizeof(bootstrap_resp));
    ok = api_catalog_parse(true, &root, body, n);
    ok = api_catalog_expect_all(ok, &root, k_bootstrap_status,
                                sizeof k_bootstrap_status /
                                sizeof k_bootstrap_status[0]);
    json_free(&root);

    n = api_handle_request("GET", "/api/v1/bootstrapstatus", NULL, 0,
                           bootstrap_resp, sizeof(bootstrap_resp));
    body = api_test_body(bootstrap_resp, n, sizeof(bootstrap_resp));
    ok = api_catalog_parse(ok, &root, body, n);
    ok = api_catalog_expect_all(ok, &root, k_bootstrap_alias,
                                sizeof k_bootstrap_alias /
                                sizeof k_bootstrap_alias[0]);
    json_free(&root);
    return ok;
}

static bool api_catalog_protocols_matches(void)
{
    static uint8_t protocols_resp[262144];
    struct json_value root;
    const char *body;
    size_t n;
    bool ok;

    n = api_handle_request("GET", "/api/v1/protocols", NULL, 0,
                           protocols_resp, sizeof(protocols_resp));
    body = api_test_body(protocols_resp, n, sizeof(protocols_resp));
    ok = api_catalog_parse(true, &root, body, n);
    ok = api_catalog_expect_all(ok, &root, k_protocols_index,
                                sizeof k_protocols_index /
                                sizeof k_protocols_index[0]);
    json_free(&root);

    n = api_handle_request("GET", "/api/v1/protocols/script_contracts",
                           NULL, 0, protocols_resp, sizeof(protocols_resp));
    body = api_test_body(protocols_resp, n, sizeof(protocols_resp));
    ok = api_catalog_parse(ok, &root, body, n);
    ok = api_catalog_expect_all(ok, &root, k_script_contracts,
                                sizeof k_script_contracts /
                                sizeof k_script_contracts[0]);
    json_free(&root);

    n = api_handle_request("GET", "/api/v1/protocols/not_real",
                           NULL, 0, protocols_resp, sizeof(protocols_resp));
    api_catalog_terminate(protocols_resp, n, sizeof(protocols_resp));
    ok = ok && strstr((char *)protocols_resp,
                      "HTTP/1.1 404 Not Found") != NULL;
    return ok;
}

static bool api_catalog_service_catalog_document(const char **catalog_body)
{
    static uint8_t catalog_resp[262144];
    struct json_value root;
    const char *body;
    size_t n;
    bool ok;

    n = api_handle_request("GET", "/api/v1/service-catalog",
                           NULL, 0, catalog_resp, sizeof(catalog_resp));
    body = api_test_body(catalog_resp, n, sizeof(catalog_resp));
    *catalog_body = body;
    ok = api_catalog_parse(true, &root, body, n);
    ok = api_catalog_expect_all(ok, &root, k_service_catalog,
                                sizeof k_service_catalog /
                                sizeof k_service_catalog[0]);
    json_free(&root);
    return ok;
}

static bool api_catalog_service_operations_index(
    bool ok, struct json_value *root,
    const struct json_value **operations)
{
    static uint8_t ops_resp[262144];
    const char *body;
    size_t n;

    n = api_handle_request("GET", "/api/v1/service-operations",
                           NULL, 0, ops_resp, sizeof(ops_resp));
    body = api_test_body(ops_resp, n, sizeof(ops_resp));
    ok = api_catalog_parse(ok, root, body, n);
    ok = api_catalog_expect_all(ok, root, k_service_operations,
                                sizeof k_service_operations /
                                sizeof k_service_operations[0]);
    *operations = json_get(root, "operations");
    return ok;
}

static bool api_catalog_service_operations_filtered(bool ok)
{
    static uint8_t filtered_ops_resp[131072];
    struct json_value filtered_root;
    const char *body;
    size_t n;

    n = api_handle_request(
        "GET",
        "/api/v1/service-operations?service=znam_names&"
        "write_safety=public_read_only&preferred_interface=rest&"
        "surface=rest&status=active",
        NULL, 0, filtered_ops_resp, sizeof(filtered_ops_resp));
    body = api_test_body(filtered_ops_resp, n, sizeof(filtered_ops_resp));
    ok = api_catalog_parse(ok, &filtered_root, body, n);
    ok = api_catalog_expect_all(ok, &filtered_root, k_filtered_operations,
                                sizeof k_filtered_operations /
                                sizeof k_filtered_operations[0]);
    json_free(&filtered_root);

    n = api_handle_request("GET",
                           "/api/v1/service-operations?"
                           "write_safety=unsafe",
                           NULL, 0, filtered_ops_resp,
                           sizeof(filtered_ops_resp));
    api_catalog_terminate(filtered_ops_resp, n, sizeof(filtered_ops_resp));
    ok = ok && strstr((char *)filtered_ops_resp,
                      "HTTP/1.1 400 Bad Request") != NULL;
    ok = ok && strstr((char *)filtered_ops_resp,
                      "invalid_service_operation_filter") != NULL;
    n = api_handle_request("GET",
                           "/api/v1/service-operations?"
                           "servce=bootstrap",
                           NULL, 0, filtered_ops_resp,
                           sizeof(filtered_ops_resp));
    api_catalog_terminate(filtered_ops_resp, n, sizeof(filtered_ops_resp));
    ok = ok && strstr((char *)filtered_ops_resp,
                      "HTTP/1.1 400 Bad Request") != NULL;
    ok = ok && strstr((char *)filtered_ops_resp,
                      "unknown filter 'servce'") != NULL;
    return ok;
}

static bool api_catalog_service_operations_bound(
    bool ok, struct json_value *ops_root,
    const struct json_value *operations, const char *catalog_body)
{
    static uint8_t index_resp[262144];
    struct json_value index_root;
    struct json_value catalog_root;
    size_t in;
    const char *index_body;

    in = api_handle_request("GET", "/api/v1", NULL, 0,
                            index_resp, sizeof(index_resp));
    index_body = api_test_body(index_resp, in, sizeof(index_resp));
    json_init(&index_root);
    json_init(&catalog_root);
    ok = ok && in > 0 && index_body &&
         json_read(&index_root, index_body, strlen(index_body));
    ok = ok && catalog_body &&
         json_read(&catalog_root, catalog_body, strlen(catalog_body));
    ok = ok && api_test_runtime_probes_consistent(
        &catalog_root, operations,
        json_get(&index_root, "route_contracts"));
    ok = ok && api_test_rest_service_operations_bound(
        operations, json_get(&index_root, "route_contracts"));
    json_free(&catalog_root);
    json_free(&index_root);
    json_free(ops_root);
    return ok;
}

static bool api_catalog_service_member_show(bool ok)
{
    static uint8_t show_resp[65536];
    struct json_value root;
    const char *body;
    size_t n;

    n = api_handle_request("GET",
                           "/api/v1/service-catalog/znam_names",
                           NULL, 0, show_resp, sizeof(show_resp));
    body = api_test_body(show_resp, n, sizeof(show_resp));
    ok = api_catalog_parse(ok, &root, body, n);
    ok = api_catalog_expect_all(ok, &root, k_znam_member,
                                sizeof k_znam_member /
                                sizeof k_znam_member[0]);
    json_free(&root);
    return ok;
}

static bool api_catalog_service_operation_show(bool ok)
{
    static uint8_t show_resp[65536];
    struct json_value root;
    const char *body;
    size_t n;

    n = api_handle_request("GET",
                           "/api/v1/service-operations/"
                           "znam_names.resolve_name",
                           NULL, 0, show_resp, sizeof(show_resp));
    body = api_test_body(show_resp, n, sizeof(show_resp));
    ok = api_catalog_parse(ok, &root, body, n);
    ok = api_catalog_expect_all(ok, &root, k_resolve_name,
                                sizeof k_resolve_name /
                                sizeof k_resolve_name[0]);
    json_free(&root);

    n = api_handle_request("GET",
                           "/api/v1/service-operations/"
                           "znam_names.resolve_service_directory",
                           NULL, 0, show_resp, sizeof(show_resp));
    body = api_test_body(show_resp, n, sizeof(show_resp));
    ok = api_catalog_parse(ok, &root, body, n);
    ok = api_catalog_expect_all(ok, &root, k_resolve_directory,
                                sizeof k_resolve_directory /
                                sizeof k_resolve_directory[0]);
    json_free(&root);

    n = api_handle_request("GET",
                           "/api/v1/service-operations/"
                           "znam_names.not_real",
                           NULL, 0, show_resp, sizeof(show_resp));
    api_catalog_terminate(show_resp, n, sizeof(show_resp));
    ok = ok && strstr((char *)show_resp,
                      "HTTP/1.1 404 Not Found") != NULL;

    n = api_handle_request("GET", "/api/v1/service-catalog/not_real",
                           NULL, 0, show_resp, sizeof(show_resp));
    api_catalog_terminate(show_resp, n, sizeof(show_resp));
    ok = ok && strstr((char *)show_resp,
                      "HTTP/1.1 404 Not Found") != NULL;
    return ok;
}

static bool api_catalog_service_catalog_matches(void)
{
    struct json_value ops_root;
    const struct json_value *operations = NULL;
    const char *catalog_body = NULL;
    bool ok;

    ok = api_catalog_service_catalog_document(&catalog_body);
    ok = api_catalog_service_operations_index(ok, &ops_root, &operations);
    ok = api_catalog_service_operations_filtered(ok);
    ok = api_catalog_service_operations_bound(ok, &ops_root, operations,
                                              catalog_body);
    ok = api_catalog_service_member_show(ok);
    ok = api_catalog_service_operation_show(ok);
    return ok;
}

int api_catalog_focused_tests(void)
{
    int failures = 0;

    printf("api: bootstrap status is a first-class REST resource... ");
    if (api_catalog_bootstrap_matches()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("api: protocol registry endpoints expose overlay contracts... ");
    if (api_catalog_protocols_matches()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("api: service catalog exposes sovereign UX contracts... ");
    if (api_catalog_service_catalog_matches()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    return failures;
}
