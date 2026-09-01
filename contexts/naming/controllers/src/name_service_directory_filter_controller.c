/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZNAM service-directory filters and HTTP response helpers.
 *
 * The base service-directory serializer owns record classification. This file
 * owns read-only, server-side filtering for the UX/API subcollection route. */

#include "controllers/name_controller.h"
#include "api_controller_internal.h"
#include "json/json.h"

#include <stdbool.h>
#include <string.h>

#include "util/log_macros.h"

static bool api_name_service_record_matches_filter(
    const struct json_value *record,
    const struct api_query_filter *filter)
{
    const char *valid;
    const char *endpoint_only;

    if (!record)
        return false; /* raw-return-ok:predicate-null-input */
    if (!filter || !filter->active)
        return true;

    valid = api_query_filter_value(filter, "valid");
    endpoint_only = api_query_filter_value(filter, "endpoint_only");
    if (!api_query_filter_matches_value(
            filter, "service",
            json_get_str(json_get(record, "service_name"))))
        return false; /* raw-return-ok:predicate-negative-match */
    if (!api_query_filter_matches_value(
            filter, "service_contract",
            json_get_str(json_get(record, "service_contract"))))
        return false; /* raw-return-ok:predicate-negative-match */
    if (!api_query_filter_matches_value(
            filter, "transport",
            json_get_str(json_get(record, "transport"))))
        return false; /* raw-return-ok:predicate-negative-match */
    if (!api_query_filter_matches_value(
            filter, "endpoint_kind",
            json_get_str(json_get(record, "endpoint_kind"))))
        return false; /* raw-return-ok:predicate-negative-match */
    if (valid[0]) {
        bool want = strcmp(valid, "true") == 0;
        if (json_get_bool(json_get(record, "endpoint_hint_valid")) != want)
            return false; /* raw-return-ok:predicate-negative-match */
    }
    if (endpoint_only[0]) {
        bool want = strcmp(endpoint_only, "true") == 0;
        if (json_get_bool(json_get(record, "is_endpoint_hint")) != want)
            return false; /* raw-return-ok:predicate-negative-match */
    }
    return true;
}

static void api_name_service_copy_str_field(struct json_value *out,
                                            const struct json_value *base,
                                            const char *key)
{
    const char *value = json_get_str(json_get(base, key));

    if (value)
        json_push_kv_str(out, key, value);
}

static void api_name_service_copy_int_field(struct json_value *out,
                                            const struct json_value *base,
                                            const char *key)
{
    const struct json_value *value = json_get(base, key);

    if (value)
        json_push_kv_int(out, key, json_get_int(value));
}

static void api_name_service_routing_plan_json(
    struct json_value *out,
    int endpoint_count,
    int valid_endpoint_count,
    int invalid_endpoint_count,
    bool supports_onion,
    bool supports_direct_p2p,
    bool supports_bootstrap)
{
    const char *preferred = "none";
    const char *fallback = "inspect_service_catalog";

    if (supports_direct_p2p) {
        preferred = "p2p";
        fallback = supports_onion ? "onion" : "bootstrap";
    } else if (supports_bootstrap) {
        preferred = "p2p_or_onion";
        fallback = supports_onion ? "onion" : "inspect_bootstrap_status";
    } else if (supports_onion) {
        preferred = "onion";
        fallback = "direct_p2p_if_directory_advertises_it";
    }

    json_set_object(out);
    json_push_kv_str(out, "schema", "zcl.names.service_routing_plan.v1");
    json_push_kv_str(out, "strategy",
                     "prefer_valid_direct_p2p_then_bootstrap_then_onion");
    json_push_kv_str(out, "preferred_transport", preferred);
    json_push_kv_str(out, "fallback_transport", fallback);
    json_push_kv_int(out, "endpoint_count", endpoint_count);
    json_push_kv_int(out, "valid_endpoint_count", valid_endpoint_count);
    json_push_kv_int(out, "invalid_endpoint_count", invalid_endpoint_count);
    json_push_kv_bool(out, "chain_verified", true);
    json_push_kv_bool(out, "requires_runtime_probe", endpoint_count > 0);
    json_push_kv_str(out, "next_action",
                     "run_selected_service_runtime_probe_before_connecting");
}

static void api_name_service_accumulate_transport(
    const struct json_value *record,
    bool *supports_onion,
    bool *supports_direct_p2p,
    bool *supports_bootstrap)
{
    const char *transport;

    if (!record)
        return;

    transport = json_get_str(json_get(record, "transport"));
    if (transport && strcmp(transport, "p2p") == 0) {
        if (supports_direct_p2p)
            *supports_direct_p2p = true;
    } else if (transport && strcmp(transport, "onion") == 0) {
        if (supports_onion)
            *supports_onion = true;
    } else if (transport && strcmp(transport, "p2p_or_onion") == 0) {
        if (supports_bootstrap)
            *supports_bootstrap = true;
    }
}

static void api_name_service_filtered_directory_json(
    const struct json_value *base,
    const struct api_query_filter *filter,
    struct json_value *out)
{
    const struct json_value *base_records;
    struct json_value filters = {0};
    struct json_value filter_contract = {0};
    struct json_value records = {0};
    struct json_value endpoints = {0};
    struct json_value plan = {0};
    int service_count = 0;
    int endpoint_count = 0;
    int valid_endpoint_count = 0;
    int invalid_endpoint_count = 0;
    bool supports_onion = false;
    bool supports_direct_p2p = false;
    bool supports_bootstrap = false;

    json_set_object(out);
    api_name_service_copy_str_field(out, base, "schema");
    api_name_service_copy_int_field(out, base, "schema_version");
    api_name_service_copy_str_field(out, base, "source");
    api_name_service_copy_str_field(out, base, "transport_model");
    api_name_service_copy_str_field(out, base, "base_layer");
    api_name_service_copy_str_field(out, base, "routing_policy");
    api_name_service_copy_str_field(out, base, "service_contract_route");
    api_name_service_copy_str_field(out, base, "operation_contract_route");
    api_name_service_copy_str_field(out, base, "runtime_probe_schema");
    api_name_service_copy_str_field(out, base, "runtime_probe_contract_field");
    api_name_service_copy_str_field(out, base, "runtime_probe_policy");
    json_push_kv_str(out, "filter_model",
                     "server-side exact-match filters over service, "
                     "service_contract, transport, endpoint_kind, valid, "
                     "and endpoint_only");
    json_set_object(&filters);
    api_query_filter_values_json(filter, &filters);
    json_push_kv(out, "filters", &filters);
    json_free(&filters);
    api_query_filter_contract_json(API_QUERY_FILTER_NAME_SERVICE_DIRECTORY,
                                   &filter_contract);
    json_push_kv(out, "filter_contract", &filter_contract);
    json_free(&filter_contract);

    json_set_array(&records);
    json_set_array(&endpoints);
    base_records = json_get(base, "records");
    if (base_records && base_records->type == JSON_ARR) {
        for (size_t i = 0; i < json_size(base_records); i++) {
            const struct json_value *record = json_at(base_records, i);
            struct json_value copy = {0};
            bool is_endpoint;
            bool valid_endpoint;

            if (!api_name_service_record_matches_filter(record, filter))
                continue;

            service_count++;
            api_name_service_accumulate_transport(record, &supports_onion,
                                                  &supports_direct_p2p,
                                                  &supports_bootstrap);
            json_copy(&copy, record);
            json_push_back(&records, &copy);
            json_free(&copy);

            is_endpoint = json_get_bool(json_get(record, "is_endpoint_hint"));
            if (!is_endpoint)
                continue;

            endpoint_count++;
            valid_endpoint =
                json_get_bool(json_get(record, "endpoint_hint_valid"));
            if (valid_endpoint)
                valid_endpoint_count++;
            else
                invalid_endpoint_count++;

            json_copy(&copy, record);
            json_push_back(&endpoints, &copy);
            json_free(&copy);
        }
    }

    json_push_kv_bool(out, "has_services", service_count > 0);
    json_push_kv_int(out, "service_record_count", service_count);
    json_push_kv_int(out, "endpoint_count", endpoint_count);
    json_push_kv_int(out, "valid_endpoint_count", valid_endpoint_count);
    json_push_kv_int(out, "invalid_endpoint_count", invalid_endpoint_count);
    json_push_kv_bool(out, "supports_onion", supports_onion);
    json_push_kv_bool(out, "supports_direct_p2p", supports_direct_p2p);
    json_push_kv_bool(out, "supports_bootstrap", supports_bootstrap);

    json_set_object(&plan);
    api_name_service_routing_plan_json(&plan, endpoint_count,
                                       valid_endpoint_count,
                                       invalid_endpoint_count,
                                       supports_onion,
                                       supports_direct_p2p,
                                       supports_bootstrap);
    json_push_kv(out, "routing_plan", &plan);
    json_free(&plan);

    json_push_kv(out, "records", &records);
    json_free(&records);
    json_push_kv(out, "endpoints", &endpoints);
    json_free(&endpoints);

    api_name_service_copy_str_field(out, base, "name");
    api_name_service_copy_str_field(out, base, "name_route");
    api_name_service_copy_str_field(out, base, "self_route");
    api_name_service_copy_str_field(out, base, "operation_id");
    api_name_service_copy_str_field(out, base, "operation_route");
    api_name_service_copy_str_field(out, base, "parent_schema");
    api_name_service_copy_str_field(out, base, "next_action");
}

bool api_name_service_directory_path(const char *name, const char *path,
                                     struct json_value *result,
                                     char *err, size_t err_len)
{
    struct json_value base = {0};
    struct api_query_filter filter;

    if (!result)
        LOG_FAIL("name",
                 "api_name_service_directory_path called with NULL result");

    if (!api_name_service_directory(name, &base)) {
        json_free(&base);
        return false; /* raw-return-ok:source-directory-missing */
    }

    api_query_filter_init(&filter,
                          API_QUERY_FILTER_NAME_SERVICE_DIRECTORY);
    api_query_filter_from_path(&filter, path);
    if (!api_query_filter_validate(&filter, err, err_len)) {
        json_free(&base);
        return false; /* raw-return-ok:filter-validation-error */
    }

    if (!filter.active) {
        struct json_value filter_contract = {0};
        json_copy(result, &base);
        api_query_filter_contract_json(
            API_QUERY_FILTER_NAME_SERVICE_DIRECTORY, &filter_contract);
        json_push_kv(result, "filter_contract", &filter_contract);
        json_free(&filter_contract);
        json_free(&base);
        return true;
    }

    api_name_service_filtered_directory_json(&base, &filter, result);
    json_free(&base);
    return true;
}

size_t api_serve_name_service_directory(const char *name, const char *path,
                                        const char *freshness,
                                        uint8_t *response,
                                        size_t response_max)
{
    struct json_value jr = {0};
    char err[192] = {0};

    if (api_name_service_directory_path(name, path, &jr,
                                        err, sizeof(err))) {
        api_json_add_freshness(&jr, freshness ? freshness : "znam_projection",
                               -1);
        size_t n = api_json_ok(response, response_max, &jr);
        json_free(&jr);
        return n;
    }

    json_free(&jr);
    if (err[0]) {
        json_init(&jr);
        api_query_filter_error_json(
            API_QUERY_FILTER_NAME_SERVICE_DIRECTORY, err, &jr);
        size_t n = api_json_status(response, response_max,
                                   "400 Bad Request", &jr);
        json_free(&jr);
        return n;
    }

    return api_json_error(response, response_max, JSON_404_HEADERS,
                          "Name service directory not found");
}
