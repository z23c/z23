/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* REST route contract JSON. The router owns route tables and dispatch;
 * this module turns those registry rows into the public contract layer. */

#include "api_controller_internal.h"

#include "json/json.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

struct api_contract_build_ctx {
    struct json_value *out;
};

static const char *api_contract_path(const char *path, char *buf,
                                     size_t buf_len)
{
    if (!path)
        return "";
    if (strcmp(path, ZCL_REST_API_COMPAT_BASE_PATH) == 0)
        return ZCL_REST_API_BASE_PATH;
    if (strncmp(path, ZCL_REST_API_COMPAT_BASE_PATH "/", 5) != 0)
        return path;
    if (!buf || buf_len == 0)
        return path;

    int n = snprintf(buf, buf_len, "%s/%s", ZCL_REST_API_BASE_PATH,
                     path + 5);
    if (n < 0 || (size_t)n >= buf_len)
        return path;
    return buf;
}

static void api_contract_query_params_json(const char *csv,
                                           struct json_value *out)
{
    json_set_array(out);
    if (!csv || !csv[0])
        return;

    const char *p = csv;
    while (*p) {
        while (*p == ',' || *p == ' ')
            p++;
        const char *start = p;
        while (*p && *p != ',')
            p++;

        size_t len = (size_t)(p - start);
        while (len > 0 && start[len - 1] == ' ')
            len--;
        if (len > 0) {
            char name[64];
            if (len >= sizeof(name))
                len = sizeof(name) - 1;
            memcpy(name, start, len);
            name[len] = '\0';

            struct json_value item;
            json_init(&item);
            json_set_str(&item, name);
            json_push_back(out, &item);
            json_free(&item);
        }
        if (*p == ',')
            p++;
    }
}

static bool api_contract_has_pagination(const char *query_params_csv)
{
    return query_params_csv && strstr(query_params_csv, "limit") != NULL;
}

static bool api_contract_freshness_scoped(const char *freshness)
{
    return freshness && freshness[0] && strcmp(freshness, "static") != 0;
}

static const char *api_contract_crud_operation(const char *method)
{
    if (!method)
        return "action";
    if (strcmp(method, "GET") == 0)
        return "read";
    if (strcmp(method, "POST") == 0)
        return "create";
    if (strcmp(method, "PUT") == 0 || strcmp(method, "PATCH") == 0)
        return "update";
    if (strcmp(method, "DELETE") == 0)
        return "delete";
    return "action";
}

static bool api_contract_path_has_id(const char *path)
{
    return path && strchr(path, '{') != NULL && strchr(path, '}') != NULL;
}

static const char *api_contract_resource_scope(const char *method,
                                               const char *action,
                                               const char *path)
{
    const bool has_id = api_contract_path_has_id(path);

    if (!method || strcmp(method, "GET") != 0)
        return has_id ? "item" : "collection";
    if (action && strcmp(action, "index") == 0)
        return has_id ? "subcollection" : "collection";
    if (action && strcmp(action, "show") == 0)
        return has_id ? "item" : "singleton";
    if (has_id)
        return "subresource";
    return "singleton";
}

static void api_contract_crud_name(char *buf, size_t buf_len,
                                   const char *operation,
                                   const char *scope)
{
    if (!buf || buf_len == 0)
        return;
    snprintf(buf, buf_len, "%s_%s",
             operation && operation[0] ? operation : "action",
             scope && scope[0] ? scope : "resource");
    buf[buf_len - 1] = '\0';
}

static void api_contract_path_params_json(const char *path,
                                          struct json_value *out)
{
    json_set_array(out);
    const char *p = path;
    while (p && (p = strchr(p, '{')) != NULL) {
        const char *end = strchr(p + 1, '}');
        if (!end)
            return;

        size_t len = (size_t)(end - (p + 1));
        if (len > 0) {
            char name[64];
            if (len >= sizeof(name))
                len = sizeof(name) - 1;
            memcpy(name, p + 1, len);
            name[len] = '\0';

            struct json_value item;
            json_init(&item);
            json_set_str(&item, name);
            json_push_back(out, &item);
            json_free(&item);
        }
        p = end + 1;
    }
}

static void api_contract_append_slug(char *buf, size_t buf_len,
                                     size_t *off, const char *s)
{
    if (!buf || !off || *off >= buf_len)
        return;

    const char *p = s ? s : "";
    bool last_sep = false;
    while (*p && *off + 1 < buf_len) {
        unsigned char c = (unsigned char)*p++;
        char out = '_';
        if (isalnum(c)) {
            out = (char)tolower(c);
            last_sep = false;
        } else {
            if (last_sep)
                continue;
            last_sep = true;
        }
        buf[(*off)++] = out;
    }
    buf[*off] = '\0';
}

static void api_contract_route_id(char *buf, size_t buf_len,
                                  const char *method,
                                  const char *resource,
                                  const char *action,
                                  const char *path)
{
    if (!buf || buf_len == 0)
        return;

    size_t off = 0;
    buf[0] = '\0';
    api_contract_append_slug(buf, buf_len, &off, "api");
    if (off + 1 < buf_len)
        buf[off++] = '.';
    api_contract_append_slug(buf, buf_len, &off, method);
    if (off + 1 < buf_len)
        buf[off++] = '.';
    api_contract_append_slug(buf, buf_len, &off, resource);
    if (off + 1 < buf_len)
        buf[off++] = '.';
    api_contract_append_slug(buf, buf_len, &off, action);
    if (off + 1 < buf_len)
        buf[off++] = '.';
    api_contract_append_slug(buf, buf_len, &off, path);
    buf[buf_len - 1] = '\0';
}

static void api_contract_telemetry_json(struct json_value *out,
                                        const char *route_id,
                                        const char *resource,
                                        const char *action,
                                        const char *freshness,
                                        bool private_route)
{
    json_set_object(out);
    json_push_kv_str(out, "route_id", route_id ? route_id : "");
    json_push_kv_str(out, "counter", "zcl_api_requests_total");
    json_push_kv_str(out, "latency_histogram",
                     "zcl_api_request_duration_seconds");
    json_push_kv_str(out, "freshness_source",
                     freshness && freshness[0] ? freshness : "none");
    json_push_kv_str(out, "auth_class",
                     private_route ? "operator_private" : "public");

    struct json_value labels;
    json_init(&labels);
    json_set_array(&labels);
    const char *items[] = {
        "route_id", "resource", "action", "status", "auth_class"
    };
    for (size_t i = 0; i < sizeof(items) / sizeof(items[0]); i++) {
        struct json_value item;
        json_init(&item);
        json_set_str(&item, items[i]);
        json_push_back(&labels, &item);
        json_free(&item);
    }
    json_push_kv(out, "labels", &labels);
    json_free(&labels);

    json_push_kv_str(out, "resource", resource ? resource : "");
    json_push_kv_str(out, "action", action ? action : "");
}

static void api_contract_crypto_policy_json(struct json_value *out)
{
    json_set_object(out);
    json_push_kv_str(out, "policy", "hash_based_dual_512_where_possible");
    json_push_kv_str(out, "service_auth_primary_digest", "SHA3-512");
    json_push_kv_str(out, "service_auth_secondary_digest",
                     "GOST R 34.11-2012-512");

    struct json_value digests;
    json_init(&digests);
    json_set_array(&digests);
    const char *items[] = { "SHA3-512", "GOST R 34.11-2012-512" };
    for (size_t i = 0; i < sizeof(items) / sizeof(items[0]); i++) {
        struct json_value item;
        json_init(&item);
        json_set_str(&item, items[i]);
        json_push_back(&digests, &item);
        json_free(&item);
    }
    json_push_kv(out, "service_auth_digests", &digests);
    json_free(&digests);

    json_push_kv_int(out, "hash_output_bits", 512);
    json_push_kv_bool(out, "requires_all_digests", true);
    json_push_kv_str(out, "service_auth_token_storage",
                     "store_sha3_512_and_gost_2012_512_commitments_not_secret");
    json_push_kv_bool(out, "signature_scheme_claimed", false);
}

static void api_contract_service_binding_json(struct json_value *item,
                                              const char *method,
                                              const char *public_path,
                                              const char *alias_of)
{
    struct json_value binding;
    const char *binding_path =
        alias_of && alias_of[0] ? alias_of : public_path;

    if (!item || !method || !binding_path)
        return;

    json_init(&binding);
    if (!api_service_operation_for_rest_route(method, binding_path,
                                              &binding)) {
        json_free(&binding);
        return;
    }

    const char *service = json_get_str(json_get(&binding, "service"));
    const char *service_route =
        json_get_str(json_get(&binding, "service_catalog_route"));
    const char *operation_id =
        json_get_str(json_get(&binding, "operation_id"));
    const char *operation_route =
        json_get_str(json_get(&binding, "self_route"));

    if (service && service[0])
        json_push_kv_str(item, "service_contract", service);
    if (service_route && service_route[0])
        json_push_kv_str(item, "service_catalog_route", service_route);
    if (operation_id && operation_id[0])
        json_push_kv_str(item, "service_operation_id", operation_id);
    if (operation_route && operation_route[0])
        json_push_kv_str(item, "service_operation_route",
                         operation_route);
    json_push_kv(item, "service_binding", &binding);
    json_free(&binding);
}

static void api_contract_push(struct json_value *out, const char *method,
                              const char *path, const char *resource,
                              const char *action,
                              const char *response_schema,
                              const char *query_params_csv,
                              const char *freshness,
                              const char *alias_of,
                              bool private_route,
                              const char *command_path)
{
    if (!out || !method || !path || !resource || !action)
        return;

    char public_path_buf[256];
    const char *public_path = api_contract_path(path, public_path_buf,
                                                sizeof(public_path_buf));
    const char *schema = response_schema && response_schema[0]
        ? response_schema : "zcl.rest.response.v1";
    const char *fresh = freshness && freshness[0] ? freshness : "none";
    const struct api_app_protocol_contract *protocol =
        api_app_protocol_for_resource(resource);
    const char *crud_operation = api_contract_crud_operation(method);
    const char *resource_scope =
        api_contract_resource_scope(method, action, public_path);
    char crud_name[64];
    api_contract_crud_name(crud_name, sizeof(crud_name), crud_operation,
                           resource_scope);
    char route_id[256];
    api_contract_route_id(route_id, sizeof(route_id), method, resource,
                          action, public_path);

    struct json_value item;
    json_init(&item);
    json_set_object(&item);
    json_push_kv_str(&item, "schema", ZCL_REST_ROUTE_CONTRACT_SCHEMA);
    json_push_kv_str(&item, "route_id", route_id);
    json_push_kv_str(&item, "version", ZCL_REST_API_VERSION);
    json_push_kv_str(&item, "method", method);
    json_push_kv_str(&item, "path", public_path);
    if (strcmp(public_path, path) != 0)
        json_push_kv_str(&item, "compat_path", path);
    json_push_kv_str(&item, "resource", resource);
    json_push_kv_str(&item, "action", action);
    json_push_kv_str(&item, "crud_operation", crud_operation);
    json_push_kv_str(&item, "resource_scope", resource_scope);
    json_push_kv_str(&item, "crud_name", crud_name);
    if (command_path && command_path[0])
        json_push_kv_str(&item, "command_path", command_path);
    json_push_kv_bool(&item, "private", private_route);
    json_push_kv_str(&item, "auth",
                     private_route ? "operator_private" : "public");
    json_push_kv_str(&item, "auth_policy",
                     private_route ? "operator_private" : "public");
    json_push_kv_bool(&item, "gateway_auth_compatible", true);
    json_push_kv_str(&item, "preferred_service_auth",
                     "hash512_sha3_gost_commitments");
    json_push_kv_str(&item, "response_schema", schema);
    json_push_kv_str(&item, "error_schema", ZCL_REST_ERROR_SCHEMA);
    if (strcmp(path, "/api/supply") == 0)
        json_push_kv_str(&item, "compat_response_schema",
                         "zcl.supply_legacy_number.v1");
    api_contract_service_binding_json(&item, method, public_path, alias_of);
    if (protocol) {
        json_push_kv_str(&item, "layer", protocol->layer);
        json_push_kv_str(&item, "base_layer", protocol->base_layer);
        json_push_kv_str(&item, "application_protocol", protocol->name);
        json_push_kv_str(&item, "protocol_status", protocol->status);
        json_push_kv_str(&item, "protocol_family", protocol->family);
        json_push_kv_str(&item, "source_anchor", protocol->anchor);
        json_push_kv_str(&item, "protocol_anchor_kind",
                         protocol->anchor_kind);
        json_push_kv_str(&item, "read_model", protocol->read_model);
        struct json_value protocol_crud;
        json_init(&protocol_crud);
        api_app_protocol_crud_json(protocol, &protocol_crud);
        json_push_kv(&item, "protocol_crud", &protocol_crud);
        json_free(&protocol_crud);
        json_push_kv_str(&item, "protocol_construction_status",
                         protocol->construction_status);
        json_push_kv_str(&item, "mutation_authority",
                         protocol->mutation_authority);
        json_push_kv_str(&item, "write_semantics",
                         protocol->write_semantics);
        json_push_kv_str(&item, "consensus_boundary",
                         protocol->consensus_boundary);
        struct json_value object_types;
        json_init(&object_types);
        api_app_protocol_csv_json(protocol->object_types_csv, &object_types);
        json_push_kv(&item, "protocol_object_types", &object_types);
        json_free(&object_types);
        struct json_value ux_surfaces;
        json_init(&ux_surfaces);
        api_app_protocol_csv_json(protocol->ux_surfaces_csv, &ux_surfaces);
        json_push_kv(&item, "protocol_ux_surfaces", &ux_surfaces);
        json_free(&ux_surfaces);
        json_push_kv_str(&item, "projection_model",
                         protocol->projection_model);
        json_push_kv_str(&item, "reorg_model", protocol->reorg_model);
        json_push_kv_str(&item, "crypto_model", protocol->crypto_model);
        json_push_kv_str(&item, "transport_model",
                         protocol->transport_model);
        json_push_kv_str(&item, "privacy_model", protocol->privacy_model);
        json_push_kv_str(&item, "diagnostics_surface",
                         protocol->diagnostics_surface);
    }
    json_push_kv_str(&item, "freshness", fresh);
    json_push_kv_bool(&item, "freshness_scoped",
                      api_contract_freshness_scoped(fresh));
    json_push_kv_bool(&item, "pagination",
                      api_contract_has_pagination(query_params_csv));
    json_push_kv_bool(&item, "canonical", !alias_of || !alias_of[0]);
    if (alias_of && alias_of[0])
        json_push_kv_str(&item, "legacy_alias_of", alias_of);

    const char *filter_contract_name =
        api_query_filter_contract_for_route(method, public_path);
    if (filter_contract_name) {
        struct json_value filter_contract;
        json_init(&filter_contract);
        api_query_filter_contract_json(filter_contract_name,
                                       &filter_contract);
        json_push_kv(&item, "filter_contract", &filter_contract);
        json_free(&filter_contract);
    }

    struct json_value path_param_contract;
    json_init(&path_param_contract);
    if (api_path_param_contracts_json(method, public_path, alias_of,
                                      &path_param_contract))
        json_push_kv(&item, "path_param_contract",
                     &path_param_contract);
    json_free(&path_param_contract);

    struct json_value query_params;
    json_init(&query_params);
    api_contract_query_params_json(query_params_csv, &query_params);
    json_push_kv(&item, "query_params", &query_params);
    json_free(&query_params);

    struct json_value id_params;
    json_init(&id_params);
    api_contract_path_params_json(public_path, &id_params);
    json_push_kv(&item, "id_params", &id_params);
    json_free(&id_params);

    struct json_value telemetry;
    json_init(&telemetry);
    api_contract_telemetry_json(&telemetry, route_id, resource, action, fresh,
                                private_route);
    json_push_kv(&item, "telemetry", &telemetry);
    json_free(&telemetry);

    struct json_value crypto_policy;
    json_init(&crypto_policy);
    api_contract_crypto_policy_json(&crypto_policy);
    json_push_kv(&item, "crypto_policy", &crypto_policy);
    json_free(&crypto_policy);

    json_push_back(out, &item);
    json_free(&item);
}

static void api_contract_visit(void *ctx, const char *method, const char *path,
                               const char *resource, const char *action,
                               const char *response_schema,
                               const char *query_params_csv,
                               const char *freshness, const char *alias_of,
                               bool private_route, const char *command_path)
{
    struct api_contract_build_ctx *build =
        (struct api_contract_build_ctx *)ctx;
    if (!build || !build->out)
        return;
    api_contract_push(build->out, method, path, resource, action,
                      response_schema, query_params_csv, freshness, alias_of,
                      private_route, command_path);
}

void api_route_contracts_json(struct json_value *out)
{
    if (!out)
        return;
    json_set_array(out);
    struct api_contract_build_ctx ctx = { .out = out };
    api_route_registry_visit(api_contract_visit, &ctx);
}
