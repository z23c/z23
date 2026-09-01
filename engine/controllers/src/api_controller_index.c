/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Self-describing REST API index. This file owns the public contract surface:
 * version, resource catalog, aliases, and route contracts emitted from the
 * shared route registry. */

#include "api_controller_internal.h"

#include "json/json.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void api_rest_index_aliases_json(struct json_value *aliases)
{
    json_set_object(aliases);
    json_push_kv_str(aliases, "agent", "/api/v1/agent");
    json_push_kv_str(aliases, "openapi", "/api/v1/openapi");
    json_push_kv_str(aliases, "milestone", "/api/v1/milestone");
    json_push_kv_str(aliases, "refold", "/api/v1/refold");
    json_push_kv_str(aliases, "node", "/api/v1/node");
    json_push_kv_str(aliases, "node_summary", "/api/v1/node/summary");
    json_push_kv_str(aliases, "status", "/api/v1/status");
    json_push_kv_str(aliases, "bootstrap", "/api/v1/bootstrap");
    json_push_kv_str(aliases, "bootstrapstatus", "/api/v1/bootstrap");
    json_push_kv_str(aliases, "protocols", "/api/v1/protocols");
    json_push_kv_str(aliases, "service_catalog",
                     "/api/v1/service-catalog");
    json_push_kv_str(aliases, "service_operations",
                     "/api/v1/service-operations");
    json_push_kv_str(aliases, "zslp_tokens", "/api/v1/zslp/tokens");
    json_push_kv_str(aliases, "names_show", "/api/v1/names/{name}");
    json_push_kv_str(aliases, "legacy_name_show", "/api/v1/name/{name}");
    json_push_kv_str(aliases, "swap_chains", "/api/v1/swaps/chains");
    json_push_kv_str(aliases, "legacy_swap_chains", "/api/v1/swap_chains");
}

static void api_rest_index_crud_json(struct json_value *crud)
{
    json_set_object(crud);
    json_push_kv_str(crud, "read_collection", "GET /api/v1/{resource}");
    json_push_kv_str(crud, "read_item", "GET /api/v1/{resource}/{id}");
    json_push_kv_str(crud, "read_singleton",
                     "GET /api/v1/{resource} for one node/operator status");
    json_push_kv_str(crud, "read_subcollection",
                     "GET /api/v1/{resource}/{id}/{child_resource}");
    json_push_kv_str(crud, "create",
                     "POST /api/v1/{resource} when documented");
    json_push_kv_str(crud, "update",
                     "PUT/PATCH /api/v1/{resource}/{id} when documented");
    json_push_kv_str(crud, "delete",
                     "DELETE /api/v1/{resource}/{id} when documented");
    json_push_kv_str(crud, "contract_fields",
                     "route_contracts[].crud_operation/resource_scope/crud_name/id_params");
}

static void api_rest_index_drilldown_json(struct json_value *drilldown)
{
    json_set_object(drilldown);
    json_push_kv_str(drilldown, "health", "/api/v1/health");
    json_push_kv_str(drilldown, "sync", "/api/v1/syncstate");
    json_push_kv_str(drilldown, "downloads", "/api/v1/downloadstats");
    json_push_kv_str(drilldown, "full_node_status",
                     "/api/v1/node/status");
    json_push_kv_str(drilldown, "bootstrap", "/api/v1/bootstrap");
    json_push_kv_str(drilldown, "service_catalog",
                     "/api/v1/service-catalog");
    json_push_kv_str(drilldown, "service_operations",
                     "/api/v1/service-operations");
}

static const char *api_openapi_method_key(const char *method, char *buf,
                                          size_t buf_len)
{
    if (!method || !buf || buf_len == 0)
        return "get";

    size_t len = strlen(method);
    if (len >= buf_len)
        len = buf_len - 1;
    for (size_t i = 0; i < len; i++)
        buf[i] = (char)tolower((unsigned char)method[i]);
    buf[len] = '\0';
    return buf;
}

static void api_openapi_schema_ref_json(struct json_value *out,
                                        const char *schema_name)
{
    char ref[192];
    const char *name = schema_name && schema_name[0]
        ? schema_name : "zcl.rest.response.v1";

    json_set_object(out);
    snprintf(ref, sizeof(ref), "#/components/schemas/%s", name);
    json_push_kv_str(out, "$ref", ref);
}

static void api_openapi_push_string_property(struct json_value *properties,
                                             const char *name)
{
    struct json_value property;
    json_init(&property);
    json_set_object(&property);
    json_push_kv_str(&property, "type", "string");
    json_push_kv(properties, name, &property);
    json_free(&property);
}

static void api_openapi_push_required(struct json_value *schema,
                                      const char *a,
                                      const char *b,
                                      const char *c)
{
    struct json_value required;
    json_init(&required);
    json_set_array(&required);

    const char *items[3] = { a, b, c };
    for (size_t i = 0; i < 3; i++) {
        if (!items[i] || !items[i][0])
            continue;
        struct json_value item;
        json_init(&item);
        json_set_str(&item, items[i]);
        json_push_back(&required, &item);
        json_free(&item);
    }

    json_push_kv(schema, "required", &required);
    json_free(&required);
}

static void api_openapi_push_schema_component(struct json_value *schemas,
                                              const char *schema_name)
{
    if (!schemas || !schema_name || !schema_name[0] ||
        json_get(schemas, schema_name))
        return;

    struct json_value schema;
    json_init(&schema);
    json_set_object(&schema);
    if (strcmp(schema_name, "zcl.supply_legacy_number.v1") == 0) {
        json_push_kv_str(&schema, "type", "number");
        json_push_kv_str(&schema, "format", "double");
    } else if (strcmp(schema_name, ZCL_REST_ERROR_SCHEMA) == 0) {
        json_push_kv_str(&schema, "type", "object");

        struct json_value properties;
        json_init(&properties);
        json_set_object(&properties);
        api_openapi_push_string_property(&properties, "schema");
        api_openapi_push_string_property(&properties, "api_version");
        api_openapi_push_string_property(&properties, "error");
        api_openapi_push_string_property(&properties, "requested_version");
        api_openapi_push_string_property(&properties, "base_path");
        api_openapi_push_string_property(&properties, "index");
        json_push_kv(&schema, "properties", &properties);
        json_free(&properties);

        api_openapi_push_required(&schema, "schema", "api_version",
                                  "error");
        json_push_kv_bool(&schema, "additionalProperties", true);
    } else {
        json_push_kv_str(&schema, "type", "object");
        json_push_kv_bool(&schema, "additionalProperties", true);
    }
    json_push_kv_str(&schema, "x-zcl-schema", schema_name);
    json_push_kv(schemas, schema_name, &schema);
    json_free(&schema);
}

static void api_openapi_param_json(struct json_value *param,
                                   const char *name,
                                   const char *location,
                                   bool required)
{
    json_set_object(param);
    json_push_kv_str(param, "name", name ? name : "");
    json_push_kv_str(param, "in", location ? location : "query");
    json_push_kv_bool(param, "required", required);

    struct json_value schema;
    json_init(&schema);
    json_set_object(&schema);
    if (name && strcmp(name, "limit") == 0) {
        json_push_kv_str(&schema, "type", "integer");
        json_push_kv_int(&schema, "minimum", 1);
    } else {
        json_push_kv_str(&schema, "type", "string");
    }
    json_push_kv(param, "schema", &schema);
    json_free(&schema);
}

static void api_openapi_append_path_params(const char *path,
                                           struct json_value *params)
{
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

            struct json_value param;
            json_init(&param);
            api_openapi_param_json(&param, name, "path", true);
            json_push_back(params, &param);
            json_free(&param);
        }
        p = end + 1;
    }
}

static void api_openapi_append_query_params(const struct json_value *contract,
                                            struct json_value *params)
{
    const struct json_value *query = json_get(contract, "query_params");
    for (size_t i = 0; i < json_size(query); i++) {
        const char *name = json_get_str(json_at(query, i));
        if (!name || !name[0])
            continue;

        struct json_value param;
        json_init(&param);
        api_openapi_param_json(&param, name, "query", false);
        json_push_back(params, &param);
        json_free(&param);
    }
}

static void api_openapi_response_json(struct json_value *response,
                                      const char *description,
                                      const char *schema_name)
{
    json_set_object(response);
    json_push_kv_str(response, "description",
                     description ? description : "Response");

    struct json_value content;
    json_init(&content);
    json_set_object(&content);

    struct json_value media;
    json_init(&media);
    json_set_object(&media);

    struct json_value schema;
    json_init(&schema);
    api_openapi_schema_ref_json(&schema, schema_name);
    json_push_kv(&media, "schema", &schema);
    json_free(&schema);

    json_push_kv(&content, "engine/application/json", &media);
    json_free(&media);

    json_push_kv(response, "content", &content);
    json_free(&content);
}

static void api_openapi_security_json(struct json_value *operation)
{
    struct json_value security;
    json_init(&security);
    json_set_array(&security);

    struct json_value requirement;
    json_init(&requirement);
    json_set_object(&requirement);

    struct json_value scopes;
    json_init(&scopes);
    json_set_array(&scopes);
    json_push_kv(&requirement, "operatorAuth", &scopes);
    json_free(&scopes);

    json_push_back(&security, &requirement);
    json_free(&requirement);

    json_push_kv(operation, "security", &security);
    json_free(&security);
}

static void api_openapi_crypto_policy_json(struct json_value *out)
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
    json_push_kv_str(out, "service_auth_header",
                     "X-ZCL-Service-Token");
    json_push_kv_str(out, "service_auth_token_storage",
                     "store_sha3_512_and_gost_2012_512_commitments_not_secret");
    json_push_kv_bool(out, "signature_scheme_claimed", false);
}

static void api_openapi_operation_json(const struct json_value *contract,
                                       size_t index,
                                       struct json_value *operation,
                                       struct json_value *schemas)
{
    const char *method = json_get_str(json_get(contract, "method"));
    const char *path = json_get_str(json_get(contract, "path"));
    const char *resource = json_get_str(json_get(contract, "resource"));
    const char *action = json_get_str(json_get(contract, "action"));
    const char *crud_operation =
        json_get_str(json_get(contract, "crud_operation"));
    const char *resource_scope =
        json_get_str(json_get(contract, "resource_scope"));
    const char *crud_name = json_get_str(json_get(contract, "crud_name"));
    const char *response_schema =
        json_get_str(json_get(contract, "response_schema"));
    const char *error_schema = json_get_str(json_get(contract, "error_schema"));
    const char *freshness = json_get_str(json_get(contract, "freshness"));
    const char *route_id = json_get_str(json_get(contract, "route_id"));
    const char *command_path = json_get_str(json_get(contract, "command_path"));
    const char *auth_policy = json_get_str(json_get(contract, "auth_policy"));
    const char *legacy_alias =
        json_get_str(json_get(contract, "legacy_alias_of"));
    const char *compat_schema =
        json_get_str(json_get(contract, "compat_response_schema"));
    bool private_route = json_get_bool(json_get(contract, "private"));
    bool canonical = json_get_bool(json_get(contract, "canonical"));
    bool freshness_scoped =
        json_get_bool(json_get(contract, "freshness_scoped"));
    bool pagination = json_get_bool(json_get(contract, "pagination"));

    char operation_id[160];
    char summary[256];
    snprintf(operation_id, sizeof(operation_id), "%s_%s_%zu",
             resource && resource[0] ? resource : "api",
             action && action[0] ? action : "show",
             index);
    snprintf(summary, sizeof(summary), "%s %s",
             method && method[0] ? method : "GET",
             path && path[0] ? path : ZCL_REST_API_BASE_PATH);

    json_set_object(operation);
    json_push_kv_str(operation, "operationId", operation_id);
    json_push_kv_str(operation, "summary", summary);

    struct json_value tags;
    json_init(&tags);
    json_set_array(&tags);
    struct json_value tag;
    json_init(&tag);
    json_set_str(&tag, resource && resource[0] ? resource : "api");
    json_push_back(&tags, &tag);
    json_free(&tag);
    json_push_kv(operation, "tags", &tags);
    json_free(&tags);

    json_push_kv_str(operation, "x-resource", resource);
    json_push_kv_str(operation, "x-action", action);
    json_push_kv_str(operation, "x-crud-operation", crud_operation);
    json_push_kv_str(operation, "x-resource-scope", resource_scope);
    json_push_kv_str(operation, "x-crud-name", crud_name);
    json_push_kv_str(operation, "x-route-id", route_id);
    if (command_path && command_path[0])
        json_push_kv_str(operation, "x-zcl-command-path", command_path);
    json_push_kv_bool(operation, "x-private", private_route);
    json_push_kv_str(operation, "x-auth",
                     private_route ? "operator_private" : "public");
    json_push_kv_str(operation, "x-auth-policy", auth_policy);
    json_push_kv_bool(operation, "x-gateway-auth-compatible",
                      json_get_bool(json_get(contract,
                                            "gateway_auth_compatible")));
    json_push_kv_str(operation, "x-response-schema", response_schema);
    json_push_kv_str(operation, "x-error-schema", error_schema);
    api_app_protocol_push_openapi_extensions(contract, operation);
    json_push_kv_str(operation, "x-freshness", freshness);
    json_push_kv_bool(operation, "x-freshness-scoped", freshness_scoped);
    json_push_kv_bool(operation, "x-pagination", pagination);
    json_push_kv_bool(operation, "x-canonical", canonical);
    if (legacy_alias && legacy_alias[0])
        json_push_kv_str(operation, "x-legacy-alias-of", legacy_alias);
    if (compat_schema && compat_schema[0])
        json_push_kv_str(operation, "x-compat-response-schema",
                         compat_schema);
    const struct json_value *telemetry = json_get(contract, "telemetry");
    if (telemetry)
        json_push_kv(operation, "x-zcl-telemetry", telemetry);
    const struct json_value *crypto_policy =
        json_get(contract, "crypto_policy");
    if (crypto_policy)
        json_push_kv(operation, "x-zcl-crypto-policy", crypto_policy);
    const struct json_value *service_binding =
        json_get(contract, "service_binding");
    if (service_binding)
        json_push_kv(operation, "x-zcl-service-binding", service_binding);
    const struct json_value *filter_contract =
        json_get(contract, "filter_contract");
    if (filter_contract)
        json_push_kv(operation, "x-zcl-filter-contract", filter_contract);
    const struct json_value *path_param_contract =
        json_get(contract, "path_param_contract");
    if (path_param_contract)
        json_push_kv(operation, "x-zcl-path-param-contract",
                     path_param_contract);
    const struct json_value *id_params = json_get(contract, "id_params");
    if (id_params)
        json_push_kv(operation, "x-id-params", id_params);
    if (private_route)
        api_openapi_security_json(operation);

    struct json_value params;
    json_init(&params);
    json_set_array(&params);
    api_openapi_append_path_params(path, &params);
    api_openapi_append_query_params(contract, &params);
    if (!json_empty(&params))
        json_push_kv(operation, "parameters", &params);
    json_free(&params);

    struct json_value responses;
    json_init(&responses);
    json_set_object(&responses);

    struct json_value ok_response;
    json_init(&ok_response);
    api_openapi_response_json(&ok_response, "OK", response_schema);
    json_push_kv(&responses, "200", &ok_response);
    json_free(&ok_response);

    struct json_value error_response;
    json_init(&error_response);
    api_openapi_response_json(&error_response, "Error", error_schema);
    json_push_kv(&responses, "default", &error_response);
    json_free(&error_response);

    json_push_kv(operation, "responses", &responses);
    json_free(&responses);

    api_openapi_push_schema_component(schemas, response_schema);
    api_openapi_push_schema_component(schemas, error_schema);
    api_openapi_push_schema_component(schemas, compat_schema);
    if (filter_contract)
        api_openapi_push_schema_component(schemas,
                                          ZCL_QUERY_FILTER_CONTRACT_SCHEMA);
    if (path_param_contract)
        api_openapi_push_schema_component(schemas,
                                          ZCL_PATH_PARAM_CONTRACT_SCHEMA);
}

static void api_openapi_components_json(struct json_value *components,
                                        struct json_value *schemas)
{
    json_set_object(components);
    json_push_kv(components, "schemas", schemas);

    struct json_value security_schemes;
    json_init(&security_schemes);
    json_set_object(&security_schemes);

    struct json_value operator_auth;
    json_init(&operator_auth);
    json_set_object(&operator_auth);
    json_push_kv_str(&operator_auth, "type", "apiKey");
    json_push_kv_str(&operator_auth, "in", "header");
    json_push_kv_str(&operator_auth, "name", "Authorization");
    json_push_kv_str(&operator_auth, "description",
                     "Operator-private transport/auth gate.");
    json_push_kv(&security_schemes, "operatorAuth", &operator_auth);
    json_free(&operator_auth);

    struct json_value service_hash_auth;
    json_init(&service_hash_auth);
    json_set_object(&service_hash_auth);
    json_push_kv_str(&service_hash_auth, "type", "apiKey");
    json_push_kv_str(&service_hash_auth, "in", "header");
    json_push_kv_str(&service_hash_auth, "name", "X-ZCL-Service-Token");
    json_push_kv_str(&service_hash_auth, "description",
        "Service-gateway API token; store and compare SHA3-512 plus "
        "GOST R 34.11-2012-512 commitments.");
    json_push_kv(&security_schemes, "serviceHash512Auth",
                 &service_hash_auth);
    json_free(&service_hash_auth);

    json_push_kv(components, "securitySchemes", &security_schemes);
    json_free(&security_schemes);
}

static void api_openapi_json(struct json_value *root)
{
    struct json_value contracts;
    json_init(&contracts);
    api_route_contracts_json(&contracts);

    struct json_value paths;
    json_init(&paths);
    json_set_object(&paths);

    struct json_value schemas;
    json_init(&schemas);
    json_set_object(&schemas);
    api_openapi_push_schema_component(&schemas, ZCL_REST_OPENAPI_SCHEMA);

    for (size_t i = 0; i < json_size(&contracts); i++) {
        const struct json_value *contract = json_at(&contracts, i);
        const char *path = json_get_str(json_get(contract, "path"));
        const char *method = json_get_str(json_get(contract, "method"));
        if (!path || !path[0] || !method || !method[0])
            continue;

        char method_buf[16];
        const char *method_key =
            api_openapi_method_key(method, method_buf, sizeof(method_buf));

        struct json_value path_item;
        json_init(&path_item);
        json_set_object(&path_item);

        struct json_value operation;
        json_init(&operation);
        api_openapi_operation_json(contract, i, &operation, &schemas);
        json_push_kv(&path_item, method_key, &operation);
        json_free(&operation);

        json_push_kv(&paths, path, &path_item);
        json_free(&path_item);
    }

    json_set_object(root);
    json_push_kv_str(root, "schema", ZCL_REST_OPENAPI_SCHEMA);
    json_push_kv_str(root, "openapi", "3.1.0");
    json_push_kv_str(root, "x-zcl-schema", ZCL_REST_OPENAPI_SCHEMA);
    json_push_kv_str(root, "x-api-version", ZCL_REST_API_VERSION);
    json_push_kv_int(root, "x-route-contract-count",
                     (int64_t)api_route_contract_count());

    struct json_value crypto_policy;
    json_init(&crypto_policy);
    api_openapi_crypto_policy_json(&crypto_policy);
    json_push_kv(root, "x-zcl-crypto-policy", &crypto_policy);
    json_free(&crypto_policy);

    struct json_value layer_model;
    json_init(&layer_model);
    api_rest_layer_model_json(&layer_model);
    json_push_kv(root, "x-zcl-layer-model", &layer_model);
    json_free(&layer_model);

    struct json_value info;
    json_init(&info);
    json_set_object(&info);
    json_push_kv_str(&info, "title", "Z23 REST API");
    json_push_kv_str(&info, "version", ZCL_REST_API_VERSION);
    json_push_kv(root, "info", &info);
    json_free(&info);

    struct json_value servers;
    json_init(&servers);
    json_set_array(&servers);
    struct json_value server;
    json_init(&server);
    json_set_object(&server);
    json_push_kv_str(&server, "url", ZCL_REST_API_BASE_PATH);
    json_push_kv_str(&server, "description", "Canonical v1 REST base path.");
    json_push_back(&servers, &server);
    json_free(&server);
    json_push_kv(root, "servers", &servers);
    json_free(&servers);

    json_push_kv(root, "paths", &paths);
    json_free(&paths);

    struct json_value components;
    json_init(&components);
    api_openapi_components_json(&components, &schemas);
    json_push_kv(root, "components", &components);
    json_free(&components);
    json_free(&schemas);

    json_free(&contracts);
}

static void api_rest_index_json(struct json_value *root)
{
    json_set_object(root);
    json_push_kv_str(root, "schema", ZCL_REST_INDEX_SCHEMA);
    json_push_kv_str(root, "name", "zclassic23 REST API");
    json_push_kv_str(root, "api_version", ZCL_REST_API_VERSION);
    json_push_kv_str(root, "version", ZCL_REST_API_VERSION);

    struct json_value versions;
    json_init(&versions);
    json_set_array(&versions);
    struct json_value version;
    json_init(&version);
    json_set_str(&version, ZCL_REST_API_VERSION);
    json_push_back(&versions, &version);
    json_free(&version);
    json_push_kv(root, "supported_versions", &versions);
    json_free(&versions);

    json_push_kv_str(root, "base_path", ZCL_REST_API_BASE_PATH);
    json_push_kv_str(root, "compat_base_path", ZCL_REST_API_COMPAT_BASE_PATH);
    json_push_kv_str(root, "first_call", ZCL_REST_API_BASE_PATH "/agent");
    json_push_kv_str(root, "summary",
        "Use noun resources. GET reads collections/items; mutating operator "
        "actions stay private unless an endpoint explicitly documents POST.");

    struct json_value aliases;
    json_init(&aliases);
    api_rest_index_aliases_json(&aliases);
    json_push_kv(root, "aliases", &aliases);
    json_free(&aliases);

    struct json_value crud;
    json_init(&crud);
    api_rest_index_crud_json(&crud);
    json_push_kv(root, "crud", &crud);
    json_free(&crud);

    struct json_value layer_model;
    json_init(&layer_model);
    api_rest_layer_model_json(&layer_model);
    json_push_kv(root, "layer_model", &layer_model);
    json_free(&layer_model);

    struct json_value resources;
    json_init(&resources);
    api_rest_index_resources_json(&resources);
    json_push_kv(root, "resources", &resources);
    json_free(&resources);

    struct json_value routes;
    json_init(&routes);
    api_route_contracts_json(&routes);
    json_push_kv(root, "route_contracts", &routes);
    json_free(&routes);
    json_push_kv_int(root, "route_contract_count",
                     (int64_t)api_route_contract_count());

    struct json_value drilldown;
    json_init(&drilldown);
    api_rest_index_drilldown_json(&drilldown);
    json_push_kv(root, "drilldown", &drilldown);
    json_free(&drilldown);

    struct json_value cli;
    json_init(&cli);
    api_rest_index_cli_json(&cli);
    json_push_kv(root, "cli", &cli);
    json_free(&cli);
}

const char *api_rest_index_body_json(void)
{
    static _Thread_local char body[262144];

    struct json_value root;
    json_init(&root);
    api_rest_index_json(&root);
    size_t len = json_write(&root, body, sizeof(body));
    json_free(&root);

    if (len >= sizeof(body)) {
        snprintf(body, sizeof(body),
            "{"
            "\"schema\":\"" ZCL_REST_ERROR_SCHEMA "\","
            "\"error\":\"rest_index_too_large\","
            "\"base_path\":\"" ZCL_REST_API_BASE_PATH "\""
            "}");
    }
    return body;
}

/* Route: /api
 * Self-describing REST entry point. Keep this stable: it is the shape humans
 * and agents should read before choosing a drill-down endpoint. */
size_t api_serve_api_index(uint8_t *response, size_t response_max)
{
    if (!response || response_max == 0)
        return 0;

    const char *body = api_rest_index_body_json();
    size_t body_len = strlen(body);

    int header_len = snprintf((char *)response, response_max,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: engine/application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "Content-Length: %zu\r\n\r\n",
        body_len);
    if (header_len < 0 || (size_t)header_len >= response_max)
        return 0;

    size_t hlen = (size_t)header_len;
    if (body_len > response_max - hlen)
        return api_json_error(response, response_max, JSON_500_HEADERS,
                              "API index response too large");

    memcpy(response + hlen, body, body_len);
    return hlen + body_len;
}

/* Route: /api/v1/openapi
 * OpenAPI-style contract emitted from the same route registry as /api/v1. */
size_t api_serve_openapi(uint8_t *response, size_t response_max)
{
    if (!response || response_max == 0)
        return 0;

    struct json_value root;
    json_init(&root);
    api_openapi_json(&root);
    size_t n = api_json_ok(response, response_max, &root);
    json_free(&root);
    return n;
}
