/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Shared query-filter contracts for REST collections. Endpoint responses,
 * route contracts, and OpenAPI extensions use this file as the single source
 * for strict filter semantics and accepted aliases. */

#include "api_controller_internal.h"

#include "json/json.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

#define API_QUERY_FILTER_SAFE_CHARS "letters,digits,underscore,dash,dot"
#define API_QF_TEXT(k_, i_, c_) \
    { k_, API_QUERY_FILTER_SAFE_CHARS, i_, c_, API_QUERY_FILTER_SAFE_TEXT, false, false }
#define API_QF_ENUM(k_, a_, i_, c_) \
    { k_, a_, i_, c_, API_QUERY_FILTER_ENUM, false, false }
#define API_QF_ALIAS(k_, a_, i_, c_) \
    { k_, a_, i_, c_, API_QUERY_FILTER_SAFE_TEXT, true, false }
#define API_QF_BOOL(k_, i_, c_) \
    { k_, "true,false", i_, c_, API_QUERY_FILTER_ENUM, false, true }
#define API_QF_COUNT(a_) (sizeof(a_) / sizeof((a_)[0]))

enum api_query_filter_validation {
    API_QUERY_FILTER_SAFE_TEXT = 0,
    API_QUERY_FILTER_ENUM
};

struct api_query_filter_field_definition {
    const char *key;
    const char *allowed;
    size_t value_index;
    size_t value_cap;
    enum api_query_filter_validation validation;
    bool alias;
    bool json_bool;
};

struct api_query_filter_contract_definition {
    const char *name;
    const struct api_query_filter_field_definition *fields;
    size_t field_count;
    size_t key_cap;
    const char *example;
    const char *filter_semantics;
    const char *error_code;
    const char *default_error;
};

static const struct api_query_filter_field_definition
k_service_operation_fields[] = {
    API_QF_TEXT("service", 0, 64),
    API_QF_ENUM("write_safety",
                "public_read_only,operator_private,operator_private_destructive",
                1, 40),
    API_QF_ENUM("preferred_interface", "rest,rpc,native_or_planned", 2, 32),
    API_QF_ALIAS("interface", "alias_for_preferred_interface", 2, 32),
    API_QF_ENUM("status", "active,in_progress", 3, 32),
    API_QF_ENUM("surface", "rest,rpc", 4, 16),
};

static const struct api_query_filter_field_definition
k_name_service_directory_fields[] = {
    API_QF_TEXT("service", 0, 64),
    API_QF_TEXT("service_contract", 1, 64),
    API_QF_ALIAS("contract", "alias_for_service_contract", 1, 64),
    API_QF_ENUM("transport", "p2p,onion,p2p_or_onion,unspecified,none", 2, 32),
    API_QF_TEXT("endpoint_kind", 3, 64),
    API_QF_BOOL("valid", 4, 8),
    API_QF_BOOL("endpoint_only", 5, 8),
};

static const struct api_query_filter_contract_definition
k_query_filter_contracts[] = {
    {
        API_QUERY_FILTER_SERVICE_OPERATIONS,
        k_service_operation_fields,
        API_QF_COUNT(k_service_operation_fields),
        40,
        "/api/v1/service-operations?"
        "service=bootstrap&write_safety=public_read_only",
        "exact-match filters over the static operation catalog",
        "invalid_service_operation_filter",
        "invalid service operation filter",
    },
    {
        API_QUERY_FILTER_NAME_SERVICE_DIRECTORY,
        k_name_service_directory_fields,
        API_QF_COUNT(k_name_service_directory_fields),
        48,
        "/api/v1/names/alice/services?"
        "transport=p2p&valid=true&endpoint_only=true",
        "exact-match filters over the verified ZNAM service record "
        "projection",
        "invalid_name_service_filter",
        "invalid name service filter",
    },
};

static bool api_query_filter_contract_valid(
    const struct api_query_filter_contract_definition *contract)
{
    if (!contract || !contract->name || !contract->name[0] ||
        !contract->fields || contract->field_count == 0 ||
        !contract->example || !contract->filter_semantics ||
        !contract->error_code || !contract->default_error ||
        contract->key_cap == 0 ||
        contract->key_cap > sizeof(((struct api_query_filter *)0)->unknown_key))
        return false; /* raw-return-ok:invalid-filter-contract */

    for (size_t i = 0; i < contract->field_count; i++) {
        const struct api_query_filter_field_definition *field =
            &contract->fields[i];
        bool canonical_slot = !field->alias;

        if (!field->key || !field->key[0] || !field->allowed ||
            !field->allowed[0] || strlen(field->key) >= contract->key_cap ||
            field->value_index >= API_QUERY_FILTER_MAX_FIELDS ||
            field->value_cap == 0 ||
            field->value_cap > API_QUERY_FILTER_VALUE_CAP ||
            field->validation > API_QUERY_FILTER_ENUM)
            return false; /* raw-return-ok:invalid-filter-contract */

        for (size_t j = 0; j < contract->field_count; j++) {
            const struct api_query_filter_field_definition *peer =
                &contract->fields[j];

            if (i != j && peer->key && strcmp(peer->key, field->key) == 0)
                return false; /* raw-return-ok:invalid-filter-contract */
            if (i == j || peer->alias ||
                peer->value_index != field->value_index)
                continue;
            if (canonical_slot || peer->value_cap != field->value_cap)
                return false; /* raw-return-ok:invalid-filter-contract */
            canonical_slot = true;
        }
        if (!canonical_slot)
            return false; /* raw-return-ok:invalid-filter-contract */
    }
    return true;
}

static const struct api_query_filter_contract_definition *
api_query_filter_contract_lookup(const char *name)
{
    if (!name || !name[0])
        return NULL;
    for (size_t i = 0; i < API_QF_COUNT(k_query_filter_contracts); i++) {
        if (k_query_filter_contracts[i].name &&
            strcmp(k_query_filter_contracts[i].name, name) == 0)
            return &k_query_filter_contracts[i];
    }
    return NULL;
}

static const struct api_query_filter_field_definition *
api_query_filter_field_lookup(
    const struct api_query_filter_contract_definition *contract,
    const char *key)
{
    if (!api_query_filter_contract_valid(contract) || !key || !key[0])
        return NULL;
    for (size_t i = 0; i < contract->field_count; i++) {
        if (strcmp(contract->fields[i].key, key) == 0)
            return &contract->fields[i];
    }
    return NULL;
}

static void api_query_filter_canonical_keys(
    const struct api_query_filter_contract_definition *contract,
    char *out, size_t out_len)
{
    size_t used = 0;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!api_query_filter_contract_valid(contract))
        return;
    for (size_t i = 0; i < contract->field_count && used < out_len; i++) {
        const struct api_query_filter_field_definition *field =
            &contract->fields[i];
        int wrote;

        if (field->alias)
            continue;
        wrote = snprintf(out + used, out_len - used, "%s%s",
                         used ? ", " : "", field->key);
        if (wrote < 0 || (size_t)wrote >= out_len - used) {
            out[out_len - 1] = '\0';
            return;
        }
        used += (size_t)wrote;
    }
}

static bool api_query_filter_value_safe(const char *value)
{
    if (!value || !value[0])
        return true;
    for (const char *p = value; *p; p++) {
        const char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
            return false; /* raw-return-ok:filter-validation-error */
    }
    return true;
}

static bool api_query_filter_allowed_value(const char *value,
                                           const char *csv)
{
    const char *p = csv;
    size_t value_len;

    if (!value || !value[0])
        return true;
    if (!csv || !csv[0])
        return false; /* raw-return-ok:filter-validation-error */

    value_len = strlen(value);
    while (*p) {
        const char *end = strchr(p, ',');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len == value_len && strncmp(p, value, len) == 0)
            return true;
        if (!end)
            break;
        p = end + 1;
    }
    return false; /* raw-return-ok:filter-validation-error */
}

const char *api_query_filter_contract_for_route(const char *method,
                                                const char *public_path)
{
    if (!method || !public_path || strcmp(method, "GET") != 0)
        return NULL;
    if (strcmp(public_path, "/api/v1/service-operations") == 0)
        return API_QUERY_FILTER_SERVICE_OPERATIONS;
    if (strcmp(public_path, "/api/v1/names/{name}/services") == 0)
        return API_QUERY_FILTER_NAME_SERVICE_DIRECTORY;
    return NULL;
}

void api_query_filter_init(struct api_query_filter *filter,
                           const char *contract_name)
{
    if (!filter)
        return;
    memset(filter, 0, sizeof(*filter));
    filter->contract = api_query_filter_contract_lookup(contract_name);
    if (!filter->contract)
        snprintf(filter->unknown_key, sizeof(filter->unknown_key), "%s",
                 contract_name && contract_name[0] ? contract_name : "(missing)");
}

void api_query_filter_set(struct api_query_filter *filter,
                          const char *key, const char *value)
{
    const struct api_query_filter_field_definition *field;

    if (!filter || !key || !key[0])
        return;
    field = api_query_filter_field_lookup(filter->contract, key);
    if (!field) {
        if (!filter->unknown_key[0])
            snprintf(filter->unknown_key, sizeof(filter->unknown_key),
                     "%s", key);
        return;
    }
    if (!value || !value[0])
        return;

    snprintf(filter->values[field->value_index], field->value_cap,
             "%s", value);
    filter->active = true;
}

void api_query_filter_from_path(struct api_query_filter *filter,
                                const char *path)
{
    const char *q;
    size_t key_cap;

    if (!path || !filter ||
        !api_query_filter_contract_valid(filter->contract))
        return;
    q = strchr(path, '?');
    if (!q)
        return;
    q++;
    key_cap = filter->contract->key_cap;

    while (*q) {
        char key[48] = {0};
        char value[128] = {0};
        const char *pair_end = strchr(q, '&');
        const char *eq = strchr(q, '=');
        size_t pair_len = pair_end ? (size_t)(pair_end - q) : strlen(q);
        size_t key_len = eq && (size_t)(eq - q) < pair_len
                             ? (size_t)(eq - q)
                             : pair_len;
        size_t value_len = eq && (size_t)(eq - q) < pair_len
                               ? pair_len - key_len - 1
                               : 0;

        if (key_len >= key_cap)
            key_len = key_cap - 1;
        if (value_len >= sizeof(value))
            value_len = sizeof(value) - 1;
        memcpy(key, q, key_len);
        key[key_len] = '\0';
        if (value_len > 0)
            memcpy(value, eq + 1, value_len);
        value[value_len] = '\0';
        api_query_filter_set(filter, key, value);

        if (!pair_end)
            break;
        q = pair_end + 1;
    }
}

const char *api_query_filter_value(const struct api_query_filter *filter,
                                   const char *canonical_key)
{
    const struct api_query_filter_field_definition *field;

    if (!filter)
        return "";
    field = api_query_filter_field_lookup(filter->contract, canonical_key);
    if (!field)
        return "";
    return filter->values[field->value_index];
}

bool api_query_filter_matches_value(const struct api_query_filter *filter,
                                    const char *canonical_key,
                                    const char *actual)
{
    if (!filter ||
        !api_query_filter_field_lookup(filter->contract, canonical_key))
        return false; /* raw-return-ok:invalid-filter-contract */
    const char *expected = api_query_filter_value(filter, canonical_key);

    return !expected[0] || (actual && strcmp(actual, expected) == 0);
}

void api_query_filter_values_json(const struct api_query_filter *filter,
                                  struct json_value *out)
{
    json_set_object(out);
    json_push_kv_bool(out, "active", filter && filter->active);
    if (!filter || !api_query_filter_contract_valid(filter->contract))
        return;

    for (size_t i = 0; i < filter->contract->field_count; i++) {
        const struct api_query_filter_field_definition *field =
            &filter->contract->fields[i];
        const char *value = filter->values[field->value_index];

        if (field->alias || !value[0])
            continue;
        if (field->json_bool)
            json_push_kv_bool(out, field->key, strcmp(value, "true") == 0);
        else
            json_push_kv_str(out, field->key, value);
    }
    json_push_kv_str(out, "semantics", filter->contract->filter_semantics);
}

bool api_query_filter_validate(const struct api_query_filter *filter,
                               char *err,
                               size_t err_len)
{
    char allowed[API_QUERY_FILTER_MAX_FIELDS * 50];

    if (!filter) {
        if (err && err_len > 0)
            snprintf(err, err_len, "missing query-filter state");
        LOG_FAIL("api.query_filter", "missing query-filter state");
    }
    if (!filter->contract) {
        if (err && err_len > 0)
            snprintf(err, err_len, "unknown query-filter contract '%s'",
                     filter->unknown_key);
        LOG_FAIL("api.query_filter", "unknown query-filter contract '%s'",
                 filter->unknown_key);
    }
    if (!api_query_filter_contract_valid(filter->contract)) {
        if (err && err_len > 0)
            snprintf(err, err_len, "invalid query-filter contract '%s'",
                     filter->contract->name ? filter->contract->name : "(unnamed)");
        LOG_FAIL("api.query_filter", "invalid query-filter contract '%s'",
                 filter->contract->name ? filter->contract->name : "(unnamed)");
    }

    if (filter->unknown_key[0]) {
        api_query_filter_canonical_keys(filter->contract,
                                        allowed, sizeof(allowed));
        if (err && err_len > 0)
            snprintf(err, err_len, "unknown filter '%s' (allowed: %s)",
                     filter->unknown_key, allowed);
        return false; /* raw-return-ok:filter-validation-error */
    }

    for (size_t i = 0; i < filter->contract->field_count; i++) {
        const struct api_query_filter_field_definition *field =
            &filter->contract->fields[i];
        const char *value;
        bool valid;

        if (field->alias)
            continue;
        value = filter->values[field->value_index];
        valid = field->validation == API_QUERY_FILTER_SAFE_TEXT
                    ? api_query_filter_value_safe(value)
                    : api_query_filter_allowed_value(value, field->allowed);
        if (valid)
            continue;
        if (err && err_len > 0)
            snprintf(err, err_len, "invalid %s '%s' (allowed: %s)",
                     field->key, value, field->allowed);
        return false; /* raw-return-ok:filter-validation-error */
    }
    return true;
}

void api_query_filter_allowed_filters_json(const char *contract_name,
                                           struct json_value *out)
{
    const struct api_query_filter_contract_definition *contract =
        api_query_filter_contract_lookup(contract_name);

    json_set_object(out);
    if (!api_query_filter_contract_valid(contract))
        return;
    for (size_t i = 0; i < contract->field_count; i++)
        json_push_kv_str(out, contract->fields[i].key,
                         contract->fields[i].allowed);
}

void api_query_filter_contract_json(const char *contract_name,
                                    struct json_value *out)
{
    struct json_value allowed = {0};
    const struct api_query_filter_contract_definition *contract =
        api_query_filter_contract_lookup(contract_name);

    if (!api_query_filter_contract_valid(contract))
        contract = NULL;

    json_set_object(out);
    json_push_kv_str(out, "schema", ZCL_QUERY_FILTER_CONTRACT_SCHEMA);
    json_push_kv_bool(out, "unknown_filters_error", true);
    json_push_kv_str(out, "semantics", "server_side_exact_match");
    if (contract_name && contract_name[0])
        json_push_kv_str(out, "contract_name", contract_name);

    api_query_filter_allowed_filters_json(contract_name, &allowed);
    json_push_kv(out, "allowed_filters", &allowed);
    json_free(&allowed);

    if (contract)
        json_push_kv_str(out, "example", contract->example);
}

void api_query_filter_error_json(const char *contract_name,
                                 const char *message,
                                 struct json_value *out)
{
    const struct api_query_filter_contract_definition *contract =
        api_query_filter_contract_lookup(contract_name);
    struct json_value allowed = {0};

    if (!api_query_filter_contract_valid(contract))
        contract = NULL;

    json_set_object(out);
    json_push_kv_str(out, "schema", ZCL_REST_ERROR_SCHEMA);
    json_push_kv_str(out, "api_version", ZCL_REST_API_VERSION);
    json_push_kv_str(out, "error", contract ? contract->error_code : "");
    json_push_kv_str(out, "message",
                     message && message[0] ? message :
                     contract ? contract->default_error : "invalid filter");
    api_query_filter_allowed_filters_json(contract_name, &allowed);
    json_push_kv(out, "allowed_filters", &allowed);
    json_free(&allowed);
    if (contract)
        json_push_kv_str(out, "example", contract->example);
}
