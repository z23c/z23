/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Shared path-parameter contracts for REST/OpenAPI. These contracts make
 * route IDs actionable for agents without requiring a source-code lookup. */

#include "api_controller_internal.h"

#include "json/json.h"

#include <string.h>

static bool api_path_uses_znam_name(const char *method,
                                    const char *canonical_path)
{
    if (!method || !canonical_path || strcmp(method, "GET") != 0)
        return false;
    return strcmp(canonical_path, "/api/v1/names/{name}") == 0 ||
           strcmp(canonical_path, "/api/v1/names/{name}/services") == 0;
}

static void api_znam_name_param_contract_json(struct json_value *out)
{
    json_set_object(out);
    json_push_kv_str(out, "contract_name", "znam_name");
    json_push_kv_str(out, "validator", "znam_validate_name");
    json_push_kv_str(out, "type", "string");
    json_push_kv_int(out, "min_length", 1);
    json_push_kv_int(out, "max_length", 63);
    json_push_kv_str(out, "charset",
                     "lowercase_ascii_letters,digits,hyphen");
    json_push_kv_str(out, "pattern",
                     "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$");
    json_push_kv_str(out, "rejects",
                     "empty,uppercase,spaces,dots,underscore,"
                     "leading_hyphen,trailing_hyphen");
    json_push_kv_str(out, "example", "alice");
}

bool api_path_param_contracts_json(const char *method,
                                   const char *public_path,
                                   const char *alias_of,
                                   struct json_value *out)
{
    const char *canonical_path =
        alias_of && alias_of[0] ? alias_of : public_path;

    json_set_object(out);
    json_push_kv_str(out, "schema", ZCL_PATH_PARAM_CONTRACT_SCHEMA);
    json_push_kv_str(out, "semantics", "server_side_route_validation");

    struct json_value params;
    json_init(&params);
    json_set_object(&params);

    if (api_path_uses_znam_name(method, canonical_path)) {
        struct json_value name;
        json_init(&name);
        api_znam_name_param_contract_json(&name);
        json_push_kv(&params, "name", &name);
        json_free(&name);
    }

    const bool has_contracts = !json_empty(&params);
    if (has_contracts)
        json_push_kv(out, "params", &params);
    json_free(&params);

    return has_contracts;
}
