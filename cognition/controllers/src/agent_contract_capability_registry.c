/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "controllers/agent_controller.h"

#include "json/json.h"

#include <string.h>

bool agent_push_contract_capability_json(struct json_value *arr,
                                         const char *method,
                                         const char *name_override,
                                         const char *purpose_override)
{
    const struct agent_contract *c = agent_contract_lookup(method);
    if (!arr || !c)
        return false;

    const char *name = name_override && name_override[0]
        ? name_override : c->capability;
    const char *purpose = purpose_override && purpose_override[0]
        ? purpose_override : c->purpose;
    const bool alias = name && c->capability &&
        strcmp(name, c->capability) != 0;

    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    json_push_kv_str(&obj, "name", name);
    json_push_kv_str(&obj, "method", c->method);
    json_push_kv_str(&obj, "schema", c->schema);
    json_push_kv_str(&obj, "native", c->native_command);
    json_push_kv_str(&obj, "rest", c->rest_route);
    json_push_kv_str(&obj, "purpose", purpose);
    json_push_kv_bool(&obj, "registry_alias", alias);
    if (alias)
        json_push_kv_str(&obj, "canonical_capability", c->capability);
    json_push_kv_str(&obj, "contract_source", "agent_contracts.def");
    json_push_back(arr, &obj);
    json_free(&obj);
    return true;
}

void agent_push_contract_capabilities_json(struct json_value *arr)
{
    if (!arr)
        return;

    for (size_t i = 0; i < agent_contract_count(); i++) {
        const struct agent_contract *c = agent_contract_at(i);
        if (!c)
            continue;
        agent_push_contract_capability_json(arr, c->method, NULL, NULL);
    }
}
