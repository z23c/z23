/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "controllers/agent_controller.h"
#include "controllers/network_controller.h"
#include "json/json.h"

#include <string.h>

bool peer_incidents_from_dumpstate_result_json(const struct json_value *result,
                                               struct json_value *out,
                                               const char *reason)
{
    if (!result || !out)
        return false;

    const struct json_value *state = result;
    if (result->type == JSON_OBJ) {
        const struct json_value *nested = json_get(result, "state");
        if (nested && nested->type == JSON_OBJ)
            state = nested;
    }
    if (!state || state->type != JSON_OBJ)
        return false;

    const char *schema = json_get_str(json_get(state, "schema"));
    if (strcmp(schema, "zcl.peer_incidents.v2") != 0)
        return false;

    json_copy(out, state);
    agent_push_contract_identity_fields_json(out, "peerincidents");
    json_push_kv_bool(out, "compatibility_fallback", true);
    json_push_kv_str(out, "compatibility_source",
                     "dumpstate peer_lifecycle incidents");
    json_push_kv_str(out, "compatibility_reason",
                     reason && reason[0]
                         ? reason
                         : "target_peerincidents_method_not_found");
    json_push_kv_str(out, "fallback_native_command",
                     "z23 dumpstate peer_lifecycle incidents");
    return true;
}
