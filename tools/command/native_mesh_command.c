/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Native read-only machine-mesh status commands. */

#include "command/native_command.h"

#include "controllers/rpc_client.h"
#include "json/json.h"
#include "util/log_macros.h"

#include <stdlib.h>
#include <string.h>

void zcl_native_handle_ops_mesh_identity(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply) {
        LOG_ERROR("native.mesh", "INVALID_REQUEST: null request or reply");
        return;
    }
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call("dumpstate", "[\"machine_identity\"]");
    if (!raw) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE",
                               "dispatch", true, false,
                               "the node did not return its machine identity",
                               "machine_identity");
        return;
    }
    struct json_value body = {0};
    bool parsed = json_read(&body, raw, strlen(raw));
    free(raw);
    const struct json_value *state = parsed && body.type == JSON_OBJ
                                         ? json_get(&body, "state")
                                         : NULL;
    if (!state || state->type != JSON_OBJ) {
        json_free(&body);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BAD_STATE_BODY",
                               "serialize", false, false,
                               "machine identity response carried no state object",
                               "machine_identity");
        return;
    }
    zcl_native_bridge_project(request, state, reply);
    json_free(&body);
}
