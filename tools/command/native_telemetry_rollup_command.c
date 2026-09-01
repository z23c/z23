/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `ops.telemetry.summary`, `ops.telemetry.health` and
 * `ops.telemetry.alerts.active` — the CLI half of the whole-node rollup.
 *
 * These are the entry point to the tree: an agent that knows nothing about
 * this node runs `ops telemetry summary`, is told which domain is the
 * problem, and is handed the exact command to drill into it.
 *
 * The fold itself is NOT here. It runs inside the node
 * (engine/services/src/telemetry_rollup.c) and is reached over the same
 * SELECT-only `dumpstate` RPC the per-domain node-scoped leaves use, because
 * a rollup collects every domain and most collectors read subsystems that
 * only exist in a running node's process — in a one-shot CLI process the sync
 * collector reaches chain_params_get() and aborts on its assertion. What a
 * handler here owns is one decision: which projection to ask for.
 *
 * Bound by engine/composition/commands/telemetry/root.def.
 */

#include "command/native_command.h"

#include "controllers/rpc_client.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* One dumpstate round trip against the `telemetry_rollup` subsystem at one
 * projection. `key` is a fixed token from the three call sites below — never
 * caller text — so it is spliced into the params array rather than
 * round-tripped through a JSON builder. */
static void trc_dispatch(const struct zcl_command_request *request,
                         struct zcl_command_reply *reply, const char *key)
{
    if (!request || !reply)
        return;

    char params[96];
    int n = snprintf(params, sizeof params, "[\"telemetry_rollup\",\"%s\"]",
                     key);
    if (n <= 0 || (size_t)n >= sizeof params) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED",
                               "normalize", false, false,
                               "could not encode the rollup projection key",
                               "telemetry_rollup");
        return;
    }

    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call("dumpstate", params);
    if (!raw) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE",
                               "dispatch", true, false,
                               "the node did not return a telemetry rollup "
                               "body; the fold runs inside the node because "
                               "most domain collectors need its process",
                               "telemetry_rollup");
        (void)zcl_command_reply_add_next(reply, "core.status", "{}",
                                         "confirm the node is running");
        return;
    }

    struct json_value body;
    if (!json_read(&body, raw, strlen(raw)) || body.type != JSON_OBJ) {
        json_free(&body);
        free(raw);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BAD_STATE_BODY",
                               "serialize", false, false,
                               "the telemetry rollup returned a non-object "
                               "body", "telemetry_rollup");
        return;
    }
    free(raw);

    /* node_rpc_call surfaces a JSON-RPC failure as either {"error":{...}} or a
     * bare {"code":..,"message":..}; both mean the dump did not happen. */
    const struct json_value *err = json_get(&body, "error");
    const struct json_value *ecode = json_get(&body, "code");
    const struct json_value *emsg = json_get(&body, "message");
    if ((err && !json_is_null(err)) ||
        (ecode && ecode->type == JSON_INT && emsg && emsg->type == JSON_STR)) {
        const char *msg = NULL;
        if (err && err->type == JSON_OBJ)
            msg = json_get_str(json_get(err, "message"));
        else if (emsg && emsg->type == JSON_STR)
            msg = json_get_str(emsg);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "STATE_ERROR",
                               "execute", false, false,
                               msg && msg[0]
                                   ? msg
                                   : "the telemetry rollup reported an error",
                               "telemetry_rollup");
        json_free(&body);
        return;
    }

    /* The rolled-up document is the `state` member; the dumpstate envelope
     * around it is a descriptor the caller already has from
     * `discover describe`, and projecting it would spend the byte budget. */
    const struct json_value *state = json_get(&body, "state");
    if (!state || state->type != JSON_OBJ) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BAD_STATE_BODY",
                               "serialize", false, false,
                               "the telemetry rollup body carried no state "
                               "object", "telemetry_rollup");
        json_free(&body);
        return;
    }
    zcl_native_bridge_project(request, state, reply);
    json_free(&body);
}

/* A next[] entry naming the command currently being served makes
 * push_next_array reject the whole reply, and the CLI reports the total loss
 * as RESPONSE_BUDGET_EXCEEDED over an empty document. Always check first. */
static void trc_suggest(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply, const char *path,
                        const char *reason)
{
    if (!request || !request->spec || !path)
        return;
    if (strcmp(path, request->spec->path) == 0)
        return;
    (void)zcl_command_reply_add_next(reply, path, "{}", reason);
}

void zcl_native_handle_ops_telemetry_summary(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    trc_dispatch(request, reply, "summary");
    trc_suggest(request, reply, "ops.telemetry.alerts.active",
                "every failing rule with what it means and what to do");
}

void zcl_native_handle_ops_telemetry_health(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    trc_dispatch(request, reply, "health");
    trc_suggest(request, reply, "ops.telemetry.summary",
                "the same fold, plus the named bottleneck and what to run");
}

void zcl_native_handle_ops_telemetry_alerts_active(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    trc_dispatch(request, reply, "alerts_active");
    trc_suggest(request, reply, "ops.telemetry.health",
                "which domains hold any alerts this page could not carry");
}
