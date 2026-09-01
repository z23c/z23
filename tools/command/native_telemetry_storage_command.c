/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `ops.telemetry.storage.*` — the CLI half of the storage telemetry domain.
 *
 * These handlers are deliberately almost empty, and that is the design. All
 * four leaves are SCOPE_NODE: the values live in a RUNNING node's process, and
 * a native CLI invocation is a separate one-shot process with no app_init()
 * (see zcl_native_bridge_ensure_rpc). So a handler here cannot call
 * telemetry_render() against a local snapshot — every subsystem it would read
 * is uninitialized in this process, and the reply would be a page of plausible
 * zeroes describing nothing.
 *
 * The snapshot is therefore filled and rendered INSIDE the node, by
 * engine/services/src/storage_telemetry_fill.c, and reached through the same
 * SELECT-only `dumpstate` RPC that `ops.state` uses, pinned to the
 * `storage_telemetry` subsystem. One round trip per call.
 *
 * What a handler here owns is exactly two decisions — which VIEW, and which
 * GROUP — encoded as the dumpstate key the renderer parses
 * (telemetry_view_parse). It names no field, reads no global, and decides no
 * health; the view/group token is the entire per-leaf difference between them.
 *
 * There is no budget logic here on purpose. zcl_native_bridge_project() is the
 * shared projector every node-state leaf already goes through: it measures
 * each top-level section before committing it and reports `_page.truncated`
 * with a cursor when the contract budget is reached. A second copy of that
 * logic in six domain controllers is precisely what the telemetry work exists
 * to delete.
 */

#include "command/native_command.h"

#include "controllers/rpc_client.h"
#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* dumpstate params for the storage telemetry subsystem at one view/group.
 * `key` is a fixed token from the table below — never caller text — so it is
 * spliced into the array literal rather than round-tripped through a JSON
 * builder. */
static void ts_dispatch(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply, const char *key,
                        const char *sibling, const char *sibling_reason)
{
    if (!request || !reply)
        return;

    char params[96];
    int n = snprintf(params, sizeof params,
                     "[\"storage_telemetry\",\"%s\"]", key);
    if (n <= 0 || (size_t)n >= sizeof params) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED",
                               "normalize", false, false,
                               "could not encode the telemetry view key",
                               "storage_telemetry");
        return;
    }

    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call("dumpstate", params);
    if (!raw) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE",
                               "dispatch", true, false,
                               "the node did not return a storage telemetry "
                               "body", "storage_telemetry");
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
                               "storage telemetry returned a non-object body",
                               "storage_telemetry");
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
                               msg && msg[0] ? msg
                                             : "storage telemetry reported an "
                                               "error",
                               "storage_telemetry");
        json_free(&body);
        return;
    }

    /* The rendered telemetry document is the `state` member; the envelope
     * around it (subsystem/description/captured_at) is dumpstate's, and
     * projecting it would spend the byte budget on a descriptor the caller
     * already has from `discover describe`. */
    const struct json_value *state = json_get(&body, "state");
    if (!state || state->type != JSON_OBJ) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BAD_STATE_BODY",
                               "serialize", false, false,
                               "storage telemetry body carried no state object",
                               "storage_telemetry");
        json_free(&body);
        return;
    }
    zcl_native_bridge_project(request, state, reply);

    /* One sibling suggestion, and NEVER this leaf: a next[] entry naming the
     * command currently being served makes push_next_array reject the whole
     * reply, and the CLI reports the total loss as RESPONSE_BUDGET_EXCEEDED
     * over an empty document. */
    if (sibling && request->spec &&
        strcmp(sibling, request->spec->path) != 0)
        (void)zcl_command_reply_add_next(reply, sibling, "{}", sibling_reason);

    json_free(&body);
}

void zcl_native_handle_telemetry_storage_summary(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    /* The leaf IS the summary view, so that is the default; --view=full
     * escalates the telemetry tier for a reader who wants every leaf rather
     * than the decisive ones. This only ever WIDENS what is rendered —
     * nothing here steps a view down to make a document fit. */
    const char *v = request && request->view ? request->view : "";
    const char *key = strcmp(v, "full") == 0 ? "full" : "summary";
    ts_dispatch(request, reply, key, "ops.telemetry.storage.disk",
                "read disk headroom and the maintenance worker in full");
}

void zcl_native_handle_telemetry_storage_database(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    ts_dispatch(request, reply, "database", "ops.telemetry.storage.summary",
                "roll the whole storage domain up to one health state");
}

void zcl_native_handle_telemetry_storage_disk(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    ts_dispatch(request, reply, "disk", "ops.telemetry.storage.summary",
                "roll the whole storage domain up to one health state");
}
