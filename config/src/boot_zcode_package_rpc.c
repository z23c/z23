/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Route package pin plan/commit through the resident store owner. */

#include "config/boot_zcode_dht.h"

#include "command/native_command.h"
#include "base/hex.h"
#include "json/json.h"
#include "rpc/server.h"
#include "vcs/package_swarm_node.h"

#include <string.h>

static const struct json_value *package_rpc_input(
    const struct json_value *params)
{
    const struct json_value *first =
        params && json_size(params) ? json_at(params, 0) : NULL;
    return first && first->type == JSON_OBJ ? first : NULL;
}

/* Recovery includes orphan GC, so one-shot clients must not open the live
 * files behind the daemon's in-memory CAS view. Execute pin work here. */
static bool package_pin_rpc(const struct json_value *params, bool help,
                            struct json_value *result, bool pinned)
{
    if (help) {
        json_set_str(result,
                     pinned ? "zcode_package_pin {root,mode,plan_token?}"
                            : "zcode_package_unpin {root,mode,plan_token?}");
        return true;
    }
    const struct json_value *input = package_rpc_input(params);
    if (!input || json_get(input, "datadir")) {
        json_set_object(result);
        json_push_kv_bool(result, "ok", false);
        json_push_kv_str(result, "code", "INVALID_INPUT");
        json_push_kv_str(result, "phase", "validate");
        json_push_kv_str(result, "message",
                         "one input object without datadir is required");
        return true;
    }

    struct zcl_command_request request = { .input = input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.zcode_package_pin.v1");
    if (pinned)
        zcl_native_handle_zcode_package_pin(&request, &reply);
    else
        zcl_native_handle_zcode_package_unpin(&request, &reply);

    bool passed = reply.status == ZCL_COMMAND_STATUS_PASSED &&
                  reply.exit_code == ZCL_COMMAND_EXIT_OK;
    json_set_object(result);
    json_push_kv_bool(result, "ok", passed);
    if (passed) {
        json_push_kv(result, "data", &reply.data);
    } else {
        json_push_kv_str(result, "code", reply.error.code[0]
                                            ? reply.error.code
                                            : "PIN_REFUSED");
        json_push_kv_str(result, "phase", reply.error.phase[0]
                                             ? reply.error.phase
                                             : "execute");
        json_push_kv_str(result, "message", reply.error.message[0]
                                               ? reply.error.message
                                               : "resident pin failed");
        json_push_kv_bool(result, "retryable", reply.error.retryable);
        json_push_kv_bool(result, "mutated", reply.error.mutated);
    }
    zcl_command_reply_free(&reply);
    return true;
}

static bool package_pin(const struct json_value *params, bool help,
                        struct json_value *result)
{
    return package_pin_rpc(params, help, result, true);
}

static bool package_unpin(const struct json_value *params, bool help,
                          struct json_value *result)
{
    return package_pin_rpc(params, help, result, false);
}

/* The fastobj carrier export writes the store, and a serving engine
 * answers from its in-memory table: an export executed outside the
 * resident would leave the daemon announcing-by-record a root it refuses
 * as not-tracked until restart. The export executes here, on the same
 * store object the engine borrows. */
static bool package_fastobj_export(const struct json_value *params,
                                   bool help, struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "zcode_package_fastobj_export {cache_dir}");
        return true;
    }
    const struct json_value *input = package_rpc_input(params);
    if (!input || json_get(input, "datadir")) {
        json_set_object(result);
        json_push_kv_bool(result, "ok", false);
        json_push_kv_str(result, "code", "INVALID_INPUT");
        json_push_kv_str(result, "phase", "validate");
        json_push_kv_str(result, "message",
                         "one input object without datadir is required "
                         "(cache_dir; the resident datadir is implicit)");
        return true;
    }

    struct zcl_command_request request = { .input = input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.zcode_package_fastobj_export.v1");
    zcl_native_handle_zcode_package_fastobj_export(&request, &reply);

    bool passed = reply.status == ZCL_COMMAND_STATUS_PASSED &&
                  reply.exit_code == ZCL_COMMAND_EXIT_OK;
    json_set_object(result);
    json_push_kv_bool(result, "ok", passed);
    if (passed) {
        json_push_kv(result, "data", &reply.data);
    } else {
        json_push_kv_str(result, "code", reply.error.code[0]
                                            ? reply.error.code
                                            : "EXPORT_REFUSED");
        json_push_kv_str(result, "phase", reply.error.phase[0]
                                             ? reply.error.phase
                                             : "execute");
        json_push_kv_str(result, "message", reply.error.message[0]
                                               ? reply.error.message
                                               : "resident export failed");
        json_push_kv_bool(result, "retryable", reply.error.retryable);
        json_push_kv_bool(result, "mutated", reply.error.mutated);
    }
    zcl_command_reply_free(&reply);
    return true;
}

/* Read-only exact-root observation for native instruments.  This reuses the
 * resident store and swarm engine; it neither starts a fetch nor opens the
 * live store from a second process. */
static bool package_status(const struct json_value *params, bool help,
                           struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "zcode_package_status {package_root,transport_root}");
        return true;
    }
    const struct json_value *input = package_rpc_input(params);
    const char *package_hex = input
        ? json_get_str(json_get(input, "package_root")) : NULL;
    const char *transport_hex = input
        ? json_get_str(json_get(input, "transport_root")) : NULL;
    uint8_t package_root[32], transport_root[32];
    if (!package_hex || !transport_hex || strlen(package_hex) != 64u ||
        strlen(transport_hex) != 64u ||
        !zcl_hex_decode_lower(package_hex, package_root, sizeof(package_root)) ||
        !zcl_hex_decode_lower(transport_hex, transport_root,
                              sizeof(transport_root))) {
        json_set_object(result);
        json_push_kv_bool(result, "ok", false);
        json_push_kv_str(result, "code", "INVALID_ROOTS");
        json_push_kv_str(result, "message",
                         "package_root and transport_root must be canonical 64-hex roots");
        return true;
    }

    struct vcs_swarm_engine *engine = vcs_swarm_engine_global();
    struct vcs_swarm_download_status download = {0};
    bool download_found = engine && vcs_swarm_engine_download_status(
                                        engine, transport_root, &download);

    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "schema", "zcl.package_download_observation.v1");
    json_push_kv_str(result, "package_root", package_hex);
    json_push_kv_str(result, "transport_root", transport_hex);
    json_push_kv_bool(result, "swarm_enabled", engine != NULL);
    json_push_kv_bool(result, "download_found", download_found);
    if (download_found)
        boot_zcode_package_download_render(result, &download);
    return true;
}

void boot_zcode_package_register_rpc(struct rpc_table *table)
{
    const struct rpc_command commands[] = {
        { "zcode", "zcode_package_pin", package_pin, true },
        { "zcode", "zcode_package_unpin", package_unpin, true },
        { "zcode", "zcode_package_fastobj_export", package_fastobj_export, true },
        { "zcode", "zcode_package_status", package_status, true },
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
        rpc_table_must_append(table, &commands[i]);
}
