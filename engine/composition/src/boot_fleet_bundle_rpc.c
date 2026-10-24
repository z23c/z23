/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Run `fleet bundle offer` / `fleet bundle fetch` steps on the
 *          resident package store and swarm engine. The store and engine
 *          live only in the node, so the one-shot CLI forwards each step
 *          here (tools/command/native_fleet_bundle_command.c). */

#include "config/boot_zcode_dht.h"

#include "command/native_command.h"
#include "json/json.h"
#include "net/tor_integration.h"
#include "rpc/server.h"
#include "vcs/package_store.h"

#include <string.h>

static void bundle_rpc_refuse(struct json_value *result, const char *code,
                              const char *message)
{
    json_set_object(result);
    json_push_kv_bool(result, "ok", false);
    json_push_kv_str(result, "code", code);
    json_push_kv_str(result, "phase", "validate");
    json_push_kv_str(result, "message", message);
}

/* Shared body: one input object (no datadir; the resident owns the store),
 * the resident store must exist, then run `handler` and wrap its reply. */
static bool bundle_rpc_run(
    const struct json_value *params, struct json_value *result,
    const char *schema,
    void (*handler)(const struct zcl_command_request *,
                    struct zcl_command_reply *),
    bool add_onion)
{
    const struct json_value *input =
        params && json_size(params) ? json_at(params, 0) : NULL;
    if (!input || input->type != JSON_OBJ || json_get(input, "datadir")) {
        bundle_rpc_refuse(result, "INVALID_INPUT",
                          "one input object without datadir is required");
        return true;
    }
    if (!vcs_package_store_global()) {
        bundle_rpc_refuse(result, "HOSTING_DISABLED",
                          "package hosting is disabled on this node "
                          "(start it with -packagehost=1)");
        return true;
    }
    struct zcl_command_request request = { .input = input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, schema);
    handler(&request, &reply);

    bool passed = reply.status == ZCL_COMMAND_STATUS_PASSED &&
                  reply.exit_code == ZCL_COMMAND_EXIT_OK;
    json_set_object(result);
    json_push_kv_bool(result, "ok", passed);
    if (passed) {
        if (add_onion) {
            const char *onion = tor_integration_get_onion_address();
            if (onion && onion[0])
                json_push_kv_str(&reply.data, "onion", onion);
        }
        json_push_kv(result, "data", &reply.data);
    } else {
        json_push_kv_str(result, "code", reply.error.code);
        json_push_kv_str(result, "phase", reply.error.phase);
        json_push_kv_str(result, "message", reply.error.message);
        json_push_kv_bool(result, "retryable", reply.error.retryable);
        json_push_kv_bool(result, "mutated", reply.error.mutated);
    }
    zcl_command_reply_free(&reply);
    return true;
}

static bool bundle_offer(const struct json_value *params, bool help,
                         struct json_value *result)
{
    if (help) {
        json_set_str(result, "fleet_bundle_offer {file}");
        return true;
    }
    return bundle_rpc_run(params, result, "zcl.fleet_bundle_offer.v1",
                          zcl_native_handle_fleet_bundle_offer, true);
}

static bool bundle_fetch(const struct json_value *params, bool help,
                         struct json_value *result)
{
    if (help) {
        json_set_str(result, "fleet_bundle_fetch {root,sha256,size,out}");
        return true;
    }
    return bundle_rpc_run(params, result, "zcl.fleet_bundle_fetch.v1",
                          zcl_native_handle_fleet_bundle_fetch, false);
}

void boot_fleet_bundle_register_rpc(struct rpc_table *table)
{
    const struct rpc_command commands[] = {
        { "fleet", "fleet_bundle_offer", bundle_offer, true },
        { "fleet", "fleet_bundle_fetch", bundle_fetch, true },
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
        rpc_table_must_append(table, &commands[i]);
}
