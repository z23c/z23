/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: plugin.dev - the developer loop for one plugin in one command:
 *          create the developer key if missing, pack <dir>, list the key as a
 *          publisher key, install the new generation and make it current, by
 *          calling the plugin module directly. A running plugin.run takes the
 *          new generation up on SIGHUP. A failed step leaves the current
 *          generation active and is named in the refusal. The daemon is not
 *          contacted. */

#include "command/native_command.h"
#include "native_plugin_common.h"

#include "json/json.h"
#include "plugin/plugin_dev.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

static void pdv_refuse(struct zcl_command_reply *reply, enum plugin_status st,
                       const struct plugin_dev_result *res)
{
    char message[192], evidence[256];
    (void)snprintf(message, sizeof(message), "plugin dev failed at step %s: %s",
                   plugin_dev_step_name(res->failed), plugin_status_code(st));
    (void)snprintf(evidence, sizeof(evidence),
                   "step %s failed after %u of %d steps; the current generation is unchanged",
                   plugin_dev_step_name(res->failed), res->steps_done,
                   PLUGIN_DEV_STEP_COUNT);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           st == PLUGIN_ERR_IO ? ZCL_COMMAND_EXIT_FAILED
                                               : ZCL_COMMAND_EXIT_INVALID,
                           plugin_status_code(st), "dev", false,
                           res->steps_done > 0, message, evidence);
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "%s", plugin_status_next_action(st));
    reply->error.human_action_required = true;
}

static const char *pdv_detail(enum plugin_dev_step step,
                              const struct plugin_dev_result *res)
{
    switch (step) {
    case PLUGIN_DEV_STEP_KEY:
        return res->key_created ? "created" : "exists";
    case PLUGIN_DEV_STEP_PUBLISHER:
        return res->publisher_added ? "added" : "already_listed";
    case PLUGIN_DEV_STEP_INSTALL:
        return res->already_present ? "already_present" : "installed";
    case PLUGIN_DEV_STEP_PACK:
    case PLUGIN_DEV_STEP_SWITCH:
    default:
        return "ok";
    }
}

static bool pdv_push_steps(struct json_value *data, const struct plugin_dev_result *res)
{
    struct json_value steps;
    json_init(&steps);
    json_set_array(&steps);
    for (unsigned i = 0; i < res->steps_done; i++) {
        struct json_value s;
        json_init(&s);
        json_set_object(&s);
        bool ok = json_push_kv_str(&s, "step", plugin_dev_step_name((enum plugin_dev_step)i)) &&
                  json_push_kv_str(&s, "result", pdv_detail((enum plugin_dev_step)i, res)) &&
                  json_push_back(&steps, &s);
        json_free(&s);
        if (!ok) {
            json_free(&steps);
            return false;
        }
    }
    bool pushed = json_push_kv(data, "steps", &steps);
    json_free(&steps);
    return pushed;
}

static bool pdv_reply(struct zcl_command_reply *reply, const struct plugin_dev_result *res)
{
    json_set_object(&reply->data);
    bool ok = json_push_kv_str(&reply->data, "schema", "zcl.plugin_dev.v1") &&
              json_push_kv_str(&reply->data, "name", res->name) &&
              json_push_kv_str(&reply->data, "generation", res->generation) &&
              json_push_kv_int(&reply->data, "sequence", (int64_t)res->sequence) &&
              json_push_kv_bool(&reply->data, "current", true) &&
              json_push_kv_str(&reply->data, "public_key", res->public_key) &&
              json_push_kv_str(&reply->data, "key_file", res->key_path) &&
              json_push_kv_str(&reply->data, "manifest", res->manifest_path) &&
              json_push_kv_str(&reply->data, "reload", "send SIGHUP to a running plugin run to take it up") &&
              pdv_push_steps(&reply->data, res);
    return ok;
}

void zcl_native_handle_plugin_dev(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    char root[PATH_MAX];
    struct plugin_dev_request dev = {0};
    struct plugin_dev_result res;
    if (!request || !reply)
        return;
    memset(&res, 0, sizeof(res));
    if (!zcl_native_plugin_root(root, sizeof(root)) || !plg_str(request, "dir") ||
        !plg_interface(request, &dev.interface_version) ||
        !plg_capabilities(request, &dev.capabilities)) {
        pdv_refuse(reply, PLUGIN_ERR_ARGUMENT, &res);
        return;
    }
    dev.root = root;
    dev.dir = plg_str(request, "dir");
    dev.name = plg_str(request, "name");
    dev.version = plg_str(request, "version");
    dev.key_path = plg_str(request, "key");
    enum plugin_status st = plugin_dev(&dev, &res);
    if (st != PLUGIN_OK) {
        pdv_refuse(reply, st, &res);
        return;
    }
    reply->error.mutated = true;
    if (!pdv_reply(reply, &res))
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                               "PLUGIN_IO", "dev", false, true,
                               "plugin dev built the generation but could not write the reply",
                               res.generation);
}
