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

#include "command/lab_priv.h"
#include "json/json.h"
#include "plugin/plugin_dev.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

/* An argument refusal ran no step, so it names none; a step failure names its step. */
static void pdv_describe(const struct plugin_dev_result *res, enum plugin_status st,
                         char *message, size_t message_cap,
                         char *evidence, size_t evidence_cap)
{
    if (res->failed >= PLUGIN_DEV_STEP_COUNT) {
        (void)snprintf(message, message_cap, "plugin dev refused: %s", plugin_status_code(st));
        (void)snprintf(evidence, evidence_cap,
                       "refused before any step ran; nothing was written and the current generation is unchanged");
        return;
    }
    (void)snprintf(message, message_cap, "plugin dev failed at step %s: %s",
                   plugin_dev_step_name(res->failed), plugin_status_code(st));
    (void)snprintf(evidence, evidence_cap,
                   "step %s failed after %u of %d steps; the current generation is unchanged",
                   plugin_dev_step_name(res->failed), res->steps_done,
                   PLUGIN_DEV_STEP_COUNT);
}

static void pdv_refuse(struct zcl_command_reply *reply, enum plugin_status st,
                       const struct plugin_dev_result *res)
{
    char message[192], evidence[256];
    pdv_describe(res, st, message, sizeof(message), evidence, sizeof(evidence));
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

static void pdv_gate_refuse(struct zcl_command_reply *reply, const char *code,
                            const char *message, const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                           code, "cases", false, false, message, evidence);
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action), "%s",
                   "fix the program or the cases and run plugin dev again; "
                   "nothing was written and the current generation is unchanged");
}

/* The leaf of dir, as plugin_dev names the executable when name is absent. */
static bool pdv_exe_path(const struct plugin_dev_request *dev, char *out, size_t cap)
{
    const char *name = dev->name;
    char leaf[PATH_MAX];
    if (!name) {
        size_t end = strlen(dev->dir), start;
        while (end > 1 && dev->dir[end - 1] == '/')
            end--;
        for (start = end; start > 0 && dev->dir[start - 1] != '/'; start--) { }
        if (end == start || end - start >= sizeof(leaf))
            return false;
        memcpy(leaf, dev->dir + start, end - start);
        leaf[end - start] = '\0';
        name = leaf;
    }
    return snprintf(out, cap, "%s/%s", dev->dir, name) < (int)cap;
}

/* Run the optional cases against dir/NAME under the confinement plugin.call
 * uses, through the lab's case runner. False means the reply carries the
 * refusal and no key, pack, publish, install or switch step has run. */
static bool pdv_cases_pass(const struct zcl_command_request *request,
                           const struct plugin_dev_request *dev,
                           struct zcl_command_reply *reply)
{
    struct lab_ctx ctx;
    struct lab_case_fail fail = { { 0 }, { 0 } };
    char exe[PATH_MAX], message[256], evidence[LAB_FAIL_DIFF + 8];
    size_t passed = 0, failed = 0;
    if (!request->input || !json_get(request->input, "cases"))
        return true;
    memset(&ctx, 0, sizeof(ctx));
    if (!pdv_exe_path(dev, exe, sizeof(exe)) || lab_dirs_open(&ctx.dirs) != LAB_OK) {
        pdv_gate_refuse(reply, "PLUGIN_DEV_CASES_UNAVAILABLE",
                        "the cases could not be run: the executable path or lab state is unusable", "");
        return false;
    }
    enum lab_check c = lab_cases_check(request, &ctx, exe, LAB_TIMEOUT_DEFAULT_MS,
                                       LAB_MEM_DEFAULT_MB, &passed, &failed, &fail);
    if (c == LAB_CHECK_NO_CASES)
        pdv_gate_refuse(reply, "PLUGIN_DEV_BAD_CASES",
                        "cases is a JSON array of 1..256 objects with name, and optional "
                        "stdin, args, expect_stdout, expect_exit (0..255)", "");
    else if (c != LAB_CHECK_RAN)
        pdv_gate_refuse(reply, "PLUGIN_DEV_CASES_UNAVAILABLE",
                        c == LAB_CHECK_UNCONFINED
                            ? "the cases could not run: confinement is unavailable on this host"
                            : "the cases could not run: allocation failed", "");
    else if (failed > 0) {
        (void)snprintf(message, sizeof(message), "case \"%s\" failed (%zu of %zu cases failed)",
                       fail.name, failed, passed + failed);
        (void)snprintf(evidence, sizeof(evidence), "%s: %s", fail.name, fail.diff);
        pdv_gate_refuse(reply, "PLUGIN_DEV_CASES_FAILED", message, evidence);
    }
    return c == LAB_CHECK_RAN && failed == 0;
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
    res.failed = PLUGIN_DEV_STEP_COUNT; /* refused before any step ran */
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
    if (!pdv_cases_pass(request, &dev, reply))
        return;
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
