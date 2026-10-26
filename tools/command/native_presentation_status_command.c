/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical node-fact status instrument for the native agent UI. */

#include "command/native_command.h"

#include "controllers/rpc_client.h"
#include "controllers/status_native_handlers.h"
#include "json/json.h"
#include "presentation/model.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NPS_LEAF "app.presentation.status"

static void nps_fail(struct zcl_command_reply *reply, const char *code,
                     const char *message)
{
    LOG_ERROR("native.presentation.status", "%s: %s", code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_FAILED, code, "observe", true, false, message,
        NPS_LEAF);
}

static const struct json_value *nps_object(const struct json_value *parent,
                                           const char *key)
{
    const struct json_value *value = parent ? json_get(parent, key) : NULL;
    return value && value->type == JSON_OBJ ? value : NULL;
}

static bool nps_bool(const struct json_value *object, const char *key,
                     bool fallback)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_BOOL ? json_get_bool(value) : fallback;
}

static int64_t nps_int(const struct json_value *object, const char *key,
                       int64_t fallback)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_INT ? json_get_int(value) : fallback;
}

static const char *nps_str(const struct json_value *object, const char *key)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static void nps_item(struct zcl_present_model_v1 *model, const char *id,
                     const char *label, const char *value, uint16_t status)
{
    if (model->item_count >= ZCL_PRESENT_MODEL_ITEMS_MAX) return;
    struct zcl_present_model_item_v1 *item =
        &model->items[model->item_count++];
    item->kind = ZCL_PRESENT_ITEM_KEY_VALUE;
    item->status = status;
    item->parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    (void)snprintf(item->id, sizeof(item->id), "%s", id);
    (void)snprintf(item->label, sizeof(item->label), "NODE FACT - %s", label);
    (void)snprintf(item->value, sizeof(item->value), "%s", value);
}

static void nps_add_chain_status_items(const struct json_value *status,
                                       struct zcl_present_model_v1 *model)
{
    char value[257];
    int64_t height = nps_int(status, "provable_tip", -1);
    bool published = nps_bool(status, "provable_tip_published", false);
    if (height >= 0)
        (void)snprintf(value, sizeof(value), "%lld", (long long)height);
    else
        (void)snprintf(value, sizeof(value), "unavailable");
    nps_item(model, "chain-height", "Chain height H*", value,
             published ? ZCL_PRESENT_STATUS_GREEN : ZCL_PRESENT_STATUS_YELLOW);

    bool gap_known = nps_bool(status, "sync_gap_known", false);
    int64_t gap = nps_int(status, "sync_gap", -1);
    if (gap_known)
        (void)snprintf(value, sizeof(value), "%lld blocks", (long long)gap);
    else
        (void)snprintf(value, sizeof(value), "unavailable");
    nps_item(model, "peer-gap", "Peer gap", value,
             !gap_known ? ZCL_PRESENT_STATUS_YELLOW :
             (gap == 0 ? ZCL_PRESENT_STATUS_GREEN : ZCL_PRESENT_STATUS_INFO));

    int64_t peers = nps_int(status, "peers", -1);
    if (peers >= 0)
        (void)snprintf(value, sizeof(value), "%lld", (long long)peers);
    else
        (void)snprintf(value, sizeof(value), "unavailable");
    nps_item(model, "peers", "Connected peers", value,
             peers < 0 ? ZCL_PRESENT_STATUS_YELLOW :
             (peers > 0 ? ZCL_PRESENT_STATUS_GREEN : ZCL_PRESENT_STATUS_RED));
}

static void nps_add_onion_service_item(const struct json_value *health,
                                       struct zcl_present_model_v1 *model)
{
    char value[257];
    const struct json_value *checks = nps_object(health, "checks");
    bool tor_enabled = nps_bool(checks, "tor_enabled", false);
    bool onion_ready = nps_bool(checks, "onion_service_ready", false);
    const char *onion = nps_str(checks, "onion_address");
    (void)snprintf(value, sizeof(value), "%s", !checks ? "unavailable" :
                   (onion_ready && onion && onion[0] ? onion :
                    (tor_enabled ? "enabled, not ready" : "disabled")));
    nps_item(model, "onion", "Onion service", value,
             !checks ? ZCL_PRESENT_STATUS_YELLOW :
             (onion_ready ? ZCL_PRESENT_STATUS_GREEN :
             (tor_enabled ? ZCL_PRESENT_STATUS_YELLOW :
                            ZCL_PRESENT_STATUS_NEUTRAL)));
}

static void nps_add_wallet_backup_item(const struct json_value *backup,
                                       struct zcl_present_model_v1 *model)
{
    char value[257];
    int64_t runs = nps_int(backup, "total_runs", -1);
    int64_t failures = nps_int(backup, "total_failures", -1);
    int64_t last_run = nps_int(backup, "last_run_unix", -1);
    const char *backup_error = nps_str(backup, "last_error");
    if (runs < 0)
        (void)snprintf(value, sizeof(value), "unavailable");
    else if (runs == 0)
        (void)snprintf(value, sizeof(value), "no completed backup");
    else
        (void)snprintf(value, sizeof(value),
                       "last=%lld runs=%lld failures=%lld",
                       (long long)last_run, (long long)runs,
                       (long long)failures);
    bool backup_green = runs > 0 && failures == 0 &&
                        (!backup_error || !backup_error[0]);
    nps_item(model, "wallet-backup", "Wallet backup", value,
             backup_green ? ZCL_PRESENT_STATUS_GREEN :
                            ZCL_PRESENT_STATUS_YELLOW);
}

static void nps_add_package_workers_item(const struct json_value *work,
                                         struct zcl_present_model_v1 *model)
{
    char value[257];
    bool work_known = work && work->type == JSON_OBJ;
    bool work_enabled = nps_bool(work, "enabled", false);
    int64_t capacity = nps_int(work, "worker_capacity", 0);
    int64_t active = nps_int(work, "worker_active", 0);
    int64_t available = nps_int(work, "worker_available", 0);
    if (!work_known)
        (void)snprintf(value, sizeof(value), "unavailable");
    else if (work_enabled)
        (void)snprintf(value, sizeof(value),
                       "%lld available / %lld total (%lld active)",
                       (long long)available, (long long)capacity,
                       (long long)active);
    else
        (void)snprintf(value, sizeof(value), "disabled (0 available)");
    nps_item(model, "package-workers", "Package workers", value,
             !work_known ? ZCL_PRESENT_STATUS_YELLOW :
             (work_enabled && available > 0 ? ZCL_PRESENT_STATUS_GREEN :
                                              ZCL_PRESENT_STATUS_NEUTRAL));
}

bool zcl_native_presentation_status_model_from_facts(
    const struct json_value *status, const struct json_value *health,
    const struct json_value *backup, const struct json_value *work,
    struct zcl_present_model_v1 *model, char *why, size_t why_cap)
{
    if (!status || status->type != JSON_OBJ || !model) {
        if (why && why_cap)
            (void)snprintf(why, why_cap, "canonical status facts are missing");
        return false;
    }
    zcl_present_model_init_v1(model, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(model->request_id, sizeof(model->request_id),
                   "node-status");
    (void)snprintf(model->title, sizeof(model->title), "Node status");
    (void)snprintf(model->summary, sizeof(model->summary),
                   "Canonical node facts captured now; peer height is an untrusted availability hint.");

    nps_add_chain_status_items(status, model);
    nps_add_onion_service_item(health, model);
    nps_add_wallet_backup_item(backup, model);
    nps_add_package_workers_item(work, model);

    return zcl_present_model_validate_v1(model, why, why_cap);
}

static bool nps_parse_body(char *raw, struct json_value *out)
{
    json_init(out);
    bool ok = raw && json_read(out, raw, strlen(raw)) && out->type == JSON_OBJ;
    free(raw);
    if (!ok) json_free(out);
    return ok;
}

bool zcl_native_presentation_dumpstate(const char *name, const char *key,
                                       struct json_value *out)
{
    char params[192];
    int n = key && key[0]
        ? snprintf(params, sizeof(params), "[\"%s\",\"%s\"]", name, key)
        : snprintf(params, sizeof(params), "[\"%s\"]", name);
    if (n <= 0 || (size_t)n >= sizeof(params)) return false;
    struct json_value envelope;
    if (!nps_parse_body(node_rpc_call("dumpstate", params), &envelope))
        return false;
    const struct json_value *state = nps_object(&envelope, "state");
    if (!state) {
        json_free(&envelope);
        return false;
    }
    json_init(out);
    json_copy(out, state);
    json_free(&envelope);
    return true;
}

void zcl_native_handle_presentation_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zcl_native_bridge_ensure_rpc();
    struct zcl_native_body_err body_error = {0};
    struct json_value status, health, backup, work;
    char *status_raw = zcl_native_status_body(NULL, &body_error);
    if (!nps_parse_body(status_raw, &status)) {
        nps_fail(reply, "NODE_STATUS_UNAVAILABLE",
                 body_error.message[0] ? body_error.message :
                 "canonical node status is unavailable");
        return;
    }
    bool have_health = nps_parse_body(
        node_rpc_call("healthcheck", "[{\"mode\":\"full\"}]"), &health);
    bool have_backup = zcl_native_presentation_dumpstate(
        "wallet_backup", NULL, &backup);
    bool have_work = zcl_native_presentation_dumpstate(
        "zcode_work", NULL, &work);

    struct zcl_present_model_v1 model;
    char why[192];
    bool built = zcl_native_presentation_status_model_from_facts(
        &status, have_health ? &health : NULL,
        have_backup ? &backup : NULL, have_work ? &work : NULL,
        &model, why, sizeof(why));
    json_free(&status);
    if (have_health) json_free(&health);
    if (have_backup) json_free(&backup);
    if (have_work) json_free(&work);
    if (!built) {
        nps_fail(reply, "STATUS_MODEL_INVALID", why);
        return;
    }
    zcl_native_present_model(&model, NPS_LEAF, request->input, reply);
    if (reply->status == ZCL_COMMAND_STATUS_PASSED) {
        (void)json_push_kv_str(&reply->data, "fact_authority", "target_node");
        (void)json_push_kv_str(&reply->data, "claim_class", "NODE_FACT");
    }
}
