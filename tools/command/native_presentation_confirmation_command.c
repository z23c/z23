/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: exact, inert native confirmation for one local package plan. */

#include "command/native_command.h"

#include "base/hex.h"
#include "json/json.h"
#include "presentation/model.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

#define NPCF_LEAF "app.presentation.publication-confirm"

static const struct json_value *npcf_object(
    const struct json_value *object, const char *key)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_OBJ ? value : NULL;
}

static const char *npcf_str(const struct json_value *object, const char *key)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool npcf_bool(const struct json_value *object, const char *key)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_BOOL && json_get_bool(value);
}

static bool npcf_int(const struct json_value *object, const char *key,
                     int64_t *out)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    if (!value || value->type != JSON_INT || !out) return false;
    *out = json_get_int(value);
    return *out >= 0;
}

static bool npcf_root(const char *root)
{
    uint8_t decoded[32];
    return root && zcl_hex_decode_lower(root, decoded, sizeof(decoded));
}

static bool npcf_plan_not_ready(const struct json_value *plan,
                                const struct json_value *package)
{
    return !plan || plan->type != JSON_OBJ || !npcf_bool(plan, "valid") ||
           !npcf_bool(plan, "ready_to_commit") ||
           !npcf_bool(package, "chunks_checked");
}

static bool npcf_plan_fields_missing(const char *token,
                                     const char *package_root,
                                     const char *name, const char *semver,
                                     const char *license)
{
    return !npcf_root(token) || !npcf_root(package_root) || !name ||
           !name[0] || !semver || !semver[0] || !license || !license[0];
}

static bool npcf_plan_counts_missing(const struct json_value *package,
                                     int64_t *files, int64_t *bytes,
                                     int64_t *chunks)
{
    return !npcf_int(package, "files", files) ||
           !npcf_int(package, "bytes", bytes) ||
           !npcf_int(package, "chunks", chunks);
}

static void npcf_item(struct zcl_present_model_v1 *model, const char *id,
                      const char *label, const char *value,
                      uint16_t status)
{
    struct zcl_present_model_item_v1 *item =
        &model->items[model->item_count++];
    item->kind = ZCL_PRESENT_ITEM_KEY_VALUE;
    item->status = status;
    item->parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    item->flags = ZCL_PRESENT_ITEM_READ_ONLY;
    (void)snprintf(item->id, sizeof(item->id), "%s", id);
    (void)snprintf(item->label, sizeof(item->label), "%s", label);
    (void)snprintf(item->value, sizeof(item->value), "%s", value);
}

static void npcf_action(struct zcl_present_model_action_v1 *action,
                        uint16_t kind, const char *id, const char *label)
{
    action->kind = kind;
    (void)snprintf(action->id, sizeof(action->id), "%s", id);
    (void)snprintf(action->label, sizeof(action->label), "%s", label);
}

bool zcl_native_presentation_publication_confirm_model_from_plan(
    const struct json_value *plan, struct zcl_present_model_v1 *model,
    char *why, size_t why_cap)
{
    const struct json_value *release = npcf_object(plan, "release");
    const struct json_value *package = npcf_object(plan, "package");
    const char *token = npcf_str(plan, "plan_token");
    const char *name = npcf_str(release, "name");
    const char *semver = npcf_str(release, "semver");
    const char *license = npcf_str(release, "license");
    const char *package_root = npcf_str(package, "package_root");
    int64_t files = 0, bytes = 0, chunks = 0;
    if (npcf_plan_not_ready(plan, package) ||
        npcf_plan_fields_missing(token, package_root, name, semver,
                                 license) ||
        npcf_plan_counts_missing(package, &files, &bytes, &chunks)) {
        (void)snprintf(why, why_cap,
                       "exact package publication plan is not ready");
        return false;
    }

    zcl_present_model_init_v1(model, ZCL_PRESENT_MODEL_CONFIRMATION);
    (void)snprintf(model->request_id, sizeof(model->request_id),
                   "publish-%.12s", token);
    (void)snprintf(model->title, sizeof(model->title),
                   "Commit this exact package locally?");
    (void)snprintf(model->summary, sizeof(model->summary),
                   "HUMAN DECISION - confirm only plan %.12s...; this window performs no write or network publication.",
                   token);
    (void)snprintf(model->exact_root, sizeof(model->exact_root), "%s",
                   token);
    npcf_item(model, "effect", "LOCAL OBSERVATION - Effect",
              "Admit exact package bytes to this node's local ZCODE store",
              ZCL_PRESENT_STATUS_YELLOW);
    npcf_item(model, "package", "LOCAL OBSERVATION - Package", name,
              ZCL_PRESENT_STATUS_INFO);
    npcf_item(model, "version", "LOCAL OBSERVATION - Version", semver,
              ZCL_PRESENT_STATUS_INFO);
    npcf_item(model, "license", "LOCAL OBSERVATION - License", license,
              ZCL_PRESENT_STATUS_INFO);
    npcf_item(model, "package-root", "LOCAL OBSERVATION - Package root",
              package_root, ZCL_PRESENT_STATUS_INFO);
    char counts[128];
    (void)snprintf(counts, sizeof(counts),
                   "%lld files, %lld bytes, %lld verified chunks",
                   (long long)files, (long long)bytes, (long long)chunks);
    npcf_item(model, "content", "LOCAL OBSERVATION - Exact content",
              counts, ZCL_PRESENT_STATUS_GREEN);
    npcf_item(model, "recheck", "LOCAL OBSERVATION - Commit boundary",
              "Separate commit rechecks bytes, current policy, and identity",
              ZCL_PRESENT_STATUS_GREEN);
    npcf_item(model, "confirmation-stage", "EVIDENCE STAGE - Human confirmation",
              "Pending this exact decision", ZCL_PRESENT_STATUS_YELLOW);
    npcf_item(model, "local-commit-stage", "EVIDENCE STAGE - Local commit",
              "Not started - separate commit required",
              ZCL_PRESENT_STATUS_NEUTRAL);
    npcf_item(model, "pointer-stage", "EVIDENCE STAGE - Pointer announcement",
              "Not observed", ZCL_PRESENT_STATUS_NEUTRAL);
    npcf_item(model, "provider-stage", "EVIDENCE STAGE - Provider announcement",
              "Not observed", ZCL_PRESENT_STATUS_NEUTRAL);
    npcf_item(model, "discovery-stage", "EVIDENCE STAGE - Peer discovery",
              "Not observed", ZCL_PRESENT_STATUS_NEUTRAL);
    npcf_item(model, "fetch-stage", "EVIDENCE STAGE - Exact peer fetch",
              "Not observed", ZCL_PRESENT_STATUS_NEUTRAL);
    model->action_count = 2;
    /* The native action row focuses index zero. Keep the harmless decision
     * there so an accidental Enter can never confirm publication intent. */
    npcf_action(&model->actions[0], ZCL_PRESENT_ACTION_CANCEL,
                "cancel", "Cancel - make no change");
    npcf_action(&model->actions[1], ZCL_PRESENT_ACTION_CONFIRM,
                "confirm", "Confirm exact local commit");
    return zcl_present_model_validate_v1(model, why, why_cap);
}

static void npcf_fail(struct zcl_command_reply *reply, const char *code,
                      const char *message, const char *evidence)
{
    LOG_ERROR("native.presentation.confirmation", "%s: %s", code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_INVALID, code, "confirm", false, false, message,
        evidence ? evidence : NPCF_LEAF);
}

void zcl_native_handle_presentation_publication_confirm(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct zcl_command_reply plan;
    zcl_command_reply_init(&plan, "zcl.zcode_publish_plan.v1");
    zcl_native_handle_zcode_package_publish_plan(request, &plan);
    if (plan.exit_code != ZCL_COMMAND_EXIT_OK) {
        char code[72], message[192], evidence[256];
        (void)snprintf(code, sizeof(code), "%s", plan.error.code[0]
                       ? plan.error.code : "PUBLICATION_PLAN_FAILED");
        (void)snprintf(message, sizeof(message), "%s", plan.error.message[0]
                       ? plan.error.message :
                         "exact package publication plan was refused");
        (void)snprintf(evidence, sizeof(evidence), "%s",
                       plan.error.evidence);
        zcl_command_reply_free(&plan);
        npcf_fail(reply, code, message, evidence);
        return;
    }
    struct zcl_present_model_v1 model;
    char why[192];
    bool built = zcl_native_presentation_publication_confirm_model_from_plan(
        &plan.data, &model, why, sizeof(why));
    char plan_identity[65] = {0};
    const char *token = npcf_str(&plan.data, "plan_token");
    if (token)
        (void)snprintf(plan_identity, sizeof(plan_identity), "%s", token);
    zcl_command_reply_free(&plan);
    if (!built) {
        npcf_fail(reply, "PUBLICATION_PLAN_NOT_READY", why,
                  "run zcode package publish plan and fix its first refusal");
        return;
    }

    zcl_native_present_model(&model, NPCF_LEAF, request->input, reply);
    if (reply->status != ZCL_COMMAND_STATUS_PASSED) return;
    const char *action = npcf_str(&reply->data, "action_id");
    bool decision_observed = action &&
        (strcmp(action, "confirm") == 0 || strcmp(action, "cancel") == 0);
    bool confirmed = action && strcmp(action, "confirm") == 0;
    if (decision_observed)
        (void)json_push_kv_str(&reply->data, "human_decision",
                              confirmed ? "CONFIRM" : "CANCEL");
    (void)json_push_kv_str(&reply->data, "plan_identity", plan_identity);
    (void)json_push_kv_str(&reply->data, "view_identity", model.request_id);
    (void)json_push_kv_bool(&reply->data, "human_confirmation_observed",
                           decision_observed);
    (void)json_push_kv_bool(&reply->data, "human_confirmed", confirmed);
    (void)json_push_kv_bool(&reply->data, "local_commit_complete", false);
    (void)json_push_kv_bool(&reply->data,
                           "pointer_publication_observed", false);
    (void)json_push_kv_bool(&reply->data,
                           "provider_publication_observed", false);
    (void)json_push_kv_bool(&reply->data, "peer_discovery_observed", false);
    (void)json_push_kv_bool(&reply->data, "exact_fetch_observed", false);
    (void)json_push_kv_str(&reply->data, "effect_boundary",
                          "separate_commit_revalidates_everything");
}
