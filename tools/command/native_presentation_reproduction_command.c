/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: live native projection of one canonical build-proof action. */

#include "command/native_command.h"

#include "base/hex.h"
#include "json/json.h"
#include "presentation/model.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

#define NPR_LEAF "app.presentation.reproduction"

static const char *npr_str(const struct json_value *object, const char *key)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool npr_bool(const struct json_value *object, const char *key)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_BOOL && json_get_bool(value);
}

static bool npr_root(const char *root, bool optional)
{
    uint8_t decoded[32];
    return optional && (!root || !root[0]) ? true :
        root && zcl_hex_decode_lower(root, decoded, sizeof(decoded));
}

static void npr_fail(struct zcl_command_reply *reply, const char *code,
                     const char *message)
{
    LOG_ERROR("native.presentation.reproduction", "%s: %s", code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_INVALID, code, "observe", true, false, message,
        NPR_LEAF);
}

static int npr_stage(const char *state, bool *refused)
{
    *refused = false;
    if (strcmp(state, "REQUESTED") == 0) return 1;
    if (strcmp(state, "PEER_DISCOVERED") == 0 ||
        strcmp(state, "CONTEXT_READY") == 0) return 2;
    if (strcmp(state, "RUNNING") == 0) return 3;
    if (strcmp(state, "REMOTE_GREEN") == 0) return 4;
    if (strcmp(state, "REMOTE_RED") == 0) { *refused = true; return 4; }
    if (strcmp(state, "RECEIPT_VERIFIED") == 0) return 5;
    if (strcmp(state, "REPRODUCED") == 0 ||
        strcmp(state, "READY_FOR_ACCEPTANCE") == 0) return 6;
    if (strcmp(state, "SUPERSEDED") == 0) { *refused = true; return 0; }
    return -1;
}

static void npr_progress_item(struct zcl_present_model_v1 *model,
                              int number, int current, bool refused,
                              const char *state, const char *receipt)
{
    static const char *const ids[] = {
        "", "queued", "admitted", "running", "output", "receipt", "match"
    };
    static const char *const labels[] = {
        "",
        "LOCAL OBSERVATION - Queued",
        "LOCAL OBSERVATION - Admitted",
        "LOCAL OBSERVATION - Running",
        "INDEPENDENT OBSERVATION - Output received",
        "LOCAL OBSERVATION - Receipt verified",
        "INDEPENDENT OBSERVATION - Matching artifact",
    };
    struct zcl_present_model_item_v1 *item =
        &model->items[model->item_count++];
    item->kind = ZCL_PRESENT_ITEM_PROGRESS;
    item->parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    item->denominator = 1;
    item->numerator = number <= current ? 1u : 0u;
    item->status = number < current ? ZCL_PRESENT_STATUS_GREEN :
        number == current && refused ? ZCL_PRESENT_STATUS_RED :
        number == current && current == 6 ? ZCL_PRESENT_STATUS_GREEN :
        number == current ? ZCL_PRESENT_STATUS_INFO : ZCL_PRESENT_STATUS_NEUTRAL;
    (void)snprintf(item->id, sizeof(item->id), "%s", ids[number]);
    (void)snprintf(item->label, sizeof(item->label), "%s", labels[number]);
    if (number < current)
        (void)snprintf(item->value, sizeof(item->value), "observed");
    else if (number > current)
        (void)snprintf(item->value, sizeof(item->value),
                       "pending - no observation");
    else if (receipt && receipt[0] && number >= 4)
        (void)snprintf(item->value, sizeof(item->value), "%s %.16s...",
                       state, receipt);
    else
        (void)snprintf(item->value, sizeof(item->value), "%s", state);
}

bool zcl_native_presentation_reproduction_model_from_facts(
    const struct json_value *facts, struct zcl_present_model_v1 *model,
    char *why, size_t why_cap)
{
    const char *schema = npr_str(facts, "schema");
    const char *action = npr_str(facts, "action_id");
    const char *state = npr_str(facts, "state");
    const char *event = npr_str(facts, "event_root");
    const char *candidate = npr_str(facts, "candidate_root");
    const char *receipt = npr_str(facts, "receipt_root");
    if (!facts || facts->type != JSON_OBJ ||
        !schema || strcmp(schema, "zcl.build_fabric_action_state.v1") != 0 ||
        !npr_bool(facts, "found") || !npr_bool(facts, "event_root_rederived") ||
        !npr_root(action, false) || !npr_root(event, false) ||
        !npr_root(candidate, false) || !npr_root(receipt, true) || !state) {
        (void)snprintf(why, why_cap,
                       "canonical build-proof action facts are unavailable");
        return false;
    }
    bool refused = false;
    int current = npr_stage(state, &refused);
    if (current < 0) {
        (void)snprintf(why, why_cap, "build-proof state is not recognized");
        return false;
    }
    zcl_present_model_init_v1(model, ZCL_PRESENT_MODEL_PROGRESS);
    (void)snprintf(model->request_id, sizeof(model->request_id),
                   "repro-%.12s", action);
    (void)snprintf(model->title, sizeof(model->title),
                   "Independent reproduction");
    (void)snprintf(model->summary, sizeof(model->summary),
                   "Action %.12s... latest event %.12s...: %s%s",
                   action, event, state, refused ? " (named refusal)" : "");
    (void)snprintf(model->exact_root, sizeof(model->exact_root), "%s",
                   candidate);
    for (int stage = 1; stage <= 6; stage++)
        npr_progress_item(model, stage, current, refused, state, receipt);
    if (refused && current == 0) {
        struct zcl_present_model_item_v1 *item =
            &model->items[model->item_count++];
        item->kind = ZCL_PRESENT_ITEM_KEY_VALUE;
        item->status = ZCL_PRESENT_STATUS_RED;
        item->parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
        (void)snprintf(item->id, sizeof(item->id), "refusal");
        (void)snprintf(item->label, sizeof(item->label),
                       "LOCAL OBSERVATION - Named refusal");
        (void)snprintf(item->value, sizeof(item->value), "%s", state);
    }
    return zcl_present_model_validate_v1(model, why, why_cap);
}

void zcl_native_handle_presentation_reproduction(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *action = npr_str(request ? request->input : NULL, "action_id");
    if (!npr_root(action, false)) {
        npr_fail(reply, "INVALID_REPRODUCTION_ACTION",
                 "action_id must be 64 lowercase hex characters, e.g. "
                 "3f9a... (32 bytes hex-encoded)");
        return;
    }
    zcl_native_bridge_ensure_rpc();
    struct json_value facts;
    if (!zcl_native_presentation_dumpstate("build_fabric", action, &facts)) {
        npr_fail(reply, "REPRODUCTION_FACTS_UNAVAILABLE",
                 "the target node did not return canonical action progress");
        return;
    }
    struct zcl_present_model_v1 model;
    char why[192];
    bool built = zcl_native_presentation_reproduction_model_from_facts(
        &facts, &model, why, sizeof(why));
    const char *state = npr_str(&facts, "state");
    const char *candidate = npr_str(&facts, "candidate_root");
    char state_copy[24] = {0};
    char candidate_copy[65] = {0};
    if (state)
        (void)snprintf(state_copy, sizeof(state_copy), "%s", state);
    if (candidate)
        (void)snprintf(candidate_copy, sizeof(candidate_copy), "%s",
                       candidate);
    bool independent = state &&
        (strcmp(state, "REMOTE_GREEN") == 0 ||
         strcmp(state, "REMOTE_RED") == 0 ||
         strcmp(state, "REPRODUCED") == 0 ||
         strcmp(state, "READY_FOR_ACCEPTANCE") == 0);
    json_free(&facts);
    if (!built) {
        npr_fail(reply, "REPRODUCTION_MODEL_INVALID", why);
        return;
    }
    zcl_native_present_model(&model, NPR_LEAF, request->input, reply);
    if (reply->status == ZCL_COMMAND_STATUS_PASSED) {
        (void)json_push_kv_str(&reply->data, "fact_authority",
                              "target_node_build_proof_ledger");
        (void)json_push_kv_str(&reply->data, "claim_class",
                              independent ? "INDEPENDENT_OBSERVATION" :
                                            "LOCAL_OBSERVATION");
        (void)json_push_kv_str(&reply->data, "action_id", action);
        (void)json_push_kv_str(&reply->data, "candidate_root",
                              candidate_copy);
        (void)json_push_kv_str(&reply->data, "proof_state", state_copy);
    }
}
