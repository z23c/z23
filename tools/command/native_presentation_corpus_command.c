/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: native display-only instrument for canonical C23 corpus facts. */

#include "command/native_command.h"

#include "json/json.h"
#include "presentation/model.h"
#include "util/log_macros.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define NPCORPUS_LEAF "app.presentation.corpus"

static void npc_fail(struct zcl_command_reply *reply, const char *code,
                     const char *message)
{
    LOG_ERROR("native.presentation.corpus", "%s: %s", code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_FAILED, code, "observe", false, false, message,
        NPCORPUS_LEAF);
}

static const struct json_value *npc_value(const struct json_value *facts,
                                          const char *key)
{
    return facts && facts->type == JSON_OBJ ? json_get(facts, key) : NULL;
}

static bool npc_u64(const struct json_value *facts, const char *key,
                    uint64_t *out)
{
    const struct json_value *value = npc_value(facts, key);
    if (!value || value->type != JSON_INT || value->val.i < 0) return false;
    *out = (uint64_t)value->val.i;
    return true;
}

static const char *npc_str(const struct json_value *facts, const char *key)
{
    const struct json_value *value = npc_value(facts, key);
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool npc_root(const char *root)
{
    if (!root || strlen(root) != 64u) return false;
    for (size_t i = 0; i < 64u; i++)
        if (!((root[i] >= '0' && root[i] <= '9') ||
              (root[i] >= 'a' && root[i] <= 'f')))
            return false;
    return true;
}

static void npc_item(struct zcl_present_model_v1 *model, const char *id,
                     const char *label, const char *value, uint16_t status)
{
    if (model->item_count >= ZCL_PRESENT_MODEL_ITEMS_MAX) return;
    struct zcl_present_model_item_v1 *item =
        &model->items[model->item_count++];
    item->kind = ZCL_PRESENT_ITEM_KEY_VALUE;
    item->status = status;
    item->parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    (void)snprintf(item->id, sizeof(item->id), "%s", id);
    (void)snprintf(item->label, sizeof(item->label),
                   "CORPUS FACT - %s", label);
    (void)snprintf(item->value, sizeof(item->value), "%s", value);
}

static void npc_count_item(struct zcl_present_model_v1 *model,
                           const struct json_value *facts, const char *key,
                           const char *id, const char *label,
                           const char *unit, uint16_t status, bool available)
{
    uint64_t count = 0;
    char value[ZCL_PRESENT_MODEL_VALUE_MAX + 1u];
    bool have_count = available && npc_u64(facts, key, &count);
    if (have_count)
        (void)snprintf(value, sizeof(value), "%" PRIu64 "%s%s", count,
                       unit && unit[0] ? " " : "", unit ? unit : "");
    else
        (void)snprintf(value, sizeof(value), "unavailable");
    npc_item(model, id, label, value,
             have_count ? status : ZCL_PRESENT_STATUS_YELLOW);
}

static bool npc_projection_ready(const struct json_value *facts)
{
    const struct json_value *ready_value =
        npc_value(facts, "projection_ready");
    return ready_value && ready_value->type == JSON_BOOL &&
           json_get_bool(ready_value);
}

static void npc_add_inventory_items(struct zcl_present_model_v1 *model,
                                    const struct json_value *facts,
                                    bool ready)
{
    npc_count_item(model, facts, "admitted_production_loc", "production-loc",
                   "Admitted production", "LOC", ZCL_PRESENT_STATUS_GREEN,
                   ready);
    npc_count_item(model, facts, "admitted_test_loc", "test-loc",
                   "Admitted tests", "LOC", ZCL_PRESENT_STATUS_GREEN, ready);
    npc_count_item(model, facts, "durably_hosted_loc", "durable-loc",
                   "Durably hosted", "LOC", ZCL_PRESENT_STATUS_INFO, ready);

    uint64_t downstream = 0;
    char value[ZCL_PRESENT_MODEL_VALUE_MAX + 1u];
    bool have_downstream = ready &&
        npc_u64(facts, "downstream_used_loc", &downstream);
    if (have_downstream)
        (void)snprintf(value, sizeof(value), "%" PRIu64 " LOC", downstream);
    else
        (void)snprintf(value, sizeof(value),
                       "unavailable (not checkpoint-bound)");
    npc_item(model, "used-loc", "Downstream used", value,
             have_downstream
                 ? ZCL_PRESENT_STATUS_GREEN : ZCL_PRESENT_STATUS_YELLOW);

    npc_count_item(model, facts, "unique_semantic_units", "semantic-units",
                   "Unique semantic units", "units",
                   ZCL_PRESENT_STATUS_GREEN, ready);
    npc_count_item(model, facts, "packages_admitted", "packages",
                   "Packages admitted", "packages",
                   ZCL_PRESENT_STATUS_GREEN, ready);

    uint64_t excluded = 0;
    bool have_excluded = ready &&
        npc_u64(facts, "packages_excluded", &excluded);
    if (have_excluded)
        (void)snprintf(value, sizeof(value),
                       "%" PRIu64 " entries; reason LOC unavailable", excluded);
    else
        (void)snprintf(value, sizeof(value), "unavailable");
    npc_item(model, "exclusions", "Exclusions", value,
             have_excluded
                 ? ZCL_PRESENT_STATUS_INFO : ZCL_PRESENT_STATUS_YELLOW);
}

static void npc_add_progress_items(struct zcl_present_model_v1 *model,
                                   const struct json_value *facts, bool ready)
{
    uint64_t loc_added = 0, packages_added = 0, days = 0;
    char value[ZCL_PRESENT_MODEL_VALUE_MAX + 1u];
    bool have_velocity = ready &&
        npc_u64(facts, "admitted_loc_added", &loc_added) &&
        npc_u64(facts, "packages_added", &packages_added) &&
        npc_u64(facts, "days_elapsed", &days);
    if (have_velocity)
        (void)snprintf(value, sizeof(value),
                       "+%" PRIu64 " LOC, +%" PRIu64
                       " packages / %" PRIu64 " days",
                       loc_added, packages_added, days);
    else
        (void)snprintf(value, sizeof(value),
                       "unavailable (previous checkpoint not bound)");
    npc_item(model, "velocity", "Velocity", value,
             have_velocity
                 ? ZCL_PRESENT_STATUS_INFO : ZCL_PRESENT_STATUS_YELLOW);

    const char *stage = npc_str(facts, "progress_stage");
    npc_item(model, "stage", "Current stage",
             stage && stage[0] ? stage : "unavailable",
             ready ? ZCL_PRESENT_STATUS_INFO : ZCL_PRESENT_STATUS_YELLOW);
    const char *blocker = npc_str(facts, "blocker");
    if (blocker && blocker[0])
        npc_item(model, "blocker", "Named blocker", blocker,
                 ZCL_PRESENT_STATUS_YELLOW);
}

bool zcl_native_presentation_corpus_model_from_facts(
    const struct json_value *facts, struct zcl_present_model_v1 *model,
    char *why, size_t why_cap)
{
    if (!facts || facts->type != JSON_OBJ || !model) {
        if (why && why_cap)
            (void)snprintf(why, why_cap, "canonical corpus facts are missing");
        return false;
    }
    bool ready = npc_projection_ready(facts);
    const char *root = ready ? npc_str(facts, "checkpoint_root")
                             : npc_str(facts, "rules_root");
    if (!npc_root(root)) {
        if (why && why_cap)
            (void)snprintf(why, why_cap,
                           "canonical corpus root is unavailable or invalid");
        return false;
    }

    zcl_present_model_init_v1(model, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(model->request_id, sizeof(model->request_id),
                   "c23-corpus-status");
    (void)snprintf(model->title, sizeof(model->title),
                   "10 Million Exact C23");
    (void)snprintf(model->summary, sizeof(model->summary),
                   "Verified corpus lower bound; never a global completeness claim.");
    (void)snprintf(model->exact_root, sizeof(model->exact_root), "%s", root);

    npc_add_inventory_items(model, facts, ready);
    npc_add_progress_items(model, facts, ready);

    return zcl_present_model_validate_v1(model, why, why_cap);
}

void zcl_native_handle_presentation_corpus(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    struct json_value empty;
    json_init(&empty);
    json_set_object(&empty);
    struct zcl_command_request facts_request = *request;
    facts_request.input = &empty;
    struct zcl_command_reply facts_reply;
    zcl_command_reply_init(&facts_reply,
                           "zcl.zcode_commons_corpus_status.v1");
    zcl_native_handle_zcode_commons_corpus_status(&facts_request,
                                                  &facts_reply);
    json_free(&empty);
    if (facts_reply.status != ZCL_COMMAND_STATUS_PASSED) {
        char message[192];
        (void)snprintf(message, sizeof(message), "%s",
                       facts_reply.error.message[0]
                           ? facts_reply.error.message
                           : "canonical corpus status is unavailable");
        zcl_command_reply_free(&facts_reply);
        npc_fail(reply, "CORPUS_STATUS_UNAVAILABLE", message);
        return;
    }

    struct zcl_present_model_v1 model;
    char why[192];
    bool built = zcl_native_presentation_corpus_model_from_facts(
        &facts_reply.data, &model, why, sizeof(why));
    zcl_command_reply_free(&facts_reply);
    if (!built) {
        npc_fail(reply, "CORPUS_MODEL_INVALID", why);
        return;
    }
    zcl_native_present_model(&model, NPCORPUS_LEAF, request->input, reply);
    if (reply->status == ZCL_COMMAND_STATUS_PASSED) {
        (void)json_push_kv_str(&reply->data, "fact_authority",
                               "canonical_corpus_status");
        (void)json_push_kv_bool(&reply->data,
                                "global_completeness_claimed", false);
    }
}
