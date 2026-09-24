/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter app-native-read-rpc-composition.v1
 * for engine/controllers/src/app_native_handlers.c.
 * Compiled only inside the capsule unity rendered by
 * tools/dev/hotfork_unity.h: phase 1 precedes the owner TU set, phase 2
 * follows it. check-hotfork-stories compiles every unity with the frozen
 * dev flags, so an owner API change cannot silently disable this story.
 */
#if !defined(ZCL_HOTFORK_STORY_PHASE)
#error "HOT_FORK stories are included only by the generated capsule unity"
#elif ZCL_HOTFORK_STORY_PHASE == 1
#define _GNU_SOURCE
#include "hotswap/hotfork_capsule.h"
#define node_rpc_call hotfork_node_rpc_call
#elif ZCL_HOTFORK_STORY_PHASE == 2
#undef node_rpc_call
static char hf_method[64], hf_params[256];
static const char *hf_reply;
char *hotfork_node_rpc_call(const char *method, const char *params)
{
    snprintf(hf_method, sizeof(hf_method), "%s", method ? method : "");
    snprintf(hf_params, sizeof(hf_params), "%s", params ? params : "<null>");
    return hf_reply ? strdup(hf_reply) : NULL;
}
__attribute__((visibility("hidden"))) bool
zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out)
{
    if (!out) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->magic = ZCL_HOTFORK_OBSERVATION_MAGIC;
#define HF_CHECK(x) \
    do { \
        out->checks_run++; \
        if (x) \
            out->checks_passed++; \
    } while (0)
    struct zcl_native_body_err err = {0};
    char *body = NULL;
    struct json_value args, doc;
    const struct json_value *value = NULL;
    hf_reply = "[\"ZCL\"]";
    body = zcl_native_zslp_listtokens_body(NULL, &err);
    json_init(&doc);
    bool parsed = body && json_read(&doc, body, strlen(body));
    value = parsed ? json_get(&doc, "tokens") : NULL;
    HF_CHECK(parsed && value && value->type == JSON_ARR && json_size(value) == 1
             && strcmp(json_get_str(json_at(value, 0)), "ZCL") == 0);
    json_free(&doc);
    free(body);
    hf_reply = "legacy-error";
    body = zcl_native_zslp_listtokens_body(NULL, &err);
    HF_CHECK(body && strcmp(body, "legacy-error") == 0);
    free(body);
    json_init(&args);
    json_set_object(&args);
    json_push_kv_str(&args, "name", "alice");
    hf_reply = "{}";
    body = zcl_native_name_resolve_body(&args, &err);
    HF_CHECK(body && strcmp(hf_method, "name_resolve") == 0
             && strcmp(hf_params, "[\"alice\"]") == 0);
    free(body);
    json_free(&args);
    body = zcl_native_name_list_body(NULL, &err);
    HF_CHECK(body && strcmp(hf_method, "name_list") == 0
             && strcmp(hf_params, "<null>") == 0);
    free(body);
    hf_reply = "[]";
    body = zcl_native_msg_inbox_body(NULL, &err);
    json_init(&doc);
    parsed = body && json_read(&doc, body, strlen(body));
    value = parsed ? json_get(&doc, "messages") : NULL;
    HF_CHECK(body && strcmp(hf_method, "msg_inbox") == 0
             && strcmp(hf_params, "<null>") == 0 && parsed && value
             && value->type == JSON_ARR && json_size(value) == 0);
    json_free(&doc);
    free(body);
    json_init(&args);
    json_set_object(&args);
    json_push_kv_str(&args, "profile", "open");
    body = zcl_native_zmarket_list_body(&args, &err);
    HF_CHECK(body && strcmp(hf_method, "zmarket_list") == 0
             && strcmp(hf_params, "[\"open\"]") == 0);
    free(body);
    json_free(&args);
    body = zcl_native_zmarket_list_body(NULL, &err);
    HF_CHECK(body && strcmp(hf_method, "zmarket_list") == 0
             && strcmp(hf_params, "<null>") == 0);
    free(body);
    body = zcl_native_zmarket_status_body(NULL, &err);
    HF_CHECK(body && strcmp(hf_method, "zmarket_status") == 0);
    free(body);
    body = zcl_native_zmarket_content_list_body(NULL, &err);
    HF_CHECK(body && strcmp(hf_method, "zmarket_content_list") == 0);
    free(body);
    body = zcl_native_swap_chains_body(NULL, &err);
    HF_CHECK(body && strcmp(hf_method, "swap_chains") == 0);
    free(body);
    json_init(&args);
    json_set_object(&args);
    json_push_kv_str(&args, "state", "complete");
    body = zcl_native_swap_list_body(&args, &err);
    HF_CHECK(body && strcmp(hf_method, "swap_list") == 0
             && strcmp(hf_params, "[\"complete\"]") == 0);
    free(body);
    json_free(&args);
    json_init(&args);
    json_set_object(&args);
    body = zcl_native_swap_list_body(&args, &err);
    HF_CHECK(body && strcmp(hf_method, "swap_list") == 0
             && strcmp(hf_params, "<null>") == 0);
    free(body);
    json_free(&args);
#undef HF_CHECK
    snprintf(out->exercised_surface, sizeof(out->exercised_surface),
             ZCL_HOTFORK_EXERCISED_SURFACE);
    snprintf(out->detail, sizeof(out->detail), "checks=%u/%u",
             out->checks_passed, out->checks_run);
    return out->checks_run == 12 && out->checks_passed == 12;
}
#else
#error "unknown HOT_FORK story phase"
#endif
