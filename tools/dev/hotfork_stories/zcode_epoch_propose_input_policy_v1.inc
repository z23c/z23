/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter zcode-epoch-propose-input-policy.v1
 * for tools/command/native_zcode_epoch_propose_command.c.
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
#define zcl_native_zcode_workspace_is_explicit_scratch \
    hotfork_workspace_is_scratch
#elif ZCL_HOTFORK_STORY_PHASE == 2
#undef zcl_native_zcode_workspace_is_explicit_scratch
bool hotfork_workspace_is_scratch(const char *path)
{
    return path && strcmp(path, "/tmp/zcl-hotfork-scratch") == 0;
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
    static const char *const allowed[] = {"workspace", "epoch",
                                          "previous_proposal_root"};
    char lower[65], upper[65];
    memset(lower, 'a', 64);
    lower[64] = 0;
    memset(upper, 'A', 64);
    upper[64] = 0;
    char valid[256];
    snprintf(
        valid, sizeof(valid),
        "{\"workspace\":\"/tmp/zcl-hotfork-scratch\",\"epoch\":7,\"previous_proposal_root\":\"%s\"}",
        lower);
    struct json_value doc;
    json_init(&doc);
    bool parsed = json_read(&doc, valid, strlen(valid));
    HF_CHECK(parsed
             && strcmp(zep_str(&doc, "workspace"), "/tmp/zcl-hotfork-scratch")
                    == 0);
    HF_CHECK(parsed && zep_str(&doc, "missing") == NULL);
    HF_CHECK(parsed && zep_keys(&doc, allowed, 3));
    uint8_t root[32];
    HF_CHECK(parsed && zep_root(&doc, "previous_proposal_root", root)
             && root[0] == 0xaa && root[31] == 0xaa);
    uint64_t epoch = 0;
    HF_CHECK(parsed && zep_u64_positive(&doc, "epoch", &epoch) && epoch == 7);
    struct zcl_command_request request = {.input = &doc};
    struct zcl_command_reply reply;
    struct vcs_zcode_epoch_schedule_input input;
    uint8_t previous[32];
    zcl_command_reply_init(&reply, "zcl.hotfork.zep.v1");
    HF_CHECK(zep_parse_propose(&request, &reply, &input, previous)
             && input.epoch == 7
             && strcmp(input.workspace, "/tmp/zcl-hotfork-scratch") == 0
             && previous[0] == 0xaa);
    zcl_command_reply_free(&reply);
    json_free(&doc);
    char candidate[320];
    snprintf(
        candidate, sizeof(candidate),
        "{\"workspace\":\"/tmp/zcl-hotfork-scratch\",\"epoch\":7,\"previous_proposal_root\":\"%s\"}",
        upper);
    json_init(&doc);
    parsed = json_read(&doc, candidate, strlen(candidate));
    HF_CHECK(parsed && !zep_root(&doc, "previous_proposal_root", root));
    json_free(&doc);
    snprintf(
        candidate, sizeof(candidate),
        "{\"workspace\":\"/tmp/zcl-hotfork-scratch\",\"epoch\":0,\"previous_proposal_root\":\"%s\"}",
        lower);
    json_init(&doc);
    parsed = json_read(&doc, candidate, strlen(candidate));
    zcl_command_reply_init(&reply, "zcl.hotfork.zep.v1");
    request.input = &doc;
    HF_CHECK(parsed && !zep_parse_propose(&request, &reply, &input, previous));
    zcl_command_reply_free(&reply);
    json_free(&doc);
    snprintf(
        candidate, sizeof(candidate),
        "{\"workspace\":\"/tmp/zcl-hotfork-scratch\",\"epoch\":7,\"previous_proposal_root\":\"%s\",\"extra\":true}",
        lower);
    json_init(&doc);
    parsed = json_read(&doc, candidate, strlen(candidate));
    zcl_command_reply_init(&reply, "zcl.hotfork.zep.v1");
    request.input = &doc;
    HF_CHECK(parsed && !zep_parse_propose(&request, &reply, &input, previous));
    zcl_command_reply_free(&reply);
    json_free(&doc);
    snprintf(
        candidate, sizeof(candidate),
        "{\"workspace\":\"/srv/zcode\",\"epoch\":7,\"previous_proposal_root\":\"%s\"}",
        lower);
    json_init(&doc);
    parsed = json_read(&doc, candidate, strlen(candidate));
    zcl_command_reply_init(&reply, "zcl.hotfork.zep.v1");
    request.input = &doc;
    HF_CHECK(parsed && !zep_parse_propose(&request, &reply, &input, previous));
    zcl_command_reply_free(&reply);
    json_free(&doc);
    json_init(&doc);
    json_set_array(&doc);
    HF_CHECK(!zep_keys(&doc, allowed, 3));
    json_free(&doc);
    json_init(&doc);
    json_set_object(&doc);
    HF_CHECK(!zep_root(&doc, "missing", root));
    json_push_kv_int(&doc, "epoch", -1);
    HF_CHECK(!zep_u64_positive(&doc, "epoch", &epoch));
    json_free(&doc);
#undef HF_CHECK
    snprintf(out->exercised_surface, sizeof(out->exercised_surface),
             ZCL_HOTFORK_EXERCISED_SURFACE);
    snprintf(out->detail, sizeof(out->detail), "checks=%u/%u",
             out->checks_passed, out->checks_run);
    return out->checks_run == 13 && out->checks_passed == 13;
}
#else
#error "unknown HOT_FORK story phase"
#endif
