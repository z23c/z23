/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter zcode-moderation-input-policy.v1
 * for tools/command/native_zcode_moderation_command.c.
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
    struct json_value doc;
    const char *workspace = NULL;
    uint64_t height = 0;
    int64_t mtp = 0;
    json_init(&doc);
    json_set_object(&doc);
    HF_CHECK(moderation_no_keys(&doc));
    json_push_kv_bool(&doc, "extra", true);
    HF_CHECK(!moderation_no_keys(&doc));
    json_free(&doc);
    HF_CHECK(!moderation_no_keys(NULL));
    json_init(&doc);
    json_set_array(&doc);
    HF_CHECK(!moderation_no_keys(&doc));
    json_free(&doc);
    const char valid[] =
        "{\"workspace\":\"/tmp/zcl-hotfork-scratch\",\"cutoff_height\":7,\"cutoff_mtp\":11}";
    json_init(&doc);
    bool parsed = json_read(&doc, valid, strlen(valid));
    HF_CHECK(parsed && moderation_backlog_input(&doc, &workspace, &height, &mtp)
             && strcmp(workspace, "/tmp/zcl-hotfork-scratch") == 0
             && height == 7 && mtp == 11);
    json_free(&doc);
    const char unknown[] =
        "{\"workspace\":\"/tmp/zcl-hotfork-scratch\",\"cutoff_height\":7,\"unknown\":11}";
    json_init(&doc);
    parsed = json_read(&doc, unknown, strlen(unknown));
    HF_CHECK(parsed
             && !moderation_backlog_input(&doc, &workspace, &height, &mtp));
    json_free(&doc);
    const char zero[] =
        "{\"workspace\":\"/tmp/zcl-hotfork-scratch\",\"cutoff_height\":0,\"cutoff_mtp\":11}";
    json_init(&doc);
    parsed = json_read(&doc, zero, strlen(zero));
    HF_CHECK(parsed
             && !moderation_backlog_input(&doc, &workspace, &height, &mtp));
    json_free(&doc);
    const char wrong_type[] =
        "{\"workspace\":\"/tmp/zcl-hotfork-scratch\",\"cutoff_height\":\"7\",\"cutoff_mtp\":11}";
    json_init(&doc);
    parsed = json_read(&doc, wrong_type, strlen(wrong_type));
    HF_CHECK(parsed
             && !moderation_backlog_input(&doc, &workspace, &height, &mtp));
    json_free(&doc);
    const char nonscratch[] =
        "{\"workspace\":\"/srv/zcode\",\"cutoff_height\":7,\"cutoff_mtp\":11}";
    json_init(&doc);
    parsed = json_read(&doc, nonscratch, strlen(nonscratch));
    HF_CHECK(parsed
             && !moderation_backlog_input(&doc, &workspace, &height, &mtp));
    json_free(&doc);
    HF_CHECK(!moderation_backlog_input(NULL, &workspace, &height, &mtp));
#undef HF_CHECK
    snprintf(out->exercised_surface, sizeof(out->exercised_surface),
             ZCL_HOTFORK_EXERCISED_SURFACE);
    snprintf(out->detail, sizeof(out->detail), "checks=%u/%u",
             out->checks_passed, out->checks_run);
    return out->checks_run == 10 && out->checks_passed == 10;
}
#else
#error "unknown HOT_FORK story phase"
#endif
