/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter native-dev-input-and-interrupt-policy.v1
 * for tools/command/native_dev_input_policy.c.
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
#include "command/native_dev_input_policy.h"
#elif ZCL_HOTFORK_STORY_PHASE == 2
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
    const char *files[4];
    size_t count = 0;
    char why[160] = {0};
    struct json_value doc;
    json_init(&doc);
    const char valid_files[] = "{\"files\":[\"tools/dev/devloop.c\"]}";
    bool parsed = json_read(&doc, valid_files, strlen(valid_files));
    HF_CHECK(parsed
             && zcl_dev_request_files(&doc, false, files, &count, why,
                                      sizeof(why))
             && count == 1 && strcmp(files[0], "tools/dev/devloop.c") == 0);
    json_free(&doc);
    const char abs_files[] = "{\"files\":[\"/tmp/x.c\"]}";
    json_init(&doc);
    parsed = json_read(&doc, abs_files, strlen(abs_files));
    HF_CHECK(
        parsed
        && !zcl_dev_request_files(&doc, false, files, &count, why,
                                  sizeof(why)));
    json_free(&doc);
    const char dotdot_files[] = "{\"files\":[\"tools/../x.c\"]}";
    json_init(&doc);
    parsed = json_read(&doc, dotdot_files, strlen(dotdot_files));
    HF_CHECK(
        parsed
        && !zcl_dev_request_files(&doc, false, files, &count, why,
                                  sizeof(why)));
    json_free(&doc);
    int64_t cursor = 0;
    const char cursor_json[] = "{\"after_epoch\":7}";
    json_init(&doc);
    parsed = json_read(&doc, cursor_json, strlen(cursor_json));
    HF_CHECK(parsed
             && zcl_dev_drive_input_int(&doc, "after_epoch", 3, &cursor)
             && cursor == 7);
    json_free(&doc);
    const char empty_json[] = "{}";
    json_init(&doc);
    parsed = json_read(&doc, empty_json, strlen(empty_json));
    HF_CHECK(parsed
             && zcl_dev_drive_input_int(&doc, "after_epoch", 3, &cursor)
             && cursor == 3);
    json_free(&doc);
    const char bad_cursor[] = "{\"after_epoch\":\"7\"}";
    json_init(&doc);
    parsed = json_read(&doc, bad_cursor, strlen(bad_cursor));
    HF_CHECK(parsed
             && !zcl_dev_drive_input_int(&doc, "after_epoch", 3,
                                         &cursor));
    json_free(&doc);
    const char red_phase[] = "{\"phase\":\"STORY_RED\"}";
    json_init(&doc);
    parsed = json_read(&doc, red_phase, strlen(red_phase));
    HF_CHECK(parsed && zcl_dev_event_interrupting(&doc));
    json_free(&doc);
    const char red_status[] = "{\"status\":\"compile_red\"}";
    json_init(&doc);
    parsed = json_read(&doc, red_status, strlen(red_status));
    HF_CHECK(parsed && zcl_dev_event_interrupting(&doc));
    json_free(&doc);
    const char pending[] = "{\"status\":\"proof_pending\"}";
    json_init(&doc);
    parsed = json_read(&doc, pending, strlen(pending));
    HF_CHECK(parsed && !zcl_dev_event_interrupting(&doc));
    json_free(&doc);
    HF_CHECK(zcl_dev_group_valid("test_vcs_core"));
    HF_CHECK(!zcl_dev_group_valid("test-vcs-core"));
    char lower[65], upper[65], gen[80], legacy[80];
    memset(lower, 'a', 64);
    lower[64] = 0;
    memset(upper, 'A', 64);
    upper[64] = 0;
    snprintf(gen, sizeof(gen), "gen-%s", lower);
    snprintf(legacy, sizeof(legacy), "legacy-%s", lower);
    HF_CHECK(zcl_dev_generation_name_valid(gen));
    HF_CHECK(zcl_dev_generation_name_valid(legacy));
    snprintf(gen, sizeof(gen), "gen-%s", upper);
    HF_CHECK(!zcl_dev_generation_name_valid(gen));
    HF_CHECK(zcl_dev_failure_id_valid(lower));
    HF_CHECK(!zcl_dev_failure_id_valid(upper));
    lower[63] = 0;
    HF_CHECK(!zcl_dev_failure_id_valid(lower));
#undef HF_CHECK
    snprintf(out->exercised_surface, sizeof(out->exercised_surface),
             ZCL_HOTFORK_EXERCISED_SURFACE);
    snprintf(out->detail, sizeof(out->detail), "checks=%u/%u",
             out->checks_passed, out->checks_run);
    return out->checks_run == 17 && out->checks_passed == 17;
}
#else
#error "unknown HOT_FORK story phase"
#endif
