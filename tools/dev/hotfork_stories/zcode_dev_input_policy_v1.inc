/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter zcode-dev-input-policy.v1
 * for tools/command/native_zcode_dev_command.c.
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
    struct json_value doc, rendered;
    json_init(&doc);
    json_set_object(&doc);
    json_push_kv_str(&doc, "name", "alice");
    json_push_kv_int(&doc, "count", 7);
    HF_CHECK(strcmp(zdev_str(&doc, "name"), "alice") == 0);
    HF_CHECK(zdev_str(&doc, "missing") == NULL);
    HF_CHECK(zdev_int(&doc, "count", 3) == 7);
    HF_CHECK(zdev_int(&doc, "missing", 3) == 3);
    char lower[65], upper[65];
    memset(lower, 'a', 64);
    lower[64] = 0;
    memset(upper, 'A', 64);
    upper[64] = 0;
    json_push_kv_str(&doc, "root", lower);
    uint8_t root[32];
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.hotfork.zdev.v1");
    HF_CHECK(zdev_root(&doc, "root", root, &reply));
    json_init(&rendered);
    json_set_object(&rendered);
    zdev_push_root(&rendered, "root", root);
    HF_CHECK(strcmp(json_get_str(json_get(&rendered, "root")), lower) == 0);
    json_free(&rendered);
    json_push_kv_str(&doc, "upper", upper);
    HF_CHECK(!zdev_root(&doc, "upper", root, &reply));
    size_t wire_len = 0;
    json_push_kv_str(&doc, "wire", "00ff");
    uint8_t *wire = zdev_hex_wire(&doc, "wire", 2, &wire_len);
    HF_CHECK(wire && wire_len == 2 && wire[0] == 0 && wire[1] == 255);
    free(wire);
    json_push_kv_str(&doc, "odd", "abc");
    HF_CHECK(zdev_hex_wire(&doc, "odd", 2, &wire_len) == NULL && wire_len == 0);
    HF_CHECK(zdev_hex_wire(&doc, "wire", 1, &wire_len) == NULL
             && wire_len == 0);
    HF_CHECK(zdev_paths_overlap("src", "src"));
    HF_CHECK(zdev_paths_overlap("src", "src/lib/x.c"));
    HF_CHECK(zdev_paths_overlap("src/lib", "src"));
    HF_CHECK(!zdev_paths_overlap("src/a", "src/b"));
    char path[VCS_PATH_MAX + 1u];
    HF_CHECK(zdev_candidate_input_path(NULL, NULL, "src/lib/x.c", path, &reply)
             && strcmp(path, "src/lib/x.c") == 0);
    HF_CHECK(
        !zdev_candidate_input_path(NULL, NULL, "src/../x.c", path, &reply));
    zcl_command_reply_free(&reply);
    json_free(&doc);
#undef HF_CHECK
    snprintf(out->exercised_surface, sizeof(out->exercised_surface),
             ZCL_HOTFORK_EXERCISED_SURFACE);
    snprintf(out->detail, sizeof(out->detail), "checks=%u/%u",
             out->checks_passed, out->checks_run);
    return out->checks_run == 16 && out->checks_passed == 16;
}
#else
#error "unknown HOT_FORK story phase"
#endif
