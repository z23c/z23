/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter zcode-source-bundle-input-policy.v1
 * for tools/command/native_zcode_source_bundle_command.c.
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
    struct json_value doc, upper, rendered;
    json_init(&doc);
    json_set_object(&doc);
    char lower[65], capital[65];
    memset(lower, 'a', 64);
    lower[64] = 0;
    memset(capital, 'A', 64);
    capital[64] = 0;
    json_push_kv_str(&doc, "source_root", lower);
    json_push_kv_str(&doc, "named_root", lower);
    json_push_kv_int(&doc, "count", 7);
    HF_CHECK(strcmp(zsb_str(&doc, "source_root"), lower) == 0);
    HF_CHECK(zsb_str(&doc, "missing") == NULL);
    HF_CHECK(zsb_str(&doc, "count") == NULL);
    uint8_t root[32], named[32];
    HF_CHECK(zsb_root(&doc, root) && root[0] == 0xaa && root[31] == 0xaa);
    HF_CHECK(zsb_named_root(&doc, "named_root", named)
             && memcmp(root, named, 32) == 0);
    json_init(&upper);
    json_set_object(&upper);
    json_push_kv_str(&upper, "source_root", capital);
    HF_CHECK(!zsb_root(&upper, root));
    json_free(&upper);
    HF_CHECK(!zsb_paths_disjoint("src", "src"));
    HF_CHECK(!zsb_paths_disjoint("src", "src/lib/x.c"));
    HF_CHECK(!zsb_paths_disjoint("src/lib/x.c", "src"));
    HF_CHECK(zsb_paths_disjoint("src/a", "src/b"));
    struct vcs_source_bundle_metrics metrics = {.source_bytes = 11,
                                                .compressed_bytes = 7,
                                                .new_bytes = 5,
                                                .reused_bytes = 6,
                                                .file_count = 2,
                                                .new_blobs = 1,
                                                .reused_blobs = 1,
                                                .manifest_reused = true,
                                                .repaired = false};
    memset(root, 0x5a, sizeof(root));
    json_init(&rendered);
    json_set_object(&rendered);
    zsb_render(&rendered, root, &metrics);
    HF_CHECK(strlen(json_get_str(json_get(&rendered, "source_root"))) == 64
             && json_get_int(json_get(&rendered, "source_bytes")) == 11
             && json_get_int(json_get(&rendered, "compressed_bytes")) == 7
             && json_get_int(json_get(&rendered, "file_count")) == 2);
    HF_CHECK(json_get_bool(json_get(&rendered, "manifest_reused"))
             && !json_get_bool(json_get(&rendered, "repaired"))
             && !json_get_bool(json_get(&rendered, "git_required"))
             && !json_get_bool(json_get(&rendered, "source_executed")));
    json_free(&rendered);
    json_free(&doc);
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
