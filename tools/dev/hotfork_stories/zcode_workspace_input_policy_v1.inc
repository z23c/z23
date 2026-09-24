/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter zcode-workspace-input-policy.v1
 * for tools/command/native_zcode_workspace_command.c.
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
    char lower[65], upper[65];
    memset(lower, 'a', 64);
    lower[64] = 0;
    memset(upper, 'A', 64);
    upper[64] = 0;
    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    json_push_kv_str(&doc, "root", lower);
    json_push_kv_str(&doc, "upper", upper);
    uint8_t root[32];
    HF_CHECK(workspace_decode_root(&doc, "root", root) && root[0] == 0xaa
             && root[31] == 0xaa);
    HF_CHECK(!workspace_decode_root(&doc, "upper", root));
    HF_CHECK(!workspace_decode_root(&doc, "missing", root));
    json_free(&doc);
    HF_CHECK(workspace_manifest_key_allowed("passport", false));
    HF_CHECK(!workspace_manifest_key_allowed("signature", false));
    HF_CHECK(workspace_manifest_key_allowed("signature", true));
    HF_CHECK(!workspace_manifest_key_allowed("unknown", true));
    HF_CHECK(!workspace_manifest_key_allowed(NULL, true));
    uint8_t zero[32] = {0}, nonzero[32] = {0};
    nonzero[17] = 1;
    HF_CHECK(zcl_bytes_all_zero(zero, 32));
    HF_CHECK(!zcl_bytes_all_zero(nonzero, 32));
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
