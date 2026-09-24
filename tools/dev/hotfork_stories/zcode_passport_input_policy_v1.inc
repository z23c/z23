/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter zcode-passport-input-policy.v1
 * for tools/command/native_zcode_passport_command.c.
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
static bool hf_passport_parse(const char *text, bool commit,
                              struct vcs_zcode_module_passport_v1 *passport)
{
    struct json_value doc;
    json_init(&doc);
    bool decoded = text && json_read(&doc, text, strlen(text));
    struct zcl_command_request request = {.input = &doc};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.hotfork.passport.v1");
    bool ok = decoded
              && passport_parse_roots(&request, &reply, passport, commit,
                                      commit ? "commit" : "plan");
    zcl_command_reply_free(&reply);
    json_free(&doc);
    return ok;
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
    HF_CHECK(passport_key_allowed("stable_api_root", false));
    HF_CHECK(!passport_key_allowed("signature", false));
    HF_CHECK(passport_key_allowed("signature", true));
    HF_CHECK(!passport_key_allowed("unknown", true));
    char lower[65], upper[65];
    memset(lower, 'a', 64);
    lower[64] = 0;
    memset(upper, 'A', 64);
    upper[64] = 0;
    char plan[1400], candidate[1600];
    snprintf(
        plan, sizeof(plan),
        "{\"stable_api_root\":\"%s\",\"recipe_root\":\"%s\",\"toolchain_root\":\"%s\",\"tests_root\":\"%s\",\"license_root\":\"%s\",\"semantic_fingerprint_root\":\"%s\",\"workspace_lineage_root\":\"%s\",\"source_assignment_root\":\"%s\",\"quality_profiles_root\":\"%s\",\"signer_pubkey\":\"%s\"}",
        lower, lower, lower, lower, lower, lower, lower, lower, lower, lower);
    struct vcs_zcode_module_passport_v1 passport;
    HF_CHECK(hf_passport_parse(plan, false, &passport)
             && passport.schema_version == 1
             && passport.flags == VCS_ZCODE_COMMONS_REQUIRED_FLAGS
             && passport.stable_api_root[0] == 0xaa
             && passport.signer_root[31] == 0xaa);
    size_t n = strlen(plan);
    snprintf(
        candidate, sizeof(candidate),
        "%.*s,\"workspace\":\"/tmp/zcl-hotfork-scratch\",\"publication_job_root\":\"00\"}",
        (int)(n - 1), plan);
    HF_CHECK(hf_passport_parse(candidate, false, &passport));
    snprintf(candidate, sizeof(candidate),
             "%.*s,\"workspace\":\"/tmp/zcl-hotfork-scratch\"}", (int)(n - 1),
             plan);
    HF_CHECK(!hf_passport_parse(candidate, false, &passport));
    snprintf(candidate, sizeof(candidate), "%s", plan);
    char *root = strstr(candidate, lower);
    if (root)
        memcpy(root, upper, 64);
    HF_CHECK(root && !hf_passport_parse(candidate, false, &passport));
    snprintf(candidate, sizeof(candidate), "%.*s,\"unknown\":true}",
             (int)(n - 1), plan);
    HF_CHECK(!hf_passport_parse(candidate, false, &passport));
    HF_CHECK(!hf_passport_parse("{}", false, &passport));
    snprintf(candidate, sizeof(candidate),
             "%.*s,\"signature\":\"placeholder\"}", (int)(n - 1), plan);
    HF_CHECK(hf_passport_parse(candidate, true, &passport));
#undef HF_CHECK
    snprintf(out->exercised_surface, sizeof(out->exercised_surface),
             ZCL_HOTFORK_EXERCISED_SURFACE);
    snprintf(out->detail, sizeof(out->detail), "checks=%u/%u",
             out->checks_passed, out->checks_run);
    return out->checks_run == 11 && out->checks_passed == 11;
}
#else
#error "unknown HOT_FORK story phase"
#endif
