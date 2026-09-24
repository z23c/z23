/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter command-registry-input-validation-core.v1
 * for engine/modules/kernel/src/command_registry_input_validate.c.
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
static bool hf_valid(const char *path, const char *keys, const char *body)
{
    struct json_value input;
    json_init(&input);
    bool parsed = json_read(&input, body, strlen(body));
    struct zcl_command_spec spec = {
        .path = path, .input_schema = "zcl.test.input.v1", .input_keys = keys};
    char why[160];
    bool ok =
        parsed
        && zcl_command_registry_input_validate(&spec, &input, why, sizeof(why));
    json_free(&input);
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
    unsigned failed = 0;
#define HF_CHECK(x) \
    do { \
        unsigned n = out->checks_run++; \
        if (x) \
            out->checks_passed++; \
        else \
            failed |= 1u << n; \
    } while (0)
    HF_CHECK(hf_valid("dev.loop.drive", "wait_for_edit,all",
                      "{\"wait_for_edit\":true,\"all\":false}")
             && !hf_valid("dev.loop.drive", "wait_for_edit",
                          "{\"wait_for_edit\":\"true\"}"));
    HF_CHECK(hf_valid("zcode.package.fetch", "maximum_bytes",
                      "{\"maximum_bytes\":268435456}")
             && !hf_valid("zcode.package.fetch", "maximum_bytes",
                          "{\"maximum_bytes\":268435457}")
             && hf_valid("metaverse.space.scout.run", "maximum_bytes",
                         "{\"maximum_bytes\":8388608}")
             && !hf_valid("metaverse.space.scout.run", "maximum_bytes",
                          "{\"maximum_bytes\":8388609}"));
    HF_CHECK(
        hf_valid(
            "zcode.epoch.plan", "cutoff_height,cutoff_mtp,epoch_capacity_atoms",
            "{\"cutoff_height\":1,\"cutoff_mtp\":2,\"epoch_capacity_atoms\":3}")
        && !hf_valid("zcode.epoch.plan", "cutoff_height",
                     "{\"cutoff_height\":0}"));
    HF_CHECK(hf_valid("zcode.work.start", "max_cpu_seconds",
                      "{\"max_cpu_seconds\":600}")
             && !hf_valid("zcode.work.start", "max_cpu_seconds",
                          "{\"max_cpu_seconds\":601}"));
    HF_CHECK(
        hf_valid(
            "app.shop.want.post",
            "issued_unix,expires_unix,amount_zatoshi,nonce",
            "{\"issued_unix\":1,\"expires_unix\":2,\"amount_zatoshi\":2100000000000000,\"nonce\":7}")
        && hf_valid("app.auth.verify", "nonce", "{\"nonce\":\"server-issued\"}")
        && !hf_valid("app.shop.want.post", "amount_zatoshi",
                     "{\"amount_zatoshi\":0}"));
    struct zcl_command_spec bounded = {.input_keys = "manifest_hex"};
    HF_CHECK(zcl_command_registry_input_str_max("manifest_hex") > 4096
             && zcl_command_registry_input_str_max("ordinary") == 4096
             && zcl_command_registry_input_budget_bytes(&bounded)
                    > ZCL_COMMAND_MAX_INPUT);
#undef HF_CHECK
    snprintf(out->exercised_surface, sizeof(out->exercised_surface),
             ZCL_HOTFORK_EXERCISED_SURFACE);
    snprintf(out->detail, sizeof(out->detail), "checks=%u/%u;failed_mask=0x%x",
             out->checks_passed, out->checks_run, failed);
    return out->checks_run == 6 && out->checks_passed == 6;
}
#else
#error "unknown HOT_FORK story phase"
#endif
