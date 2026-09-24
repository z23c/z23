/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter native-dev-hotswap-receipt-policy.v1
 * for tools/command/native_dev_hotswap.c.
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
    struct hotswap_publish_hooks hooks = {0};
    zcl_native_hotswap_publish_hooks(&hooks, false);
    HF_CHECK(hooks.commit == registry_commit_batch_cb);
    HF_CHECK(hooks.probe == registry_probe_cb);
    HF_CHECK(hooks.quiesced == NULL && hooks.ctx == NULL);
    zcl_native_hotswap_publish_hooks(&hooks, true);
    HF_CHECK(hooks.quiesced == registry_quiesced_cb);
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.hotswap_activate.v2");
    struct hotswap_activate_report module = {.ok = true,
                                             .verify_only = true,
                                             .rolled_back = true,
                                             .probed = true,
                                             .generation = 7,
                                             .leaf_count = 2};
    snprintf(module.source_tu, sizeof(module.source_tu), "app/example.c");
    snprintf(module.stage, sizeof(module.stage), "verified");
    report_to_reply(&reply, &module);
    HF_CHECK(reply.status == ZCL_COMMAND_STATUS_PASSED
             && reply.exit_code == ZCL_COMMAND_EXIT_OK);
    const struct json_value *schema = json_get(&reply.data, "schema");
    const struct json_value *generation = json_get(&reply.data, "generation");
    HF_CHECK(schema
             && strcmp(json_get_str(schema), "zcl.hotswap_activate.v2") == 0
             && generation && json_get_int(generation) == 7);
    zcl_command_reply_free(&reply);
    zcl_command_reply_init(&reply, "zcl.hotswap_activate.v2");
    memset(&module, 0, sizeof(module));
    snprintf(module.stage, sizeof(module.stage), "abi");
    snprintf(module.error, sizeof(module.error), "descriptor refused");
    snprintf(module.handler_name, sizeof(module.handler_name), "core.status");
    report_to_reply(&reply, &module);
    HF_CHECK(reply.status == ZCL_COMMAND_STATUS_BLOCKED
             && strcmp(reply.error.code, "HOTSWAP_REFUSED") == 0
             && strcmp(reply.error.phase, "abi") == 0);
    zcl_command_reply_free(&reply);
    zcl_command_reply_init(&reply, "zcl.hotswap_service_activate.v1");
    struct zcl_hotswap_service_report service = {.recognized = true,
                                                 .ok = true,
                                                 .verify_only = true,
                                                 .probed = true,
                                                 .generation = 9};
    snprintf(service.service_id, sizeof(service.service_id),
             "example.service.v1");
    snprintf(service.stage, sizeof(service.stage), "verified");
    service_report_to_reply(&reply, &service);
    HF_CHECK(reply.status == ZCL_COMMAND_STATUS_PASSED
             && reply.exit_code == ZCL_COMMAND_EXIT_OK);
    generation = json_get(&reply.data, "generation");
    HF_CHECK(generation && json_get_int(generation) == 9);
    zcl_command_reply_free(&reply);
    zcl_command_reply_init(&reply, "zcl.hotswap_service_activate.v1");
    memset(&service, 0, sizeof(service));
    service.dev_restart = true;
    snprintf(service.service_id, sizeof(service.service_id),
             "unknown.service.v1");
    snprintf(service.stage, sizeof(service.stage), "contract");
    snprintf(service.error, sizeof(service.error), "resident contract absent");
    service_report_to_reply(&reply, &service);
    HF_CHECK(reply.status == ZCL_COMMAND_STATUS_BLOCKED
             && strcmp(reply.error.code, "DEV_RESTART") == 0
             && strcmp(reply.error.phase, "contract") == 0);
    zcl_command_reply_free(&reply);
    char why[160] = {0};
    uint32_t generation_out = 0;
    HF_CHECK(!registry_commit_batch_cb(NULL, NULL, 0, &generation_out, why,
                                       sizeof(why))
             && strstr(why, "no leaves") != NULL);
    struct zcl_hotswap_leaf dummy = {.name = "core.status", .fn = NULL};
    memset(why, 0, sizeof(why));
    HF_CHECK(!registry_commit_batch_cb(NULL, &dummy,
                                       ZCL_COMMAND_HANDLER_OVERRIDE_MAX + 1u,
                                       &generation_out, why, sizeof(why))
             && strstr(why, "ceiling") != NULL);
    memset(why, 0, sizeof(why));
    HF_CHECK(!registry_probe_cb(NULL, NULL, NULL, why, sizeof(why))
             && strstr(why, "missing") != NULL);
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
