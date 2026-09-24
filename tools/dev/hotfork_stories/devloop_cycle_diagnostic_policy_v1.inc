/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter devloop-cycle-diagnostic-policy.v1
 * for tools/dev/devloop_cycle.c.
 * Compiled only inside the capsule unity rendered by
 * tools/dev/hotfork_unity.h: phase 1 precedes the owner TU set, phase 2
 * follows it. check-hotfork-stories compiles every unity with the frozen
 * dev flags, so an owner API change cannot silently disable this story.
 */
#if !defined(ZCL_HOTFORK_STORY_PHASE)
#error "HOT_FORK stories are included only by the generated capsule unity"
#elif ZCL_HOTFORK_STORY_PHASE == 1
#define _GNU_SOURCE
#define ZCL_TESTING 1
#define ZCL_HOTFORK_DEVLOOP_CYCLE_CORE 1
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
    unsigned failed = 0;
#define HF_CHECK(x) \
    do { \
        unsigned n = out->checks_run++; \
        if (x) \
            out->checks_passed++; \
        else \
            failed |= 1u << n; \
    } while (0)
    const char log[] = "noise\na.c:7:2: error: broken\nFAIL later\n";
    char first[64];
    HF_CHECK(distill_first_error(log, sizeof(log) - 1, first, sizeof(first))
             && strcmp(first, "a.c:7:2: error: broken") == 0);
    const char good[] = "a.c:7:2: error: broken";
    const char transient[] = "a.c:7:2: error: Killed";
    HF_CHECK(compiler_error_shape(good, sizeof(good) - 1)
             && !compiler_error_shape(transient, sizeof(transient) - 1));
    char preview[8];
    bool truncated = false;
    HF_CHECK(
        cycle_text_preview("a\nbcd", 4, preview, sizeof(preview), &truncated)
        && strcmp(preview, "a?bc") == 0 && truncated
        && !cycle_text_preview("x", 8, preview, sizeof(preview), NULL));
    HF_CHECK(zcl_devloop_cycle_proof_complete("passed", "verify")
             && !zcl_devloop_cycle_proof_complete("passed", "compile")
             && !zcl_devloop_cycle_proof_complete("rejected", "verify"));
    HF_CHECK(!zcl_devloop_publish_mode_applies(ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY)
             && zcl_devloop_publish_mode_applies(ZCL_DEVLOOP_PUBLISH_APPLY)
             && strcmp(zcl_devloop_publish_mode_name(
                           ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY),
                       "verify")
                    == 0
             && strcmp(zcl_devloop_publish_mode_name(ZCL_DEVLOOP_PUBLISH_APPLY),
                       "auto")
                    == 0
             && zcl_devloop_publish_mode_name((enum zcl_devloop_publish_mode)9)
                    == NULL
             && zcl_devloop_publication_target_port_supported(18252)
             && !zcl_devloop_publication_target_port_supported(18232));
    HF_CHECK(
        strcmp(zcl_devloop_watcher_freshness(false, false, false),
               "watcher_not_running")
            == 0
        && strcmp(zcl_devloop_watcher_freshness(true, false, false),
                  "watcher_starting")
               == 0
        && strcmp(zcl_devloop_watcher_freshness(true, true, false),
                  "runtime_starting")
               == 0
        && strcmp(zcl_devloop_watcher_freshness(true, true, true), "current")
               == 0
        && strcmp(zcl_devloop_watcher_next_action(
                      false, false, false, ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY),
                  "z23-dev dev begin")
               == 0
        && strcmp(zcl_devloop_watcher_next_action(
                      true, true, true, ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY),
                  "edit one C23 file")
               == 0);
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
