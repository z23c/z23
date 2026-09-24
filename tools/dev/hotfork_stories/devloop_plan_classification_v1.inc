/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter devloop-plan-classification.v1
 * for tools/dev/devloop_plan.c.
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
    unsigned failed = 0;
#define HF_CHECK(x) \
    do { \
        unsigned n = out->checks_run++; \
        if (x) \
            out->checks_passed++; \
        else \
            failed |= 1u << n; \
    } while (0)
    HF_CHECK(path_is_safe("tools/dev/a.c") && !path_is_safe("../a.c")
             && !path_is_safe("/a.c") && !path_is_safe("a\\b.c")
             && !path_is_safe(NULL));
    HF_CHECK(path_is_docs("docs/a.md") && path_is_docs("README.md")
             && !path_is_docs("lib/a.c")
             && zcl_devloop_path_is_sealed_core("core/math/a.c")
             && !zcl_devloop_path_is_sealed_core("lib/a.c"));
    HF_CHECK(zcl_devloop_path_is_relevant("lib/a.c")
             && zcl_devloop_path_is_relevant("Makefile")
             && !zcl_devloop_path_is_relevant("build/a.c")
             && !zcl_devloop_path_is_relevant("lib/a.c~")
             && !zcl_devloop_path_is_relevant("lib/_x_fixture.c"));
    HF_CHECK(zcl_devloop_watch_event_is_mutation(IN_CLOSE_WRITE)
             && zcl_devloop_watch_event_is_mutation(IN_DELETE)
             && !zcl_devloop_watch_event_is_mutation(IN_ATTRIB));
    HF_CHECK(zcl_devloop_watch_dir_is_ignored("build")
             && zcl_devloop_watch_dir_is_ignored(".cache")
             && !zcl_devloop_watch_dir_is_ignored("lib"));
    HF_CHECK(
        strcmp(zcl_devloop_dim_name(ZCL_DEVLOOP_DIM_OPAQUE), "opaque") == 0
        && strcmp(zcl_devloop_dim_name(ZCL_DEVLOOP_DIM_SEMANTIC), "semantic")
               == 0
        && strcmp(zcl_devloop_dim_status_name(ZCL_DEVLOOP_DIM_COMPLETE),
                  "complete")
               == 0
        && strcmp(zcl_devloop_dim_status_name(ZCL_DEVLOOP_DIM_UNAVAILABLE),
                  "unavailable")
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
