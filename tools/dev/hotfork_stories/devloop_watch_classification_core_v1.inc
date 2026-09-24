/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter devloop-watch-classification-core.v1
 * for tools/dev/devloop_watch.c.
 * Compiled only inside the capsule unity rendered by
 * tools/dev/hotfork_unity.h: phase 1 precedes the owner TU set, phase 2
 * follows it. check-hotfork-stories compiles every unity with the frozen
 * dev flags, so an owner API change cannot silently disable this story.
 */
#if !defined(ZCL_HOTFORK_STORY_PHASE)
#error "HOT_FORK stories are included only by the generated capsule unity"
#elif ZCL_HOTFORK_STORY_PHASE == 1
#define _GNU_SOURCE
#define ZCL_HOTFORK_DEVLOOP_WATCH_CORE 1
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
    HF_CHECK(watch_c_source("tools/dev/a.c") && !watch_c_source("tools/dev/a.h")
             && !watch_c_source("tools/dev/a.C") && !watch_c_source(NULL));
    const char *all_c[] = {"tools/dev/a.c", "tools/dev/b.c"};
    const char *mixed[] = {"tools/dev/a.c", "tools/dev/b.h"};
    HF_CHECK(watch_epoch_all_c(all_c, 2) && !watch_epoch_all_c(mixed, 2)
             && !watch_epoch_all_c(NULL, 2) && !watch_epoch_all_c(all_c, 0));
    char component[128];
    watch_component_for_files(all_c, 2, component);
    HF_CHECK(strcmp(component, "tools/dev") == 0);
    const char *owners[] = {"tools/dev/a.c",
                            "contexts/commons/modules/vcs/a.c"};
    watch_component_for_files(owners, 2, component);
    bool mixed_ok = strcmp(component, "mixed") == 0;
    const char *root[] = {"Makefile"};
    watch_component_for_files(root, 1, component);
    HF_CHECK(mixed_ok && strcmp(component, "Makefile") == 0);
#undef HF_CHECK
    snprintf(out->exercised_surface, sizeof(out->exercised_surface),
             ZCL_HOTFORK_EXERCISED_SURFACE);
    snprintf(out->detail, sizeof(out->detail), "checks=%u/%u;failed_mask=0x%x",
             out->checks_passed, out->checks_run, failed);
    return out->checks_run == 4 && out->checks_passed == 4;
}
#else
#error "unknown HOT_FORK story phase"
#endif
