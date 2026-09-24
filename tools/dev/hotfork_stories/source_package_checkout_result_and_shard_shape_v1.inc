/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter source-package-checkout-result-and-shard-shape.v1
 * for contexts/commons/modules/vcs/src/source_package_checkout.c.
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
    static const char *const expected[] = {"ok",
                                           "null-argument",
                                           "package-incomplete",
                                           "package-manifest",
                                           "source-carrier-shape",
                                           "package-chunk",
                                           "source-verification",
                                           "destination"};
    if (!out) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->magic = ZCL_HOTFORK_OBSERVATION_MAGIC;
    for (unsigned i = 0; i < 8; i++) {
        out->checks_run++;
        if (strcmp(vcs_source_package_checkout_result_string(
                       (enum vcs_source_package_checkout_result)i),
                   expected[i])
            == 0)
            out->checks_passed++;
    }
    uint16_t shard = 0;
    out->checks_run++;
    if (source_checkout_shard_index("zclassic23-source/shard-0a.zvss", &shard)
        && shard == 10)
        out->checks_passed++;
    out->checks_run++;
    if (source_checkout_shard_index("zclassic23-source/shard-ff.zvss", &shard)
        && shard == 255)
        out->checks_passed++;
    static const char *const bad[] = {"zclassic23-source/shard-0A.zvss",
                                      "zclassic23-source/shard-100.zvss",
                                      "zclassic23-source/shard-0a"};
    for (unsigned i = 0; i < 3; i++) {
        out->checks_run++;
        if (!source_checkout_shard_index(bad[i], &shard))
            out->checks_passed++;
    }
    snprintf(out->exercised_surface, sizeof(out->exercised_surface),
             ZCL_HOTFORK_EXERCISED_SURFACE);
    snprintf(out->detail, sizeof(out->detail), "checks=%u/%u",
             out->checks_passed, out->checks_run);
    return out->checks_run == 13 && out->checks_passed == 13;
}
#else
#error "unknown HOT_FORK story phase"
#endif
