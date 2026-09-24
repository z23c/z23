/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter test-group-catalog-selection-policy.v1
 * for tools/dev/test_group_catalog.c.
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
    char resolved[ZCL_TEST_GROUP_FULL_MAX];
    HF_CHECK(zcl_test_group_catalog_count() > 100);
    HF_CHECK(zcl_test_group_catalog_contains("test_dev_platform")
             && !zcl_test_group_catalog_contains("dev_platform"));
    HF_CHECK(
        zcl_test_group_requires_exclusive_run("test_command_registry_latency")
        && zcl_test_group_requires_exclusive_run("test_sapling_crypto")
        && zcl_test_group_requires_exclusive_run("test_vcs_core")
        && zcl_test_group_requires_exclusive_run(
            "test_validate_parallel_determinism")
        && !zcl_test_group_requires_exclusive_run("test_dev_platform"));
    /* test_dev_platform became a semantic leaf in 0a32c833f2; the non-leaf
     * side of this check uses a test source that is still an ordinary one. */
    HF_CHECK(zcl_test_group_source_is_semantic_leaf(
                 "tests/harness/src/test_stage_repair_coin_backfill.c")
             && !zcl_test_group_source_is_semantic_leaf(
                 "tests/harness/src/test_vcs_core.c"));
    HF_CHECK(zcl_test_group_resolve_exact("dev_platform", resolved)
             && strcmp(resolved, "test_dev_platform") == 0);
    HF_CHECK(zcl_test_group_resolve_exact("test_dev_platform", resolved)
             && !zcl_test_group_resolve_exact("dev_plat", resolved));
    HF_CHECK(
        zcl_test_group_plan_selects("oracle_policy", "test_zclassicd_oracle")
        && !zcl_test_group_plan_selects("dev_platform",
                                        "test_zclassicd_oracle"));
    HF_CHECK(zcl_test_group_is_integration_only("test_test_group_selector")
             && !zcl_test_group_is_integration_only("test_dev_platform")
             && zcl_test_group_integration_policy_valid());
    const char *ordinary[] = {"dev_platform"};
    char groups[2][ZCL_TEST_GROUP_FULL_MAX];
    bool truncated = false;
    size_t count =
        zcl_test_group_expand_plan(ordinary, 1, groups, 2, &truncated);
    HF_CHECK(count == 1 && !truncated
             && strcmp(groups[0], "test_dev_platform") == 0);
    const char *integration[] = {"test_group_selector"};
    count = zcl_test_group_expand_plan_immediate(integration, 1, groups, 2,
                                                 &truncated);
    HF_CHECK(count == 0 && !truncated);
#undef HF_CHECK
    snprintf(out->exercised_surface, sizeof(out->exercised_surface),
             ZCL_HOTFORK_EXERCISED_SURFACE);
    snprintf(out->detail, sizeof(out->detail), "checks=%u/%u;failed_mask=0x%x",
             out->checks_passed, out->checks_run, failed);
    return out->checks_run == 10 && out->checks_passed == 10;
}
#else
#error "unknown HOT_FORK story phase"
#endif
