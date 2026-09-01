/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Prove source-universe observation remains read-only and refuses
 * incomplete or disagreeing evidence instead of minting an ontology root. */

#include "test/test_core.h"

#include "codeindex/codeindex_source_universe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define CO_FIX "test-tmp/code_ontology_fixture"
#define CO_INVENTORY CO_FIX "/docs/CAPABILITY_INVENTORY.jsonl"

static bool co_write(const char *path, const char *text)
{
    FILE *out = fopen(path, "wb");
    if (!out) return false;
    const size_t len = strlen(text);
    const bool written = fwrite(text, 1, len, out) == len;
    const bool closed = fclose(out) == 0;
    return written && closed;
}

static bool co_fixture(void)
{
    if (system("rm -rf " CO_FIX " && mkdir -p "
               CO_FIX "/lib/demo/include/demo "
               CO_FIX "/lib/demo/src "
               CO_FIX "/tests/harness/src "
               CO_FIX "/tools/dev "
               CO_FIX "/tools/lint "
               CO_FIX "/docs") != 0)
        return false;
    return co_write(CO_FIX "/lib/demo/include/demo/demo.h",
        "/* purpose: Source-universe fixture. */\n"
        "#ifndef CO_DEMO_H\n#define CO_DEMO_H\n"
        "int co_demo(void);\n#endif\n") &&
        co_write(CO_FIX "/lib/demo/src/demo.c",
        "#include \"demo/demo.h\"\nint co_demo(void) { return 23; }\n") &&
        co_write(CO_FIX "/tests/harness/src/test_code_ontology_fixture.c",
        "#include \"demo/demo.h\"\n"
        "int test_code_ontology_fixture(void) { return co_demo() == 23 ? 0 : 1; }\n") &&
        co_write(CO_FIX "/tools/dev/test_group_catalog.def",
        "ZCL_TEST_GROUP(code_ontology_fixture)\n") &&
        co_write(CO_FIX "/tools/lint/arm_symbol_single_baseline.txt",
        "# z23-generated-artifact: zcl.generated_artifact.v1\n"
        "# artifact-id: zcl.arm_symbol_single_baseline.v1\n"
        "# asserts: multi_arm_definition(path,symbol)\n"
        "# generated-by: tools/lint/check_arm_symbol_single.sh\n"
        "# regenerate: ZCL_LINT_MODE=UPDATE tools/lint/check_arm_symbol_single.sh\n") &&
        co_write(CO_INVENTORY,
        "{\"record\":\"inventory\",\"files_scanned\":99,"
        "\"production_files\":98,\"test_files\":1}\n");
}

static bool co_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static void co_fill_root(uint8_t root[32], uint8_t seed)
{
    for (size_t i = 0; i < 32; i++) root[i] = (uint8_t)(seed + i);
}

static bool co_component_equal(
    const struct ci_source_universe_component *left,
    const struct ci_source_universe_component *right)
{
    return left->observed == right->observed &&
           left->scope_complete == right->scope_complete &&
           left->whole_scan_stable == right->whole_scan_stable &&
           left->root_available == right->root_available &&
           left->byte_count_available == right->byte_count_available &&
           left->root_domain == right->root_domain &&
           left->path_count == right->path_count &&
           left->total_bytes == right->total_bytes &&
           memcmp(left->root, right->root, sizeof(left->root)) == 0;
}

static bool co_observation_equal(
    const struct ci_source_universe_observation *left,
    const struct ci_source_universe_observation *right)
{
    for (size_t i = 0; i < CI_SOURCE_COMPONENT_COUNT; i++)
        if (!co_component_equal(&left->components[i], &right->components[i]))
            return false;
    return left->all_components_observed == right->all_components_observed &&
           left->evidence_nonempty == right->evidence_nonempty &&
           left->evidence_counts_agree == right->evidence_counts_agree &&
           left->evidence_bytes_agree == right->evidence_bytes_agree &&
           left->component_roots_well_formed ==
               right->component_roots_well_formed &&
           left->same_domain_roots_compared ==
               right->same_domain_roots_compared &&
           left->same_domain_roots_agree == right->same_domain_roots_agree &&
           left->inventory_artifact_present ==
               right->inventory_artifact_present &&
           left->inventory_artifact_count_agrees ==
               right->inventory_artifact_count_agrees &&
           left->inventory_artifact_root_agrees ==
               right->inventory_artifact_root_agrees &&
           left->inventory_fresh == right->inventory_fresh &&
           left->projection_observed_mask == right->projection_observed_mask &&
           left->projection_proven_mask == right->projection_proven_mask &&
           left->projection_unavailable_mask ==
               right->projection_unavailable_mask &&
           left->projection_missing_mask == right->projection_missing_mask &&
           left->projection_masks_consistent ==
               right->projection_masks_consistent &&
           left->complete == right->complete &&
           left->verified == right->verified &&
           left->refusal == right->refusal;
}

static void co_exact_input(struct ci_source_universe_reconcile_input *input)
{
    memset(input, 0, sizeof(*input));
    for (size_t i = 0; i < CI_SOURCE_COMPONENT_COUNT; i++) {
        struct ci_source_universe_component *c = &input->components[i];
        c->observed = true;
        c->root_available = true;
        c->byte_count_available = true;
        c->root_domain = CI_SOURCE_ROOT_VCS_MANIFEST_V1;
        c->path_count = 7;
        c->total_bytes = 700;
        co_fill_root(c->root, 20);
    }
    input->inventory_artifact_present = true;
    input->inventory_artifact_files = 7;
    input->inventory_artifact_root_available = true;
    input->inventory_artifact_root_domain = CI_SOURCE_ROOT_VCS_MANIFEST_V1;
    memcpy(input->inventory_artifact_root,
           input->components[CI_SOURCE_COMPONENT_CAPABILITY_INVENTORY].root,
           32);
    input->projection_observed_mask = ZCL_SOURCE_COVER_ALL;
}

static int co_equal_count_different_root(void)
{
    int failures = 0;
    TEST("code_ontology: equal counts cannot hide same-domain root conflict") {
        struct ci_source_universe_reconcile_input input;
        struct ci_source_universe_observation out;
        co_exact_input(&input);
        co_fill_root(input.components[CI_SOURCE_COMPONENT_SCIENCE_CENSUS].root,
                     81);
        ASSERT(ci_source_universe_reconcile(&input, &out));
        ASSERT(out.evidence_counts_agree);
        ASSERT(out.evidence_bytes_agree);
        ASSERT(out.same_domain_roots_compared);
        ASSERT(!out.same_domain_roots_agree);
        ASSERT(!out.complete && !out.verified);
        ASSERT(out.refusal == CI_SOURCE_UNIVERSE_REFUSAL_EVIDENCE_DISAGREES);
        PASS();
    } _test_next:;
    return failures;
}

static int co_stale_inventory(void)
{
    int failures = 0;
    TEST("code_ontology: stale inventory refuses even when every count agrees") {
        struct ci_source_universe_reconcile_input input;
        struct ci_source_universe_observation out;
        co_exact_input(&input);
        co_fill_root(input.inventory_artifact_root, 99);
        ASSERT(ci_source_universe_reconcile(&input, &out));
        ASSERT(out.projection_masks_consistent);
        ASSERT(out.inventory_artifact_count_agrees);
        ASSERT(!out.inventory_artifact_root_agrees);
        ASSERT(!out.inventory_fresh);
        ASSERT(!out.complete && !out.verified);
        ASSERT(out.refusal == CI_SOURCE_UNIVERSE_REFUSAL_INVENTORY_STALE);
        PASS();
    } _test_next:;
    return failures;
}

static int co_missing_projections(void)
{
    int failures = 0;
    TEST("code_ontology: unavailable projections are named and fail closed") {
        struct ci_source_universe_reconcile_input input;
        struct ci_source_universe_observation out;
        co_exact_input(&input);
        input.projection_observed_mask =
            ZCL_SOURCE_COVER_GOVERNED | ZCL_SOURCE_COVER_INDEXED;
        input.projection_unavailable_mask =
            ZCL_SOURCE_COVER_GENERATED | ZCL_SOURCE_COVER_VENDOR |
            ZCL_SOURCE_COVER_METADATA | ZCL_SOURCE_COVER_PUBLISHABLE |
            ZCL_SOURCE_COVER_CONSENSUS;
        ASSERT(ci_source_universe_reconcile(&input, &out));
        ASSERT(out.projection_masks_consistent);
        ASSERT(out.projection_proven_mask == 0);
        ASSERT(!out.complete && !out.verified);
        ASSERT((out.projection_missing_mask &
                input.projection_unavailable_mask) ==
               input.projection_unavailable_mask);
        ASSERT_STR_EQ(ci_source_universe_projection_name(
                          ZCL_SOURCE_COVER_GENERATED), "generated");
        ASSERT_STR_EQ(ci_source_universe_projection_name(
                          ZCL_SOURCE_COVER_VENDOR), "vendor");
        ASSERT_STR_EQ(ci_source_universe_projection_name(
                          ZCL_SOURCE_COVER_METADATA), "metadata");
        ASSERT_STR_EQ(ci_source_universe_projection_name(
                          ZCL_SOURCE_COVER_PUBLISHABLE), "publishable");
        ASSERT(out.refusal == CI_SOURCE_UNIVERSE_REFUSAL_PROJECTIONS_MISSING);
        co_exact_input(&input);
        input.components[0].root_domain =
            (enum ci_source_universe_root_domain)99;
        ASSERT(ci_source_universe_reconcile(&input, &out));
        ASSERT(!out.component_roots_well_formed);
        ASSERT(out.refusal == CI_SOURCE_UNIVERSE_REFUSAL_EVIDENCE_DISAGREES);
        co_exact_input(&input);
        input.projection_observed_mask |= 1u << 31;
        ASSERT(ci_source_universe_reconcile(&input, &out));
        ASSERT(!out.projection_masks_consistent);
        ASSERT(out.refusal == CI_SOURCE_UNIVERSE_REFUSAL_EVIDENCE_DISAGREES);
        PASS();
    } _test_next:;
    return failures;
}

static int co_live_deterministic_read_only(void)
{
    int failures = 0;
    TEST("code_ontology: live observation is deterministic and creates no cache") {
        ASSERT(co_fixture());
        ASSERT(!co_exists(CO_FIX "/.zvcs"));
        ASSERT(!co_exists(CO_FIX "/.codeindex"));
        struct ci_source_universe_observation first, second;
        ASSERT(ci_source_universe_observe(CO_FIX, CO_INVENTORY, &first));
        ASSERT(ci_source_universe_observe(CO_FIX, CO_INVENTORY, &second));
        ASSERT(co_observation_equal(&first, &second));
        ASSERT(first.all_components_observed);
        ASSERT(first.projection_observed_mask == 0);
        ASSERT(first.projection_unavailable_mask == ZCL_SOURCE_COVER_ALL);
        ASSERT(!first.components[CI_SOURCE_COMPONENT_VCS_MANIFEST]
                    .scope_complete);
        ASSERT(!first.components[CI_SOURCE_COMPONENT_VCS_MANIFEST]
                    .whole_scan_stable);
        ASSERT_STR_EQ(ci_source_universe_component_scope_name(
                          CI_SOURCE_COMPONENT_VCS_MANIFEST),
                      "vcs_walk_regular_files_with_ignores.candidate.v1");
        ASSERT(first.components[CI_SOURCE_COMPONENT_VCS_MANIFEST].root_available);
        ASSERT(first.components[CI_SOURCE_COMPONENT_CODE_MERKLE].root_available);
        ASSERT(first.components[CI_SOURCE_COMPONENT_CAPABILITY_INVENTORY]
                   .root_available);
        ASSERT(!first.components[CI_SOURCE_COMPONENT_SCIENCE_CENSUS]
                    .root_available);
        ASSERT(first.inventory_artifact_present);
        ASSERT(!first.inventory_artifact_count_agrees);
        ASSERT(!first.inventory_fresh);
        ASSERT(!first.complete && !first.verified);
        ASSERT((first.projection_unavailable_mask &
                (ZCL_SOURCE_COVER_GENERATED | ZCL_SOURCE_COVER_VENDOR |
                 ZCL_SOURCE_COVER_METADATA | ZCL_SOURCE_COVER_PUBLISHABLE)) ==
               (ZCL_SOURCE_COVER_GENERATED | ZCL_SOURCE_COVER_VENDOR |
                ZCL_SOURCE_COVER_METADATA | ZCL_SOURCE_COVER_PUBLISHABLE));
        ASSERT(!co_exists(CO_FIX "/.zvcs"));
        ASSERT(!co_exists(CO_FIX "/.codeindex"));
        ASSERT(system("rm -rf " CO_FIX) == 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_code_ontology(void)
{
    int failures = 0;
    failures += co_equal_count_different_root();
    failures += co_stale_inventory();
    failures += co_missing_projections();
    failures += co_live_deterministic_read_only();
    return failures;
}
