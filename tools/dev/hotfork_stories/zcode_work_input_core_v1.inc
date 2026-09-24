/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter zcode-work-input-core.v1
 * for tools/command/native_zcode_work_command.c.
 * Compiled only inside the capsule unity rendered by
 * tools/dev/hotfork_unity.h: phase 1 precedes the owner TU set, phase 2
 * follows it. check-hotfork-stories compiles every unity with the frozen
 * dev flags, so an owner API change cannot silently disable this story.
 */
#if !defined(ZCL_HOTFORK_STORY_PHASE)
#error "HOT_FORK stories are included only by the generated capsule unity"
#elif ZCL_HOTFORK_STORY_PHASE == 1
#define _GNU_SOURCE
#define ZCL_HOTFORK_ZWORK_INPUT_CORE 1
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
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    json_push_kv_str(&input, "goal", "ship");
    json_push_kv_int(&input, "budget", 7);
    HF_CHECK(strcmp(zwork_str(&input, "goal"), "ship") == 0
             && zwork_str(&input, "budget") == NULL);
    HF_CHECK(zwork_int(&input, "budget", 3) == 7
             && zwork_int(&input, "missing", 3) == 3);
    json_free(&input);
    char scopes[1024] = {0};
    HF_CHECK(zwork_scope_add(scopes, "lib/a.c")
             && zwork_scope_add(scopes, "lib/b.c")
             && zwork_scope_add(scopes, "app/x.c")
             && !zwork_scope_add(scopes, "") && strcmp(scopes, "lib,app") == 0);
    char *headers[] = {"include/a.h"};
    char *sources[] = {"src/a.c", "include/b.c"};
    char *tests[] = {"tests/a.c"};
    /* zwork_scopes() takes the prepared package since a2fbd77c4a; an empty
     * manifest and no package metadata keep this the recipe-only scope. */
    struct vcs_package_prepared scoped;
    memset(&scoped, 0, sizeof(scoped));
    scoped.recipe.public_headers =
        (struct vcs_package_recipe_strings){headers, 1, 1};
    scoped.recipe.sources = (struct vcs_package_recipe_strings){sources, 2, 2};
    scoped.recipe.test_sources =
        (struct vcs_package_recipe_strings){tests, 1, 1};
    HF_CHECK(zwork_scopes(&scoped, false, scopes)
             && strcmp(scopes, "include,src,tests") == 0);
    struct vcs_package_prepared prepared;
    memset(&prepared, 0, sizeof(prepared));
    char *prepared_sources[] = {"src/a.c", "src/missing.c"};
    struct vcs_package_file files[2] = {{.path = "src/a.c", .size = 11},
                                        {.path = "other.c", .size = 99}};
    prepared.recipe.sources =
        (struct vcs_package_recipe_strings){prepared_sources, 2, 2};
    prepared.manifest = (struct vcs_package_manifest){files, 2, 2};
    HF_CHECK(zwork_source_bytes(&prepared) == 11);
    prepared_sources[1] = "other.c";
    prepared.manifest.files[0].size = UINT64_MAX;
    prepared.manifest.files[1].size = 1;
    HF_CHECK(zwork_source_bytes(&prepared) == 0);
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
