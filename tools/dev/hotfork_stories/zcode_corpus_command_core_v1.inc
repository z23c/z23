/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter zcode-corpus-command-core.v1
 * for tools/command/native_zcode_corpus_command.c.
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
#include "hotswap/hotswap_service.h"
#define zcl_hotswap_service_acquire(...) NULL
#define zcl_hotswap_service_release(...) ((void)0)
#define zcl_hotswap_service_generation(...) 0
#elif ZCL_HOTFORK_STORY_PHASE == 2
#undef zcl_hotswap_service_generation
#undef zcl_hotswap_service_release
#undef zcl_hotswap_service_acquire
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
    const char *lower =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const char *upper =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeF";
    HF_CHECK(lowercase_root(lower) && !lowercase_root(upper)
             && !lowercase_root("abcd") && !lowercase_root(NULL));
    struct vcs_zcode_c23_corpus_checkpoint_v1 checkpoint = {0};
    checkpoint.production_loc = 7;
    checkpoint.test_loc = 5;
    uint64_t total = 0;
    HF_CHECK(corpus_checkpoint_renderable(&checkpoint, &total) && total == 12);
    checkpoint.production_loc = UINT64_MAX;
    checkpoint.test_loc = 1;
    HF_CHECK(!corpus_checkpoint_renderable(&checkpoint, &total)
             && !corpus_checkpoint_renderable(NULL, &total));
    struct vcs_zcode_c23_corpus_entry_v1 entries[2] = {{0}};
    entries[0].production_loc = 3;
    entries[0].test_loc = 2;
    entries[0].physical_lines = 6;
    entries[0].unique_semantic_units = 2;
    entries[0].flags =
        VCS_ZCODE_C23_ENTRY_COUNTED | VCS_ZCODE_C23_ENTRY_DURABLE;
    entries[1].production_loc = 4;
    entries[1].test_loc = 1;
    entries[1].physical_lines = 8;
    entries[1].unique_semantic_units = 3;
    struct vcs_zcode_c23_corpus_shard_v1 shard = {.entries = entries,
                                                  .entry_count = 2};
    struct corpus_shard_metrics metrics;
    HF_CHECK(corpus_shard_metrics_collect(&shard, &metrics)
             && metrics.counted_entries == 1 && metrics.durable_entries == 1
             && metrics.excluded_entries == 1 && metrics.production_loc == 7
             && metrics.test_loc == 3 && metrics.total_loc == 10
             && metrics.durable_loc == 5 && metrics.physical_lines == 14
             && metrics.unique_semantic_units == 5);
    entries[1].production_loc = UINT64_MAX;
    HF_CHECK(!corpus_shard_metrics_collect(&shard, &metrics)
             && !corpus_shard_metrics_collect(NULL, &metrics));
#undef HF_CHECK
    snprintf(out->exercised_surface, sizeof(out->exercised_surface),
             ZCL_HOTFORK_EXERCISED_SURFACE);
    snprintf(out->detail, sizeof(out->detail), "checks=%u/%u;failed_mask=0x%x",
             out->checks_passed, out->checks_run, failed);
    return out->checks_run == 5 && out->checks_passed == 5;
}
#else
#error "unknown HOT_FORK story phase"
#endif
