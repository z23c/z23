/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter shop-reputation-view-contract.v1
 * for contexts/market/controllers/src/shop_native_reputation.c.
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
#define zcl_hotswap_service_acquire(service_id, lease) \
    ((void)(service_id), (void)(lease), NULL)
#define zcl_hotswap_service_release(lease) ((void)(lease))
#define zcl_hotswap_service_generation(...) 0
#elif ZCL_HOTFORK_STORY_PHASE == 2
#undef zcl_hotswap_service_generation
#undef zcl_hotswap_service_release
#undef zcl_hotswap_service_acquire
#include "../../../contexts/market/services/src/shop_reputation_view_service.c"
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
    uint8_t roots[2][32] = {{0}};
    roots[0][0] = 1;
    roots[1][0] = 2;
    uint8_t one[32] = {1}, three[32] = {3};
    HF_CHECK(rep_root_seen(roots, 2, one) && !rep_root_seen(roots, 2, three));
    struct shop_rep_pair pairs[1];
    memset(pairs, 0, sizeof(pairs));
    pairs[0].package_root[0] = 1;
    pairs[0].recipe_root[0] = 2;
    uint8_t two[32] = {2};
    HF_CHECK(rep_pair_seen(pairs, 1, one, two)
             && !rep_pair_seen(pairs, 1, one, three));
    const struct zcl_hotswap_service_contract *contract =
        zcl_native_shop_reputation_view_service_contract();
    char why[160] = {0};
    HF_CHECK(contract
             && strcmp(contract->service_id, SHOP_REPUTATION_VIEW_SERVICE_ID)
                    == 0
             && contract->frozen_kat);
    HF_CHECK(contract && contract->frozen_kat
             && contract->frozen_kat(shop_reputation_view_service_builtin(),
                                     why, sizeof(why)));
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
