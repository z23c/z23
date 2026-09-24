/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter zcode-package-view-contract.v1
 * for tools/command/native_zcode_package_view_command.c.
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
#include "../../../contexts/commons/services/src/zcode_package_view_service.c"
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
    const struct zcl_hotswap_service_contract *contract =
        zcl_native_zcode_package_view_service_contract();
    char why[160] = {0};
    HF_CHECK(contract
             && strcmp(contract->service_id, ZCODE_PACKAGE_VIEW_SERVICE_ID) == 0
             && contract->frozen_kat);
    HF_CHECK(contract && contract->frozen_kat
             && contract->frozen_kat(zcode_package_view_service_builtin(), why,
                                     sizeof(why)));
#undef HF_CHECK
    snprintf(out->exercised_surface, sizeof(out->exercised_surface),
             ZCL_HOTFORK_EXERCISED_SURFACE);
    snprintf(out->detail, sizeof(out->detail), "checks=%u/%u;failed_mask=0x%x",
             out->checks_passed, out->checks_run, failed);
    return out->checks_run == 2 && out->checks_passed == 2;
}
#else
#error "unknown HOT_FORK story phase"
#endif
