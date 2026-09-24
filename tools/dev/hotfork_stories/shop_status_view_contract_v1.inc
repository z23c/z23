/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter shop-status-view-contract.v1
 * for contexts/market/controllers/src/shop_native_handler.c.
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
#include "../../../contexts/market/services/src/shop_status_view_service.c"
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
    HF_CHECK(shop_status_wallet(SHOP_WALLET_ABSENT) == SHOP_STATUS_WALLET_ABSENT
             && shop_status_wallet(SHOP_WALLET_PLAINTEXT)
                    == SHOP_STATUS_WALLET_PLAINTEXT
             && shop_status_wallet(SHOP_WALLET_ENCRYPTED)
                    == SHOP_STATUS_WALLET_ENCRYPTED
             && shop_status_wallet(SHOP_WALLET_UNREADABLE)
                    == SHOP_STATUS_WALLET_UNREADABLE);
    struct shop_snapshot closed = {.wallet = SHOP_WALLET_ABSENT,
                                   .schema_version = -1,
                                   .product_count = -1};
    struct shop_status_view_result_v1 view;
    HF_CHECK(shop_status_render(&closed, &view) && !view.shop_live
             && view.gap_count == 5
             && strcmp(view.gaps[0].gap, "tor_stub_build") == 0
             && strcmp(view.gaps[4].gap, "shop_not_announced") == 0);
    struct shop_snapshot live = {.tor_real = true,
                                 .identity_present = true,
                                 .wallet = SHOP_WALLET_ENCRYPTED,
                                 .node_db_present = true,
                                 .store_schema = true,
                                 .schema_version = 1,
                                 .product_count = 3,
                                 .announced = true};
    snprintf(live.address, sizeof(live.address), "example");
    HF_CHECK(shop_status_render(&live, &view) && view.shop_live
             && view.gap_count == 0
             && strcmp(view.wallet_posture, "encrypted") == 0
             && strcmp(view.shop_url, "http://example.onion/store") == 0);
    const struct zcl_hotswap_service_contract *contract =
        zcl_native_shop_status_view_service_contract();
    char why[160] = {0};
    HF_CHECK(contract
             && strcmp(contract->service_id, SHOP_STATUS_VIEW_SERVICE_ID) == 0
             && contract->frozen_kat
             && contract->frozen_kat(shop_status_view_service_builtin(), why,
                                     sizeof(why)));
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
