/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter shop-want-view-contract.v1
 * for contexts/market/controllers/src/shop_native_want_view_contract.c.
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
#elif ZCL_HOTFORK_STORY_PHASE == 2
#undef zcl_hotswap_service_release
#undef zcl_hotswap_service_acquire
#include "../../../contexts/market/services/src/shop_want_view_service.c"
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
    struct shop_want row;
    memset(&row, 0, sizeof(row));
    row.want.amount_zatoshi = 500000;
    row.want.criteria_len = 5;
    memcpy(row.want.criteria, "proof", 5);
    row.want.issued_unix = 100;
    row.want.expires_unix = 200;
    row.review_state = 1;
    row.want_id[0] = 1;
    row.want.buyer_pubkey[0] = 2;
    struct shop_want_view_result_v1 view;
    HF_CHECK(zcl_shop_want_view_render(&row, 150, false, &view));
    HF_CHECK(strcmp(view.state, "open") == 0 && !view.expired
             && strcmp(view.review_state, "reviewed_ok") == 0);
    HF_CHECK(strcmp(view.criteria_preview, "proof") == 0
             && view.amount_zatoshi == 500000 && !view.spec_hash_present);
    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    zcl_shop_want_view_push_json(&doc, &view);
    HF_CHECK(
        json_get_int(json_get(&doc, "amount_zatoshi")) == 500000
        && strcmp(json_get_str(json_get(&doc, "criteria_preview")), "proof")
               == 0
        && !json_get_bool(json_get(&doc, "criteria_truncated")));
    json_free(&doc);
    const struct zcl_hotswap_service_contract *contract =
        zcl_native_shop_want_view_service_contract();
    char why[160] = {0};
    HF_CHECK(contract
             && strcmp(contract->service_id, SHOP_WANT_VIEW_SERVICE_ID) == 0
             && contract->frozen_kat);
    HF_CHECK(contract && contract->frozen_kat
             && contract->frozen_kat(shop_want_view_service_builtin(), why,
                                     sizeof(why)));
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
