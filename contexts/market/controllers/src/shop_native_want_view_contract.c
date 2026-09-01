/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Resident-owned contract and frozen KAT for the pure buyer-want view. */

#include "controllers/shop_native_want_view.h"

#include "hotswap/hotswap_service.h"

#include <stdio.h>
#include <string.h>

bool zcl_shop_want_view_render(const struct shop_want *row, int64_t now_unix,
                               bool full,
                               struct shop_want_view_result_v1 *out)
{
    if (!row || !out || row->want.criteria_len == 0 ||
        row->want.criteria_len > SHOP_WANT_VIEW_CRITERIA_MAX)
        return false;
    struct shop_want_view_input_v1 input = {
        .amount_zatoshi = row->want.amount_zatoshi,
        .criteria_len = row->want.criteria_len,
        .issued_unix = row->want.issued_unix,
        .expires_unix = row->want.expires_unix,
        .cancelled_unix = row->cancelled_unix,
        .posted_unix = row->posted_unix,
        .now_unix = now_unix,
        .review_state = row->review_state,
        .full = full,
    };
    memcpy(input.want_id, row->want_id, sizeof(input.want_id));
    memcpy(input.buyer_pubkey, row->want.buyer_pubkey,
           sizeof(input.buyer_pubkey));
    memcpy(input.spec_hash, row->want.spec_hash, sizeof(input.spec_hash));
    memcpy(input.criteria, row->want.criteria, row->want.criteria_len);
    struct zcl_hotswap_service_lease lease = {0};
    const struct shop_want_view_service_v1 *service =
        zcl_hotswap_service_acquire(SHOP_WANT_VIEW_SERVICE_ID, &lease);
    if (!service)
        service = shop_want_view_service_builtin();
    bool ok = service->render(&input, out);
    zcl_hotswap_service_release(&lease);
    return ok;
}

void zcl_shop_want_view_push_json(
    struct json_value *into, const struct shop_want_view_result_v1 *view)
{
    if (!into || !view)
        return;
    (void)json_push_kv_str(into, "want_id", view->want_id);
    (void)json_push_kv_str(into, "buyer_pubkey", view->buyer_pubkey);
    (void)json_push_kv_int(into, "amount_zatoshi",
                           (int64_t)view->amount_zatoshi);
    if (view->full)
        (void)json_push_kv_str(into, "criteria", view->criteria);
    else {
        (void)json_push_kv_str(into, "criteria_preview",
                               view->criteria_preview);
        (void)json_push_kv_bool(into, "criteria_truncated",
                                view->criteria_truncated);
    }
    if (view->spec_hash_present)
        (void)json_push_kv_str(into, "spec_hash", view->spec_hash);
    (void)json_push_kv_int(into, "issued_unix", view->issued_unix);
    (void)json_push_kv_int(into, "expires_unix", view->expires_unix);
    (void)json_push_kv_bool(into, "expired", view->expired);
    (void)json_push_kv_str(into, "review_state", view->review_state);
    (void)json_push_kv_str(into, "next_action", view->next_action);
    if (view->cancelled_unix > 0)
        (void)json_push_kv_int(into, "cancelled_unix",
                               view->cancelled_unix);
    if (view->full)
        (void)json_push_kv_int(into, "posted_unix", view->posted_unix);
}

static bool shop_want_view_frozen_kat(const void *opaque, char *why,
                                      size_t why_sz)
{
    const struct shop_want_view_service_v1 *service = opaque;
    struct shop_want_view_input_v1 input = {
        .amount_zatoshi = 500000u,
        .criteria_len = 200u,
        .issued_unix = 100,
        .expires_unix = 200,
        .now_unix = 150,
        .review_state = 1,
    };
    input.want_id[0] = 1;
    input.buyer_pubkey[0] = 2;
    memset(input.criteria, 'x', input.criteria_len);
    struct shop_want_view_result_v1 out;
    if (!service || !service->render || !service->render_fulfillment_status ||
        !service->render(&input, &out) ||
        strcmp(out.state, "open") != 0 || out.expired ||
        strcmp(out.review_state, "reviewed_ok") != 0 ||
        !out.criteria_truncated ||
        strlen(out.criteria_preview) != SHOP_WANT_VIEW_CRITERIA_PREVIEW ||
        out.want_id[0] != '0' || out.want_id[1] != '1' ||
        out.spec_hash_present || strstr(out.next_action, "moves no value") == NULL) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen buyer-want open/preview vector failed");
        return false;
    }
    struct shop_fulfill_status_view_input_v1 status = {
        .signature_valid = true,
        .evidence_valid = true,
    };
    struct shop_fulfill_status_view_result_v1 status_out;
    if (!service->render_fulfillment_status(&status, &status_out) ||
        strcmp(status_out.readiness, "hidden_by_profile") != 0 ||
        strcmp(status_out.next_action, "app shop want fulfill review") != 0) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen fulfillment hidden vector failed");
        return false;
    }
    status.visible = true;
    if (!service->render_fulfillment_status(&status, &status_out) ||
        strcmp(status_out.readiness, "ready_for_human_review") != 0) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen fulfillment visible vector failed");
        return false;
    }
    status.evidence_valid = false;
    if (!service->render_fulfillment_status(&status, &status_out) ||
        strcmp(status_out.readiness, "blocked_by_evidence") != 0) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen fulfillment evidence vector failed");
        return false;
    }
    status.withdrawn = true;
    if (!service->render_fulfillment_status(&status, &status_out) ||
        strcmp(status_out.readiness, "closed") != 0) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen fulfillment closed vector failed");
        return false;
    }
    input.full = true;
    input.cancelled_unix = 175;
    input.spec_hash[0] = 3;
    if (!service->render(&input, &out) ||
        strcmp(out.state, "cancelled") != 0 || !out.spec_hash_present ||
        strlen(out.criteria) != input.criteria_len ||
        strstr(out.next_action, "moves no value") == NULL) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen buyer-want cancelled/full vector failed");
        return false;
    }
    input.review_state = 99;
    if (service->render(&input, &out)) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen buyer-want invalid-state vector failed");
        return false;
    }
    return true;
}

static const struct zcl_hotswap_service_contract k_shop_want_contract = {
    .service_id = SHOP_WANT_VIEW_SERVICE_ID,
    .source_tu = "contexts/market/services/src/shop_want_view_service.c",
    .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
    .vtable_size = sizeof(struct shop_want_view_service_v1),
    .abi_fingerprint = SHOP_WANT_VIEW_ABI_FINGERPRINT,
    .schema_fingerprint = SHOP_WANT_VIEW_SCHEMA_FINGERPRINT,
    .wire_fingerprint = SHOP_WANT_VIEW_WIRE_FINGERPRINT,
    .kat_fingerprint = SHOP_WANT_VIEW_KAT_FINGERPRINT,
    .frozen_kat = shop_want_view_frozen_kat,
};

const struct zcl_hotswap_service_contract *
zcl_native_shop_want_view_service_contract(void)
{
    return &k_shop_want_contract;
}
