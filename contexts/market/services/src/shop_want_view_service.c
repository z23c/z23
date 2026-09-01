/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure signed buyer-want rendering. Keys, verification, storage, clocks,
 * moderation policy, networking, and settlement remain in static callers. */
// one-result-type-ok:pure-vtable-uses-bounded-caller-owned-output-only

#include "services/shop_want_view_service.h"

#include "base/bytes.h"
#include "base/hex.h"
#include "hotswap/hotswap_service.h"
#include "shop_want_view_internal.h"

#include <stdio.h>
#include <string.h>

static const char *review_name(int review_state)
{
    switch (review_state) {
    case 0: return "unreviewed";
    case 1: return "reviewed_ok";
    case 2: return "sensitive";
    }
    return NULL;
}

static bool render(const struct shop_want_view_input_v1 *input,
                   struct shop_want_view_result_v1 *out)
{
    const char *review = input ? review_name(input->review_state) : NULL;
    if (!input || !out || !review || input->criteria_len == 0 ||
        input->criteria_len > SHOP_WANT_VIEW_CRITERIA_MAX ||
        input->amount_zatoshi == 0 || input->issued_unix <= 0 ||
        input->expires_unix <= input->issued_unix || input->now_unix <= 0)
        return false;

    memset(out, 0, sizeof(*out));
    zcl_hex_encode(input->want_id, sizeof(input->want_id), out->want_id);
    zcl_hex_encode(input->buyer_pubkey, sizeof(input->buyer_pubkey),
                   out->buyer_pubkey);
    out->spec_hash_present = zcl_bytes_any_set(input->spec_hash,
                                           sizeof(input->spec_hash));
    if (out->spec_hash_present)
        zcl_hex_encode(input->spec_hash, sizeof(input->spec_hash),
                       out->spec_hash);
    out->amount_zatoshi = input->amount_zatoshi;
    out->full = input->full;
    if (input->full) {
        memcpy(out->criteria, input->criteria, input->criteria_len);
        out->criteria[input->criteria_len] = '\0';
    } else {
        size_t n = input->criteria_len;
        out->criteria_truncated = n > SHOP_WANT_VIEW_CRITERIA_PREVIEW;
        if (out->criteria_truncated)
            n = SHOP_WANT_VIEW_CRITERIA_PREVIEW;
        memcpy(out->criteria_preview, input->criteria, n);
        out->criteria_preview[n] = '\0';
    }
    out->issued_unix = input->issued_unix;
    out->expires_unix = input->expires_unix;
    out->cancelled_unix = input->cancelled_unix;
    out->posted_unix = input->posted_unix;
    out->expired = input->expires_unix <= input->now_unix;
    (void)snprintf(out->review_state, sizeof(out->review_state), "%s", review);
    const char *state;
    const char *next;
    if (input->cancelled_unix > 0) {
        state = "cancelled";
        next = SHOP_WANT_NEXT_CANCELLED;
    } else if (out->expired) {
        state = "expired";
        next = SHOP_WANT_NEXT_EXPIRED;
    } else {
        state = "open";
        next = SHOP_WANT_NEXT_OPEN;
    }
    (void)snprintf(out->state, sizeof(out->state), "%s", state);
    (void)snprintf(out->next_action, sizeof(out->next_action), "%s%s",
                   strcmp(state, "open") == 0 ? "seller next action: " : "",
                   next);
    return true;
}

static bool render_fulfillment_status(
    const struct shop_fulfill_status_view_input_v1 *input,
    struct shop_fulfill_status_view_result_v1 *out)
{
    if (!input || !out) return false;
    memset(out, 0, sizeof(*out));
    const char *readiness;
    const char *next;
    if (input->withdrawn || input->expired) {
        readiness = "closed";
        next = "retain the signed claim as evidence; no value moved";
    } else if (!input->signature_valid || !input->evidence_valid) {
        readiness = "blocked_by_evidence";
        next = "repair evidence, then rerun app shop want fulfill status";
    } else if (!input->visible) {
        readiness = "hidden_by_profile";
        next = "app shop want fulfill review";
    } else {
        readiness = "ready_for_human_review";
        next = "human reviews the claim; acceptance and settlement stay separate";
    }
    (void)snprintf(out->readiness, sizeof(out->readiness), "%s", readiness);
    (void)snprintf(out->next_action, sizeof(out->next_action), "%s", next);
    return true;
}

static const struct shop_want_view_service_v1 k_builtin = {
    .render = render,
    .render_fulfillment_status = render_fulfillment_status,
};

ZCL_HOTSWAP_SERVICE_EXPORT(
    SHOP_WANT_VIEW_SERVICE_ID, k_builtin, SHOP_WANT_VIEW_ABI_FINGERPRINT,
    SHOP_WANT_VIEW_SCHEMA_FINGERPRINT, SHOP_WANT_VIEW_WIRE_FINGERPRINT,
    SHOP_WANT_VIEW_KAT_FINGERPRINT)

const struct shop_want_view_service_v1 *shop_want_view_service_builtin(void)
{
    return &k_builtin;
}
