/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure paid-file workflow rendering. Authority and effects stay resident. */
// one-result-type-ok:pure-vtable-uses-bounded-caller-owned-output-only

#include "services/market_purchase_view_service.h"

#include "hotswap/hotswap_service.h"

#include <stdio.h>
#include <string.h>

struct market_purchase_code_class {
    const char *code;
    enum market_purchase_error_class_v1 error_class;
};

static const struct market_purchase_code_class k_code_classes[] = {
    { "MONEY_STATE_NOT_CURRENT", MARKET_PURCHASE_ERROR_TRANSIENT },
    { "IDEMPOTENCY_CONFLICT", MARKET_PURCHASE_ERROR_INVALID },
    { "CUSTODY_ALLOCATION_EXCEEDED", MARKET_PURCHASE_ERROR_DENIED },
    { "COMMIT_UNCERTAIN", MARKET_PURCHASE_ERROR_BLOCKED },
    { "MONEY_SNAPSHOT_CHANGED", MARKET_PURCHASE_ERROR_TRANSIENT },
    { "OFFER_CONTRACT_CHANGED", MARKET_PURCHASE_ERROR_BLOCKED },
    { "COMMIT_BUSY", MARKET_PURCHASE_ERROR_TRANSIENT },
    { "COMMIT_STATE_UNCERTAIN", MARKET_PURCHASE_ERROR_BLOCKED },
    { "DESTINATION_INVALID", MARKET_PURCHASE_ERROR_INVALID },
    { "DOWNLOAD_BINDING_CONFLICT", MARKET_PURCHASE_ERROR_BLOCKED },
    { "DESTINATION_CONFLICT", MARKET_PURCHASE_ERROR_BLOCKED },
    { "MANIFEST_VERIFICATION_FAILED", MARKET_PURCHASE_ERROR_FAILED },
    { "STAGING_VERIFICATION_FAILED", MARKET_PURCHASE_ERROR_FAILED },
    { "DELIVERY_NOT_READY", MARKET_PURCHASE_ERROR_TRANSIENT },
    { "ONION_DELIVERY_UNAVAILABLE", MARKET_PURCHASE_ERROR_DENIED },
};

static bool classify_error(
    const char *code, struct market_purchase_error_result_v1 *out)
{
    if (!out) return false;
    out->known = false;
    out->error_class = MARKET_PURCHASE_ERROR_FAILED;
    if (!code) return true;
    for (size_t i = 0; i < sizeof(k_code_classes) / sizeof(k_code_classes[0]);
         i++) {
        if (strcmp(code, k_code_classes[i].code) == 0) {
            out->known = true;
            out->error_class = k_code_classes[i].error_class;
            break;
        }
    }
    return true;
}

static bool plan_id_canonicalize(const char *plan_id, char out[65])
{
    if (!plan_id || strlen(plan_id) != 64) return false;
    for (size_t i = 0; i < 64; i++) {
        char c = plan_id[i];
        if (c >= '0' && c <= '9') out[i] = c;
        else if (c >= 'a' && c <= 'f') out[i] = c;
        else if (c >= 'A' && c <= 'F') out[i] = (char)(c - 'A' + 'a');
        else return false;
    }
    out[64] = '\0';
    return true;
}

static bool render_commit_input(const char *wallet_scope, const char *plan_id,
                                char *out, size_t out_size)
{
    char canonical_plan[65];
    if (!out || out_size == 0 || !wallet_scope ||
        (strcmp(wallet_scope, "dev") != 0 &&
         strcmp(wallet_scope, "prod") != 0) ||
        !plan_id_canonicalize(plan_id, canonical_plan))
        return false;
    int written = snprintf(out, out_size,
        "{\"wallet_scope\":\"%s\",\"plan_id\":\"%s\",\"confirm\":true}",
        wallet_scope, canonical_plan);
    return written > 0 && (size_t)written < out_size;
}

static bool render_guide(struct market_purchase_guide_result_v1 *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    out->classified_error_count =
        (uint16_t)(sizeof(k_code_classes) / sizeof(k_code_classes[0]));
    out->effects_swappable = false;
    out->payment_authority_static = true;
    (void)snprintf(out->flow, sizeof(out->flow), "%s",
                   "plan->commit->status->retrieve");
    (void)snprintf(out->live_surface, sizeof(out->live_surface), "%s",
        "pure refusal classification, canonical commit hint, workflow rendering");
    (void)snprintf(out->static_boundary, sizeof(out->static_boundary), "%s",
        "input parsing, moderation admission, authentication, RPC, wallet, storage, network, payment, retrieval, publication");
    (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
        "z23 discover schema app.market.purchase.plan");
    return true;
}

static const struct market_purchase_view_service_v1 k_builtin = {
    .classify_error = classify_error,
    .render_commit_input = render_commit_input,
    .render_guide = render_guide,
};

ZCL_HOTSWAP_SERVICE_EXPORT(
    MARKET_PURCHASE_VIEW_SERVICE_ID, k_builtin,
    MARKET_PURCHASE_VIEW_ABI_FINGERPRINT,
    MARKET_PURCHASE_VIEW_SCHEMA_FINGERPRINT,
    MARKET_PURCHASE_VIEW_WIRE_FINGERPRINT,
    MARKET_PURCHASE_VIEW_KAT_FINGERPRINT)

const struct market_purchase_view_service_v1 *
market_purchase_view_service_builtin(void)
{
    return &k_builtin;
}
