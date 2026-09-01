/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure Passport workflow presentation over caller-owned buffers. */
// one-result-type-ok:pure-vtable-uses-bounded-caller-owned-output-only

#include "services/zcode_passport_view_service.h"

#include "hotswap/hotswap_service.h"

#include <stdio.h>
#include <string.h>

static bool render(enum zcode_passport_view_mode_v1 mode,
                   struct zcode_passport_view_result_v1 *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    (void)snprintf(out->kind, sizeof(out->kind), "%s", "module_passport.v1");
    switch (mode) {
    case ZCODE_PASSPORT_VIEW_STATUS:
        (void)snprintf(
            out->capability, sizeof(out->capability), "%s",
            "offline plan, external-signature commit and verification are ready");
        (void)snprintf(out->next_action, sizeof(out->next_action), "%s",
                       "zcode passport plan");
        break;
    case ZCODE_PASSPORT_VIEW_PLAN:
        (void)snprintf(
            out->capability, sizeof(out->capability), "%s",
            "exact evidence roots are ready for an offline Ed25519 signature");
        (void)snprintf(
            out->next_action, sizeof(out->next_action), "%s",
            "sign signing_payload with the matching offline Ed25519 key, then run zcode passport commit with the same roots and signature");
        break;
    case ZCODE_PASSPORT_VIEW_COMMIT:
        (void)snprintf(
            out->capability, sizeof(out->capability), "%s",
            "the external signature and canonical Passport wire are verified");
        (void)snprintf(out->next_action, sizeof(out->next_action), "%s",
                       "zcode passport verify --passport=<passport>");
        break;
    case ZCODE_PASSPORT_VIEW_VERIFY:
        (void)snprintf(
            out->capability, sizeof(out->capability), "%s",
            "the signed Passport and every committed evidence root are verified");
        (void)snprintf(
            out->next_action, sizeof(out->next_action), "%s",
            "bind this passport root into a workspace manifest");
        break;
    default:
        return false;
    }
    out->valid = true;
    return true;
}

static const struct zcode_passport_view_service_v1 k_builtin = {
    .render = render,
};

ZCL_HOTSWAP_SERVICE_EXPORT(
    ZCODE_PASSPORT_VIEW_SERVICE_ID, k_builtin,
    ZCODE_PASSPORT_VIEW_ABI_FINGERPRINT,
    ZCODE_PASSPORT_VIEW_SCHEMA_FINGERPRINT,
    ZCODE_PASSPORT_VIEW_WIRE_FINGERPRINT,
    ZCODE_PASSPORT_VIEW_KAT_FINGERPRINT)

const struct zcode_passport_view_service_v1 *
zcode_passport_view_service_builtin(void)
{
    return &k_builtin;
}
