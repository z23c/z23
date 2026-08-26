/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure marketplace moderation visibility and presentation calculations. */

#ifndef ZCL_SERVICES_MARKET_MODERATION_VIEW_SERVICE_H
#define ZCL_SERVICES_MARKET_MODERATION_VIEW_SERVICE_H

#include "services/market_moderation_service.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MARKET_MODERATION_VIEW_SERVICE_ID "app.market.moderation.view.v1"
#define MARKET_MODERATION_VIEW_ABI_FINGERPRINT \
    "app.market.moderation.view.abi.v1:74ac9e20"
#define MARKET_MODERATION_VIEW_SCHEMA_FINGERPRINT \
    "zcl.app_market_moderation_guide.v1+zcl.market_moderation_profile.v1"
#define MARKET_MODERATION_VIEW_WIRE_FINGERPRINT \
    "profile-resolve+visibility+description+guide.v1"
#define MARKET_MODERATION_VIEW_KAT_FINGERPRINT \
    "b3bb4162ded56964518aca6175fba41521ed9b121029a5eb38dd893267f80f26"

/* One decision, asked by every surface that lists or hands out an offer.
 * `visible` means "this node shows AND serves it"; a false answer is a
 * local refusal, never a deletion and never a claim about the offer.
 * `local_view_only` says the decision stays on this node: it is not
 * gossiped, binds no peer, and no peer's decision binds this one — which
 * is what keeps a per-node profile from becoming a network-wide ban.
 * `wire_unchanged` says the signed offer bytes are untouched by it, which
 * is what keeps it out of consensus. */
struct market_moderation_decision_result_v1 {
    bool valid;
    bool visible;
    bool local_view_only;
    bool wire_unchanged;
    char reason[128];
};

struct market_moderation_profile_result_v1 {
    bool valid;
    bool immutable;
    char profile[32];
    char shows[128];
    char hides[192];
};

struct market_moderation_guide_result_v1 {
    bool policy_authority_static;
    bool persistence_static;
    bool network_authority_static;
    bool wire_unchanged;
    char live_surface[128];
    char static_boundary[192];
    char next_command[192];
};

struct market_moderation_view_service_v1 {
    bool (*resolve_profile)(const char *override_name, int active_profile,
                            int *profile_out);
    bool (*decide)(int profile, int review_state,
                   struct market_moderation_decision_result_v1 *out);
    bool (*render_profile)(int profile,
                           struct market_moderation_profile_result_v1 *out);
    bool (*render_guide)(struct market_moderation_guide_result_v1 *out);
};

const struct market_moderation_view_service_v1 *
market_moderation_view_service_builtin(void);

struct zcl_hotswap_service_contract;
const struct zcl_hotswap_service_contract *
zcl_native_market_moderation_view_service_contract(void);

#endif /* ZCL_SERVICES_MARKET_MODERATION_VIEW_SERVICE_H */
