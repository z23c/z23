/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure caller-owned moderation calculations. All authority stays resident. */
// one-result-type-ok:pure-vtable-uses-bounded-caller-owned-output-only

#include "services/market_moderation_view_service.h"

#include "market_moderation_view_internal.h"

#include "hotswap/hotswap_service.h"

#include <stdio.h>
#include <string.h>

static bool resolve_profile(const char *override_name, int active_profile,
                            int *profile_out)
{
    if (!profile_out || !market_moderation_profile_valid(active_profile))
        return false;
    int profile = active_profile;
    if (override_name && override_name[0] &&
        strcmp(override_name, "default") != 0) {
        if (strcmp(override_name, "open") == 0 ||
            strcmp(override_name, MARKET_MODERATION_PROFILE_OPEN_VIEW) == 0)
            profile = MARKET_MODERATION_PROFILE_OPEN;
        else if (strcmp(override_name, "general") == 0 ||
                 strcmp(override_name,
                        MARKET_MODERATION_PROFILE_GENERAL_AUDIENCE_V1) == 0)
            profile = MARKET_MODERATION_PROFILE_DEFAULT;
        else
            return false;
    }
    *profile_out = profile;
    return true;
}

static bool decide(int profile, int review_state,
                   struct market_moderation_decision_result_v1 *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    out->local_view_only = true;
    out->wire_unchanged = true;
    if (!market_moderation_profile_valid(profile) ||
        !market_review_state_valid(review_state)) {
        (void)snprintf(out->reason, sizeof(out->reason), "%s",
                       MMV_REASON_INVALID);
        return true;
    }
    out->valid = true;
    out->visible = profile == MARKET_MODERATION_PROFILE_OPEN ||
                   review_state == MARKET_REVIEW_REVIEWED_OK;
    if (out->visible) {
        (void)snprintf(out->reason, sizeof(out->reason), "%s",
                       profile == MARKET_MODERATION_PROFILE_OPEN
                           ? MMV_REASON_OPEN : MMV_REASON_GENERAL);
    } else {
        (void)snprintf(out->reason, sizeof(out->reason), "%s",
                       MMV_REASON_HIDDEN);
    }
    return true;
}

static bool render_profile(int profile,
                           struct market_moderation_profile_result_v1 *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!market_moderation_profile_valid(profile)) return true;
    out->valid = true;
    out->immutable = true;
    if (profile == MARKET_MODERATION_PROFILE_OPEN) {
        (void)snprintf(out->profile, sizeof(out->profile), "%s",
                       MARKET_MODERATION_PROFILE_OPEN_VIEW);
        (void)snprintf(out->shows, sizeof(out->shows), "%s", MMV_OPEN_SHOWS);
        (void)snprintf(out->hides, sizeof(out->hides), "%s", "nothing");
    } else {
        (void)snprintf(out->profile, sizeof(out->profile), "%s",
                       MARKET_MODERATION_PROFILE_GENERAL_AUDIENCE_V1);
        (void)snprintf(out->shows, sizeof(out->shows), "%s",
                       MMV_GENERAL_SHOWS);
        (void)snprintf(out->hides, sizeof(out->hides), "%s",
                       MMV_GENERAL_HIDES);
    }
    return true;
}

static bool render_guide(struct market_moderation_guide_result_v1 *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    out->policy_authority_static = true;
    out->persistence_static = true;
    out->network_authority_static = true;
    out->wire_unchanged = true;
    (void)snprintf(out->live_surface, sizeof(out->live_surface), "%s",
                   MMV_LIVE_SURFACE);
    (void)snprintf(out->static_boundary, sizeof(out->static_boundary), "%s",
                   "profile files, SQLite review marks, offer cache, RPC, enforcement, storage, deletion (none), consensus and signed wire");
    (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
                   "z23 app market moderation status");
    return true;
}

static const struct market_moderation_view_service_v1 k_builtin = {
    .resolve_profile = resolve_profile,
    .decide = decide,
    .render_profile = render_profile,
    .render_guide = render_guide,
};

ZCL_HOTSWAP_SERVICE_EXPORT(
    MARKET_MODERATION_VIEW_SERVICE_ID, k_builtin,
    MARKET_MODERATION_VIEW_ABI_FINGERPRINT,
    MARKET_MODERATION_VIEW_SCHEMA_FINGERPRINT,
    MARKET_MODERATION_VIEW_WIRE_FINGERPRINT,
    MARKET_MODERATION_VIEW_KAT_FINGERPRINT)

const struct market_moderation_view_service_v1 *
market_moderation_view_service_builtin(void)
{
    return &k_builtin;
}
