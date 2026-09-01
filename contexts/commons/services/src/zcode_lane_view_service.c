/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure signed-lane presentation over caller-owned buffers. */
// one-result-type-ok:pure-vtable-uses-bounded-caller-owned-output-only

#include "services/zcode_lane_view_service.h"

#include "hotswap/hotswap_service.h"
#include "vcs/zcode_lane.h"

#include <stdio.h>
#include <string.h>

static bool render(uint8_t lane, struct zcode_lane_view_result_v1 *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    switch (lane) {
    case ZCODE_LANE_VIEW_GUIDE:
        (void)snprintf(out->lane_name, sizeof(out->lane_name), "%s",
                       "FRONTIER -> CANDIDATE -> PROVEN");
        (void)snprintf(
            out->capability, sizeof(out->capability), "%s",
            "signed admission, proof-readiness, and human-acceptance lanes are available");
        (void)snprintf(
            out->next_action, sizeof(out->next_action), "%s",
            "zcode package dev lane --input='{\"workspace\":\"<path>\",\"source_root\":\"<64hex>\",\"datadir\":\"/tmp/zclassic23-lane\"}'");
        break;
    case VCS_ZCODE_LANE_FRONTIER:
        (void)snprintf(out->lane_name, sizeof(out->lane_name), "%s",
                       "FRONTIER");
        (void)snprintf(
            out->capability, sizeof(out->capability), "%s",
            "the exact candidate source is admitted to the signed frontier");
        (void)snprintf(out->next_action, sizeof(out->next_action), "%s",
                       "zcode accept --input='<action_id and lane CANDIDATE>'");
        break;
    case VCS_ZCODE_LANE_CANDIDATE:
        (void)snprintf(out->lane_name, sizeof(out->lane_name), "%s",
                       "CANDIDATE");
        (void)snprintf(
            out->capability, sizeof(out->capability), "%s",
            "compile and task-required tests are ready; this is not human acceptance");
        (void)snprintf(out->next_action, sizeof(out->next_action), "%s",
                       "zcode work accept --input='{\"work\":\"latest\"}'");
        break;
    case VCS_ZCODE_LANE_PROVEN:
        (void)snprintf(out->lane_name, sizeof(out->lane_name), "%s", "PROVEN");
        (void)snprintf(
            out->capability, sizeof(out->capability), "%s",
            "the human accepted this exact work after the complete proof policy passed");
        (void)snprintf(out->next_action, sizeof(out->next_action), "%s",
                       "zcode publish plan");
        break;
    default:
        return false;
    }
    out->valid = true;
    return true;
}

static const struct zcode_lane_view_service_v1 k_builtin = {
    .render = render,
};

ZCL_HOTSWAP_SERVICE_EXPORT(
    ZCODE_LANE_VIEW_SERVICE_ID, k_builtin,
    ZCODE_LANE_VIEW_ABI_FINGERPRINT,
    ZCODE_LANE_VIEW_SCHEMA_FINGERPRINT,
    ZCODE_LANE_VIEW_WIRE_FINGERPRINT,
    ZCODE_LANE_VIEW_KAT_FINGERPRINT)

const struct zcode_lane_view_service_v1 *
zcode_lane_view_service_builtin(void)
{
    return &k_builtin;
}
