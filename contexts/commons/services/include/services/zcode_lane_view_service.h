/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure presentation ABI for signed ZCODE lane states. */

#ifndef ZCL_SERVICES_ZCODE_LANE_VIEW_SERVICE_H
#define ZCL_SERVICES_ZCODE_LANE_VIEW_SERVICE_H

#include <stdbool.h>
#include <stdint.h>

#define ZCODE_LANE_VIEW_SERVICE_ID "zcode.lane.view.v1"
#define ZCODE_LANE_VIEW_ABI_FINGERPRINT \
    "zcode.lane.view.abi.v1:08a820c2"
#define ZCODE_LANE_VIEW_SCHEMA_FINGERPRINT \
    "zcl.zcode_lane.v1+zcl.zcode_lane_guide.v1"
#define ZCODE_LANE_VIEW_WIRE_FINGERPRINT \
    "frontier-candidate-proven-presentation.v1"
#define ZCODE_LANE_VIEW_KAT_FINGERPRINT \
    "d362c0ecd095ade5ec43eecfd0e5a00750d3b5ba4d2eef7848e8337163b1a8ae"

#define ZCODE_LANE_VIEW_GUIDE 0u

struct zcode_lane_view_result_v1 {
    bool valid;
    char lane_name[32];
    char capability[160];
    char next_action[160];
};

struct zcode_lane_view_service_v1 {
    bool (*render)(uint8_t lane, struct zcode_lane_view_result_v1 *out);
};

const struct zcode_lane_view_service_v1 *
zcode_lane_view_service_builtin(void);

struct zcl_hotswap_service_contract;
const struct zcl_hotswap_service_contract *
zcode_lane_view_service_contract(void);

#endif /* ZCL_SERVICES_ZCODE_LANE_VIEW_SERVICE_H */
