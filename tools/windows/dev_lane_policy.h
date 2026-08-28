/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef ZCL_TOOLS_WINDOWS_DEV_LANE_POLICY_H
#define ZCL_TOOLS_WINDOWS_DEV_LANE_POLICY_H

#include <stdbool.h>
#include <stdint.h>

#ifdef _WIN32

enum zcl_win_dev_lane_result {
    ZCL_WIN_DEV_LANE_OK = 0,
    ZCL_WIN_DEV_LANE_INVALID_ARGUMENT,
    ZCL_WIN_DEV_LANE_PATH_RESOLUTION_FAILED,
    ZCL_WIN_DEV_LANE_OUTSIDE_LOCAL_ROOT,
    ZCL_WIN_DEV_LANE_CANONICAL_PATH,
    ZCL_WIN_DEV_LANE_PATH_COLLISION,
    ZCL_WIN_DEV_LANE_WRONG_PORT,
    ZCL_WIN_DEV_LANE_WRONG_IDENTITY
};

struct zcl_win_dev_lane_config {
    const wchar_t *local_app_data;
    const wchar_t *datadir;
    const wchar_t *generation_root;
    const wchar_t *service_identity;
    uint16_t p2p_port;
    uint16_t rpc_port;
};

/* Fail-closed admission gate for every Windows service mutation.  Call this
 * before installing a scheduled task, starting a supervisor, or activating a
 * generation.  The caller owns no canonical-lane override. */
enum zcl_win_dev_lane_result zcl_win_dev_lane_validate(
    const struct zcl_win_dev_lane_config *config);

const char *zcl_win_dev_lane_result_name(enum zcl_win_dev_lane_result result);

#endif
#endif
