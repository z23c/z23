/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "dev_lane_policy.h"

#ifdef _WIN32
#include <stdio.h>

static int expect(const char *name, enum zcl_win_dev_lane_result got,
                  enum zcl_win_dev_lane_result want)
{
    if (got == want)
        return 0;
    fprintf(stderr, "%s: got %s, want %s\n", name,
            zcl_win_dev_lane_result_name(got),
            zcl_win_dev_lane_result_name(want));
    return 1;
}

int main(void)
{
    struct zcl_win_dev_lane_config config = {
        .local_app_data = L"C:\\Users\\tester\\AppData\\Local",
        .datadir = L"C:\\Users\\tester\\AppData\\Local\\z23\\dev\\node",
        .generation_root =
            L"C:\\Users\\tester\\AppData\\Local\\z23\\dev\\generations",
        .service_identity = L"Z23 Dev Node",
        .p2p_port = 8053,
        .rpc_port = 18252
    };
    int failures = 0;

    failures += expect("valid isolated lane", zcl_win_dev_lane_validate(&config),
                       ZCL_WIN_DEV_LANE_OK);
    config.rpc_port = 18232;
    failures += expect("canonical RPC port",
                       zcl_win_dev_lane_validate(&config),
                       ZCL_WIN_DEV_LANE_WRONG_PORT);
    config.rpc_port = 18252;
    config.datadir =
        L"C:\\Users\\tester\\AppData\\Local\\z23\\.zclassic-c23";
    failures += expect("canonical datadir",
                       zcl_win_dev_lane_validate(&config),
                       ZCL_WIN_DEV_LANE_CANONICAL_PATH);
    config.datadir = L"C:\\Users\\tester\\canonical-node";
    failures += expect("datadir outside LocalAppData",
                       zcl_win_dev_lane_validate(&config),
                       ZCL_WIN_DEV_LANE_OUTSIDE_LOCAL_ROOT);
    config.datadir =
        L"C:\\Users\\tester\\AppData\\Local\\z23\\dev\\generations\\node";
    failures += expect("generation/datadir collision",
                       zcl_win_dev_lane_validate(&config),
                       ZCL_WIN_DEV_LANE_PATH_COLLISION);
    config.datadir = L"C:\\Users\\tester\\AppData\\Locality\\z23\\dev";
    failures += expect("prefix boundary",
                       zcl_win_dev_lane_validate(&config),
                       ZCL_WIN_DEV_LANE_OUTSIDE_LOCAL_ROOT);
    config.datadir = L"C:\\Users\\tester\\AppData\\Local\\z23\\dev\\node";
    config.service_identity = L"zclassic23";
    failures += expect("canonical service identity",
                       zcl_win_dev_lane_validate(&config),
                       ZCL_WIN_DEV_LANE_WRONG_IDENTITY);

    if (failures == 0)
        puts("Windows dev-lane policy: PASS");
    return failures ? 1 : 0;
}
#else
int main(void) { return 0; }
#endif
