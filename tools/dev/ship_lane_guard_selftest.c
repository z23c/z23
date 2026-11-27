/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Validate isolated ship subjects and their fixture evidence. */
#define _XOPEN_SOURCE 700
#include "ship_lane_guard.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
int main(void)
{
    char home[] = "/tmp/z23-ship-lane-XXXXXX", dir[512], canonical[512], child[512];
    if (!mkdtemp(home) || snprintf(dir, sizeof dir, "%s/.zclassic-c23-devfleet", home) < 0 ||
        snprintf(canonical, sizeof canonical, "%s/.zclassic-c23", home) < 0 ||
        snprintf(child, sizeof child, "%s/.zclassic-c23-devfleet/child", home) < 0 ||
        mkdir(dir, 0700) || mkdir(canonical, 0700) || mkdir(child, 0700)) return 1;
    struct ship_lane_subject s = {"z23-devfleet-node.service", "dev", "/bin/z23",
        dir, 10, 100, 8053, 18260, true, true};
    struct ship_lane_subject o[4] = {
        {"z23-node.service", "canonical", "/bin/z23", canonical, 11, 101, 8033, 18232, true, true},
        { .unit = "zclassic23.service", .observed = true },
        { .unit = "z23-soak.service", .observed = true },
        { .unit = "zcl23-dev.service", .observed = true }
    };
    int fail = 0;
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d\n", __LINE__); fail++; } } while (0)
    CHECK(ship_lane_devfleet_allowed(&s, dir, o, 4));
    s.lane = "unknown"; CHECK(!ship_lane_devfleet_allowed(&s, dir, o, 4)); s.lane = "dev";
    s.unit = "unrelated.service"; CHECK(!ship_lane_devfleet_allowed(&s, dir, o, 4)); s.unit = "z23-devfleet-node.service";
    s.rpc_port = 18232; CHECK(!ship_lane_devfleet_allowed(&s, dir, o, 4)); s.rpc_port = 18260;
    s.datadir = canonical; CHECK(!ship_lane_devfleet_allowed(&s, dir, o, 4)); s.datadir = dir;
    o[0].pid = s.pid; CHECK(!ship_lane_devfleet_allowed(&s, dir, o, 4)); o[0].pid = 11;
    o[0].datadir = child; CHECK(!ship_lane_devfleet_allowed(&s, dir, o, 4)); o[0].datadir = canonical;
    o[0].rpc_port = 8053; CHECK(!ship_lane_devfleet_allowed(&s, dir, o, 4)); o[0].rpc_port = 18232;
    o[1].observed = false; CHECK(!ship_lane_devfleet_allowed(&s, dir, o, 4)); o[1].observed = true;
    o[2].unit = "unexpected.service"; CHECK(!ship_lane_devfleet_allowed(&s, dir, o, 4));
    o[2].unit = "z23-soak.service";
    s.start_token = 0; CHECK(!ship_lane_devfleet_allowed(&s, dir, o, 4));
    if (rmdir(child) || rmdir(canonical) || rmdir(dir) || rmdir(home)) fail++;
    if (!fail) puts("ship lane guard: PASS");
    return fail != 0;
}
