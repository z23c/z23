/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Validate isolated ship subjects and their fixture evidence. */
#ifndef Z23_SHIP_LANE_GUARD_H
#define Z23_SHIP_LANE_GUARD_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
struct ship_lane_subject {
    const char *unit;
    const char *lane;
    const char *executable;
    const char *datadir;
    uint64_t pid;
    uint64_t start_token;
    unsigned p2p_port;
    unsigned rpc_port;
    bool observed;
    bool active;
};
bool ship_lane_subjects_disjoint(const struct ship_lane_subject *a,
                                  const struct ship_lane_subject *b);
/* Inputs are resolved, exact process and unit observations, not unit intent. */
bool ship_lane_devfleet_allowed(const struct ship_lane_subject *selected,
                               const char *expected_datadir,
                               const struct ship_lane_subject *others,
                               size_t other_count);
/* Process snapshots must be tied to a manager-provided MainPID. */
struct ship_lane_proc_snapshot {
    char executable[4096];
    char datadir[4096];
    uint64_t start_token;
    unsigned p2p_port;
    unsigned rpc_port;
    bool declared_dev;
};
bool ship_lane_read_process(uint64_t pid, struct ship_lane_proc_snapshot *out);
bool ship_lane_read_client(uint64_t pid, const char *datadir, bool worker, uint64_t *start);
bool ship_lane_read_mcp_client(uint64_t pid);
bool ship_lane_read_tunnel(uint64_t pid, uint64_t *start);
bool ship_lane_listeners_disjoint(uint64_t pid, uint64_t selected_pid, unsigned p2p, unsigned rpc, unsigned required, unsigned required2, unsigned *other);
#endif
