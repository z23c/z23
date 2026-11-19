/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: verified roster, signed-vitals and board-bound worker projection. */
#ifndef ZCL_NATIVE_FLEET_STEER_MACHINES_H
#define ZCL_NATIVE_FLEET_STEER_MACHINES_H

#include "json/json.h"

#define ZCL_FMC_MACHINE_CAP 16u
#define ZCL_FMC_MACHINE_FRESH_S 900

struct zcl_fmc_machines {
    struct json_value rows;
    size_t total;
    size_t unbound_workers;
    bool roster_ok;
    bool workers_complete;
    bool complete;
    bool truncated;
};

void zcl_fmc_machines_init(struct zcl_fmc_machines *view);
void zcl_fmc_machines_free(struct zcl_fmc_machines *view);

/* roster is one complete fleet.machines page, histories is an array of
 * fleet.vitals.history data objects, and workers is the brief's worker array.
 * Only a complete final history page supplies current values. Signed board
 * evidence binds an agent to its enrolled box_pubkey; task fields remain
 * worker-self-reported. */
bool zcl_fmc_machines_project(struct zcl_fmc_machines *view,
    const struct json_value *roster, const struct json_value *histories,
    const struct json_value *workers, bool workers_complete,
    long long now, long long heartbeat_window_s);

/* Copies the whole projection or returns false; callers must not ship a
 * partially emitted array. */
bool zcl_fmc_machines_emit(const struct zcl_fmc_machines *view,
    struct json_value *data);

#endif
