/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Non-authoritative async-proof performance observations. */

#ifndef ZCL_CONFIG_BOOT_ZCODE_WORK_PERF_H
#define ZCL_CONFIG_BOOT_ZCODE_WORK_PERF_H

#include "vcs/package_store.h"
#include "vcs/zcode_work_swarm.h"

#include <stdint.h>

struct vcs_swarm_engine;

void boot_zcode_work_perf_admission(
    const struct vcs_zcode_work_request_v1 *request,
    const struct vcs_package_store_status *status,
    struct vcs_swarm_engine *engine, int64_t admission_us);

#endif /* ZCL_CONFIG_BOOT_ZCODE_WORK_PERF_H */
