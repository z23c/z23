/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Shared private verification of action-bound build observations. */

#ifndef ZCL_BUILD_FABRIC_OBSERVATION_INTERNAL_H
#define ZCL_BUILD_FABRIC_OBSERVATION_INTERNAL_H

#include "services/build_fabric_service.h"

struct zcl_result build_fabric_observation_verify(
    const char *workspace, const struct db_build_job *job,
    const struct db_build_action *action,
    const struct db_build_receipt *receipt);

#endif /* ZCL_BUILD_FABRIC_OBSERVATION_INTERNAL_H */
