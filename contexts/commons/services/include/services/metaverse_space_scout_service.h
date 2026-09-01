/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Exact-plan storage service for bounded Space Scout evidence. */

#ifndef ZCL_SERVICES_METAVERSE_SPACE_SCOUT_SERVICE_H
#define ZCL_SERVICES_METAVERSE_SPACE_SCOUT_SERVICE_H

#include "base/result.h"
#include "vcs/space_scout.h"

#include <stdbool.h>

struct metaverse_space_scout_plan_out {
  char mission_root[65];
  char plan_token[65];
};

struct metaverse_space_scout_run_out {
  char mission_root[65];
  char evidence_root[65];
  char attestation_root[65];
  bool already_recorded;
};

typedef bool (*metaverse_space_scout_store_allowed_fn)(
    void *context, const uint8_t semantic_root[32],
    const char *service_type);

/* Planning is stateless. Running stores the canonical mission, deterministic
 * map and separate signed attestation only after exact-byte verification. */
struct zcl_result metaverse_space_scout_plan(
    const struct vcs_space_scout_mission_v1 *mission,
    struct metaverse_space_scout_plan_out *out);
struct zcl_result metaverse_space_scout_run(
    const char *workspace,
    const struct vcs_space_scout_mission_v1 *mission,
    const char *plan_token, bool confirm,
    const struct vcs_space_scout_run_context *run_context,
    const struct vcs_zcode_dht_delegation *observer_delegation,
    const uint8_t online_seed[32],
    metaverse_space_scout_store_allowed_fn store_allowed,
    void *store_policy_context,
    bool *mutated_out,
    struct metaverse_space_scout_run_out *out);
struct zcl_result metaverse_space_scout_show(
    const char *workspace, const char *evidence_root,
    struct vcs_space_scout_map_v1 *out);
struct zcl_result metaverse_space_scout_mission_show(
    const char *workspace, const char *mission_root,
    struct vcs_space_scout_mission_v1 *out);
struct zcl_result metaverse_space_scout_attestation_show(
    const char *workspace, const char *attestation_root,
    struct vcs_space_scout_attestation_v1 *out);

#endif /* ZCL_SERVICES_METAVERSE_SPACE_SCOUT_SERVICE_H */
