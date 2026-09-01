/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Explicit ZCODE source acceptance and durability promotion. */

#ifndef ZCL_SERVICES_ZCODE_LANE_SERVICE_H
#define ZCL_SERVICES_ZCODE_LANE_SERVICE_H

#include "base/result.h"
#include "models/database.h"
#include "vcs/zcode_accepted_work.h"

#include <stdint.h>

struct zcode_lane_status {
    int lane;
    char lane_name[16];
    char source_root_sha3[65];
    char task_root_sha3[65];
    char candidate_root_sha3[65];
    char proof_policy_root_sha3[65];
    char proof_set_root_sha3[65];
    char receipt_root_sha3[65];
    char prior_receipt_root_sha3[65];
    char signer_pubkey[65];
    int64_t created_at;
    uint32_t view_service_generation;
    char capability[160];
    char next_action[160];
};

struct zcode_accepted_work_status {
    struct vcs_zcode_accepted_work_v1 accepted;
    char action_id[65];
    char worker_id[65];
    bool projection_rebuilt;
};

/* target_lane is FRONTIER, CANDIDATE, or PROVEN. FRONTIER is idempotent
 * candidate admission. Later lanes require the exact previous receipt and
 * the proof evaluator's corresponding acceptance bar. */
struct zcl_result zcode_lane_advance(
    struct node_db *ndb, const char *workspace, const char *action_id,
    int target_lane, int64_t now, const uint8_t signer_secret[32],
    const uint8_t signer_pubkey[32], struct zcode_lane_status *out);

struct zcl_result zcode_lane_find(
    struct node_db *ndb, const char *workspace,
    const char *source_root_sha3, struct zcode_lane_status *out);

/* Resolve exactly one current human-accepted work for source_root. The CAS
 * chain is authoritative; the ZBuild action/worker and lane tables are
 * cross-checked projections. An entirely absent lane projection may be
 * rebuilt from the verified CAS chain when rebuild_projection is true;
 * partial or disagreeing projections always fail closed. */
struct zcl_result zcode_accepted_work_find(
    struct node_db *ndb, const char *workspace,
    const char *source_root_sha3, int64_t now,
    bool rebuild_projection, struct zcode_accepted_work_status *out);

#endif /* ZCL_SERVICES_ZCODE_LANE_SERVICE_H */
