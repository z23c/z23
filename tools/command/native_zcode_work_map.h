/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Verified map inputs for native Commons work projections. */
#ifndef ZCL_COMMAND_NATIVE_ZCODE_WORK_MAP_H
#define ZCL_COMMAND_NATIVE_ZCODE_WORK_MAP_H

#include "ontology/work_map.h"
#include "services/build_fabric_service.h"

/* Bind the map's requested identity before using the existing read-only
 * evaluator. Failure clears all facts. Success is an observation, not task
 * acceptance or publication; retained proof-set and lifecycle qualification
 * remain separate. No database or CAS writes are performed. */
struct zcl_result zcl_native_work_map_evaluate(
    struct node_db *ndb, const char *workspace, const char *task_root,
    const char *candidate_root, const char *policy_root, const char *action_id,
    int64_t now, struct build_fabric_proof_evaluation *out);

/* Read existing CAS only; never creates a workspace or accepts a task.
 * Reverify SHA3(wire) against root before parsing the complete map. Failed
 * reads set count to zero and leave nodes untouched. Missing/read failures
 * are OBJECT, oversize is BOUNDS, hash mismatch is IDENTITY; malformed
 * metadata retains the validator's specific refusal. */
enum zcl_work_map_result zcl_native_work_map_load(
    const char *workspace, const uint8_t root[32],
    struct zcl_work_map_node *nodes, size_t capacity, size_t *count);

#endif /* ZCL_COMMAND_NATIVE_ZCODE_WORK_MAP_H */
