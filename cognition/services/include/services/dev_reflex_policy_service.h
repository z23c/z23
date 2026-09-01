/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure policy boundary for reflex feedback and async-proof handoff. */

#ifndef ZCL_DEV_REFLEX_POLICY_SERVICE_H
#define ZCL_DEV_REFLEX_POLICY_SERVICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DEV_REFLEX_POLICY_SERVICE_ID "dev.reflex.policy.v1"
#define DEV_REFLEX_POLICY_ABI \
    "dev.reflex.policy.abi.v2:event-projection+semantic-proof-handoff"
#define DEV_REFLEX_POLICY_SCHEMA \
    "zcl.dev_cycle.v1+zcl.dev_drive.v1+zcl.dev_proof_handoff.v2"
#define DEV_REFLEX_POLICY_WIRE \
    "progress-phase+semantic-class+candidate-story-roots.v2"
#define DEV_REFLEX_POLICY_KAT \
    "4f44bc02d76cd948b4c85de32bbf5225021d852790c4976a0d069c554e8f03e7"

struct json_value;

/* This is the entire reflex-to-proof boundary. The producer owns these bytes;
 * the consumer may add receipts but cannot mutate, delay, or invalidate the
 * already-published reflex result. No path, command, or ambient capability is
 * carried across the boundary. */
struct dev_reflex_proof_handoff_v2 {
    char candidate_epoch[65];
    char source_epoch[65];
    char affected_component[128];
    char action[32];
    char proof_inputs_sha3[65];
    char focused_evidence_sha3[65];
    char feedback_class[24];
    char candidate_object_root[65];
    char candidate_module_root[65];
    char story_root[65];
    char story_fixture_root[65];
    char observation_root[65];
    uint32_t affected_file_count;
    bool compile_green;
    bool story_obtained;
};

struct dev_reflex_policy_service_v1 {
    const char *(*progress_phase)(const char *status, const char *detail);
    bool (*action_changing)(const char *status, const char *source_tu);
    bool (*project_cycle)(const struct json_value *cycle,
                          int64_t epoch, struct json_value *compact);
    bool (*handoff_validate)(const struct dev_reflex_proof_handoff_v2 *input,
                             char *why, size_t why_size);
};

const struct dev_reflex_policy_service_v1 *
dev_reflex_policy_service_builtin(void);

struct zcl_hotswap_service_contract;
const struct zcl_hotswap_service_contract *
zcl_native_dev_reflex_policy_service_contract(void);

#endif /* ZCL_DEV_REFLEX_POLICY_SERVICE_H */
