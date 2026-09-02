/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: pure, evidence-bound retrieval measurements as science wires. */
#ifndef ZCL_SERVICES_ZCODE_RETRIEVAL_SCIENCE_ADAPTER_SERVICE_H
#define ZCL_SERVICES_ZCODE_RETRIEVAL_SCIENCE_ADAPTER_SERVICE_H

#include "retrieval/retrieval_pair_observation.h"
#include "services/zcode_retrieval_profile_pair_measure_service.h"
#include "vcs/build_action.h"
#include "vcs/zcode_benchmark_receipt.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_science.h"

#include <stddef.h>
#include <stdint.h>

enum zcode_retrieval_science_adapter_error {
    ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK = 0,
    ZCODE_RETRIEVAL_SCIENCE_ADAPTER_NULL,
    ZCODE_RETRIEVAL_SCIENCE_ADAPTER_ALIAS,
    ZCODE_RETRIEVAL_SCIENCE_ADAPTER_PARAMETER,
    ZCODE_RETRIEVAL_SCIENCE_ADAPTER_MEASUREMENT,
    ZCODE_RETRIEVAL_SCIENCE_ADAPTER_STUDY,
    ZCODE_RETRIEVAL_SCIENCE_ADAPTER_TASK,
    ZCODE_RETRIEVAL_SCIENCE_ADAPTER_CANDIDATE,
    ZCODE_RETRIEVAL_SCIENCE_ADAPTER_POLICY,
    ZCODE_RETRIEVAL_SCIENCE_ADAPTER_ENVIRONMENT,
    ZCODE_RETRIEVAL_SCIENCE_ADAPTER_ACTION,
    ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OBSERVATION,
    ZCODE_RETRIEVAL_SCIENCE_ADAPTER_RESULT,
    ZCODE_RETRIEVAL_SCIENCE_ADAPTER_ANCHOR_INELIGIBLE,
    ZCODE_RETRIEVAL_SCIENCE_ADAPTER_BINDING,
    ZCODE_RETRIEVAL_SCIENCE_ADAPTER_REPRODUCTION,
};

/* Proposal and observation values have no caller-supplied result channel.
 * The adapter reruns pair_measure, requires candidate.patch_root to name the
 * measured child heuristic and candidate source to name the measured source,
 * derives its fixed action over the exact paired input and every root,
 * and treats environment/challenge/time values only as declared run facts. */
struct zcode_retrieval_science_result_request {
    const struct zcode_retrieval_profile_pair_measure_request *measurement;
    const struct vcs_zcode_task_v1 *task;
    const struct vcs_zcode_candidate_v1 *candidate;
    const struct vcs_zcode_environment_policy_v1 *environment_policy;
    const struct vcs_zcode_hardware_profile_v1 *hardware_profile;
    uint64_t action_sequence;
    uint64_t result_sequence;
    uint64_t challenge_block_height;
    uint8_t challenge_block_hash[32];
    int64_t started_unix;
    int64_t finished_unix;
    int64_t now_unix;
};

struct zcode_retrieval_science_result_bundle {
    struct zcode_retrieval_profile_pair_measure_report measurement;
    struct vcs_build_action_v1 action;
    uint8_t action_root[32];
    uint8_t parent_retrieval_result_wire
        [ZCL_RETRIEVAL_EVAL_RESULT_WIRE_BYTES];
    uint8_t child_retrieval_result_wire
        [ZCL_RETRIEVAL_EVAL_RESULT_WIRE_BYTES];
    struct zcl_retrieval_pair_observation_v1 observation;
    uint8_t observation_wire[ZCL_RETRIEVAL_PAIR_OBSERVATION_WIRE_BYTES];
    uint8_t observation_root[32];
    struct vcs_zcode_benchmark_result_v1 result;
    uint8_t result_wire[VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES];
    uint8_t result_root[32];
};

/* Compose one immutable result bundle without storage, signing, execution,
 * publication, acceptance, attention, lifecycle, consensus or wallet
 * authority. out is unchanged on every error and may not overlap any input
 * reachable from request. */
enum zcode_retrieval_science_adapter_error
zcode_retrieval_science_result_compose(
    const struct zcode_retrieval_science_result_request *request,
    struct zcode_retrieval_science_result_bundle *out);

struct zcode_retrieval_science_reproduction_request {
    struct zcode_retrieval_science_result_request original;
    struct zcode_retrieval_science_result_request reproduced;
    uint8_t expected_original_result_root[32];
    uint8_t expected_reproduced_result_root[32];
    uint8_t reproducer_pubkey[32];
    uint64_t reproduction_sequence;
    int64_t created_unix;
    int64_t now_unix;
};

struct zcode_retrieval_science_reproduction_bundle {
    struct zcode_retrieval_science_result_bundle original;
    struct zcode_retrieval_science_result_bundle reproduced;
    struct vcs_zcode_reproduction_v1 reproduction;
    uint8_t reproduction_wire[VCS_ZCODE_REPRODUCTION_WIRE_BYTES];
    uint8_t reproduction_root[32];
};

/* Independently recompose both exact result requests. Only an OBSERVED
 * original is an eligible heuristic anchor. The reproduced result alone
 * determines REPLICATED/CONTRADICTED/INCONCLUSIVE; callers supply no verdict.
 * out is unchanged on every error and may not overlap reachable input. */
enum zcode_retrieval_science_adapter_error
zcode_retrieval_science_reproduction_compose(
    const struct zcode_retrieval_science_reproduction_request *request,
    struct zcode_retrieval_science_reproduction_bundle *out);

const char *zcode_retrieval_science_adapter_error_string(
    enum zcode_retrieval_science_adapter_error error);

#endif /* ZCL_SERVICES_ZCODE_RETRIEVAL_SCIENCE_ADAPTER_SERVICE_H */
