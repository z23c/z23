/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: local-policy-relative replication qualification for heuristics. */
#ifndef ZCL_VCS_ZCODE_HEURISTIC_REPLICATION_H
#define ZCL_VCS_ZCODE_HEURISTIC_REPLICATION_H

#include <stdbool.h>
#include <stdint.h>

#include "vcs/build_action.h"
#include "vcs/zcode_attention_bid.h"

#define VCS_ZCODE_HEURISTIC_REPLICATION_MAX_STATEMENTS 64u
#define VCS_ZCODE_HEURISTIC_REPLICATION_SNAPSHOT_VERSION 1u
#define VCS_ZCODE_HEURISTIC_REPLICATION_SNAPSHOT_DOMAIN \
    "zcl.heuristic_replication_snapshot.v1"

enum vcs_zcode_heuristic_replication_reason {
    VCS_ZCODE_HEURISTIC_REPLICATION_REASON_NONE = 0,
    VCS_ZCODE_HEURISTIC_REPLICATION_REASON_BELOW_THRESHOLD = 1,
    VCS_ZCODE_HEURISTIC_REPLICATION_REASON_INCONCLUSIVE = 2,
    VCS_ZCODE_HEURISTIC_REPLICATION_REASON_CONTRADICTED = 3,
};

/* Output of caller-owned local acceptance policy. Roots are exact, sorted,
 * and unique. CAS presence, a signature, or a global index never inserts a
 * row. The policy root owns any stronger claim that distinct signing keys
 * correspond to independent people, operators, or machines. */
struct vcs_zcode_heuristic_replication_snapshot_v1 {
    uint16_t schema_version;
    uint16_t statement_count;
    uint8_t local_policy_root[32];
    uint8_t expected_evaluator_signer[32];
    uint8_t heuristic_root[32];
    uint8_t anchor_statement_root[32];
    uint8_t statement_roots
        [VCS_ZCODE_HEURISTIC_REPLICATION_MAX_STATEMENTS][32];
};

struct vcs_zcode_heuristic_replication_report {
    bool complete;
    bool qualified;
    uint8_t reason;
    uint16_t validated_count;
    uint16_t replicated_count;
    uint16_t contradicted_count;
    uint16_t inconclusive_count;
    uint16_t required_reproductions;
    uint8_t study_root[32];
    uint8_t original_result_root[32];
    uint8_t snapshot_root[32];
};

/* Verify an exact RESULT anchor and its benchmark_result.v1, study, task,
 * CAS candidate, and caller-supplied canonical fixed action, then fold the
 * caller-accepted signed REPLICATION statements. Distinct keys
 * are an exact cryptographic observation, not proof of distinct operators.
 * REPLICATED rows count; INCONCLUSIVE rows do not; CONTRADICTED rows prevent
 * qualification. Below-threshold evidence is a complete UNDETERMINED report,
 * never retirement. Missing, corrupt, replayed, or misbound accepted evidence
 * fails atomically. This read-only projection grants no lifecycle, acceptance,
 * execution, publication, consensus, wallet, or deployment authority. */
enum vcs_zcode_attention_error vcs_zcode_heuristic_replication_fold(
    const char *workspace,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_build_action_v1 *action,
    const struct vcs_zcode_heuristic_replication_snapshot_v1 *snapshot,
    int64_t now_unix,
    struct vcs_zcode_heuristic_replication_report *report);

#endif /* ZCL_VCS_ZCODE_HEURISTIC_REPLICATION_H */
