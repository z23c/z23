/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: local-policy-relative lifecycle projection for heuristic evidence. */
#ifndef ZCL_VCS_ZCODE_HEURISTIC_LIFECYCLE_H
#define ZCL_VCS_ZCODE_HEURISTIC_LIFECYCLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "vcs/zcode_attention_bid.h"

#define VCS_ZCODE_HEURISTIC_LIFECYCLE_MAX_STATEMENTS 64u
#define VCS_ZCODE_HEURISTIC_LIFECYCLE_SNAPSHOT_VERSION 1u
#define VCS_ZCODE_HEURISTIC_LIFECYCLE_SNAPSHOT_DOMAIN \
    "zcl.heuristic_lifecycle_snapshot.v1"

enum vcs_zcode_heuristic_lifecycle_status {
    VCS_ZCODE_HEURISTIC_LIFECYCLE_UNDETERMINED = 0,
    VCS_ZCODE_HEURISTIC_LIFECYCLE_RETAINED = 1,
    VCS_ZCODE_HEURISTIC_LIFECYCLE_RETIRED = 2,
};

enum vcs_zcode_heuristic_lifecycle_reason {
    VCS_ZCODE_HEURISTIC_LIFECYCLE_REASON_NONE = 0,
    VCS_ZCODE_HEURISTIC_LIFECYCLE_REASON_EMPTY = 1,
    VCS_ZCODE_HEURISTIC_LIFECYCLE_REASON_AMBIGUOUS = 2,
};

/* This snapshot is output of caller-owned local acceptance policy. Its roots
 * are canonical, sorted, and exact; a signature or CAS presence alone must
 * never cause a root to enter this set. The caller also owns evidence that
 * the anchor passed the verified attention selector: this fold cannot infer
 * selection from object bytes. It is read-only and creates no authority. */
struct vcs_zcode_heuristic_lifecycle_snapshot_v1 {
    uint16_t schema_version;
    uint16_t statement_count;
    uint8_t local_policy_root[32];
    uint8_t expected_signer[32];
    uint8_t heuristic_root[32];
    uint8_t anchor_statement_root[32];
    uint8_t statement_roots
        [VCS_ZCODE_HEURISTIC_LIFECYCLE_MAX_STATEMENTS][32];
};

struct vcs_zcode_heuristic_lifecycle_report {
    uint8_t status;
    uint8_t reason;
    bool complete;
    uint16_t validated_count;
    uint8_t head_statement_root[32];
    uint8_t snapshot_root[32];
};

/* Resolve the accepted snapshot through the existing workspace CAS, reroot
 * and verify every statement and relation set, then fold one connected,
 * acyclic, unforked chain from the exact RESULT anchor. Only explicit
 * SUPERSESSION and RETRACTION statements are lifecycle transitions;
 * unsupported profiles fail closed. Ambiguous but complete evidence returns
 * OK/UNDETERMINED. Missing, corrupt, forged, or misbound accepted evidence
 * fails closed. Timestamps and input order never choose a winner. The result
 * is a projection only: no task, execution,
 * publication, wallet, consensus, or local-acceptance authority is granted. */
enum vcs_zcode_attention_error vcs_zcode_heuristic_lifecycle_fold(
    const char *workspace,
    const struct vcs_zcode_heuristic_lifecycle_snapshot_v1 *snapshot,
    struct vcs_zcode_heuristic_lifecycle_report *report);

#endif /* ZCL_VCS_ZCODE_HEURISTIC_LIFECYCLE_H */
