/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zcode_task_index — the local ZCODE dev-task search index. This is a
 * REBUILDABLE PROJECTION over the workspace CAS (<repo_root>/.zvcs/objects):
 * the persisted task.v1, candidate.v1 and agent_context.v1 wires stay
 * authoritative and this index holds no truth of its own — like package_index, it is rebuilt from
 * the canonical objects on every build and may be discarded at any time. No
 * task table is created.
 *
 * A task entry projects one persisted task wire whose parse, structural
 * validation, and rederived root all succeed and whose root equals its CAS
 * address (the object file name). Candidate and context entries project their
 * persisted wires under the same discipline. Objects of any other size or
 * magic are other CAS citizens and are skipped unread; a file carrying task,
 * candidate or context magic that fails parse/validation/root agreement is logged
 * and skipped — a forged or misplaced file cannot enter the projection.
 * Entries are sorted by root hex for deterministic output. Bounds: at most
 * VCS_ZCODE_TASK_INDEX_MAX_TASKS tasks, MAX_CANDIDATES candidates and
 * MAX_CONTEXTS contexts.
 *
 * Read-only: the index never writes to the CAS. Signed work receipts are
 * re-rooted and signature-checked before they may affect display state; full
 * proof-policy evaluation remains with the evidence owner. Signed lane
 * receipts are additionally prior-chained and joined to the latest exact
 * task/candidate/policy/source and canonical proof set before CANDIDATE or
 * PROVEN may affect display state. */

#ifndef ZCL_VCS_ZCODE_TASK_INDEX_H
#define ZCL_VCS_ZCODE_TASK_INDEX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_TASK_INDEX_MAX_TASKS 1024u
#define VCS_ZCODE_TASK_INDEX_MAX_CANDIDATES 4096u
#define VCS_ZCODE_TASK_INDEX_MAX_CONTEXTS 4096u
#define VCS_ZCODE_TASK_INDEX_MAX_RECEIPTS 8192u
#define VCS_ZCODE_TASK_INDEX_MAX_LANES 8192u

/* Derived per-task states. EXPIRED takes precedence: an expired task is
 * refused by task_validate_at no matter what its candidates look like. */
#define VCS_ZCODE_TASK_STATE_EXPIRED "EXPIRED"
#define VCS_ZCODE_TASK_STATE_AWAITING_CANDIDATE "AWAITING_CANDIDATE"
#define VCS_ZCODE_TASK_STATE_CANDIDATE_ADMITTED "CANDIDATE_ADMITTED"
#define VCS_ZCODE_TASK_STATE_REPAIR_NEEDED "REPAIR_NEEDED"
#define VCS_ZCODE_TASK_STATE_EVIDENCE_READY "EVIDENCE_READY"
#define VCS_ZCODE_TASK_STATE_CANDIDATE_PROOFS_READY "CANDIDATE_PROOFS_READY"
#define VCS_ZCODE_TASK_STATE_PROVEN "PROVEN"

struct vcs_zcode_task_index_entry {
    char task_root_hex[65];
    char source_root_hex[65];
    char goal_root_hex[65];
    char proof_policy_root_hex[65];
    char acceptance_tests_root_hex[65];
    char toolchain_capsule_root_hex[65];
    int64_t expires_unix;
    bool expired;             /* at the build's now_unix */
    uint32_t candidate_count; /* projected candidates binding this task */
    uint32_t receipt_count;
    uint32_t passing_receipt_count;
    uint32_t review_count;
    uint8_t latest_review_verdict;
    char latest_review_root_hex[65];
    uint64_t latest_candidate_sequence;
    char latest_candidate_root_hex[65];
    char latest_candidate_source_root_hex[65];
    char latest_patch_root_hex[65];
    char latest_work_receipt_hex[65];
    char latest_action_root_hex[65];
    char latest_receipt_output_root_hex[65];
    uint8_t latest_receipt_status;
    int32_t latest_receipt_exit_status;
    uint32_t app_run_receipt_count;
    uint32_t valid_app_run_receipt_count;
    char latest_app_run_receipt_hex[65];
    char latest_app_run_observation_hex[65];
    char latest_app_run_artifact_root_hex[65];
    char latest_app_run_invocation_root_hex[65];
    char latest_app_run_action_root_hex[65];
    uint16_t latest_app_run_flags;
    uint8_t latest_app_run_status;
    int32_t latest_app_run_exit_status;
    uint8_t latest_lane;
    char latest_lane_receipt_hex[65];
    char latest_proof_set_root_hex[65];
    char state[24];
};

struct vcs_zcode_task_candidate_entry {
    char task_root_hex[65];
    char candidate_root_hex[65];
    char candidate_source_root_hex[65];
    char patch_root_hex[65];
    char author_pubkey_hex[65];
    uint64_t sequence;
    int64_t created_unix;
};

struct vcs_zcode_task_context_entry {
    char task_root_hex[65];
    char context_root_hex[65];
    char query[257];
    uint64_t wire_bytes;
    uint64_t excerpt_bytes;
    uint32_t file_count;
};

struct vcs_zcode_task_receipt_entry {
    char task_root_hex[65];
    char candidate_root_hex[65];
    char proof_policy_root_hex[65];
    char toolchain_capsule_root_hex[65];
    char receipt_root_hex[65];
    char output_root_hex[65];
    char action_root_hex[65];
    char input_root_hex[65];
    char evidence_root_hex[65];
    char confinement_root_hex[65];
    char signer_pubkey_hex[65];
    uint8_t work_kind;
    uint8_t status;
    int32_t exit_status;
    int64_t started_unix;
    int64_t finished_unix;
};

struct vcs_zcode_task_lane_entry {
    char receipt_root_hex[65];
    char task_root_hex[65];
    char candidate_root_hex[65];
    char source_root_hex[65];
    char proof_policy_root_hex[65];
    char proof_set_root_hex[65];
    char prior_receipt_root_hex[65];
    char signer_pubkey_hex[65];
    uint8_t lane;
    int64_t created_unix;
};

struct vcs_zcode_task_index; /* opaque */

/* Build the projection from repo_root's workspace CAS. A missing/empty
 * object store yields an empty index. NULL on hard allocation failure
 * (logged). now_unix drives the expired flag and derived state. */
struct vcs_zcode_task_index *vcs_zcode_task_index_build(
    const char *repo_root, int64_t now_unix);
void vcs_zcode_task_index_free(struct vcs_zcode_task_index *index);

size_t vcs_zcode_task_index_task_count(
    const struct vcs_zcode_task_index *index);
const struct vcs_zcode_task_index_entry *vcs_zcode_task_index_task_at(
    const struct vcs_zcode_task_index *index, size_t i);

size_t vcs_zcode_task_index_candidate_count(
    const struct vcs_zcode_task_index *index);
const struct vcs_zcode_task_candidate_entry *
vcs_zcode_task_index_candidate_at(const struct vcs_zcode_task_index *index,
                                  size_t i);

/* Verified lane objects projected from CAS. Callers that assign authority
 * must still resolve the complete chain with zcode_accepted_work. */
size_t vcs_zcode_task_index_lane_count(
    const struct vcs_zcode_task_index *index);
const struct vcs_zcode_task_lane_entry *vcs_zcode_task_index_lane_at(
    const struct vcs_zcode_task_index *index, size_t i);

/* Return the one verified context bound to task_root_hex. Multiple distinct
 * contexts are ambiguous because task.v1 intentionally does not choose one. */
const struct vcs_zcode_task_context_entry *
vcs_zcode_task_index_context_for_task(
    const struct vcs_zcode_task_index *index, const char *task_root_hex,
    bool *ambiguous);

/* Look up one task entry by task root (32 bytes). NULL when absent. */
const struct vcs_zcode_task_index_entry *vcs_zcode_task_index_find(
    const struct vcs_zcode_task_index *index, const uint8_t task_root[32]);

struct vcs_zcode_task_search {
    const char *task_root;   /* hex prefix of the task root, or NULL */
    const char *source_root; /* hex prefix of the source root, or NULL */
    const char *author;      /* hex prefix of a candidate author, or NULL */
    const char *state;       /* exact VCS_ZCODE_TASK_STATE_* string, or NULL */
};

/* Bounded search: fills out[] (entry pointers, sorted order) with up to
 * out_cap matches of ALL given filters; returns the TOTAL number of
 * matches (>= the count written), so callers can flag truncation. */
size_t vcs_zcode_task_index_search(
    const struct vcs_zcode_task_index *index,
    const struct vcs_zcode_task_search *search,
    const struct vcs_zcode_task_index_entry **out, size_t out_cap);

#endif /* ZCL_VCS_ZCODE_TASK_INDEX_H */
