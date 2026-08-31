/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Canonical, model-neutral ZCODE development objects.  These records compose
 * the roots already owned by content.v2, package_lock, toolchain_capsule and
 * ZBuild; they do not introduce another source store, dependency resolver,
 * sandbox, scheduler, or trust database.  Every wire is fixed-width,
 * little-endian, closed-grammar, domain-separated and SHA3-256 addressed.
 * JSON is display only.
 */

#ifndef ZCL_VCS_ZCODE_DEV_H
#define ZCL_VCS_ZCODE_DEV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_DEV_VERSION 1u
#define VCS_ZCODE_ROOT_BYTES 32u
#define VCS_ZCODE_PUBKEY_BYTES 32u
#define VCS_ZCODE_SIGNATURE_BYTES 64u

#define VCS_ZCODE_TASK_DOMAIN "zcl.zcode.task.v1"
#define VCS_ZCODE_CANDIDATE_DOMAIN "zcl.zcode.candidate.v1"
#define VCS_ZCODE_PROOF_POLICY_DOMAIN "zcl.zcode.proof_policy.v1"
#define VCS_ZCODE_REVIEW_DOMAIN "zcl.zcode.review.v1"
#define VCS_ZCODE_WORK_RECEIPT_DOMAIN "zcl.zcode.work_receipt.v1"
#define VCS_ZCODE_PROOF_SET_DOMAIN "zcl.zcode.proof_set.v1"
#define VCS_ZCODE_ACCEPTANCE_PLAN_DOMAIN "zcl.zcode.acceptance_plan.v1"

#define VCS_ZCODE_TASK_WIRE_BYTES 318u
#define VCS_ZCODE_CANDIDATE_WIRE_BYTES 218u
#define VCS_ZCODE_PROOF_POLICY_WIRE_BYTES 36u
#define VCS_ZCODE_REVIEW_WIRE_BYTES 219u
#define VCS_ZCODE_WORK_RECEIPT_BODY_BYTES 384u
#define VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES 448u
#define VCS_ZCODE_PROOF_SET_HEADER_BYTES 12u
#define VCS_ZCODE_PROOF_SET_MAX_RECEIPTS 64u
#define VCS_ZCODE_FUZZ_SEEDS_MAX 4096u
#define VCS_ZCODE_PROOF_SET_WIRE_MAX \
    (VCS_ZCODE_PROOF_SET_HEADER_BYTES + VCS_ZCODE_PROOF_SET_MAX_RECEIPTS * 32u)

#define VCS_ZCODE_TASK_MAX_PATCH_BYTES (UINT64_C(64) * 1024u * 1024u)
#define VCS_ZCODE_TASK_MAX_CONTEXT_BYTES (UINT64_C(64) * 1024u * 1024u)
#define VCS_ZCODE_TASK_MAX_OUTPUT_BYTES (UINT64_C(4) * 1024u * 1024u * 1024u)
#define VCS_ZCODE_TASK_MAX_MEMORY_BYTES (UINT64_C(16) * 1024u * 1024u * 1024u)

enum vcs_zcode_task_capability {
    VCS_ZCODE_TASK_CAP_SOURCE_READ = 1u << 0,
    VCS_ZCODE_TASK_CAP_CANDIDATE_WRITE = 1u << 1,
    VCS_ZCODE_TASK_CAP_FIXED_ACTIONS = 1u << 2,
};

#define VCS_ZCODE_TASK_CAP_V1_MASK \
    (VCS_ZCODE_TASK_CAP_SOURCE_READ | VCS_ZCODE_TASK_CAP_CANDIDATE_WRITE | \
     VCS_ZCODE_TASK_CAP_FIXED_ACTIONS)

enum vcs_zcode_proof_kind {
    VCS_ZCODE_PROOF_COMPILE = 1u << 0,
    VCS_ZCODE_PROOF_TEST = 1u << 1,
    VCS_ZCODE_PROOF_FUZZ = 1u << 2,
    VCS_ZCODE_PROOF_REVIEW = 1u << 3,
    VCS_ZCODE_PROOF_LOCAL_REPRODUCTION = 1u << 4,
};

#define VCS_ZCODE_PROOF_V1_MASK \
    (VCS_ZCODE_PROOF_COMPILE | VCS_ZCODE_PROOF_TEST | \
     VCS_ZCODE_PROOF_FUZZ | VCS_ZCODE_PROOF_REVIEW | \
     VCS_ZCODE_PROOF_LOCAL_REPRODUCTION)

enum vcs_zcode_proof_policy_flag {
    VCS_ZCODE_POLICY_INDEPENDENT_SIGNERS = 1u << 0,
    VCS_ZCODE_POLICY_RELEASE_BYTE_IDENTITY = 1u << 1,
};

#define VCS_ZCODE_POLICY_V1_FLAG_MASK \
    (VCS_ZCODE_POLICY_INDEPENDENT_SIGNERS | \
     VCS_ZCODE_POLICY_RELEASE_BYTE_IDENTITY)

enum vcs_zcode_review_verdict {
    VCS_ZCODE_REVIEW_APPROVE = 1,
    VCS_ZCODE_REVIEW_REQUEST_CHANGES = 2,
    VCS_ZCODE_REVIEW_REJECT = 3,
};

enum vcs_zcode_work_kind {
    VCS_ZCODE_WORK_PROPOSE = 1,
    VCS_ZCODE_WORK_BUILD = 2,
    VCS_ZCODE_WORK_TEST = 3,
    VCS_ZCODE_WORK_FUZZ = 4,
    VCS_ZCODE_WORK_REVIEW = 5,
    VCS_ZCODE_WORK_REPRODUCE = 6,
    VCS_ZCODE_WORK_DIAGNOSE = 7,
    /* Evidence-only today: the public worker/action registry deliberately
     * has no application launcher. A signed receipt of this kind may bind a
     * canonical app_run_observation emitted by an independently authorized
     * bounded executor; it is not a proof-policy kind. */
    VCS_ZCODE_WORK_APP_RUN = 8,
};

enum vcs_zcode_work_status {
    VCS_ZCODE_WORK_PASS = 1,
    VCS_ZCODE_WORK_FAIL = 2,
    VCS_ZCODE_WORK_CANCELLED = 3,
    VCS_ZCODE_WORK_REFUSED = 4,
};

enum vcs_zcode_dev_error {
    VCS_ZCODE_DEV_OK = 0,
    VCS_ZCODE_DEV_ERR_NULL,
    VCS_ZCODE_DEV_ERR_VERSION,
    VCS_ZCODE_DEV_ERR_WIRE_SIZE,
    VCS_ZCODE_DEV_ERR_WIRE_MAGIC,
    VCS_ZCODE_DEV_ERR_ROOT_ZERO,
    VCS_ZCODE_DEV_ERR_PUBKEY_ZERO,
    VCS_ZCODE_DEV_ERR_SIGNATURE,
    VCS_ZCODE_DEV_ERR_CAPABILITY,
    VCS_ZCODE_DEV_ERR_LIMIT,
    VCS_ZCODE_DEV_ERR_EXPIRY,
    VCS_ZCODE_DEV_ERR_POLICY,
    VCS_ZCODE_DEV_ERR_VERDICT,
    VCS_ZCODE_DEV_ERR_WORK_KIND,
    VCS_ZCODE_DEV_ERR_WORK_STATUS,
    VCS_ZCODE_DEV_ERR_TIME_ORDER,
    VCS_ZCODE_DEV_ERR_TASK_MISMATCH,
    VCS_ZCODE_DEV_ERR_SOURCE_STALE,
    VCS_ZCODE_DEV_ERR_POLICY_MISMATCH,
    VCS_ZCODE_DEV_ERR_TOOLCHAIN_STALE,
    VCS_ZCODE_DEV_ERR_OUTPUT_MISMATCH,
};

const char *vcs_zcode_dev_error_string(enum vcs_zcode_dev_error error);

struct vcs_zcode_task_v1 {
    uint16_t schema_version;
    uint8_t source_root[32];
    uint8_t dependency_lock_root[32];
    uint8_t toolchain_capsule_root[32];
    uint8_t write_scope_root[32];
    uint8_t acceptance_tests_root[32];
    uint8_t proof_policy_root[32];
    uint8_t model_policy_root[32];
    uint8_t goal_root[32];
    uint32_t capabilities;
    uint32_t max_changed_files;
    uint64_t max_patch_bytes;
    uint64_t max_context_bytes;
    uint32_t max_cpu_seconds;
    uint64_t max_memory_bytes;
    uint64_t max_output_bytes;
    int64_t expires_unix;
};

struct vcs_zcode_proof_policy_v1 {
    uint16_t schema_version;
    uint32_t required_proofs;
    uint16_t minimum_compile_receipts;
    uint16_t minimum_test_receipts;
    uint16_t minimum_fuzz_receipts;
    uint16_t minimum_reviews;
    uint16_t minimum_matching_receipts;
    uint16_t flags;
    uint32_t deterministic_fuzz_seeds;
    uint16_t audit_basis_points;
    uint32_t maximum_proof_age_seconds;
};

struct vcs_zcode_candidate_v1 {
    uint16_t schema_version;
    uint8_t task_root[32];
    uint8_t base_source_root[32];
    uint8_t patch_root[32];
    uint8_t candidate_source_root[32];
    uint8_t adapter_policy_root[32];
    uint8_t author_pubkey[32];
    uint64_t sequence;
    int64_t created_unix;
};

struct vcs_zcode_review_v1 {
    uint16_t schema_version;
    uint8_t task_root[32];
    uint8_t candidate_root[32];
    uint8_t proof_policy_root[32];
    uint8_t proof_set_root[32];
    uint8_t findings_root[32];
    uint8_t reviewer_pubkey[32];
    uint8_t verdict;
    uint64_t sequence;
    int64_t created_unix;
};

struct vcs_zcode_work_receipt_v1 {
    uint16_t schema_version;
    uint8_t task_root[32];
    uint8_t candidate_root[32];
    uint8_t action_root[32];
    uint8_t input_root[32];
    uint8_t output_root[32];
    uint8_t proof_policy_root[32];
    uint8_t toolchain_capsule_root[32];
    uint8_t lease_id[32];
    uint8_t evidence_root[32];
    uint8_t confinement_root[32];
    uint8_t work_kind;
    uint8_t status;
    int32_t exit_status;
    int64_t started_unix;
    int64_t finished_unix;
    uint8_t signer_pubkey[32];
    uint8_t signature[64];
};

enum vcs_zcode_dev_error vcs_zcode_task_validate(
    const struct vcs_zcode_task_v1 *task);
enum vcs_zcode_dev_error vcs_zcode_task_validate_at(
    const struct vcs_zcode_task_v1 *task, int64_t now_unix);
enum vcs_zcode_dev_error vcs_zcode_proof_policy_validate(
    const struct vcs_zcode_proof_policy_v1 *policy);
enum vcs_zcode_dev_error vcs_zcode_candidate_validate(
    const struct vcs_zcode_candidate_v1 *candidate);
enum vcs_zcode_dev_error vcs_zcode_review_validate(
    const struct vcs_zcode_review_v1 *review);
enum vcs_zcode_dev_error vcs_zcode_work_receipt_validate(
    const struct vcs_zcode_work_receipt_v1 *receipt);

enum vcs_zcode_dev_error vcs_zcode_task_serialize(
    const struct vcs_zcode_task_v1 *task,
    uint8_t out[VCS_ZCODE_TASK_WIRE_BYTES]);
enum vcs_zcode_dev_error vcs_zcode_task_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_zcode_task_v1 *out);
enum vcs_zcode_dev_error vcs_zcode_task_root(
    const struct vcs_zcode_task_v1 *task, uint8_t out[32]);

enum vcs_zcode_dev_error vcs_zcode_proof_policy_serialize(
    const struct vcs_zcode_proof_policy_v1 *policy,
    uint8_t out[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES]);
enum vcs_zcode_dev_error vcs_zcode_proof_policy_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_proof_policy_v1 *out);
enum vcs_zcode_dev_error vcs_zcode_proof_policy_root(
    const struct vcs_zcode_proof_policy_v1 *policy, uint8_t out[32]);

enum vcs_zcode_dev_error vcs_zcode_candidate_serialize(
    const struct vcs_zcode_candidate_v1 *candidate,
    uint8_t out[VCS_ZCODE_CANDIDATE_WIRE_BYTES]);
enum vcs_zcode_dev_error vcs_zcode_candidate_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_zcode_candidate_v1 *out);
enum vcs_zcode_dev_error vcs_zcode_candidate_root(
    const struct vcs_zcode_candidate_v1 *candidate, uint8_t out[32]);

enum vcs_zcode_dev_error vcs_zcode_review_serialize(
    const struct vcs_zcode_review_v1 *review,
    uint8_t out[VCS_ZCODE_REVIEW_WIRE_BYTES]);
enum vcs_zcode_dev_error vcs_zcode_review_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_zcode_review_v1 *out);
enum vcs_zcode_dev_error vcs_zcode_review_root(
    const struct vcs_zcode_review_v1 *review, uint8_t out[32]);

enum vcs_zcode_dev_error vcs_zcode_work_receipt_serialize(
    const struct vcs_zcode_work_receipt_v1 *receipt,
    uint8_t out[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES]);
enum vcs_zcode_dev_error vcs_zcode_work_receipt_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_work_receipt_v1 *out);
enum vcs_zcode_dev_error vcs_zcode_work_receipt_id(
    const struct vcs_zcode_work_receipt_v1 *receipt, uint8_t out[32]);

/* Canonical proof-set wires contain strictly ascending, unique canonical
 * work-receipt roots. They are the immutable evidence root reviews bind. */
enum vcs_zcode_dev_error vcs_zcode_proof_set_serialize(
    const uint8_t (*receipt_roots)[32], size_t count, uint8_t *out,
    size_t out_cap, size_t *out_len);
enum vcs_zcode_dev_error vcs_zcode_proof_set_parse(
    const uint8_t *wire, size_t wire_len, uint8_t (*receipt_roots)[32],
    size_t roots_cap, size_t *count);
enum vcs_zcode_dev_error vcs_zcode_proof_set_root(
    const uint8_t (*receipt_roots)[32], size_t count, uint8_t out[32]);

/* Deterministic identity for one inert human decision. It binds the exact
 * task, candidate, proof policy and verified proof set shown to the human;
 * it is not a stored object and grants no acceptance or publication
 * authority. The later accept command re-derives it before writing PROVEN. */
enum vcs_zcode_dev_error vcs_zcode_acceptance_plan_root(
    const uint8_t task_root[32], const uint8_t candidate_root[32],
    const uint8_t proof_policy_root[32], const uint8_t proof_set_root[32],
    uint8_t out[32]);
enum vcs_zcode_dev_error vcs_zcode_work_receipt_seal(
    struct vcs_zcode_work_receipt_v1 *receipt, const uint8_t secret[32],
    const uint8_t pubkey[32]);
enum vcs_zcode_dev_error vcs_zcode_work_receipt_verify(
    const struct vcs_zcode_work_receipt_v1 *receipt,
    const uint8_t expected_signer[32]);

/* Cross-object checks.  These are where stale source/toolchain/policy state is
 * refused; a codec-valid object is not thereby valid for a moved task. */
enum vcs_zcode_dev_error vcs_zcode_candidate_validate_for_task(
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate, int64_t now_unix);
enum vcs_zcode_dev_error vcs_zcode_review_validate_for_candidate(
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_zcode_review_v1 *review, int64_t now_unix);
enum vcs_zcode_dev_error vcs_zcode_work_receipt_validate_for_candidate(
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_zcode_work_receipt_v1 *receipt, int64_t now_unix);

#endif /* ZCL_VCS_ZCODE_DEV_H */
