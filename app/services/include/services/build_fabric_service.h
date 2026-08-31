/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Typed workflows for the durable ZBuild coordinator ledger. */

#ifndef ZCL_SERVICES_BUILD_FABRIC_SERVICE_H
#define ZCL_SERVICES_BUILD_FABRIC_SERVICE_H

#include "base/result.h"
#include "models/build_fabric.h"

#include <stdint.h>

struct vcs_zcode_work_request_v1;
struct vcs_zcode_work_result_v1;

enum {
    BUILD_FABRIC_LEASE_SECONDS_MIN = 5,
    BUILD_FABRIC_LEASE_SECONDS_MAX = 600,
    BUILD_FABRIC_LEASE_SECONDS_DEFAULT = 120,
};

/* Domain-separated immutable identities. The action identity binds every
 * V1 execution input; the job identity additionally binds the source oracle
 * and the ordered action. Neither lifecycle state nor wall time participates. */
struct zcl_result build_fabric_action_id(
    const struct db_build_job *job, const struct db_build_action *action,
    char out_hex[BUILD_FABRIC_ID_HEX + 1]);
struct zcl_result build_fabric_job_id(
    const struct db_build_job *job, const char *action_id,
    char out_hex[BUILD_FABRIC_ID_HEX + 1]);

/* Persist one immutable job/action plan atomically. Repeating the exact plan
 * is idempotent; an id collision with different immutable inputs refuses. */
struct zcl_result build_fabric_plan(struct node_db *ndb,
                                    const struct db_build_job *job,
                                    const struct db_build_action *action);

/* Plan a cross-profile reproduction action. Because profile participates in
 * build_action.v1 this deliberately creates a DIFFERENT action id; it is not
 * the clean-shadow primitive. Clean shadow uses two receipts for one exact
 * action and build_fabric_clean_shadow_compare(). */
struct zcl_result build_fabric_plan_reproduction(
    struct node_db *ndb, const char *primary_action_id,
    const char *reproduction_profile, int64_t now,
    char out_action_id[BUILD_FABRIC_ID_HEX + 1],
    char out_job_id[BUILD_FABRIC_ID_HEX + 1]);

/* Advance PLANNED/SNAPSHOTTED work to QUEUED. */
struct zcl_result build_fabric_submit(struct node_db *ndb,
                                      const char *job_id, int64_t now);

/* A worker lease is an atomic, expiring ownership token. Every transition
 * after claim compares the exact prior state and lease id; restart recovery
 * returns expired work to QUEUED without allowing the old owner to publish. */
struct zcl_result build_fabric_claim(
    struct node_db *ndb, const char *worker_id, const char *lease_id,
    int64_t now, int64_t lease_seconds, struct db_build_action *out,
    bool *claimed);
struct zcl_result build_fabric_start(
    struct node_db *ndb, const char *action_id, const char *lease_id,
    int64_t now);
struct zcl_result build_fabric_heartbeat(
    struct node_db *ndb, const char *action_id, const char *lease_id,
    int64_t now, int64_t lease_seconds);
struct zcl_result build_fabric_begin_verify(
    struct node_db *ndb, const char *action_id, const char *lease_id,
    int64_t now);
struct zcl_result build_fabric_recover_expired(
    struct node_db *ndb, int64_t now, size_t *requeued);
struct zcl_result build_fabric_finish_leased(
    struct node_db *ndb, const char *action_id, const char *lease_id,
    const char *outcome, const char *detail, int64_t now);

/* Idempotently cancel every nonterminal action and the owning job. */
struct zcl_result build_fabric_cancel(struct node_db *ndb,
                                      const char *job_id, int64_t now);

/* Operator trust transitions. Approve creates/updates a worker; revoke never
 * deletes its receipts and is idempotent. */
struct zcl_result build_fabric_worker_approve(
    struct node_db *ndb, const struct db_build_worker *worker, int64_t now);
struct zcl_result build_fabric_worker_revoke(
    struct node_db *ndb, const char *worker_id, int64_t now);

/* Enroll this node's own operator identity as an authority on this node.
 * The key lives in the datadir and is authorized by possession of it, so a
 * requester node that never runs `-buildworker` can still promote a lane it
 * owns. An identity the operator has already ruled on is left exactly as it
 * stands: a revoked or expired local row keeps refusing, because this never
 * resurrects one. */
struct zcl_result build_fabric_worker_enroll_local(
    struct node_db *ndb, const struct db_build_worker *worker, int64_t now);

/* A worker may only quarantine its signed bytes and physical observation.
 * It cannot advance the action or admit a shared cache result. */
struct zcl_result build_fabric_receipt_quarantine(
    struct node_db *ndb, const struct db_build_receipt *receipt, int64_t now);

/* Supervisor-owned admission. Reload and re-hash the canonical observation
 * from CAS, compare it with the immutable action, then atomically promote the
 * quarantined receipt and action. Missing or undeclared observation is RED. */
struct zcl_result build_fabric_receipt_admit(
    struct node_db *ndb, const char *workspace, const char *receipt_id,
    int64_t now);

struct build_fabric_shadow_match {
    bool same_action;
    bool distinct_signers;
    bool artifact_match;
    bool declared_reads_match;
    bool observed_reads_match;
    bool declared_writes_match;
    bool observed_writes_match;
    char artifact_root_sha3[BUILD_FABRIC_ID_HEX + 1];
    char first_bad_invariant[BUILD_FABRIC_ERROR_MAX + 1];
};

/* Compare two preserved physical observations of one exact action. This is a
 * pure admission proof: it never retries, substitutes a clean build, mutates
 * either receipt, or infers physical independence from hostnames. */
struct zcl_result build_fabric_clean_shadow_compare(
    struct node_db *ndb, const char *workspace,
    const char *primary_receipt_id, const char *shadow_receipt_id,
    struct build_fabric_shadow_match *out);

struct build_fabric_release_qualification_report {
    bool candidate_admitted;
    bool clean_shadow_match;
    bool independent_reproduction_match;
    bool distinct_executor_signers;
    bool physical_evidence_present;
    bool human_confirmed;
    bool confirmer_approved;
    bool regression_proof_satisfied;
    bool publication_performed;
    char artifact_root_sha3[BUILD_FABRIC_ID_HEX + 1];
    char confirmation_root_sha3[BUILD_FABRIC_ID_HEX + 1];
    char qualification_root_sha3[BUILD_FABRIC_ID_HEX + 1];
    char first_bad_invariant[BUILD_FABRIC_ERROR_MAX + 1];
};

/* Qualify an inert release candidate from three exact executions, one
 * already-admitted exact regression action/proof set, and one signed human
 * decision. Physical-machine roots are reviewed evidence, not a hostname
 * inference. The function writes only the existing CAS; it cannot publish,
 * deploy, restart, or admit a worker result. */
struct zcl_result build_fabric_release_qualify(
    struct node_db *ndb, const char *workspace,
    const char *confirmation_root_sha3, int64_t now,
    struct build_fabric_release_qualification_report *out);

/* Low-level supervisor transition retained for exact ledger tests and older
 * callers. New worker paths must call quarantine, never this function. */
struct zcl_result build_fabric_receipt_accept(
    struct node_db *ndb, const struct db_build_receipt *receipt, int64_t now);

/* Persist a self-authenticating remote work_receipt.v1 as explicitly
 * untrusted evidence. It never advances the action lifecycle and never makes
 * the signer approved; local reproduction or policy quorum is a later step. */
struct zcl_result build_fabric_receipt_observe_remote(
    struct node_db *ndb, const char *workspace,
    const struct vcs_zcode_work_request_v1 *request,
    const struct vcs_zcode_work_result_v1 *result, int64_t now,
    char receipt_id[BUILD_FABRIC_ID_HEX + 1]);

/* Parse only the closed evidence wires emitted by the fixed confined
 * executors. Target failures are valid evidence and return WORK_FAIL. */
struct zcl_result build_fabric_test_evidence_parse(
    const uint8_t *bytes, size_t len, uint8_t *status, int *exit_status);
struct zcl_result build_fabric_fuzz_evidence_parse(
    const uint8_t *bytes, size_t len, uint32_t expected_seeds,
    uint8_t *status, int *exit_status);

struct build_fabric_proof_evaluation {
    size_t valid_receipts;
    size_t approved_distinct_signers;
    size_t matching_receipts;
    size_t compile_receipts;
    size_t test_receipts;
    size_t fuzz_receipts;
    size_t review_receipts;
    bool local_reproduced;
    bool quorum_satisfied;
    bool compile_satisfied;
    bool test_satisfied;
    bool fuzz_satisfied;
    bool review_satisfied;
    bool release_identity_satisfied;
    bool policy_satisfied;
    char output_root_sha3[BUILD_FABRIC_ID_HEX + 1];
    char proof_set_root_sha3[BUILD_FABRIC_ID_HEX + 1];
};

/* Re-verify canonical receipt bytes from CAS, apply the task's exact proof
 * policy, and promote observations only through local reproduction or a
 * distinct approved-signer quorum. */
struct zcl_result build_fabric_proof_evaluate(
    struct node_db *ndb, const char *workspace, const char *action_id,
    int64_t now, struct build_fabric_proof_evaluation *out);

/* Re-verify the same canonical facts and persist only the immutable proof-set
 * object. This grants no receipt trust promotion and changes no database
 * projection. Repeated materialization of the same set is a CAS no-op. */
struct zcl_result build_fabric_proof_materialize(
    struct node_db *ndb, const char *workspace, const char *action_id,
    int64_t now, struct build_fabric_proof_evaluation *out);

/* Same canonical verification and policy calculation, without writing the
 * proof-set object or promoting receipt trust. Presentation/status readers
 * and release qualification use this to verify current facts without
 * acquiring evidence authority. A release caller must separately require the
 * derived proof-set root to exist as an exact content-addressed CAS object. */
struct zcl_result build_fabric_proof_evaluate_readonly(
    struct node_db *ndb, const char *workspace, const char *action_id,
    int64_t now, struct build_fabric_proof_evaluation *out);

/* Canonical build_receipt.v2 projection id (signature excluded). */
struct zcl_result build_fabric_receipt_id(
    const struct db_build_receipt *receipt,
    char out_hex[BUILD_FABRIC_ID_HEX + 1]);

#endif /* ZCL_SERVICES_BUILD_FABRIC_SERVICE_H */
