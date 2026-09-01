/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: CAS-authoritative ZCODE lane promotion over the ZBuild ledger. */

#include "services/zcode_lane_service.h"

#include "base/bytes.h"
#include "base/hex.h"
#include "crypto/sha3.h"
#include "hotswap/hotswap_service.h"
#include "models/build_fabric.h"
#include "models/zcode_lane.h"
#include "services/build_fabric_service.h"
#include "services/zcode_lane_view_service.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_lane.h"
#include "vcs/zcode_task_index.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool lane_load_raw(const char *workspace, const char *hex,
                          uint8_t **wire, size_t *wire_len, uint8_t root[32])
{
    return zcl_hex_decode_lower(hex, root, 32) &&
           vcs_object_load_raw(workspace, root, wire, wire_len) == 0;
}

static struct zcl_result lane_load_context(
    const char *workspace, const struct db_build_action *action,
    struct vcs_zcode_task_v1 *task,
    struct vcs_zcode_candidate_v1 *candidate,
    struct vcs_zcode_proof_policy_v1 *policy)
{
    uint8_t *wire = NULL, root[32], checked[32]; size_t wire_len = 0;
    if (!lane_load_raw(workspace, action->task_root_sha3,
                       &wire, &wire_len, root) ||
        vcs_zcode_task_parse(wire, wire_len, task) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_task_root(task, checked) != VCS_ZCODE_DEV_OK ||
        memcmp(root, checked, 32) != 0) {
        free(wire); return ZCL_ERR(-1, "lane-task-cas-invalid");
    }
    free(wire); wire = NULL;
    if (!lane_load_raw(workspace, action->candidate_root_sha3,
                       &wire, &wire_len, root) ||
        vcs_zcode_candidate_parse(wire, wire_len, candidate) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_root(candidate, checked) != VCS_ZCODE_DEV_OK ||
        memcmp(root, checked, 32) != 0) {
        free(wire); return ZCL_ERR(-1, "lane-candidate-cas-invalid");
    }
    free(wire); wire = NULL;
    if (!lane_load_raw(workspace, action->proof_policy_root_sha3,
                       &wire, &wire_len, root) ||
        vcs_zcode_proof_policy_parse(wire, wire_len, policy) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_proof_policy_root(policy, checked) != VCS_ZCODE_DEV_OK ||
        memcmp(root, checked, 32) != 0) {
        free(wire); return ZCL_ERR(-1, "lane-policy-cas-invalid");
    }
    free(wire);
    return ZCL_OK;
}

static bool lane_load_receipt(
    const char *workspace, const char *receipt_hex,
    struct vcs_zcode_lane_receipt_v1 *receipt)
{
    uint8_t root[32], checked[32], *wire = NULL; size_t wire_len = 0;
    bool ok = lane_load_raw(workspace, receipt_hex, &wire, &wire_len, root) &&
        vcs_zcode_lane_receipt_parse(wire, wire_len, receipt) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_lane_receipt_id(receipt, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0 &&
        vcs_zcode_lane_receipt_verify(receipt, receipt->signer_pubkey) ==
            VCS_ZCODE_DEV_OK;
    free(wire);
    return ok;
}

static bool lane_view_resolve(int lane, struct zcode_lane_view_result_v1 *view,
                              uint32_t *generation)
{
    if (!view || !generation || lane < VCS_ZCODE_LANE_FRONTIER ||
        lane > VCS_ZCODE_LANE_PROVEN)
        return false;
    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_lane_view_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_LANE_VIEW_SERVICE_ID, &lease);
    if (!service) service = zcode_lane_view_service_builtin();
    *generation = zcl_hotswap_service_generation();
    bool rendered = service->render((uint8_t)lane, view) && view->valid &&
        view->lane_name[0] && view->capability[0] && view->next_action[0];
    zcl_hotswap_service_release(&lease);
    return rendered &&
        strcmp(view->lane_name, vcs_zcode_lane_name((uint8_t)lane)) == 0;
}

static void lane_status_from_row(
    const struct db_zcode_lane_receipt *row,
    const struct zcode_lane_view_result_v1 *view, uint32_t generation,
    struct zcode_lane_status *out)
{
    memset(out, 0, sizeof(*out));
    out->lane = row->lane;
    (void)snprintf(out->lane_name, sizeof(out->lane_name), "%.15s",
                   view->lane_name);
    (void)snprintf(out->source_root_sha3, sizeof(out->source_root_sha3),
                   "%s", row->source_root_sha3);
    (void)snprintf(out->task_root_sha3, sizeof(out->task_root_sha3),
                   "%s", row->task_root_sha3);
    (void)snprintf(out->candidate_root_sha3, sizeof(out->candidate_root_sha3),
                   "%s", row->candidate_root_sha3);
    (void)snprintf(out->proof_policy_root_sha3,
                   sizeof(out->proof_policy_root_sha3), "%s",
                   row->proof_policy_root_sha3);
    (void)snprintf(out->proof_set_root_sha3,
                   sizeof(out->proof_set_root_sha3), "%s",
                   row->proof_set_root_sha3);
    (void)snprintf(out->receipt_root_sha3, sizeof(out->receipt_root_sha3),
                   "%s", row->receipt_id);
    (void)snprintf(out->prior_receipt_root_sha3,
                   sizeof(out->prior_receipt_root_sha3), "%s",
                   row->prior_receipt_root_sha3);
    (void)snprintf(out->signer_pubkey, sizeof(out->signer_pubkey), "%s",
                   row->signer_pubkey);
    out->created_at = row->created_at;
    out->view_service_generation = generation;
    (void)snprintf(out->capability, sizeof(out->capability), "%s",
                   view->capability);
    (void)snprintf(out->next_action, sizeof(out->next_action), "%s",
                   view->next_action);
}

static bool lane_row_matches_receipt(
    const struct db_zcode_lane_receipt *row,
    const struct vcs_zcode_lane_receipt_v1 *receipt)
{
    char hex[65];
    zcl_hex_encode(receipt->source_root, 32, hex);
    if (strcmp(hex, row->source_root_sha3) != 0) return false;
    zcl_hex_encode(receipt->task_root, 32, hex);
    if (strcmp(hex, row->task_root_sha3) != 0) return false;
    zcl_hex_encode(receipt->candidate_root, 32, hex);
    if (strcmp(hex, row->candidate_root_sha3) != 0) return false;
    zcl_hex_encode(receipt->proof_policy_root, 32, hex);
    if (strcmp(hex, row->proof_policy_root_sha3) != 0) return false;
    zcl_hex_encode(receipt->proof_set_root, 32, hex);
    if ((zcl_bytes_any_set(receipt->proof_set_root, 32) &&
         strcmp(hex, row->proof_set_root_sha3) != 0) ||
        (!zcl_bytes_any_set(receipt->proof_set_root, 32) &&
         row->proof_set_root_sha3[0]))
        return false;
    zcl_hex_encode(receipt->prior_receipt_root, 32, hex);
    if ((zcl_bytes_any_set(receipt->prior_receipt_root, 32) &&
         strcmp(hex, row->prior_receipt_root_sha3) != 0) ||
        (!zcl_bytes_any_set(receipt->prior_receipt_root, 32) &&
         row->prior_receipt_root_sha3[0]))
        return false;
    zcl_hex_encode(receipt->signer_pubkey, 32, hex);
    if (strcmp(hex, row->signer_pubkey) != 0) return false;
    return receipt->lane == row->lane &&
           receipt->created_unix == row->created_at;
}

struct zcl_result zcode_lane_find(
    struct node_db *ndb, const char *workspace,
    const char *source_root_sha3, struct zcode_lane_status *out)
{
    struct db_zcode_lane_receipt row;
    struct vcs_zcode_lane_receipt_v1 receipt;
    if (!ndb || !ndb->open || !workspace || !source_root_sha3 || !out ||
        !db_zcode_lane_latest(ndb, source_root_sha3, &row))
        return ZCL_ERR(-1, "zcode-lane-not-found");
    if (!lane_load_receipt(workspace, row.receipt_id, &receipt) ||
        !lane_row_matches_receipt(&row, &receipt))
        return ZCL_ERR(-1, "zcode-lane-projection-or-cas-corrupt");
    struct zcode_lane_view_result_v1 view;
    uint32_t generation = 0;
    if (!lane_view_resolve(row.lane, &view, &generation))
        return ZCL_ERR(-1, "zcode-lane-view-mismatch");
    lane_status_from_row(&row, &view, generation, out);
    return ZCL_OK;
}

static void accepted_worker_id(
    const uint8_t signer[32], uint8_t root[32], char hex[65])
{
    static const char domain[] = "zcl.build_worker.v1";
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, signer, 32);
    sha3_256_finalize(&sha, root);
    zcl_hex_encode(root, 32, hex);
}

static bool accepted_signer_current(
    struct node_db *ndb, const uint8_t signer[32], int64_t now,
    char worker_id_out[65])
{
    uint8_t worker_root[32];
    char worker_id[65], signer_hex[65];
    struct db_build_worker worker;
    accepted_worker_id(signer, worker_root, worker_id);
    zcl_hex_encode(signer, 32, signer_hex);
    bool current = db_build_worker_find(ndb, worker_id, &worker) &&
        strcmp(worker.signer_pubkey, signer_hex) == 0 &&
        worker.approved && !worker.revoked &&
        (worker.expires_at == 0 || now < worker.expires_at);
    if (current && worker_id_out)
        (void)snprintf(worker_id_out, 65, "%s", worker_id);
    return current;
}

static void accepted_row_from_receipt(
    const struct vcs_zcode_lane_receipt_v1 *receipt,
    const uint8_t root[32], struct db_zcode_lane_receipt *row)
{
    memset(row, 0, sizeof(*row));
    zcl_hex_encode(root, 32, row->receipt_id);
    zcl_hex_encode(receipt->source_root, 32, row->source_root_sha3);
    zcl_hex_encode(receipt->task_root, 32, row->task_root_sha3);
    zcl_hex_encode(receipt->candidate_root, 32, row->candidate_root_sha3);
    zcl_hex_encode(receipt->proof_policy_root, 32,
                   row->proof_policy_root_sha3);
    if (receipt->lane != VCS_ZCODE_LANE_FRONTIER) {
        zcl_hex_encode(receipt->proof_set_root, 32,
                       row->proof_set_root_sha3);
        zcl_hex_encode(receipt->prior_receipt_root, 32,
                       row->prior_receipt_root_sha3);
    }
    zcl_hex_encode(receipt->signer_pubkey, 32, row->signer_pubkey);
    row->lane = receipt->lane;
    row->created_at = receipt->created_unix;
}

static bool accepted_projection_row(
    struct node_db *ndb, const struct vcs_zcode_lane_receipt_v1 *receipt,
    const uint8_t root[32], bool save)
{
    struct db_zcode_lane_receipt expected, stored;
    accepted_row_from_receipt(receipt, root, &expected);
    if (save && !db_zcode_lane_receipt_save(ndb, &expected))
        return false;
    return db_zcode_lane_receipt_find(ndb, expected.receipt_id, &stored) &&
        lane_row_matches_receipt(&stored, receipt);
}

static struct zcl_result accepted_projection_check(
    struct node_db *ndb, const struct vcs_zcode_accepted_work_v1 *accepted,
    bool rebuild, bool *rebuilt)
{
    const struct vcs_zcode_lane_receipt_v1 *receipts[] = {
        &accepted->frontier, &accepted->candidate_lane, &accepted->proven,
    };
    const uint8_t *roots[] = {
        accepted->frontier_root, accepted->candidate_lane_root,
        accepted->accepted_work_root,
    };
    size_t present = 0;
    for (size_t i = 0; i < 3; i++) {
        char hex[65];
        struct db_zcode_lane_receipt row;
        zcl_hex_encode(roots[i], 32, hex);
        if (db_zcode_lane_receipt_find(ndb, hex, &row)) present++;
    }
    if (present != 0 && present != 3)
        return ZCL_ERR(-1, "accepted-lane-projection-partial");
    if (present == 0 && !rebuild)
        return ZCL_ERR(-1, "accepted-lane-projection-absent");
    bool save = present == 0;
    for (size_t i = 0; i < 3; i++)
        if (!accepted_projection_row(ndb, receipts[i], roots[i], save))
            return ZCL_ERR(-1, "accepted-lane-projection-cas-disagreement");
    if (rebuilt) *rebuilt = save;
    return ZCL_OK;
}

/* long-function-ok:accepted-work-authority-join -- one fail-closed join over
 * immutable CAS acceptance and all live revocation/projection authorities. */
struct zcl_result zcode_accepted_work_find(
    struct node_db *ndb, const char *workspace,
    const char *source_root_sha3, int64_t now,
    bool rebuild_projection, struct zcode_accepted_work_status *out)
{
    uint8_t source_root[32];
    if (!ndb || !ndb->open || !workspace || !source_root_sha3 ||
        !zcl_hex_decode_lower(source_root_sha3, source_root, 32) ||
        now <= 0 || !out)
        return ZCL_ERR(-1, "accepted-work-input-invalid");
    memset(out, 0, sizeof(*out));
    struct vcs_zcode_task_index *index =
        vcs_zcode_task_index_build(workspace, now);
    if (!index) return ZCL_ERR(-1, "accepted-work-index-failed");
    size_t matches = 0;
    for (size_t i = 0; i < vcs_zcode_task_index_lane_count(index); i++) {
        const struct vcs_zcode_task_lane_entry *lane =
            vcs_zcode_task_index_lane_at(index, i);
        uint8_t accepted_root[32];
        struct vcs_zcode_accepted_work_v1 accepted;
        if (!lane || lane->lane != VCS_ZCODE_LANE_PROVEN ||
            strcmp(lane->source_root_hex, source_root_sha3) != 0 ||
            !zcl_hex_decode_lower(
                lane->receipt_root_hex, accepted_root, 32) ||
            !vcs_zcode_accepted_work_resolve(
                workspace, accepted_root, now, &accepted) ||
            memcmp(accepted.proven.source_root, source_root, 32) != 0)
            continue;
        if (matches == 0) out->accepted = accepted;
        matches++;
    }
    if (matches != 1) {
        vcs_zcode_task_index_free(index);
        return ZCL_ERR(-1, matches > 1
            ? "accepted-work-source-ambiguous"
            : "accepted-work-not-human-accepted");
    }
    char task_hex[65], candidate_hex[65], policy_hex[65], proof_hex[65];
    zcl_hex_encode(out->accepted.task_root, 32, task_hex);
    zcl_hex_encode(out->accepted.candidate_root, 32, candidate_hex);
    zcl_hex_encode(out->accepted.proof_policy_root, 32, policy_hex);
    zcl_hex_encode(out->accepted.proof_set_root, 32, proof_hex);
    enum { ACCEPTED_ACTION_MAX = 64 };
    struct db_build_action actions[ACCEPTED_ACTION_MAX + 1];
    int action_count = db_build_candidate_actions(
        ndb, task_hex, candidate_hex, policy_hex, actions,
        ACCEPTED_ACTION_MAX + 1);
    if (action_count <= 0 || action_count > ACCEPTED_ACTION_MAX) {
        vcs_zcode_task_index_free(index);
        return ZCL_ERR(-1, "accepted-work-action-projection-mismatch");
    }
    bool evaluated = false;
    for (int i = 0; i < action_count; i++) {
        struct build_fabric_proof_evaluation evaluation = {0};
        if (build_fabric_proof_evaluate(
                ndb, workspace, actions[i].action_id, now, &evaluation).ok &&
            evaluation.policy_satisfied &&
            strcmp(evaluation.proof_set_root_sha3, proof_hex) == 0) {
            size_t action_id_len = strlen(actions[i].action_id);
            if (action_id_len != sizeof(out->action_id) - 1)
                continue;
            if (!evaluated)
                memcpy(out->action_id, actions[i].action_id,
                       action_id_len + 1);
            evaluated = true;
        }
    }
    if (!evaluated) {
        vcs_zcode_task_index_free(index);
        return ZCL_ERR(-1, "accepted-work-proof-set-or-policy-mismatch");
    }
    if (!accepted_signer_current(
            ndb, out->accepted.expected_signer, now, out->worker_id)) {
        vcs_zcode_task_index_free(index);
        return ZCL_ERR(-1, "accepted-work-signer-unapproved-expired-or-revoked");
    }
    struct zcl_result projection = accepted_projection_check(
        ndb, &out->accepted, rebuild_projection,
        &out->projection_rebuilt);
    vcs_zcode_task_index_free(index);
    return projection;
}

static struct zcl_result lane_prior_validate(
    const char *workspace, const struct db_zcode_lane_receipt *prior,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_zcode_proof_policy_v1 *policy,
    const uint8_t signer_pubkey[32])
{
    struct vcs_zcode_lane_receipt_v1 receipt;
    if (!lane_load_receipt(workspace, prior->receipt_id, &receipt) ||
        !lane_row_matches_receipt(prior, &receipt) ||
        vcs_zcode_lane_receipt_validate_for_candidate(
            &receipt, task, candidate, policy) != VCS_ZCODE_DEV_OK ||
        memcmp(receipt.signer_pubkey, signer_pubkey, 32) != 0)
        return ZCL_ERR(-1, "prior-lane-receipt-invalid-or-wrong-signer");
    return ZCL_OK;
}

// long-function-ok:promotion-transaction — proof evaluation, prior-chain
// verification, CAS write, and model projection form one fail-closed ritual.
struct zcl_result zcode_lane_advance(
    struct node_db *ndb, const char *workspace, const char *action_id,
    int target_lane, int64_t now, const uint8_t signer_secret[32],
    const uint8_t signer_pubkey[32], struct zcode_lane_status *out)
{
    if (!ndb || !ndb->open || !workspace || !action_id || now <= 0 ||
        !signer_secret || !signer_pubkey || !out ||
        target_lane < VCS_ZCODE_LANE_FRONTIER ||
        target_lane > VCS_ZCODE_LANE_PROVEN)
        return ZCL_ERR(-1, "lane-advance-input-invalid");
    struct zcode_lane_view_result_v1 target_view;
    uint32_t view_generation = 0;
    if (!lane_view_resolve(target_lane, &target_view, &view_generation))
        return ZCL_ERR(-1, "lane-view-mismatch");
    struct db_build_action action;
    if (!db_build_action_find(ndb, action_id, &action) ||
        !action.task_root_sha3[0])
        return ZCL_ERR(-1, "lane-action-not-found");
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    struct vcs_zcode_proof_policy_v1 policy;
    ZCL_CHECK(lane_load_context(
        workspace, &action, &task, &candidate, &policy));
    if (memcmp(candidate.author_pubkey, signer_pubkey, 32) != 0)
        return ZCL_ERR(-1, "lane-signer-is-not-candidate-work-authority");
    /* FRONTIER admission precedes the first build-worker claim, so its
     * candidate-author key is pinned above but is not live-ledger-approved
     * until execution begins. Any proof-bearing promotion must use the
     * current, non-revoked worker authority. */
    if (target_lane != VCS_ZCODE_LANE_FRONTIER &&
        !accepted_signer_current(ndb, signer_pubkey, now, NULL))
        return ZCL_ERR(-1, "lane-signer-unapproved-expired-or-revoked");
    if (vcs_zcode_candidate_validate_for_task(&task, &candidate, now) !=
            VCS_ZCODE_DEV_OK)
        return ZCL_ERR(-1, "lane-candidate-stale-or-expired");
    char source_hex[65];
    zcl_hex_encode(candidate.candidate_source_root, 32, source_hex);
    struct db_zcode_lane_receipt prior;
    bool have_prior = db_zcode_lane_latest(ndb, source_hex, &prior);
    if (have_prior && prior.lane >= target_lane) {
        if (prior.lane > target_lane)
            return ZCL_ERR(-1, "lane-downgrade-refused");
        if (strcmp(prior.task_root_sha3, action.task_root_sha3) != 0 ||
            strcmp(prior.candidate_root_sha3,
                   action.candidate_root_sha3) != 0 ||
            strcmp(prior.proof_policy_root_sha3,
                   action.proof_policy_root_sha3) != 0)
            return ZCL_ERR(-1, "lane-idempotency-context-mismatch");
        ZCL_CHECK(lane_prior_validate(
            workspace, &prior, &task, &candidate, &policy, signer_pubkey));
        lane_status_from_row(&prior, &target_view, view_generation, out);
        return ZCL_OK;
    }
    if ((!have_prior && target_lane != VCS_ZCODE_LANE_FRONTIER) ||
        (have_prior && target_lane != prior.lane + 1))
        return ZCL_ERR(-1, "lane-transition-must-be-sequential");
    if (have_prior)
        ZCL_CHECK(lane_prior_validate(
            workspace, &prior, &task, &candidate, &policy, signer_pubkey));
    if (have_prior && now < prior.created_at)
        return ZCL_ERR(-1, "lane-promotion-time-precedes-prior-receipt");
    struct build_fabric_proof_evaluation evaluation = {0};
    if (target_lane != VCS_ZCODE_LANE_FRONTIER) {
        ZCL_CHECK(build_fabric_proof_evaluate(
            ndb, workspace, action_id, now, &evaluation));
        bool candidate_ready = evaluation.compile_satisfied &&
            (!(policy.required_proofs & VCS_ZCODE_PROOF_TEST) ||
             evaluation.test_satisfied);
        if (target_lane == VCS_ZCODE_LANE_CANDIDATE && !candidate_ready)
            return ZCL_ERR(-1, "candidate-fast-proof-policy-unsatisfied");
        if (target_lane == VCS_ZCODE_LANE_PROVEN &&
            !evaluation.policy_satisfied)
            return ZCL_ERR(-1, "proven-proof-policy-unsatisfied");
    }
    struct vcs_zcode_lane_receipt_v1 receipt = {
        .schema_version = VCS_ZCODE_DEV_VERSION,
        .lane = (uint8_t)target_lane,
        .created_unix = now,
    };
    memcpy(receipt.source_root, candidate.candidate_source_root, 32);
    (void)zcl_hex_decode_lower(action.task_root_sha3, receipt.task_root, 32);
    (void)zcl_hex_decode_lower(
        action.candidate_root_sha3, receipt.candidate_root, 32);
    (void)zcl_hex_decode_lower(
        action.proof_policy_root_sha3, receipt.proof_policy_root, 32);
    if (target_lane != VCS_ZCODE_LANE_FRONTIER) {
        if (!zcl_hex_decode_lower(evaluation.proof_set_root_sha3,
                                  receipt.proof_set_root, 32) ||
            !zcl_hex_decode_lower(prior.receipt_id,
                                  receipt.prior_receipt_root, 32))
            return ZCL_ERR(-1, "lane-proof-or-prior-root-invalid");
    }
    if (vcs_zcode_lane_receipt_seal(
            &receipt, signer_secret, signer_pubkey) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_lane_receipt_validate_for_candidate(
            &receipt, &task, &candidate, &policy) != VCS_ZCODE_DEV_OK)
        return ZCL_ERR(-1, "lane-receipt-seal-refused");
    uint8_t wire[VCS_ZCODE_LANE_WIRE_BYTES], root[32]; char root_hex[65];
    if (vcs_zcode_lane_receipt_serialize(&receipt, wire) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_lane_receipt_id(&receipt, root) != VCS_ZCODE_DEV_OK)
        return ZCL_ERR(-1, "lane-receipt-encoding-failed");
    zcl_hex_encode(root, 32, root_hex);
    if (!vcs_object_put_addressed(workspace, root, wire, sizeof(wire)))
        return ZCL_ERR(-1, "lane-receipt-cas-store-failed");
    struct vcs_zcode_lane_receipt_v1 persisted_receipt;
    uint8_t persisted_wire[VCS_ZCODE_LANE_WIRE_BYTES];
    if (!lane_load_receipt(workspace, root_hex, &persisted_receipt) ||
        vcs_zcode_lane_receipt_serialize(
            &persisted_receipt, persisted_wire) != VCS_ZCODE_DEV_OK ||
        memcmp(persisted_wire, wire, sizeof(wire)) != 0)
        return ZCL_ERR(-1, "lane-receipt-cas-readback-mismatch");
    struct db_zcode_lane_receipt row = { .lane = target_lane,
                                        .created_at = now };
    (void)snprintf(row.receipt_id, sizeof(row.receipt_id), "%s", root_hex);
    (void)snprintf(row.source_root_sha3, sizeof(row.source_root_sha3),
                   "%s", source_hex);
    (void)snprintf(row.task_root_sha3, sizeof(row.task_root_sha3), "%s",
                   action.task_root_sha3);
    (void)snprintf(row.candidate_root_sha3,
                   sizeof(row.candidate_root_sha3), "%s",
                   action.candidate_root_sha3);
    (void)snprintf(row.proof_policy_root_sha3,
                   sizeof(row.proof_policy_root_sha3), "%s",
                   action.proof_policy_root_sha3);
    if (target_lane != VCS_ZCODE_LANE_FRONTIER) {
        (void)snprintf(row.proof_set_root_sha3,
                       sizeof(row.proof_set_root_sha3), "%s",
                       evaluation.proof_set_root_sha3);
        (void)snprintf(row.prior_receipt_root_sha3,
                       sizeof(row.prior_receipt_root_sha3), "%s",
                       prior.receipt_id);
    }
    zcl_hex_encode(signer_pubkey, 32, row.signer_pubkey);
    if (!db_zcode_lane_receipt_save(ndb, &row))
        return ZCL_ERR(-1, "lane-receipt-projection-save-failed");
    struct db_zcode_lane_receipt stored;
    if (!db_zcode_lane_receipt_find(ndb, root_hex, &stored) ||
        !lane_row_matches_receipt(&stored, &receipt))
        return ZCL_ERR(-1, "lane-receipt-projection-verify-failed");
    lane_status_from_row(&stored, &target_view, view_generation, out);
    return ZCL_OK;
}

static bool lane_view_frozen_kat(const void *opaque, char *why,
                                 size_t why_sz)
{
    const struct zcode_lane_view_service_v1 *service = opaque;
    struct zcode_lane_view_result_v1 view;
    static const struct {
        uint8_t lane;
        const char *name;
        const char *next_action;
    } cases[] = {
        {ZCODE_LANE_VIEW_GUIDE, "FRONTIER -> CANDIDATE -> PROVEN",
         "zcode package dev lane --input='{\"workspace\":\"<path>\",\"source_root\":\"<64hex>\",\"datadir\":\"/tmp/zclassic23-lane\"}'"},
        {VCS_ZCODE_LANE_FRONTIER, "FRONTIER",
         "zcode accept --input='<action_id and lane CANDIDATE>'"},
        {VCS_ZCODE_LANE_CANDIDATE, "CANDIDATE",
         "zcode work accept --input='{\"work\":\"latest\"}'"},
        {VCS_ZCODE_LANE_PROVEN, "PROVEN", "zcode publish plan"},
    };
    if (!service || !service->render) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen lane view service shape failed");
        return false;
    }
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (!service->render(cases[i].lane, &view) || !view.valid ||
            strcmp(view.lane_name, cases[i].name) != 0 ||
            strcmp(view.next_action, cases[i].next_action) != 0) {
            if (why && why_sz) (void)snprintf(
                why, why_sz, "frozen lane view vector %zu failed", i);
            return false;
        }
    }
    if (service->render(UINT8_MAX, &view)) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen unknown lane rejection failed");
        return false;
    }
    return true;
}

static const struct zcl_hotswap_service_contract k_lane_view_contract = {
    .service_id = ZCODE_LANE_VIEW_SERVICE_ID,
    .source_tu = "contexts/commons/services/src/zcode_lane_view_service.c",
    .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
    .vtable_size = sizeof(struct zcode_lane_view_service_v1),
    .abi_fingerprint = ZCODE_LANE_VIEW_ABI_FINGERPRINT,
    .schema_fingerprint = ZCODE_LANE_VIEW_SCHEMA_FINGERPRINT,
    .wire_fingerprint = ZCODE_LANE_VIEW_WIRE_FINGERPRINT,
    .kat_fingerprint = ZCODE_LANE_VIEW_KAT_FINGERPRINT,
    .frozen_kat = lane_view_frozen_kat,
};

const struct zcl_hotswap_service_contract *
zcode_lane_view_service_contract(void)
{
    return &k_lane_view_contract;
}
