/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: scratch-only Proof-of-Participation epoch schedule proposals. */

#include "command/native_command.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "hotswap/hotswap_service.h"
#include "services/zcode_c23_economics_service.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_claim_epoch.h"
#include "vcs/zcode_commons_projection.h"
#include "vcs/zcode_epoch_schedule.h"

#include <stdlib.h>
#include <string.h>

static const char *zep_str(const struct json_value *input, const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool zep_keys(const struct json_value *input,
                     const char *const *allowed, size_t count)
{
    if (!input || input->type != JSON_OBJ) return false;
    for (size_t i = 0; i < input->num_children; i++) {
        bool known = false;
        for (size_t j = 0; j < count; j++)
            known = known || strcmp(input->keys[i], allowed[j]) == 0;
        if (!known) return false;
    }
    return true;
}

static bool zep_root(const struct json_value *input, const char *key,
                     uint8_t root[32])
{
    const char *hex = zep_str(input, key);
    return hex && strlen(hex) == 64 && zcl_hex_decode_lower(hex, root, 32);
}

static bool zep_u64_positive(const struct json_value *input, const char *key,
                             uint64_t *out)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    if (!value || value->type != JSON_INT || json_get_int(value) <= 0)
        return false;
    *out = (uint64_t)json_get_int(value);
    return true;
}

static void zep_fail(struct zcl_command_reply *reply, const char *code,
                     const char *detail)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "validate", false,
                           false, detail, "zcode.commons.schedule.propose");
}

static void zep_claim_fail(struct zcl_command_reply *reply, const char *code,
                           const char *detail, const char *command)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "validate", false,
                           false, detail, command);
}

static void zep_hex(struct json_value *data, const char *key,
                    const uint8_t root[32])
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    (void)json_push_kv_str(data, key, hex);
}

static bool zep_workspace(const char *workspace,
                          struct zcl_command_reply *reply)
{
    if (zcl_native_zcode_workspace_is_explicit_scratch(workspace))
        return true;
    zep_fail(reply, "UNSAFE_PROPOSE_WORKSPACE",
             "workspace must explicitly name an isolated tmp, test-tmp, or scratch path");
    return false;
}

static bool zep_render_proposal(
    struct json_value *data,
    const struct vcs_zcode_epoch_schedule_proposal_v1 *proposal,
    const uint8_t proposal_root[32],
    const struct zcode_c23_economics_service_v1 *service,
    uint64_t service_generation, bool persisted)
{
    struct zcode_c23_schedule_proposal_view_v1 view;
    if (!service || !service->render_schedule_proposal ||
        !service->schedule_class_name ||
        !service->render_schedule_proposal(proposal, persisted, &view))
        return false;
    (void)json_push_kv_str(data, "service_id",
                           ZCODE_C23_ECONOMICS_SERVICE_ID);
    (void)json_push_kv_int(data, "service_generation",
                           (int64_t)service_generation);
    (void)json_push_kv_bool(data, "pure_calculation", true);
    zep_hex(data, "schedule_proposal_root", proposal_root);
    zep_hex(data, "previous_proposal_root",
            proposal->previous_proposal_root);
    (void)json_push_kv_int(data, "epoch", (int64_t)view.epoch);
    (void)json_push_kv_int(data, "cap_atoms", (int64_t)view.cap_atoms);
    (void)json_push_kv_int(data, "total_epochs",
                           (int64_t)view.total_epochs);
    (void)json_push_kv_int(data, "budget_atoms", (int64_t)view.budget_atoms);
    (void)json_push_kv_int(data, "already_emitted_atoms",
                           (int64_t)view.already_emitted_atoms);
    (void)json_push_kv_int(data, "proposed_mint_atoms",
                           (int64_t)view.proposed_mint_atoms);
    (void)json_push_kv_int(data, "unissued_atoms",
                           (int64_t)view.unissued_atoms);
    (void)json_push_kv_int(data, "evidence_count",
                           (int64_t)view.evidence_count);
    (void)json_push_kv_int(data, "eligible_count",
                           (int64_t)view.eligible_count);
    (void)json_push_kv_int(data, "preservation_skipped",
                           (int64_t)view.preservation_skipped);
    (void)json_push_kv_str(data, "preservation_skip_reason",
                           view.preservation_skip_reason);
    (void)json_push_kv_int(data, "class_weight_creation",
                           (int64_t)view.class_weights[0]);
    (void)json_push_kv_int(data, "class_weight_reproduction",
                           (int64_t)view.class_weights[1]);
    (void)json_push_kv_int(data, "class_weight_repair",
                           (int64_t)view.class_weights[2]);
    (void)json_push_kv_int(data, "class_weight_preservation",
                           (int64_t)view.class_weights[3]);
    struct json_value allocations;
    json_init(&allocations); json_set_array(&allocations);
    for (size_t i = 0; i < proposal->allocation_count; i++) {
        const struct vcs_zcode_epoch_schedule_allocation *allocation =
            &proposal->allocations[i];
        struct json_value row;
        char class_name[16];
        json_init(&row); json_set_object(&row);
        zep_hex(&row, "contributor_binding_root",
                allocation->contributor_binding_root);
        if (!service->schedule_class_name(allocation->schedule_class,
                                          class_name, sizeof(class_name))) {
            json_free(&row);
            json_free(&allocations);
            return false;
        }
        (void)json_push_kv_str(&row, "class", class_name);
        (void)json_push_kv_int(&row, "award_atoms",
                               (int64_t)allocation->award_atoms);
        (void)json_push_back(&allocations, &row);
        json_free(&row);
    }
    (void)json_push_kv(data, "allocations", &allocations);
    json_free(&allocations);
    (void)json_push_kv_str(data, "mint_authority", view.mint_authority);
    (void)json_push_kv_bool(data, "simulated", view.simulated);
    (void)json_push_kv_bool(data, "persisted", view.persisted);
    (void)json_push_kv_bool(data, "schedule_proposal",
                            view.schedule_proposal);
    (void)json_push_kv_bool(data, "mint", view.mint);
    (void)json_push_kv_bool(data, "token_exists", view.token_exists);
    (void)json_push_kv_bool(data, "funds_moved", view.funds_moved);
    (void)json_push_kv_bool(data, "custody_used", view.custody_used);
    (void)json_push_kv_bool(data, "genesis_gate_satisfied",
                            view.genesis_gate_satisfied);
    (void)json_push_kv_bool(data, "balance_used_for_truth",
                            view.balance_used_for_truth);
    return true;
}

static bool zep_parse_propose(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    struct vcs_zcode_epoch_schedule_input *input,
    uint8_t previous_proposal_root[32])
{
    static const char *const keys[] = {
        "workspace", "epoch", "previous_proposal_root",
    };
    memset(input, 0, sizeof(*input));
    const char *workspace = request
        ? zep_str(request->input, "workspace") : NULL;
    if (!request || !reply || !workspace ||
        !zep_keys(request->input, keys, sizeof(keys) / sizeof(keys[0])) ||
        !zep_u64_positive(request->input, "epoch", &input->epoch) ||
        !zep_root(request->input, "previous_proposal_root",
                  previous_proposal_root)) {
        zep_fail(reply, "BAD_PROPOSE_INPUT",
                 "closed input requires workspace, positive epoch and previous_proposal_root");
        return false;
    }
    if (!zep_workspace(workspace, reply)) return false;
    input->workspace = workspace;
    input->previous_proposal_root = previous_proposal_root;
    return true;
}

static void zep_propose_handle(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    bool persist)
{
    struct vcs_zcode_epoch_schedule_input input;
    struct vcs_zcode_epoch_schedule_proposal_v1 proposal;
    uint8_t previous_proposal_root[32], proposal_root[32];
    if (!zep_parse_propose(request, reply, &input,
                           previous_proposal_root))
        return;
    enum vcs_zcode_epoch_schedule_error error =
        vcs_zcode_epoch_schedule_propose_cas(&input, &proposal);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (error == VCS_ZCODE_EPOCH_SCHEDULE_OK)
        error = vcs_zcode_epoch_schedule_root(&proposal, proposal_root);
    if (error == VCS_ZCODE_EPOCH_SCHEDULE_OK)
        error = vcs_zcode_epoch_schedule_serialize(&proposal, &wire,
                                                   &wire_len);
    if (error != VCS_ZCODE_EPOCH_SCHEDULE_OK) {
        zep_fail(reply, "EPOCH_SCHEDULE_PROPOSE_REFUSED",
                 vcs_zcode_epoch_schedule_error_string(error));
        vcs_zcode_epoch_schedule_proposal_free(&proposal);
        free(wire);
        return;
    }
    if (persist &&
        (!vcs_object_store_init(input.workspace) ||
         !vcs_object_put_addressed(input.workspace, proposal_root,
                                   wire, wire_len))) {
        zep_fail(reply, "EPOCH_SCHEDULE_STORE_REFUSED",
                 "existing scratch CAS refused the canonical schedule proposal");
        vcs_zcode_epoch_schedule_proposal_free(&proposal);
        free(wire);
        return;
    }
    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_c23_economics_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_C23_ECONOMICS_SERVICE_ID, &lease);
    if (!service) service = zcode_c23_economics_service_builtin();
    uint64_t service_generation = zcl_hotswap_service_generation();
    if (!zep_render_proposal(&reply->data, &proposal, proposal_root, service,
                             service_generation, persist)) {
        zcl_hotswap_service_release(&lease);
        zep_fail(reply, "EPOCH_SCHEDULE_VIEW_REFUSED",
                 "the pure economics service refused the validated proposal view");
        vcs_zcode_epoch_schedule_proposal_free(&proposal);
        free(wire);
        return;
    }
    zcl_hotswap_service_release(&lease);
    vcs_zcode_epoch_schedule_proposal_free(&proposal);
    free(wire);
}

void zcl_native_handle_zcode_commons_schedule_propose_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zep_propose_handle(request, reply, false);
}

void zcl_native_handle_zcode_commons_schedule_propose_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zep_propose_handle(request, reply, true);
}

/* The v1 schedule proposer above intentionally preserves its creation-
 * attribution inputs and roots.  This additive planner is the first native
 * consumer of the signed creation_claim.v2 projection and the frozen v2
 * selector.  Static code retains parsing and projection ownership; only the
 * pure calculation crosses the hot-swappable economics ABI. */
static void zep_claim_handle(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    bool persist)
{
    static const char *const keys[] = {
        "workspace", "epoch", "cutoff_height", "cutoff_mtp",
        "epoch_capacity_atoms", "previous_epoch_root",
        "network_genesis_root", "moderation_policy_root",
        "qualification_predicates_root", "backlog_algorithm_root",
    };
    struct vcs_zcode_epoch_selection_v2 input;
    struct vcs_zcode_policy_candidate_v2 policy;
    struct vcs_zcode_epoch_selection_result_v2 result;
    uint8_t roots[5][32], policy_root[32], projection_root[32];
    uint64_t cutoff_mtp_u64 = 0;
    const char *command = persist
        ? "zcode.commons.schedule.claim.commit"
        : "zcode.commons.schedule.claim.plan";
    memset(&input, 0, sizeof(input));
    const char *workspace = request
        ? zep_str(request->input, "workspace") : NULL;
    if (!request || !reply || !workspace ||
        !zep_keys(request->input, keys, sizeof(keys) / sizeof(keys[0])) ||
        !zep_u64_positive(request->input, "epoch", &input.epoch) ||
        !zep_u64_positive(request->input, "cutoff_height",
                          &input.cutoff_height) ||
        !zep_u64_positive(request->input, "cutoff_mtp", &cutoff_mtp_u64) ||
        cutoff_mtp_u64 > INT64_MAX ||
        !zep_u64_positive(request->input, "epoch_capacity_atoms",
                          &input.epoch_capacity_atoms) ||
        !zep_root(request->input, "previous_epoch_root", roots[0]) ||
        !zep_root(request->input, "network_genesis_root", roots[1]) ||
        !zep_root(request->input, "moderation_policy_root", roots[2]) ||
        !zep_root(request->input, "qualification_predicates_root", roots[3]) ||
        !zep_root(request->input, "backlog_algorithm_root", roots[4])) {
        zep_claim_fail(reply, "BAD_CLAIM_EPOCH_INPUT",
                       "closed input requires scratch workspace, positive epoch/cutoffs/capacity and five exact lowercase roots",
                       command);
        return;
    }
    if (!zcl_native_zcode_workspace_is_explicit_scratch(workspace)) {
        zep_claim_fail(reply, "UNSAFE_PROPOSE_WORKSPACE",
                       "workspace must explicitly name an isolated tmp, test-tmp, or scratch path",
                       command);
        return;
    }
    input.cutoff_mtp = (int64_t)cutoff_mtp_u64;
    memcpy(input.previous_epoch_root, roots[0], 32);

    struct vcs_zcode_commons_projection *projection =
        vcs_zcode_commons_projection_build(workspace);
    if (!projection ||
        !vcs_zcode_commons_claim_projection_ready(projection) ||
        !vcs_zcode_commons_claim_projection_root(projection,
                                                 projection_root)) {
        vcs_zcode_commons_projection_free(projection);
        zep_claim_fail(reply, "CLAIM_PROJECTION_NOT_READY",
                       "the bounded signed-claim projection is unavailable or contains a recognized corrupt object",
                       command);
        return;
    }
    input.claim_count = vcs_zcode_commons_projection_claim_count(projection);
    struct vcs_zcode_creation_claim_v2 *claims = NULL;
    if (input.claim_count != 0) {
        claims = zcl_calloc(input.claim_count, sizeof(*claims),
                            "ZCODE_claim_epoch_plan_claims");
        if (!claims) {
            vcs_zcode_commons_projection_free(projection);
            zep_claim_fail(reply, "CLAIM_EPOCH_ALLOC",
                           "bounded caller-owned claim buffer allocation failed",
                           command);
            return;
        }
        for (size_t i = 0; i < input.claim_count; i++) {
            const struct vcs_zcode_creation_claim_v2 *claim =
                vcs_zcode_commons_projection_claim_at(projection, i);
            if (!claim) {
                free(claims);
                vcs_zcode_commons_projection_free(projection);
                zep_claim_fail(reply, "CLAIM_PROJECTION_TORN",
                               "the immutable projection refused an indexed claim",
                               command);
                return;
            }
            claims[i] = *claim;
        }
    }
    input.claims = claims;

    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_c23_economics_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_C23_ECONOMICS_SERVICE_ID, &lease);
    if (!service) service = zcode_c23_economics_service_builtin();
    service->policy_init(&policy, roots[1], roots[2], roots[3], roots[4]);
    enum vcs_zcode_commons_error error = service->policy_validate(&policy);
    if (error == VCS_ZCODE_COMMONS_OK)
        error = service->policy_root(&policy, policy_root);
    if (error == VCS_ZCODE_COMMONS_OK)
        error = service->epoch_select(&input, &policy, &result);
    if (error != VCS_ZCODE_COMMONS_OK) {
        zcl_hotswap_service_release(&lease);
        free(claims);
        vcs_zcode_commons_projection_free(projection);
        zep_claim_fail(reply, "CLAIM_EPOCH_SELECTION_REFUSED",
                       vcs_zcode_commons_error_string(error), command);
        return;
    }
    struct vcs_zcode_claim_epoch_proposal_v2 claim_epoch;
    uint8_t claim_epoch_root[32];
    enum vcs_zcode_claim_epoch_error claim_epoch_error =
        vcs_zcode_claim_epoch_from_selection(
            &input, policy_root, projection_root, &result, &claim_epoch);
    if (claim_epoch_error == VCS_ZCODE_CLAIM_EPOCH_OK)
        claim_epoch_error = vcs_zcode_claim_epoch_root(
            &claim_epoch, claim_epoch_root);
    if (claim_epoch_error != VCS_ZCODE_CLAIM_EPOCH_OK) {
        vcs_zcode_claim_epoch_free(&claim_epoch);
        zcl_hotswap_service_release(&lease);
        free(claims);
        vcs_zcode_commons_projection_free(projection);
        zep_claim_fail(reply, "CLAIM_EPOCH_OBJECT_REFUSED",
                       vcs_zcode_claim_epoch_error_string(claim_epoch_error),
                       command);
        return;
    }
    uint8_t *claim_epoch_wire = NULL;
    size_t claim_epoch_wire_len = 0;
    if (persist) {
        claim_epoch_error = vcs_zcode_claim_epoch_encode(
            &claim_epoch, &claim_epoch_wire, &claim_epoch_wire_len);
        if (claim_epoch_error != VCS_ZCODE_CLAIM_EPOCH_OK ||
            !vcs_object_store_init(workspace) ||
            !vcs_object_put_addressed(workspace, claim_epoch_root,
                                      claim_epoch_wire,
                                      claim_epoch_wire_len)) {
            free(claim_epoch_wire);
            vcs_zcode_claim_epoch_free(&claim_epoch);
            zcl_hotswap_service_release(&lease);
            free(claims);
            vcs_zcode_commons_projection_free(projection);
            zep_claim_fail(reply, "CLAIM_EPOCH_STORE_REFUSED",
                           claim_epoch_error == VCS_ZCODE_CLAIM_EPOCH_OK
                               ? "scratch CAS refused the canonical proposal bytes"
                               : vcs_zcode_claim_epoch_error_string(
                                     claim_epoch_error),
                           command);
            return;
        }
    }

    (void)json_push_kv_str(&reply->data, "service_id",
                           ZCODE_C23_ECONOMICS_SERVICE_ID);
    (void)json_push_kv_int(&reply->data, "service_generation",
                           (int64_t)zcl_hotswap_service_generation());
    (void)json_push_kv_bool(&reply->data, "pure_calculation", true);
    (void)json_push_kv_bool(&reply->data, "simulation_only", true);
    (void)json_push_kv_bool(&reply->data, "not_owner_approved", true);
    (void)json_push_kv_bool(&reply->data, "persisted", persist);
    (void)json_push_kv_bool(&reply->data, "issuance_enabled", false);
    (void)json_push_kv_bool(&reply->data, "funds_moved", false);
    (void)json_push_kv_bool(&reply->data, "wallet_used", false);
    zep_hex(&reply->data, "policy_root", policy_root);
    zep_hex(&reply->data, "claim_projection_root", projection_root);
    zep_hex(&reply->data, "previous_epoch_root", input.previous_epoch_root);
    zep_hex(&reply->data, "epoch_selection_root",
            result.epoch_creation_root);
    zep_hex(&reply->data, "claim_epoch_proposal_root", claim_epoch_root);
    (void)json_push_kv_int(
        &reply->data, "claim_epoch_proposal_bytes",
        (int64_t)(VCS_ZCODE_CLAIM_EPOCH_HEADER_BYTES +
                  result.selected_count * 32u));
    (void)json_push_kv_int(&reply->data, "epoch", (int64_t)input.epoch);
    (void)json_push_kv_int(&reply->data, "cutoff_height",
                           (int64_t)input.cutoff_height);
    (void)json_push_kv_int(&reply->data, "cutoff_mtp", input.cutoff_mtp);
    (void)json_push_kv_int(&reply->data, "epoch_capacity_atoms",
                           (int64_t)input.epoch_capacity_atoms);
    (void)json_push_kv_int(&reply->data, "claim_count",
                           (int64_t)input.claim_count);
    (void)json_push_kv_int(&reply->data, "selected_count",
                           (int64_t)result.selected_count);
    (void)json_push_kv_int(&reply->data, "deferred_count",
                           (int64_t)result.deferred_count);
    (void)json_push_kv_int(&reply->data, "invalid_count",
                           (int64_t)result.invalid_count);
    (void)json_push_kv_int(&reply->data, "selected_atoms",
                           (int64_t)result.selected_atoms);
    (void)json_push_kv_int(&reply->data, "expired_capacity_atoms",
                           (int64_t)result.expired_capacity_atoms);
    (void)json_push_kv_int(&reply->data, "recipient_cap_atoms",
                           (int64_t)result.recipient_cap_atoms);
    (void)json_push_kv_int(&reply->data, "lineage_cap_atoms",
                           (int64_t)result.lineage_cap_atoms);
    (void)json_push_kv_int(&reply->data, "first_category",
                           result.first_category);
    /* The result root always binds the complete ordered selected set. Keep
     * the inline review page bounded so a 4096-claim epoch cannot overflow a
     * native result frame, and say when it is not complete. */
    const size_t inline_limit = 16;
    size_t inline_count = result.selected_count < inline_limit
        ? result.selected_count : inline_limit;
    struct json_value selected;
    json_init(&selected); json_set_array(&selected);
    for (size_t i = 0; i < inline_count; i++) {
        const struct vcs_zcode_creation_claim_v2 *claim =
            &claims[result.selected_indices[i]];
        struct json_value row;
        json_init(&row); json_set_object(&row);
        zep_hex(&row, "claim_root", claim->claim_root);
        (void)json_push_kv_int(&row, "category", claim->category);
        (void)json_push_kv_int(&row, "award_atoms",
                               (int64_t)policy.award_atoms[claim->category]);
        (void)json_push_back(&selected, &row);
        json_free(&row);
    }
    (void)json_push_kv(&reply->data, "selected_claims", &selected);
    json_free(&selected);
    (void)json_push_kv_int(&reply->data, "selected_claims_inline_count",
                           (int64_t)inline_count);
    (void)json_push_kv_bool(&reply->data, "selected_claims_complete",
                            inline_count == result.selected_count);
    free(claim_epoch_wire);
    vcs_zcode_claim_epoch_free(&claim_epoch);
    zcl_hotswap_service_release(&lease);
    free(claims);
    vcs_zcode_commons_projection_free(projection);
}

void zcl_native_handle_zcode_commons_schedule_claim_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zep_claim_handle(request, reply, false);
}

void zcl_native_handle_zcode_commons_schedule_claim_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zep_claim_handle(request, reply, true);
}

void zcl_native_handle_zcode_commons_schedule_claim_verify(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    static const char command[] = "zcode.commons.schedule.claim.verify";
    static const char *const keys[] = {
        "workspace", "proposal_root", "network_genesis_root",
        "moderation_policy_root", "qualification_predicates_root",
        "backlog_algorithm_root",
    };
    const char *workspace = request
        ? zep_str(request->input, "workspace") : NULL;
    uint8_t roots[5][32], loaded_root[32], projection_root[32], policy_root[32];
    if (!request || !reply || !workspace ||
        !zep_keys(request->input, keys, sizeof(keys) / sizeof(keys[0])) ||
        !zep_root(request->input, "proposal_root", roots[0]) ||
        !zep_root(request->input, "network_genesis_root", roots[1]) ||
        !zep_root(request->input, "moderation_policy_root", roots[2]) ||
        !zep_root(request->input, "qualification_predicates_root", roots[3]) ||
        !zep_root(request->input, "backlog_algorithm_root", roots[4])) {
        zep_claim_fail(reply, "BAD_CLAIM_EPOCH_VERIFY_INPUT",
                       "closed input requires scratch workspace, proposal_root and four exact policy binding roots",
                       command);
        return;
    }
    if (!zcl_native_zcode_workspace_is_explicit_scratch(workspace)) {
        zep_claim_fail(reply, "UNSAFE_VERIFY_WORKSPACE",
                       "workspace must explicitly name an isolated tmp, test-tmp, or scratch path",
                       command);
        return;
    }

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    int load_error = vcs_object_load_raw_bounded(
        workspace, roots[0], VCS_ZCODE_CLAIM_EPOCH_MAX_WIRE_BYTES,
        &wire, &wire_len);
    if (load_error != 0) {
        zep_claim_fail(
            reply, "CLAIM_EPOCH_LOAD_REFUSED",
            load_error == -2
                ? "proposal exceeds the canonical bounded wire maximum"
                : "proposal is missing, unreadable, or outside the exact scratch CAS",
            command);
        return;
    }

    struct vcs_zcode_claim_epoch_proposal_v2 proposal;
    enum vcs_zcode_claim_epoch_error proposal_error =
        vcs_zcode_claim_epoch_decode(&proposal, wire, wire_len);
    free(wire);
    if (proposal_error != VCS_ZCODE_CLAIM_EPOCH_OK) {
        zep_claim_fail(reply, "CLAIM_EPOCH_DECODE_REFUSED",
                       vcs_zcode_claim_epoch_error_string(proposal_error),
                       command);
        return;
    }
    proposal_error = vcs_zcode_claim_epoch_root(&proposal, loaded_root);
    if (proposal_error != VCS_ZCODE_CLAIM_EPOCH_OK ||
        memcmp(loaded_root, roots[0], 32) != 0) {
        vcs_zcode_claim_epoch_free(&proposal);
        zep_claim_fail(reply, "CLAIM_EPOCH_ADDRESS_MISMATCH",
                       "canonical proposal bytes do not rederive the requested CAS address",
                       command);
        return;
    }

    struct vcs_zcode_commons_projection *projection =
        vcs_zcode_commons_projection_build(workspace);
    if (!projection ||
        !vcs_zcode_commons_claim_projection_ready(projection) ||
        !vcs_zcode_commons_claim_projection_root(projection,
                                                 projection_root) ||
        memcmp(projection_root, proposal.claim_projection_root, 32) != 0) {
        vcs_zcode_commons_projection_free(projection);
        vcs_zcode_claim_epoch_free(&proposal);
        zep_claim_fail(reply, "CLAIM_EPOCH_PROJECTION_STALE",
                       "current signed-claim projection does not exactly match the proposal binding",
                       command);
        return;
    }

    struct vcs_zcode_epoch_selection_v2 selection;
    memset(&selection, 0, sizeof(selection));
    selection.epoch = proposal.epoch;
    selection.cutoff_height = proposal.cutoff_height;
    selection.cutoff_mtp = proposal.cutoff_mtp;
    selection.epoch_capacity_atoms = proposal.epoch_capacity_atoms;
    memcpy(selection.previous_epoch_root, proposal.previous_epoch_root, 32);
    selection.claim_count =
        vcs_zcode_commons_projection_claim_count(projection);
    struct vcs_zcode_creation_claim_v2 *claims = NULL;
    if (selection.claim_count != 0) {
        claims = zcl_calloc(selection.claim_count, sizeof(*claims),
                            "ZCODE_claim_epoch_verify_claims");
        if (!claims) {
            vcs_zcode_commons_projection_free(projection);
            vcs_zcode_claim_epoch_free(&proposal);
            zep_claim_fail(reply, "CLAIM_EPOCH_VERIFY_ALLOC",
                           "bounded caller-owned claim buffer allocation failed",
                           command);
            return;
        }
        for (size_t i = 0; i < selection.claim_count; i++) {
            const struct vcs_zcode_creation_claim_v2 *claim =
                vcs_zcode_commons_projection_claim_at(projection, i);
            if (!claim) {
                free(claims);
                vcs_zcode_commons_projection_free(projection);
                vcs_zcode_claim_epoch_free(&proposal);
                zep_claim_fail(reply, "CLAIM_EPOCH_PROJECTION_TORN",
                               "the immutable projection refused an indexed claim",
                               command);
                return;
            }
            claims[i] = *claim;
        }
    }
    selection.claims = claims;

    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_c23_economics_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_C23_ECONOMICS_SERVICE_ID, &lease);
    if (!service) service = zcode_c23_economics_service_builtin();
    struct vcs_zcode_policy_candidate_v2 policy;
    service->policy_init(&policy, roots[1], roots[2], roots[3], roots[4]);
    enum vcs_zcode_commons_error error = service->policy_validate(&policy);
    if (error == VCS_ZCODE_COMMONS_OK)
        error = service->policy_root(&policy, policy_root);
    if (error != VCS_ZCODE_COMMONS_OK ||
        memcmp(policy_root, proposal.policy_root, 32) != 0) {
        zcl_hotswap_service_release(&lease);
        free(claims);
        vcs_zcode_commons_projection_free(projection);
        vcs_zcode_claim_epoch_free(&proposal);
        zep_claim_fail(reply, "CLAIM_EPOCH_POLICY_MISMATCH",
                       error == VCS_ZCODE_COMMONS_OK
                           ? "supplied policy bindings do not match the proposal"
                           : vcs_zcode_commons_error_string(error),
                       command);
        return;
    }

    struct vcs_zcode_epoch_selection_result_v2 result;
    error = service->epoch_select(&selection, &policy, &result);
    struct vcs_zcode_claim_epoch_proposal_v2 rebuilt;
    vcs_zcode_claim_epoch_init(&rebuilt);
    if (error == VCS_ZCODE_COMMONS_OK)
        proposal_error = vcs_zcode_claim_epoch_from_selection(
            &selection, policy_root, projection_root, &result, &rebuilt);
    else
        proposal_error = VCS_ZCODE_CLAIM_EPOCH_SELECTION;
    if (proposal_error == VCS_ZCODE_CLAIM_EPOCH_OK)
        proposal_error = vcs_zcode_claim_epoch_root(&rebuilt, loaded_root);
    if (proposal_error != VCS_ZCODE_CLAIM_EPOCH_OK ||
        memcmp(loaded_root, roots[0], 32) != 0) {
        vcs_zcode_claim_epoch_free(&rebuilt);
        zcl_hotswap_service_release(&lease);
        free(claims);
        vcs_zcode_commons_projection_free(projection);
        vcs_zcode_claim_epoch_free(&proposal);
        zep_claim_fail(reply, "CLAIM_EPOCH_RECONSTRUCTION_MISMATCH",
                       proposal_error == VCS_ZCODE_CLAIM_EPOCH_OK
                           ? "fresh selection does not reproduce the proposal root"
                           : vcs_zcode_claim_epoch_error_string(proposal_error),
                       command);
        return;
    }

    struct zcode_c23_claim_epoch_view_v1 view;
    if (!service->render_claim_epoch(&rebuilt, true, true, &view)) {
        vcs_zcode_claim_epoch_free(&rebuilt);
        zcl_hotswap_service_release(&lease);
        free(claims);
        vcs_zcode_commons_projection_free(projection);
        vcs_zcode_claim_epoch_free(&proposal);
        zep_claim_fail(reply, "CLAIM_EPOCH_VERIFY_RENDER_REFUSED",
                       "the pure economics service refused the reconstructed proposal view",
                       command);
        return;
    }

    (void)json_push_kv_bool(&reply->data, "verified", true);
    (void)json_push_kv_bool(&reply->data, "restart_reconstructed", true);
    (void)json_push_kv_bool(&reply->data, "bounded_load", true);
    (void)json_push_kv_bool(&reply->data, "pure_calculation", true);
    (void)json_push_kv_bool(&reply->data, "valid", view.valid);
    (void)json_push_kv_bool(&reply->data, "persisted", view.persisted);
    (void)json_push_kv_bool(&reply->data, "canonical_proposal",
                            view.canonical_proposal);
    (void)json_push_kv_bool(&reply->data, "current_selection_verified",
                            view.current_selection_verified);
    (void)json_push_kv_bool(&reply->data, "simulation_only",
                            view.simulation_only);
    (void)json_push_kv_bool(&reply->data, "not_owner_approved", true);
    (void)json_push_kv_bool(&reply->data, "issuance_enabled",
                            view.issuance_enabled);
    (void)json_push_kv_bool(&reply->data, "wallet_used", view.wallet_used);
    (void)json_push_kv_bool(&reply->data, "funds_moved", view.funds_moved);
    (void)json_push_kv_str(&reply->data, "verification_state",
                           view.verification_state);
    (void)json_push_kv_str(&reply->data, "next_command", view.next_command);
    (void)json_push_kv_str(&reply->data, "service_id",
                           ZCODE_C23_ECONOMICS_SERVICE_ID);
    (void)json_push_kv_int(&reply->data, "service_generation",
                           (int64_t)zcl_hotswap_service_generation());
    zep_hex(&reply->data, "claim_epoch_proposal_root", roots[0]);
    zep_hex(&reply->data, "policy_root", policy_root);
    zep_hex(&reply->data, "claim_projection_root", projection_root);
    zep_hex(&reply->data, "epoch_selection_root",
            result.epoch_creation_root);
    (void)json_push_kv_int(&reply->data, "proposal_bytes",
                           (int64_t)wire_len);
    (void)json_push_kv_int(&reply->data, "claim_count",
                           (int64_t)view.claim_count);
    (void)json_push_kv_int(&reply->data, "selected_count",
                           (int64_t)view.selected_count);
    (void)json_push_kv_int(&reply->data, "selected_atoms",
                           (int64_t)view.selected_atoms);
    vcs_zcode_claim_epoch_free(&rebuilt);
    zcl_hotswap_service_release(&lease);
    free(claims);
    vcs_zcode_commons_projection_free(projection);
    vcs_zcode_claim_epoch_free(&proposal);
}

void zcl_native_handle_zcode_commons_schedule_claim_show(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    static const char command[] = "zcode.commons.schedule.claim.show";
    static const char *const keys[] = {"workspace", "root"};
    const char *workspace = request
        ? zep_str(request->input, "workspace") : NULL;
    uint8_t requested_root[32], derived_root[32];
    if (!request || !reply || !workspace ||
        !zep_keys(request->input, keys, sizeof(keys) / sizeof(keys[0])) ||
        !zep_root(request->input, "root", requested_root)) {
        zep_claim_fail(reply, "BAD_CLAIM_EPOCH_SHOW_INPUT",
                       "closed input requires scratch workspace and one exact lowercase root",
                       command);
        return;
    }
    if (!zcl_native_zcode_workspace_is_explicit_scratch(workspace)) {
        zep_claim_fail(reply, "UNSAFE_SHOW_WORKSPACE",
                       "workspace must explicitly name an isolated tmp, test-tmp, or scratch path",
                       command);
        return;
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    int load_error = vcs_object_load_raw_bounded(
        workspace, requested_root, VCS_ZCODE_CLAIM_EPOCH_MAX_WIRE_BYTES,
        &wire, &wire_len);
    if (load_error != 0) {
        zep_claim_fail(
            reply, "CLAIM_EPOCH_SHOW_LOAD_REFUSED",
            load_error == -2
                ? "proposal exceeds the canonical bounded wire maximum"
                : "proposal is missing, unreadable, or outside the exact scratch CAS",
            command);
        return;
    }
    struct vcs_zcode_claim_epoch_proposal_v2 proposal;
    enum vcs_zcode_claim_epoch_error error =
        vcs_zcode_claim_epoch_decode(&proposal, wire, wire_len);
    free(wire);
    if (error == VCS_ZCODE_CLAIM_EPOCH_OK)
        error = vcs_zcode_claim_epoch_root(&proposal, derived_root);
    if (error != VCS_ZCODE_CLAIM_EPOCH_OK ||
        memcmp(derived_root, requested_root, 32) != 0) {
        vcs_zcode_claim_epoch_free(&proposal);
        zep_claim_fail(reply, "CLAIM_EPOCH_SHOW_VERIFY_REFUSED",
                       error == VCS_ZCODE_CLAIM_EPOCH_OK
                           ? "canonical proposal bytes do not rederive the requested CAS address"
                           : vcs_zcode_claim_epoch_error_string(error),
                       command);
        return;
    }
    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_c23_economics_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_C23_ECONOMICS_SERVICE_ID, &lease);
    if (!service) service = zcode_c23_economics_service_builtin();
    struct zcode_c23_claim_epoch_view_v1 view;
    if (!service->render_claim_epoch(
            &proposal, true, false, &view)) {
        zcl_hotswap_service_release(&lease);
        vcs_zcode_claim_epoch_free(&proposal);
        zep_claim_fail(reply, "CLAIM_EPOCH_SHOW_RENDER_REFUSED",
                       "the pure economics service refused the canonical proposal view",
                       command);
        return;
    }
    (void)json_push_kv_str(&reply->data, "service_id",
                           ZCODE_C23_ECONOMICS_SERVICE_ID);
    (void)json_push_kv_int(&reply->data, "service_generation",
                           (int64_t)zcl_hotswap_service_generation());
    (void)json_push_kv_bool(&reply->data, "pure_calculation", true);
    (void)json_push_kv_bool(&reply->data, "valid", view.valid);
    (void)json_push_kv_bool(&reply->data, "persisted", view.persisted);
    (void)json_push_kv_bool(&reply->data, "canonical_proposal",
                            view.canonical_proposal);
    (void)json_push_kv_bool(&reply->data, "current_selection_verified",
                            view.current_selection_verified);
    (void)json_push_kv_bool(&reply->data, "simulation_only",
                            view.simulation_only);
    (void)json_push_kv_bool(&reply->data, "issuance_enabled",
                            view.issuance_enabled);
    (void)json_push_kv_bool(&reply->data, "wallet_used", view.wallet_used);
    (void)json_push_kv_bool(&reply->data, "funds_moved", view.funds_moved);
    (void)json_push_kv_str(&reply->data, "verification_state",
                           view.verification_state);
    (void)json_push_kv_str(&reply->data, "next_command", view.next_command);
    zep_hex(&reply->data, "claim_epoch_proposal_root", requested_root);
    zep_hex(&reply->data, "previous_epoch_root", proposal.previous_epoch_root);
    zep_hex(&reply->data, "policy_root", proposal.policy_root);
    zep_hex(&reply->data, "claim_projection_root",
            proposal.claim_projection_root);
    zep_hex(&reply->data, "epoch_selection_root",
            proposal.epoch_selection_root);
    (void)json_push_kv_int(&reply->data, "proposal_bytes",
                           (int64_t)wire_len);
    (void)json_push_kv_int(&reply->data, "epoch", (int64_t)view.epoch);
    (void)json_push_kv_int(&reply->data, "cutoff_height",
                           (int64_t)view.cutoff_height);
    (void)json_push_kv_int(&reply->data, "cutoff_mtp", view.cutoff_mtp);
    (void)json_push_kv_int(&reply->data, "epoch_capacity_atoms",
                           (int64_t)view.epoch_capacity_atoms);
    (void)json_push_kv_int(&reply->data, "selected_atoms",
                           (int64_t)view.selected_atoms);
    (void)json_push_kv_int(&reply->data, "expired_capacity_atoms",
                           (int64_t)view.expired_capacity_atoms);
    (void)json_push_kv_int(&reply->data, "recipient_cap_atoms",
                           (int64_t)view.recipient_cap_atoms);
    (void)json_push_kv_int(&reply->data, "lineage_cap_atoms",
                           (int64_t)view.lineage_cap_atoms);
    (void)json_push_kv_int(&reply->data, "claim_count",
                           (int64_t)view.claim_count);
    (void)json_push_kv_int(&reply->data, "selected_count",
                           (int64_t)view.selected_count);
    (void)json_push_kv_int(&reply->data, "deferred_count",
                           (int64_t)view.deferred_count);
    (void)json_push_kv_int(&reply->data, "invalid_count",
                           (int64_t)view.invalid_count);
    (void)json_push_kv_int(&reply->data, "first_category",
                           view.first_category);
    const size_t inline_limit = 16;
    size_t inline_count = proposal.selected_count < inline_limit
        ? proposal.selected_count : inline_limit;
    struct json_value selected;
    json_init(&selected); json_set_array(&selected);
    for (size_t i = 0; i < inline_count; i++) {
        struct json_value item;
        char root_hex[65];
        zcl_hex_encode(proposal.selected_claim_roots[i], 32, root_hex);
        json_init(&item); json_set_str(&item, root_hex);
        (void)json_push_back(&selected, &item);
        json_free(&item);
    }
    (void)json_push_kv(&reply->data, "selected_claim_roots", &selected);
    json_free(&selected);
    (void)json_push_kv_bool(&reply->data, "selected_claim_roots_complete",
                            inline_count == proposal.selected_count);
    zcl_hotswap_service_release(&lease);
    vcs_zcode_claim_epoch_free(&proposal);
}
