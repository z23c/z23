/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: non-creating native views of Commons policy authorities. */

#include "command/native_command.h"

#include "base/hex.h"
#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "services/zcode_c23_economics_service.h"
#include "services/zcode_moderation_view_service.h"
#include "vcs/zcode_commons_projection.h"
#include "vcs/zcode_commons.h"

#include <stdio.h>
#include <string.h>

static void moderation_fail(struct zcl_command_reply *reply,
                            const char *code, const char *detail)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "validate", false,
                           false, detail, "zcode.moderation");
}

static bool moderation_no_keys(const struct json_value *input)
{
    return input && input->type == JSON_OBJ && input->num_children == 0;
}

static bool moderation_backlog_input(
    const struct json_value *input, const char **workspace,
    uint64_t *cutoff_height, int64_t *cutoff_mtp)
{
    if (!input || input->type != JSON_OBJ || input->num_children != 3 ||
        !workspace || !cutoff_height || !cutoff_mtp)
        return false;
    static const char *const allowed[] = {
        "workspace", "cutoff_height", "cutoff_mtp",
    };
    for (size_t i = 0; i < input->num_children; i++) {
        bool known = false;
        for (size_t j = 0; j < sizeof(allowed) / sizeof(allowed[0]); j++)
            known = known || strcmp(input->keys[i], allowed[j]) == 0;
        if (!known) return false;
    }
    const struct json_value *workspace_value = json_get(input, "workspace");
    const struct json_value *height_value = json_get(input, "cutoff_height");
    const struct json_value *mtp_value = json_get(input, "cutoff_mtp");
    if (!workspace_value || workspace_value->type != JSON_STR ||
        !height_value || height_value->type != JSON_INT ||
        !mtp_value || mtp_value->type != JSON_INT ||
        json_get_int(height_value) <= 0 || json_get_int(mtp_value) <= 0)
        return false;
    *workspace = json_get_str(workspace_value);
    *cutoff_height = (uint64_t)json_get_int(height_value);
    *cutoff_mtp = json_get_int(mtp_value);
    return zcl_native_zcode_workspace_is_explicit_scratch(*workspace);
}

static bool render_family_policy_with_service(
    struct zcl_command_reply *reply, bool include_current_activation_status,
    const struct zcode_moderation_view_service_v1 *service)
{
    struct vcs_zcode_family_policy_v1 policy;
    uint8_t root[32];
    char root_hex[65];
    vcs_zcode_family_policy_v1_default(&policy);
    if (vcs_zcode_family_policy_v1_root(&policy, root) !=
            VCS_ZCODE_COMMONS_OK) {
        moderation_fail(reply, "MODERATION_POLICY_ROOT",
                        "the immutable Family policy root could not be derived");
        return false;
    }
    zcl_hex_encode(root, sizeof(root), root_hex);
    struct zcode_moderation_policy_view_v1 view;
    if (!service->render_policy(&policy, root_hex, &view) || !view.valid) {
        moderation_fail(reply, "MODERATION_VIEW_FAILED",
                        "the pure moderation view refused the Family policy");
        return false;
    }
    struct json_value *data = &reply->data;
    (void)json_push_kv_str(data, "profile", "family-c23.v1");
    (void)json_push_kv_str(data, "policy_root", view.policy_root);
    (void)json_push_kv_str(data, "view_service_id",
                           ZCODE_MODERATION_VIEW_SERVICE_ID);
    (void)json_push_kv_int(data, "view_service_generation",
                           zcl_hotswap_service_generation());
    (void)json_push_kv_bool(data, "immutable", true);
    if (include_current_activation_status) {
        (void)json_push_kv_bool(data, "policy_selected_as_default", true);
        (void)json_push_kv_bool(data, "enforcement_complete", false);
        (void)json_push_kv_bool(data, "effective_default", false);
        (void)json_push_kv_bool(data, "default_public_view", false);
    }
    (void)json_push_kv_bool(data, "simulation_only", true);
    (void)json_push_kv_bool(data, "owner_can_rewrite", false);
    (void)json_push_kv_int(data, "excluded_reason_mask",
                           view.excluded_reason_mask);
    (void)json_push_kv_int(data, "max_dependency_objects",
                           view.max_dependency_objects);
    (void)json_push_kv_int(data, "max_extracted_bytes",
                           (int64_t)view.max_extracted_bytes);
    (void)json_push_kv_str(data, "pass_audiences",
                           view.pass_audiences);
    (void)json_push_kv_str(data, "pass_behaviors", view.pass_behaviors);
    (void)json_push_kv_str(data, "incomplete_result",
                           view.incomplete_result);
    (void)json_push_kv_str(data, "new_content_state",
                           view.new_content_state);
    (void)json_push_kv_str(data, "contextual_eligibility",
                           view.contextual_eligibility);
    (void)json_push_kv_bool(data,
                            "separate_from_accuracy_quality_security",
                            view.separate_from_accuracy_quality_security);
    (void)json_push_kv_str(data, "policy_summary", view.policy_summary);
    return true;
}

static bool render_family_policy(struct zcl_command_reply *reply,
                                 bool include_current_activation_status)
{
    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_moderation_view_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_MODERATION_VIEW_SERVICE_ID, &lease);
    if (!service)
        service = zcode_moderation_view_service_builtin();
    bool rendered = render_family_policy_with_service(
        reply, include_current_activation_status, service);
    zcl_hotswap_service_release(&lease);
    return rendered;
}

void zcl_native_handle_zcode_moderation_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply || !moderation_no_keys(request->input)) {
        if (reply) moderation_fail(reply, "BAD_MODERATION_STATUS_INPUT",
            "zcode moderation status accepts no input keys");
        return;
    }
    const struct zcode_moderation_admission_status_input_v1 input = {
        .policy_selected_as_default = true,
        .admission_projection_ready = false,
        .dependency_closure_complete = false,
        .cross_surface_gate_passed = false,
    };
    struct zcode_moderation_admission_status_result_v1 view;
    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_moderation_view_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_MODERATION_VIEW_SERVICE_ID, &lease);
    if (!service)
        service = zcode_moderation_view_service_builtin();
    bool policy_rendered =
        render_family_policy_with_service(reply, false, service);
    bool rendered = policy_rendered &&
        service->render_admission_status(&input, &view) && view.valid;
    zcl_hotswap_service_release(&lease);
    if (!policy_rendered)
        return;
    if (!rendered) {
        moderation_fail(reply, "MODERATION_ADMISSION_VIEW_FAILED",
                        "the pure moderation view refused admission facts");
        return;
    }
    (void)json_push_kv_bool(&reply->data, "policy_selected_as_default",
                            input.policy_selected_as_default);
    (void)json_push_kv_bool(&reply->data, "admission_projection_ready",
                            input.admission_projection_ready);
    (void)json_push_kv_bool(&reply->data, "dependency_closure_complete",
                            input.dependency_closure_complete);
    (void)json_push_kv_bool(&reply->data, "cross_surface_gate_passed",
                            input.cross_surface_gate_passed);
    (void)json_push_kv_bool(&reply->data, "enforcement_complete",
                            view.enforcement_complete);
    (void)json_push_kv_bool(&reply->data, "effective_default",
                            view.effective_default);
    (void)json_push_kv_bool(&reply->data, "default_public_view",
                            view.default_public_view);
    (void)json_push_kv_str(&reply->data, "phase", view.phase);
    (void)json_push_kv_str(&reply->data, "admission_readiness",
                           view.admission_readiness);
    (void)json_push_kv_str(&reply->data, "official_surface_policy",
                           view.official_surface_policy);
    (void)json_push_kv_str(&reply->data, "activation_blocker",
                           view.activation_blocker);
    (void)json_push_kv_str(&reply->data, "next_command", view.next_command);
}

void zcl_native_handle_zcode_moderation_service_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply || !moderation_no_keys(request->input)) {
        if (reply) moderation_fail(reply, "BAD_MODERATION_SERVICE_INPUT",
            "zcode moderation service status accepts no input keys");
        return;
    }
    const struct zcode_moderation_service_status_input_v1 input = {0};
    struct zcode_moderation_service_status_result_v1 view;
    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_moderation_view_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_MODERATION_VIEW_SERVICE_ID, &lease);
    if (!service)
        service = zcode_moderation_view_service_builtin();
    bool policy_rendered =
        render_family_policy_with_service(reply, true, service);
    bool rendered = policy_rendered &&
        service->render_service_status(&input, &view) && view.valid;
    zcl_hotswap_service_release(&lease);
    if (!policy_rendered)
        return;
    if (!rendered) {
        moderation_fail(reply, "MODERATION_SERVICE_VIEW_FAILED",
                        "the pure moderation view refused service readiness facts");
        return;
    }
    (void)json_push_kv_bool(&reply->data, "projection_ready",
                            input.projection_ready);
    (void)json_push_kv_int(&reply->data, "registered_service_count",
                           input.registered_service_count);
    (void)json_push_kv_int(&reply->data, "eligible_service_count",
                           input.eligible_service_count);
    (void)json_push_kv_bool(&reply->data, "roster_finalized",
                            input.roster_finalized);
    (void)json_push_kv_bool(&reply->data, "classification_enabled",
                            input.classification_enabled);
    (void)json_push_kv_bool(&reply->data, "advertisement_enabled",
                            input.advertisement_enabled);
    (void)json_push_kv_bool(&reply->data, "chain_selection_enabled",
                            input.chain_selection_enabled);
    (void)json_push_kv_bool(&reply->data,
                            "operator_group_diversity_declared",
                            input.operator_group_diversity_declared);
    (void)json_push_kv_bool(&reply->data, "service_ready", view.ready);
    (void)json_push_kv_str(&reply->data, "bootstrap_label",
                           view.bootstrap_label);
    (void)json_push_kv_str(&reply->data, "blocker", view.blocker);
    (void)json_push_kv_str(&reply->data, "next_command", view.next_command);
}

void zcl_native_handle_zcode_moderation_policy_list(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply || !moderation_no_keys(request->input)) {
        if (reply) moderation_fail(reply, "BAD_MODERATION_POLICY_LIST_INPUT",
            "zcode moderation policy list accepts no input keys");
        return;
    }
    (void)json_push_kv_int(&reply->data, "count", 1);
    if (!render_family_policy(reply, true))
        return;
    (void)json_push_kv_str(&reply->data, "future_policy_rule",
                           "a new profile and root; never rewrite v1");
}

void zcl_native_handle_zcode_moderation_policy_show(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *profile_value = request && request->input
        ? json_get(request->input, "profile") : NULL;
    const char *profile = profile_value ? json_get_str(profile_value) : NULL;
    if (!request || !reply || !request->input ||
        request->input->type != JSON_OBJ ||
        request->input->num_children != 1 || !profile ||
        strcmp(profile, "family-c23.v1") != 0) {
        if (reply) moderation_fail(reply, "UNKNOWN_MODERATION_POLICY",
            "profile must be exactly family-c23.v1");
        return;
    }
    if (!render_family_policy(reply, true))
        return;
}

static bool moderation_view_frozen_kat(const void *opaque, char *why,
                                       size_t why_sz)
{
    const struct zcode_moderation_view_service_v1 *service = opaque;
    struct vcs_zcode_family_policy_v1 policy;
    struct zcode_moderation_policy_view_v1 view;
    uint8_t root[32];
    char root_hex[65];
    vcs_zcode_family_policy_v1_default(&policy);
    if (!service || !service->render_policy ||
        !service->render_service_status ||
        !service->render_admission_status ||
        vcs_zcode_family_policy_v1_root(&policy, root) !=
            VCS_ZCODE_COMMONS_OK) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen moderation service shape/root vector failed");
        return false;
    }
    zcl_hex_encode(root, sizeof(root), root_hex);
    if (!service->render_policy(&policy, root_hex, &view) || !view.valid ||
        strcmp(view.policy_root, root_hex) != 0 ||
        view.excluded_reason_mask != policy.excluded_reason_mask ||
        view.max_dependency_objects != policy.max_dependency_objects ||
        view.max_extracted_bytes != policy.max_extracted_bytes ||
        strcmp(view.pass_audiences, "GENERAL|CONTEXTUAL_SCIENCE") != 0 ||
        strcmp(view.pass_behaviors, "BENIGN|DUAL_USE") != 0 ||
        strcmp(view.incomplete_result, "UNKNOWN") != 0 ||
        strcmp(view.new_content_state, "PENDING") != 0 ||
        !view.separate_from_accuracy_quality_security) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen Family policy presentation vector failed");
        return false;
    }
    struct zcode_moderation_service_status_input_v1 status_input = {0};
    struct zcode_moderation_service_status_result_v1 status_view;
    if (!service->render_service_status(&status_input, &status_view) ||
        !status_view.valid || status_view.ready ||
        strcmp(status_view.bootstrap_label,
               "unavailable:no_signed_service_roster") != 0) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen moderation service-readiness vector failed");
        return false;
    }
    status_input.projection_ready = true;
    status_input.registered_service_count = 3;
    status_input.eligible_service_count = 3;
    status_input.roster_finalized = true;
    status_input.classification_enabled = true;
    status_input.advertisement_enabled = true;
    status_input.chain_selection_enabled = true;
    status_input.operator_group_diversity_declared = true;
    if (!service->render_service_status(&status_input, &status_view) ||
        !status_view.ready ||
        strcmp(status_view.next_command,
               "zcode moderation classify plan") != 0) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen moderation ready-roster vector failed");
        return false;
    }
    struct zcode_moderation_admission_status_input_v1 admission_input = {0};
    struct zcode_moderation_admission_status_result_v1 admission_view;
    if (!service->render_admission_status(&admission_input, &admission_view) ||
        !admission_view.valid || admission_view.enforcement_complete ||
        admission_view.effective_default ||
        strcmp(admission_view.admission_readiness,
               "blocked:policy_not_selected") != 0 ||
        strcmp(admission_view.next_command,
               "zcode moderation policy list") != 0) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen unselected-policy admission vector failed");
        return false;
    }
    admission_input.policy_selected_as_default = true;
    if (!service->render_admission_status(&admission_input, &admission_view) ||
        strcmp(admission_view.admission_readiness,
               "blocked:projection_missing") != 0 ||
        strcmp(admission_view.next_command,
               "zcode moderation service status") != 0) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen missing-projection admission vector failed");
        return false;
    }
    admission_input.admission_projection_ready = true;
    if (!service->render_admission_status(&admission_input, &admission_view) ||
        strcmp(admission_view.admission_readiness,
               "blocked:closure_incomplete") != 0) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen incomplete-closure admission vector failed");
        return false;
    }
    admission_input.dependency_closure_complete = true;
    if (!service->render_admission_status(&admission_input, &admission_view) ||
        strcmp(admission_view.admission_readiness,
               "blocked:cross_surface_gate") != 0) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen cross-surface admission vector failed");
        return false;
    }
    admission_input.cross_surface_gate_passed = true;
    if (!service->render_admission_status(&admission_input, &admission_view) ||
        !admission_view.enforcement_complete ||
        !admission_view.effective_default ||
        !admission_view.default_public_view ||
        strcmp(admission_view.admission_readiness,
               "ready:family_default") != 0 ||
        strcmp(admission_view.official_surface_policy,
               "family-c23.v1") != 0 ||
        admission_view.activation_blocker[0] != '\0') {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen effective-Family admission vector failed");
        return false;
    }
    return true;
}

static const struct zcl_hotswap_service_contract k_moderation_view_contract = {
    .service_id = ZCODE_MODERATION_VIEW_SERVICE_ID,
    .source_tu = "contexts/commons/services/src/zcode_moderation_view_service.c",
    .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
    .vtable_size = sizeof(struct zcode_moderation_view_service_v1),
    .abi_fingerprint = ZCODE_MODERATION_VIEW_ABI_FINGERPRINT,
    .schema_fingerprint = ZCODE_MODERATION_VIEW_SCHEMA_FINGERPRINT,
    .wire_fingerprint = ZCODE_MODERATION_VIEW_WIRE_FINGERPRINT,
    .kat_fingerprint = ZCODE_MODERATION_VIEW_KAT_FINGERPRINT,
    .frozen_kat = moderation_view_frozen_kat,
};

const struct zcl_hotswap_service_contract *
zcl_native_zcode_moderation_view_service_contract(void)
{
    return &k_moderation_view_contract;
}

static bool economics_service_frozen_kat(const void *opaque, char *why,
                                         size_t why_sz)
{
    const struct zcode_c23_economics_service_v1 *service = opaque;
    struct vcs_zcode_family_policy_v1 family;
    uint8_t family_root[32], network[32], qualification[32], backlog[32];
    struct vcs_zcode_policy_candidate_v2 policy;
    struct zcode_c23_economics_status_result_v1 status;
    memset(network, 0x21, sizeof(network));
    memset(qualification, 0x22, sizeof(qualification));
    memset(backlog, 0x23, sizeof(backlog));
    vcs_zcode_family_policy_v1_default(&family);
    if (!service || !service->award_atoms || !service->policy_init ||
        !service->policy_validate || !service->policy_root ||
        !service->epoch_select || !service->render_status ||
        !service->render_schedule_proposal ||
        !service->render_backlog_status || !service->render_claim_epoch ||
        !service->schedule_class_name ||
        vcs_zcode_family_policy_v1_root(&family, family_root) !=
            VCS_ZCODE_COMMONS_OK) {
        if (why && why_sz) (void)snprintf(why, why_sz,
            "frozen economics service shape/family-root vector failed");
        return false;
    }
    service->policy_init(&policy, network, family_root, qualification, backlog);
    uint8_t root[32], expected[32];
    if (service->policy_validate(&policy) != VCS_ZCODE_COMMONS_OK ||
        service->policy_root(&policy, root) != VCS_ZCODE_COMMONS_OK ||
        !zcl_hex_decode(ZCODE_C23_ECONOMICS_POLICY_KAT_ROOT, expected, 32) ||
        memcmp(root, expected, 32) != 0 || !service->render_status(&status) ||
        status.award_atoms[VCS_ZCODE_CREATION_V2_MODULE_PUBLICATION] !=
            UINT64_C(100000000) ||
        status.award_atoms[VCS_ZCODE_CREATION_V2_PRESERVATION] !=
            UINT64_C(12500000) || status.partial_claim_issuance ||
        status.unused_capacity_carries) {
        if (why && why_sz) (void)snprintf(why, why_sz,
            "frozen policy-root/award/status vector failed");
        return false;
    }
    struct vcs_zcode_epoch_selection_v2 input = {
        .epoch = 7, .cutoff_height = 2000, .cutoff_mtp = 4000,
        .epoch_capacity_atoms = UINT64_C(300000000),
    };
    struct vcs_zcode_epoch_selection_result_v2 selected;
    if (service->epoch_select(&input, &policy, &selected) !=
            VCS_ZCODE_COMMONS_OK || selected.selected_count != 0 ||
        selected.expired_capacity_atoms != UINT64_C(300000000) ||
        selected.recipient_cap_atoms != UINT64_C(100000000)) {
        if (why && why_sz) (void)snprintf(why, why_sz,
            "frozen empty-epoch selection vector failed");
        return false;
    }
    uint8_t projection_root[32];
    memset(projection_root, 0x24, sizeof(projection_root));
    struct vcs_zcode_claim_epoch_proposal_v2 claim_epoch;
    struct zcode_c23_claim_epoch_view_v1 claim_epoch_view;
    if (vcs_zcode_claim_epoch_from_selection(
            &input, root, projection_root, &selected, &claim_epoch) !=
            VCS_ZCODE_CLAIM_EPOCH_OK ||
        !service->render_claim_epoch(&claim_epoch, true, false,
                                     &claim_epoch_view) ||
        !claim_epoch_view.valid || !claim_epoch_view.persisted ||
        !claim_epoch_view.canonical_proposal ||
        claim_epoch_view.current_selection_verified ||
        !claim_epoch_view.simulation_only ||
        claim_epoch_view.issuance_enabled || claim_epoch_view.wallet_used ||
        claim_epoch_view.funds_moved || claim_epoch_view.epoch != 7 ||
        claim_epoch_view.expired_capacity_atoms != UINT64_C(300000000) ||
        strcmp(claim_epoch_view.verification_state,
               "canonical:selection_not_reconstructed") != 0 ||
        strcmp(claim_epoch_view.next_command,
               "zcode commons schedule claim verify") != 0) {
        vcs_zcode_claim_epoch_free(&claim_epoch);
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen claim-epoch view vector failed");
        return false;
    }
    vcs_zcode_claim_epoch_free(&claim_epoch);
    struct vcs_zcode_epoch_schedule_proposal_v1 proposal;
    vcs_zcode_epoch_schedule_proposal_init(&proposal);
    proposal.schema_version = VCS_ZCODE_EPOCH_SCHEDULE_VERSION;
    proposal.epoch = 1;
    proposal.budget_atoms =
        VCS_ZC23_SCHEDULE_CAP_ATOMS / VCS_ZC23_SCHEDULE_TOTAL_EPOCHS;
    proposal.unissued_atoms = proposal.budget_atoms;
    struct zcode_c23_schedule_proposal_view_v1 proposal_view;
    char class_name[16];
    if (!service->render_schedule_proposal(&proposal, false, &proposal_view) ||
        proposal_view.epoch != 1 ||
        proposal_view.budget_atoms != UINT64_C(2019230769230) ||
        proposal_view.class_weights[0] != 100 ||
        proposal_view.class_weights[1] != 40 ||
        proposal_view.class_weights[2] != 20 ||
        proposal_view.class_weights[3] != 5 || !proposal_view.simulated ||
        proposal_view.persisted || proposal_view.mint ||
        strcmp(proposal_view.mint_authority,
               "simulation_only;no_issuance_authority") != 0 ||
        !service->schedule_class_name(
            VCS_ZCODE_EPOCH_SCHEDULE_CLASS_REPRODUCTION, class_name,
            sizeof(class_name)) || strcmp(class_name, "reproduction") != 0) {
        if (why && why_sz) (void)snprintf(why, why_sz,
            "frozen schedule-proposal view vector failed");
        return false;
    }
    struct zcode_c23_backlog_status_input_v1 backlog_input = {0};
    struct zcode_c23_backlog_status_result_v1 backlog_view;
    if (!service->render_backlog_status(&backlog_input, &backlog_view) ||
        !backlog_view.valid || backlog_view.backlog_ready ||
        backlog_view.issuance_enabled ||
        !backlog_view.unused_capacity_expires ||
        strcmp(backlog_view.readiness,
               "blocked:claim_projection_missing") != 0 ||
        strcmp(backlog_view.next_command,
               "zcode commons claim plan") != 0) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen missing-backlog projection vector failed");
        return false;
    }
    backlog_input.projection_ready = true;
    if (!service->render_backlog_status(&backlog_input, &backlog_view) ||
        !backlog_view.backlog_ready ||
        strcmp(backlog_view.readiness, "ready:empty_projection") != 0) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen empty-backlog projection vector failed");
        return false;
    }
    backlog_input.claim_count = 3;
    if (!service->render_backlog_status(&backlog_input, &backlog_view) ||
        strcmp(backlog_view.readiness, "waiting:claims_ineligible") != 0) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen ineligible-backlog vector failed");
        return false;
    }
    backlog_input.eligible_claim_count = 2;
    if (!service->render_backlog_status(&backlog_input, &backlog_view) ||
        strcmp(backlog_view.readiness, "ready:epoch_plan") != 0 ||
        strcmp(backlog_view.next_command,
               "zcode commons schedule claim plan") != 0) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen eligible-backlog vector failed");
        return false;
    }
    backlog_input.eligible_claim_count = 4;
    if (service->render_backlog_status(&backlog_input, &backlog_view)) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen invalid-backlog subset rejection failed");
        return false;
    }
    return true;
}

static const struct zcl_hotswap_service_contract k_economics_contract = {
    .service_id = ZCODE_C23_ECONOMICS_SERVICE_ID,
    .source_tu = "contexts/commons/services/src/zcode_c23_economics_service.c",
    .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
    .vtable_size = sizeof(struct zcode_c23_economics_service_v1),
    .abi_fingerprint = ZCODE_C23_ECONOMICS_ABI_FINGERPRINT,
    .schema_fingerprint = ZCODE_C23_ECONOMICS_SCHEMA_FINGERPRINT,
    .wire_fingerprint = ZCODE_C23_ECONOMICS_WIRE_FINGERPRINT,
    .kat_fingerprint = ZCODE_C23_ECONOMICS_KAT_FINGERPRINT,
    .frozen_kat = economics_service_frozen_kat,
};

const struct zcl_hotswap_service_contract *
zcl_native_zcode_economics_service_contract(void)
{
    return &k_economics_contract;
}

void zcl_native_handle_zcode_commons_economics_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply || !moderation_no_keys(request->input)) {
        if (reply) moderation_fail(reply, "BAD_COMMONS_ECONOMICS_INPUT",
            "zcode commons economics status accepts no input keys");
        return;
    }
    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_c23_economics_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_C23_ECONOMICS_SERVICE_ID, &lease);
    if (!service) service = zcode_c23_economics_service_builtin();
    struct zcode_c23_economics_status_result_v1 status;
    if (!service->render_status(&status)) {
        zcl_hotswap_service_release(&lease);
        moderation_fail(reply, "ECONOMICS_SERVICE_FAILED",
                        "the pure economics service refused status rendering");
        return;
    }
    (void)json_push_kv_str(&reply->data, "policy_object",
                           "zc23_policy_candidate.v2");
    (void)json_push_kv_str(&reply->data, "service_id",
                           ZCODE_C23_ECONOMICS_SERVICE_ID);
    (void)json_push_kv_int(&reply->data, "service_generation",
                           zcl_hotswap_service_generation());
    (void)json_push_kv_bool(&reply->data, "simulation_only", true);
    (void)json_push_kv_bool(&reply->data, "not_owner_approved", true);
    (void)json_push_kv_bool(&reply->data, "token_exists", false);
    (void)json_push_kv_bool(&reply->data, "funds_moved", false);
    (void)json_push_kv_bool(&reply->data, "ordinary_activity_mints", false);
    (void)json_push_kv_int(&reply->data, "challenge_blocks",
                           (int64_t)status.challenge_blocks);
    (void)json_push_kv_int(&reply->data, "challenge_seconds",
                           status.challenge_seconds);
    (void)json_push_kv_int(&reply->data, "module_publication_atoms",
        (int64_t)status.award_atoms[VCS_ZCODE_CREATION_V2_MODULE_PUBLICATION]);
    (void)json_push_kv_int(&reply->data, "defect_repair_atoms",
        (int64_t)status.award_atoms[VCS_ZCODE_CREATION_V2_DEFECT_REPAIR]);
    (void)json_push_kv_int(&reply->data, "security_finding_atoms",
        (int64_t)status.award_atoms[VCS_ZCODE_CREATION_V2_SECURITY_FINDING]);
    (void)json_push_kv_int(&reply->data, "independent_test_atoms",
        (int64_t)status.award_atoms[VCS_ZCODE_CREATION_V2_INDEPENDENT_TEST]);
    (void)json_push_kv_int(&reply->data, "reproduction_atoms",
        (int64_t)status.award_atoms[VCS_ZCODE_CREATION_V2_REPRODUCTION]);
    (void)json_push_kv_int(&reply->data, "performance_frontier_atoms",
        (int64_t)status.award_atoms[VCS_ZCODE_CREATION_V2_PERFORMANCE_FRONTIER]);
    (void)json_push_kv_int(&reply->data, "compatibility_proof_atoms",
        (int64_t)status.award_atoms[VCS_ZCODE_CREATION_V2_COMPATIBILITY_PROOF]);
    (void)json_push_kv_int(&reply->data, "preservation_atoms",
        (int64_t)status.award_atoms[VCS_ZCODE_CREATION_V2_PRESERVATION]);
    (void)json_push_kv_str(&reply->data, "queue_order",
                           status.queue_order);
    (void)json_push_kv_str(&reply->data, "category_order",
                           status.category_order);
    (void)json_push_kv_str(&reply->data, "concentration_cap",
        status.concentration_cap);
    (void)json_push_kv_bool(&reply->data, "partial_claim_issuance",
                            status.partial_claim_issuance);
    (void)json_push_kv_bool(&reply->data, "unused_capacity_carries",
                            status.unused_capacity_carries);
    zcl_hotswap_service_release(&lease);
}

void zcl_native_handle_zcode_commons_backlog(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *workspace = NULL;
    uint64_t cutoff_height = 0;
    int64_t cutoff_mtp = 0;
    if (!request || !reply || !moderation_backlog_input(
            request->input, &workspace, &cutoff_height, &cutoff_mtp)) {
        if (reply) moderation_fail(reply, "BAD_COMMONS_BACKLOG_INPUT",
            "zcode commons backlog requires an explicit scratch workspace and positive cutoff_height/cutoff_mtp integers");
        return;
    }
    struct vcs_zcode_commons_projection *projection =
        vcs_zcode_commons_projection_build(workspace);
    if (!projection) {
        moderation_fail(reply, "COMMONS_BACKLOG_REBUILD_FAILED",
                        "bounded read-only claim projection rebuild failed");
        return;
    }
    size_t claim_count =
        vcs_zcode_commons_projection_claim_count(projection);
    size_t eligible_claim_count =
        vcs_zcode_commons_projection_eligible_claim_count(
            projection, cutoff_height, cutoff_mtp);
    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_c23_economics_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_C23_ECONOMICS_SERVICE_ID, &lease);
    if (!service) service = zcode_c23_economics_service_builtin();
    struct zcode_c23_economics_status_result_v1 status;
    const struct zcode_c23_backlog_status_input_v1 input = {
        .projection_ready =
            vcs_zcode_commons_claim_projection_ready(projection),
        .claim_count = (uint32_t)claim_count,
        .eligible_claim_count = (uint32_t)eligible_claim_count,
    };
    struct zcode_c23_backlog_status_result_v1 view;
    if (!service->render_status(&status) ||
        !service->render_backlog_status(&input, &view) || !view.valid) {
        zcl_hotswap_service_release(&lease);
        vcs_zcode_commons_projection_free(projection);
        moderation_fail(reply, "BACKLOG_SERVICE_FAILED",
                        "the pure economics service refused backlog rendering");
        return;
    }
    (void)json_push_kv_str(&reply->data, "service_id",
                           ZCODE_C23_ECONOMICS_SERVICE_ID);
    (void)json_push_kv_int(&reply->data, "service_generation",
                           zcl_hotswap_service_generation());
    (void)json_push_kv_bool(&reply->data, "simulation_only", true);
    (void)json_push_kv_bool(&reply->data, "not_owner_approved", true);
    (void)json_push_kv_str(&reply->data, "projection_authority",
                           "canonical_workspace_cas");
    uint8_t projection_root[32]; char projection_hex[65];
    if (vcs_zcode_commons_claim_projection_root(
            projection, projection_root)) {
        zcl_hex_encode(projection_root, sizeof(projection_root),
                       projection_hex);
        (void)json_push_kv_str(&reply->data, "claim_projection_root",
                               projection_hex);
    }
    (void)json_push_kv_int(&reply->data, "cutoff_height",
                           (int64_t)cutoff_height);
    (void)json_push_kv_int(&reply->data, "cutoff_mtp", cutoff_mtp);
    (void)json_push_kv_bool(&reply->data, "projection_ready",
                            input.projection_ready);
    (void)json_push_kv_int(&reply->data, "claim_count", input.claim_count);
    (void)json_push_kv_int(&reply->data, "eligible_claim_count",
                           input.eligible_claim_count);
    (void)json_push_kv_bool(&reply->data, "issuance_enabled",
                            view.issuance_enabled);
    (void)json_push_kv_bool(&reply->data, "funds_moved", false);
    (void)json_push_kv_str(&reply->data, "queue_order",
                           status.queue_order);
    (void)json_push_kv_str(&reply->data, "category_rotation",
                           status.category_order);
    (void)json_push_kv_bool(&reply->data, "partial_claim_issuance",
                            status.partial_claim_issuance);
    (void)json_push_kv_bool(&reply->data, "unused_capacity_carries",
                            status.unused_capacity_carries);
    (void)json_push_kv_bool(&reply->data, "unused_capacity_expires",
                            view.unused_capacity_expires);
    (void)json_push_kv_str(&reply->data, "backlog_readiness",
                           view.readiness);
    (void)json_push_kv_str(&reply->data, "blocker", view.reason);
    (void)json_push_kv_str(&reply->data, "next_command", view.next_command);
    zcl_hotswap_service_release(&lease);
    vcs_zcode_commons_projection_free(projection);
}
