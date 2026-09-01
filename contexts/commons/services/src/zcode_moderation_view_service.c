/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure Family-policy presentation over caller-owned input and output. */
// one-result-type-ok:pure-vtable-uses-bounded-caller-owned-output-only

#include "services/zcode_moderation_view_service.h"

#include "hotswap/hotswap_service.h"

#include <stdio.h>
#include <string.h>

static bool render_policy(const struct vcs_zcode_family_policy_v1 *policy,
                          const char *policy_root_hex,
                          struct zcode_moderation_policy_view_v1 *out)
{
    if (!policy || !policy_root_hex || !out)
        return false;
    memset(out, 0, sizeof(*out));
    (void)snprintf(out->policy_root, sizeof(out->policy_root), "%s",
                   policy_root_hex);
    out->excluded_reason_mask = policy->excluded_reason_mask;
    out->max_dependency_objects = policy->max_dependency_objects;
    out->max_extracted_bytes = policy->max_extracted_bytes;
    (void)snprintf(out->pass_audiences, sizeof(out->pass_audiences), "%s",
                   "GENERAL|CONTEXTUAL_SCIENCE");
    (void)snprintf(out->pass_behaviors, sizeof(out->pass_behaviors), "%s",
                   "BENIGN|DUAL_USE");
    (void)snprintf(out->incomplete_result, sizeof(out->incomplete_result),
                   "%s", "UNKNOWN");
    (void)snprintf(out->new_content_state, sizeof(out->new_content_state),
                   "%s", "PENDING");
    (void)snprintf(out->contextual_eligibility,
                   sizeof(out->contextual_eligibility), "%s",
                   "neutral scientific, medical, historical, cybersecurity and dual-use education");
    out->separate_from_accuracy_quality_security = true;
    (void)snprintf(out->policy_summary, sizeof(out->policy_summary), "%s",
                   "immutable Family policy and service-roster presentation; enforcement remains resident and incomplete");
    out->valid = strlen(out->policy_root) == 64 &&
                 out->max_dependency_objects > 0 &&
                 out->max_extracted_bytes > 0;
    return true;
}

static bool render_service_status(
    const struct zcode_moderation_service_status_input_v1 *input,
    struct zcode_moderation_service_status_result_v1 *out)
{
    if (!input || !out ||
        input->eligible_service_count > input->registered_service_count)
        return false;
    memset(out, 0, sizeof(*out));
    out->valid = true;
    out->ready = input->projection_ready &&
        input->registered_service_count > 0 &&
        input->eligible_service_count > 0 && input->roster_finalized &&
        input->classification_enabled && input->advertisement_enabled &&
        input->chain_selection_enabled &&
        input->operator_group_diversity_declared;
    if (out->ready) {
        (void)snprintf(out->bootstrap_label, sizeof(out->bootstrap_label),
                       "%s", "ready:signed_service_roster");
        (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
                       "zcode moderation classify plan");
    } else if (input->registered_service_count == 0) {
        (void)snprintf(out->bootstrap_label, sizeof(out->bootstrap_label),
                       "%s", "unavailable:no_signed_service_roster");
        (void)snprintf(out->blocker, sizeof(out->blocker), "%s",
                       "signed service registration and finalized roster projection are not implemented");
        (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
                       "zcode moderation status");
    } else {
        (void)snprintf(out->bootstrap_label, sizeof(out->bootstrap_label),
                       "%s", "bootstrap:roster_incomplete");
        (void)snprintf(out->blocker, sizeof(out->blocker), "%s",
                       "the signed roster exists but projection, eligibility, diversity, or service activation is incomplete");
        (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
                       "zcode moderation service status");
    }
    return true;
}

static bool render_admission_status(
    const struct zcode_moderation_admission_status_input_v1 *input,
    struct zcode_moderation_admission_status_result_v1 *out)
{
    if (!input || !out)
        return false;
    memset(out, 0, sizeof(*out));
    out->valid = true;
    out->enforcement_complete = input->admission_projection_ready &&
        input->dependency_closure_complete &&
        input->cross_surface_gate_passed;
    out->effective_default = input->policy_selected_as_default &&
        out->enforcement_complete;
    out->default_public_view = out->effective_default;
    (void)snprintf(out->official_surface_policy,
                   sizeof(out->official_surface_policy), "%s",
                   out->effective_default ? "family-c23.v1" :
                                            "legacy_v1_unchanged");
    if (!input->policy_selected_as_default) {
        (void)snprintf(out->phase, sizeof(out->phase), "%s",
                       "policy_unselected");
        (void)snprintf(out->admission_readiness,
                       sizeof(out->admission_readiness), "%s",
                       "blocked:policy_not_selected");
        (void)snprintf(out->activation_blocker,
                       sizeof(out->activation_blocker), "%s",
                       "no immutable Family policy is selected as the default");
        (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
                       "zcode moderation policy list");
    } else if (!input->admission_projection_ready) {
        (void)snprintf(out->phase, sizeof(out->phase), "%s",
                       "protocol_foundation");
        (void)snprintf(out->admission_readiness,
                       sizeof(out->admission_readiness), "%s",
                       "blocked:projection_missing");
        (void)snprintf(out->activation_blocker,
                       sizeof(out->activation_blocker), "%s",
                       "family admission projection is incomplete");
        (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
                       "zcode moderation service status");
    } else if (!input->dependency_closure_complete) {
        (void)snprintf(out->phase, sizeof(out->phase), "%s",
                       "projection_incomplete");
        (void)snprintf(out->admission_readiness,
                       sizeof(out->admission_readiness), "%s",
                       "blocked:closure_incomplete");
        (void)snprintf(out->activation_blocker,
                       sizeof(out->activation_blocker), "%s",
                       "Family admission lacks a complete dependency closure");
        (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
                       "zcode moderation service status");
    } else if (!input->cross_surface_gate_passed) {
        (void)snprintf(out->phase, sizeof(out->phase), "%s",
                       "enforcement_incomplete");
        (void)snprintf(out->admission_readiness,
                       sizeof(out->admission_readiness), "%s",
                       "blocked:cross_surface_gate");
        (void)snprintf(out->activation_blocker,
                       sizeof(out->activation_blocker), "%s",
                       "cross-surface Family enforcement matrix has not passed");
        (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
                       "zcode moderation status");
    } else {
        (void)snprintf(out->phase, sizeof(out->phase), "%s", "effective");
        (void)snprintf(out->admission_readiness,
                       sizeof(out->admission_readiness), "%s",
                       "ready:family_default");
        (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
                       "zcode package search");
    }
    return true;
}

static const struct zcode_moderation_view_service_v1 k_builtin = {
    .render_policy = render_policy,
    .render_service_status = render_service_status,
    .render_admission_status = render_admission_status,
};

ZCL_HOTSWAP_SERVICE_EXPORT(
    ZCODE_MODERATION_VIEW_SERVICE_ID, k_builtin,
    ZCODE_MODERATION_VIEW_ABI_FINGERPRINT,
    ZCODE_MODERATION_VIEW_SCHEMA_FINGERPRINT,
    ZCODE_MODERATION_VIEW_WIRE_FINGERPRINT,
    ZCODE_MODERATION_VIEW_KAT_FINGERPRINT)

const struct zcode_moderation_view_service_v1 *
zcode_moderation_view_service_builtin(void)
{
    return &k_builtin;
}
