/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure presentation projection for the immutable Family moderation policy. */
// blocker-ok:pure_admission_status_presentation
/* This island renders caller-owned admission facts; it cannot raise or own a
 * runtime blocker. The static command caller publishes the bounded explanation. */

#ifndef ZCL_SERVICES_ZCODE_MODERATION_VIEW_SERVICE_H
#define ZCL_SERVICES_ZCODE_MODERATION_VIEW_SERVICE_H

#include "vcs/zcode_commons.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCODE_MODERATION_VIEW_SERVICE_ID "zcode.moderation.view.v1"
#define ZCODE_MODERATION_VIEW_ABI_FINGERPRINT \
    "zcode.moderation.view.abi.v2:admission-status"
#define ZCODE_MODERATION_VIEW_SCHEMA_FINGERPRINT \
    "zcl.zcode_moderation_status.v1:admission-readiness+service-status.v1+policy-list.v1+policy-show.v1"
#define ZCODE_MODERATION_VIEW_WIRE_FINGERPRINT \
    "family-policy+service-readiness+admission-readiness-caller-owned-view.v2"
#define ZCODE_MODERATION_VIEW_KAT_FINGERPRINT \
    "09fa2911b1af51e7b919ee61d09819f5bdc810f5b4f7d0a22573c5353f8ca3b5"

struct zcode_moderation_policy_view_v1 {
    bool valid;
    char policy_root[65];
    uint32_t excluded_reason_mask;
    uint32_t max_dependency_objects;
    uint64_t max_extracted_bytes;
    char pass_audiences[48];
    char pass_behaviors[32];
    char incomplete_result[16];
    char new_content_state[16];
    char contextual_eligibility[160];
    bool separate_from_accuracy_quality_security;
    char policy_summary[160];
};

struct zcode_moderation_service_status_input_v1 {
    bool projection_ready;
    uint32_t registered_service_count;
    uint32_t eligible_service_count;
    bool roster_finalized;
    bool classification_enabled;
    bool advertisement_enabled;
    bool chain_selection_enabled;
    bool operator_group_diversity_declared;
};

struct zcode_moderation_service_status_result_v1 {
    bool valid;
    bool ready;
    char bootstrap_label[64];
    char blocker[192];
    char next_command[64];
};

struct zcode_moderation_admission_status_input_v1 {
    bool policy_selected_as_default;
    bool admission_projection_ready;
    bool dependency_closure_complete;
    bool cross_surface_gate_passed;
};

struct zcode_moderation_admission_status_result_v1 {
    bool valid;
    bool enforcement_complete;
    bool effective_default;
    bool default_public_view;
    char phase[48];
    char admission_readiness[64];
    char official_surface_policy[32];
    char activation_blocker[192];
    char next_command[64];
};

struct zcode_moderation_view_service_v1 {
    bool (*render_policy)(const struct vcs_zcode_family_policy_v1 *policy,
                          const char *policy_root_hex,
                          struct zcode_moderation_policy_view_v1 *out);
    bool (*render_service_status)(
        const struct zcode_moderation_service_status_input_v1 *input,
        struct zcode_moderation_service_status_result_v1 *out);
    bool (*render_admission_status)(
        const struct zcode_moderation_admission_status_input_v1 *input,
        struct zcode_moderation_admission_status_result_v1 *out);
};

const struct zcode_moderation_view_service_v1 *
zcode_moderation_view_service_builtin(void);

struct zcl_hotswap_service_contract;
const struct zcl_hotswap_service_contract *
zcl_native_zcode_moderation_view_service_contract(void);

#endif /* ZCL_SERVICES_ZCODE_MODERATION_VIEW_SERVICE_H */
