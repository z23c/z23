/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: independently rederive patronage intent authority from CAS. */
#include "vcs/zcode_patronage.h"

#include "vcs/package_manifest.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_contributor_binding.h"
#include "vcs/zcode_creation_attribution.h"
#include "vcs/zcode_dev.h"

#include <stdlib.h>
#include <string.h>

static bool patronage_equal(const uint8_t left[32], const uint8_t right[32])
{
    return memcmp(left, right, 32) == 0;
}

static bool patronage_load(const char *workspace, const uint8_t root[32],
                           size_t maximum, uint8_t **wire, size_t *wire_len)
{
    *wire = NULL;
    *wire_len = 0;
    return vcs_object_load_raw_bounded(workspace, root, maximum,
                                       wire, wire_len) == 0;
}

static enum vcs_zcode_patronage_error patronage_binding(
    const uint8_t root[32], const uint8_t expected_pubkey[32],
    const struct vcs_zcode_patronage_validation_context *context)
{
    uint8_t *wire = NULL, derived[32] = {0}, pubkey[32] = {0};
    uint8_t operation = 0;
    size_t wire_len = 0;
    if (!patronage_load(context->workspace, root,
                        VCS_ZCODE_CONTRIBUTOR_BINDING_V2_WIRE_BYTES,
                        &wire, &wire_len))
        return VCS_ZCODE_PATRONAGE_CONTRIBUTOR;
    enum vcs_zcode_binding_error error = VCS_ZCODE_BINDING_ERR_VERSION;
    if (wire_len == VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES) {
        struct vcs_zcode_contributor_binding_v1 binding;
        error = vcs_zcode_contributor_binding_parse(wire, wire_len, &binding);
        if (error == VCS_ZCODE_BINDING_OK)
            error = vcs_zcode_contributor_binding_root(&binding, derived);
        if (error == VCS_ZCODE_BINDING_OK)
            error = vcs_zcode_contributor_binding_verify(
                &binding, context->expected_network_genesis_root,
                binding.zid_pubkey, context->now_unix);
        memcpy(pubkey, binding.zid_pubkey, 32);
        operation = binding.operation;
    } else if (wire_len == VCS_ZCODE_CONTRIBUTOR_BINDING_V2_WIRE_BYTES) {
        struct vcs_zcode_contributor_binding_v2 binding;
        error = vcs_zcode_contributor_binding_parse_v2(
            wire, wire_len, &binding);
        if (error == VCS_ZCODE_BINDING_OK)
            error = vcs_zcode_contributor_binding_root_v2(&binding, derived);
        if (error == VCS_ZCODE_BINDING_OK)
            error = vcs_zcode_contributor_binding_verify_v2(
                &binding, context->expected_network_genesis_root,
                binding.zid_pubkey, context->now_unix);
        memcpy(pubkey, binding.zid_pubkey, 32);
        operation = binding.operation;
    }
    free(wire);
    if (error != VCS_ZCODE_BINDING_OK || !patronage_equal(root, derived) ||
        operation == VCS_ZCODE_BINDING_REVOKE ||
        (expected_pubkey && !patronage_equal(pubkey, expected_pubkey)))
        return VCS_ZCODE_PATRONAGE_CONTRIBUTOR;
    if (operation != VCS_ZCODE_BINDING_ACTIVE &&
        (!context->binding_is_current ||
         !context->binding_is_current(context->callback_opaque, root)))
        return VCS_ZCODE_PATRONAGE_CONTRIBUTOR;
    return VCS_ZCODE_PATRONAGE_OK;
}

static enum vcs_zcode_patronage_error patronage_policy(
    const struct vcs_zcode_patronage_intent_v1 *intent,
    struct vcs_zcode_proof_policy_v1 *policy,
    const struct vcs_zcode_patronage_validation_context *context)
{
    uint8_t *wire = NULL, derived[32]; size_t wire_len = 0;
    if (!patronage_load(context->workspace, intent->proof_policy_root,
                        VCS_ZCODE_PROOF_POLICY_WIRE_BYTES,
                        &wire, &wire_len) ||
        vcs_zcode_proof_policy_parse(wire, wire_len, policy) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_proof_policy_root(policy, derived) != VCS_ZCODE_DEV_OK ||
        !patronage_equal(derived, intent->proof_policy_root)) {
        free(wire);
        return VCS_ZCODE_PATRONAGE_POLICY;
    }
    free(wire);
    return VCS_ZCODE_PATRONAGE_OK;
}

static enum vcs_zcode_patronage_error patronage_task(
    const struct vcs_zcode_patronage_intent_v1 *intent,
    const struct vcs_zcode_patronage_validation_context *context)
{
    uint8_t *wire = NULL, derived[32]; size_t wire_len = 0;
    struct vcs_zcode_task_v1 task;
    if (!patronage_load(context->workspace, intent->task_root,
                        VCS_ZCODE_TASK_WIRE_BYTES, &wire, &wire_len) ||
        vcs_zcode_task_parse(wire, wire_len, &task) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_task_root(&task, derived) != VCS_ZCODE_DEV_OK ||
        !patronage_equal(derived, intent->task_root) ||
        !patronage_equal(task.proof_policy_root,
                         intent->proof_policy_root) ||
        vcs_zcode_task_validate_at(&task, intent->created_unix) !=
            VCS_ZCODE_DEV_OK) {
        free(wire);
        return VCS_ZCODE_PATRONAGE_TASK;
    }
    free(wire);
    struct vcs_zcode_proof_policy_v1 policy;
    return patronage_policy(intent, &policy, context);
}

static enum vcs_zcode_patronage_error patronage_package_target(
    const struct vcs_zcode_patronage_intent_v1 *intent,
    const struct vcs_zcode_patronage_validation_context *context)
{
    uint8_t *wire = NULL, derived[32]; size_t wire_len = 0;
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    bool ok = patronage_load(context->workspace, intent->target_root,
            VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES, &wire, &wire_len) &&
        vcs_package_manifest_parse(wire, wire_len, &manifest) &&
        vcs_package_manifest_root(&manifest, derived) &&
        patronage_equal(derived, intent->target_root);
    free(wire); vcs_package_manifest_free(&manifest);
    return ok ? VCS_ZCODE_PATRONAGE_OK : VCS_ZCODE_PATRONAGE_TARGET;
}

static enum vcs_zcode_patronage_error patronage_target(
    const struct vcs_zcode_patronage_intent_v1 *intent,
    const struct vcs_zcode_patronage_validation_context *context)
{
    if (intent->target_kind == VCS_ZCODE_PATRONAGE_TARGET_PACKAGE)
        return patronage_package_target(intent, context);
    if (intent->target_kind == VCS_ZCODE_PATRONAGE_TARGET_CONTRIBUTOR)
        return patronage_binding(intent->target_root, NULL, context);
    if (intent->target_kind == VCS_ZCODE_PATRONAGE_TARGET_CREATION) {
        uint8_t *wire = NULL, derived[32]; size_t wire_len = 0;
        struct vcs_zcode_creation_attribution_v1 creation;
        bool ok = patronage_load(context->workspace, intent->target_root,
                VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES,
                &wire, &wire_len) &&
            vcs_zcode_creation_attribution_parse(wire, wire_len, &creation) ==
                VCS_ZCODE_CREATION_OK &&
            vcs_zcode_creation_attribution_root(&creation, derived) ==
                VCS_ZCODE_CREATION_OK &&
            patronage_equal(derived, intent->target_root);
        free(wire);
        return ok ? VCS_ZCODE_PATRONAGE_OK : VCS_ZCODE_PATRONAGE_TARGET;
    }
    return VCS_ZCODE_PATRONAGE_TARGET;
}

enum vcs_zcode_patronage_error vcs_zcode_patronage_intent_verify_cas(
    const struct vcs_zcode_patronage_intent_v1 *intent,
    const struct vcs_zcode_patronage_validation_context *context)
{
    enum vcs_zcode_patronage_error error =
        vcs_zcode_patronage_intent_verify(
            intent, context ? context->now_unix : 0);
    if (error != VCS_ZCODE_PATRONAGE_OK) return error;
    if (!context || !context->workspace ||
        !context->expected_network_genesis_root || context->now_unix <= 0)
        return VCS_ZCODE_PATRONAGE_CONTEXT;
    if (!patronage_equal(intent->network_genesis_root,
                         context->expected_network_genesis_root))
        return VCS_ZCODE_PATRONAGE_NETWORK;
    error = patronage_binding(intent->patron_contributor_binding_root,
                              intent->patron_zid_pubkey, context);
    if (error != VCS_ZCODE_PATRONAGE_OK) return error;
    error = patronage_binding(intent->intended_recipient_binding_root,
                              NULL, context);
    if (error != VCS_ZCODE_PATRONAGE_OK) return error;
    if (intent->mode == VCS_ZCODE_PATRONAGE_EXACT_TASK_COMMISSION)
        return patronage_task(intent, context);
    if (intent->mode == VCS_ZCODE_PATRONAGE_PACKAGE_CONTINUITY) {
        error = patronage_package_target(intent, context);
        if (error != VCS_ZCODE_PATRONAGE_OK) return error;
        struct vcs_zcode_proof_policy_v1 policy;
        return patronage_policy(intent, &policy, context);
    }
    return patronage_target(intent, context);
}
