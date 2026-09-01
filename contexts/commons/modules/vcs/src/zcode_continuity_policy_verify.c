/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: independently rederive continuity policy authority from CAS. */
#include "vcs/zcode_continuity_policy.h"

#include "vcs/package_manifest.h"
#include "vcs/package_release.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_contributor_binding.h"
#include "vcs/zcode_dev.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static bool continuity_equal(const uint8_t left[32],
                             const uint8_t right[32])
{
    return memcmp(left, right, 32) == 0;
}

static bool continuity_load(const char *workspace, const uint8_t root[32],
                            size_t maximum, uint8_t **wire,
                            size_t *wire_len)
{
    *wire = NULL;
    *wire_len = 0;
    return vcs_object_load_raw_bounded(workspace, root, maximum,
                                       wire, wire_len) == 0;
}

static enum vcs_zcode_continuity_error continuity_binding_v1(
    const uint8_t *wire, size_t wire_len, const uint8_t root[32],
    const struct vcs_zcode_continuity_policy_v1 *policy,
    const struct vcs_zcode_patronage_validation_context *context)
{
    struct vcs_zcode_contributor_binding_v1 binding;
    uint8_t derived[32];
    enum vcs_zcode_binding_error error =
        vcs_zcode_contributor_binding_parse(wire, wire_len, &binding);
    if (error == VCS_ZCODE_BINDING_OK)
        error = vcs_zcode_contributor_binding_root(&binding, derived);
    if (error == VCS_ZCODE_BINDING_OK)
        error = vcs_zcode_contributor_binding_verify(
            &binding, context->expected_network_genesis_root,
            policy->patron_zid_pubkey, context->now_unix);
    if (error != VCS_ZCODE_BINDING_OK ||
        !continuity_equal(derived, root) ||
        binding.operation == VCS_ZCODE_BINDING_REVOKE)
        return VCS_ZCODE_CONTINUITY_CONTRIBUTOR;
    if (binding.operation != VCS_ZCODE_BINDING_ACTIVE &&
        (!context->binding_is_current ||
         !context->binding_is_current(context->callback_opaque, root)))
        return VCS_ZCODE_CONTINUITY_CONTRIBUTOR;
    return VCS_ZCODE_CONTINUITY_OK;
}

static enum vcs_zcode_continuity_error continuity_binding_v2(
    const uint8_t *wire, size_t wire_len, const uint8_t root[32],
    const struct vcs_zcode_continuity_policy_v1 *policy,
    const struct vcs_zcode_patronage_validation_context *context)
{
    struct vcs_zcode_contributor_binding_v2 binding;
    uint8_t derived[32];
    enum vcs_zcode_binding_error error =
        vcs_zcode_contributor_binding_parse_v2(wire, wire_len, &binding);
    if (error == VCS_ZCODE_BINDING_OK)
        error = vcs_zcode_contributor_binding_root_v2(&binding, derived);
    if (error == VCS_ZCODE_BINDING_OK)
        error = vcs_zcode_contributor_binding_verify_v2(
            &binding, context->expected_network_genesis_root,
            policy->patron_zid_pubkey, context->now_unix);
    if (error != VCS_ZCODE_BINDING_OK ||
        !continuity_equal(derived, root) ||
        binding.operation == VCS_ZCODE_BINDING_REVOKE)
        return VCS_ZCODE_CONTINUITY_CONTRIBUTOR;
    if (binding.operation != VCS_ZCODE_BINDING_ACTIVE &&
        (!context->binding_is_current ||
         !context->binding_is_current(context->callback_opaque, root)))
        return VCS_ZCODE_CONTINUITY_CONTRIBUTOR;
    return VCS_ZCODE_CONTINUITY_OK;
}

static enum vcs_zcode_continuity_error continuity_binding(
    const struct vcs_zcode_continuity_policy_v1 *policy,
    const struct vcs_zcode_patronage_validation_context *context)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (!continuity_load(context->workspace,
            policy->patron_contributor_binding_root,
            VCS_ZCODE_CONTRIBUTOR_BINDING_V2_WIRE_BYTES,
            &wire, &wire_len))
        return VCS_ZCODE_CONTINUITY_CONTRIBUTOR;
    enum vcs_zcode_continuity_error error =
        wire_len == VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES
            ? continuity_binding_v1(
                wire, wire_len, policy->patron_contributor_binding_root,
                policy, context)
            : wire_len == VCS_ZCODE_CONTRIBUTOR_BINDING_V2_WIRE_BYTES
                ? continuity_binding_v2(
                    wire, wire_len,
                    policy->patron_contributor_binding_root,
                    policy, context)
                : VCS_ZCODE_CONTINUITY_CONTRIBUTOR;
    free(wire);
    return error;
}

static enum vcs_zcode_continuity_error continuity_package(
    const struct vcs_zcode_continuity_policy_v1 *policy,
    const struct vcs_zcode_patronage_validation_context *context)
{
    uint8_t *wire = NULL, derived[32];
    size_t wire_len = 0;
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    bool ok = continuity_load(context->workspace, policy->package_root,
            VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES, &wire, &wire_len) &&
        vcs_package_manifest_parse(wire, wire_len, &manifest) &&
        vcs_package_manifest_root(&manifest, derived) &&
        continuity_equal(derived, policy->package_root);
    free(wire);
    vcs_package_manifest_free(&manifest);
    return ok ? VCS_ZCODE_CONTINUITY_OK : VCS_ZCODE_CONTINUITY_PACKAGE;
}

static enum vcs_zcode_continuity_error continuity_release(
    const struct vcs_zcode_continuity_policy_v1 *policy,
    const struct vcs_zcode_patronage_validation_context *context)
{
    uint8_t *wire = NULL, derived[32];
    size_t wire_len = 0;
    struct vcs_package_release release;
    bool ok = continuity_load(context->workspace,
            policy->current_release_root,
            VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES, &wire, &wire_len) &&
        vcs_package_release_parse(wire, wire_len, &release) ==
            VCS_PACKAGE_RELEASE_OK &&
        vcs_package_release_verify(&release) == VCS_PACKAGE_RELEASE_OK &&
        vcs_package_release_id(&release, derived) ==
            VCS_PACKAGE_RELEASE_OK &&
        continuity_equal(derived, policy->current_release_root) &&
        continuity_equal(release.package_root, policy->package_root) &&
        strcmp(release.chain_id, "zclassic-main") == 0;
    free(wire);
    return ok ? VCS_ZCODE_CONTINUITY_OK : VCS_ZCODE_CONTINUITY_RELEASE;
}

static enum vcs_zcode_continuity_error continuity_proof_policy(
    const struct vcs_zcode_continuity_policy_v1 *policy,
    const struct vcs_zcode_patronage_validation_context *context)
{
    uint8_t *wire = NULL, derived[32];
    size_t wire_len = 0;
    struct vcs_zcode_proof_policy_v1 proof_policy;
    bool ok = continuity_load(context->workspace,
            policy->proof_policy_root, VCS_ZCODE_PROOF_POLICY_WIRE_BYTES,
            &wire, &wire_len) &&
        vcs_zcode_proof_policy_parse(wire, wire_len, &proof_policy) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_proof_policy_root(&proof_policy, derived) ==
            VCS_ZCODE_DEV_OK &&
        continuity_equal(derived, policy->proof_policy_root);
    free(wire);
    return ok ? VCS_ZCODE_CONTINUITY_OK
              : VCS_ZCODE_CONTINUITY_PROOF_POLICY;
}

enum vcs_zcode_continuity_error vcs_zcode_continuity_policy_verify_cas(
    const struct vcs_zcode_continuity_policy_v1 *policy,
    const struct vcs_zcode_patronage_validation_context *context)
{
    enum vcs_zcode_continuity_error error =
        vcs_zcode_continuity_policy_verify(
            policy, context ? context->now_unix : 0);
    if (error != VCS_ZCODE_CONTINUITY_OK) return error;
    if (!context || !context->workspace ||
        !context->expected_network_genesis_root || context->now_unix <= 0)
        return VCS_ZCODE_CONTINUITY_CONTEXT;
    if (!continuity_equal(policy->network_genesis_root,
                          context->expected_network_genesis_root))
        return VCS_ZCODE_CONTINUITY_NETWORK;
    error = continuity_binding(policy, context);
    if (error != VCS_ZCODE_CONTINUITY_OK) return error;
    error = continuity_package(policy, context);
    if (error != VCS_ZCODE_CONTINUITY_OK) return error;
    error = continuity_release(policy, context);
    if (error != VCS_ZCODE_CONTINUITY_OK) return error;
    return continuity_proof_policy(policy, context);
}
