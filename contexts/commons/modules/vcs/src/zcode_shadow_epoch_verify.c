/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bind public shadow-epoch verification to one policy candidate. */

#include "vcs/zcode_shadow_policy.h"

#include <string.h>

struct shadow_epoch_callbacks {
    const struct vcs_zcode_epoch_creation_validation_context *original;
    const struct vcs_zcode_policy_candidate_v1 *policy;
};

static bool shadow_epoch_anchor(void *opaque, uint64_t height,
                                const uint8_t block_hash[32])
{
    const struct shadow_epoch_callbacks *callbacks = opaque;
    return callbacks->original->anchor_is_active(
        callbacks->original->callback_opaque, height, block_hash);
}

static bool shadow_epoch_duplicate(void *opaque,
                                   const uint8_t candidate_root[32],
                                   const uint8_t attribution_root[32])
{
    const struct shadow_epoch_callbacks *callbacks = opaque;
    return callbacks->original->contribution_is_duplicate(
        callbacks->original->callback_opaque, candidate_root,
        attribution_root);
}

static bool shadow_epoch_binding(void *opaque,
                                 const uint8_t binding_root[32])
{
    const struct shadow_epoch_callbacks *callbacks = opaque;
    return callbacks->original->binding_is_current &&
        callbacks->original->binding_is_current(
            callbacks->original->callback_opaque, binding_root);
}

static bool shadow_epoch_continuity_duplicate(
    void *opaque, const uint8_t event_key[32],
    const uint8_t attribution_root[32])
{
    const struct shadow_epoch_callbacks *callbacks = opaque;
    return callbacks->original->continuity_is_duplicate(
        callbacks->original->callback_opaque, event_key, attribution_root);
}

static bool shadow_epoch_award(
    void *opaque,
    const struct vcs_zcode_creation_attribution_v1 *attribution,
    uint64_t *expected_atoms)
{
    const struct shadow_epoch_callbacks *callbacks = opaque;
    return attribution &&
        vcs_zcode_policy_candidate_award_atoms(
            callbacks->policy, attribution->category, expected_atoms) ==
            VCS_ZCODE_SHADOW_OK;
}

enum vcs_zcode_epoch_creation_error vcs_zcode_shadow_epoch_verify_cas(
    const struct vcs_zcode_epoch_creation_set_v1 *set,
    const struct vcs_zcode_epoch_creation_validation_context *context,
    const struct vcs_zcode_policy_candidate_v1 *policy)
{
    if (!set || !context || !policy ||
        !context->expected_zc23_policy_root ||
        !context->anchor_is_active || !context->contribution_is_duplicate ||
        !context->continuity_is_duplicate)
        return VCS_ZCODE_EPOCH_CREATION_CONTEXT;
    if (vcs_zcode_policy_candidate_validate(policy) != VCS_ZCODE_SHADOW_OK)
        return VCS_ZCODE_EPOCH_CREATION_CONTEXT;
    uint8_t policy_root[32];
    if (vcs_zcode_policy_candidate_root(policy, policy_root) !=
            VCS_ZCODE_SHADOW_OK ||
        memcmp(policy_root, context->expected_zc23_policy_root, 32) != 0)
        return VCS_ZCODE_EPOCH_CREATION_CONTEXT;

    struct shadow_epoch_callbacks callbacks = {
        .original = context,
        .policy = policy,
    };
    struct vcs_zcode_epoch_creation_validation_context bound = *context;
    bound.anchor_is_active = shadow_epoch_anchor;
    bound.contribution_is_duplicate = shadow_epoch_duplicate;
    bound.binding_is_current = shadow_epoch_binding;
    bound.continuity_is_duplicate = shadow_epoch_continuity_duplicate;
    bound.award_atoms_for_creation = shadow_epoch_award;
    bound.callback_opaque = &callbacks;
    return vcs_zcode_epoch_creation_verify_cas(set, &bound);
}
