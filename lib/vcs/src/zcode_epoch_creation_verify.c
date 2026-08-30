/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rederive complete epoch issuance attribution from canonical CAS. */
#include "vcs/zcode_epoch_creation.h"

#include "base/bytes.h"
#include "base/checked.h"
#include "base/safe_alloc.h"
#include "vcs/vcs_object.h"

#include <stdlib.h>
#include <string.h>

static bool epoch_verify_equal(const uint8_t a[32], const uint8_t b[32])
{
    return memcmp(a, b, 32) == 0;
}

static enum vcs_zcode_epoch_creation_error epoch_verify_context(
    const struct vcs_zcode_epoch_creation_set_v1 *set,
    const struct vcs_zcode_epoch_creation_validation_context *context)
{
    if (!context || !context->workspace ||
        !context->expected_network_genesis_root ||
        !context->expected_zc23_policy_root ||
        !context->expected_previous_epoch_creation_root ||
        !context->anchor_is_active ||
        !context->contribution_is_duplicate ||
        !context->award_atoms_for_creation || context->now_unix <= 0)
        return VCS_ZCODE_EPOCH_CREATION_CONTEXT;
    if (!epoch_verify_equal(set->network_genesis_root,
                            context->expected_network_genesis_root) ||
        !epoch_verify_equal(set->zc23_policy_root,
                            context->expected_zc23_policy_root) ||
        !epoch_verify_equal(set->previous_epoch_creation_root,
                            context->expected_previous_epoch_creation_root))
        return VCS_ZCODE_EPOCH_CREATION_PREDECESSOR;
    if (set->epoch == 0 &&
        !zcl_bytes_all_zero(context->expected_previous_epoch_creation_root, 32))
        return VCS_ZCODE_EPOCH_CREATION_PREDECESSOR;
    if (set->actual_mint_atoms != context->observed_actual_mint_atoms)
        return VCS_ZCODE_EPOCH_CREATION_MINT;
    if (context->active_height < set->maturity_height ||
        context->active_mtp < set->maturity_mtp)
        return VCS_ZCODE_EPOCH_CREATION_IMMATURE;
    if (!context->anchor_is_active(context->callback_opaque,
                                   set->opening_height, set->opening_hash) ||
        !context->anchor_is_active(context->callback_opaque,
                                   set->maturity_height, set->maturity_hash))
        return VCS_ZCODE_EPOCH_CREATION_REORG;
    return VCS_ZCODE_EPOCH_CREATION_OK;
}

enum vcs_zcode_epoch_creation_error vcs_zcode_epoch_creation_verify_cas(
    const struct vcs_zcode_epoch_creation_set_v1 *set,
    const struct vcs_zcode_epoch_creation_validation_context *context)
{
    enum vcs_zcode_epoch_creation_error error =
        vcs_zcode_epoch_creation_validate(set);
    if (error != VCS_ZCODE_EPOCH_CREATION_OK)
        return error;
    error = epoch_verify_context(set, context);
    if (error != VCS_ZCODE_EPOCH_CREATION_OK)
        return error;

    uint64_t sum = 0;
    uint8_t (*seen_candidates)[32] = NULL;
    if (set->attribution_count != 0) {
        seen_candidates = zcl_calloc(
            set->attribution_count, 32u, "zcode_epoch_seen_candidates");
        if (!seen_candidates)
            return VCS_ZCODE_EPOCH_CREATION_ALLOC;
    }
    for (size_t i = 0; i < set->attribution_count; i++) {
        uint8_t *wire = NULL; size_t wire_len = 0;
        if (vcs_object_load_raw_bounded(
                context->workspace, set->attribution_roots[i],
                VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES,
                &wire, &wire_len) != 0) {
            free(seen_candidates);
            return VCS_ZCODE_EPOCH_CREATION_CAS;
        }
        struct vcs_zcode_creation_attribution_v1 attribution;
        uint8_t root[32];
        enum vcs_zcode_creation_error creation_error =
            vcs_zcode_creation_attribution_parse(wire, wire_len,
                                                  &attribution);
        free(wire);
        if (creation_error != VCS_ZCODE_CREATION_OK ||
            vcs_zcode_creation_attribution_root(&attribution, root) !=
                VCS_ZCODE_CREATION_OK ||
            !epoch_verify_equal(root, set->attribution_roots[i]) ||
            attribution.epoch != set->epoch ||
            !epoch_verify_equal(attribution.network_genesis_root,
                                set->network_genesis_root) ||
            !epoch_verify_equal(attribution.zc23_policy_root,
                                set->zc23_policy_root)) {
            free(seen_candidates);
            return VCS_ZCODE_EPOCH_CREATION_ATTRIBUTION;
        }
        for (size_t j = 0; j < i; j++) {
            if (epoch_verify_equal(seen_candidates[j],
                                   attribution.candidate_root)) {
                free(seen_candidates);
                return VCS_ZCODE_EPOCH_CREATION_DUPLICATE;
            }
        }
        memcpy(seen_candidates[i], attribution.candidate_root, 32);

        uint64_t expected_award = 0;
        struct vcs_zcode_creation_attribution_v1 policy_attribution =
            attribution;
        /* v1 has no security-specific structured finding root.  A caller
         * may display SECURITY_FIX, but issuance must evaluate it as the
         * ordinary born-red class so the label can never increase award. */
        if (policy_attribution.category == VCS_ZCODE_CREATION_SECURITY_FIX)
            policy_attribution.category = VCS_ZCODE_CREATION_BORN_RED_FIX;
        if (!context->award_atoms_for_creation(
                context->callback_opaque, &policy_attribution,
                &expected_award) ||
            expected_award == 0 || expected_award != attribution.award_atoms) {
            free(seen_candidates);
            return VCS_ZCODE_EPOCH_CREATION_ATTRIBUTION;
        }
        struct vcs_zcode_creation_validation_context creation_context = {
            .workspace = context->workspace,
            .expected_network_genesis_root =
                context->expected_network_genesis_root,
            .expected_zc23_policy_root = context->expected_zc23_policy_root,
            .expected_epoch = set->epoch,
            .expected_award_atoms = expected_award,
            .active_height = context->active_height,
            .active_mtp = context->active_mtp,
            .now_unix = context->now_unix,
            .anchor_is_active = context->anchor_is_active,
            .contribution_is_duplicate =
                context->contribution_is_duplicate,
            .binding_is_current = context->binding_is_current,
            .continuity_is_duplicate = context->continuity_is_duplicate,
            .callback_opaque = context->callback_opaque,
        };
        creation_error = vcs_zcode_creation_attribution_verify_cas(
            &attribution, &creation_context);
        if (creation_error != VCS_ZCODE_CREATION_OK) {
            free(seen_candidates);
            return creation_error == VCS_ZCODE_CREATION_DUPLICATE
                ? VCS_ZCODE_EPOCH_CREATION_DUPLICATE
                : VCS_ZCODE_EPOCH_CREATION_ATTRIBUTION;
        }
        if (!zcl_u64_add(sum, attribution.award_atoms, &sum)) {
            free(seen_candidates);
            return VCS_ZCODE_EPOCH_CREATION_OVERFLOW;
        }
    }
    free(seen_candidates);
    return sum == set->actual_mint_atoms
        ? VCS_ZCODE_EPOCH_CREATION_OK : VCS_ZCODE_EPOCH_CREATION_SUM;
}
