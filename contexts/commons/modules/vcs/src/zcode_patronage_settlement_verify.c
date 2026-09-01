/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: independently rederive simulated patronage settlement authority. */
#include "vcs/zcode_patronage_settlement.h"

#include "vcs/vcs_object.h"

#include <stdlib.h>
#include <string.h>

static bool settlement_equal(const uint8_t left[32],
                             const uint8_t right[32])
{
    return memcmp(left, right, 32) == 0;
}

static bool settlement_load(const char *workspace, const uint8_t root[32],
                            size_t maximum, uint8_t **wire,
                            size_t *wire_len)
{
    *wire = NULL;
    *wire_len = 0;
    return vcs_object_load_raw_bounded(workspace, root, maximum,
                                       wire, wire_len) == 0;
}

static enum vcs_zcode_patronage_settlement_error settlement_load_intent(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_patronage_intent_v1 *intent)
{
    uint8_t *wire = NULL, derived[32];
    size_t wire_len = 0;
    bool ok = settlement_load(workspace, root,
            VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES, &wire, &wire_len) &&
        vcs_zcode_patronage_intent_parse(wire, wire_len, intent) ==
            VCS_ZCODE_PATRONAGE_OK &&
        vcs_zcode_patronage_intent_root(intent, derived) ==
            VCS_ZCODE_PATRONAGE_OK &&
        settlement_equal(root, derived);
    free(wire);
    return ok ? VCS_ZCODE_PATRONAGE_SETTLEMENT_OK
              : VCS_ZCODE_PATRONAGE_SETTLEMENT_INTENT;
}

static enum vcs_zcode_patronage_settlement_error settlement_load_funding(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_patronage_funding_v1 *funding)
{
    uint8_t *wire = NULL, derived[32];
    size_t wire_len = 0;
    bool ok = settlement_load(workspace, root,
            VCS_ZCODE_PATRONAGE_FUNDING_WIRE_BYTES, &wire, &wire_len) &&
        vcs_zcode_patronage_funding_parse(wire, wire_len, funding) ==
            VCS_ZCODE_PATRONAGE_FUNDING_OK &&
        vcs_zcode_patronage_funding_root(funding, derived) ==
            VCS_ZCODE_PATRONAGE_FUNDING_OK &&
        settlement_equal(root, derived);
    free(wire);
    return ok ? VCS_ZCODE_PATRONAGE_SETTLEMENT_OK
              : VCS_ZCODE_PATRONAGE_SETTLEMENT_FUNDING;
}

static enum vcs_zcode_patronage_settlement_error settlement_load_creation(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_creation_attribution_v1 *creation)
{
    uint8_t *wire = NULL, derived[32];
    size_t wire_len = 0;
    bool ok = settlement_load(workspace, root,
            VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES, &wire, &wire_len) &&
        vcs_zcode_creation_attribution_parse(wire, wire_len, creation) ==
            VCS_ZCODE_CREATION_OK &&
        vcs_zcode_creation_attribution_root(creation, derived) ==
            VCS_ZCODE_CREATION_OK &&
        settlement_equal(root, derived);
    free(wire);
    return ok ? VCS_ZCODE_PATRONAGE_SETTLEMENT_OK
              : VCS_ZCODE_PATRONAGE_SETTLEMENT_EVIDENCE;
}

static enum vcs_zcode_patronage_settlement_error settlement_proof_chain(
    const struct vcs_zcode_patronage_settlement_v1 *settlement,
    const struct vcs_zcode_patronage_intent_v1 *intent,
    const struct vcs_zcode_patronage_settlement_validation_context *context)
{
    if (!context->creation)
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_CONTEXT;
    struct vcs_zcode_creation_attribution_v1 creation;
    enum vcs_zcode_patronage_settlement_error error =
        settlement_load_creation(context->patronage->workspace,
                                 settlement->creation_attribution_root,
                                 &creation);
    if (error != VCS_ZCODE_PATRONAGE_SETTLEMENT_OK) return error;

    struct vcs_zcode_creation_validation_context creation_context =
        *context->creation;
    creation_context.workspace = context->patronage->workspace;
    creation_context.active_height = settlement->observed_height;
    creation_context.active_mtp = settlement->observed_mtp;
    creation_context.now_unix = settlement->created_unix;
    if (vcs_zcode_creation_attribution_verify_cas(
            &creation, &creation_context) != VCS_ZCODE_CREATION_OK)
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_EVIDENCE;

    if (!settlement_equal(creation.network_genesis_root,
                          settlement->network_genesis_root) ||
        !settlement_equal(creation.contributor_binding_root,
                          settlement->recipient_contributor_binding_root) ||
        !settlement_equal(creation.task_root, settlement->task_root) ||
        !settlement_equal(creation.candidate_root,
                          settlement->candidate_root) ||
        !settlement_equal(creation.proof_policy_root,
                          settlement->proof_policy_root) ||
        !settlement_equal(creation.proof_set_root,
                          settlement->proof_set_root) ||
        !settlement_equal(creation.proven_lane_root,
                          settlement->proven_lane_root) ||
        !settlement_equal(creation.score_receipt_root,
                          settlement->score_receipt_root) ||
        !settlement_equal(intent->intended_recipient_binding_root,
                          creation.contributor_binding_root) ||
        !settlement_equal(intent->proof_policy_root,
                          creation.proof_policy_root))
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_EVIDENCE;
    if (intent->mode == VCS_ZCODE_PATRONAGE_EXACT_TASK_COMMISSION &&
        !settlement_equal(intent->task_root, creation.task_root))
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_EVIDENCE;
    if (intent->mode == VCS_ZCODE_PATRONAGE_PACKAGE_CONTINUITY &&
        !settlement_equal(intent->target_root, creation.package_root))
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_EVIDENCE;
    return VCS_ZCODE_PATRONAGE_SETTLEMENT_OK;
}

enum vcs_zcode_patronage_settlement_error
vcs_zcode_patronage_settlement_verify_cas(
    const struct vcs_zcode_patronage_settlement_v1 *settlement,
    const struct vcs_zcode_patronage_settlement_validation_context *context)
{
    enum vcs_zcode_patronage_settlement_error error =
        vcs_zcode_patronage_settlement_verify(settlement);
    if (error != VCS_ZCODE_PATRONAGE_SETTLEMENT_OK) return error;
    if (!context || !context->patronage ||
        !context->patronage->workspace ||
        !context->patronage->expected_network_genesis_root ||
        context->now_unix <= 0 || context->active_height == 0 ||
        context->active_mtp <= 0)
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_CONTEXT;
    if (!settlement_equal(settlement->network_genesis_root,
            context->patronage->expected_network_genesis_root))
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_CONTEXT;
    if (settlement->created_unix > context->now_unix ||
        settlement->observed_height > context->active_height ||
        settlement->observed_mtp > context->active_mtp ||
        settlement->observed_mtp > settlement->created_unix)
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_TIME;

    struct vcs_zcode_patronage_funding_v1 funding;
    error = settlement_load_funding(context->patronage->workspace,
                                    settlement->patronage_funding_root,
                                    &funding);
    if (error != VCS_ZCODE_PATRONAGE_SETTLEMENT_OK) return error;
    struct vcs_zcode_patronage_intent_v1 intent;
    error = settlement_load_intent(context->patronage->workspace,
                                   settlement->patronage_intent_root,
                                   &intent);
    if (error != VCS_ZCODE_PATRONAGE_SETTLEMENT_OK) return error;

    struct vcs_zcode_patronage_validation_context historical =
        *context->patronage;
    historical.now_unix = funding.created_unix;
    if (vcs_zcode_patronage_funding_verify_cas(
            &funding, &historical) != VCS_ZCODE_PATRONAGE_FUNDING_OK)
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_FUNDING;
    if (!settlement_equal(funding.patronage_intent_root,
                          settlement->patronage_intent_root) ||
        !settlement_equal(funding.network_genesis_root,
                          settlement->network_genesis_root) ||
        !settlement_equal(funding.funder_zid_pubkey,
                          settlement->settler_zid_pubkey))
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_FUNDING;
    if (funding.amount_atoms != settlement->amount_atoms ||
        intent.amount_atoms != settlement->amount_atoms)
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_AMOUNT;
    if (funding.created_unix >= settlement->created_unix)
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_TIME;

    if (settlement->action == VCS_ZCODE_PATRONAGE_SIMULATED_REFUNDED) {
        if (intent.mode == VCS_ZCODE_PATRONAGE_DIRECT_GIFT ||
            !settlement_equal(
                settlement->recipient_contributor_binding_root,
                intent.patron_contributor_binding_root))
            return VCS_ZCODE_PATRONAGE_SETTLEMENT_INTENT;
        return settlement->created_unix >= intent.expires_unix &&
               settlement->created_unix >= intent.refund_unix &&
               settlement->observed_height >= intent.refund_height &&
               settlement->observed_mtp >= intent.refund_unix
            ? VCS_ZCODE_PATRONAGE_SETTLEMENT_OK
            : VCS_ZCODE_PATRONAGE_SETTLEMENT_TIME;
    }

    if (settlement->created_unix >= intent.expires_unix ||
        !settlement_equal(settlement->recipient_contributor_binding_root,
                          intent.intended_recipient_binding_root))
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_INTENT;
    if (intent.mode == VCS_ZCODE_PATRONAGE_DIRECT_GIFT) {
        const uint8_t *evidence[] = {
            settlement->creation_attribution_root, settlement->task_root,
            settlement->candidate_root, settlement->proof_policy_root,
            settlement->proof_set_root, settlement->proven_lane_root,
            settlement->score_receipt_root,
        };
        static const uint8_t zero[32] = {0};
        for (size_t i = 0; i < sizeof(evidence) / sizeof(evidence[0]); i++)
            if (!settlement_equal(evidence[i], zero))
                return VCS_ZCODE_PATRONAGE_SETTLEMENT_EVIDENCE;
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_OK;
    }
    return settlement_proof_chain(settlement, &intent, context);
}
