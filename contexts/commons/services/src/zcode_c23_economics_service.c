/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure simulation-only economics calculations. No issuance, wallet, storage,
 * clock, network, process, or node-global authority belongs here. */
// one-result-type-ok:pure-vtable-preserves-versioned-vcs-error-enums

#include "services/zcode_c23_economics_service.h"

#include "zcode_c23_economics_internal.h"

#include "hotswap/hotswap_service.h"

#include <stdio.h>
#include <string.h>

static bool render_status(struct zcode_c23_economics_status_result_v1 *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    out->challenge_blocks = VCS_ZCODE_COMMONS_CHALLENGE_BLOCKS;
    out->challenge_seconds = VCS_ZCODE_COMMONS_CHALLENGE_SECONDS;
    /* Frozen policy: claims are all-or-nothing and unused epoch capacity
     * expires. Set both explicitly so a status consumer never has to infer
     * policy from zero-initialization. */
    out->partial_claim_issuance = false;
    out->unused_capacity_carries = false;
    for (uint16_t i = 0; i < VCS_ZCODE_COMMONS_CATEGORY_COUNT; i++)
        out->award_atoms[i] = vcs_zcode_creation_award_atoms_v2(i);
    (void)snprintf(out->queue_order, sizeof(out->queue_order), "%s",
                   ZCODE_C23_ECONOMICS_QUEUE_ORDER);
    (void)snprintf(out->category_order, sizeof(out->category_order), "%s",
                   ZCODE_C23_ECONOMICS_CATEGORY_ORDER);
    (void)snprintf(out->concentration_cap, sizeof(out->concentration_cap),
                   "%s", ZCODE_C23_ECONOMICS_CONCENTRATION_CAP);
    return true;
}

static bool render_schedule_proposal(
    const struct vcs_zcode_epoch_schedule_proposal_v1 *proposal,
    bool persisted, struct zcode_c23_schedule_proposal_view_v1 *out)
{
    /* The caller owns proposal and output storage for the entire lease. */
    if (!proposal || !out ||
        vcs_zcode_epoch_schedule_validate(proposal) !=
            VCS_ZCODE_EPOCH_SCHEDULE_OK)
        return false;
    memset(out, 0, sizeof(*out));
    out->cap_atoms = VCS_ZC23_SCHEDULE_CAP_ATOMS;
    out->total_epochs = VCS_ZC23_SCHEDULE_TOTAL_EPOCHS;
    out->epoch = proposal->epoch;
    out->budget_atoms = proposal->budget_atoms;
    out->already_emitted_atoms = proposal->already_emitted_atoms;
    out->proposed_mint_atoms = proposal->proposed_mint_atoms;
    out->unissued_atoms = proposal->unissued_atoms;
    out->evidence_count = proposal->evidence_count;
    out->eligible_count = proposal->eligible_count;
    out->preservation_skipped = proposal->preservation_skipped;
    for (uint16_t schedule_class = VCS_ZCODE_EPOCH_SCHEDULE_CLASS_CREATION;
         schedule_class <= VCS_ZCODE_EPOCH_SCHEDULE_CLASS_PRESERVATION;
         schedule_class++) {
        if (!vcs_zcode_epoch_schedule_class_weight(
                schedule_class, &out->class_weights[schedule_class - 1]))
            return false;
    }
    out->simulated = true;
    out->persisted = persisted;
    out->schedule_proposal = true;
    out->mint = false;
    out->token_exists = false;
    out->funds_moved = false;
    out->custody_used = false;
    out->genesis_gate_satisfied = false;
    out->balance_used_for_truth = false;
    (void)snprintf(out->preservation_skip_reason,
                   sizeof(out->preservation_skip_reason), "%s",
                   VCS_ZCODE_EPOCH_SCHEDULE_PRESERVATION_SKIP_REASON);
    (void)snprintf(out->mint_authority, sizeof(out->mint_authority), "%s",
                   "simulation_only;no_issuance_authority");
    return true;
}

static bool render_backlog_status(
    const struct zcode_c23_backlog_status_input_v1 *input,
    struct zcode_c23_backlog_status_result_v1 *out)
{
    if (!input || !out || input->eligible_claim_count > input->claim_count ||
        (!input->projection_ready &&
         (input->claim_count != 0 || input->eligible_claim_count != 0)))
        return false;
    memset(out, 0, sizeof(*out));
    out->valid = true;
    out->backlog_ready = input->projection_ready;
    out->issuance_enabled = false;
    out->unused_capacity_expires = true;
    if (!input->projection_ready) {
        (void)snprintf(out->readiness, sizeof(out->readiness), "%s",
                       ZCODE_C23_BACKLOG_PROJECTION_MISSING);
        (void)snprintf(out->reason, sizeof(out->reason), "%s",
                       "the verified claim projection is unavailable or incomplete; issuance selection is unavailable");
        (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
                       ZCODE_C23_BACKLOG_CLAIM_NEXT);
    } else if (input->claim_count == 0) {
        (void)snprintf(out->readiness, sizeof(out->readiness), "%s",
                       ZCODE_C23_BACKLOG_EMPTY);
        (void)snprintf(out->reason, sizeof(out->reason), "%s",
                       "the verified claim projection is current and empty");
        (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
                       ZCODE_C23_BACKLOG_CLAIM_NEXT);
    } else if (input->eligible_claim_count == 0) {
        (void)snprintf(out->readiness, sizeof(out->readiness), "%s",
                       ZCODE_C23_BACKLOG_INELIGIBLE);
        (void)snprintf(out->reason, sizeof(out->reason), "%s",
                       "claims exist but none is eligible at the current cutoff");
        (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
                       ZCODE_C23_BACKLOG_STATUS_NEXT);
    } else {
        (void)snprintf(out->readiness, sizeof(out->readiness), "%s",
                       ZCODE_C23_BACKLOG_EPOCH_READY);
        (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
                       ZCODE_C23_BACKLOG_EPOCH_NEXT);
    }
    return true;
}

static bool render_claim_epoch(
    const struct vcs_zcode_claim_epoch_proposal_v2 *proposal,
    bool persisted, bool current_selection_verified,
    struct zcode_c23_claim_epoch_view_v1 *out)
{
    if (!proposal || !out ||
        vcs_zcode_claim_epoch_validate(proposal) !=
            VCS_ZCODE_CLAIM_EPOCH_OK)
        return false;
    memset(out, 0, sizeof(*out));
    out->epoch = proposal->epoch;
    out->cutoff_height = proposal->cutoff_height;
    out->cutoff_mtp = proposal->cutoff_mtp;
    out->epoch_capacity_atoms = proposal->epoch_capacity_atoms;
    out->selected_atoms = proposal->selected_atoms;
    out->expired_capacity_atoms = proposal->expired_capacity_atoms;
    out->recipient_cap_atoms = proposal->recipient_cap_atoms;
    out->lineage_cap_atoms = proposal->lineage_cap_atoms;
    out->claim_count = proposal->claim_count;
    out->selected_count = proposal->selected_count;
    out->deferred_count = proposal->deferred_count;
    out->invalid_count = proposal->invalid_count;
    out->first_category = proposal->first_category;
    out->valid = true;
    out->persisted = persisted;
    out->canonical_proposal = true;
    out->current_selection_verified = current_selection_verified;
    out->simulation_only = true;
    out->issuance_enabled = false;
    out->wallet_used = false;
    out->funds_moved = false;
    (void)snprintf(out->verification_state,
                   sizeof(out->verification_state), "%s",
                   current_selection_verified
                       ? "verified:current_selection"
                       : "canonical:selection_not_reconstructed");
    (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
                   current_selection_verified
                       ? "zcode commons backlog"
                       : "zcode commons schedule claim verify");
    return true;
}

static bool schedule_class_name(uint16_t schedule_class,
                                char *out, size_t out_size)
{
    const char *name = NULL;
    switch (schedule_class) {
    case VCS_ZCODE_EPOCH_SCHEDULE_CLASS_CREATION: name = "creation"; break;
    case VCS_ZCODE_EPOCH_SCHEDULE_CLASS_REPRODUCTION:
        name = "reproduction";
        break;
    case VCS_ZCODE_EPOCH_SCHEDULE_CLASS_REPAIR: name = "repair"; break;
    case VCS_ZCODE_EPOCH_SCHEDULE_CLASS_PRESERVATION:
        name = "preservation";
        break;
    default: return false;
    }
    if (!out || out_size == 0 || strlen(name) + 1 > out_size)
        return false;
    (void)snprintf(out, out_size, "%s", name);
    return true;
}

static const struct zcode_c23_economics_service_v1 k_builtin = {
    .award_atoms = vcs_zcode_creation_award_atoms_v2,
    .policy_init = vcs_zcode_policy_candidate_v2_init,
    .policy_validate = vcs_zcode_policy_candidate_v2_validate,
    .policy_root = vcs_zcode_policy_candidate_v2_root,
    .epoch_select = vcs_zcode_epoch_select_v2,
    .render_status = render_status,
    .render_schedule_proposal = render_schedule_proposal,
    .render_backlog_status = render_backlog_status,
    .render_claim_epoch = render_claim_epoch,
    .schedule_class_name = schedule_class_name,
};

ZCL_HOTSWAP_SERVICE_EXPORT(
    ZCODE_C23_ECONOMICS_SERVICE_ID, k_builtin,
    ZCODE_C23_ECONOMICS_ABI_FINGERPRINT,
    ZCODE_C23_ECONOMICS_SCHEMA_FINGERPRINT,
    ZCODE_C23_ECONOMICS_WIRE_FINGERPRINT,
    ZCODE_C23_ECONOMICS_KAT_FINGERPRINT)

const struct zcode_c23_economics_service_v1 *
zcode_c23_economics_service_builtin(void)
{
    return &k_builtin;
}
