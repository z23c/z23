/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure C23 corpus calculations. No storage, clock, RNG, wallet, network,
 * process, or node-global authority belongs in this translation unit. */
// one-result-type-ok:pure-vtable-preserves-versioned-vcs-error-enums

#include "services/zcode_c23_corpus_service.h"

#include "zcode_c23_corpus_internal.h"

#include "base/checked.h"
#include "base/hex.h"
#include "hotswap/hotswap_service.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static enum vcs_zcode_c23_error rules_validate(
    const struct vcs_zcode_c23_corpus_rules_v1 *rules)
{
    return vcs_zcode_c23_corpus_rules_v1_validate(rules);
}

static enum vcs_zcode_c23_error shard_validate(
    const struct vcs_zcode_c23_corpus_shard_v1 *shard)
{
    return vcs_zcode_c23_corpus_shard_v1_validate(shard);
}

static enum vcs_zcode_c23_error shard_page(
    const struct vcs_zcode_c23_corpus_shard_v1 *shard,
    const struct vcs_zcode_c23_page_cursor_v1 *cursor, size_t page_size,
    size_t *first_index, size_t *item_count,
    struct vcs_zcode_c23_page_cursor_v1 *next_cursor, bool *has_more)
{
    return vcs_zcode_c23_corpus_shard_v1_page(
        shard, cursor, page_size, first_index, item_count, next_cursor,
        has_more);
}

static enum vcs_zcode_c23_error checkpoint_validate(
    const struct vcs_zcode_c23_corpus_checkpoint_v1 *checkpoint)
{
    return vcs_zcode_c23_corpus_checkpoint_v1_validate(checkpoint);
}

static enum vcs_zcode_c23_error productivity_validate(
    const struct vcs_zcode_productivity_receipt_v1 *receipt)
{
    return vcs_zcode_productivity_receipt_v1_validate(receipt);
}

static bool render_status(
    const struct vcs_zcode_c23_corpus_checkpoint_v1 *checkpoint,
    struct zcode_c23_corpus_status_result_v1 *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    struct vcs_zcode_c23_corpus_rules_v1 rules;
    uint8_t root[32];
    vcs_zcode_c23_corpus_rules_v1_default(&rules);
    if (vcs_zcode_c23_corpus_rules_v1_root(&rules, root) !=
        VCS_ZCODE_C23_OK)
        return false;
    zcl_hex_encode(root, sizeof(root), out->rules_root);
    if (!checkpoint) {
        (void)snprintf(out->blocker, sizeof(out->blocker),
            "checkpoint_missing: commit a verified corpus checkpoint projection");
        (void)snprintf(out->progress_stage, sizeof(out->progress_stage), "%s",
                       ZCODE_C23_CORPUS_STAGE_MISSING);
        (void)snprintf(out->next_command, sizeof(out->next_command),
                       "zcode commons corpus show --root=%s",
                       out->rules_root);
        return true;
    }
    if (vcs_zcode_c23_corpus_checkpoint_v1_validate(checkpoint) !=
        VCS_ZCODE_C23_OK) {
        (void)snprintf(out->blocker, sizeof(out->blocker),
                       "the selected corpus checkpoint is invalid");
        (void)snprintf(out->progress_stage, sizeof(out->progress_stage), "%s",
                       ZCODE_C23_CORPUS_STAGE_INVALID);
        (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
                       ZCODE_C23_CORPUS_NEXT_VERIFY);
        return true;
    }
    uint64_t total = 0;
    if (!zcl_u64_add(checkpoint->production_loc, checkpoint->test_loc,
                     &total)) {
        (void)snprintf(out->blocker, sizeof(out->blocker),
                       "the selected corpus checkpoint count overflows");
        (void)snprintf(out->progress_stage, sizeof(out->progress_stage), "%s",
                       ZCODE_C23_CORPUS_STAGE_INVALID);
        (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
                       ZCODE_C23_CORPUS_NEXT_VERIFY);
        return true;
    }
    out->projection_ready = true;
    out->lower_bound_checkpoint_present = true;
    out->admitted_production_loc = checkpoint->production_loc;
    out->admitted_test_loc = checkpoint->test_loc;
    out->admitted_total_loc = total;
    out->durably_hosted_loc = checkpoint->durable_loc;
    out->physical_lines = checkpoint->physical_lines;
    out->unique_semantic_units = checkpoint->unique_semantic_units;
    if (total < VCS_ZCODE_C23_FIRST_MILESTONE_LOC) {
        (void)snprintf(out->progress_stage, sizeof(out->progress_stage), "%s",
                       ZCODE_C23_CORPUS_STAGE_BELOW_50M);
        (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
                       ZCODE_C23_CORPUS_NEXT_CREATE);
        (void)snprintf(out->blocker, sizeof(out->blocker),
            "verified lower bound is %" PRIu64
            " LOC; next milestone requires %" PRIu64 " LOC",
            total, (uint64_t)VCS_ZCODE_C23_FIRST_MILESTONE_LOC);
    } else if (checkpoint->durable_loc < total) {
        (void)snprintf(out->progress_stage, sizeof(out->progress_stage), "%s",
                       ZCODE_C23_CORPUS_STAGE_HOSTING);
        (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
                       ZCODE_C23_CORPUS_NEXT_HOST);
        (void)snprintf(out->blocker, sizeof(out->blocker),
            "durable hosting covers %" PRIu64 " of %" PRIu64
            " admitted LOC",
            checkpoint->durable_loc, total);
    } else if (total < VCS_ZCODE_C23_SECOND_MILESTONE_LOC) {
        (void)snprintf(out->progress_stage, sizeof(out->progress_stage), "%s",
                       ZCODE_C23_CORPUS_STAGE_DURABLE_50M);
        (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
                       ZCODE_C23_CORPUS_NEXT_CREATE);
        (void)snprintf(out->blocker, sizeof(out->blocker),
            "verified durable lower bound is %" PRIu64
            " LOC; next milestone requires %" PRIu64 " LOC",
            total, (uint64_t)VCS_ZCODE_C23_SECOND_MILESTONE_LOC);
    } else {
        (void)snprintf(out->progress_stage, sizeof(out->progress_stage), "%s",
                       ZCODE_C23_CORPUS_STAGE_DURABLE_100M);
        (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
                       ZCODE_C23_CORPUS_NEXT_IMPACT);
    }
    return true;
}

static bool render_rules(const char *requested_root,
                         struct zcode_c23_corpus_rules_result_v1 *out)
{
    if (!requested_root || !out) return false;
    memset(out, 0, sizeof(*out));
    struct vcs_zcode_c23_corpus_rules_v1 rules;
    uint8_t root[32];
    vcs_zcode_c23_corpus_rules_v1_default(&rules);
    if (vcs_zcode_c23_corpus_rules_v1_validate(&rules) != VCS_ZCODE_C23_OK ||
        vcs_zcode_c23_corpus_rules_v1_root(&rules, root) != VCS_ZCODE_C23_OK)
        return false;
    zcl_hex_encode(root, sizeof(root), out->root);
    out->found = strcmp(requested_root, out->root) == 0;
    if (!out->found) return true;
    out->overlap_threshold_bps = rules.overlap_threshold_bps;
    out->shard_entry_max = rules.shard_entry_max;
    out->checkpoint_shard_max = rules.checkpoint_shard_max;
    out->page_max = rules.page_max;
    out->publication_batch_max = rules.publication_batch_max;
    out->durable_ack_count = rules.durable_ack_count;
    out->durable_operator_group_count =
        rules.durable_operator_group_count;
    out->max_file_bytes = rules.max_file_bytes;
    out->first_milestone_loc = rules.first_milestone_loc;
    out->second_milestone_loc = rules.second_milestone_loc;
    return true;
}

static bool render_impact_readiness(
    const struct zcode_c23_impact_readiness_input_v1 *input,
    struct zcode_c23_impact_readiness_result_v1 *out)
{
    if (!input || !out) return false;
    memset(out, 0, sizeof(*out));
    out->valid = true;
    const char *readiness = ZCODE_C23_IMPACT_READY;
    const char *reason = "the current signed basis proves the complete chain";
    const char *next = "zcode commons impact share";
    if (!input->proven_work) {
        readiness = ZCODE_C23_IMPACT_MISSING_WORK;
        reason = "no current PROVEN work is bound to the productivity basis";
        next = "zcode guide";
    } else if (!input->human_acceptance) {
        readiness = ZCODE_C23_IMPACT_MISSING_ACCEPTANCE;
        reason = "human acceptance is not proven by the current basis";
        next = "zcode work status";
    } else if (!input->signed_release) {
        readiness = ZCODE_C23_IMPACT_MISSING_RELEASE;
        reason = "a signed release is not proven by the current basis";
        next = "zcode package publish plan";
    } else if (!input->independent_family_admission) {
        readiness = ZCODE_C23_IMPACT_MISSING_ADMISSION;
        reason = "independent current Family admission is not proven";
        next = "zcode moderation status";
    } else if (!input->complete_retrievable_package) {
        readiness = ZCODE_C23_IMPACT_MISSING_PACKAGE;
        reason = "the complete package is not currently retrievable";
        next = "zcode storage status";
    } else if (!input->basis_current) {
        readiness = ZCODE_C23_IMPACT_STALE;
        reason = "the signed productivity basis is stale";
        next = "zcode commons impact verify";
    } else {
        out->shareable = true;
    }
    (void)snprintf(out->readiness, sizeof(out->readiness), "%s", readiness);
    (void)snprintf(out->reason, sizeof(out->reason), "%s", reason);
    (void)snprintf(out->next_command, sizeof(out->next_command), "%s", next);
    return true;
}

static const struct zcode_c23_corpus_service_v1 k_builtin = {
    .rules_validate = rules_validate,
    .shard_validate = shard_validate,
    .shard_page = shard_page,
    .checkpoint_validate = checkpoint_validate,
    .productivity_validate = productivity_validate,
    .render_status = render_status,
    .render_rules = render_rules,
    .render_impact_readiness = render_impact_readiness,
};

ZCL_HOTSWAP_SERVICE_EXPORT(
    ZCODE_C23_CORPUS_SERVICE_ID, k_builtin,
    ZCODE_C23_CORPUS_ABI_FINGERPRINT,
    ZCODE_C23_CORPUS_SCHEMA_FINGERPRINT,
    ZCODE_C23_CORPUS_WIRE_FINGERPRINT,
    ZCODE_C23_CORPUS_KAT_FINGERPRINT)

const struct zcode_c23_corpus_service_v1 *zcode_c23_corpus_service_builtin(void)
{
    return &k_builtin;
}
