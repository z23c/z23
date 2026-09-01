/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: fail-closed read surfaces for the verified C23 corpus sprint. */

#include "command/native_command.h"

#include "base/checked.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "services/zcode_c23_corpus_service.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "vcs/zcode_c23_corpus.h"

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool corpus_no_keys(const struct json_value *input)
{
    return input && input->type == JSON_OBJ && input->num_children == 0;
}

static void corpus_fail(struct zcl_command_reply *reply, const char *code,
                        const char *detail)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "validate", false,
                           false, detail, "zcode.commons.corpus");
}

static void corpus_kat_fill(uint8_t root[32], uint8_t value)
{
    memset(root, value, 32);
}

static bool corpus_shard_frozen_kat(
    const struct zcode_c23_corpus_service_v1 *service, char *why,
    size_t why_sz)
{
    struct vcs_zcode_c23_corpus_entry_v1 entry = {
        .release_sequence = 1,
        .production_loc = 2,
        .test_loc = 1,
        .physical_lines = 4,
        .unique_semantic_units = 2,
        .evidence_mask = VCS_ZCODE_C23_EVIDENCE_REQUIRED_MASK,
        .flags = VCS_ZCODE_C23_ENTRY_COUNTED |
                 VCS_ZCODE_C23_ENTRY_DURABLE,
    };
    corpus_kat_fill(entry.semantic_lineage_root, 0x51);
    corpus_kat_fill(entry.release_root, 0x52);
    corpus_kat_fill(entry.passport_root, 0x53);
    corpus_kat_fill(entry.proof_root, 0x54);
    corpus_kat_fill(entry.source_assignment_root, 0x55);
    corpus_kat_fill(entry.admission_root, 0x56);
    corpus_kat_fill(entry.possession_root, 0x57);
    struct vcs_zcode_c23_corpus_shard_v1 shard = {
        .schema_version = 1,
        .flags = VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS,
        .entries = &entry,
        .entry_count = 1,
    };
    struct vcs_zcode_c23_corpus_rules_v1 rules;
    vcs_zcode_c23_corpus_rules_v1_default(&rules);
    if (vcs_zcode_c23_corpus_rules_v1_root(&rules, shard.rules_root) !=
            VCS_ZCODE_C23_OK) {
        if (why && why_sz)
            (void)snprintf(why, why_sz, "frozen shard rules-root vector failed");
        return false;
    }
    corpus_kat_fill(shard.family_policy_root, 0x58);
    corpus_kat_fill(shard.moderation_set_root, 0x59);
    if (service->shard_validate(&shard) != VCS_ZCODE_C23_OK) {
        if (why && why_sz)
            (void)snprintf(why, why_sz, "frozen valid shard vector failed");
        return false;
    }
    size_t first = SIZE_MAX, count = SIZE_MAX;
    struct vcs_zcode_c23_page_cursor_v1 next;
    bool more = true;
    if (service->shard_page(&shard, NULL, 1, &first, &count, &next,
                            &more) != VCS_ZCODE_C23_OK ||
        first != 0 || count != 1 || more) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen first shard-page vector failed");
        return false;
    }
    struct vcs_zcode_c23_page_cursor_v1 wrong = {.next_index = 1};
    corpus_kat_fill(wrong.shard_root, 0xa5);
    if (service->shard_page(&shard, &wrong, 1, &first, &count, &next,
                            &more) != VCS_ZCODE_C23_CURSOR) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen shard-page cursor rejection vector failed");
        return false;
    }
    entry.flags |= UINT32_C(0x80000000);
    if (service->shard_validate(&shard) != VCS_ZCODE_C23_FLAGS) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen invalid shard rejection vector failed");
        return false;
    }
    return true;
}

static bool corpus_checkpoint_frozen_kat(
    const struct zcode_c23_corpus_service_v1 *service, char *why,
    size_t why_sz)
{
    struct vcs_zcode_c23_checkpoint_shard_v1 binding = {
        .entry_count = 1,
        .production_loc = 2,
        .test_loc = 1,
        .durable_loc = 3,
        .physical_lines = 4,
        .unique_semantic_units = 2,
    };
    corpus_kat_fill(binding.shard_root, 0x61);
    corpus_kat_fill(binding.first_lineage_root, 0x62);
    corpus_kat_fill(binding.last_lineage_root, 0x63);
    struct vcs_zcode_c23_corpus_checkpoint_v1 checkpoint = {
        .schema_version = 1,
        .flags = VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS,
        .milestone = VCS_ZCODE_C23_MILESTONE_NONE,
        .sequence = 1,
        .cutoff_height = 1,
        .cutoff_mtp = 1,
        .total_entries = binding.entry_count,
        .production_loc = binding.production_loc,
        .test_loc = binding.test_loc,
        .durable_loc = binding.durable_loc,
        .physical_lines = binding.physical_lines,
        .unique_semantic_units = binding.unique_semantic_units,
        .shards = &binding,
        .shard_count = 1,
    };
    struct vcs_zcode_c23_corpus_rules_v1 rules;
    vcs_zcode_c23_corpus_rules_v1_default(&rules);
    if (vcs_zcode_c23_corpus_rules_v1_root(
            &rules, checkpoint.rules_root) != VCS_ZCODE_C23_OK) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen checkpoint rules-root vector failed");
        return false;
    }
    corpus_kat_fill(checkpoint.family_policy_root, 0x64);
    corpus_kat_fill(checkpoint.moderation_set_root, 0x65);
    corpus_kat_fill(checkpoint.replication_evidence_root, 0x66);
    uint8_t seed[32];
    corpus_kat_fill(seed, 0x67);
    if (vcs_zcode_c23_corpus_checkpoint_v1_sign(&checkpoint, seed) !=
            VCS_ZCODE_C23_OK ||
        service->checkpoint_validate(&checkpoint) != VCS_ZCODE_C23_OK) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen signed checkpoint validation vector failed");
        return false;
    }
    struct zcode_c23_corpus_status_result_v1 status;
    if (!service->render_status(&checkpoint, &status) ||
        strcmp(status.progress_stage, "below_50m") != 0 ||
        strcmp(status.next_command, "zcode package guide") != 0) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen below-50m status vector failed");
        return false;
    }
    binding.production_loc = VCS_ZCODE_C23_FIRST_MILESTONE_LOC;
    binding.test_loc = 0;
    binding.durable_loc = VCS_ZCODE_C23_FIRST_MILESTONE_LOC - 1u;
    checkpoint.production_loc = binding.production_loc;
    checkpoint.test_loc = binding.test_loc;
    checkpoint.durable_loc = binding.durable_loc;
    if (vcs_zcode_c23_corpus_checkpoint_v1_sign(&checkpoint, seed) !=
            VCS_ZCODE_C23_OK ||
        !service->render_status(&checkpoint, &status) ||
        strcmp(status.progress_stage, "hosting_incomplete") != 0 ||
        strcmp(status.next_command, "zcode storage status") != 0) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen incomplete-hosting status vector failed");
        return false;
    }
    binding.durable_loc = VCS_ZCODE_C23_FIRST_MILESTONE_LOC;
    checkpoint.durable_loc = binding.durable_loc;
    if (vcs_zcode_c23_corpus_checkpoint_v1_sign(&checkpoint, seed) !=
            VCS_ZCODE_C23_OK ||
        !service->render_status(&checkpoint, &status) ||
        strcmp(status.progress_stage, "durable_50m_lower_bound") != 0 ||
        strcmp(status.next_command, "zcode package guide") != 0) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen durable-50m status vector failed");
        return false;
    }
    binding.production_loc = VCS_ZCODE_C23_SECOND_MILESTONE_LOC;
    binding.durable_loc = VCS_ZCODE_C23_SECOND_MILESTONE_LOC;
    checkpoint.production_loc = binding.production_loc;
    checkpoint.durable_loc = binding.durable_loc;
    checkpoint.milestone = VCS_ZCODE_C23_MILESTONE_100M;
    corpus_kat_fill(checkpoint.verified_50m_ancestor_root, 0x68);
    if (vcs_zcode_c23_corpus_checkpoint_v1_sign(&checkpoint, seed) !=
            VCS_ZCODE_C23_OK ||
        !service->render_status(&checkpoint, &status) ||
        strcmp(status.progress_stage, "durable_100m_lower_bound") != 0 ||
        strcmp(status.next_command, "zcode commons impact status") != 0) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen durable-100m status vector failed");
        return false;
    }
    checkpoint.signature[0] ^= 1u;
    if (service->checkpoint_validate(&checkpoint) !=
        VCS_ZCODE_C23_SIGNATURE) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen tampered checkpoint rejection vector failed");
        return false;
    }
    return true;
}

static bool corpus_productivity_frozen_kat(
    const struct zcode_c23_corpus_service_v1 *service, char *why,
    size_t why_sz)
{
    struct vcs_zcode_productivity_receipt_v1 receipt = {
        .schema_version = 1,
        .flags = VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS,
        .evidence_mask = VCS_ZCODE_PRODUCTIVITY_REQUIRED_MASK,
        .completed_height = 1,
        .completed_mtp = 1,
    };
    corpus_kat_fill(receipt.work_root, 0x71);
    corpus_kat_fill(receipt.acceptance_root, 0x72);
    corpus_kat_fill(receipt.release_root, 0x73);
    corpus_kat_fill(receipt.admission_root, 0x74);
    corpus_kat_fill(receipt.package_root, 0x75);
    corpus_kat_fill(receipt.checkpoint_root, 0x76);
    uint8_t seed[32];
    corpus_kat_fill(seed, 0x77);
    if (vcs_zcode_productivity_receipt_v1_sign(&receipt, seed) !=
            VCS_ZCODE_C23_OK ||
        service->productivity_validate(&receipt) != VCS_ZCODE_C23_OK) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen signed productivity validation vector failed");
        return false;
    }
    receipt.signature[0] ^= 1u;
    if (service->productivity_validate(&receipt) !=
        VCS_ZCODE_C23_SIGNATURE) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen tampered productivity rejection vector failed");
        return false;
    }
    return true;
}

static bool corpus_service_frozen_kat(const void *opaque, char *why,
                                      size_t why_sz)
{
    const struct zcode_c23_corpus_service_v1 *service = opaque;
    struct zcode_c23_corpus_status_result_v1 status;
    if (!service || !service->rules_validate || !service->shard_validate ||
        !service->shard_page ||
        !service->checkpoint_validate || !service->productivity_validate ||
        !service->render_status || !service->render_rules ||
        !service->render_impact_readiness ||
        !service->render_status(NULL, &status) ||
        status.projection_ready || status.admitted_total_loc != 0 ||
        strcmp(status.rules_root, ZCODE_C23_CORPUS_KAT_FINGERPRINT) != 0 ||
        strcmp(status.progress_stage, "checkpoint_missing") != 0 ||
        strstr(status.next_command, ZCODE_C23_CORPUS_KAT_FINGERPRINT) == NULL) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen empty-projection/rules-root vector failed");
        return false;
    }
    struct zcode_c23_impact_readiness_input_v1 impact = {0};
    struct zcode_c23_impact_readiness_result_v1 impact_view;
    if (!service->render_impact_readiness(&impact, &impact_view) ||
        !impact_view.valid || impact_view.shareable ||
        strcmp(impact_view.readiness, "blocked:proven_work_missing") != 0 ||
        strcmp(impact_view.next_command, "zcode guide") != 0) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen missing-work impact vector failed");
        return false;
    }
    impact.proven_work = true;
    impact.human_acceptance = true;
    impact.signed_release = true;
    impact.independent_family_admission = true;
    impact.complete_retrievable_package = true;
    if (!service->render_impact_readiness(&impact, &impact_view) ||
        strcmp(impact_view.readiness, "blocked:basis_stale") != 0) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen stale-basis impact vector failed");
        return false;
    }
    impact.basis_current = true;
    if (!service->render_impact_readiness(&impact, &impact_view) ||
        !impact_view.shareable ||
        strcmp(impact_view.readiness, "ready:shareable") != 0 ||
        strcmp(impact_view.next_command,
               "zcode commons impact share") != 0) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen complete-chain impact vector failed");
        return false;
    }
    struct zcode_c23_corpus_rules_result_v1 rules;
    if (!service->render_rules(ZCODE_C23_CORPUS_KAT_FINGERPRINT, &rules) ||
        !rules.found || rules.global_completeness_claimed ||
        strcmp(rules.root, ZCODE_C23_CORPUS_KAT_FINGERPRINT) != 0 ||
        rules.shard_entry_max != VCS_ZCODE_C23_SHARD_ENTRY_MAX ||
        rules.page_max != VCS_ZCODE_C23_PAGE_MAX) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen exact-root rules rendering vector failed");
        return false;
    }
    if (!corpus_shard_frozen_kat(service, why, why_sz))
        return false;
    if (!corpus_checkpoint_frozen_kat(service, why, why_sz))
        return false;
    if (!corpus_productivity_frozen_kat(service, why, why_sz))
        return false;
    return true;
}

static const struct zcl_hotswap_service_contract k_corpus_contract = {
    .service_id = ZCODE_C23_CORPUS_SERVICE_ID,
    .source_tu = "contexts/commons/services/src/zcode_c23_corpus_service.c",
    .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
    .vtable_size = sizeof(struct zcode_c23_corpus_service_v1),
    .abi_fingerprint = ZCODE_C23_CORPUS_ABI_FINGERPRINT,
    .schema_fingerprint = ZCODE_C23_CORPUS_SCHEMA_FINGERPRINT,
    .wire_fingerprint = ZCODE_C23_CORPUS_WIRE_FINGERPRINT,
    .kat_fingerprint = ZCODE_C23_CORPUS_KAT_FINGERPRINT,
    .frozen_kat = corpus_service_frozen_kat,
};

const struct zcl_hotswap_service_contract *
zcl_native_zcode_corpus_service_contract(void)
{
    return &k_corpus_contract;
}

/* Resident signed checkpoint: the census driver (--install) drops the
 * verified wire at <datadir>/zcode/corpus/checkpoint.hex. Presence is
 * optional: a missing file renders checkpoint_missing exactly as before; a
 * present but undecodable or signature-invalid file is logged and also
 * degrades to checkpoint_missing (never trusted, never fatal to the read).
 * Returns true only when *out holds a fully validated checkpoint. */
#define CORPUS_RESIDENT_WIRE_CAP 8192u
#define CORPUS_RESIDENT_SHARD_CAP 256u

static bool corpus_resident_load(
    struct vcs_zcode_c23_corpus_checkpoint_v1 *out,
    struct vcs_zcode_c23_checkpoint_shard_v1 *shards, size_t shard_cap,
    bool *present)
{
    if (present) *present = false;
    if (!out || !shards || !shard_cap) return false;
    const char *datadir = zcl_native_command_datadir();
    if (!datadir || !datadir[0]) return false;
    char path[4400];
    int n = snprintf(path, sizeof(path), "%s/zcode/corpus/checkpoint.hex",
                     datadir);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        LOG_FAIL("zcode.corpus", "resident checkpoint path too long");
        return false;
    }
    FILE *f = fopen(path, "rb");
    if (!f) return false; /* the ordinary not-installed case */
    if (present) *present = true;
    char hex[2u * CORPUS_RESIDENT_WIRE_CAP + 2u];
    size_t len = fread(hex, 1, sizeof(hex) - 1u, f);
    bool truncated = ferror(f) || !feof(f);
    (void)fclose(f);
    if (truncated || !len || len > 2u * CORPUS_RESIDENT_WIRE_CAP) {
        LOG_FAIL("zcode.corpus", "resident checkpoint unreadable or "
                 "oversize (%zu hex chars)", len);
        return false;
    }
    while (len && (hex[len - 1] == '\n' || hex[len - 1] == '\r' ||
                   hex[len - 1] == ' ' || hex[len - 1] == '\t'))
        len--;
    if (!len || (len & 1u)) {
        LOG_FAIL("zcode.corpus", "resident checkpoint hex length %zu", len);
        return false;
    }
    hex[len] = '\0';
    uint8_t wire[CORPUS_RESIDENT_WIRE_CAP];
    size_t wire_len = len / 2u;
    if (!zcl_hex_decode_lower(hex, wire, wire_len)) {
        LOG_FAIL("zcode.corpus", "resident checkpoint is not lowercase hex");
        return false;
    }
    enum vcs_zcode_c23_error error =
        vcs_zcode_c23_corpus_checkpoint_v1_decode(out, shards, shard_cap,
                                                  wire, wire_len);
    if (error != VCS_ZCODE_C23_OK) {
        LOG_FAIL("zcode.corpus", "resident checkpoint rejected: %s",
                 vcs_zcode_c23_error_string(error));
        return false;
    }
    return true;
}

void zcl_native_handle_zcode_commons_corpus_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply || !corpus_no_keys(request->input)) {
        if (reply) corpus_fail(reply, "BAD_CORPUS_STATUS_INPUT",
            "zcode commons corpus status accepts no input keys");
        return;
    }
    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_c23_corpus_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_C23_CORPUS_SERVICE_ID, &lease);
    if (!service) service = zcode_c23_corpus_service_builtin();
    struct vcs_zcode_c23_corpus_checkpoint_v1 resident;
    struct vcs_zcode_c23_checkpoint_shard_v1
        resident_shards[CORPUS_RESIDENT_SHARD_CAP];
    bool resident_present = false;
    bool resident_ok = corpus_resident_load(&resident, resident_shards,
        CORPUS_RESIDENT_SHARD_CAP, &resident_present);
    struct zcode_c23_corpus_status_result_v1 status;
    if (!service->render_status(resident_ok ? &resident : NULL, &status)) {
        zcl_hotswap_service_release(&lease);
        corpus_fail(reply, "CORPUS_SERVICE_FAILED",
                    "the pure corpus calculation service refused its input");
        return;
    }
    (void)json_push_kv_bool(&reply->data, "simulation_only", true);
    (void)json_push_kv_bool(&reply->data, "not_owner_approved", true);
    (void)json_push_kv_str(&reply->data, "service_id",
                           ZCODE_C23_CORPUS_SERVICE_ID);
    (void)json_push_kv_int(&reply->data, "service_generation",
                           zcl_hotswap_service_generation());
    (void)json_push_kv_str(&reply->data, "rules_root", status.rules_root);
    (void)json_push_kv_bool(&reply->data, "projection_ready",
                            status.projection_ready);
    (void)json_push_kv_bool(&reply->data,
        "lower_bound_checkpoint_present",
        status.lower_bound_checkpoint_present);
    (void)json_push_kv_int(&reply->data, "admitted_production_loc",
                           (int64_t)status.admitted_production_loc);
    (void)json_push_kv_int(&reply->data, "admitted_test_loc",
                           (int64_t)status.admitted_test_loc);
    (void)json_push_kv_int(&reply->data, "admitted_total_loc",
                           (int64_t)status.admitted_total_loc);
    (void)json_push_kv_int(&reply->data, "durably_hosted_loc",
                           (int64_t)status.durably_hosted_loc);
    (void)json_push_kv_int(&reply->data, "physical_lines",
                           (int64_t)status.physical_lines);
    (void)json_push_kv_int(&reply->data, "unique_semantic_units",
                           (int64_t)status.unique_semantic_units);
    (void)json_push_kv_int(&reply->data, "first_milestone_loc",
                           VCS_ZCODE_C23_FIRST_MILESTONE_LOC);
    (void)json_push_kv_int(&reply->data, "second_milestone_loc",
                           VCS_ZCODE_C23_SECOND_MILESTONE_LOC);
    (void)json_push_kv_bool(&reply->data, "global_completeness_claimed",
                            status.global_completeness_claimed);
    if (status.blocker[0])
        (void)json_push_kv_str(&reply->data, "blocker", status.blocker);
    (void)json_push_kv_str(&reply->data, "progress_stage",
                           status.progress_stage);
    (void)json_push_kv_str(&reply->data, "next_command",
                           status.next_command);
    (void)json_push_kv_str(&reply->data, "resident_checkpoint",
        resident_ok ? "loaded" : resident_present ? "rejected" : "missing");
    if (resident_ok) {
        uint8_t checkpoint_root[32];
        char checkpoint_root_hex[65];
        if (vcs_zcode_c23_corpus_checkpoint_v1_root(
                &resident, checkpoint_root) == VCS_ZCODE_C23_OK) {
            zcl_hex_encode(checkpoint_root, sizeof(checkpoint_root),
                           checkpoint_root_hex);
            (void)json_push_kv_str(&reply->data, "checkpoint_root",
                                   checkpoint_root_hex);
        }
        (void)json_push_kv_int(&reply->data, "checkpoint_sequence",
                               (int64_t)resident.sequence);
        (void)json_push_kv_int(&reply->data, "checkpoint_cutoff_height",
                               (int64_t)resident.cutoff_height);
        (void)json_push_kv_int(&reply->data, "packages_admitted",
            (int64_t)(resident.total_entries - resident.excluded_entries));
        (void)json_push_kv_int(&reply->data, "packages_excluded",
                               (int64_t)resident.excluded_entries);
    }
    zcl_hotswap_service_release(&lease);
}

static bool lowercase_root(const char *root)
{
    if (!root || strlen(root) != 64) return false;
    for (size_t i = 0; i < 64; i++)
        if (!((root[i] >= '0' && root[i] <= '9') ||
              (root[i] >= 'a' && root[i] <= 'f')))
            return false;
    return true;
}

void zcl_native_handle_zcode_commons_corpus_show(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *root_value =
        request && request->input ? json_get(request->input, "root") : NULL;
    const char *root = json_get_str(root_value);
    if (!request || !reply || !request->input ||
        request->input->type != JSON_OBJ ||
        request->input->num_children != 1 || !lowercase_root(root)) {
        if (reply) corpus_fail(reply, "BAD_CORPUS_SHOW_INPUT",
            "zcode commons corpus show requires one lowercase 64-hex root");
        return;
    }
    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_c23_corpus_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_C23_CORPUS_SERVICE_ID, &lease);
    if (!service) service = zcode_c23_corpus_service_builtin();
    struct zcode_c23_corpus_rules_result_v1 rules;
    if (!service->render_rules(root, &rules)) {
        zcl_hotswap_service_release(&lease);
        corpus_fail(reply, "CORPUS_SERVICE_FAILED",
                    "the pure corpus service refused the exact-root read");
        return;
    }
    (void)json_push_kv_bool(&reply->data, "simulation_only", true);
    (void)json_push_kv_bool(&reply->data, "not_owner_approved", true);
    (void)json_push_kv_bool(&reply->data, "found", rules.found);
    (void)json_push_kv_str(&reply->data, "requested_root", root);
    (void)json_push_kv_str(&reply->data, "root", rules.root);
    (void)json_push_kv_str(&reply->data, "kind", "c23_corpus_rules.v1");
    (void)json_push_kv_str(&reply->data, "service_id",
                           ZCODE_C23_CORPUS_SERVICE_ID);
    (void)json_push_kv_int(&reply->data, "service_generation",
                           zcl_hotswap_service_generation());
    (void)json_push_kv_bool(&reply->data, "global_completeness_claimed",
                            rules.global_completeness_claimed);
    if (rules.found) {
        (void)json_push_kv_str(&reply->data, "counted_extensions",
                               ".c,.h,.def");
        (void)json_push_kv_int(&reply->data, "overlap_threshold_bps",
                               rules.overlap_threshold_bps);
        (void)json_push_kv_int(&reply->data, "shard_entry_max",
                               rules.shard_entry_max);
        (void)json_push_kv_int(&reply->data, "checkpoint_shard_max",
                               rules.checkpoint_shard_max);
        (void)json_push_kv_int(&reply->data, "page_max", rules.page_max);
        (void)json_push_kv_int(&reply->data, "publication_batch_max",
                               rules.publication_batch_max);
        (void)json_push_kv_int(&reply->data, "durable_ack_count",
                               rules.durable_ack_count);
        (void)json_push_kv_int(&reply->data,
                               "durable_operator_group_count",
                               rules.durable_operator_group_count);
        (void)json_push_kv_int(&reply->data, "max_file_bytes",
                               (int64_t)rules.max_file_bytes);
        (void)json_push_kv_int(&reply->data, "first_milestone_loc",
                               (int64_t)rules.first_milestone_loc);
        (void)json_push_kv_int(&reply->data, "second_milestone_loc",
                               (int64_t)rules.second_milestone_loc);
    } else {
        (void)json_push_kv_str(&reply->data, "blocker",
            "the requested root is not the resident frozen C23 corpus rules root");
    }
    zcl_hotswap_service_release(&lease);
}

static void corpus_push_root(struct json_value *out, const char *key,
                             const uint8_t root[32])
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    (void)json_push_kv_str(out, key, hex);
}

static bool corpus_checkpoint_renderable(
    const struct vcs_zcode_c23_corpus_checkpoint_v1 *checkpoint,
    uint64_t *total_loc)
{
    if (!checkpoint || !total_loc ||
        !zcl_u64_add(checkpoint->production_loc, checkpoint->test_loc,
                     total_loc))
        return false;
    const uint64_t values[] = {
        checkpoint->sequence, checkpoint->cutoff_height,
        checkpoint->total_entries, checkpoint->production_loc,
        checkpoint->test_loc, checkpoint->durable_loc,
        checkpoint->physical_lines, checkpoint->unique_semantic_units,
        checkpoint->excluded_entries, *total_loc,
    };
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
        if (values[i] > INT64_MAX) return false;
    return true;
}

static size_t corpus_checkpoint_inline_wire_max(void)
{
    return zcl_command_registry_input_str_max("checkpoint") / 2u;
}

static size_t corpus_shard_inline_wire_max(void)
{
    return zcl_command_registry_input_str_max("shard") / 2u;
}

static size_t corpus_shard_inline_entry_max(void)
{
    size_t wire_max = corpus_shard_inline_wire_max();
    return wire_max > VCS_ZCODE_C23_SHARD_HEADER_WIRE_BYTES
        ? (wire_max - VCS_ZCODE_C23_SHARD_HEADER_WIRE_BYTES) /
              VCS_ZCODE_C23_SHARD_ENTRY_WIRE_BYTES
        : 0;
}

struct corpus_shard_metrics {
    uint64_t counted_entries;
    uint64_t durable_entries;
    uint64_t excluded_entries;
    uint64_t production_loc;
    uint64_t test_loc;
    uint64_t total_loc;
    uint64_t durable_loc;
    uint64_t physical_lines;
    uint64_t unique_semantic_units;
};

static bool corpus_shard_metrics_collect(
    const struct vcs_zcode_c23_corpus_shard_v1 *shard,
    struct corpus_shard_metrics *metrics)
{
    if (!shard || !metrics) return false;
    memset(metrics, 0, sizeof(*metrics));
    for (size_t i = 0; i < shard->entry_count; i++) {
        const struct vcs_zcode_c23_corpus_entry_v1 *entry =
            &shard->entries[i];
        uint64_t entry_loc = 0;
        if (!zcl_u64_add(entry->production_loc, entry->test_loc,
                         &entry_loc) ||
            !zcl_u64_add(metrics->production_loc, entry->production_loc,
                         &metrics->production_loc) ||
            !zcl_u64_add(metrics->test_loc, entry->test_loc,
                         &metrics->test_loc) ||
            !zcl_u64_add(metrics->total_loc, entry_loc,
                         &metrics->total_loc) ||
            !zcl_u64_add(metrics->physical_lines, entry->physical_lines,
                         &metrics->physical_lines) ||
            !zcl_u64_add(metrics->unique_semantic_units,
                         entry->unique_semantic_units,
                         &metrics->unique_semantic_units))
            return false;
        if (entry->flags & VCS_ZCODE_C23_ENTRY_COUNTED)
            metrics->counted_entries++;
        else
            metrics->excluded_entries++;
        if (entry->flags & VCS_ZCODE_C23_ENTRY_DURABLE) {
            metrics->durable_entries++;
            if (!zcl_u64_add(metrics->durable_loc, entry_loc,
                             &metrics->durable_loc))
                return false;
        }
    }
    const uint64_t values[] = {
        (uint64_t)shard->entry_count, metrics->counted_entries,
        metrics->durable_entries, metrics->excluded_entries,
        metrics->production_loc, metrics->test_loc, metrics->total_loc,
        metrics->durable_loc, metrics->physical_lines,
        metrics->unique_semantic_units,
    };
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
        if (values[i] > INT64_MAX) return false;
    return true;
}

static bool corpus_shard_decode_hex(
    const char *hex, struct vcs_zcode_c23_corpus_shard_v1 *shard,
    struct vcs_zcode_c23_corpus_entry_v1 **entries_out,
    struct zcl_command_reply *reply)
{
    size_t hex_len = hex ? strlen(hex) : 0;
    if (!shard || !entries_out || !hex_len || (hex_len & 1u) != 0 ||
        hex_len > corpus_shard_inline_wire_max() * 2u) {
        corpus_fail(reply, "BAD_CORPUS_SHARD_INPUT",
            "shard must be one nonempty lowercase even-length hex wire within the 8192-byte inline bound");
        return false;
    }
    size_t wire_len = hex_len / 2u;
    if (wire_len < VCS_ZCODE_C23_SHARD_HEADER_WIRE_BYTES ||
        (wire_len - VCS_ZCODE_C23_SHARD_HEADER_WIRE_BYTES) %
            VCS_ZCODE_C23_SHARD_ENTRY_WIRE_BYTES != 0) {
        corpus_fail(reply, "BAD_CORPUS_SHARD_INPUT",
                    "shard wire length is not a canonical header plus whole entries");
        return false;
    }
    size_t entry_capacity =
        (wire_len - VCS_ZCODE_C23_SHARD_HEADER_WIRE_BYTES) /
        VCS_ZCODE_C23_SHARD_ENTRY_WIRE_BYTES;
    if (!entry_capacity || entry_capacity > corpus_shard_inline_entry_max()) {
        corpus_fail(reply, "BAD_CORPUS_SHARD_INPUT",
                    "shard must contain between 1 and 28 inline entries");
        return false;
    }
    uint8_t *wire = zcl_malloc(wire_len, "corpus.shard.wire");
    struct vcs_zcode_c23_corpus_entry_v1 *entries = zcl_malloc(
        entry_capacity * sizeof(*entries), "corpus.shard.entries");
    if (!wire || !entries) {
        free(entries);
        free(wire);
        corpus_fail(reply, "CORPUS_SHARD_MEMORY",
                    "bounded shard verification allocation failed");
        return false;
    }
    if (!zcl_hex_decode_lower(hex, wire, wire_len)) {
        free(entries);
        free(wire);
        corpus_fail(reply, "BAD_CORPUS_SHARD_INPUT",
                    "shard must use canonical lowercase hexadecimal");
        return false;
    }
    enum vcs_zcode_c23_error error = vcs_zcode_c23_corpus_shard_v1_decode(
        shard, entries, entry_capacity, wire, wire_len);
    free(wire);
    if (error != VCS_ZCODE_C23_OK) {
        free(entries);
        corpus_fail(reply, "CORPUS_SHARD_INVALID",
                    vcs_zcode_c23_error_string(error));
        return false;
    }
    *entries_out = entries;
    return true;
}

void zcl_native_handle_zcode_commons_corpus_shard_verify(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *value =
        request && request->input ? json_get(request->input, "shard") : NULL;
    const char *hex = json_get_str(value);
    if (!request || !reply || !request->input ||
        request->input->type != JSON_OBJ ||
        request->input->num_children != 1 || !hex) {
        if (reply) corpus_fail(reply, "BAD_CORPUS_SHARD_INPUT",
            "shard must be one nonempty lowercase even-length hex wire within the 8192-byte inline bound");
        return;
    }
    struct vcs_zcode_c23_corpus_shard_v1 shard;
    struct vcs_zcode_c23_corpus_entry_v1 *entries = NULL;
    if (!corpus_shard_decode_hex(hex, &shard, &entries, reply)) return;

    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_c23_corpus_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_C23_CORPUS_SERVICE_ID, &lease);
    if (!service) service = zcode_c23_corpus_service_builtin();
    enum vcs_zcode_c23_error error = service->shard_validate(&shard);
    if (error != VCS_ZCODE_C23_OK) {
        zcl_hotswap_service_release(&lease);
        free(entries);
        corpus_fail(reply, "CORPUS_SHARD_INVALID",
                    vcs_zcode_c23_error_string(error));
        return;
    }

    uint8_t shard_root[32];
    struct corpus_shard_metrics metrics;
    error = vcs_zcode_c23_corpus_shard_v1_root(&shard, shard_root);
    if (error != VCS_ZCODE_C23_OK ||
        !corpus_shard_metrics_collect(&shard, &metrics)) {
        zcl_hotswap_service_release(&lease);
        free(entries);
        corpus_fail(reply, "CORPUS_SHARD_RENDER_RANGE",
                    "verified shard counts exceed the bounded JSON integer renderer");
        return;
    }

    (void)json_push_kv_bool(&reply->data, "verified", true);
    (void)json_push_kv_bool(&reply->data, "simulation_only", true);
    (void)json_push_kv_bool(&reply->data, "not_owner_approved", true);
    (void)json_push_kv_bool(&reply->data, "global_completeness_claimed",
                            false);
    (void)json_push_kv_str(&reply->data, "kind", "c23_corpus_shard.v1");
    (void)json_push_kv_str(&reply->data, "service_id",
                           ZCODE_C23_CORPUS_SERVICE_ID);
    (void)json_push_kv_int(&reply->data, "service_generation",
                           zcl_hotswap_service_generation());
    corpus_push_root(&reply->data, "shard_root", shard_root);
    corpus_push_root(&reply->data, "rules_root", shard.rules_root);
    corpus_push_root(&reply->data, "family_policy_root",
                     shard.family_policy_root);
    corpus_push_root(&reply->data, "moderation_set_root",
                     shard.moderation_set_root);
    (void)json_push_kv_int(&reply->data, "entry_count",
                           (int64_t)shard.entry_count);
    (void)json_push_kv_int(&reply->data, "inline_entry_limit",
                           (int64_t)corpus_shard_inline_entry_max());
    (void)json_push_kv_int(&reply->data, "counted_entries",
                           (int64_t)metrics.counted_entries);
    (void)json_push_kv_int(&reply->data, "durable_entries",
                           (int64_t)metrics.durable_entries);
    (void)json_push_kv_int(&reply->data, "excluded_entries",
                           (int64_t)metrics.excluded_entries);
    (void)json_push_kv_int(&reply->data, "production_loc",
                           (int64_t)metrics.production_loc);
    (void)json_push_kv_int(&reply->data, "test_loc",
                           (int64_t)metrics.test_loc);
    (void)json_push_kv_int(&reply->data, "total_loc",
                           (int64_t)metrics.total_loc);
    (void)json_push_kv_int(&reply->data, "durably_hosted_loc",
                           (int64_t)metrics.durable_loc);
    (void)json_push_kv_int(&reply->data, "physical_lines",
                           (int64_t)metrics.physical_lines);
    (void)json_push_kv_int(&reply->data, "unique_semantic_units",
                           (int64_t)metrics.unique_semantic_units);
    zcl_hotswap_service_release(&lease);
    free(entries);
}

static bool corpus_shard_entry_json_range(
    const struct vcs_zcode_c23_corpus_entry_v1 *entry)
{
    return entry && entry->release_sequence <= INT64_MAX &&
           entry->production_loc <= INT64_MAX && entry->test_loc <= INT64_MAX &&
           entry->physical_lines <= INT64_MAX &&
           entry->unique_semantic_units <= INT64_MAX;
}

static void corpus_shard_entry_push_json(
    struct json_value *rows,
    const struct vcs_zcode_c23_corpus_entry_v1 *entry)
{
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    corpus_push_root(&row, "semantic_lineage_root",
                     entry->semantic_lineage_root);
    corpus_push_root(&row, "release_root", entry->release_root);
    corpus_push_root(&row, "passport_root", entry->passport_root);
    corpus_push_root(&row, "proof_root", entry->proof_root);
    corpus_push_root(&row, "source_assignment_root",
                     entry->source_assignment_root);
    corpus_push_root(&row, "admission_root", entry->admission_root);
    corpus_push_root(&row, "possession_root", entry->possession_root);
    (void)json_push_kv_int(&row, "release_sequence",
                           (int64_t)entry->release_sequence);
    (void)json_push_kv_int(&row, "production_loc",
                           (int64_t)entry->production_loc);
    (void)json_push_kv_int(&row, "test_loc", (int64_t)entry->test_loc);
    (void)json_push_kv_int(&row, "physical_lines",
                           (int64_t)entry->physical_lines);
    (void)json_push_kv_int(&row, "unique_semantic_units",
                           (int64_t)entry->unique_semantic_units);
    char evidence[19];
    (void)snprintf(evidence, sizeof(evidence), "0x%016" PRIx64,
                   entry->evidence_mask);
    (void)json_push_kv_str(&row, "evidence_mask", evidence);
    (void)json_push_kv_int(&row, "exclusion_mask",
                           (int64_t)entry->exclusion_mask);
    (void)json_push_kv_int(&row, "flags", (int64_t)entry->flags);
    (void)json_push_back(rows, &row);
    json_free(&row);
}

void zcl_native_handle_zcode_commons_corpus_shard_page(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *input = request ? request->input : NULL;
    const struct json_value *shard_value = input ? json_get(input, "shard") : NULL;
    const struct json_value *cursor_value = input ? json_get(input, "cursor") : NULL;
    const struct json_value *limit_value = input ? json_get(input, "limit") : NULL;
    size_t known_keys = 1u + (cursor_value ? 1u : 0u) +
                        (limit_value ? 1u : 0u);
    const char *hex = json_get_str(shard_value);
    int64_t limit = limit_value ? json_get_int(limit_value) :
                                  (int64_t)VCS_ZCODE_C23_PAGE_MAX;
    if (!request || !reply || !input || input->type != JSON_OBJ || !hex ||
        input->num_children != known_keys ||
        (limit_value && limit_value->type != JSON_INT) || limit < 1 ||
        limit > VCS_ZCODE_C23_PAGE_MAX) {
        if (reply) corpus_fail(reply, "BAD_CORPUS_SHARD_PAGE_INPUT",
            "shard is required; cursor must be a 68-character lowercase root cursor and limit must be 1..256");
        return;
    }

    struct vcs_zcode_c23_page_cursor_v1 cursor;
    const struct vcs_zcode_c23_page_cursor_v1 *cursor_ptr = NULL;
    if (cursor_value) {
        const char *cursor_hex = json_get_str(cursor_value);
        uint8_t cursor_wire[34];
        if (!cursor_hex || strlen(cursor_hex) != sizeof(cursor_wire) * 2u ||
            !zcl_hex_decode_lower(cursor_hex, cursor_wire,
                                  sizeof(cursor_wire))) {
            corpus_fail(reply, "BAD_CORPUS_SHARD_PAGE_INPUT",
                        "cursor must be exactly 68 lowercase hexadecimal characters");
            return;
        }
        memcpy(cursor.shard_root, cursor_wire, 32);
        cursor.next_index = zcl_read_u16_le(cursor_wire + 32);
        cursor_ptr = &cursor;
    }

    struct vcs_zcode_c23_corpus_shard_v1 shard;
    struct vcs_zcode_c23_corpus_entry_v1 *entries = NULL;
    if (!corpus_shard_decode_hex(hex, &shard, &entries, reply)) return;

    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_c23_corpus_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_C23_CORPUS_SERVICE_ID, &lease);
    if (!service) service = zcode_c23_corpus_service_builtin();
    size_t first = 0, count = 0;
    struct vcs_zcode_c23_page_cursor_v1 next;
    bool has_more = false;
    enum vcs_zcode_c23_error error = service->shard_page(
        &shard, cursor_ptr, (size_t)limit, &first, &count, &next, &has_more);
    if (error != VCS_ZCODE_C23_OK) {
        zcl_hotswap_service_release(&lease);
        free(entries);
        corpus_fail(reply,
                    error == VCS_ZCODE_C23_CURSOR
                        ? "CORPUS_SHARD_CURSOR_INVALID"
                        : "CORPUS_SHARD_INVALID",
                    vcs_zcode_c23_error_string(error));
        return;
    }
    for (size_t i = first; i < first + count; i++) {
        if (!corpus_shard_entry_json_range(&shard.entries[i])) {
            zcl_hotswap_service_release(&lease);
            free(entries);
            corpus_fail(reply, "CORPUS_SHARD_RENDER_RANGE",
                        "page entry exceeds the bounded JSON integer renderer");
            return;
        }
    }
    uint8_t shard_root[32];
    error = vcs_zcode_c23_corpus_shard_v1_root(&shard, shard_root);
    if (error != VCS_ZCODE_C23_OK) {
        zcl_hotswap_service_release(&lease);
        free(entries);
        corpus_fail(reply, "CORPUS_SHARD_INVALID",
                    vcs_zcode_c23_error_string(error));
        return;
    }

    (void)json_push_kv_bool(&reply->data, "verified", true);
    (void)json_push_kv_bool(&reply->data, "simulation_only", true);
    (void)json_push_kv_bool(&reply->data, "not_owner_approved", true);
    (void)json_push_kv_bool(&reply->data, "global_completeness_claimed",
                            false);
    (void)json_push_kv_str(&reply->data, "kind", "c23_corpus_shard.page.v1");
    (void)json_push_kv_str(&reply->data, "service_id",
                           ZCODE_C23_CORPUS_SERVICE_ID);
    (void)json_push_kv_int(&reply->data, "service_generation",
                           zcl_hotswap_service_generation());
    corpus_push_root(&reply->data, "shard_root", shard_root);
    (void)json_push_kv_int(&reply->data, "first_index", (int64_t)first);
    (void)json_push_kv_int(&reply->data, "item_count", (int64_t)count);
    (void)json_push_kv_int(&reply->data, "limit", limit);
    (void)json_push_kv_int(&reply->data, "page_limit",
                           VCS_ZCODE_C23_PAGE_MAX);
    (void)json_push_kv_bool(&reply->data, "has_more", has_more);
    char next_hex[69] = {0};
    if (has_more) {
        uint8_t next_wire[34];
        memcpy(next_wire, next.shard_root, 32);
        zcl_write_u16_le(next_wire + 32, next.next_index);
        zcl_hex_encode(next_wire, sizeof(next_wire), next_hex);
    }
    (void)json_push_kv_str(&reply->data, "next_cursor", next_hex);
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = first; i < first + count; i++)
        corpus_shard_entry_push_json(&rows, &shard.entries[i]);
    (void)json_push_kv(&reply->data, "entries", &rows);
    json_free(&rows);
    zcl_hotswap_service_release(&lease);
    free(entries);
}

static size_t corpus_checkpoint_inline_shard_max(void)
{
    size_t wire_max = corpus_checkpoint_inline_wire_max();
    return wire_max > VCS_ZCODE_C23_CHECKPOINT_HEADER_WIRE_BYTES
        ? (wire_max - VCS_ZCODE_C23_CHECKPOINT_HEADER_WIRE_BYTES) /
              VCS_ZCODE_C23_CHECKPOINT_BINDING_WIRE_BYTES
        : 0;
}

void zcl_native_handle_zcode_commons_corpus_verify(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *value =
        request && request->input ? json_get(request->input, "checkpoint")
                                  : NULL;
    const char *hex = json_get_str(value);
    size_t hex_len = hex ? strlen(hex) : 0;
    if (!request || !reply || !request->input ||
        request->input->type != JSON_OBJ ||
        request->input->num_children != 1 || !hex_len ||
        (hex_len & 1u) != 0 ||
        hex_len > corpus_checkpoint_inline_wire_max() * 2u) {
        if (reply) corpus_fail(reply, "BAD_CORPUS_CHECKPOINT_INPUT",
            "checkpoint must be one nonempty lowercase even-length hex wire within the 8192-byte inline bound");
        return;
    }

    size_t wire_len = hex_len / 2u;
    if (wire_len < VCS_ZCODE_C23_CHECKPOINT_HEADER_WIRE_BYTES ||
        (wire_len - VCS_ZCODE_C23_CHECKPOINT_HEADER_WIRE_BYTES) %
            VCS_ZCODE_C23_CHECKPOINT_BINDING_WIRE_BYTES != 0) {
        corpus_fail(reply, "BAD_CORPUS_CHECKPOINT_INPUT",
                    "checkpoint wire length is not a canonical header plus whole shard bindings");
        return;
    }
    size_t shard_capacity =
        (wire_len - VCS_ZCODE_C23_CHECKPOINT_HEADER_WIRE_BYTES) /
        VCS_ZCODE_C23_CHECKPOINT_BINDING_WIRE_BYTES;
    if (!shard_capacity ||
        shard_capacity > corpus_checkpoint_inline_shard_max()) {
        corpus_fail(reply, "BAD_CORPUS_CHECKPOINT_INPUT",
                    "checkpoint must contain between 1 and 54 inline shard bindings");
        return;
    }

    uint8_t *wire = zcl_malloc(wire_len, "corpus.checkpoint.wire");
    struct vcs_zcode_c23_checkpoint_shard_v1 *shards = zcl_malloc(
        shard_capacity * sizeof(*shards), "corpus.checkpoint.shards");
    if (!wire || !shards) {
        free(shards);
        free(wire);
        corpus_fail(reply, "CORPUS_CHECKPOINT_MEMORY",
                    "bounded checkpoint verification allocation failed");
        return;
    }
    if (!zcl_hex_decode_lower(hex, wire, wire_len)) {
        free(shards);
        free(wire);
        corpus_fail(reply, "BAD_CORPUS_CHECKPOINT_INPUT",
                    "checkpoint must use canonical lowercase hexadecimal");
        return;
    }

    struct vcs_zcode_c23_corpus_checkpoint_v1 checkpoint;
    enum vcs_zcode_c23_error error =
        vcs_zcode_c23_corpus_checkpoint_v1_decode(
            &checkpoint, shards, shard_capacity, wire, wire_len);
    free(wire);
    if (error != VCS_ZCODE_C23_OK) {
        free(shards);
        corpus_fail(reply, "CORPUS_CHECKPOINT_INVALID",
                    vcs_zcode_c23_error_string(error));
        return;
    }

    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_c23_corpus_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_C23_CORPUS_SERVICE_ID, &lease);
    if (!service) service = zcode_c23_corpus_service_builtin();
    error = service->checkpoint_validate(&checkpoint);
    if (error != VCS_ZCODE_C23_OK) {
        zcl_hotswap_service_release(&lease);
        free(shards);
        corpus_fail(reply, "CORPUS_CHECKPOINT_INVALID",
                    vcs_zcode_c23_error_string(error));
        return;
    }

    uint8_t checkpoint_root[32];
    uint64_t total_loc = 0;
    error = vcs_zcode_c23_corpus_checkpoint_v1_root(
        &checkpoint, checkpoint_root);
    if (error != VCS_ZCODE_C23_OK ||
        !corpus_checkpoint_renderable(&checkpoint, &total_loc)) {
        zcl_hotswap_service_release(&lease);
        free(shards);
        corpus_fail(reply, "CORPUS_CHECKPOINT_RENDER_RANGE",
                    "verified checkpoint counts exceed the bounded JSON integer renderer");
        return;
    }

    (void)json_push_kv_bool(&reply->data, "verified", true);
    (void)json_push_kv_bool(&reply->data, "simulation_only", true);
    (void)json_push_kv_bool(&reply->data, "not_owner_approved", true);
    (void)json_push_kv_bool(&reply->data, "global_completeness_claimed",
                            false);
    (void)json_push_kv_str(&reply->data, "kind",
                           "c23_corpus_checkpoint.v1");
    (void)json_push_kv_str(&reply->data, "service_id",
                           ZCODE_C23_CORPUS_SERVICE_ID);
    (void)json_push_kv_int(&reply->data, "service_generation",
                           zcl_hotswap_service_generation());
    corpus_push_root(&reply->data, "checkpoint_root", checkpoint_root);
    corpus_push_root(&reply->data, "rules_root", checkpoint.rules_root);
    corpus_push_root(&reply->data, "family_policy_root",
                     checkpoint.family_policy_root);
    corpus_push_root(&reply->data, "moderation_set_root",
                     checkpoint.moderation_set_root);
    corpus_push_root(&reply->data, "replication_evidence_root",
                     checkpoint.replication_evidence_root);
    corpus_push_root(&reply->data, "signer_pubkey", checkpoint.signer_pubkey);
    (void)json_push_kv_int(&reply->data, "sequence",
                           (int64_t)checkpoint.sequence);
    (void)json_push_kv_int(&reply->data, "cutoff_height",
                           (int64_t)checkpoint.cutoff_height);
    (void)json_push_kv_int(&reply->data, "cutoff_mtp",
                           checkpoint.cutoff_mtp);
    (void)json_push_kv_int(&reply->data, "milestone", checkpoint.milestone);
    (void)json_push_kv_int(&reply->data, "shard_count",
                           (int64_t)checkpoint.shard_count);
    (void)json_push_kv_int(&reply->data, "inline_shard_limit",
                           (int64_t)corpus_checkpoint_inline_shard_max());
    (void)json_push_kv_int(&reply->data, "total_entries",
                           (int64_t)checkpoint.total_entries);
    (void)json_push_kv_int(&reply->data, "production_loc",
                           (int64_t)checkpoint.production_loc);
    (void)json_push_kv_int(&reply->data, "test_loc",
                           (int64_t)checkpoint.test_loc);
    (void)json_push_kv_int(&reply->data, "total_loc", (int64_t)total_loc);
    (void)json_push_kv_int(&reply->data, "durably_hosted_loc",
                           (int64_t)checkpoint.durable_loc);
    (void)json_push_kv_int(&reply->data, "physical_lines",
                           (int64_t)checkpoint.physical_lines);
    (void)json_push_kv_int(&reply->data, "unique_semantic_units",
                           (int64_t)checkpoint.unique_semantic_units);
    (void)json_push_kv_int(&reply->data, "excluded_entries",
                           (int64_t)checkpoint.excluded_entries);
    zcl_hotswap_service_release(&lease);
    free(shards);
}

static bool render_impact_unshareable(struct json_value *data)
{
    const struct zcode_c23_impact_readiness_input_v1 input = {0};
    struct zcode_c23_impact_readiness_result_v1 view;
    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_c23_corpus_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_C23_CORPUS_SERVICE_ID, &lease);
    if (!service) service = zcode_c23_corpus_service_builtin();
    bool rendered = service->render_impact_readiness(&input, &view) &&
        view.valid && !view.shareable;
    zcl_hotswap_service_release(&lease);
    if (!rendered) return false;
    (void)json_push_kv_bool(data, "simulation_only", true);
    (void)json_push_kv_bool(data, "shareable", view.shareable);
    (void)json_push_kv_bool(data, "posted_externally", false);
    (void)json_push_kv_str(data, "required_chain",
        "PROVEN work -> human acceptance -> signed release -> independent Family admission -> complete retrievable package");
    (void)json_push_kv_str(data, "impact_readiness", view.readiness);
    (void)json_push_kv_str(data, "blocker", view.reason);
    (void)json_push_kv_str(data, "next_command", view.next_command);
    return true;
}

void zcl_native_handle_zcode_commons_impact_verify(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *value =
        request && request->input ? json_get(request->input, "receipt") : NULL;
    const char *hex = json_get_str(value);
    uint8_t wire[VCS_ZCODE_PRODUCTIVITY_RECEIPT_WIRE_BYTES];
    if (!request || !reply || !request->input ||
        request->input->type != JSON_OBJ ||
        request->input->num_children != 1 || !hex ||
        strlen(hex) != sizeof(wire) * 2u ||
        !zcl_hex_decode_lower(hex, wire, sizeof(wire))) {
        if (reply) corpus_fail(reply, "BAD_PRODUCTIVITY_RECEIPT_INPUT",
            "receipt must be exactly one canonical lowercase 648-hex productivity_receipt.v1 wire");
        return;
    }

    struct vcs_zcode_productivity_receipt_v1 receipt;
    enum vcs_zcode_c23_error error =
        vcs_zcode_productivity_receipt_v1_decode(
            &receipt, wire, sizeof(wire));
    if (error != VCS_ZCODE_C23_OK) {
        corpus_fail(reply, "PRODUCTIVITY_RECEIPT_INVALID",
                    vcs_zcode_c23_error_string(error));
        return;
    }

    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_c23_corpus_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_C23_CORPUS_SERVICE_ID, &lease);
    if (!service) service = zcode_c23_corpus_service_builtin();
    error = service->productivity_validate(&receipt);
    if (error != VCS_ZCODE_C23_OK) {
        zcl_hotswap_service_release(&lease);
        corpus_fail(reply, "PRODUCTIVITY_RECEIPT_INVALID",
                    vcs_zcode_c23_error_string(error));
        return;
    }

    uint8_t receipt_root[32];
    error = vcs_zcode_productivity_receipt_v1_root(&receipt, receipt_root);
    if (error != VCS_ZCODE_C23_OK || receipt.completed_height > INT64_MAX) {
        zcl_hotswap_service_release(&lease);
        corpus_fail(reply, "PRODUCTIVITY_RECEIPT_RENDER_RANGE",
                    "verified receipt values exceed the bounded JSON integer renderer");
        return;
    }

    (void)json_push_kv_bool(&reply->data, "structurally_verified", true);
    (void)json_push_kv_bool(&reply->data, "simulation_only", true);
    (void)json_push_kv_bool(&reply->data, "not_owner_approved", true);
    (void)json_push_kv_str(&reply->data, "kind",
                           "productivity_receipt.v1");
    (void)json_push_kv_str(&reply->data, "service_id",
                           ZCODE_C23_CORPUS_SERVICE_ID);
    (void)json_push_kv_int(&reply->data, "service_generation",
                           zcl_hotswap_service_generation());
    corpus_push_root(&reply->data, "receipt_root", receipt_root);
    corpus_push_root(&reply->data, "work_root", receipt.work_root);
    corpus_push_root(&reply->data, "acceptance_root", receipt.acceptance_root);
    corpus_push_root(&reply->data, "release_root", receipt.release_root);
    corpus_push_root(&reply->data, "admission_root", receipt.admission_root);
    corpus_push_root(&reply->data, "package_root", receipt.package_root);
    corpus_push_root(&reply->data, "checkpoint_root", receipt.checkpoint_root);
    corpus_push_root(&reply->data, "signer_pubkey", receipt.signer_pubkey);
    (void)json_push_kv_int(&reply->data, "completed_height",
                           (int64_t)receipt.completed_height);
    (void)json_push_kv_int(&reply->data, "completed_mtp",
                           receipt.completed_mtp);
    (void)json_push_kv_bool(&reply->data, "proven_work_present", true);
    (void)json_push_kv_bool(&reply->data, "human_acceptance_present", true);
    (void)json_push_kv_bool(&reply->data, "signed_release_present", true);
    (void)json_push_kv_bool(&reply->data, "family_admission_present", true);
    (void)json_push_kv_bool(&reply->data, "package_reference_present", true);
    (void)json_push_kv_bool(&reply->data, "external_chain_proof_present",
                            false);
    (void)json_push_kv_bool(&reply->data, "shareable", false);
    (void)json_push_kv_bool(&reply->data, "slogan_emitted", false);
    (void)json_push_kv_bool(&reply->data, "posted_externally", false);
    (void)json_push_kv_str(&reply->data, "required_chain",
        "PROVEN work -> human acceptance -> signed release -> independent Family admission -> complete retrievable package");
    (void)json_push_kv_str(&reply->data, "blocker",
        "structural receipt verification is not independent current chain proof");
    zcl_hotswap_service_release(&lease);
}

void zcl_native_handle_zcode_commons_impact_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply || !corpus_no_keys(request->input)) {
        if (reply) corpus_fail(reply, "BAD_IMPACT_STATUS_INPUT",
            "zcode commons impact status accepts no input keys");
        return;
    }
    if (!render_impact_unshareable(&reply->data))
        corpus_fail(reply, "IMPACT_SERVICE_FAILED",
                    "the pure corpus service refused impact readiness facts");
}

void zcl_native_handle_zcode_commons_impact_share(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply || !corpus_no_keys(request->input)) {
        if (reply) corpus_fail(reply, "BAD_IMPACT_SHARE_INPUT",
            "zcode commons impact share accepts no input keys");
        return;
    }
    if (!render_impact_unshareable(&reply->data)) {
        corpus_fail(reply, "IMPACT_SERVICE_FAILED",
                    "the pure corpus service refused impact readiness facts");
        return;
    }
    (void)json_push_kv_bool(&reply->data, "slogan_emitted", false);
}
