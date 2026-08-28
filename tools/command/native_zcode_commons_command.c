/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: read-only native views of the ZC23 Living Commons projection. */

#include "command/native_command.h"

#include "base/checked.h"
#include "base/hex.h"
#include "config/c23_commons_build_profile.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "vcs/build_action.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_commons_projection.h"
#include "vcs/zcode_creation_attribution.h"
#include "vcs/zcode_reproduction_qualification.h"
#include "vcs/zcode_score_receipt.h"

#include <stdlib.h>
#include <string.h>

struct zcc_shadow_package {
    const char *name;
    const char *content_root_hex;
    const char *release_root_hex;
};

#define ZCODE_PACKAGE(name, dir, sequence, content, release, recipe, lock, capsule, publisher, signature) \
    {name, content, release},
static const struct zcc_shadow_package zcc_shadow_packages[] = {
#include "../../config/zcode_package_registry.def"
};
#undef ZCODE_PACKAGE

static const char *zcc_str(const struct json_value *input, const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool zcc_keys(const struct json_value *input,
                     const char *const *allowed, size_t count)
{
    if (!input || input->type != JSON_OBJ) return false;
    for (size_t i = 0; i < input->num_children; i++) {
        bool known = false;
        for (size_t j = 0; j < count; j++)
            known = known || strcmp(input->keys[i], allowed[j]) == 0;
        if (!known) return false;
    }
    return true;
}

static bool zcc_segment_contains(const char *segment, size_t segment_len,
                                 const char *needle, size_t needle_len)
{
    if (!segment || !needle || needle_len == 0 || needle_len > segment_len)
        return false;
    for (size_t i = 0; i + needle_len <= segment_len; i++)
        if (memcmp(segment + i, needle, needle_len) == 0) return true;
    return false;
}

static bool zcc_workspace_is_lexical_scratch(const char *workspace)
{
    if (!workspace || workspace[0] == '\0' || workspace[0] == '~')
        return false;
    size_t len = strlen(workspace);
    if (len > 4096 || strcmp(workspace, "/") == 0 ||
        strcmp(workspace, "\\") == 0 ||
        strcmp(workspace, ".") == 0 || strcmp(workspace, "./") == 0 ||
        strcmp(workspace, ".\\") == 0 || strcmp(workspace, "..") == 0)
        return false;

    size_t pos = 0;
    if (workspace[0] == '/' || workspace[0] == '\\') pos = 1;
    else if (workspace[0] == '.' &&
             (workspace[1] == '/' || workspace[1] == '\\')) pos = 2;
#if defined(_WIN32)
    else if (((workspace[0] >= 'A' && workspace[0] <= 'Z') ||
              (workspace[0] >= 'a' && workspace[0] <= 'z')) &&
             workspace[1] == ':' &&
             (workspace[2] == '/' || workspace[2] == '\\')) pos = 3;
#endif
    bool scratch_named = false;
    while (pos < len) {
        size_t start = pos;
        while (pos < len && workspace[pos] != '/' && workspace[pos] != '\\') {
            unsigned char ch = (unsigned char)workspace[pos];
            if (ch < 0x20 || ch == 0x7f || ch == ':') return false;
            pos++;
        }
        size_t segment_len = pos - start;
        if (segment_len == 0 ||
            (segment_len == 1 && workspace[start] == '.') ||
            (segment_len == 2 && workspace[start] == '.' &&
             workspace[start + 1] == '.'))
            return false;
        if (segment_len >= 9 &&
            memcmp(workspace + start, ".zclassic", 9) == 0)
            return false;
        if ((segment_len == 3 &&
             memcmp(workspace + start, "tmp", 3) == 0) ||
            (segment_len == 8 &&
             memcmp(workspace + start, "test-tmp", 8) == 0) ||
            zcc_segment_contains(workspace + start, segment_len,
                                 "scratch", 7))
            scratch_named = true;
        if (pos < len) pos++;
    }
    return scratch_named && workspace[len - 1] != '/' &&
           workspace[len - 1] != '\\';
}

bool zcl_native_zcode_workspace_is_explicit_scratch(const char *workspace)
{
    if (!zcc_workspace_is_lexical_scratch(workspace)) return false;
    char resolved[4097];
    if (platform_directory_canonical_real(workspace, resolved,
                                          sizeof(resolved)) &&
        !zcc_workspace_is_lexical_scratch(resolved))
        return false;
    return true;
}

static void zcc_fail(struct zcl_command_reply *reply, const char *code,
                     const char *detail)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "validate", false,
                           false, detail, "zcode.commons");
}

static void zcc_hex(struct json_value *data, const char *key,
                    const uint8_t root[32])
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    (void)json_push_kv_str(data, key, hex);
}

static bool zcc_root(const struct json_value *input, const char *key,
                     uint8_t root[32])
{
    const char *hex = zcc_str(input, key);
    return hex && strlen(hex) == 64 && zcl_hex_decode_lower(hex, root, 32);
}

void zcl_native_handle_zcode_guide(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply || !zcc_keys(request->input, NULL, 0)) {
        zcc_fail(reply, "BAD_ZCODE_GUIDE_INPUT",
                 "zcode guide accepts no input keys");
        return;
    }
    bool ok = json_push_kv_str(
            &reply->data, "mission",
            "Tell Z23 what you want C23 software on this device to do.") &&
        json_push_kv_str(&reply->data, "next_action",
                         "Describe the behavior you want.") &&
        json_push_kv_str(
            &reply->data, "start_command",
            "z23 zcode work start . \"<desired behavior>\"") &&
        json_push_kv_str(
            &reply->data, "journey",
            "reuse C23 -> create only missing code -> build and test -> show "
            "behavior -> reproduce -> accept exact version -> fetch and use") &&
        json_push_kv_str(
            &reply->data, "continue_rule",
            "Follow the next_safe_command returned by each work step.") &&
        json_push_kv_str(
            &reply->data, "proof_view",
            "Add details=true only when you want exact roots and receipts.");
    if (!ok)
        zcc_fail(reply, "ZCODE_GUIDE_OUTPUT",
                 "the reuse-first guide could not be rendered");
}

static const char *zcc_status_name(
    enum vcs_zcode_commons_verification_status status)
{
    switch (status) {
    case VCS_ZCODE_COMMONS_PARTIAL: return "partial";
    case VCS_ZCODE_COMMONS_COMPLETE: return "complete";
    default: return "unknown";
    }
}

static const char *zcc_category_name(uint16_t category)
{
    switch (category) {
    case VCS_ZCODE_CREATION_PUBLIC_SOURCE: return "public_source";
    case VCS_ZCODE_CREATION_BORN_RED_FIX: return "born_red_fix";
    case VCS_ZCODE_CREATION_SECURITY_FIX: return "security_fix";
    case VCS_ZCODE_CREATION_INDEPENDENT_REPRODUCTION:
        return "independent_reproduction";
    case VCS_ZCODE_CREATION_COMPATIBILITY: return "compatibility";
    case VCS_ZCODE_CREATION_PRESERVATION: return "preservation";
    default: return "invalid";
    }
}

static size_t zcc_unique_packages(
    const struct vcs_zcode_commons_projection *projection, bool releases)
{
    size_t unique = 0;
    size_t count = vcs_zcode_commons_projection_creation_count(projection);
    for (size_t i = 0; i < count; i++) {
        const struct vcs_zcode_commons_creation_entry *entry =
            vcs_zcode_commons_projection_creation_at(projection, i);
        const uint8_t *root = releases ? entry->release_root
                                       : entry->package_root;
        bool seen = false;
        for (size_t j = 0; j < i; j++) {
            const struct vcs_zcode_commons_creation_entry *prior =
                vcs_zcode_commons_projection_creation_at(projection, j);
            const uint8_t *prior_root = releases ? prior->release_root
                                                 : prior->package_root;
            seen = seen || memcmp(root, prior_root, 32) == 0;
        }
        if (!seen) unique++;
    }
    return unique;
}

static void zcc_render_summary(
    struct json_value *data,
    const struct vcs_zcode_commons_projection *projection,
    bool anchors_complete)
{
    enum vcs_zcode_commons_verification_status status =
        vcs_zcode_commons_projection_status(projection);
    /* Anchors verified only ever upgrades; a structural failure can never be
     * papered over because the caller refuses to set anchors_complete then. */
    if (anchors_complete)
        status = VCS_ZCODE_COMMONS_COMPLETE;
    uint64_t attributed =
        vcs_zcode_commons_projection_attributed_atoms(projection);
    uint64_t minted = vcs_zcode_commons_projection_minted_atoms(projection);
    uint64_t unattributed = minted >= attributed ? minted - attributed : 0;
    (void)json_push_kv_str(data, "verification_status",
                           zcc_status_name(status));
    (void)json_push_kv_bool(data, "policy_valid_minted_supply_known",
                            status == VCS_ZCODE_COMMONS_COMPLETE);
    (void)json_push_kv_int(data, "policy_valid_minted_supply_atoms",
                           status == VCS_ZCODE_COMMONS_COMPLETE
                               ? (int64_t)minted : 0);
    (void)json_push_kv_int(data, "parsed_mint_atoms", (int64_t)minted);
    (void)json_push_kv_int(data, "attributed_atoms", (int64_t)attributed);
    (void)json_push_kv_int(data, "unattributed_atoms",
                           (int64_t)unattributed);
    (void)json_push_kv_bool(data, "attributed_exceeds_mint",
                            attributed > minted);
    (void)json_push_kv_int(data, "unissued_atoms",
        (int64_t)vcs_zcode_commons_projection_unissued_atoms(projection));
    size_t creations =
        vcs_zcode_commons_projection_creation_count(projection);
    (void)json_push_kv_int(data, "creation_objects", (int64_t)creations);
    (void)json_push_kv_int(data, "epoch_objects",
        (int64_t)vcs_zcode_commons_projection_epoch_count(projection));
    (void)json_push_kv_int(data, "package_count",
                           (int64_t)zcc_unique_packages(projection, false));
    (void)json_push_kv_int(data, "release_count",
                           (int64_t)zcc_unique_packages(projection, true));
    uint64_t categories[7] = {0};
    for (size_t i = 0; i < creations; i++) {
        uint16_t category =
            vcs_zcode_commons_projection_creation_at(projection, i)->category;
        if (category < 7) categories[category]++;
    }
    (void)json_push_kv_int(data, "born_red_defect_tests",
                           (int64_t)categories[VCS_ZCODE_CREATION_BORN_RED_FIX]);
    (void)json_push_kv_int(data, "independent_reproductions",
        (int64_t)categories[VCS_ZCODE_CREATION_INDEPENDENT_REPRODUCTION]);
    (void)json_push_kv_int(data, "security_fixes",
        (int64_t)categories[VCS_ZCODE_CREATION_SECURITY_FIX]);
    (void)json_push_kv_int(data, "compatibility_events",
        (int64_t)categories[VCS_ZCODE_CREATION_COMPATIBILITY]);
    uint8_t failed[32]; const char *reason = NULL;
    bool has_failure = vcs_zcode_commons_projection_first_failure(
        projection, failed, &reason);
    (void)json_push_kv_bool(data, "structural_integrity", !has_failure);
    if (has_failure) {
        zcc_hex(data, "first_failure_root", failed);
        (void)json_push_kv_str(data, "first_failure", reason);
        (void)json_push_kv_str(data, "next_safe_diagnostic_action",
                               "inspect first_failure_root in workspace CAS");
    } else if (creations == 0) {
        (void)json_push_kv_str(data, "next_safe_diagnostic_action",
                               "publish canonical creation evidence to CAS");
    } else {
        (void)json_push_kv_str(data, "next_safe_diagnostic_action",
            "supply immutable policy and active-chain anchor context");
    }
}

static struct vcs_zcode_commons_projection *zcc_build(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    const char *const *keys, size_t key_count)
{
    const char *workspace = request ? zcc_str(request->input, "workspace")
                                    : NULL;
    if (!request || !reply || !workspace ||
        !zcc_keys(request->input, keys, key_count)) {
        zcc_fail(reply, "BAD_COMMONS_INPUT",
                 "closed input requires an explicit workspace");
        return NULL;
    }
    if (!zcl_native_zcode_workspace_is_explicit_scratch(workspace)) {
        zcc_fail(reply, "UNSAFE_COMMONS_WORKSPACE",
                 "workspace must explicitly name an isolated tmp, test-tmp, or scratch path");
        return NULL;
    }
    struct vcs_zcode_commons_projection *projection =
        vcs_zcode_commons_projection_build(workspace);
    if (!projection)
        zcc_fail(reply, "COMMONS_REBUILD_FAILED",
                 "read-only CAS projection rebuild failed");
    return projection;
}

void zcl_native_handle_zcode_commons_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    /* The anchor/policy pins are optional but all-or-nothing: supplied in
     * full, every indexed creation attribution is re-verified under them and
     * the status can report complete; absent or partial, a NAMED blocker is
     * reported — never a silent unknown. */
    static const char *const keys[] = {
        "workspace", "expected_network_genesis_root",
        "expected_zc23_policy_root", "expected_epoch", "expected_award_atoms",
        "active_height", "active_mtp", "anchor_opening_height",
        "anchor_opening_hash", "anchor_maturity_height",
        "anchor_maturity_hash", "now_unix",
    };
    struct vcs_zcode_commons_projection *projection =
        zcc_build(request, reply, keys, 12);
    if (!projection) return;
    struct zcl_native_zcode_anchor_report report;
    bool answered = zcl_native_zcode_anchor_verify_commons(request->input,
                                                           &report);
    uint8_t failed[32]; const char *reason = NULL;
    bool structural_failure = vcs_zcode_commons_projection_first_failure(
        projection, failed, &reason);
    bool complete = answered && report.context_bound && report.verified &&
                    !structural_failure;
    zcc_render_summary(&reply->data, projection, complete);
    (void)json_push_kv_bool(&reply->data, "anchor_context_bound",
                            answered && report.context_bound);
    (void)json_push_kv_int(&reply->data, "anchor_verified_attributions",
                           report.attributions_checked);
    if (!complete) {
        const char *blocker =
            report.context_blocker[0] ? report.context_blocker
            : report.first_failure[0] ? report.first_failure
            : "commons_projection_incomplete";
        (void)json_push_kv_str(&reply->data, "verification_blocker", blocker);
        if (report.first_failure[0])
            zcc_hex(&reply->data, "anchor_first_failure_root",
                    report.first_failure_root);
    }
    vcs_zcode_commons_projection_free(projection);
}

void zcl_native_handle_zcode_commons_rebuild(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    static const char *const keys[] = {"workspace"};
    struct vcs_zcode_commons_projection *projection =
        zcc_build(request, reply, keys, 1);
    if (!projection) return;
    uint8_t root[32];
    zcc_render_summary(&reply->data, projection, false);
    if (vcs_zcode_commons_projection_root(projection, root))
        zcc_hex(&reply->data, "projection_root", root);
    (void)json_push_kv_bool(&reply->data, "persisted", false);
    (void)json_push_kv_str(&reply->data, "authority", "canonical_workspace_cas");
    vcs_zcode_commons_projection_free(projection);
}

static const struct zcc_shadow_package *zcc_shadow_package_lookup(
    const uint8_t package_root[32], const uint8_t release_root[32])
{
    for (size_t i = 0;
         i < sizeof(zcc_shadow_packages) / sizeof(zcc_shadow_packages[0]);
         i++) {
        uint8_t package[32], release[32];
        if (zcl_hex_decode_lower(zcc_shadow_packages[i].content_root_hex,
                                 package, sizeof(package)) &&
            zcl_hex_decode_lower(zcc_shadow_packages[i].release_root_hex,
                                 release, sizeof(release)) &&
            memcmp(package, package_root, 32) == 0 &&
            memcmp(release, release_root, 32) == 0)
            return &zcc_shadow_packages[i];
    }
    return NULL;
}

void zcl_native_handle_zcode_commons_shadow_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    static const char *const keys[] = {
        "workspace", "score_receipt_root", "policy_candidate_root",
        "reproduction_request_root", "reproduction_proof_set_root",
        "epoch", "now_unix"
    };
    const char *workspace = request ? zcc_str(request->input, "workspace")
                                    : NULL;
    const struct json_value *epoch_value = request
        ? json_get(request->input, "epoch") : NULL;
    const struct json_value *now_value = request
        ? json_get(request->input, "now_unix") : NULL;
    uint8_t score_root[32], policy_root[32], reproduction_root[32];
    uint8_t reproduction_proof_set_root[32];
    uint8_t derived[32], *wire = NULL;
    size_t wire_len = 0;
    if (!request || !reply || !workspace ||
        !zcc_keys(request->input, keys, 7) || !epoch_value || !now_value ||
        epoch_value->type != JSON_INT || now_value->type != JSON_INT ||
        json_get_int(epoch_value) < 0 || json_get_int(now_value) <= 0) {
        zcc_fail(reply, "BAD_SHADOW_INPUT",
                 "closed input requires workspace, score/policy/request/result-proof-set roots, epoch and now_unix");
        return;
    }
    if (!zcl_native_zcode_workspace_is_explicit_scratch(workspace)) {
        zcc_fail(reply, "UNSAFE_COMMONS_WORKSPACE",
                 "workspace must explicitly name an isolated tmp, test-tmp, or scratch path");
        return;
    }
    if (!zcc_root(request->input, "score_receipt_root", score_root) ||
        !zcc_root(request->input, "policy_candidate_root", policy_root) ||
        !zcc_root(request->input, "reproduction_request_root",
                  reproduction_root) ||
        !zcc_root(request->input, "reproduction_proof_set_root",
                  reproduction_proof_set_root) ||
        vcs_object_load_raw_bounded(
            workspace, score_root, VCS_ZCODE_SCORE_WIRE_BYTES,
            &wire, &wire_len) != 0) {
        free(wire);
        zcc_fail(reply, "SHADOW_SCORE_NOT_FOUND",
                 "exact Score receipt root absent or input malformed");
        return;
    }
    struct vcs_zcode_score_receipt_v1 score;
    bool parsed = vcs_zcode_score_receipt_parse(
            wire, wire_len, &score) == VCS_ZCODE_SCORE_OK &&
        vcs_zcode_score_receipt_id(&score, derived) == VCS_ZCODE_SCORE_OK &&
        memcmp(derived, score_root, 32) == 0;
    free(wire);
    if (!parsed ||
        vcs_zcode_score_receipt_verify_cas(workspace, &score) !=
            VCS_ZCODE_SCORE_OK) {
        zcc_fail(reply, "SHADOW_VERTICAL_INVALID",
                 "Score task/candidate/proof/PROVEN vertical did not rederive");
        return;
    }
    const struct zcc_shadow_package *package = zcc_shadow_package_lookup(
        score.package_root, score.release_root);
    if (!package) {
        zcc_fail(reply, "SHADOW_PACKAGE_UNREGISTERED",
                 "Score package/release pair is absent from the generated registry");
        return;
    }

    struct vcs_zcode_reproduction_qualification_report qualification;
    enum vcs_zcode_reproduction_qualification verdict =
        vcs_zcode_reproduction_qualify_cas(
            workspace, score_root, policy_root, reproduction_root,
            reproduction_proof_set_root,
            (uint64_t)json_get_int(epoch_value), json_get_int(now_value),
            &qualification);
    bool ready = verdict == VCS_ZCODE_QUALIFICATION_READY;
    (void)json_push_kv_str(&reply->data, "mode", "shadow_pre_genesis");
    (void)json_push_kv_str(&reply->data, "package_name", package->name);
    zcc_hex(&reply->data, "score_receipt_root", score_root);
    zcc_hex(&reply->data, "policy_candidate_root", policy_root);
    zcc_hex(&reply->data, "reproduction_request_root", reproduction_root);
    zcc_hex(&reply->data, "reproduction_proof_set_root",
            reproduction_proof_set_root);
    zcc_hex(&reply->data, "package_root", score.package_root);
    zcc_hex(&reply->data, "release_root", score.release_root);
    zcc_hex(&reply->data, "task_root", score.task_root);
    zcc_hex(&reply->data, "candidate_root", score.candidate_root);
    zcc_hex(&reply->data, "proof_policy_root", score.proof_policy_root);
    zcc_hex(&reply->data, "proof_set_root", score.proof_set_root);
    zcc_hex(&reply->data, "proven_lane_root", score.proven_lane_root);
    zcc_hex(&reply->data, "accepted_extraction_evidence_root",
            score.evidence_roots[VCS_ZCODE_SCORE_ACCEPTED_EXTRACTION]);
    zcc_hex(&reply->data, "independent_reproduction_evidence_root",
            score.evidence_roots[VCS_ZCODE_SCORE_INDEPENDENT_REPRODUCTION]);
    (void)json_push_kv_bool(&reply->data, "vertical_reverified", true);
    (void)json_push_kv_bool(&reply->data, "exact_reproduction_match",
                            qualification.exact_reproduction_match);
    (void)json_push_kv_bool(&reply->data, "distinct_signer",
                            qualification.distinct_signer);
    (void)json_push_kv_bool(&reply->data, "signer_policy_approved",
                            qualification.signer_policy_approved);
    (void)json_push_kv_bool(&reply->data,
        "declared_operator_group_distinct",
        qualification.declared_operator_group_distinct);
    (void)json_push_kv_bool(&reply->data, "remote_transport_used",
                            qualification.remote_transport_used);
    (void)json_push_kv_bool(&reply->data,
        "physical_independence_proven",
        qualification.physical_independence_proven);
    (void)json_push_kv_bool(&reply->data, "identity_linkage_complete",
                            qualification.identity_linkage_complete);
    (void)json_push_kv_int(&reply->data, "reproduction_receipts",
                           qualification.reproduction_receipts);
    (void)json_push_kv_str(&reply->data, "reproduction_compare_rule",
        vcs_reproduce_rule_string(
            (enum vcs_reproduce_rule)qualification.reproduce_rule));
    if (ready) {
        zcc_hex(&reply->data, "reproduction_receipt_root",
                qualification.reproduction_receipt_root);
        zcc_hex(&reply->data, "reproducer_contributor_binding_root",
                qualification.reproducer_contributor_binding_root);
        zcc_hex(&reply->data, "declared_operator_group_root",
                qualification.operator_group_root);
    }
    (void)json_push_kv_str(&reply->data, "shadow_status",
        ready ? "ready_for_shadow_attribution"
              : "blocked_reproduction_qualification");
    (void)json_push_kv_str(&reply->data,
        ready ? "qualification" : "blocker",
        vcs_zcode_reproduction_qualification_string(verdict));
    (void)json_push_kv_str(&reply->data, "why_shadow_units_would_exist",
        "challenge_matured_public_c23_creation_with_approved_off_host_reproduction");
    (void)json_push_kv_int(&reply->data, "shadow_award_atoms", 0);
    (void)json_push_kv_bool(&reply->data,
                            "creation_attribution_created", false);
    (void)json_push_kv_bool(&reply->data,
                            "epoch_creation_set_created", false);
    (void)json_push_kv_bool(&reply->data, "moves_live_funds", false);
    (void)json_push_kv_bool(&reply->data, "creates_ownership_right", false);
    (void)json_push_kv_bool(&reply->data, "token_required_for_access", false);
    (void)json_push_kv_bool(&reply->data, "money_establishes_truth", false);
    (void)json_push_kv_bool(&reply->data,
                            "permissive_license_validation_required", true);
    (void)json_push_kv_str(&reply->data, "next_safe_action",
        ready ? "prepare_scratch_only_shadow_attribution_plan"
              : "inspect_qualification_blocker_and_exact_cas_roots");
}

void zcl_native_handle_zcode_commons_verify(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    static const char *const keys[] = {"workspace"};
    struct vcs_zcode_commons_projection *projection =
        zcc_build(request, reply, keys, 1);
    if (!projection) return;
    zcc_render_summary(&reply->data, projection, false);
    uint8_t failed[32]; const char *reason = NULL;
    bool structural = !vcs_zcode_commons_projection_first_failure(
        projection, failed, &reason);
    (void)json_push_kv_bool(&reply->data, "exact_epoch_accounting",
                            structural);
    (void)json_push_kv_str(&reply->data, "creation_attribution_invariant",
        structural ? "unknown_without_active_chain_policy_context"
                   : "invalid_structural_accounting");
    (void)json_push_kv_bool(&reply->data, "balance_used_for_truth", false);
    vcs_zcode_commons_projection_free(projection);
}

void zcl_native_handle_zcode_commons_epoch(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    static const char *const keys[] = {"workspace", "epoch"};
    const struct json_value *value = request ? json_get(request->input, "epoch")
                                             : NULL;
    struct vcs_zcode_commons_projection *projection =
        zcc_build(request, reply, keys, 2);
    if (!projection) return;
    if (!value || value->type != JSON_INT || json_get_int(value) < 0) {
        vcs_zcode_commons_projection_free(projection);
        zcc_fail(reply, "BAD_EPOCH", "epoch must be a nonnegative integer");
        return;
    }
    uint64_t wanted = (uint64_t)json_get_int(value);
    const struct vcs_zcode_commons_epoch_entry *found = NULL;
    for (size_t i = 0; i < vcs_zcode_commons_projection_epoch_count(projection);
         i++) {
        const struct vcs_zcode_commons_epoch_entry *entry =
            vcs_zcode_commons_projection_epoch_at(projection, i);
        if (entry->epoch == wanted) { found = entry; break; }
    }
    if (!found) {
        vcs_zcode_commons_projection_free(projection);
        zcc_fail(reply, "EPOCH_NOT_FOUND", "epoch absent from workspace CAS");
        return;
    }
    zcc_hex(&reply->data, "epoch_creation_root", found->root);
    zcc_hex(&reply->data, "previous_epoch_creation_root", found->previous_root);
    (void)json_push_kv_int(&reply->data, "epoch", (int64_t)found->epoch);
    (void)json_push_kv_int(&reply->data, "cap_atoms", (int64_t)found->cap_atoms);
    (void)json_push_kv_int(&reply->data, "minted_atoms",
                           (int64_t)found->minted_atoms);
    (void)json_push_kv_int(&reply->data, "unissued_atoms",
                           (int64_t)found->unissued_atoms);
    (void)json_push_kv_int(&reply->data, "attribution_count",
                           found->attribution_count);
    vcs_zcode_commons_projection_free(projection);
}

static void zcc_render_creation(
    struct json_value *data,
    const struct vcs_zcode_creation_attribution_v1 *attribution,
    const uint8_t root[32])
{
    zcc_hex(data, "creation_attribution_root", root);
    (void)json_push_kv_int(data, "epoch", (int64_t)attribution->epoch);
    (void)json_push_kv_int(data, "award_atoms",
                           (int64_t)attribution->award_atoms);
    (void)json_push_kv_str(data, "category",
                           zcc_category_name(attribution->category));
    (void)json_push_kv_int(data, "challenge_opening_height",
                           (int64_t)attribution->challenge_opening_height);
    (void)json_push_kv_int(data, "challenge_maturity_height",
                           (int64_t)attribution->challenge_maturity_height);
    (void)json_push_kv_int(data, "challenge_maturity_mtp",
                           attribution->challenge_maturity_mtp);
    zcc_hex(data, "contributor_binding_root",
            attribution->contributor_binding_root);
    zcc_hex(data, "task_root", attribution->task_root);
    zcc_hex(data, "candidate_root", attribution->candidate_root);
    zcc_hex(data, "proof_policy_root", attribution->proof_policy_root);
    zcc_hex(data, "proof_set_root", attribution->proof_set_root);
    zcc_hex(data, "proven_lane_root", attribution->proven_lane_root);
    zcc_hex(data, "score_receipt_root", attribution->score_receipt_root);
    zcc_hex(data, "package_root", attribution->package_root);
    zcc_hex(data, "release_root", attribution->release_root);
    zcc_hex(data, "license_evidence_root", attribution->license_evidence_root);
    (void)json_push_kv_bool(data, "patronage_receipt_is_ownership", false);
}

void zcl_native_handle_zcode_commons_creation_show(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    static const char *const keys[] = {"workspace", "root"};
    uint8_t root[32], derived[32], *wire = NULL; size_t wire_len = 0;
    const char *workspace = request ? zcc_str(request->input, "workspace")
                                    : NULL;
    if (!request || !reply || !workspace ||
        !zcc_keys(request->input, keys, 2)) {
        zcc_fail(reply, "BAD_CREATION_INPUT",
                 "closed input requires workspace and creation root");
        return;
    }
    if (!zcl_native_zcode_workspace_is_explicit_scratch(workspace)) {
        zcc_fail(reply, "UNSAFE_COMMONS_WORKSPACE",
                 "workspace must explicitly name an isolated tmp, test-tmp, or scratch path");
        return;
    }
    if (
        !zcc_root(request->input, "root", root) ||
        vcs_object_load_raw_bounded(workspace, root,
            VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES, &wire, &wire_len) != 0) {
        free(wire);
        zcc_fail(reply, "CREATION_NOT_FOUND",
                 "exact creation root absent or input malformed");
        return;
    }
    struct vcs_zcode_creation_attribution_v1 attribution;
    bool ok = vcs_zcode_creation_attribution_parse(wire, wire_len,
            &attribution) == VCS_ZCODE_CREATION_OK &&
        vcs_zcode_creation_attribution_root(&attribution, derived) ==
            VCS_ZCODE_CREATION_OK && memcmp(root, derived, 32) == 0;
    free(wire);
    if (!ok) {
        zcc_fail(reply, "CREATION_CORRUPT",
                 "stored creation wire did not rederive its address");
        return;
    }
    zcc_render_creation(&reply->data, &attribution, root);
}

void zcl_native_handle_zcode_commons_lineage(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    static const char *const keys[] = {"workspace", "package_root"};
    uint8_t package[32];
    struct vcs_zcode_commons_projection *projection =
        zcc_build(request, reply, keys, 2);
    if (!projection) return;
    if (!zcc_root(request->input, "package_root", package)) {
        vcs_zcode_commons_projection_free(projection);
        zcc_fail(reply, "BAD_PACKAGE_ROOT", "full lowercase package root required");
        return;
    }
    struct json_value rows; json_init(&rows); json_set_array(&rows);
    size_t matches = 0;
    for (size_t i = 0;
         i < vcs_zcode_commons_projection_creation_count(projection); i++) {
        const struct vcs_zcode_commons_creation_entry *entry =
            vcs_zcode_commons_projection_creation_at(projection, i);
        if (memcmp(entry->package_root, package, 32) != 0) continue;
        struct json_value row; json_init(&row); json_set_object(&row);
        zcc_hex(&row, "creation_attribution_root", entry->root);
        zcc_hex(&row, "release_root", entry->release_root);
        (void)json_push_kv_int(&row, "epoch", (int64_t)entry->epoch);
        (void)json_push_kv_int(&row, "award_atoms",
                               (int64_t)entry->award_atoms);
        (void)json_push_kv_str(&row, "category",
                               zcc_category_name(entry->category));
        (void)json_push_back(&rows, &row); json_free(&row); matches++;
    }
    zcc_hex(&reply->data, "package_root", package);
    (void)json_push_kv_int(&reply->data, "count", (int64_t)matches);
    (void)json_push_kv(&reply->data, "creations", &rows); json_free(&rows);
    (void)json_push_kv_bool(&reply->data, "implies_package_ownership", false);
    vcs_zcode_commons_projection_free(projection);
}
