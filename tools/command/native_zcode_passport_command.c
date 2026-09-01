/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded native verification for canonical module_passport.v1. */

#include "command/native_command.h"

#include "base/hex.h"
#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "services/zcode_passport_view_service.h"
#include "vcs/package_mapping.h"
#include "vcs/package_release.h"
#include "vcs/vcs_devloop.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_commons.h"
#include "vcs/zcode_lane.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void passport_fail_action(struct zcl_command_reply *reply,
                                 const char *code, const char *phase,
                                 const char *detail, const char *next_action)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, phase, false,
                           false, detail, next_action);
}

static void passport_fail(struct zcl_command_reply *reply, const char *code,
                          const char *detail)
{
    passport_fail_action(reply, code, "verify", detail,
                         "zcode.passport.verify");
}

static void passport_push_root(struct json_value *data, const char *key,
                               const uint8_t root[32]);

static bool passport_key_allowed(const char *key, bool commit)
{
    static const char *const keys[] = {
        "stable_api_root", "recipe_root", "toolchain_root", "tests_root",
        "license_root", "semantic_fingerprint_root",
        "workspace_lineage_root", "source_assignment_root",
        "quality_profiles_root", "signer_pubkey", "workspace",
        "publication_job_root",
    };
    if (!key) return false;
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        if (strcmp(key, keys[i]) == 0) return true;
    return commit && strcmp(key, "signature") == 0;
}

static bool passport_view(
    struct zcl_command_reply *reply, enum zcode_passport_view_mode_v1 mode,
    struct zcode_passport_view_result_v1 *out)
{
    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_passport_view_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_PASSPORT_VIEW_SERVICE_ID, &lease);
    if (!service) service = zcode_passport_view_service_builtin();
    bool rendered = service->render(mode, out) && out->valid && out->kind[0] &&
        out->capability[0] && out->next_action[0];
    zcl_hotswap_service_release(&lease);
    if (!rendered) {
        passport_fail_action(
            reply, "MODULE_PASSPORT_VIEW_FAILED", "render",
            "the pure Passport view refused resident-confirmed evidence",
            "zcode.passport.status");
        return false;
    }
    return true;
}

static void passport_render_view(
    struct json_value *data,
    const struct zcode_passport_view_result_v1 *view)
{
    (void)json_push_kv_str(data, "kind", view->kind);
    (void)json_push_kv_str(data, "capability", view->capability);
    (void)json_push_kv_str(data, "view_service_id",
                           ZCODE_PASSPORT_VIEW_SERVICE_ID);
    (void)json_push_kv_int(data, "view_service_generation",
                           zcl_hotswap_service_generation());
    (void)json_push_kv_str(data, "agent_next_action", view->next_action);
}

static bool passport_parse_roots(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply,
    struct vcs_zcode_module_passport_v1 *passport,
    bool commit, const char *phase)
{
    const size_t required_children = commit ? 11u : 10u;
    if (!request || !reply || !passport || !request->input ||
        request->input->type != JSON_OBJ ||
        (request->input->num_children != required_children &&
         request->input->num_children != required_children + 2u)) {
        if (reply) passport_fail_action(
            reply, "BAD_MODULE_PASSPORT_INPUT", phase,
            "provide exactly the nine evidence roots and signer_pubkey as "
            "canonical lowercase 32-byte hexadecimal values",
            "zcode.passport.plan");
        return false;
    }
    for (size_t i = 0; i < request->input->num_children; i++) {
        if (!passport_key_allowed(request->input->keys[i], commit)) {
            passport_fail_action(
                reply, "BAD_MODULE_PASSPORT_INPUT", phase,
                "Passport input contains an undeclared field",
                "zcode.passport.plan");
            return false;
        }
    }
    const char *workspace = json_get_str(json_get(request->input,
                                                   "workspace"));
    const char *job = json_get_str(json_get(request->input,
                                             "publication_job_root"));
    bool have_workspace = workspace && workspace[0];
    bool have_job = job && job[0];
    if (have_workspace != have_job) {
        passport_fail_action(
            reply, "BAD_MODULE_PASSPORT_JOB_BINDING", phase,
            "workspace and publication_job_root must be provided together",
            "zcode.passport.plan");
        return false;
    }
    memset(passport, 0, sizeof(*passport));
    passport->schema_version = 1;
    passport->flags = VCS_ZCODE_COMMONS_REQUIRED_FLAGS;
    static const char *keys[] = {
        "stable_api_root", "recipe_root", "toolchain_root", "tests_root",
        "license_root", "semantic_fingerprint_root",
        "workspace_lineage_root", "source_assignment_root",
        "quality_profiles_root", "signer_pubkey",
    };
    uint8_t *roots[] = {
        passport->stable_api_root, passport->recipe_root,
        passport->toolchain_root, passport->tests_root,
        passport->license_root, passport->semantic_fingerprint_root,
        passport->workspace_lineage_root, passport->source_assignment_root,
        passport->quality_profiles_root, passport->signer_root,
    };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        const char *hex = json_get_str(json_get(request->input, keys[i]));
        if (!hex || strlen(hex) != 64u ||
            !zcl_hex_decode_lower(hex, roots[i], 32)) {
            passport_fail_action(
                reply, "BAD_MODULE_PASSPORT_ROOT", phase,
                "every evidence root and signer_pubkey must be canonical "
                "lowercase 32-byte hexadecimal",
                "zcode.passport.plan");
            memset(passport, 0, sizeof(*passport));
            return false;
        }
    }
    return true;
}

struct passport_job_binding {
    bool requested;
    char workspace[PATH_MAX];
    uint8_t job_root[32];
    uint8_t mapping_root[32];
    uint8_t release_root[32];
};

static bool passport_job_preflight(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply,
    const struct vcs_zcode_module_passport_v1 *passport,
    struct passport_job_binding *binding)
{
    memset(binding, 0, sizeof(*binding));
    const char *workspace = json_get_str(json_get(request->input,
                                                   "workspace"));
    const char *job_hex = json_get_str(json_get(request->input,
                                                 "publication_job_root"));
    if ((!workspace || !workspace[0]) && (!job_hex || !job_hex[0]))
        return true;
    binding->requested = true;
    struct vcs_devloop_publication_job job;
    struct vcs_devloop_publication_receipt progress, passport_receipt;
    struct vcs_devloop_publication_receipt release, mapping;
    uint8_t progress_root[32];
    bool valid = workspace && job_hex &&
        platform_directory_canonical_real(
            workspace, binding->workspace, sizeof(binding->workspace)) &&
        strlen(job_hex) == 64u &&
        zcl_hex_decode_lower(job_hex, binding->job_root, 32) &&
        vcs_devloop_publication_job_load(
            binding->workspace, binding->job_root, &job) &&
        vcs_devloop_publication_job_is_queued(
            binding->workspace, binding->job_root) &&
        vcs_devloop_publication_progress_load(
            binding->workspace, binding->job_root, &progress,
            progress_root);
    if (valid && progress.phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED) {
        release = progress;
    } else if (valid && progress.phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED) {
        passport_receipt = progress;
        valid = vcs_devloop_publication_receipt_load(
                binding->workspace, passport_receipt.predecessor_receipt_root,
                &release) &&
            release.phase ==
                VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED;
    } else if (valid && progress.phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED) {
        uint8_t expected_passport_root[32];
        bool loaded_passport = vcs_devloop_publication_receipt_load(
                binding->workspace, progress.predecessor_receipt_root,
                &passport_receipt);
        bool passport_phase = loaded_passport && passport_receipt.phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED;
        bool rooted = vcs_zcode_module_passport_v1_root(
                passport, expected_passport_root) ==
                VCS_ZCODE_COMMONS_OK;
        bool same_passport = rooted && loaded_passport &&
            memcmp(passport_receipt.artifact_root,
                   expected_passport_root, 32) == 0;
        bool loaded_release = same_passport &&
            vcs_devloop_publication_receipt_load(
                binding->workspace,
                passport_receipt.predecessor_receipt_root,
                &release);
        valid = passport_phase && same_passport && loaded_release &&
            release.phase == VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED;
    } else {
        valid = false;
    }
    valid = valid && vcs_devloop_publication_receipt_load(
            binding->workspace, release.predecessor_receipt_root,
            &mapping) &&
        mapping.phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY;
    struct vcs_package_mapping_set mapping_set;
    vcs_package_mapping_set_init(&mapping_set);
    struct vcs_zcode_lane_receipt_v1 lane;
    uint8_t *lane_wire = NULL;
    size_t lane_wire_len = 0;
    uint8_t lane_root[32];
    valid = valid && vcs_package_mapping_set_load(
            binding->workspace, mapping.artifact_root, &mapping_set) &&
        vcs_object_load_raw_bounded(
            binding->workspace, mapping_set.lane_receipt_root,
            VCS_ZCODE_LANE_WIRE_BYTES, &lane_wire, &lane_wire_len) == 0 &&
        vcs_zcode_lane_receipt_parse(lane_wire, lane_wire_len, &lane) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_lane_receipt_verify(&lane, lane.signer_pubkey) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_lane_receipt_id(&lane, lane_root) == VCS_ZCODE_DEV_OK &&
        memcmp(lane_root, mapping_set.lane_receipt_root, 32) == 0 &&
        memcmp(passport->workspace_lineage_root,
               job.vcs_commit_root, 32) == 0 &&
        memcmp(passport->tests_root, lane.proof_set_root, 32) == 0;
    uint8_t *release_wire = NULL;
    size_t release_wire_len = 0;
    struct vcs_package_release envelope;
    uint8_t checked_release_root[32];
    valid = valid && vcs_object_load_raw_bounded(
            binding->workspace, release.artifact_root,
            VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
            &release_wire, &release_wire_len) == 0 &&
        vcs_package_release_parse(
            release_wire, release_wire_len, &envelope) ==
            VCS_PACKAGE_RELEASE_OK &&
        vcs_package_release_verify(&envelope) == VCS_PACKAGE_RELEASE_OK &&
        vcs_package_release_id(
            &envelope, checked_release_root) == VCS_PACKAGE_RELEASE_OK &&
        memcmp(checked_release_root, release.artifact_root, 32) == 0 &&
        memcmp(passport->recipe_root, envelope.recipe_root, 32) == 0;
    if (valid) {
        memcpy(binding->mapping_root, mapping.artifact_root, 32);
        memcpy(binding->release_root, release.artifact_root, 32);
    }
    free(release_wire);
    free(lane_wire);
    vcs_package_mapping_set_free(&mapping_set);
    if (!valid) {
        passport_fail_action(
            reply, "MODULE_PASSPORT_JOB_BINDING_INVALID", "bind",
            "publication_job_root must be queued at RELEASE_PUBLISHED or a "
            "later matching phase and the Passport must bind its exact signed "
            "release recipe, ZVCS commit, and accepted proof set",
            "dev publication status");
        return false;
    }
    return true;
}

static bool passport_store_verified(
    const char *workspace, const uint8_t root[32],
    const uint8_t *wire, size_t wire_len)
{
    if (!vcs_object_store_init(workspace) ||
        !vcs_object_put_addressed(workspace, root, wire, wire_len))
        return false;
    uint8_t *stored = NULL;
    size_t stored_len = 0;
    struct vcs_zcode_module_passport_v1 decoded;
    uint8_t checked_root[32];
    bool ok = vcs_object_load_raw_bounded(
            workspace, root, VCS_ZCODE_MODULE_PASSPORT_V1_WIRE_BYTES,
            &stored, &stored_len) == 0 &&
        stored_len == wire_len && memcmp(stored, wire, wire_len) == 0 &&
        vcs_zcode_module_passport_v1_decode(
            &decoded, stored, stored_len) == VCS_ZCODE_COMMONS_OK &&
        vcs_zcode_module_passport_v1_root(&decoded, checked_root) ==
            VCS_ZCODE_COMMONS_OK &&
        memcmp(checked_root, root, 32) == 0;
    free(stored);
    return ok;
}

static void passport_render_evidence(
    struct json_value *data,
    const struct vcs_zcode_module_passport_v1 *passport)
{
    passport_push_root(data, "stable_api_root", passport->stable_api_root);
    passport_push_root(data, "recipe_root", passport->recipe_root);
    passport_push_root(data, "toolchain_root", passport->toolchain_root);
    passport_push_root(data, "tests_root", passport->tests_root);
    passport_push_root(data, "license_root", passport->license_root);
    passport_push_root(data, "semantic_fingerprint_root",
                       passport->semantic_fingerprint_root);
    passport_push_root(data, "workspace_lineage_root",
                       passport->workspace_lineage_root);
    passport_push_root(data, "source_assignment_root",
                       passport->source_assignment_root);
    passport_push_root(data, "quality_profiles_root",
                       passport->quality_profiles_root);
    passport_push_root(data, "signer_pubkey", passport->signer_root);
}

void zcl_native_handle_zcode_passport_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct vcs_zcode_module_passport_v1 passport;
    if (!passport_parse_roots(request, reply, &passport, false, "plan"))
        return;
    struct passport_job_binding binding;
    if (!passport_job_preflight(request, reply, &passport, &binding)) return;
    uint8_t payload[VCS_ZCODE_MODULE_PASSPORT_V1_SIGNING_PAYLOAD_BYTES];
    size_t payload_len = 0;
    enum vcs_zcode_commons_error error =
        vcs_zcode_module_passport_v1_signing_payload(
            &passport, payload, sizeof(payload), &payload_len);
    if (error != VCS_ZCODE_COMMONS_OK) {
        passport_fail_action(reply, "MODULE_PASSPORT_PLAN_FAILED", "plan",
                             vcs_zcode_commons_error_string(error),
                             "zcode.passport.plan");
        return;
    }
    char payload_hex[
        VCS_ZCODE_MODULE_PASSPORT_V1_SIGNING_PAYLOAD_BYTES * 2u + 1u];
    zcl_hex_encode(payload, payload_len, payload_hex);
    struct zcode_passport_view_result_v1 view;
    if (!passport_view(reply, ZCODE_PASSPORT_VIEW_PLAN, &view)) return;
    (void)json_push_kv_bool(&reply->data, "ready_to_sign", true);
    passport_render_view(&reply->data, &view);
    (void)json_push_kv_str(&reply->data, "signing_algorithm", "Ed25519");
    (void)json_push_kv_str(&reply->data, "signing_domain",
                           VCS_ZCODE_MODULE_PASSPORT_V1_SIGNING_DOMAIN);
    (void)json_push_kv_str(&reply->data, "signing_payload", payload_hex);
    (void)json_push_kv_int(&reply->data, "signing_payload_bytes",
                           (int64_t)payload_len);
    (void)json_push_kv_bool(&reply->data, "simulation_only", true);
    (void)json_push_kv_bool(&reply->data, "not_owner_approved", true);
    (void)json_push_kv_bool(&reply->data, "private_key_accepted", false);
    (void)json_push_kv_bool(&reply->data, "wallet_accessed", false);
    passport_render_evidence(&reply->data, &passport);
    if (binding.requested) {
        passport_push_root(&reply->data, "publication_job_root",
                           binding.job_root);
        passport_push_root(&reply->data, "package_mapping_root",
                           binding.mapping_root);
        passport_push_root(&reply->data, "release_root",
                           binding.release_root);
        (void)json_push_kv_bool(&reply->data,
                                "will_persist_on_commit", true);
    }
}

void zcl_native_handle_zcode_passport_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct vcs_zcode_module_passport_v1 passport;
    if (!passport_parse_roots(request, reply, &passport, true, "commit"))
        return;
    const char *signature = json_get_str(json_get(request->input, "signature"));
    if (!signature || strlen(signature) != 128u ||
        !zcl_hex_decode_lower(signature, passport.signature, 64)) {
        passport_fail_action(
            reply, "BAD_MODULE_PASSPORT_SIGNATURE", "commit",
            "signature must be one canonical lowercase 64-byte Ed25519 "
            "signature produced over the planned payload",
            "zcode.passport.plan");
        return;
    }
    enum vcs_zcode_commons_error error =
        vcs_zcode_module_passport_v1_verify(&passport);
    if (error != VCS_ZCODE_COMMONS_OK) {
        passport_fail_action(reply, "MODULE_PASSPORT_SIGNATURE_INVALID",
                             "commit",
                             vcs_zcode_commons_error_string(error),
                             "zcode.passport.plan");
        return;
    }
    struct passport_job_binding binding;
    if (!passport_job_preflight(request, reply, &passport, &binding)) return;
    uint8_t wire[VCS_ZCODE_MODULE_PASSPORT_V1_WIRE_BYTES], root[32];
    size_t wire_len = 0;
    error = vcs_zcode_module_passport_v1_encode(
        &passport, wire, sizeof(wire), &wire_len);
    if (error == VCS_ZCODE_COMMONS_OK)
        error = vcs_zcode_module_passport_v1_root(&passport, root);
    if (error != VCS_ZCODE_COMMONS_OK) {
        passport_fail_action(reply, "MODULE_PASSPORT_COMMIT_FAILED", "commit",
                             vcs_zcode_commons_error_string(error),
                             "zcode.passport.plan");
        return;
    }
    char wire_hex[VCS_ZCODE_MODULE_PASSPORT_V1_WIRE_BYTES * 2u + 1u];
    zcl_hex_encode(wire, wire_len, wire_hex);
    struct zcode_passport_view_result_v1 view;
    if (!passport_view(reply, ZCODE_PASSPORT_VIEW_COMMIT, &view)) return;
    uint8_t progress_root[32];
    bool progress_reused = false;
    if (binding.requested &&
        (!passport_store_verified(binding.workspace, root, wire, wire_len) ||
         !vcs_devloop_publication_advance_passport(
             binding.workspace, binding.job_root, binding.mapping_root,
             binding.release_root, root, progress_root,
             &progress_reused))) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "MODULE_PASSPORT_PROGRESS_FAILED", "persist", true, true,
            "the verified Passport could not be durably bound to its publication job; retry the exact commit",
            "dev publication status");
        return;
    }
    (void)json_push_kv_bool(&reply->data, "verified", true);
    passport_render_view(&reply->data, &view);
    (void)json_push_kv_str(&reply->data, "passport", wire_hex);
    passport_push_root(&reply->data, "passport_root", root);
    (void)json_push_kv_bool(&reply->data, "persisted", binding.requested);
    (void)json_push_kv_bool(&reply->data, "published", false);
    (void)json_push_kv_bool(&reply->data, "simulation_only", true);
    (void)json_push_kv_bool(&reply->data, "not_owner_approved", true);
    passport_render_evidence(&reply->data, &passport);
    if (binding.requested) {
        passport_push_root(&reply->data, "publication_job_root",
                           binding.job_root);
        passport_push_root(&reply->data, "progress_receipt_root",
                           progress_root);
        passport_push_root(&reply->data, "package_mapping_root",
                           binding.mapping_root);
        passport_push_root(&reply->data, "release_root",
                           binding.release_root);
        (void)json_push_kv_str(&reply->data, "publication_status",
                               "PASSPORT_PUBLISHED");
        (void)json_push_kv_bool(&reply->data, "progress_reused",
                                progress_reused);
        (void)json_push_kv_bool(&reply->data, "network_called", false);
        (void)json_push_kv_bool(&reply->data, "wallet_called", false);
    }
}

static void passport_push_root(struct json_value *data, const char *key,
                               const uint8_t root[32])
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    (void)json_push_kv_str(data, key, hex);
}

void zcl_native_handle_zcode_passport_verify(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *value = request && request->input
        ? json_get(request->input, "passport") : NULL;
    const char *hex = json_get_str(value);
    if (!request || !reply || !request->input ||
        request->input->type != JSON_OBJ ||
        request->input->num_children != 1 || !hex ||
        strlen(hex) != VCS_ZCODE_MODULE_PASSPORT_V1_WIRE_BYTES * 2u) {
        if (reply) passport_fail(
            reply, "BAD_MODULE_PASSPORT_INPUT",
            "passport must be exactly one canonical 396-byte lowercase hex wire");
        return;
    }

    uint8_t wire[VCS_ZCODE_MODULE_PASSPORT_V1_WIRE_BYTES];
    if (!zcl_hex_decode_lower(hex, wire, sizeof(wire))) {
        passport_fail(reply, "BAD_MODULE_PASSPORT_INPUT",
                      "passport must use canonical lowercase hexadecimal");
        return;
    }
    struct vcs_zcode_module_passport_v1 passport;
    enum vcs_zcode_commons_error error =
        vcs_zcode_module_passport_v1_decode(&passport, wire, sizeof(wire));
    if (error != VCS_ZCODE_COMMONS_OK) {
        passport_fail(reply, "MODULE_PASSPORT_INVALID",
                      vcs_zcode_commons_error_string(error));
        return;
    }
    uint8_t root[32];
    error = vcs_zcode_module_passport_v1_root(&passport, root);
    if (error != VCS_ZCODE_COMMONS_OK) {
        passport_fail(reply, "MODULE_PASSPORT_ROOT_FAILED",
                      vcs_zcode_commons_error_string(error));
        return;
    }

    struct zcode_passport_view_result_v1 view;
    if (!passport_view(reply, ZCODE_PASSPORT_VIEW_VERIFY, &view)) return;
    (void)json_push_kv_bool(&reply->data, "verified", true);
    passport_render_view(&reply->data, &view);
    (void)json_push_kv_bool(&reply->data, "simulation_only", true);
    (void)json_push_kv_bool(&reply->data, "not_owner_approved", true);
    passport_push_root(&reply->data, "passport_root", root);
    passport_render_evidence(&reply->data, &passport);
}

void zcl_native_handle_zcode_passport_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply || !request->input ||
        request->input->type != JSON_OBJ || request->input->num_children != 0) {
        if (reply) passport_fail_action(
            reply, "BAD_MODULE_PASSPORT_STATUS_INPUT", "status",
            "zcode passport status accepts no input keys",
            "zcode.passport.status");
        return;
    }
    struct zcode_passport_view_result_v1 view;
    if (!passport_view(reply, ZCODE_PASSPORT_VIEW_STATUS, &view)) return;
    (void)json_push_kv_bool(&reply->data, "ready", true);
    passport_render_view(&reply->data, &view);
    (void)json_push_kv_bool(&reply->data, "parsing_static", true);
    (void)json_push_kv_bool(&reply->data, "signature_verification_static", true);
    (void)json_push_kv_bool(&reply->data, "canonical_root_static", true);
    (void)json_push_kv_bool(&reply->data, "signing_payload_static", true);
    (void)json_push_kv_bool(&reply->data, "persistence_swappable", false);
    (void)json_push_kv_bool(&reply->data, "publication_swappable", false);
    (void)json_push_kv_bool(&reply->data, "simulation_only", true);
}

static bool passport_view_frozen_kat(const void *opaque, char *why,
                                     size_t why_sz)
{
    const struct zcode_passport_view_service_v1 *service = opaque;
    struct zcode_passport_view_result_v1 view;
    static const struct {
        enum zcode_passport_view_mode_v1 mode;
        const char *next_action;
    } cases[] = {
        {ZCODE_PASSPORT_VIEW_STATUS, "zcode passport plan"},
        {ZCODE_PASSPORT_VIEW_PLAN,
         "sign signing_payload with the matching offline Ed25519 key, then run zcode passport commit with the same roots and signature"},
        {ZCODE_PASSPORT_VIEW_COMMIT,
         "zcode passport verify --passport=<passport>"},
        {ZCODE_PASSPORT_VIEW_VERIFY,
         "bind this passport root into a workspace manifest"},
    };
    if (!service || !service->render) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen Passport service shape vector failed");
        return false;
    }
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (!service->render(cases[i].mode, &view) || !view.valid ||
            strcmp(view.kind, "module_passport.v1") != 0 ||
            strcmp(view.next_action, cases[i].next_action) != 0) {
            if (why && why_sz) (void)snprintf(
                why, why_sz, "frozen Passport presentation vector %zu failed",
                i);
            return false;
        }
    }
    if (service->render((enum zcode_passport_view_mode_v1)99, &view)) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen unknown Passport mode rejection failed");
        return false;
    }
    return true;
}

static const struct zcl_hotswap_service_contract k_passport_view_contract = {
    .service_id = ZCODE_PASSPORT_VIEW_SERVICE_ID,
    .source_tu = "contexts/commons/services/src/zcode_passport_view_service.c",
    .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
    .vtable_size = sizeof(struct zcode_passport_view_service_v1),
    .abi_fingerprint = ZCODE_PASSPORT_VIEW_ABI_FINGERPRINT,
    .schema_fingerprint = ZCODE_PASSPORT_VIEW_SCHEMA_FINGERPRINT,
    .wire_fingerprint = ZCODE_PASSPORT_VIEW_WIRE_FINGERPRINT,
    .kat_fingerprint = ZCODE_PASSPORT_VIEW_KAT_FINGERPRINT,
    .frozen_kat = passport_view_frozen_kat,
};

const struct zcl_hotswap_service_contract *
zcl_native_zcode_passport_view_service_contract(void)
{
    return &k_passport_view_contract;
}
