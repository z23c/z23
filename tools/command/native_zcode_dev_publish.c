/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ZCODE dev-loop publish — publish an explicit PROVEN accepted
 * work as a signed release. The signed lane receipt in the workspace CAS is
 * the acceptance authority: it is reloaded and re-verified (Ed25519
 * signature, cross-object task/candidate/policy roots, the evaluated proof
 * set) before anything is built — caller claims are never trusted. The
 * ordinary content.v2 package carries a compressed, fully rederivable ZVCS
 * tree plus the exact lane receipt wire, so the signed release binds the
 * accepted source root and, through the receipt, the proof-set and task
 * roots. Its declarative recipe builds only the inert carrier marker; the
 * task's independently verified acceptance recipe remains the authority for
 * the accepted product. Commit runs through the existing
 * zcode.package.publish commit handler: one lifecycle, one store, one
 * rebuildable index. No second package format or task table is created.
 * The lane-reload/verify, staging-directory, and lineage primitives this
 * file composes live in the sibling native_zcode_dev_publish_stage.c. */

#include "command/native_command.h"
#include "command/native_zcode_dev_priv.h"
#include "command/native_zcode_dev_publish_priv.h"

#include "controllers/rpc_client.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "config/runtime.h"
#include "config/command_catalog.h"
#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "models/database.h"
#include "models/database_owner_lease.h"
#include "platform/directory_compat.h"
#include "platform/directory_transaction.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "platform/rng.h"
#include "platform/time_compat.h"
#include "services/build_fabric_service.h"
#include "services/build_fabric_async.h"
#include "services/build_fabric_worker.h"
#include "services/zcode_agent_context_service.h"
#include "services/zcode_lane_service.h"
#include "services/zcode_lane_view_service.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "vcs/build_action.h"
#include "vcs/build_artifact_manifest.h"
#include "vcs/package_accept.h"
#include "vcs/package_index.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_lane.h"
#include "vcs/package_manifest.h"
#include "vcs/package_mapping.h"
#include "vcs/package_deps.h"
#include "vcs/package_recipe.h"
#include "vcs/package_store.h"
#include "vcs/source_package_transport.h"
#include "vcs/vcs_devloop.h"
#include "vcs/zcode_work_context.h"
#include "vcs/zcode_work_node.h"
#include "vcs/zcode_action_input.h"
#include "vcs/zcode_write_scope.h"
#include "vcs/zcode_patch.h"
#include "vcs/zcode_candidate_bundle.h"
#include "vcs/zcode_task_authority.h"
#include "vcs/zcode_task_authority_bundle.h"
#include "vcs/zcode_task_index.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

struct zpub_job_binding {
    bool requested;
    uint8_t job_root[32];
    uint64_t bytes_scanned;
    uint32_t new_chunks;
    uint32_t reused_chunks;
};

struct zpub_package_facts {
    char name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    char semver[VCS_PACKAGE_RELEASE_SEMVER_MAX + 1u];
    char license[VCS_PACKAGE_RELEASE_LICENSE_MAX + 1u];
};

enum zpub_package_facts_state {
    ZPUB_PACKAGE_FACTS_INVALID = -1,
    ZPUB_PACKAGE_FACTS_ABSENT = 0,
    ZPUB_PACKAGE_FACTS_PRESENT = 1,
};

/* Find the zcode-package.json entry in the accepted source tree, if any. */
static const struct vcs_entry *zpub_package_facts_find_entry(
    const struct vcs_manifest *tree)
{
    for (size_t i = 0; i < tree->count; i++)
        if (strcmp(tree->entries[i].path, VCS_PACKAGE_DEPS_META_PATH) == 0)
            return &tree->entries[i];
    return NULL;
}

/* Load and CAS-verify the exact bytes behind one manifest entry. */
static bool zpub_package_facts_load_bytes(
    const struct zpub_accepted_bundle *bundle,
    const struct vcs_entry *entry, uint8_t **wire, size_t *wire_len)
{
    bool bounded = (entry->mode & 0170000u) == 0100000u && entry->size > 0 &&
        entry->size <= VCS_PACKAGE_DEPS_META_MAX_BYTES;
    bool loaded = bounded && vcs_object_load_raw_bounded(
        bundle->workspace, entry->blob, VCS_PACKAGE_DEPS_META_MAX_BYTES,
        wire, wire_len) == 0 && *wire_len == entry->size;
    if (!loaded) return false;
    uint8_t derived[32];
    struct sha3_256_ctx ctx;
    uint8_t tag = VCS_TAG_BLOB;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, &tag, 1);
    sha3_256_write(&ctx, *wire, *wire_len);
    sha3_256_finalize(&ctx, derived);
    return memcmp(derived, entry->blob, sizeof(derived)) == 0;
}

/* Parse the zcode-package.json bytes into the fixed fact fields. */
static bool zpub_package_facts_parse(
    const uint8_t *wire, size_t wire_len, struct zpub_package_facts *facts)
{
    struct json_value meta;
    if (!json_read(&meta, (const char *)wire, wire_len) ||
        meta.type != JSON_OBJ)
        return false;
    const struct json_value *schema = json_get(&meta, "schema");
    const char *name = zdev_str(&meta, "name");
    const char *semver = zdev_str(&meta, "semver");
    const char *license = zdev_str(&meta, "license");
    const char *language = zdev_str(&meta, "language");
    bool valid = schema && schema->type == JSON_INT &&
        json_get_int(schema) == 1 && language &&
        strcmp(language, "c23") == 0 &&
        zpub_copy_field(facts->name, sizeof(facts->name), name) &&
        zpub_copy_field(facts->semver, sizeof(facts->semver), semver) &&
        zpub_copy_field(facts->license, sizeof(facts->license), license);
    json_free(&meta);
    return valid;
}

static enum zpub_package_facts_state zpub_package_facts_load(
    const struct zpub_accepted_bundle *bundle,
    struct zpub_package_facts *facts)
{
    memset(facts, 0, sizeof(*facts));
    struct vcs_manifest tree;
    if (!vcs_tree_load(bundle->workspace, bundle->source_root, &tree))
        return ZPUB_PACKAGE_FACTS_INVALID;
    const struct vcs_entry *entry = zpub_package_facts_find_entry(&tree);
    if (!entry) {
        vcs_manifest_free(&tree);
        return ZPUB_PACKAGE_FACTS_ABSENT;
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool loaded = zpub_package_facts_load_bytes(bundle, entry, &wire,
                                                &wire_len);
    vcs_manifest_free(&tree);
    bool valid = loaded && zpub_package_facts_parse(wire, wire_len, facts);
    free(wire);
    return valid ? ZPUB_PACKAGE_FACTS_PRESENT : ZPUB_PACKAGE_FACTS_INVALID;
}

static bool zpub_package_fact_matches(const char *requested,
                                      const char *accepted)
{
    return !requested || !requested[0] || strcmp(requested, accepted) == 0;
}

static bool zpub_job_preflight(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    const struct zpub_accepted_bundle *bundle,
    struct zpub_job_binding *binding)
{
    memset(binding, 0, sizeof(*binding));
    const char *job_hex = zdev_str(request->input, "publication_job_root");
    if (!job_hex || !job_hex[0])
        return true;
    binding->requested = true;
    struct vcs_devloop_publication_job job;
    struct vcs_devloop_publication_receipt progress, mapping = {0};
    uint8_t progress_root[32];
    bool valid = bundle->have_mapping &&
        zcl_hex_decode_lower(job_hex, binding->job_root, 32) &&
        vcs_devloop_publication_job_load(
            bundle->workspace, binding->job_root, &job) &&
        vcs_devloop_publication_job_is_queued(
            bundle->workspace, binding->job_root) &&
        memcmp(job.source_tree_root, bundle->source_root, 32) == 0 &&
        vcs_devloop_publication_progress_load(
            bundle->workspace, binding->job_root, &progress,
            progress_root);
    if (valid && progress.phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY) {
        mapping = progress;
    } else if (valid && progress.phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED) {
        valid = vcs_devloop_publication_receipt_load(
                bundle->workspace, progress.predecessor_receipt_root,
                &mapping) &&
            mapping.phase ==
                VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY;
    } else {
        valid = false;
    }
    valid = valid &&
        memcmp(mapping.artifact_root, bundle->mapping_root, 32) == 0;
    if (!valid) {
        zpub_fail(
            reply, "PUBLICATION_JOB_BINDING_INVALID",
            "publication_job_root must be one queued exact-source job at "
            "PACKAGE_MAPPING_READY (or its idempotent RELEASE_PUBLISHED "
            "successor), bound to package_mapping_root");
        return false;
    }
    binding->bytes_scanned = mapping.bytes_scanned;
    binding->new_chunks = mapping.new_chunks;
    binding->reused_chunks = mapping.reused_chunks;
    return true;
}

/* Resolve name/semver/license: from the exact accepted zcode-package.json
 * when present (caller overrides refused), otherwise from caller input. */
static bool zpub_plan_resolve_facts(
    const struct zcl_command_request *request,
    struct zpub_accepted_bundle *bundle, struct zpub_package_facts *facts,
    enum zpub_package_facts_state *state, const char **name,
    const char **semver, const char **license, struct zcl_command_reply *reply)
{
    *name = zdev_str(request->input, "name");
    *semver = zdev_str(request->input, "semver");
    *license = zdev_str(request->input, "license");
    *state = zpub_package_facts_load(bundle, facts);
    if (*state == ZPUB_PACKAGE_FACTS_INVALID) {
        zpub_bundle_free(bundle);
        zpub_fail(reply, "PACKAGE_FACTS_INVALID",
                  "the exact accepted zcode-package.json is malformed, "
                  "unreadable, or not C23");
        return false;
    }
    if (*state == ZPUB_PACKAGE_FACTS_PRESENT) {
        if (!zpub_package_fact_matches(*name, facts->name) ||
            !zpub_package_fact_matches(*semver, facts->semver) ||
            !zpub_package_fact_matches(*license, facts->license)) {
            zpub_bundle_free(bundle);
            zpub_fail(reply, "PACKAGE_FACTS_MISMATCH",
                      "name, semver, and license may not override the exact "
                      "accepted zcode-package.json");
            return false;
        }
        *name = facts->name;
        *semver = facts->semver;
        *license = facts->license;
    }
    return true;
}

/* Fill and validate the unsigned release plan fields, deriving publisher
 * lineage from the persisted release index. */
/* Fill the caller-supplied release fields (publisher key, name/semver/
 * license/reward, optional znam). */
static bool zpub_plan_release_fields(
    const struct zcl_command_request *request, const char *pubkey_hex,
    const char *name, const char *semver, const char *license,
    struct vcs_package_release *release)
{
    const char *reward = zdev_str(request->input, "reward_address");
    const char *znam = zdev_str(request->input, "znam");
    bool fields_ok = pubkey_hex &&
        zcl_hex_decode_lower(pubkey_hex, release->publisher_pubkey,
                             sizeof(release->publisher_pubkey)) &&
        zpub_copy_field(release->name, sizeof(release->name), name) &&
        zpub_copy_field(release->semver, sizeof(release->semver), semver) &&
        zpub_copy_field(release->license, sizeof(release->license), license) &&
        zpub_copy_field(release->reward_address,
                        sizeof(release->reward_address), reward);
    if (znam && znam[0]) {
        release->has_znam = true;
        fields_ok = fields_ok &&
            zpub_copy_field(release->znam, sizeof(release->znam), znam);
    }
    return fields_ok;
}

/* Derive the chain id and persisted publisher lineage, checking any claimed
 * sequence/parent still matches. */
static bool zpub_plan_release_lineage(
    const struct zcl_command_request *request,
    const struct zpub_accepted_bundle *bundle, const char *pubkey_hex,
    struct vcs_package_release *release)
{
    char zcode_dir[ZPUB_PATH_MAX];
    int n = snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode",
                     bundle->datadir);
    return n > 0 && (size_t)n < sizeof(zcode_dir) &&
        vcs_package_accept_chain_id(release->chain_id,
                                    sizeof(release->chain_id)) &&
        zpub_lineage(zcode_dir, pubkey_hex, &release->has_parent,
                     release->parent_root, &release->publisher_sequence) &&
        zpub_lineage_claims_match(request->input, release->has_parent,
                                  release->parent_root,
                                  release->publisher_sequence);
}

static bool zpub_plan_build_release(
    const struct zcl_command_request *request,
    struct zpub_accepted_bundle *bundle, const char *name,
    const char *semver, const char *license, struct vcs_package_release *release,
    uint8_t **release_body, size_t *release_body_len, uint8_t digest[32],
    struct zcl_command_reply *reply)
{
    const char *pubkey_hex = zdev_str(request->input, "publisher_pubkey");
    memset(release, 0, sizeof(*release));
    release->schema_version = VCS_PACKAGE_RELEASE_VERSION;
    memcpy(release->package_root, bundle->transport.package_root, 32);
    memcpy(release->recipe_root, bundle->transport.recipe_root, 32);
    bool fields_ok =
        zpub_plan_release_fields(request, pubkey_hex, name, semver, license,
                                 release) &&
        zpub_plan_release_lineage(request, bundle, pubkey_hex, release) &&
        vcs_package_release_validate(release) == VCS_PACKAGE_RELEASE_OK &&
        zpub_release_body(release, release_body, release_body_len, digest);
    if (!fields_ok) {
        free(*release_body);
        *release_body = NULL;
        zpub_bundle_free(bundle);
        zpub_fail(reply, "RELEASE_PLAN_FAILED",
                  "publisher key, release fields, chain id, or persisted "
                  "publisher lineage is invalid or stale");
        return false;
    }
    return true;
}

/* Render the unsigned publication plan response. */
static bool zpub_plan_render_core(
    struct zcl_command_reply *reply, const struct zpub_accepted_bundle *bundle,
    const struct vcs_package_release *release, const uint8_t digest[32],
    const uint8_t *release_body, size_t release_body_len)
{
    bool rendered =
        zpub_push_hex(&reply->data, "package_root",
                      bundle->transport.package_root, 32) &&
        zpub_push_hex(&reply->data, "release_signing_digest",
                      digest, 32) &&
        zpub_push_hex(&reply->data, "release_body_hex",
                      release_body, release_body_len) &&
        json_push_kv_int(&reply->data, "manifest_bytes",
                         (int64_t)bundle->transport.manifest_wire_len) &&
        json_push_kv_int(&reply->data, "recipe_bytes",
                         (int64_t)bundle->transport.recipe_wire_len) &&
        json_push_kv_str(&reply->data, "carrier_material",
                         "rederived_from_accepted_source_at_commit") &&
        json_push_kv_int(&reply->data, "publisher_sequence",
                         (int64_t)release->publisher_sequence) &&
        json_push_kv_bool(&reply->data, "has_parent",
                          release->has_parent) &&
        json_push_kv_str(&reply->data, "signature_status", "unsigned") &&
        json_push_kv_bool(&reply->data, "read_only", true);
    if (rendered && release->has_parent)
        rendered = zpub_push_hex(&reply->data, "parent_release_root",
                                 release->parent_root, 32);
    return rendered;
}

/* Push the job-binding/package-facts fields that follow the common output
 * block; these are best-effort (void) fields, not part of the render
 * success/failure decision. */
static void zpub_plan_render_extra(
    struct zcl_command_reply *reply, const struct zpub_accepted_bundle *bundle,
    const struct vcs_package_release *release,
    enum zpub_package_facts_state package_facts_state,
    const struct zpub_job_binding *job_binding)
{
    (void)json_push_kv_int(&reply->data, "bytes_scanned",
                           (int64_t)job_binding->bytes_scanned);
    (void)json_push_kv_int(&reply->data, "new_chunks",
                           job_binding->new_chunks);
    (void)json_push_kv_int(&reply->data, "reused_chunks",
                           job_binding->reused_chunks);
    (void)json_push_kv_int(&reply->data, "synthetic_bytes_hashed",
                           (int64_t)bundle->transport.source_transport_bytes +
                           (int64_t)bundle->transport.offline_input_bytes +
                           VCS_ZCODE_LANE_WIRE_BYTES);
    (void)json_push_kv_str(&reply->data, "package_name", release->name);
    (void)json_push_kv_str(&reply->data, "package_version", release->semver);
    (void)json_push_kv_str(&reply->data, "package_license", release->license);
    (void)json_push_kv_str(
        &reply->data, "package_facts",
        package_facts_state == ZPUB_PACKAGE_FACTS_PRESENT
            ? "exact_accepted_source" : "explicit_input");
    if (bundle->have_mapping)
        zdev_push_root(&reply->data, "package_mapping_root",
                       bundle->mapping_root);
    if (job_binding->requested)
        zdev_push_root(&reply->data, "publication_job_root",
                       job_binding->job_root);
}

static bool zpub_plan_render(
    struct zcl_command_reply *reply, const struct zpub_accepted_bundle *bundle,
    const struct vcs_package_release *release, const uint8_t digest[32],
    const uint8_t *release_body, size_t release_body_len,
    enum zpub_package_facts_state package_facts_state,
    const struct zpub_job_binding *job_binding)
{
    if (!zpub_plan_render_core(reply, bundle, release, digest, release_body,
                               release_body_len))
        return false;
    zpub_common_output(&reply->data, bundle);
    zpub_plan_render_extra(reply, bundle, release, package_facts_state,
                           job_binding);
    return true;
}

void zcl_native_handle_zcode_publish_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *datadir = zdev_str(request->input, "acceptance_datadir");
    if (!datadir || !datadir[0]) datadir = zdev_str(request->input, "datadir");
    if (zcl_native_forward_live_command(
            request, datadir, "zcode_publish_plan_owned",
            "LIVE_PUBLISH_PLAN_FAILED", "plan", "zcode.publish.plan",
            reply))
        return;
    struct zpub_accepted_bundle bundle;
    if (!zpub_normalize(request, reply, &bundle) ||
        !zpub_find_lane_readonly(request, reply, &bundle) ||
        !zpub_prepare_accepted_objects(request, reply, &bundle))
        return;
    struct zpub_job_binding job_binding;
    if (!zpub_job_preflight(request, reply, &bundle, &job_binding)) {
        zpub_bundle_free(&bundle);
        return;
    }

    struct zpub_package_facts package_facts;
    enum zpub_package_facts_state package_facts_state;
    const char *name, *semver, *license;
    if (!zpub_plan_resolve_facts(request, &bundle, &package_facts,
                                 &package_facts_state, &name, &semver,
                                 &license, reply))
        return;

    struct vcs_package_release release;
    uint8_t *release_body = NULL;
    size_t release_body_len = 0;
    uint8_t digest[32];
    if (!zpub_plan_build_release(request, &bundle, name, semver, license,
                                 &release, &release_body, &release_body_len,
                                 digest, reply))
        return;

    bool rendered = zpub_plan_render(
        reply, &bundle, &release, digest, release_body, release_body_len,
        package_facts_state, &job_binding);
    free(release_body);
    zpub_bundle_free(&bundle);
    if (!rendered)
        zpub_fail(reply, "RELEASE_PLAN_OUTPUT",
                  "bounded canonical publication plan could not be rendered");
}

/* Decode, verify, and lineage-check the offline-signed release envelope. */
static bool zpub_commit_verify_release(
    const struct zcl_command_request *request,
    struct zpub_accepted_bundle *bundle, struct vcs_package_release *release,
    uint8_t release_id[32], uint8_t **release_wire, size_t *release_wire_len,
    struct zcl_command_reply *reply)
{
    const char *release_hex_input = zdev_str(request->input, "release_hex");
    bool release_ok =
        zpub_decode_hex(release_hex_input, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
                        release_wire, release_wire_len) &&
        vcs_package_release_parse(*release_wire, *release_wire_len,
                                  release) == VCS_PACKAGE_RELEASE_OK &&
        vcs_package_release_verify(release) == VCS_PACKAGE_RELEASE_OK &&
        vcs_package_release_id(release, release_id) ==
            VCS_PACKAGE_RELEASE_OK &&
        memcmp(release->package_root,
               bundle->transport.package_root, 32) == 0 &&
        memcmp(release->recipe_root,
               bundle->transport.recipe_root, 32) == 0;
    char expected_chain[VCS_PACKAGE_RELEASE_CHAIN_ID_MAX + 1u];
    release_ok = release_ok &&
        vcs_package_accept_chain_id(expected_chain, sizeof(expected_chain)) &&
        strcmp(release->chain_id, expected_chain) == 0;
    char zcode_dir[ZPUB_PATH_MAX];
    int n = snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode",
                     bundle->datadir);
    release_ok = release_ok && n > 0 && (size_t)n < sizeof(zcode_dir) &&
        zpub_release_lineage_valid(zcode_dir, release, release_id);
    if (!release_ok) {
        free(*release_wire);
        *release_wire = NULL;
        zpub_bundle_free(bundle);
        zpub_fail(reply, "SIGNED_RELEASE_INVALID",
                  "release_hex must be one canonical verified offline-signed "
                  "envelope binding the accepted package, recipe, chain, "
                  "and current publisher lineage");
        return false;
    }
    return true;
}

/* Stage the verified CAS source bytes into a fresh temporary directory. */
static bool zpub_commit_stage(
    struct zpub_accepted_bundle *bundle, char staging[ZPUB_PATH_MAX],
    uint8_t *release_wire, struct zcl_command_reply *reply)
{
    bool stage_created = zpub_stage_create(bundle->datadir, staging);
    bool staged = stage_created &&
        zpub_stage_transport(staging, &bundle->transport);
    if (!staged) {
        if (stage_created) zpub_stage_cleanup(staging, &bundle->transport);
        free(release_wire);
        zpub_bundle_free(bundle);
        zpub_fail(reply, "SOURCE_STAGE_FAILED",
                  "verified CAS source bytes could not be staged in the "
                  "explicit datadir");
        return false;
    }
    return true;
}

/* Build the hex-encoded input for the existing package.publish commit
 * handler, which performs the actual store/index write. */
static bool zpub_commit_build_input(
    const struct zcl_command_request *request,
    struct zpub_accepted_bundle *bundle, const char *staging,
    const uint8_t *release_wire, size_t release_wire_len,
    struct json_value *commit_input, struct zcl_command_reply *reply)
{
    char *release_hex =
        zcl_malloc(release_wire_len * 2u + 1u, "zcode.publish.release_hex");
    char *manifest_hex =
        zcl_malloc(bundle->transport.manifest_wire_len * 2u + 1u,
                   "zcode.publish.manifest_hex");
    char *recipe_hex =
        zcl_malloc(bundle->transport.recipe_wire_len * 2u + 1u,
                   "zcode.publish.recipe_hex");
    if (!release_hex || !manifest_hex || !recipe_hex) {
        zpub_stage_cleanup(staging, &bundle->transport);
        free(release_hex);
        free(manifest_hex);
        free(recipe_hex);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC", "publish",
                               false, false, "hex wire buffers",
                               "zcode.publish");
        return false;
    }
    zcl_hex_encode(release_wire, release_wire_len, release_hex);
    zcl_hex_encode(bundle->transport.manifest_wire,
                   bundle->transport.manifest_wire_len, manifest_hex);
    zcl_hex_encode(bundle->transport.recipe_wire,
                   bundle->transport.recipe_wire_len, recipe_hex);
    json_init(commit_input);
    json_set_object(commit_input);
    (void)json_push_kv_str(commit_input, "release_hex", release_hex);
    (void)json_push_kv_str(commit_input, "manifest_hex", manifest_hex);
    (void)json_push_kv_str(commit_input, "recipe_hex", recipe_hex);
    (void)json_push_kv_str(commit_input, "dir", staging);
    (void)json_push_kv_str(commit_input, "datadir", bundle->datadir);
    const struct json_value *day = json_get(request->input, "day");
    if (day)
        (void)json_push_kv_int(commit_input, "day", json_get_int(day));
    free(release_hex);
    free(manifest_hex);
    free(recipe_hex);
    return true;
}

/* Map the inner package.publish commit failure onto our own reply. */
static void zpub_commit_map_failure(
    struct zcl_command_reply *reply, struct zcl_command_reply *commit_reply)
{
    char code[72], message[192], evidence[256];
    (void)snprintf(code, sizeof(code), "%s",
                   commit_reply->error.code[0]
                       ? commit_reply->error.code
                       : "PUBLISH_COMMIT_FAILED");
    (void)snprintf(message, sizeof(message), "%s",
                   commit_reply->error.message);
    (void)snprintf(evidence, sizeof(evidence), "%s",
                   commit_reply->error.evidence);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "validate",
                           false, false, message, evidence);
}

/* Bind the CAS release object into the exact publication job progress, if
 * one was requested; a request without a job binding always progresses. */
static bool zpub_commit_progress(
    struct zpub_accepted_bundle *bundle, const struct zpub_job_binding *job_binding,
    const uint8_t release_id[32], uint8_t *release_wire, size_t release_wire_len,
    uint8_t progress_root[32], bool *progress_reused, bool *release_repaired)
{
    *progress_reused = false;
    *release_repaired = false;
    bool release_bound = !job_binding->requested ||
        (vcs_object_store_init(bundle->workspace) &&
         vcs_object_put_addressed_repair(
             bundle->workspace, release_id, release_wire, release_wire_len,
             release_repaired));
    return release_bound && (!job_binding->requested ||
        vcs_devloop_publication_advance_release(
            bundle->workspace, job_binding->job_root, bundle->mapping_root,
            release_id, progress_root, progress_reused));
}

static void zpub_commit_render(
    struct zcl_command_reply *reply, const struct zpub_accepted_bundle *bundle,
    const struct zpub_job_binding *job_binding, const uint8_t progress_root[32],
    const uint8_t release_id[32], bool progress_reused, bool release_repaired)
{
    zpub_common_output(&reply->data, bundle);
    if (!job_binding->requested) return;
    zdev_push_root(&reply->data, "publication_job_root", job_binding->job_root);
    zdev_push_root(&reply->data, "progress_receipt_root", progress_root);
    zdev_push_root(&reply->data, "release_root", release_id);
    (void)json_push_kv_str(&reply->data, "publication_status",
                           "RELEASE_PUBLISHED");
    (void)json_push_kv_bool(&reply->data, "progress_reused", progress_reused);
    (void)json_push_kv_bool(&reply->data, "release_cas_repaired",
                            release_repaired);
}

/* Stage the release, invoke the inner package-publish-commit handler, and
 * clean up staging. On failure, replies and frees everything belonging to
 * this attempt (including release_wire and bundle) and returns false; the
 * caller must then simply return. */
static bool zpub_commit_run_inner(
    const struct zcl_command_request *request,
    struct zpub_accepted_bundle *bundle, uint8_t *release_wire,
    size_t release_wire_len, struct zcl_command_reply *reply,
    struct zcl_command_reply *commit_reply)
{
    char staging[ZPUB_PATH_MAX] = {0};
    if (!zpub_commit_stage(bundle, staging, release_wire, reply)) {
        free(release_wire);
        return false;
    }

    struct json_value commit_input;
    if (!zpub_commit_build_input(request, bundle, staging, release_wire,
                                 release_wire_len, &commit_input, reply)) {
        free(release_wire);
        return false;
    }
    struct zcl_command_request commit_request = { .input = &commit_input };
    zcl_command_reply_init(commit_reply, "zcl.zcode_publish_commit.v1");
    zcl_native_handle_zcode_package_publish_commit(
        &commit_request, commit_reply);
    zpub_stage_cleanup(staging, &bundle->transport);
    json_free(&commit_input);

    if (commit_reply->exit_code != ZCL_COMMAND_EXIT_OK) {
        zpub_commit_map_failure(reply, commit_reply);
        free(release_wire);
        zcl_command_reply_free(commit_reply);
        zpub_bundle_free(bundle);
        return false;
    }
    return true;
}

/* Advance the durable publication-job receipt and render the final reply
 * (or, on progress failure, an idempotency-safe retry error). Always frees
 * release_wire, commit_reply, and bundle. */
static void zpub_commit_finish(
    struct zcl_command_reply *reply, struct zpub_accepted_bundle *bundle,
    struct zpub_job_binding *job_binding, uint8_t release_id[32],
    uint8_t *release_wire, size_t release_wire_len,
    struct zcl_command_reply *commit_reply)
{
    uint8_t progress_root[32];
    bool progress_reused, release_repaired;
    bool progressed = zpub_commit_progress(
        bundle, job_binding, release_id, release_wire, release_wire_len,
        progress_root, &progress_reused, &release_repaired);
    free(release_wire);
    if (!progressed) {
        char release_id_hex[65];
        zcl_hex_encode(release_id, 32, release_id_hex);
        zcl_command_reply_free(commit_reply);
        zpub_bundle_free(bundle);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "PUBLICATION_PROGRESS_FAILED", "schedule", true, true,
            "the signed package release was published, but its durable job "
            "receipt could not advance; retry the exact idempotent commit",
            release_id_hex);
        return;
    }
    json_copy(&reply->data, &commit_reply->data);
    zcl_command_reply_free(commit_reply);
    zpub_commit_render(reply, bundle, job_binding, progress_root,
                       release_id, progress_reused, release_repaired);
    zpub_bundle_free(bundle);
}

void zcl_native_handle_zcode_publish_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *datadir = zdev_str(request->input, "acceptance_datadir");
    if (!datadir || !datadir[0]) datadir = zdev_str(request->input, "datadir");
    if (zcl_native_forward_live_command(
            request, datadir, "zcode_publish_commit_owned",
            "LIVE_PUBLISH_COMMIT_FAILED", "publish",
            "zcode.publish.commit", reply))
        return;
    struct zpub_accepted_bundle bundle;
    if (!zpub_normalize(request, reply, &bundle) ||
        !zpub_find_lane_commit(request, reply, &bundle) ||
        !zpub_prepare_accepted_objects(request, reply, &bundle))
        return;
    struct zpub_job_binding job_binding;
    if (!zpub_job_preflight(request, reply, &bundle, &job_binding)) {
        zpub_bundle_free(&bundle);
        return;
    }

    struct vcs_package_release release;
    uint8_t release_id[32];
    uint8_t *release_wire = NULL;
    size_t release_wire_len = 0;
    if (!zpub_commit_verify_release(request, &bundle, &release, release_id,
                                    &release_wire, &release_wire_len, reply))
        return;

    struct zcl_command_reply commit_reply;
    if (!zpub_commit_run_inner(request, &bundle, release_wire,
                               release_wire_len, reply, &commit_reply))
        return;

    zpub_commit_finish(reply, &bundle, &job_binding, release_id,
                       release_wire, release_wire_len, &commit_reply);
}
