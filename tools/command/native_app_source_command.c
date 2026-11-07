/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Join verified saved app source and its existing build into an exclusive inert export. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "command/native_app_source_command.h"
#include "command/native_command.h"
#include "command/native_zcode_package_copy.h"
#if !defined(_WIN32)
#include "command/app_copy_build.h"
#include "command/app_image.h"
#include "command/app_installed_source.h"
#include "command/app_seed.h"
#include "command/native_package_artifact.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "platform/directory_compat.h"
#include "platform/directory_transaction.h"
#include "platform/temp_directory.h"
#include "platform/rename_compat.h"
#include "util/file_tree_ops.h"
#include "util/path_util.h"
#include "vcs/package_prepare.h"
#include "vcs/source_bundle.h"
#include "vcs/vcs_manifest.h"
#include "vcs/vcs_object.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define ASE_COMMAND "app.source.export"
#define ASE_PATH 4400u
#define ASE_IMAGE "image"
struct ase_work {
    const struct zcl_command_request *request;
    struct zcl_command_reply *reply;
    const char *app, *datadir, *version;
    char copy_dir[ASE_PATH], output[ASE_PATH], parent_path[ASE_PATH];
    char leaf[256], staging[ASE_PATH], scratch[ASE_PATH], snapshot[ASE_PATH];
    uint8_t env[32], deps[32], wanted_record[32], projection_hash[32];
    struct zcl_package_copy copy;
    struct vcs_package_prepared prepared;
    struct app_image_build record;
    struct platform_directory_transaction parent, staged;
    uint8_t *bundle, *image;
    size_t bundle_len, image_len, projection_len;
    uint8_t record_wire[APP_IMAGE_BUILD_WIRE_BYTES];
    char projection[APP_INSTALLED_SOURCE_PROJECTION_MAX + 1];
    bool staging_owned, published, uncertain, scratch_retained, scratch_owned;
};
static bool ase_fail(struct ase_work *w, const char *code, const char *why)
{
    zcl_package_copy_fail(w->reply, code, w->staging_owned || w->published || w->uncertain || w->scratch_retained,
                          why, ASE_COMMAND);
    return false;
}
static bool ase_keys(const struct json_value *in)
{
    static const char *const keys[] = {"app", "copy", "version", "env_root",
        "dependency_root", "record_id", "artifact_dir", "datadir"};
    if (!in || in->type != JSON_OBJ) return false;
    unsigned seen = 0;
    for (size_t i = 0; i < in->num_children; ++i) {
        unsigned bit = 0;
        for (unsigned j = 0; j < sizeof(keys) / sizeof(keys[0]); ++j)
            if (!strcmp(in->keys[i], keys[j])) bit = 1u << j;
        if (!bit || (seen & bit) || in->children[i].type != JSON_STR) return false;
        const char *value = json_get_str(&in->children[i]);
        if (!value || !*value || strlen(value) >= ASE_PATH) return false;
        seen |= bit;
    }
    return (seen & 127u) == 127u;
}
static bool ase_inputs(struct ase_work *w)
{
    const struct json_value *in = w->request->input;
    if (!ase_keys(in)) return ase_fail(w, "BAD_INPUT", "Provide the seven exact export fields and optional datadir.");
    w->app = zcl_package_copy_str(in, "app"); w->version = zcl_package_copy_str(in, "version");
    uint8_t version[32];
    if (!w->app || !app_seed_name_valid(w->app) || strlen(w->app) > APP_INSTALLED_SOURCE_APP_MAX ||
        !zcl_hex_decode_lower(zcl_package_copy_str(in, "version"), version, 32)) return ase_fail(w, "BAD_INPUT", "Invalid app or saved version.");
    if (!zcl_hex_decode_lower(zcl_package_copy_str(in, "env_root"), w->env, 32) ||
        !zcl_hex_decode_lower(zcl_package_copy_str(in, "dependency_root"), w->deps, 32) ||
        !zcl_hex_decode_lower(zcl_package_copy_str(in, "record_id"), w->wanted_record, 32)) return ase_fail(w, "BAD_INPUT", "Build identities must be exact lowercase roots.");
    w->datadir = zcl_package_copy_datadir(in, w->reply, ASE_COMMAND);
    const char *copy = zcl_package_copy_str(in, "copy");
    return w->datadir && copy && app_copy_build_dir(w->datadir, copy, w->copy_dir, sizeof(w->copy_dir), w->reply);
}
static bool ase_output_path(struct ase_work *w)
{
    const char *out = zcl_package_copy_str(w->request->input, "artifact_dir");
    if (!out || out[0] != '/' || strlen(out) >= sizeof(w->output))
        return ase_fail(w, "BAD_ARTIFACT_DIR", "Export requires an absolute absent directory under an existing private parent.");
    memcpy(w->output, out, strlen(out) + 1); memcpy(w->parent_path, out, strlen(out) + 1);
    char *slash = strrchr(w->parent_path, '/');
    if (!slash || !slash[1] || strlen(slash + 1) >= sizeof(w->leaf))
        return ase_fail(w, "BAD_ARTIFACT_DIR", "Invalid export directory leaf.");
    memcpy(w->leaf, slash + 1, strlen(slash + 1) + 1); *slash = 0;
    return true;
}
static bool ase_destination(struct ase_work *w)
{
    if (!ase_output_path(w)) return false;
    size_t copy_len = strlen(w->copy_dir);
    if (!strncmp(w->output, w->copy_dir, copy_len) &&
        (w->output[copy_len] == '/' || w->output[copy_len] == 0))
        return ase_fail(w, "BAD_ARTIFACT_DIR", "Export must not write inside the source copy.");
    char canonical[ASE_PATH];
    if (!strcmp(w->leaf, ".") || !strcmp(w->leaf, "..") ||
        !platform_directory_canonical_real(w->parent_path, canonical, sizeof(canonical)) ||
        strcmp(canonical, w->parent_path) || !platform_directory_transaction_open(&w->parent, canonical))
        return ase_fail(w, "BAD_ARTIFACT_PARENT", "Parent must be canonical, private and owned; trusted stable ancestors are required.");
    struct stat st;
    if (!lstat(w->output, &st)) return ase_fail(w, "OUTPUT_EXISTS", "Export never overwrites or merges an existing destination.");
    return errno == ENOENT || ase_fail(w, "ARTIFACT_PROBE_FAILED", "Cannot prove destination absent.");
}
static bool ase_copy(struct ase_work *w)
{
    if (!zcl_package_copy_open_selected_as(w->copy_dir, ZCL_PACKAGE_COPY_READ,
        &w->copy, w->reply, ASE_COMMAND, w->version)) return false;
    enum zcl_package_copy_adoption a = zcl_package_copy_adopted(w->datadir, &w->copy, NULL);
    return a == ZCL_PACKAGE_COPY_ADOPTED || a == ZCL_PACKAGE_COPY_RECEIVED_TRUSTED ||
        ase_fail(w, "NOT_ADOPTED", "Export requires an adopted or trusted received copy.");
}
/* Copy strict verified objects to a fresh private CAS before invoking the
 * existing recovery-capable bundle encoder. No recovery touches the source. */
static bool ase_blob(struct ase_work *w, const struct vcs_entry *entry)
{
    uint8_t *bytes = NULL, hash[32]; size_t len = 0;
    if (vcs_object_get_readonly_bounded(w->copy_dir, entry->blob, VCS_TAG_BLOB,
        (size_t)entry->size, &bytes, &len) != 0) return false;
    bool ok = len == entry->size && vcs_object_put(w->scratch, bytes, len, VCS_TAG_BLOB, hash) &&
        !memcmp(hash, entry->blob, 32);
    free(bytes); return ok;
}
static bool ase_objects(struct ase_work *w, const struct vcs_manifest *m)
{
    uint64_t total = 0;
    for (size_t i = 0; i < m->count; ++i) {
        if (m->entries[i].size > VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES - total) return false;
        total += m->entries[i].size;
        if (!ase_blob(w, &m->entries[i])) return false;
    }
    uint8_t *wire = NULL; size_t len = 0;
    bool ok = vcs_manifest_serialize(m, &wire, &len) &&
        vcs_object_put_addressed(w->scratch, w->copy.selected_tree, wire, len);
    free(wire); return ok;
}
static bool ase_scratch(struct ase_work *w)
{
    if (!platform_temp_directory_create("z23-app-export-", w->scratch, sizeof(w->scratch))) return false;
    w->scratch_owned = true;
    return vcs_object_store_init(w->scratch);
}
static bool ase_snapshot(struct ase_work *w)
{
    struct vcs_manifest m; vcs_manifest_init(&m);
    if (!vcs_tree_load_readonly_bounded(w->copy_dir, w->copy.selected_tree,
        VCS_SOURCE_BUNDLE_MAX_MANIFEST_BYTES, 65536, &m))
        return ase_fail(w, "SOURCE_INVALID", "Saved manifest is missing, aliased, corrupt or oversized.");
    bool ok = ase_scratch(w) && ase_objects(w, &m);
    vcs_manifest_free(&m);
    if (!ok) return ase_fail(w, "SOURCE_INVALID", "Cannot copy the exact bounded saved objects to private scratch.");
    if (!zcl_path_join(w->snapshot, sizeof(w->snapshot), w->scratch, "source") || mkdir(w->snapshot, 0700) ||
        vcs_tree_materialize(w->scratch, w->copy.selected_tree, w->snapshot,
            VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES, 0) != VCS_OK)
        return ase_fail(w, "SNAPSHOT_FAILED", "Cannot materialize the verified saved tree.");
    struct vcs_source_bundle_metrics metrics;
    return vcs_source_bundle_create(w->scratch, w->copy.selected_tree, &w->bundle,
        &w->bundle_len, &metrics) == VCS_SOURCE_BUNDLE_OK ||
        ase_fail(w, "SOURCE_BUNDLE_FAILED", "Cannot encode the exact saved tree.");
}
static bool ase_package(struct ase_work *w)
{
    struct vcs_package_release parent; uint8_t id[32];
    if (zcl_package_copy_find_release(w->datadir, w->copy.parent_release, &parent, id) != ZCL_PACKAGE_COPY_FOUND)
        return ase_fail(w, "RELEASE_UNKNOWN", "Verified copy parent release is unavailable.");
    struct vcs_package_prepare_options o = {.dir = w->snapshot, .publisher_sequence = 1,
        .reward_address = "", .chain_id = parent.chain_id};
    memcpy(o.publisher_pubkey, parent.publisher_pubkey, sizeof(o.publisher_pubkey));
    char why[256] = {0};
    if (vcs_package_prepare(&o, &w->prepared, why, sizeof(why)) != VCS_PACKAGE_PREPARE_OK)
        return ase_fail(w, "PACKAGE_INVALID", why);
    uint8_t deps[32]; app_image_dependency_root(&w->prepared.lock, deps);
    if (memcmp(deps, w->deps, 32)) return ase_fail(w, "DEPENDENCY_MISMATCH", "Saved package dependencies differ from the requested build.");
    if (w->prepared.manifest_wire_len > (1u << 20) || w->prepared.recipe_wire_len > (256u << 10))
        return ase_fail(w, "PACKAGE_LIMIT", "Canonical manifest or recipe exceeds installed-source limits.");
    return true;
}
static bool ase_image(struct ase_work *w, const char *path)
{
    struct app_image_build observed = w->record;
    struct zcl_result r = app_image_capture(path, &observed);
    if (!r.ok || memcmp(observed.image_sha3, w->record.image_sha3, 32) ||
        observed.image_size != w->record.image_size || observed.image_volume != w->record.image_volume ||
        observed.image_low != w->record.image_low || observed.image_high != w->record.image_high)
        return ase_fail(w, "IMAGE_CHANGED", "Stored image no longer matches the actual build record.");
    struct json_value in; json_init(&in); json_set_object(&in);
    char hex[65]; zcl_hex_encode(w->record.image_sha3, 32, hex);
    bool ok = json_push_kv_str(&in, "file", path) && json_push_kv_str(&in, "digest", hex) &&
        zcl_native_package_artifact_read_file(&in, "file", "digest", APP_INSTALLED_SOURCE_IMAGE_MAX,
            &w->image, &w->image_len);
    json_free(&in);
    return (ok && w->image_len == w->record.image_size) ||
        ase_fail(w, "IMAGE_CHANGED", "Cannot retain the exact bounded image bytes.");
}
static bool ase_record(struct ase_work *w)
{
    struct app_copy_build_store store;
    if (!app_copy_build_store(w->datadir, w->copy.fork_version, &store, w->reply)) return false;
    bool hit = false; uint8_t id[32];
    struct zcl_result r = app_image_build_load(store.records, w->prepared.package_root,
        w->env, w->deps, &w->record, &hit);
    if (!r.ok || !hit || !app_image_build_id(&w->record, id).ok || memcmp(id, w->wanted_record, 32))
        return ase_fail(w, "BUILD_RECORD_MISMATCH", "No exact existing build record for the selected package and requested identities.");
    if (w->record.image_size > APP_INSTALLED_SOURCE_IMAGE_MAX)
        return ase_fail(w, "IMAGE_LIMIT", "Recorded image exceeds the installed-source bound.");
    if (!app_image_build_encode(&w->record, w->record_wire).ok)
        return ase_fail(w, "BUILD_RECORD_INVALID", "Cannot encode the existing build record.");
    char hex[65], path[ASE_PATH]; zcl_hex_encode(w->record.image_sha3, 32, hex);
    if (!zcl_path_join(path, sizeof(path), store.images, hex)) return ase_fail(w, "IMAGE_PATH", "Image path exceeds the bound.");
    return ase_image(w, path);
}
static bool ase_hex(struct json_value *j, const char *key, const uint8_t hash[32])
{
    char hex[65]; zcl_hex_encode(hash, 32, hex); return json_push_kv_str(j, key, hex);
}
static bool ase_member(struct json_value *j, const char *file_key, const char *file,
    const char *digest_key, const uint8_t *bytes, size_t len)
{
    uint8_t hash[32]; zcl_native_package_artifact_digest(hash, bytes, len);
    return json_push_kv_str(j, file_key, file) && ase_hex(j, digest_key, hash);
}
static bool ase_projection_members(struct ase_work *w, struct json_value *j)
{
    return ase_member(j, "bundle_file", APP_INSTALLED_SOURCE_BUNDLE, "bundle_sha3", w->bundle, w->bundle_len) &&
        ase_member(j, "manifest_file", APP_INSTALLED_SOURCE_MANIFEST, "manifest_sha3",
            w->prepared.manifest_wire, w->prepared.manifest_wire_len) &&
        ase_member(j, "recipe_file", APP_INSTALLED_SOURCE_RECIPE, "recipe_sha3",
            w->prepared.recipe_wire, w->prepared.recipe_wire_len) &&
        ase_member(j, "record_file", APP_INSTALLED_SOURCE_RECORD, "record_sha3", w->record_wire, sizeof(w->record_wire));
}
static bool ase_projection(struct ase_work *w)
{
    struct json_value j; json_init(&j); json_set_object(&j);
    bool ok = json_push_kv_str(&j, "schema", APP_INSTALLED_SOURCE_SCHEMA) && json_push_kv_str(&j, "app", w->app) &&
        ase_projection_members(w, &j) && ase_hex(&j, "tree_root", w->copy.selected_tree) &&
        ase_hex(&j, "package_root", w->prepared.package_root) && ase_hex(&j, "recipe_root", w->prepared.recipe_root) &&
        ase_hex(&j, "record_id", w->wanted_record) && ase_hex(&j, "image_sha3", w->record.image_sha3);
    if (ok) w->projection_len = json_write(&j, w->projection, sizeof(w->projection));
    json_free(&j);
    if (!ok || !w->projection_len || w->projection_len > APP_INSTALLED_SOURCE_PROJECTION_MAX)
        return ase_fail(w, "PROJECTION_FAILED", "Cannot encode the bounded canonical source projection.");
    zcl_native_package_artifact_digest(w->projection_hash, (const uint8_t *)w->projection, w->projection_len);
    return true;
}
static bool ase_write(struct ase_work *w, const char *leaf, const void *bytes, size_t size, bool executable)
{
    struct platform_directory_child f; platform_directory_child_init(&f);
    if (!platform_directory_child_create(&w->staged, leaf, &f)) return false;
    bool ok = platform_directory_child_write_exact(&f, bytes, size, 0);
    if (ok && executable) ok = fchmod((int)f.native, 0700) == 0;
    ok = ok && platform_directory_child_flush(&f);
    platform_directory_child_close(&f); return ok;
}
static bool ase_stage_files(struct ase_work *w)
{
    return ase_write(w, APP_INSTALLED_SOURCE_BUNDLE, w->bundle, w->bundle_len, false) &&
        ase_write(w, APP_INSTALLED_SOURCE_MANIFEST, w->prepared.manifest_wire, w->prepared.manifest_wire_len, false) &&
        ase_write(w, APP_INSTALLED_SOURCE_RECIPE, w->prepared.recipe_wire, w->prepared.recipe_wire_len, false) &&
        ase_write(w, APP_INSTALLED_SOURCE_RECORD, w->record_wire, sizeof(w->record_wire), false) &&
        ase_write(w, ASE_IMAGE, w->image, w->image_len, true) &&
        ase_write(w, APP_INSTALLED_SOURCE_PROJECTION, w->projection, w->projection_len, false) &&
        platform_directory_transaction_flush(&w->staged);
}
/* POSIX retained descriptors; the existing no-clobber primitive refuses on
 * hosts without an exclusive rename. No pathname fallback is permitted. */
static bool ase_move(struct ase_work *w, const char *leaf)
{
    int parent = (int)w->parent.native, staged = (int)w->staged.native;
    struct stat held, named;
    if (fstat(staged, &held) || fstatat(parent, leaf, &named, AT_SYMLINK_NOFOLLOW) ||
        held.st_dev != named.st_dev || held.st_ino != named.st_ino)
        return ase_fail(w, "EXPORT_STAGE_CHANGED", "Staging name no longer identifies the retained directory.");
    if (platform_renameat_noreplace(parent, leaf, parent, w->leaf))
        return ase_fail(w, "EXPORT_PUBLISH_FAILED", "Exclusive publication refused; staging retained, no overwrite attempted.");
    w->published = true; w->staging_owned = false;
    if (fstatat(parent, w->leaf, &named, AT_SYMLINK_NOFOLLOW) ||
        held.st_dev != named.st_dev || held.st_ino != named.st_ino || fsync(parent)) {
        w->uncertain = true;
        return ase_fail(w, "EXPORT_OUTCOME_UNKNOWN", "Directory moved but identity or durability confirmation failed; preserve both names.");
    }
    return true;
}
static bool ase_publish(struct ase_work *w)
{
    int n = snprintf(w->staging, sizeof(w->staging), "%s/.app-export-XXXXXX", w->parent_path);
    if (n < 0 || (size_t)n >= sizeof(w->staging) || !mkdtemp(w->staging))
        return ase_fail(w, "EXPORT_STAGE_FAILED", "Cannot create private output staging directory.");
    w->staging_owned = true;
    if (!platform_directory_transaction_open(&w->staged, w->staging) || !ase_stage_files(w))
        return ase_fail(w, "EXPORT_WRITE_FAILED", "Staging member or durability operation failed.");
    const char *leaf = strrchr(w->staging, '/') + 1;
    return ase_move(w, leaf);
}
static bool ase_result(struct ase_work *w)
{
    return json_push_kv_str(&w->reply->data, "artifact_dir", w->output) &&
        json_push_kv_str(&w->reply->data, "image_file", ASE_IMAGE) &&
        json_push_kv_str(&w->reply->data, "app", w->app) &&
        ase_hex(&w->reply->data, "version", w->copy.selected_version) &&
        ase_hex(&w->reply->data, "tree_root", w->copy.selected_tree) &&
        ase_hex(&w->reply->data, "package_root", w->prepared.package_root) &&
        ase_hex(&w->reply->data, "recipe_root", w->prepared.recipe_root) &&
        ase_hex(&w->reply->data, "env_root", w->record.env_root) &&
        ase_hex(&w->reply->data, "dependency_root", w->record.dependency_root) &&
        ase_hex(&w->reply->data, "image_sha3", w->record.image_sha3) &&
        ase_hex(&w->reply->data, "record_id", w->wanted_record) &&
        ase_hex(&w->reply->data, "projection_sha3", w->projection_hash);
}
static bool ase_result_ready(struct ase_work *w)
{
    if (!ase_result(w)) return ase_fail(w, "EXPORT_REPLY_FAILED", "Cannot allocate bounded export facts before publication.");
    size_t budget = 8192;
    if (w->request->success_data_budget_provided && w->request->success_data_budget < budget)
        budget = w->request->success_data_budget;
    size_t length = json_write(&w->reply->data, NULL, 0);
    struct json_value reserve; json_init(&reserve); json_set_object(&reserve);
    bool ok = json_push_kv_str(&reserve, "staging_dir", w->output) &&
        json_push_kv_str(&reserve, "retained_scratch", w->scratch);
    size_t extra = json_write(&reserve, NULL, 0);
    json_free(&reserve);
    /* Reserve for a sibling staging name, uncertainty and the error envelope,
     * not only the successful data. Preserve paths on post-mutation refusal. */
    if (!ok || length > budget || length + extra + 1536 > ZCL_COMMAND_ERROR_BUDGET) {
        json_free(&w->reply->data); json_set_object(&w->reply->data);
        return ase_fail(w, "EXPORT_REPLY_LIMIT", "Escaped artifact paths exceed the bounded success/failure reply.");
    }
    return true;
}
static void ase_cleanup(struct ase_work *w)
{
    platform_directory_transaction_close(&w->staged);
    platform_directory_transaction_close(&w->parent);
    if (w->staging_owned || w->uncertain) {
        w->reply->error.mutated = true;
        (void)json_push_kv_str(&w->reply->data, "staging_dir", w->staging);
        if (!json_get(&w->reply->data, "artifact_dir"))
            (void)json_push_kv_str(&w->reply->data, "artifact_dir", w->output);
        (void)json_push_kv_bool(&w->reply->data, "publication_uncertain", w->uncertain);
    }
    if (w->scratch_owned) {
        struct zcl_result r = zcl_tree_remove(w->scratch);
        if (!r.ok) {
            w->scratch_retained = true;
            w->reply->error.mutated = true;
            (void)json_push_kv_str(&w->reply->data, "retained_scratch", w->scratch);
            if (w->reply->status == ZCL_COMMAND_STATUS_PASSED)
                (void)ase_fail(w, "EXPORT_CLEANUP_FAILED", "Export completed but private source scratch cleanup failed.");
        }
    }
    zcl_package_copy_close(&w->copy); vcs_package_prepared_free(&w->prepared);
    free(w->bundle); free(w->image);
}
#endif
void zcl_native_handle_app_source_export(const struct zcl_command_request *request,
                                       struct zcl_command_reply *reply)
{
    if (!reply) return;
    if (!request) { zcl_package_copy_fail(reply, "BAD_INPUT", false, "Missing export request.", "app.source.export"); return; }
#if defined(_WIN32)
    (void)request;
    zcl_package_copy_fail(reply, "UNSUPPORTED_PLATFORM", false,
        "Exclusive installed-source export is not qualified on Windows.", "app.source.export");
#else
    struct ase_work *w = zcl_calloc(1, sizeof(*w), "app.source.export");
    if (!w) { zcl_package_copy_fail(reply, "OUT_OF_MEMORY", false, "Cannot allocate export state.", ASE_COMMAND); return; }
    w->request = request; w->reply = reply;
    vcs_package_prepared_init(&w->prepared);
    platform_directory_transaction_init(&w->parent); platform_directory_transaction_init(&w->staged);
    bool ok = ase_inputs(w) && ase_destination(w) && ase_copy(w) && ase_snapshot(w) &&
        ase_package(w) && ase_record(w) && ase_projection(w) && ase_result_ready(w) && ase_publish(w);
    if (ok) reply->error.mutated = true;
    ase_cleanup(w); free(w);
#endif
}
