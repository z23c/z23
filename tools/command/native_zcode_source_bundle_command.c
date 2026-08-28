/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: typed operator surface for Git-free ZVCS source transport. */

#include "command/native_command.h"

#include "base/hex.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/directory_transaction.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"
#include "util/safe_alloc.h"
#include "vcs/source_bundle.h"
#include "vcs/source_package_checkout.h"
#include "vcs/package_store.h"
#include "vcs/vcs.h"

#if !defined(_WIN32)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

#define ZSB_PATH_MAX 4400

static const char *zsb_str(const struct json_value *input, const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static void zsb_fail(struct zcl_command_reply *reply, const char *code,
                     const char *stage, const char *detail)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, stage, false,
                           false, detail, "zcode.workspace.source.bundle");
}

static bool zsb_root(const struct json_value *input, uint8_t out[32])
{
    const char *hex = zsb_str(input, "source_root");
    return hex && zcl_hex_decode_lower(hex, out, 32);
}

static bool zsb_named_root(const struct json_value *input, const char *key,
                           uint8_t out[32])
{
    const char *hex = zsb_str(input, key);
    return hex && zcl_hex_decode_lower(hex, out, 32);
}

static bool zsb_paths_disjoint(const char *left, const char *right)
{
    size_t left_len = strlen(left), right_len = strlen(right);
#if defined(_WIN32)
    return _stricmp(left, right) != 0 &&
        !(left_len < right_len && _strnicmp(left, right, left_len) == 0 &&
          (right[left_len] == '/' || right[left_len] == '\\')) &&
        !(right_len < left_len && _strnicmp(right, left, right_len) == 0 &&
          (left[right_len] == '/' || left[right_len] == '\\'));
#else
    return strcmp(left, right) != 0 &&
        !(left_len < right_len && strncmp(left, right, left_len) == 0 &&
          right[left_len] == '/') &&
        !(right_len < left_len && strncmp(right, left, right_len) == 0 &&
          left[right_len] == '/');
#endif
}

static uint8_t *zsb_read(const char *path, size_t *len_out)
{
    *len_out = 0;
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!path || !platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &before) ||
        before.size == 0 || before.size > VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES) {
        platform_positioned_file_close(&file);
        return NULL;
    }
    size_t len = (size_t)before.size;
    uint8_t *bytes = zcl_malloc(len, "zcode.workspace.source.bundle.read");
    if (!bytes) { platform_positioned_file_close(&file); return NULL; }
    size_t off = 0;
    while (off < len) {
        int64_t got = platform_positioned_file_read(
            &file, bytes + off, len - off, off);
        if (got <= 0) break;
        off += (size_t)got;
    }
    bool ok = off == len && platform_positioned_file_snapshot(&file, &after) &&
        platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    if (!ok) { free(bytes); return NULL; }
    *len_out = len;
    return bytes;
}

static bool zsb_write_exclusive(const char *path, const uint8_t *bytes,
                                size_t len)
{
#if defined(_WIN32)
    char resolved[ZSB_PATH_MAX], parent[ZSB_PATH_MAX];
    if (!path || !bytes || !platform_private_path_resolve(
            path, resolved, sizeof(resolved), parent, sizeof(parent)))
        return false;
    const char *slash = strrchr(resolved, '\\');
    if (!slash) slash = strrchr(resolved, '/');
    const char *leaf = slash ? slash + 1 : NULL;
    struct platform_directory_transaction directory;
    struct platform_directory_child file;
    platform_directory_transaction_init(&directory);
    platform_directory_child_init(&file);
    bool created = leaf && leaf[0] &&
        platform_directory_transaction_open(&directory, parent) &&
        platform_directory_child_create(&directory, leaf, &file);
    bool ok = created &&
        platform_directory_child_write_exact(&file, bytes, len, 0) &&
        platform_directory_child_flush(&file) &&
        platform_directory_transaction_flush(&directory);
    platform_directory_child_close(&file);
    if (created && !ok)
        (void)platform_directory_child_unlink(&directory, leaf, true);
    platform_directory_transaction_close(&directory);
    return ok;
#else
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                  0400);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < len) {
        ssize_t wrote = write(fd, bytes + off, len - off);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) break;
        off += (size_t)wrote;
    }
    bool ok = off == len;
    if (ok && fsync(fd) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    if (!ok) (void)unlink(path);
    return ok;
#endif
}

static bool zsb_empty_dir(const char *path)
{
#if defined(_WIN32)
    /* The current retained enumeration API intentionally omits reparse
     * points, so it cannot prove an attacker-controlled directory empty.
     * Refuse until an all-entry retained enumeration is available. */
    (void)path;
    return false;
#else
    DIR *dir = opendir(path);
    if (!dir) return false;
    bool empty = true;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) {
            empty = false;
            break;
        }
    }
    return closedir(dir) == 0 && empty;
#endif
}

static void zsb_render(struct json_value *out, const uint8_t root[32],
                       const struct vcs_source_bundle_metrics *metrics)
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    (void)json_push_kv_str(out, "source_root", hex);
    (void)json_push_kv_int(out, "source_bytes",
                           (int64_t)metrics->source_bytes);
    (void)json_push_kv_int(out, "compressed_bytes",
                           (int64_t)metrics->compressed_bytes);
    (void)json_push_kv_int(out, "file_count", metrics->file_count);
    (void)json_push_kv_int(out, "new_bytes", (int64_t)metrics->new_bytes);
    (void)json_push_kv_int(out, "reused_bytes",
                           (int64_t)metrics->reused_bytes);
    (void)json_push_kv_int(out, "new_blobs", metrics->new_blobs);
    (void)json_push_kv_int(out, "reused_blobs", metrics->reused_blobs);
    (void)json_push_kv_bool(out, "manifest_reused",
                            metrics->manifest_reused);
    (void)json_push_kv_bool(out, "repaired", metrics->repaired);
    (void)json_push_kv_bool(out, "git_required", false);
    (void)json_push_kv_bool(out, "source_executed", false);
}

void zcl_native_handle_zcode_source_capture(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace_arg = zsb_str(request->input, "workspace");
    char workspace[ZSB_PATH_MAX];
    uint8_t root[32];
    if (!workspace_arg || !platform_directory_canonical_real(
            workspace_arg, workspace, sizeof(workspace)) ||
        vcs_tree_capture_path(workspace, root) != VCS_OK) {
        zsb_fail(reply, "SOURCE_CAPTURE_REFUSED", "capture",
                 "workspace must resolve and remain byte-stable through the complete ZVCS capture");
        return;
    }
    struct vcs_manifest manifest;
    if (!vcs_tree_load(workspace, root, &manifest)) {
        zsb_fail(reply, "SOURCE_CAPTURE_READBACK_REFUSED", "capture",
                 "captured manifest did not rederive from the ZVCS CAS");
        return;
    }
    uint64_t bytes = 0;
    bool bounded = manifest.count <= UINT32_MAX;
    for (size_t i = 0; bounded && i < manifest.count; i++) {
        bounded = manifest.entries[i].size <= UINT64_MAX - bytes;
        if (bounded) bytes += manifest.entries[i].size;
    }
    bounded = bounded && bytes <= INT64_MAX;
    uint32_t files = bounded ? (uint32_t)manifest.count : 0;
    vcs_manifest_free(&manifest);
    if (!bounded) {
        zsb_fail(reply, "SOURCE_CAPTURE_LIMIT", "capture",
                 "captured source accounting exceeded the typed result bounds");
        return;
    }
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    (void)json_push_kv_str(&reply->data, "source_root", hex);
    (void)json_push_kv_int(&reply->data, "source_bytes", (int64_t)bytes);
    (void)json_push_kv_int(&reply->data, "file_count", files);
    (void)json_push_kv_bool(&reply->data, "accepted", false);
    (void)json_push_kv_bool(&reply->data, "git_required", false);
    (void)json_push_kv_bool(&reply->data, "source_executed", false);
    (void)json_push_kv_str(
        &reply->data, "next",
        "complete the existing proof and explicit zcode work accept lifecycle before publication");
}

void zcl_native_handle_zcode_source_bundle_create(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace = zsb_str(request->input, "workspace");
    const char *output = zsb_str(request->input, "output");
    uint8_t root[32];
    if (!workspace || !output || !zsb_root(request->input, root) ||
        !zcl_native_zcode_workspace_is_explicit_scratch(output)) {
        zsb_fail(reply, "BAD_SOURCE_BUNDLE_CREATE_INPUT", "validate",
                 "workspace, source_root and an explicit scratch output path are required");
        return;
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    struct vcs_source_bundle_metrics metrics;
    enum vcs_source_bundle_result result = vcs_source_bundle_create(
        workspace, root, &wire, &wire_len, &metrics);
    if (result != VCS_SOURCE_BUNDLE_OK ||
        !zsb_write_exclusive(output, wire, wire_len)) {
        free(wire);
        zsb_fail(reply, result == VCS_SOURCE_BUNDLE_OK
                            ? "SOURCE_BUNDLE_OUTPUT_REFUSED"
                            : "SOURCE_BUNDLE_CREATE_REFUSED",
                 "create", result == VCS_SOURCE_BUNDLE_OK
                    ? "output must be a new no-follow file in an existing scratch directory"
                    : vcs_source_bundle_result_string(result));
        return;
    }
    free(wire);
    zsb_render(&reply->data, root, &metrics);
    (void)json_push_kv_str(&reply->data, "output", output);
    (void)json_push_kv_int(&reply->data, "wire_bytes", (int64_t)wire_len);
}

void zcl_native_handle_zcode_source_bundle_verify(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *bundle = zsb_str(request->input, "bundle");
    uint8_t root[32];
    size_t wire_len = 0;
    uint8_t *wire = bundle ? zsb_read(bundle, &wire_len) : NULL;
    struct vcs_source_bundle_metrics metrics;
    enum vcs_source_bundle_result result = wire && zsb_root(request->input, root)
        ? vcs_source_bundle_verify(wire, wire_len, root, &metrics)
        : VCS_SOURCE_BUNDLE_ERR_NULL;
    free(wire);
    if (result != VCS_SOURCE_BUNDLE_OK) {
        zsb_fail(reply, "SOURCE_BUNDLE_VERIFY_REFUSED", "verify",
                 vcs_source_bundle_result_string(result));
        return;
    }
    zsb_render(&reply->data, root, &metrics);
    (void)json_push_kv_bool(&reply->data, "verified", true);
}

void zcl_native_handle_zcode_source_bundle_import(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *bundle = zsb_str(request->input, "bundle");
    const char *workspace = zsb_str(request->input, "workspace");
    char workspace_real[ZSB_PATH_MAX];
    uint8_t root[32];
    if (!bundle || !workspace || !zsb_root(request->input, root) ||
        !zcl_native_zcode_workspace_is_explicit_scratch(workspace) ||
        !platform_directory_canonical_real(
            workspace, workspace_real, sizeof(workspace_real))) {
        zsb_fail(reply, "BAD_SOURCE_BUNDLE_IMPORT_INPUT", "validate",
                 "bundle, source_root and an explicit scratch workspace are required");
        return;
    }
    size_t wire_len = 0;
    uint8_t *wire = zsb_read(bundle, &wire_len);
    struct vcs_source_bundle_metrics metrics;
    enum vcs_source_bundle_result result = wire
        ? vcs_source_bundle_import(wire, wire_len, root, workspace_real,
                                   &metrics)
        : VCS_SOURCE_BUNDLE_ERR_WIRE;
    free(wire);
    if (result != VCS_SOURCE_BUNDLE_OK) {
        zsb_fail(reply, "SOURCE_BUNDLE_IMPORT_REFUSED", "import",
                 vcs_source_bundle_result_string(result));
        return;
    }
    zsb_render(&reply->data, root, &metrics);
    (void)json_push_kv_bool(&reply->data, "imported", true);
}

void zcl_native_handle_zcode_source_bundle_checkout(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *bundle = zsb_str(request->input, "bundle");
    const char *workspace = zsb_str(request->input, "workspace");
    const char *destination = zsb_str(request->input, "destination");
    char workspace_real[ZSB_PATH_MAX];
    char destination_real[ZSB_PATH_MAX];
    uint8_t root[32];
    if (!bundle || !workspace || !destination ||
        !zsb_root(request->input, root) ||
        !zcl_native_zcode_workspace_is_explicit_scratch(workspace) ||
        !zcl_native_zcode_workspace_is_explicit_scratch(destination) ||
        !platform_directory_canonical_real(
            workspace, workspace_real, sizeof(workspace_real)) ||
        !platform_directory_canonical_real(
            destination, destination_real, sizeof(destination_real)) ||
        strcmp(workspace_real, destination_real) == 0 ||
        !zsb_empty_dir(destination_real)) {
        zsb_fail(reply, "BAD_SOURCE_BUNDLE_CHECKOUT_INPUT", "validate",
                 "bundle, source_root, a separate scratch CAS workspace, and an existing empty scratch destination are required");
        return;
    }
    size_t wire_len = 0;
    uint8_t *wire = zsb_read(bundle, &wire_len);
    struct vcs_source_bundle_metrics metrics;
    enum vcs_source_bundle_result result = wire
        ? vcs_source_bundle_import(wire, wire_len, root, workspace_real,
                                   &metrics)
        : VCS_SOURCE_BUNDLE_ERR_WIRE;
    free(wire);
    if (result != VCS_SOURCE_BUNDLE_OK ||
        vcs_tree_materialize(workspace_real, root, destination_real,
                             VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES, 0) != VCS_OK) {
        zsb_fail(reply, result == VCS_SOURCE_BUNDLE_OK
                            ? "SOURCE_BUNDLE_MATERIALIZE_REFUSED"
                            : "SOURCE_BUNDLE_IMPORT_REFUSED",
                 "checkout", result == VCS_SOURCE_BUNDLE_OK
                    ? "verified ZVCS source could not be materialized into the empty destination"
                    : vcs_source_bundle_result_string(result));
        return;
    }
    zsb_render(&reply->data, root, &metrics);
    (void)json_push_kv_bool(&reply->data, "checked_out", true);
    (void)json_push_kv_str(&reply->data, "destination", destination_real);
}

void zcl_native_handle_zcode_source_package_checkout(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *datadir = zsb_str(request->input, "datadir");
    const char *workspace = zsb_str(request->input, "workspace");
    const char *destination = zsb_str(request->input, "destination");
    char workspace_real[ZSB_PATH_MAX], destination_real[ZSB_PATH_MAX];
    uint8_t package_root[32], source_root[32], accepted_work_root[32];
    bool valid = datadir && workspace && destination &&
        zsb_named_root(request->input, "package_root", package_root) &&
        zsb_named_root(request->input, "accepted_work_root",
                       accepted_work_root) &&
        zsb_root(request->input, source_root) &&
        zcl_native_zcode_workspace_is_explicit_scratch(workspace) &&
        zcl_native_zcode_workspace_is_explicit_scratch(destination) &&
        platform_directory_canonical_real(
            workspace, workspace_real, sizeof(workspace_real)) &&
        platform_directory_canonical_real(
            destination, destination_real, sizeof(destination_real)) &&
        zsb_paths_disjoint(workspace_real, destination_real) &&
        zsb_empty_dir(destination_real);
    if (!valid) {
        zsb_fail(reply, "BAD_SOURCE_PACKAGE_CHECKOUT_INPUT", "validate",
                 "datadir, package_root, source_root, accepted_work_root, a separate scratch CAS workspace, and an existing empty scratch destination are required");
        return;
    }
    struct vcs_package_store *store = vcs_package_store_open(
        datadir, vcs_package_store_quota_bytes());
    if (!store) {
        zsb_fail(reply, "SOURCE_PACKAGE_STORE_REFUSED", "open",
                 "the existing content.v2 package store could not be opened");
        return;
    }
    struct vcs_source_package_checkout_metrics metrics;
    enum vcs_source_package_checkout_result result =
        vcs_source_package_checkout_accepted(
            store, package_root, source_root, accepted_work_root,
            workspace_real, destination_real, &metrics);
    vcs_package_store_close(store);
    if (result != VCS_SOURCE_PACKAGE_CHECKOUT_OK) {
        zsb_fail(reply, "SOURCE_PACKAGE_CHECKOUT_REFUSED", "checkout",
                 vcs_source_package_checkout_result_string(result));
        return;
    }
    zsb_render(&reply->data, source_root, &metrics.source);
    char package_hex[65];
    zcl_hex_encode(package_root, 32, package_hex);
    (void)json_push_kv_str(&reply->data, "package_root", package_hex);
    (void)json_push_kv_int(&reply->data, "source_shards",
                           metrics.source_shards);
    (void)json_push_kv_int(&reply->data, "offline_input_bytes",
                           (int64_t)metrics.offline_input_bytes);
    (void)json_push_kv_int(&reply->data, "offline_input_files",
                           metrics.offline_input_files);
    (void)json_push_kv_int(&reply->data, "carrier_files",
                           metrics.carrier_files);
    char accepted_hex[65], signer_hex[65];
    zcl_hex_encode(accepted_work_root, 32, accepted_hex);
    zcl_hex_encode(metrics.accepted_signer, 32, signer_hex);
    (void)json_push_kv_str(&reply->data, "accepted_work_root", accepted_hex);
    (void)json_push_kv_str(&reply->data, "accepted_signer", signer_hex);
    (void)json_push_kv_int(&reply->data, "authority_objects",
                           metrics.authority_objects);
    (void)json_push_kv_int(&reply->data, "work_receipts",
                           metrics.work_receipts);
    (void)json_push_kv_bool(&reply->data, "checked_out", true);
    (void)json_push_kv_str(&reply->data, "destination", destination_real);
}
