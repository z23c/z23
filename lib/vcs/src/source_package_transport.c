/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: build the existing content.v2 carrier for verified source. */

#include "vcs/source_package_transport.h"

#include "util/safe_alloc.h"
#include "vcs/package_manifest.h"
#include "vcs/package_content.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"
#include "vcs/package_store.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_accepted_work_bundle.h"
#include "vcs/zcode_lane.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SOURCE_PACKAGE_MAX_AUTHORITY_BYTES 4096u

static const uint8_t source_transport_marker[] =
    "/* Inert source carrier. Product source is zclassic23-source/. */\n"
    "const char zclassic23_source_transport_v2[] = \"vcs_source_bundle.v2\";\n";

static const char *const offline_input_paths[] = {
    "vendor/.cache/leveldb-1.23.tar.gz",
    "vendor/.cache/libevent-2.1.12.tar.gz",
    "vendor/.cache/openssl-3.0.16.tar.gz",
    "vendor/.cache/sqlite-amalgamation-3490000.zip",
    "vendor/.cache/zlib-1.3.1.tar.gz",
};

static bool source_package_proven_lane(
    const uint8_t *wire, size_t wire_len, const uint8_t source_root[32],
    const uint8_t expected_signer[32])
{
    struct vcs_zcode_lane_receipt_v1 lane;
    return vcs_zcode_lane_receipt_parse(wire, wire_len, &lane) ==
            VCS_ZCODE_DEV_OK &&
        lane.lane == VCS_ZCODE_LANE_PROVEN &&
        memcmp(lane.source_root, source_root, 32) == 0 &&
        vcs_zcode_lane_receipt_verify(&lane, expected_signer) ==
            VCS_ZCODE_DEV_OK;
}

size_t vcs_source_package_offline_input_count(void)
{
    return sizeof(offline_input_paths) / sizeof(offline_input_paths[0]);
}

const char *vcs_source_package_offline_input_path(size_t index)
{
    return index < vcs_source_package_offline_input_count()
        ? offline_input_paths[index] : NULL;
}

void vcs_source_package_transport_init(
    struct vcs_source_package_transport *transport)
{
    if (transport) memset(transport, 0, sizeof(*transport));
}

void vcs_source_package_transport_free(
    struct vcs_source_package_transport *transport)
{
    if (!transport) return;
    free(transport->manifest_wire);
    free(transport->recipe_wire);
    free(transport->license_bytes);
    free(transport->lane_wire);
    free(transport->authority_wire);
    vcs_source_bundle_sharded_free(&transport->source);
    for (size_t i = 0; i < transport->offline_input_count; i++)
        free(transport->offline_inputs[i].bytes);
    memset(transport, 0, sizeof(*transport));
}

const uint8_t *vcs_source_package_transport_marker(size_t *len_out)
{
    if (len_out) *len_out = sizeof(source_transport_marker) - 1u;
    return source_transport_marker;
}

size_t vcs_source_package_transport_file_count(
    const struct vcs_source_package_transport *transport)
{
    return transport ? 4u + (transport->authority_wire_len > 0 ? 1u : 0u) +
        transport->source.shard_count + transport->offline_input_count : 0;
}

bool vcs_source_package_transport_file_at(
    const struct vcs_source_package_transport *transport, size_t index,
    const char **path_out, const uint8_t **bytes_out, size_t *len_out)
{
    if (!transport || !path_out || !bytes_out || !len_out) return false;
    size_t marker_len = 0;
    const uint8_t *marker = vcs_source_package_transport_marker(&marker_len);
    if (index == 0) {
        *path_out = VCS_SOURCE_PACKAGE_LICENSE_PATH;
        *bytes_out = transport->license_bytes;
        *len_out = transport->license_len;
        return true;
    }
    if (index == 1) {
        *path_out = VCS_SOURCE_PACKAGE_MANIFEST_PATH;
        *bytes_out = transport->source.manifest_wire;
        *len_out = transport->source.manifest_wire_len;
        return true;
    }
    index -= 2u;
    if (index < transport->source.shard_count) {
        static _Thread_local char shard_path[
            VCS_SOURCE_BUNDLE_SHARD_PATH_MAX];
        const struct vcs_source_bundle_shard *shard =
            &transport->source.shards[index];
        if (!vcs_source_bundle_shard_path(
                shard->index, shard_path, sizeof(shard_path)))
            return false;
        *path_out = shard_path;
        *bytes_out = shard->wire;
        *len_out = shard->wire_len;
        return true;
    }
    index -= transport->source.shard_count;
    if (index == 0) {
        *path_out = VCS_SOURCE_PACKAGE_LANE_PATH;
        *bytes_out = transport->lane_wire;
        *len_out = transport->lane_wire_len;
        return true;
    }
    if (index == 1) {
        *path_out = VCS_SOURCE_PACKAGE_MARKER_PATH;
        *bytes_out = marker;
        *len_out = marker_len;
        return true;
    }
    index -= 2u;
    if (transport->authority_wire_len > 0) {
        if (index == 0) {
            *path_out = VCS_SOURCE_PACKAGE_AUTHORITY_PATH;
            *bytes_out = transport->authority_wire;
            *len_out = transport->authority_wire_len;
            return true;
        }
        index--;
    }
    if (index >= transport->offline_input_count) return false;
    *path_out = transport->offline_inputs[index].path;
    *bytes_out = transport->offline_inputs[index].bytes;
    *len_out = transport->offline_inputs[index].len;
    return true;
}

static bool source_package_load_license(
    const char *workspace, const struct vcs_manifest *tree,
    uint8_t **bytes_out, size_t *len_out)
{
    *bytes_out = NULL;
    *len_out = 0;
    const struct vcs_entry *license = NULL;
    for (size_t i = 0; i < tree->count; i++) {
        if (strcmp(tree->entries[i].path,
                   VCS_SOURCE_PACKAGE_LICENSE_PATH) == 0) {
            license = &tree->entries[i];
            break;
        }
    }
    bool loaded = license &&
        license->size <= VCS_PACKAGE_RELEASE_LICENSE_TEXT_MAX_BYTES &&
        vcs_object_get(workspace, license->blob, VCS_TAG_BLOB,
                       bytes_out, len_out) == 0 &&
        *len_out == (size_t)license->size;
    if (loaded && vcs_package_release_license_text_allowed(
                      *bytes_out, *len_out))
        return true;
    free(*bytes_out);
    *bytes_out = NULL;
    *len_out = 0;
    return false;
}

static bool source_package_read_file(const char *workspace, const char *path,
                                     uint8_t **bytes_out, size_t *len_out)
{
    *bytes_out = NULL;
    *len_out = 0;
    char full[4096];
    int n = snprintf(full, sizeof(full), "%s/%s", workspace, path);
    struct stat before;
    if (n <= 0 || (size_t)n >= sizeof(full) || lstat(full, &before) != 0 ||
        !S_ISREG(before.st_mode) || before.st_size <= 0 ||
        (uint64_t)before.st_size > VCS_PACKAGE_MAX_FILE_BYTES)
        return false;
    int fd = open(full, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    size_t len = (size_t)before.st_size;
    uint8_t *bytes = zcl_malloc(len, "vcs.source_package.offline_input");
    size_t off = 0;
    bool ok = bytes != NULL;
    while (ok && off < len) {
        ssize_t got = read(fd, bytes + off, len - off);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) ok = false;
        else off += (size_t)got;
    }
    struct stat after;
    ok = ok && fstat(fd, &after) == 0 &&
        before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
        before.st_mode == after.st_mode &&
        before.st_size == after.st_size &&
        before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
        before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
        before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
        before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
    if (close(fd) != 0) ok = false;
    if (!ok) {
        free(bytes);
        return false;
    }
    *bytes_out = bytes;
    *len_out = len;
    return true;
}

static bool source_package_offline_inputs(
    const char *workspace, struct vcs_source_package_transport *transport)
{
    size_t count = vcs_source_package_offline_input_count();
    if (count > VCS_SOURCE_PACKAGE_OFFLINE_INPUT_MAX) return false;
    size_t present = 0;
    for (size_t i = 0; i < count; i++) {
        char full[4096];
        int n = snprintf(full, sizeof(full), "%s/%s", workspace,
                         offline_input_paths[i]);
        struct stat st;
        if (n <= 0 || (size_t)n >= sizeof(full)) return false;
        if (lstat(full, &st) == 0) {
            present++;
        } else if (errno != ENOENT) {
            return false;
        }
    }
    /* Standalone C23 packages reproduce from their declared package DAG and
     * therefore have no node-toolchain cache.  A node-source publication may
     * carry the existing closed cache, but a partial cache is never accepted. */
    if (present == 0) return true;
    if (present != count) return false;
    for (size_t i = 0; i < count; i++) {
        struct vcs_source_package_file *file =
            &transport->offline_inputs[transport->offline_input_count];
        file->path = offline_input_paths[i];
        if (!source_package_read_file(
                workspace, file->path, &file->bytes, &file->len) ||
            UINT64_MAX - transport->offline_input_bytes < file->len) {
            free(file->bytes);
            file->bytes = NULL;
            file->len = 0;
            return false;
        }
        transport->offline_input_bytes += file->len;
        transport->offline_input_count++;
    }
    return true;
}

static bool source_package_recipe(
    struct vcs_source_package_transport *transport)
{
    struct vcs_package_recipe recipe;
    vcs_package_recipe_init(&recipe);
    enum vcs_package_recipe_error error = VCS_PACKAGE_RECIPE_OK;
    bool ok = vcs_package_recipe_add_source(
        &recipe, VCS_SOURCE_PACKAGE_MARKER_PATH, &error);
    vcs_package_recipe_set_test_limits(
        &recipe, 0, 60, UINT64_C(64) * 1024u * 1024u);
    ok = ok && vcs_package_recipe_serialize(
        &recipe, &transport->recipe_wire,
        &transport->recipe_wire_len) == VCS_PACKAGE_RECIPE_OK &&
        vcs_package_recipe_root(
            &recipe, transport->recipe_root) == VCS_PACKAGE_RECIPE_OK;
    vcs_package_recipe_free(&recipe);
    return ok;
}

static bool source_package_manifest_build(
    struct vcs_source_package_transport *transport)
{
    free(transport->manifest_wire);
    transport->manifest_wire = NULL;
    transport->manifest_wire_len = 0;
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    bool ok = true;
    uint64_t total = 0;
    size_t count = vcs_source_package_transport_file_count(transport);
    for (size_t i = 0; ok && i < count; i++) {
        const char *path = NULL;
        const uint8_t *bytes = NULL;
        size_t len = 0;
        ok = vcs_source_package_transport_file_at(
            transport, i, &path, &bytes, &len) &&
            UINT64_MAX - total >= len;
        if (ok) total += len;
        if (ok) ok = vcs_package_content_add_file(
            &manifest, path, VCS_PACKAGE_MODE_FILE, bytes, len);
    }
    ok = ok && total <= VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES &&
        vcs_package_manifest_root(&manifest, transport->package_root) &&
        vcs_package_manifest_serialize(
            &manifest, &transport->manifest_wire,
            &transport->manifest_wire_len);
    vcs_package_manifest_free(&manifest);
    return ok;
}

bool vcs_source_package_transport_build(
    const char *workspace, const uint8_t source_root[32],
    const uint8_t expected_signer[32],
    const uint8_t *lane_wire, size_t lane_wire_len,
    struct vcs_source_package_transport *transport)
{
    if (!workspace || !source_root || !expected_signer || !lane_wire ||
        !transport ||
        lane_wire_len > SOURCE_PACKAGE_MAX_AUTHORITY_BYTES ||
        !source_package_proven_lane(
            lane_wire, lane_wire_len, source_root, expected_signer))
        return false;
    vcs_source_package_transport_free(transport);
    struct vcs_manifest tree;
    if (!vcs_tree_load(workspace, source_root, &tree)) return false;
    bool ok = source_package_load_license(
        workspace, &tree, &transport->license_bytes,
        &transport->license_len);
    vcs_manifest_free(&tree);
    if (ok) {
        transport->lane_wire = zcl_malloc(
            lane_wire_len, "vcs.source_package.lane");
        ok = transport->lane_wire != NULL;
    }
    if (ok) {
        memcpy(transport->lane_wire, lane_wire, lane_wire_len);
        transport->lane_wire_len = lane_wire_len;
    }
    enum vcs_source_bundle_result bundle_result = ok
        ? vcs_source_bundle_sharded_create(
              workspace, source_root, &transport->source)
        : VCS_SOURCE_BUNDLE_ERR_SOURCE;
    ok = ok && bundle_result == VCS_SOURCE_BUNDLE_OK &&
        source_package_offline_inputs(workspace, transport);
    if (ok) {
        transport->bundle_metrics = transport->source.metrics;
        transport->source_transport_bytes =
            transport->source.manifest_wire_len;
        for (size_t i = 0; i < transport->source.shard_count; i++)
            transport->source_transport_bytes +=
                transport->source.shards[i].wire_len;
    }

    ok = ok && source_package_manifest_build(transport);
    if (ok) ok = source_package_recipe(transport);
    if (!ok) vcs_source_package_transport_free(transport);
    return ok;
}

bool vcs_source_package_transport_build_accepted(
    const char *workspace, const uint8_t source_root[32],
    const uint8_t accepted_work_root[32], int64_t now_unix,
    struct vcs_source_package_transport *transport)
{
    if (!workspace || !source_root || !accepted_work_root ||
        now_unix <= 0 || !transport)
        return false;
    uint8_t *authority = NULL, *lane_wire = NULL;
    size_t authority_len = 0, lane_len = 0;
    struct vcs_zcode_accepted_work_v1 accepted;
    bool ok = vcs_zcode_accepted_work_bundle_export(
            workspace, accepted_work_root, now_unix,
            &authority, &authority_len, &accepted) ==
            VCS_ZCODE_ACCEPTED_WORK_BUNDLE_OK &&
        memcmp(accepted.candidate.candidate_source_root,
               source_root, 32) == 0 &&
        vcs_object_load_raw_bounded(
            workspace, accepted_work_root, VCS_ZCODE_LANE_WIRE_BYTES,
            &lane_wire, &lane_len) == 0 &&
        vcs_source_package_transport_build(
            workspace, source_root, accepted.expected_signer,
            lane_wire, lane_len, transport);
    free(lane_wire);
    if (!ok) {
        free(authority);
        return false;
    }
    transport->authority_wire = authority;
    transport->authority_wire_len = authority_len;
    memcpy(transport->accepted_work_root, accepted_work_root, 32);
    if (!source_package_manifest_build(transport)) {
        vcs_source_package_transport_free(transport);
        return false;
    }
    return true;
}
