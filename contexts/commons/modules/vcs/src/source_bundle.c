/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: compressed transport for verified ZVCS manifests and blobs. */

#include "vcs/source_bundle.h"

#include "util/safe_alloc.h"
#include "vcs/package_manifest.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "vcs_priv.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <zlib.h>

static const uint8_t source_bundle_magic[8] = {
    'Z', 'V', 'S', 'B', 'Z', '\r', '\n', 0
};

struct source_bundle_decoded {
    uint8_t *payload;
    size_t payload_len;
    uint8_t *manifest_wire;
    size_t manifest_len;
    struct vcs_manifest manifest;
};

const char *vcs_source_bundle_result_string(
    enum vcs_source_bundle_result result)
{
    switch (result) {
    case VCS_SOURCE_BUNDLE_OK: return "ok";
    case VCS_SOURCE_BUNDLE_ERR_NULL: return "null-argument";
    case VCS_SOURCE_BUNDLE_ERR_SOURCE: return "source-cas-invalid";
    case VCS_SOURCE_BUNDLE_ERR_LIMIT: return "bundle-limit";
    case VCS_SOURCE_BUNDLE_ERR_ALLOC: return "allocation";
    case VCS_SOURCE_BUNDLE_ERR_CODEC: return "compression-codec";
    case VCS_SOURCE_BUNDLE_ERR_WIRE: return "wire-invalid";
    case VCS_SOURCE_BUNDLE_ERR_ROOT: return "tree-root-mismatch";
    case VCS_SOURCE_BUNDLE_ERR_BLOB: return "blob-invalid";
    case VCS_SOURCE_BUNDLE_ERR_STORE: return "object-store";
    }
    return "unknown";
}

static void source_bundle_metrics_init(struct vcs_source_bundle_metrics *m)
{
    if (m) memset(m, 0, sizeof(*m));
}

static void source_bundle_decoded_free(struct source_bundle_decoded *d)
{
    if (!d) return;
    vcs_manifest_free(&d->manifest);
    free(d->payload);
    memset(d, 0, sizeof(*d));
}

static bool source_bundle_total(const struct vcs_manifest *manifest,
                                size_t manifest_len, uint64_t *total_out)
{
    uint64_t total = manifest_len;
    if (manifest_len > VCS_SOURCE_BUNDLE_MAX_MANIFEST_BYTES)
        return false;
    for (size_t i = 0; i < manifest->count; i++) {
        if (manifest->entries[i].size >
            VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES - total)
            return false;
        total += manifest->entries[i].size;
    }
    *total_out = total;
    return total <= VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES && total <= SIZE_MAX;
}

enum vcs_source_bundle_result vcs_source_bundle_create(
    const char *workspace, const uint8_t tree_root[32], uint8_t **wire_out,
    size_t *wire_len_out, struct vcs_source_bundle_metrics *metrics)
{
    if (wire_out) *wire_out = NULL;
    if (wire_len_out) *wire_len_out = 0;
    source_bundle_metrics_init(metrics);
    if (!workspace || !tree_root || !wire_out || !wire_len_out)
        return VCS_SOURCE_BUNDLE_ERR_NULL;
    struct vcs_manifest manifest;
    if (!vcs_tree_load(workspace, tree_root, &manifest))
        return VCS_SOURCE_BUNDLE_ERR_SOURCE;
    uint8_t *manifest_wire = NULL;
    size_t manifest_len = 0;
    uint64_t payload_len64 = 0;
    if (!vcs_manifest_serialize(&manifest, &manifest_wire, &manifest_len) ||
        !source_bundle_total(&manifest, manifest_len, &payload_len64)) {
        free(manifest_wire);
        vcs_manifest_free(&manifest);
        return VCS_SOURCE_BUNDLE_ERR_LIMIT;
    }
    size_t payload_len = (size_t)payload_len64;
    uint8_t *payload = zcl_malloc(payload_len, "vcs.source_bundle.payload");
    if (!payload) {
        free(manifest_wire); vcs_manifest_free(&manifest);
        return VCS_SOURCE_BUNDLE_ERR_ALLOC;
    }
    memcpy(payload, manifest_wire, manifest_len);
    size_t off = manifest_len;
    enum vcs_source_bundle_result result = VCS_SOURCE_BUNDLE_OK;
    for (size_t i = 0; i < manifest.count; i++) {
        uint8_t *blob = NULL;
        size_t blob_len = 0;
        const struct vcs_entry *entry = &manifest.entries[i];
        if (entry->size > SIZE_MAX ||
            vcs_object_get(workspace, entry->blob, VCS_TAG_BLOB,
                           &blob, &blob_len) != 0 ||
            blob_len != (size_t)entry->size) {
            free(blob);
            result = VCS_SOURCE_BUNDLE_ERR_BLOB;
            break;
        }
        memcpy(payload + off, blob, blob_len);
        off += blob_len;
        free(blob);
    }
    uLong bound = 0;
    uint8_t *compressed = NULL;
    uLongf compressed_len = 0;
    if (result == VCS_SOURCE_BUNDLE_OK) {
        if (payload_len > ULONG_MAX)
            result = VCS_SOURCE_BUNDLE_ERR_LIMIT;
        else
            bound = compressBound((uLong)payload_len);
    }
    if (result == VCS_SOURCE_BUNDLE_OK) {
        compressed = zcl_malloc((size_t)bound,
                                "vcs.source_bundle.compressed");
        if (!compressed)
            result = VCS_SOURCE_BUNDLE_ERR_ALLOC;
    }
    compressed_len = bound;
    if (result == VCS_SOURCE_BUNDLE_OK &&
        compress2(compressed, &compressed_len, payload, (uLong)payload_len,
                  Z_BEST_COMPRESSION) != Z_OK)
        result = VCS_SOURCE_BUNDLE_ERR_CODEC;
    uint64_t wire_len64 = VCS_SOURCE_BUNDLE_HEADER_BYTES +
                          (uint64_t)compressed_len;
    if (result == VCS_SOURCE_BUNDLE_OK &&
        (wire_len64 > VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES ||
         wire_len64 > SIZE_MAX))
        result = VCS_SOURCE_BUNDLE_ERR_LIMIT;
    uint8_t *wire = NULL;
    if (result == VCS_SOURCE_BUNDLE_OK) {
        wire = zcl_malloc((size_t)wire_len64, "vcs.source_bundle.wire");
        if (!wire) result = VCS_SOURCE_BUNDLE_ERR_ALLOC;
    }
    if (result == VCS_SOURCE_BUNDLE_OK) {
        memcpy(wire, source_bundle_magic, sizeof(source_bundle_magic));
        vcs_wr_u16le(wire + 8, VCS_SOURCE_BUNDLE_VERSION);
        vcs_wr_u16le(wire + 10, VCS_SOURCE_BUNDLE_CODEC_ZLIB);
        memcpy(wire + 12, tree_root, 32);
        vcs_wr_u64le(wire + 44, manifest_len);
        vcs_wr_u64le(wire + 52, payload_len);
        vcs_wr_u64le(wire + 60, compressed_len);
        memcpy(wire + VCS_SOURCE_BUNDLE_HEADER_BYTES, compressed,
               compressed_len);
        *wire_out = wire;
        *wire_len_out = (size_t)wire_len64;
        if (metrics) {
            metrics->source_bytes = payload_len - manifest_len;
            metrics->compressed_bytes = compressed_len;
            metrics->file_count = (uint32_t)manifest.count;
        }
    }
    free(compressed); free(payload); free(manifest_wire);
    vcs_manifest_free(&manifest);
    return result;
}

static enum vcs_source_bundle_result source_bundle_decode(
    const uint8_t *wire, size_t wire_len,
    const uint8_t expected_tree_root[32], struct source_bundle_decoded *out,
    struct vcs_source_bundle_metrics *metrics)
{
    memset(out, 0, sizeof(*out));
    vcs_manifest_init(&out->manifest);
    if (!wire || !expected_tree_root ||
        wire_len < VCS_SOURCE_BUNDLE_HEADER_BYTES ||
        wire_len > VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES ||
        memcmp(wire, source_bundle_magic, sizeof(source_bundle_magic)) != 0 ||
        vcs_rd_u16le(wire + 8) != VCS_SOURCE_BUNDLE_VERSION ||
        vcs_rd_u16le(wire + 10) != VCS_SOURCE_BUNDLE_CODEC_ZLIB)
        return VCS_SOURCE_BUNDLE_ERR_WIRE;
    if (memcmp(wire + 12, expected_tree_root, 32) != 0)
        return VCS_SOURCE_BUNDLE_ERR_ROOT;
    uint64_t manifest_len64 = vcs_rd_u64le(wire + 44);
    uint64_t payload_len64 = vcs_rd_u64le(wire + 52);
    uint64_t compressed_len64 = vcs_rd_u64le(wire + 60);
    if (manifest_len64 == 0 ||
        manifest_len64 > VCS_SOURCE_BUNDLE_MAX_MANIFEST_BYTES ||
        payload_len64 < manifest_len64 ||
        payload_len64 > VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES ||
        compressed_len64 == 0 || compressed_len64 > SIZE_MAX ||
        payload_len64 > SIZE_MAX ||
        compressed_len64 != wire_len - VCS_SOURCE_BUNDLE_HEADER_BYTES)
        return VCS_SOURCE_BUNDLE_ERR_LIMIT;
    out->payload_len = (size_t)payload_len64;
    out->manifest_len = (size_t)manifest_len64;
    out->payload = zcl_malloc(out->payload_len,
                              "vcs.source_bundle.inflate");
    if (!out->payload)
        return VCS_SOURCE_BUNDLE_ERR_ALLOC;
    uLongf inflated = (uLongf)out->payload_len;
    int zrc = uncompress(out->payload, &inflated,
        wire + VCS_SOURCE_BUNDLE_HEADER_BYTES, (uLong)compressed_len64);
    if (zrc != Z_OK || inflated != out->payload_len) {
        source_bundle_decoded_free(out);
        return VCS_SOURCE_BUNDLE_ERR_CODEC;
    }
    out->manifest_wire = out->payload;
    if (!vcs_manifest_parse(out->manifest_wire, out->manifest_len,
                            &out->manifest)) {
        source_bundle_decoded_free(out);
        return VCS_SOURCE_BUNDLE_ERR_WIRE;
    }
    uint8_t checked_root[32];
    uint64_t expected_payload = 0;
    if (!vcs_manifest_tree_hash(&out->manifest, checked_root) ||
        memcmp(checked_root, expected_tree_root, 32) != 0 ||
        !source_bundle_total(&out->manifest, out->manifest_len,
                             &expected_payload) ||
        expected_payload != payload_len64) {
        source_bundle_decoded_free(out);
        return VCS_SOURCE_BUNDLE_ERR_ROOT;
    }
    size_t off = out->manifest_len;
    for (size_t i = 0; i < out->manifest.count; i++) {
        const struct vcs_entry *entry = &out->manifest.entries[i];
        uint8_t blob_root[32];
        if (!S_ISREG(entry->mode) ||
            !vcs_package_path_valid(entry->path) ||
            entry->size > SIZE_MAX ||
            (size_t)entry->size > out->payload_len - off) {
            source_bundle_decoded_free(out);
            return VCS_SOURCE_BUNDLE_ERR_WIRE;
        }
        vcs_sha3_tag(VCS_TAG_BLOB, out->payload + off,
                     (size_t)entry->size, blob_root);
        if (memcmp(blob_root, entry->blob, 32) != 0) {
            source_bundle_decoded_free(out);
            return VCS_SOURCE_BUNDLE_ERR_BLOB;
        }
        off += (size_t)entry->size;
    }
    if (off != out->payload_len) {
        source_bundle_decoded_free(out);
        return VCS_SOURCE_BUNDLE_ERR_WIRE;
    }
    if (metrics) {
        metrics->source_bytes = payload_len64 - manifest_len64;
        metrics->compressed_bytes = compressed_len64;
        metrics->file_count = (uint32_t)out->manifest.count;
    }
    return VCS_SOURCE_BUNDLE_OK;
}

enum vcs_source_bundle_result vcs_source_bundle_verify(
    const uint8_t *wire, size_t wire_len,
    const uint8_t expected_tree_root[32],
    struct vcs_source_bundle_metrics *metrics)
{
    source_bundle_metrics_init(metrics);
    if (!wire || !expected_tree_root)
        return VCS_SOURCE_BUNDLE_ERR_NULL;
    struct source_bundle_decoded decoded;
    enum vcs_source_bundle_result result = source_bundle_decode(
        wire, wire_len, expected_tree_root, &decoded, metrics);
    if (result == VCS_SOURCE_BUNDLE_OK)
        source_bundle_decoded_free(&decoded);
    return result;
}

enum vcs_source_bundle_result vcs_source_bundle_import(
    const uint8_t *wire, size_t wire_len,
    const uint8_t expected_tree_root[32], const char *workspace,
    struct vcs_source_bundle_metrics *metrics)
{
    source_bundle_metrics_init(metrics);
    if (!wire || !expected_tree_root || !workspace)
        return VCS_SOURCE_BUNDLE_ERR_NULL;
    struct source_bundle_decoded decoded;
    enum vcs_source_bundle_result result = source_bundle_decode(
        wire, wire_len, expected_tree_root, &decoded, metrics);
    if (result != VCS_SOURCE_BUNDLE_OK)
        return result;
    if (!vcs_object_store_init(workspace)) {
        source_bundle_decoded_free(&decoded);
        return VCS_SOURCE_BUNDLE_ERR_STORE;
    }
    size_t off = decoded.manifest_len;
    for (size_t i = 0; i < decoded.manifest.count; i++) {
        const struct vcs_entry *entry = &decoded.manifest.entries[i];
        bool existed = vcs_object_has(workspace, entry->blob);
        bool repaired = false;
        uint8_t stored[32];
        if (!vcs_object_put_repair(workspace, decoded.payload + off,
                                   (size_t)entry->size, VCS_TAG_BLOB,
                                   stored, &repaired) ||
            memcmp(stored, entry->blob, 32) != 0) {
            result = VCS_SOURCE_BUNDLE_ERR_STORE;
            break;
        }
        if (metrics) {
            if (existed && !repaired) {
                metrics->reused_blobs++;
                metrics->reused_bytes += entry->size;
            } else {
                metrics->new_blobs++;
                metrics->new_bytes += entry->size;
            }
            metrics->repaired = metrics->repaired || repaired;
        }
        off += (size_t)entry->size;
    }
    if (result == VCS_SOURCE_BUNDLE_OK) {
        bool manifest_existed = vcs_object_has(workspace,
                                               expected_tree_root);
        bool repaired = false;
        if (!vcs_object_put_addressed_repair(
                workspace, expected_tree_root, decoded.manifest_wire,
                decoded.manifest_len, &repaired))
            result = VCS_SOURCE_BUNDLE_ERR_STORE;
        else if (metrics) {
            metrics->manifest_reused = manifest_existed && !repaired;
            metrics->repaired = metrics->repaired || repaired;
        }
    }
    source_bundle_decoded_free(&decoded);
    return result;
}
