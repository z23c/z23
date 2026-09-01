/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: delta-efficient path-sharded ZVCS source-bundle transport. */

#include "vcs/source_bundle.h"

#include "util/safe_alloc.h"
#include "vcs/package_manifest.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "vcs_priv.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <zlib.h>

static const uint8_t sharded_magic[8] = {
    'Z', 'V', 'S', 'S', 'Z', '\r', '\n', 0
};
static const uint8_t sharded_path_domain[] =
    "zcl.source_bundle.path_shard.v2\0";

void vcs_source_bundle_sharded_init(
    struct vcs_source_bundle_sharded *bundle)
{
    if (bundle) memset(bundle, 0, sizeof(*bundle));
}

void vcs_source_bundle_sharded_free(
    struct vcs_source_bundle_sharded *bundle)
{
    if (!bundle) return;
    free(bundle->manifest_wire);
    for (size_t i = 0; i < bundle->shard_count; i++)
        free(bundle->shards[i].wire);
    memset(bundle, 0, sizeof(*bundle));
}

bool vcs_source_bundle_shard_path(uint16_t index, char *out, size_t out_size)
{
    if (!out || index >= VCS_SOURCE_BUNDLE_SHARD_COUNT) return false;
    int n = snprintf(out, out_size,
                     "zclassic23-source/shard-%02x.zvss", index);
    return n > 0 && (size_t)n < out_size;
}

static uint16_t sharded_index(const char *path)
{
    uint8_t digest[32];
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, sharded_path_domain,
                   sizeof(sharded_path_domain) - 1u);
    sha3_256_write(&sha, (const uint8_t *)path, strlen(path));
    sha3_256_finalize(&sha, digest);
    return digest[0];
}

static bool sharded_manifest_shape(const struct vcs_manifest *manifest,
                                   uint64_t sizes[256], uint64_t *total_out)
{
    memset(sizes, 0, 256u * sizeof(sizes[0]));
    uint64_t total = 0;
    for (size_t i = 0; i < manifest->count; i++) {
        const struct vcs_entry *entry = &manifest->entries[i];
        uint16_t shard = sharded_index(entry->path);
        if (!S_ISREG(entry->mode) ||
            !vcs_package_path_valid(entry->path) ||
            entry->size > VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES - total ||
            entry->size > VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES - sizes[shard])
            return false;
        total += entry->size;
        sizes[shard] += entry->size;
    }
    *total_out = total;
    return total <= VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES && total <= SIZE_MAX;
}

static enum vcs_source_bundle_result sharded_payloads(
    const char *workspace, const struct vcs_manifest *manifest,
    const uint64_t sizes[256], uint8_t *payloads[256])
{
    size_t offsets[256] = {0};
    for (size_t i = 0; i < 256u; i++) {
        payloads[i] = sizes[i] > 0
            ? zcl_malloc((size_t)sizes[i], "vcs.source_shard.payload") : NULL;
        if (sizes[i] > 0 && !payloads[i]) return VCS_SOURCE_BUNDLE_ERR_ALLOC;
    }
    for (size_t i = 0; i < manifest->count; i++) {
        const struct vcs_entry *entry = &manifest->entries[i];
        uint16_t shard = sharded_index(entry->path);
        uint8_t *blob = NULL;
        size_t blob_len = 0;
        if (entry->size > SIZE_MAX ||
            vcs_object_get(workspace, entry->blob, VCS_TAG_BLOB,
                           &blob, &blob_len) != 0 ||
            blob_len != (size_t)entry->size) {
            free(blob);
            return VCS_SOURCE_BUNDLE_ERR_BLOB;
        }
        memcpy(payloads[shard] + offsets[shard], blob, blob_len);
        offsets[shard] += blob_len;
        free(blob);
    }
    for (size_t i = 0; i < 256u; i++)
        if (offsets[i] != sizes[i]) return VCS_SOURCE_BUNDLE_ERR_BLOB;
    return VCS_SOURCE_BUNDLE_OK;
}

static enum vcs_source_bundle_result sharded_compress_one(
    uint16_t index, const uint8_t *payload, size_t payload_len,
    struct vcs_source_bundle_shard *out)
{
    if (payload_len == 0 || payload_len > ULONG_MAX)
        return VCS_SOURCE_BUNDLE_ERR_LIMIT;
    uLong bound = compressBound((uLong)payload_len);
    uint8_t *compressed = zcl_malloc((size_t)bound,
                                     "vcs.source_shard.compressed");
    if (!compressed) return VCS_SOURCE_BUNDLE_ERR_ALLOC;
    uLongf compressed_len = bound;
    if (compress2(compressed, &compressed_len, payload, (uLong)payload_len,
                  Z_BEST_COMPRESSION) != Z_OK) {
        free(compressed);
        return VCS_SOURCE_BUNDLE_ERR_CODEC;
    }
    uint64_t wire_len64 = VCS_SOURCE_BUNDLE_SHARD_HEADER_BYTES +
                          (uint64_t)compressed_len;
    if (wire_len64 > VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES ||
        wire_len64 > SIZE_MAX) {
        free(compressed);
        return VCS_SOURCE_BUNDLE_ERR_LIMIT;
    }
    uint8_t *wire = zcl_malloc((size_t)wire_len64,
                               "vcs.source_shard.wire");
    if (!wire) {
        free(compressed);
        return VCS_SOURCE_BUNDLE_ERR_ALLOC;
    }
    memcpy(wire, sharded_magic, sizeof(sharded_magic));
    vcs_wr_u16le(wire + 8, VCS_SOURCE_BUNDLE_SHARDED_VERSION);
    vcs_wr_u16le(wire + 10, VCS_SOURCE_BUNDLE_CODEC_ZLIB);
    memset(wire + 12, 0, 32);
    vcs_wr_u16le(wire + 44, index);
    vcs_wr_u16le(wire + 46, VCS_SOURCE_BUNDLE_SHARD_COUNT);
    vcs_wr_u64le(wire + 48, payload_len);
    vcs_wr_u64le(wire + 56, compressed_len);
    memcpy(wire + VCS_SOURCE_BUNDLE_SHARD_HEADER_BYTES,
           compressed, compressed_len);
    free(compressed);
    out->index = index;
    out->wire = wire;
    out->wire_len = (size_t)wire_len64;
    return VCS_SOURCE_BUNDLE_OK;
}

enum vcs_source_bundle_result vcs_source_bundle_sharded_create(
    const char *workspace, const uint8_t tree_root[32],
    struct vcs_source_bundle_sharded *bundle)
{
    if (!workspace || !tree_root || !bundle)
        return VCS_SOURCE_BUNDLE_ERR_NULL;
    vcs_source_bundle_sharded_free(bundle);
    struct vcs_manifest manifest;
    if (!vcs_tree_load(workspace, tree_root, &manifest))
        return VCS_SOURCE_BUNDLE_ERR_SOURCE;
    uint64_t sizes[256], source_bytes = 0;
    bool shape_ok = sharded_manifest_shape(&manifest, sizes, &source_bytes) &&
        vcs_manifest_serialize(&manifest, &bundle->manifest_wire,
                               &bundle->manifest_wire_len) &&
        bundle->manifest_wire_len <= VCS_SOURCE_BUNDLE_MAX_MANIFEST_BYTES;
    if (!shape_ok) {
        vcs_manifest_free(&manifest);
        vcs_source_bundle_sharded_free(bundle);
        return VCS_SOURCE_BUNDLE_ERR_LIMIT;
    }
    uint8_t *payloads[256] = {0};
    enum vcs_source_bundle_result result = sharded_payloads(
        workspace, &manifest, sizes, payloads);
    uint64_t aggregate = bundle->manifest_wire_len;
    uint64_t compressed_bytes = 0;
    for (uint16_t i = 0; result == VCS_SOURCE_BUNDLE_OK && i < 256u; i++) {
        if (sizes[i] == 0) continue;
        struct vcs_source_bundle_shard *part =
            &bundle->shards[bundle->shard_count];
        result = sharded_compress_one(i, payloads[i],
                                      (size_t)sizes[i], part);
        if (result == VCS_SOURCE_BUNDLE_OK) {
            bundle->shard_count++;
            uint64_t payload_len = part->wire_len -
                VCS_SOURCE_BUNDLE_SHARD_HEADER_BYTES;
            if (UINT64_MAX - aggregate < part->wire_len ||
                UINT64_MAX - compressed_bytes < payload_len) {
                result = VCS_SOURCE_BUNDLE_ERR_LIMIT;
            } else {
                aggregate += part->wire_len;
                compressed_bytes += payload_len;
                if (aggregate > VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES)
                    result = VCS_SOURCE_BUNDLE_ERR_LIMIT;
            }
        }
    }
    for (size_t i = 0; i < 256u; i++) free(payloads[i]);
    if (result == VCS_SOURCE_BUNDLE_OK) {
        bundle->metrics.source_bytes = source_bytes;
        bundle->metrics.compressed_bytes = compressed_bytes;
        bundle->metrics.file_count = (uint32_t)manifest.count;
    } else {
        vcs_source_bundle_sharded_free(bundle);
    }
    vcs_manifest_free(&manifest);
    return result;
}

static enum vcs_source_bundle_result sharded_decode(
    const struct vcs_source_bundle_shard *part,
    uint16_t expected_index, size_t expected_len, uint8_t **payload_out)
{
    *payload_out = NULL;
    if (!part || !part->wire ||
        part->wire_len < VCS_SOURCE_BUNDLE_SHARD_HEADER_BYTES ||
        part->wire_len > VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES ||
        part->index != expected_index ||
        memcmp(part->wire, sharded_magic, sizeof(sharded_magic)) != 0 ||
        vcs_rd_u16le(part->wire + 8) !=
            VCS_SOURCE_BUNDLE_SHARDED_VERSION ||
        vcs_rd_u16le(part->wire + 10) != VCS_SOURCE_BUNDLE_CODEC_ZLIB ||
        memcmp(part->wire + 12, (const uint8_t[32]){0}, 32) != 0 ||
        vcs_rd_u16le(part->wire + 44) != expected_index ||
        vcs_rd_u16le(part->wire + 46) != VCS_SOURCE_BUNDLE_SHARD_COUNT ||
        vcs_rd_u64le(part->wire + 48) != expected_len)
        return VCS_SOURCE_BUNDLE_ERR_WIRE;
    uint64_t compressed_len = vcs_rd_u64le(part->wire + 56);
    if (compressed_len == 0 || compressed_len > ULONG_MAX ||
        compressed_len !=
            part->wire_len - VCS_SOURCE_BUNDLE_SHARD_HEADER_BYTES ||
        expected_len == 0 || expected_len > ULONG_MAX)
        return VCS_SOURCE_BUNDLE_ERR_LIMIT;
    uint8_t *payload = zcl_malloc(expected_len,
                                  "vcs.source_shard.inflate");
    if (!payload) return VCS_SOURCE_BUNDLE_ERR_ALLOC;
    uLongf inflated = (uLongf)expected_len;
    int rc = uncompress(payload, &inflated,
        part->wire + VCS_SOURCE_BUNDLE_SHARD_HEADER_BYTES,
        (uLong)compressed_len);
    if (rc != Z_OK || inflated != expected_len) {
        free(payload);
        return VCS_SOURCE_BUNDLE_ERR_CODEC;
    }
    *payload_out = payload;
    return VCS_SOURCE_BUNDLE_OK;
}

enum vcs_source_bundle_result vcs_source_bundle_sharded_verify(
    const struct vcs_source_bundle_sharded *bundle,
    const uint8_t expected_tree_root[32],
    struct vcs_source_bundle_metrics *metrics)
{
    if (metrics) memset(metrics, 0, sizeof(*metrics));
    if (!bundle || !expected_tree_root || !bundle->manifest_wire ||
        bundle->manifest_wire_len == 0 ||
        bundle->manifest_wire_len > VCS_SOURCE_BUNDLE_MAX_MANIFEST_BYTES ||
        bundle->shard_count > VCS_SOURCE_BUNDLE_SHARD_COUNT)
        return VCS_SOURCE_BUNDLE_ERR_NULL;
    struct vcs_manifest manifest;
    if (!vcs_manifest_parse(bundle->manifest_wire,
                            bundle->manifest_wire_len, &manifest))
        return VCS_SOURCE_BUNDLE_ERR_WIRE;
    uint8_t checked_root[32];
    uint64_t sizes[256], source_bytes = 0;
    bool shape_ok = vcs_manifest_tree_hash(&manifest, checked_root) &&
        memcmp(checked_root, expected_tree_root, 32) == 0 &&
        sharded_manifest_shape(&manifest, sizes, &source_bytes);
    if (!shape_ok) {
        vcs_manifest_free(&manifest);
        return VCS_SOURCE_BUNDLE_ERR_ROOT;
    }
    const struct vcs_source_bundle_shard *parts[256] = {0};
    uint64_t compressed_bytes = 0;
    enum vcs_source_bundle_result result = VCS_SOURCE_BUNDLE_OK;
    for (size_t i = 0; result == VCS_SOURCE_BUNDLE_OK &&
                       i < bundle->shard_count; i++) {
        const struct vcs_source_bundle_shard *part = &bundle->shards[i];
        if (part->index >= 256u || parts[part->index] ||
            sizes[part->index] == 0)
            result = VCS_SOURCE_BUNDLE_ERR_WIRE;
        else {
            parts[part->index] = part;
            compressed_bytes += part->wire_len -
                VCS_SOURCE_BUNDLE_SHARD_HEADER_BYTES;
        }
    }
    for (uint16_t shard = 0; result == VCS_SOURCE_BUNDLE_OK &&
                              shard < 256u; shard++) {
        if ((sizes[shard] > 0) != (parts[shard] != NULL)) {
            result = VCS_SOURCE_BUNDLE_ERR_WIRE;
            break;
        }
        if (sizes[shard] == 0) continue;
        uint8_t *payload = NULL;
        result = sharded_decode(parts[shard], shard, (size_t)sizes[shard],
                                 &payload);
        size_t off = 0;
        for (size_t i = 0; result == VCS_SOURCE_BUNDLE_OK &&
                           i < manifest.count; i++) {
            const struct vcs_entry *entry = &manifest.entries[i];
            if (sharded_index(entry->path) != shard) continue;
            uint8_t blob_root[32];
            if (off > sizes[shard] ||
                entry->size > sizes[shard] - off) {
                result = VCS_SOURCE_BUNDLE_ERR_WIRE;
                break;
            }
            vcs_sha3_tag(VCS_TAG_BLOB, payload + off,
                         (size_t)entry->size, blob_root);
            if (memcmp(blob_root, entry->blob, 32) != 0)
                result = VCS_SOURCE_BUNDLE_ERR_BLOB;
            off += (size_t)entry->size;
        }
        if (result == VCS_SOURCE_BUNDLE_OK && off != sizes[shard])
            result = VCS_SOURCE_BUNDLE_ERR_WIRE;
        free(payload);
    }
    if (result == VCS_SOURCE_BUNDLE_OK && metrics) {
        metrics->source_bytes = source_bytes;
        metrics->compressed_bytes = compressed_bytes;
        metrics->file_count = (uint32_t)manifest.count;
    }
    vcs_manifest_free(&manifest);
    return result;
}

enum vcs_source_bundle_result vcs_source_bundle_sharded_import(
    const struct vcs_source_bundle_sharded *bundle,
    const uint8_t expected_tree_root[32], const char *workspace,
    struct vcs_source_bundle_metrics *metrics)
{
    struct vcs_source_bundle_metrics verified;
    enum vcs_source_bundle_result result =
        vcs_source_bundle_sharded_verify(
            bundle, expected_tree_root, &verified);
    if (result != VCS_SOURCE_BUNDLE_OK) return result;
    if (!workspace || !vcs_object_store_init(workspace))
        return VCS_SOURCE_BUNDLE_ERR_STORE;
    struct vcs_manifest manifest;
    if (!vcs_manifest_parse(bundle->manifest_wire,
                            bundle->manifest_wire_len, &manifest))
        return VCS_SOURCE_BUNDLE_ERR_WIRE;
    const struct vcs_source_bundle_shard *parts[256] = {0};
    uint64_t sizes[256], source_bytes = 0;
    if (!sharded_manifest_shape(&manifest, sizes, &source_bytes)) {
        vcs_manifest_free(&manifest);
        return VCS_SOURCE_BUNDLE_ERR_WIRE;
    }
    for (size_t i = 0; i < bundle->shard_count; i++)
        parts[bundle->shards[i].index] = &bundle->shards[i];
    struct vcs_source_bundle_metrics admitted = verified;
    for (uint16_t shard = 0; result == VCS_SOURCE_BUNDLE_OK &&
                              shard < 256u; shard++) {
        if (sizes[shard] == 0) continue;
        uint8_t *payload = NULL;
        result = sharded_decode(parts[shard], shard, (size_t)sizes[shard],
                                 &payload);
        size_t off = 0;
        for (size_t i = 0; result == VCS_SOURCE_BUNDLE_OK &&
                           i < manifest.count; i++) {
            const struct vcs_entry *entry = &manifest.entries[i];
            if (sharded_index(entry->path) != shard) continue;
            bool existed = vcs_object_has(workspace, entry->blob);
            bool repaired = false;
            uint8_t stored[32];
            if (!vcs_object_put_repair(
                    workspace, payload + off, (size_t)entry->size,
                    VCS_TAG_BLOB, stored, &repaired) ||
                memcmp(stored, entry->blob, 32) != 0) {
                result = VCS_SOURCE_BUNDLE_ERR_STORE;
                break;
            }
            if (existed && !repaired) {
                admitted.reused_blobs++;
                admitted.reused_bytes += entry->size;
            } else {
                admitted.new_blobs++;
                admitted.new_bytes += entry->size;
            }
            admitted.repaired = admitted.repaired || repaired;
            off += (size_t)entry->size;
        }
        free(payload);
    }
    if (result == VCS_SOURCE_BUNDLE_OK) {
        bool existed = vcs_object_has(workspace, expected_tree_root);
        bool repaired = false;
        if (!vcs_object_put_addressed_repair(
                workspace, expected_tree_root, bundle->manifest_wire,
                bundle->manifest_wire_len, &repaired))
            result = VCS_SOURCE_BUNDLE_ERR_STORE;
        else {
            admitted.manifest_reused = existed && !repaired;
            admitted.repaired = admitted.repaired || repaired;
        }
    }
    if (result == VCS_SOURCE_BUNDLE_OK && metrics) *metrics = admitted;
    vcs_manifest_free(&manifest);
    return result;
}
