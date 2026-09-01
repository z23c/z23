/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Codec and verifier for chunked build-object CAS manifests. */

#include "vcs/build_artifact_manifest.h"

#include "crypto/sha3.h"

#include <string.h>

static void bam_put_u32(uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i < 4; i++) p[i] = (uint8_t)(value >> (8U * i));
}

static void bam_put_u64(uint8_t *p, uint64_t value)
{
    for (unsigned i = 0; i < 8; i++) p[i] = (uint8_t)(value >> (8U * i));
}

static uint32_t bam_get_u32(const uint8_t *p)
{
    uint32_t value = 0;
    for (unsigned i = 0; i < 4; i++) value |= (uint32_t)p[i] << (8U * i);
    return value;
}

static uint64_t bam_get_u64(const uint8_t *p)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; i++) value |= (uint64_t)p[i] << (8U * i);
    return value;
}

bool vcs_build_artifact_manifest_v1_valid(
    const struct vcs_build_artifact_manifest_v1 *manifest)
{
    if (!manifest || manifest->total_bytes == 0 ||
        manifest->total_bytes > VCS_BUILD_ARTIFACT_MAX_BYTES ||
        manifest->chunk_bytes == 0 ||
        manifest->chunk_bytes > VCS_BUILD_ARTIFACT_CHUNK_BYTES ||
        manifest->chunk_count == 0 ||
        manifest->chunk_count > VCS_BUILD_ARTIFACT_MAX_CHUNKS)
        return false;
    uint64_t expected = (manifest->total_bytes + manifest->chunk_bytes - 1) /
                        manifest->chunk_bytes;
    return expected == manifest->chunk_count;
}

bool vcs_build_artifact_manifest_v1_root(
    const struct vcs_build_artifact_manifest_v1 *manifest, uint8_t out[32])
{
    if (!vcs_build_artifact_manifest_v1_valid(manifest) || !out) return false;
    static const char domain[] = "zcl.build_artifact_manifest.v1";
    uint8_t numbers[16];
    bam_put_u64(numbers, manifest->total_bytes);
    bam_put_u32(numbers + 8, manifest->chunk_bytes);
    bam_put_u32(numbers + 12, manifest->chunk_count);
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, manifest->action_sha3, 32);
    sha3_256_write(&sha, numbers, sizeof(numbers));
    sha3_256_write(&sha, &manifest->chunk_sha3[0][0],
                   (size_t)manifest->chunk_count * 32u);
    sha3_256_finalize(&sha, out);
    return true;
}

bool vcs_build_artifact_manifest_v1_serialize(
    const struct vcs_build_artifact_manifest_v1 *manifest,
    uint8_t *wire, size_t wire_cap, size_t *wire_len)
{
    if (!vcs_build_artifact_manifest_v1_valid(manifest) || !wire || !wire_len)
        return false;
    size_t need = 54u + (size_t)manifest->chunk_count * 32u;
    if (wire_cap < need) return false;
    memcpy(wire, "ZBAM", 4); wire[4] = 1; wire[5] = 0;
    memcpy(wire + 6, manifest->action_sha3, 32);
    bam_put_u64(wire + 38, manifest->total_bytes);
    bam_put_u32(wire + 46, manifest->chunk_bytes);
    bam_put_u32(wire + 50, manifest->chunk_count);
    memcpy(wire + 54, manifest->chunk_sha3,
           (size_t)manifest->chunk_count * 32u);
    *wire_len = need;
    return true;
}

bool vcs_build_artifact_manifest_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_build_artifact_manifest_v1 *out)
{
    if (!wire || !out || wire_len < 54 || memcmp(wire, "ZBAM", 4) != 0 ||
        wire[4] != 1 || wire[5] != 0)
        return false;
    uint32_t count = bam_get_u32(wire + 50);
    if (count > VCS_BUILD_ARTIFACT_MAX_CHUNKS ||
        wire_len != 54u + (size_t)count * 32u)
        return false;
    memset(out, 0, sizeof(*out));
    memcpy(out->action_sha3, wire + 6, 32);
    out->total_bytes = bam_get_u64(wire + 38);
    out->chunk_bytes = bam_get_u32(wire + 46);
    out->chunk_count = count;
    memcpy(out->chunk_sha3, wire + 54, (size_t)count * 32u);
    return vcs_build_artifact_manifest_v1_valid(out);
}

bool vcs_build_artifact_manifest_v1_verify_chunk(
    const struct vcs_build_artifact_manifest_v1 *manifest, uint32_t index,
    const uint8_t *bytes, size_t length)
{
    if (!vcs_build_artifact_manifest_v1_valid(manifest) ||
        index >= manifest->chunk_count || !bytes)
        return false;
    uint64_t offset = (uint64_t)index * manifest->chunk_bytes;
    uint64_t remaining = manifest->total_bytes - offset;
    size_t expected = remaining < manifest->chunk_bytes
        ? (size_t)remaining : (size_t)manifest->chunk_bytes;
    if (length != expected) return false;
    uint8_t digest[32];
    sha3_256(bytes, length, digest);
    return memcmp(digest, manifest->chunk_sha3[index], 32) == 0;
}
