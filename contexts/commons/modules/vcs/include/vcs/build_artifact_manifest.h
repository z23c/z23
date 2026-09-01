/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Dedicated chunked CAS manifest for one build object artifact. */

#ifndef ZCL_VCS_BUILD_ARTIFACT_MANIFEST_H
#define ZCL_VCS_BUILD_ARTIFACT_MANIFEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_BUILD_ARTIFACT_CHUNK_BYTES (1024u * 1024u)
#define VCS_BUILD_ARTIFACT_MAX_CHUNKS 256u
#define VCS_BUILD_ARTIFACT_MAX_BYTES \
    (UINT64_C(256) * 1024u * 1024u)
#define VCS_BUILD_ARTIFACT_WIRE_MAX \
    (4u + 2u + 32u + 8u + 4u + 4u + VCS_BUILD_ARTIFACT_MAX_CHUNKS * 32u)

struct vcs_build_artifact_manifest_v1 {
    uint8_t action_sha3[32];
    uint64_t total_bytes;
    uint32_t chunk_bytes;
    uint32_t chunk_count;
    uint8_t chunk_sha3[VCS_BUILD_ARTIFACT_MAX_CHUNKS][32];
};

bool vcs_build_artifact_manifest_v1_valid(
    const struct vcs_build_artifact_manifest_v1 *manifest);
bool vcs_build_artifact_manifest_v1_root(
    const struct vcs_build_artifact_manifest_v1 *manifest, uint8_t out[32]);
bool vcs_build_artifact_manifest_v1_serialize(
    const struct vcs_build_artifact_manifest_v1 *manifest,
    uint8_t *wire, size_t wire_cap, size_t *wire_len);
bool vcs_build_artifact_manifest_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_build_artifact_manifest_v1 *out);
bool vcs_build_artifact_manifest_v1_verify_chunk(
    const struct vcs_build_artifact_manifest_v1 *manifest, uint32_t index,
    const uint8_t *bytes, size_t length);

#endif /* ZCL_VCS_BUILD_ARTIFACT_MANIFEST_H */
