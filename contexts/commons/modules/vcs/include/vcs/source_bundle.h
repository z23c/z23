/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: compressed transport for an already-authoritative ZVCS source tree. */

#ifndef ZCL_VCS_SOURCE_BUNDLE_H
#define ZCL_VCS_SOURCE_BUNDLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_SOURCE_BUNDLE_VERSION 1u
#define VCS_SOURCE_BUNDLE_CODEC_ZLIB 1u
#define VCS_SOURCE_BUNDLE_HEADER_BYTES 68u
#define VCS_SOURCE_BUNDLE_MAX_MANIFEST_BYTES (4u * 1024u * 1024u)
#define VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES \
    (UINT64_C(256) * 1024u * 1024u)
#define VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES \
    (UINT64_C(64) * 1024u * 1024u)

#define VCS_SOURCE_BUNDLE_SHARDED_VERSION 2u
#define VCS_SOURCE_BUNDLE_SHARD_COUNT 256u
#define VCS_SOURCE_BUNDLE_SHARD_HEADER_BYTES 64u
#define VCS_SOURCE_BUNDLE_SHARD_PATH_MAX 48u

enum vcs_source_bundle_result {
    VCS_SOURCE_BUNDLE_OK = 0,
    VCS_SOURCE_BUNDLE_ERR_NULL,
    VCS_SOURCE_BUNDLE_ERR_SOURCE,
    VCS_SOURCE_BUNDLE_ERR_LIMIT,
    VCS_SOURCE_BUNDLE_ERR_ALLOC,
    VCS_SOURCE_BUNDLE_ERR_CODEC,
    VCS_SOURCE_BUNDLE_ERR_WIRE,
    VCS_SOURCE_BUNDLE_ERR_ROOT,
    VCS_SOURCE_BUNDLE_ERR_BLOB,
    VCS_SOURCE_BUNDLE_ERR_STORE,
};

struct vcs_source_bundle_metrics {
    uint64_t source_bytes;
    uint64_t compressed_bytes;
    uint64_t new_bytes;
    uint64_t reused_bytes;
    uint32_t file_count;
    uint32_t new_blobs;
    uint32_t reused_blobs;
    bool manifest_reused;
    bool repaired;
};

struct vcs_source_bundle_shard {
    uint16_t index;
    uint8_t *wire;
    size_t wire_len;
};

/* Delta-efficient representation of the same authoritative ZVCS tree. The
 * manifest is carried once, while source blobs are independently compressed
 * into stable path-selected shards. Editing one path therefore changes the
 * manifest and at most one shard instead of shifting a repository-wide
 * compression stream. */
struct vcs_source_bundle_sharded {
    uint8_t *manifest_wire;
    size_t manifest_wire_len;
    struct vcs_source_bundle_shard shards[VCS_SOURCE_BUNDLE_SHARD_COUNT];
    size_t shard_count;
    struct vcs_source_bundle_metrics metrics;
};

void vcs_source_bundle_sharded_init(
    struct vcs_source_bundle_sharded *bundle);
void vcs_source_bundle_sharded_free(
    struct vcs_source_bundle_sharded *bundle);

bool vcs_source_bundle_shard_path(uint16_t index, char *out, size_t out_size);

/* bundle must first be initialized with vcs_source_bundle_sharded_init(). */
enum vcs_source_bundle_result vcs_source_bundle_sharded_create(
    const char *workspace, const uint8_t tree_root[32],
    struct vcs_source_bundle_sharded *bundle);

/* Re-derive the tree root and every blob from a complete in-memory shard set.
 * Verification is read-only and detects missing, duplicate, misplaced,
 * truncated, corrupt, or superfluous shards. */
enum vcs_source_bundle_result vcs_source_bundle_sharded_verify(
    const struct vcs_source_bundle_sharded *bundle,
    const uint8_t expected_tree_root[32],
    struct vcs_source_bundle_metrics *metrics);

/* Verify the complete set first, then admit blobs and manifest into the
 * existing ZVCS CAS with exact-address deduplication and repair. */
enum vcs_source_bundle_result vcs_source_bundle_sharded_import(
    const struct vcs_source_bundle_sharded *bundle,
    const uint8_t expected_tree_root[32], const char *workspace,
    struct vcs_source_bundle_metrics *metrics);

const char *vcs_source_bundle_result_string(
    enum vcs_source_bundle_result result);

/* Build a deterministic zlib-compressed transport from a verified ZVCS tree.
 * The tree manifest and every domain-tagged blob are reloaded and rehashed.
 * The returned wire is transport only: tree_root remains the authority. */
enum vcs_source_bundle_result vcs_source_bundle_create(
    const char *workspace, const uint8_t tree_root[32], uint8_t **wire_out,
    size_t *wire_len_out, struct vcs_source_bundle_metrics *metrics);

/* Parse, decompress and fully rederive a bundle without writing anything. */
enum vcs_source_bundle_result vcs_source_bundle_verify(
    const uint8_t *wire, size_t wire_len,
    const uint8_t expected_tree_root[32],
    struct vcs_source_bundle_metrics *metrics);

/* Verify the complete bundle first, then admit its blobs and manifest into the
 * existing ZVCS CAS. Existing valid objects are reused; corrupt objects at the
 * exact committed addresses are atomically repaired from verified bytes. */
enum vcs_source_bundle_result vcs_source_bundle_import(
    const uint8_t *wire, size_t wire_len,
    const uint8_t expected_tree_root[32], const char *workspace,
    struct vcs_source_bundle_metrics *metrics);

#endif /* ZCL_VCS_SOURCE_BUNDLE_H */
