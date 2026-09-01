/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Incremental ZVCS-blob to content.v2 chunk mapping evidence. */
#ifndef ZCL_VCS_PACKAGE_MAPPING_H
#define ZCL_VCS_PACKAGE_MAPPING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_PACKAGE_MAPPING_VERSION 1u

struct vcs_package_mapping_metrics {
    uint64_t bytes_scanned;
    uint32_t new_chunks;
    uint32_t reused_chunks;
    uint32_t blob_misses;
    uint32_t blob_hits;
};

struct vcs_package_mapping_entry {
    uint8_t blob_root[32];
    uint8_t mapping_root[32];
};

struct vcs_package_mapping_set {
    uint32_t version;
    uint8_t source_tree_root[32];
    uint8_t lane_receipt_root[32];
    struct vcs_package_mapping_entry *entries;
    size_t count;
};

void vcs_package_mapping_set_init(struct vcs_package_mapping_set *set);
void vcs_package_mapping_set_free(struct vcs_package_mapping_set *set);

/* Background-worker operation. Every cache miss is loaded from the bounded
 * ZVCS blob CAS, chunked once, stored as immutable mapping evidence, then
 * indexed in one short derived-index transaction. The returned set root
 * binds the exact source tree and human-accepted PROVEN work root. */
bool vcs_package_mapping_set_build(
    const char *repo_root, const uint8_t source_tree_root[32],
    const uint8_t lane_receipt_root[32],
    struct vcs_package_mapping_metrics *metrics,
    uint8_t mapping_set_root[32]);

/* Read-only load/reverification. The set and every selected blob mapping are
 * root-addressed; callers never trust the rebuildable SQLite projection. */
bool vcs_package_mapping_set_load(
    const char *repo_root, const uint8_t mapping_set_root[32],
    struct vcs_package_mapping_set *out);
bool vcs_package_mapping_set_find(
    const char *repo_root, const struct vcs_package_mapping_set *set,
    const uint8_t blob_root[32], uint64_t expected_size,
    uint8_t **chunk_hashes_out, uint32_t *chunk_count_out);

#endif /* ZCL_VCS_PACKAGE_MAPPING_H */
