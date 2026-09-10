/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Shared Merkle snapshot records for the inventory-current seam. */

#ifndef ZCL_CODEINDEX_MERKLE_INTERNAL_H
#define ZCL_CODEINDEX_MERKLE_INTERNAL_H

#include "codeindex_priv.h"
#include "codeindex/codeindex_merkle.h"

struct merkle_leaf_rec {
    char                   path[256];
    struct zcl_sha3_digest digest;
    struct zcl_sha3_digest content_digest;
    uint64_t               size;
    struct ci_merkle_stat_key key;
    bool                   dirty;
};

struct merkle_node_rec {
    char                   path[256];
    struct zcl_sha3_digest digest;
    uint32_t               direct_children;
    uint32_t               file_count;
    uint32_t               dir_count;
    uint64_t               total_bytes;
};

struct merkle_snapshot {
    struct merkle_leaf_rec *leaves;
    uint32_t                nleaves;
    struct merkle_node_rec *nodes;
    uint32_t                nnodes;
};

void merkle_snapshot_free(struct merkle_snapshot *s);
bool merkle_snapshot_load(const char *root, struct merkle_snapshot *out,
                          bool *found);
const struct merkle_leaf_rec *
merkle_find_leaf(const struct merkle_leaf_rec *v, uint32_t n, const char *path);
const struct merkle_node_rec *
merkle_find_node(const struct merkle_node_rec *v, uint32_t n, const char *path);

#endif /* ZCL_CODEINDEX_MERKLE_INTERNAL_H */
