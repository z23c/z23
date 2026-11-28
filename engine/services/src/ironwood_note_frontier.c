/* purpose: Maintain the depth-32 public Ironwood commitment frontier. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_note_frontier.h"
#include "ironwood_pasta_internal.h"
#include <string.h>

#define NOTE_CAPACITY (UINT64_C(1) << IRONWOOD_NOTE_TREE_DEPTH)

static struct zcl_result append_commitment(struct ironwood_note_frontier *tree,
    const uint8_t leaf[32], const uint8_t *params, size_t size)
{
    struct zcl_result r = ironwood_pasta_fp_canonical(leaf);
    if (!r.ok) return r;
    uint8_t node[32];
    memcpy(node, leaf, sizeof node);
    unsigned level = 0;
    for (uint64_t occupied = tree->count; occupied & 1; occupied >>= 1) {
        r = ironwood_merkle_crh(level, tree->slots[level], node, params, size, node);
        if (!r.ok) return r;
        memset(tree->slots[level], 0, sizeof node);
        ++level;
    }
    memcpy(tree->slots[level], node, sizeof node);
    ++tree->count;
    return ZCL_OK;
}

static struct zcl_result frontier_root(const struct ironwood_note_frontier *tree,
    const uint8_t *params, size_t size, uint8_t root[32])
{
    if (tree->count == NOTE_CAPACITY) {
        struct zcl_result pin = ironwood_merkle_parameters_validate(params, size);
        if (!pin.ok) return pin;
        struct zcl_result r = ironwood_pasta_fp_canonical(tree->slots[IRONWOOD_NOTE_TREE_DEPTH]);
        if (r.ok) memcpy(root, tree->slots[IRONWOOD_NOTE_TREE_DEPTH], 32);
        return r;
    }
    uint8_t empty[32] = {2};
    memcpy(root, empty, sizeof empty);
    for (unsigned level = 0; level < IRONWOOD_NOTE_TREE_DEPTH; ++level) {
        struct zcl_result r;
        if ((tree->count >> level) & 1)
            r = ironwood_merkle_crh(level, tree->slots[level], root, params, size, root);
        else
            r = ironwood_merkle_crh(level, root, empty, params, size, root);
        if (!r.ok) return r;
        if (!tree->count) {
            memcpy(empty, root, sizeof empty);
        } else if (level + 1 < IRONWOOD_NOTE_TREE_DEPTH) {
            r = ironwood_merkle_crh(level, empty, empty, params, size, empty);
            if (!r.ok) return r;
        }
    }
    return ZCL_OK;
}

struct zcl_result ironwood_note_frontier_extend(struct ironwood_note_frontier *frontier,
    const uint8_t (*commitments)[32], size_t count, const uint8_t *parameters,
    size_t parameters_size, uint8_t anchor[32])
{
    if (!frontier || !anchor || !parameters || (count && !commitments) ||
        frontier->count > NOTE_CAPACITY || count > NOTE_CAPACITY - frontier->count ||
        count > SIZE_MAX / sizeof *commitments)
        return ZCL_ERR(-1, "Invalid Ironwood note frontier or batch size");
    struct ironwood_note_frontier next = *frontier;
    for (size_t i = 0; i < count; ++i) {
        struct zcl_result r = append_commitment(&next, commitments[i], parameters, parameters_size);
        if (!r.ok) return r;
    }
    uint8_t root[32];
    struct zcl_result r = frontier_root(&next, parameters, parameters_size, root);
    if (!r.ok) return r;
    *frontier = next;
    memcpy(anchor, root, sizeof root);
    return ZCL_OK;
}
