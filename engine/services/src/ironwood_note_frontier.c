/* purpose: Maintain the depth-32 public Ironwood commitment frontier. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_note_frontier.h"
#include "ironwood_pasta_internal.h"
#include "primitives/transaction_v6_wire.h"
#include "base/serialize_le.h"
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

static size_t frontier_storage_size(uint64_t count)
{
    size_t size = 9;
    for (; count; count &= count - 1)
        size += 32;
    return size;
}

struct zcl_result ironwood_frontier_encode(const struct ironwood_note_frontier *tree,
    uint8_t *bytes, size_t capacity, size_t *written)
{
    if (!tree || !bytes || !written || tree->count > NOTE_CAPACITY)
        return ZCL_ERR(-1, "Invalid Ironwood frontier to encode");
    size_t size = frontier_storage_size(tree->count);
    if (size > capacity) return ZCL_ERR(-1, "Short Ironwood frontier buffer");
    uint8_t frame[IRONWOOD_FRONTIER_STORAGE_MAX];
    frame[0] = 1;
    zcl_write_u64_le(frame + 1, tree->count);
    size_t offset = 9;
    for (unsigned i = 0; i <= IRONWOOD_NOTE_TREE_DEPTH; ++i) {
        if (!((tree->count >> i) & 1)) continue;
        struct zcl_result r = ironwood_pasta_fp_canonical(tree->slots[i]);
        if (!r.ok) return r;
        memcpy(frame + offset, tree->slots[i], 32);
        offset += 32;
    }
    memcpy(bytes, frame, size);
    *written = size;
    return ZCL_OK;
}

struct zcl_result ironwood_frontier_restore(const uint8_t *bytes, size_t size,
    uint64_t expected_count, const uint8_t expected_root[32], const uint8_t *parameters,
    size_t parameters_size, struct ironwood_note_frontier *out)
{
    if (!bytes || !out || !expected_root || !parameters || expected_count > NOTE_CAPACITY ||
        size != frontier_storage_size(expected_count) || bytes[0] != 1 ||
        zcl_read_u64_le(bytes + 1) != expected_count)
        return ZCL_ERR(-1, "Invalid Ironwood frontier record or leaf count");
    struct ironwood_note_frontier next = {.count = expected_count};
    size_t offset = 9;
    for (unsigned i = 0; i <= IRONWOOD_NOTE_TREE_DEPTH; ++i) {
        if (!((expected_count >> i) & 1)) continue;
        memcpy(next.slots[i], bytes + offset, 32);
        offset += 32;
    }
    uint8_t root[32];
    struct zcl_result r = frontier_root(&next, parameters, parameters_size, root);
    if (!r.ok) return r;
    if (memcmp(root, expected_root, sizeof root))
        return ZCL_ERR(-1, "Ironwood frontier does not match expected anchor");
    *out = next;
    return ZCL_OK;
}

struct zcl_result ironwood_frontier_append_v6(struct ironwood_note_frontier *frontier,
    const uint8_t *wire, size_t wire_size, const uint8_t *parameters, size_t parameters_size)
{
    if (!frontier || frontier->count > NOTE_CAPACITY)
        return ZCL_ERR(-1, "Invalid Ironwood frontier");
    struct v6_wire_view view;
    if (v6_core_parse(wire, wire_size, &view) != V6_WIRE_OK)
        return ZCL_ERR(-1, "Invalid v6 transaction frame for Ironwood frontier");
    if (view.ironwood.count > NOTE_CAPACITY - frontier->count)
        return ZCL_ERR(-1, "Ironwood block commitments exceed tree capacity");
    struct zcl_result r = ironwood_merkle_parameters_validate(parameters, parameters_size);
    if (!r.ok) return r;
    struct ironwood_note_frontier next = *frontier;
    for (uint64_t i = 0; i < view.ironwood.count; ++i) {
        struct v6_action_view action;
        if (!v6_core_bundle_action(&view.ironwood, i, &action) || action.cmx.size != 32)
            return ZCL_ERR(-1, "Cannot read Ironwood action commitment");
        r = append_commitment(&next, action.cmx.data, parameters, parameters_size);
        if (!r.ok) return r;
    }
    *frontier = next;
    return ZCL_OK;
}
