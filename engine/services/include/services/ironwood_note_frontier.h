/* purpose: Derive Ironwood note anchors from ordered commitment appends. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_NOTE_FRONTIER_H
#define ZCL_IRONWOOD_NOTE_FRONTIER_H
#include "services/ironwood_merkle_crh.h"

enum { IRONWOOD_NOTE_TREE_DEPTH = 32 };
struct ironwood_note_frontier {
    uint64_t count;
    /* Bit i of count identifies the completed left subtree in slots[i].
     * A completely full depth-32 tree has just slot 32 occupied. */
    uint8_t slots[IRONWOOD_NOTE_TREE_DEPTH + 1][32];
};

/* Start with a zero-initialized frontier or a previously successful result.
 * Append canonical cmx values in wire order and return the resulting anchor.
 * An empty batch computes the current anchor. State and anchor (which must
 * be separate objects) are unchanged on failure. No chainstate I/O. */
struct zcl_result ironwood_note_frontier_extend(struct ironwood_note_frontier *frontier,
    const uint8_t (*commitments)[32], size_t count, const uint8_t *parameters,
    size_t parameters_size, uint8_t anchor[32]);

/* Private storage format version 1: version byte, little-endian u64 leaf
 * count, then one canonical field element for each set bit from low to high.
 * At most 32 nodes are occupied (the full tree has a single level-32 node). */
enum { IRONWOOD_FRONTIER_STORAGE_MAX = 1 + 8 + IRONWOOD_NOTE_TREE_DEPTH * 32 };
/* tree, output buffer and written count must be separate objects. Both
 * outputs preserve their prior values on failure. */
struct zcl_result ironwood_frontier_encode(const struct ironwood_note_frontier *tree,
    uint8_t *bytes, size_t capacity, size_t *written);
/* Count and root must come from the caller's expected chainstate. The root
 * alone cannot distinguish an uncommitted leaf from an unused position.
 * Store the result in an object separate from the inputs. On failure the
 * caller's frontier is unchanged. */
struct zcl_result ironwood_frontier_restore(const uint8_t *bytes, size_t size,
    uint64_t expected_count, const uint8_t expected_root[32], const uint8_t *parameters,
    size_t parameters_size, struct ironwood_note_frontier *out);
#endif
