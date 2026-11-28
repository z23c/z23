/* purpose: Compare Ironwood frontier transitions with Orchard 0.16 anchors. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_note_frontier.h"
#include "base/hex.h"
#include <stdio.h>
#include <string.h>

static const char *const roots[] = {
    "ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f",
    "ba3699744f9a51d60cead29b609ac37d73e269864e08e79e2aedaca67c809608",
    "382ccad224a7e382b6e18d38beb6f518ef9a30ea0a0cc259aa9021737d41cf22",
    "011466e64a799c5ab7d8c83741f1dc5ffebabb53f00a53a1966a1ddf90827f1e",
    "660bc565dc99b5f2d377d0946b77a34e681f218b2d467ab725fd6ff2d554ff3a"
};

static bool correct_anchor(size_t count, const uint8_t *root)
{
    uint8_t expected[32];
    return zcl_hex_decode(roots[count], expected, sizeof expected) &&
           memcmp(expected, root, sizeof expected) == 0;
}

static bool checkpoint_roundtrip(const struct ironwood_note_frontier *tree,
    const uint8_t root[32], const uint8_t *params, size_t expected_size)
{
    uint8_t frame[IRONWOOD_FRONTIER_STORAGE_MAX];
    size_t size = 0;
    struct ironwood_note_frontier restored = {0};
    if (!ironwood_frontier_encode(tree, frame, sizeof frame, &size).ok ||
        size != expected_size || frame[0] != 1 ||
        !ironwood_frontier_restore(frame, size, tree->count, root, params,
            IRONWOOD_MERKLE_PARAMETERS_SIZE, &restored).ok) return false;
    return restored.count == tree->count &&
           !memcmp(restored.slots, tree->slots, sizeof tree->slots);
}

static bool damaged_checkpoints(const uint8_t *params, const uint8_t leaves[4][32])
{
    struct ironwood_note_frontier tree = {0}, out = {.count = 15};
    uint8_t frame[IRONWOOD_FRONTIER_STORAGE_MAX] = {0}, root[32];
    size_t size = 0;
    if (!ironwood_note_frontier_extend(&tree, leaves, 3, params,
            IRONWOOD_MERKLE_PARAMETERS_SIZE, root).ok ||
        !checkpoint_roundtrip(&tree, root, params, 73) ||
        !ironwood_frontier_encode(&tree, frame, sizeof frame, &size).ok) return false;
    /* The low slot is the last leaf. The higher slot covers the first pair. */
    if (frame[1] != 3 || memcmp(frame + 9, leaves[2], 32) ||
        memcmp(frame + 41, tree.slots[1], 32)) return false;
    struct ironwood_note_frontier saved;
    memcpy(&saved, &out, sizeof saved);
    uint8_t wrong_root[32];
    memcpy(wrong_root, root, sizeof root);
    wrong_root[0] ^= 1;
    if (ironwood_frontier_restore(frame, size, 3, wrong_root, params, IRONWOOD_MERKLE_PARAMETERS_SIZE, &out).ok ||
        ironwood_frontier_restore(frame, size, 3, root, params, 0, &out).ok) return false;
    if (ironwood_frontier_restore(frame, size - 1, 3, root, params, IRONWOOD_MERKLE_PARAMETERS_SIZE, &out).ok ||
        ironwood_frontier_restore(frame, size + 1, 3, root, params, IRONWOOD_MERKLE_PARAMETERS_SIZE, &out).ok ||
        ironwood_frontier_restore(frame, size, 5, root, params, IRONWOOD_MERKLE_PARAMETERS_SIZE, &out).ok) return false;
    frame[0]++;
    if (ironwood_frontier_restore(frame, size, 3, root, params, IRONWOOD_MERKLE_PARAMETERS_SIZE, &out).ok) return false;
    frame[0]--;
    memcpy(frame + 9, leaves[1], 32);
    if (ironwood_frontier_restore(frame, size, 3, root, params, IRONWOOD_MERKLE_PARAMETERS_SIZE, &out).ok) return false;
    memset(frame + 9, 0xff, 32);
    if (ironwood_frontier_restore(frame, size, 3, root, params, IRONWOOD_MERKLE_PARAMETERS_SIZE, &out).ok ||
        memcmp(&out, &saved, sizeof out)) return false;
    memset(tree.slots[1], 0xff, 32);
    memset(frame, 0xaa, sizeof frame);
    uint8_t before[sizeof frame];
    memcpy(before, frame, sizeof frame);
    size = 123;
    return !ironwood_frontier_encode(&tree, frame, sizeof frame, &size).ok &&
           !ironwood_frontier_encode(&tree, frame, 1, &size).ok &&
           size == 123 && !memcmp(before, frame, sizeof frame);
}

static bool append_shapes(const uint8_t *params, const uint8_t leaves[4][32])
{
    struct ironwood_note_frontier tree = {0}, batch = {0};
    uint8_t root[32], batched[32];
    for (size_t i = 0; i <= 4; ++i) {
        if (!ironwood_note_frontier_extend(&tree, i ? leaves + i - 1 : NULL,
                i ? 1 : 0, params, IRONWOOD_MERKLE_PARAMETERS_SIZE, root).ok ||
            tree.count != i || !correct_anchor(i, root) || !checkpoint_roundtrip(&tree, root, params, i == 0 ? 9 : i == 3 ? 73 : 41)) return false;
    }
    return ironwood_note_frontier_extend(&batch, leaves, 4, params,
                IRONWOOD_MERKLE_PARAMETERS_SIZE, batched).ok &&
           tree.count == batch.count && memcmp(tree.slots, batch.slots, sizeof tree.slots) == 0 && memcmp(root, batched, 32) == 0;
}

static bool rollback(const uint8_t *params, const uint8_t leaves[4][32])
{
    struct ironwood_note_frontier tree = {0};
    uint8_t root[32], before[32], bad[2][32];
    if (!ironwood_note_frontier_extend(&tree, leaves, 1, params,
                                      IRONWOOD_MERKLE_PARAMETERS_SIZE, root).ok) return false;
    struct ironwood_note_frontier saved;
    memcpy(&saved, &tree, sizeof saved);
    memcpy(before, root, 32);
    memcpy(bad[0], leaves[1], 32);
    memset(bad[1], 0xff, 32);
    return !ironwood_note_frontier_extend(&tree, bad, 2, params,
                IRONWOOD_MERKLE_PARAMETERS_SIZE, root).ok &&
           !ironwood_note_frontier_extend(&tree, leaves, 1, params, 0, root).ok &&
           memcmp(&saved, &tree, sizeof saved) == 0 && memcmp(before, root, 32) == 0;
}

/* A prefix of 2^32-1 uncommitted leaves has one empty subtree at every level. */
static bool capacity(const uint8_t *params)
{
    struct ironwood_note_frontier tree = {.count = UINT32_MAX};
    uint8_t leaf[1][32] = {{2}}, root[32];
    memcpy(tree.slots[0], leaf[0], 32);
    for (unsigned i = 1; i < IRONWOOD_NOTE_TREE_DEPTH; ++i)
        if (!ironwood_merkle_crh(i-1, tree.slots[i-1], tree.slots[i-1],
                params, IRONWOOD_MERKLE_PARAMETERS_SIZE, tree.slots[i]).ok) return false;
    if (!ironwood_note_frontier_extend(&tree, NULL, 0, params,
            IRONWOOD_MERKLE_PARAMETERS_SIZE, root).ok ||
        !checkpoint_roundtrip(&tree, root, params, IRONWOOD_FRONTIER_STORAGE_MAX)) return false;
    if (!ironwood_note_frontier_extend(&tree, leaf, 1, params,
            IRONWOOD_MERKLE_PARAMETERS_SIZE, root).ok || !correct_anchor(0, root) ||
        tree.count != (UINT64_C(1) << 32) || !checkpoint_roundtrip(&tree, root, params, 41)) return false;
    struct ironwood_note_frontier full;
    memcpy(&full, &tree, sizeof full);
    return !ironwood_note_frontier_extend(&tree, leaf, 1, params,
                IRONWOOD_MERKLE_PARAMETERS_SIZE, root).ok &&
           memcmp(&full, &tree, sizeof full) == 0 && correct_anchor(0, root);
}

int test_ironwood_note_frontier(void)
{
    uint8_t params[IRONWOOD_MERKLE_PARAMETERS_SIZE], leaves[4][32];
    FILE *f = fopen("tests/fixtures/ironwood/sinsemilla-merkle-parameters.bin", "rb");
    if (!f) return 1;
    bool ok = fread(params, 1, sizeof params, f) == sizeof params && fgetc(f) == EOF && !ferror(f);
    if (fclose(f) != 0 || !ok) return 1;
    if (!zcl_hex_decode("7bd7041a794980ac3d8c413946d9a58e2b70de01ad27bfe18959f63d90e2b31a", leaves[0], 32) ||
        !zcl_hex_decode("72d98fa009f5a73de8e05e9e25744cf6518f503881b1ed4056ae4fe176120f04", leaves[1], 32)) return 1;
    memcpy(leaves + 2, leaves, 64);
    return append_shapes(params, leaves) && rollback(params, leaves) && damaged_checkpoints(params, leaves) && capacity(params) ? 0 : 1;
}
