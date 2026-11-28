/* purpose: Fold public ZIP 244 and ZIP 229 transaction authorization digests. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_auth_data_root.h"
#include "services/ironwood_checked_wire.h"
#include "crypto/blake2b.h"
#include "primitives/block.h"
#include "primitives/transaction_v6_digest.h"
#include "validation/main_constants.h"
#include <string.h>

static_assert(MAX_BLOCK_TRANSACTIONS <= 65536, "authorization tree requires more levels");

static bool auth_parent(const uint8_t left[32], const uint8_t right[32], uint8_t out[32])
{
    static const uint8_t domain[16] = {'Z','c','a','s','h','A','u','t','h','D','a','t','H','a','s','h'};
    struct blake2b_ctx hash;
    return !blake2b_init_salt_personal(&hash, 32, NULL, 0, NULL, domain) &&
        !blake2b_update(&hash, left, 32) && !blake2b_update(&hash, right, 32) &&
        !blake2b_final(&hash, out, 32);
}

static bool auth_leaf(const struct transaction *tx, uint8_t out[32])
{
    if (tx->version > 0 && tx->version < 5 && !tx->v6_wire.data && !tx->v6_wire.size) {
        memset(out, 0xff, 32);
        return true;
    }
    if (tx->version != IRONWOOD_TX_VERSION) return false;
    struct v6_wire_view view;
    if (!ironwood_checked_wire(tx, MAX_BLOCK_SIZE, &view).ok) return false;
    struct v6_digests digests;
    if (!v6_wire_digests(&view, &digests)) return false;
    memcpy(out, digests.auth, 32);
    return true;
}

struct zcl_result ironwood_auth_data_root(const struct block *block, uint8_t out[32])
{
    if (!block || !out || !block->num_vtx || block->num_vtx > MAX_BLOCK_TRANSACTIONS || !block->vtx)
        return ZCL_ERR(-1, "Invalid authorization root block");
    size_t total = 0;
    for (size_t i = 0; i < block->num_vtx; ++i) {
        size_t size = block->vtx[i].v6_wire.size;
        if (size > MAX_BLOCK_SIZE - total)
            return ZCL_ERR(-1, "Authorization frames exceed block size");
        total += size;
    }
    /* 50000 leaves round up to 65536, so 17 levels suffice. */
    uint8_t forest[17][32] = {{0}}, value[32], parent[32];
    size_t width = 1;
    while (width < block->num_vtx) width *= 2;
    unsigned root_level = 0;
    for (size_t i = 0; i < width; ++i) {
        memset(value, 0, sizeof value);
        if (i < block->num_vtx && !auth_leaf(&block->vtx[i], value))
            return ZCL_ERR(-1, "Unsupported or inconsistent authorization leaf");
        size_t position = i;
        unsigned level = 0;
        while (position & 1) {
            if (!auth_parent(forest[level], value, parent))
                return ZCL_ERR(-1, "Cannot hash authorization root");
            memcpy(value, parent, sizeof value);
            position >>= 1;
            ++level;
        }
        memcpy(forest[level], value, sizeof value);
        root_level = level;
    }
    memcpy(out, forest[root_level], 32);
    return ZCL_OK;
}
