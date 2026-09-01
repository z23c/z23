/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * checkpoint_rung_from_rom_checkpoint — the ONE rung helper that needs the
 * sealed `struct rom_state_checkpoint` layout, kept out of checkpoint_rung.c so
 * that TU stays free of the chain/ include tree (and thus standalone-linkable
 * into tools/checkpoint_rung_export). See storage/checkpoint_rung.h.
 */

#include "storage/checkpoint_rung.h"

#include "chain/checkpoints.h"  /* struct rom_state_checkpoint */
#include "util/log_macros.h"

#include <string.h>

bool checkpoint_rung_from_rom_checkpoint(const struct rom_state_checkpoint *cp,
                                         const uint8_t chainwork[32],
                                         struct checkpoint_rung *out)
{
    if (!cp || !out)
        LOG_FAIL("checkpoint_rung",
                 "from_rom_checkpoint: NULL arg (cp=%p out=%p)",
                 (const void *)cp, (const void *)out);
    memset(out, 0, sizeof(*out));
    out->height = cp->height;
    memcpy(out->block_hash, cp->block_hash, 32);
    memcpy(out->utxo_root, cp->utxo_root, 32);
    out->utxo_count = cp->utxo_count;
    out->total_supply = cp->total_supply;
    memcpy(out->anchor_digest, cp->anchor_digest, 32);
    out->anchor_count = cp->anchor_count;
    memcpy(out->sprout_frontier_root, cp->sprout_frontier_root, 32);
    out->sprout_frontier_height = cp->sprout_frontier_height;
    memcpy(out->sapling_frontier_root, cp->sapling_frontier_root, 32);
    out->sapling_frontier_height = cp->sapling_frontier_height;
    memcpy(out->nullifier_digest, cp->nullifier_digest, 32);
    out->nullifier_count = cp->nullifier_count;
    if (chainwork)
        memcpy(out->chainwork, chainwork, 32);
    checkpoint_rung_finalize(out);
    return true;
}
