/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: which baked block a STAGED consensus-state bundle's install waits on.
 *
 * A bundle named consensus-state-bundle-<H>.sqlite whose H has a baked
 * commitment (the ROM keystone or a ladder rung,
 * get_baked_rom_state_checkpoint_at_height) waits on that commitment's header
 * and its Equihash solution; any other name, or no bundle, waits on the compiled
 * SHA3 checkpoint exactly as before the ladder. This only decides what to WAIT
 * on; trust still binds at install against the full baked commitment. */

#include "config/consensus_state_install_runtime.h"

#include "chain/checkpoints.h"

#include <stdint.h>
#include <string.h>

/* Height from a canonical "consensus-state-bundle-<N>.sqlite" basename, or -1. */
static long staged_bundle_name_height(const char *name)
{
    static const char PFX[] = "consensus-state-bundle-";
    static const char SFX[] = ".sqlite";
    size_t pl = sizeof(PFX) - 1, sl = sizeof(SFX) - 1, nl = strlen(name);
    if (nl <= pl + sl || strncmp(name, PFX, pl) != 0 ||
        strcmp(name + nl - sl, SFX) != 0)
        return -1;
    size_t digits = nl - pl - sl;
    if (digits >= 10)
        return -1;
    long h = 0;
    for (size_t i = 0; i < digits; i++) {
        char c = name[pl + i];
        if (c < '0' || c > '9')
            return -1;
        h = h * 10 + (c - '0');
    }
    return h;
}

bool boot_staged_bundle_wait_target(const char *bundle_path, int32_t *height,
                                    uint8_t block_hash[32])
{
    if (!height || !block_hash)
        return false;
    if (bundle_path) {
        const char *base = strrchr(bundle_path, '/');
        long h = staged_bundle_name_height(base ? base + 1 : bundle_path);
        const struct rom_state_checkpoint *baked =
            (h > 0 && h <= INT32_MAX)
                ? get_baked_rom_state_checkpoint_at_height((int32_t)h)
                : NULL;
        if (baked) {
            *height = baked->height;
            memcpy(block_hash, baked->block_hash, 32);
            return true;
        }
    }
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp)
        return false;
    *height = cp->height;
    memcpy(block_hash, cp->block_hash, 32);
    return true;
}
