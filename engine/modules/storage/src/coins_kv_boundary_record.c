/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Boundary coin-root records bound to the block they were computed at.
 *
 * Each record is 64 bytes under "coin_root_v2:<height>": the 32-byte block
 * hash (internal byte order) followed by the 32-byte coins_kv_commitment. The
 * writer stores a record only while the coins applied frontier equals
 * height + 1, so the root is the coin set after exactly that block. */

#include "storage/coins_kv.h"
#include "storage/progress_store.h"

#include <stdio.h>
#include <string.h>

#define BOUNDARY_RECORD_LEN 64

static void boundary_record_key(int32_t height, char *buf, size_t cap)
{
    snprintf(buf, cap, "coin_root_v2:%d", (int)height);
}

bool coins_kv_boundary_record_set_in_tx(struct sqlite3 *db, int32_t height,
                                        const uint8_t block_hash[32],
                                        const uint8_t root[32])
{
    uint8_t blob[BOUNDARY_RECORD_LEN];
    char key[40];
    if (!db || !block_hash || !root || height < 0)
        return false;
    memcpy(blob, block_hash, 32);
    memcpy(blob + 32, root, 32);
    boundary_record_key(height, key, sizeof(key));
    return progress_meta_set_in_tx(db, key, blob, sizeof(blob));
}

bool coins_kv_boundary_record_get(struct sqlite3 *db, int32_t height,
                                  uint8_t block_hash_out[32],
                                  uint8_t root_out[32], bool *found)
{
    uint8_t blob[BOUNDARY_RECORD_LEN];
    char key[40];
    size_t n = 0;
    bool f = false;
    if (found)
        *found = false;
    if (!db || !block_hash_out || !root_out || height < 0)
        return false;
    boundary_record_key(height, key, sizeof(key));
    if (!progress_meta_get(db, key, blob, sizeof(blob), &n, &f))
        return false;
    if (!f)
        return true;
    if (n != sizeof(blob))
        return false;
    memcpy(block_hash_out, blob, 32);
    memcpy(root_out, blob + 32, 32);
    if (found)
        *found = true;
    return true;
}
