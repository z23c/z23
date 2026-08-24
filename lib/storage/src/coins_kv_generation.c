/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "storage/coins_kv.h"
#include "storage/progress_store.h"

#include <stdint.h>

bool coins_kv_get_authority_generation(sqlite3 *db, uint64_t *out)
{
    if (out) *out = 0;
    if (!db || !out) return false;
    uint8_t blob[8] = {0};
    size_t len = 0;
    bool found = false;
    if (!progress_meta_get_blob_exact(
            db, COINS_KV_AUTHORITY_GENERATION_KEY, blob, sizeof(blob),
            &len, &found) || (found && len != sizeof(blob)))
        return false;
    if (found)
        for (int i = 0; i < 8; i++) *out |= (uint64_t)blob[i] << (8 * i);
    return true;
}

bool coins_kv_bump_authority_generation_in_tx(sqlite3 *db)
{
    uint64_t generation = 0;
    uint8_t blob[8] = {0};
    if (!coins_kv_get_authority_generation(db, &generation) ||
        generation == UINT64_MAX)
        return false;
    generation++;
    for (int i = 0; i < 8; i++) blob[i] = (uint8_t)(generation >> (8 * i));
    return progress_meta_set_in_tx(
        db, COINS_KV_AUTHORITY_GENERATION_KEY, blob, sizeof(blob));
}
