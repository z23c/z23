/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Decode the reducer's canonical durable trusted-base declaration. */

#include "jobs/reducer_frontier.h"
#include "reducer_frontier_trusted_base_internal.h"

#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

bool reducer_frontier_trusted_base_height_read(sqlite3 *db, int32_t *out,
                                                bool *found)
{
    if (!db || !out || !found)
        LOG_FAIL("reducer", "trusted-base height read requires outputs");
    *found = false;
    uint8_t blob[8] = {0};
    size_t n = 0;
    bool present = false;
    if (!progress_meta_get_blob_exact(db, REDUCER_TRUSTED_BASE_HEIGHT_KEY,
                                      blob, sizeof(blob), &n, &present))
        LOG_FAIL("reducer", "trusted-base height read failed");
    if (!present)
        return true;
    if (n != sizeof(blob))
        LOG_FAIL("reducer", "trusted-base height malformed len=%zu", n);

    uint64_t value = 0;
    for (int i = 7; i >= 0; i--)
        value = (value << 8) | blob[i];
    if (value > INT32_MAX)
        LOG_FAIL("reducer", "trusted-base height out of range=%llu",
                 (unsigned long long)value);
    *out = (int32_t)value;
    *found = true;
    return true;
}

bool reducer_frontier_trusted_base_read(sqlite3 *db, int32_t *height,
                                        uint8_t hash[32], bool *found)
{
    if (!db || !height || !hash || !found)
        LOG_FAIL("reducer", "trusted-base pair read requires outputs");
    *found = false;
    bool height_found = false;
    if (!reducer_frontier_trusted_base_height_read(db, height,
                                                    &height_found))
        return false; /* raw-return-ok:callee logged the read failure */

    uint8_t stored_hash[32] = {0};
    size_t hash_size = 0;
    bool hash_found = false;
    if (!progress_meta_get_blob_exact(db, REDUCER_TRUSTED_BASE_HASH_KEY,
                                      stored_hash, sizeof(stored_hash),
                                      &hash_size, &hash_found))
        LOG_FAIL("reducer", "trusted-base hash read failed");
    if (!height_found && !hash_found)
        return true;
    if (!height_found || !hash_found || hash_size != sizeof(stored_hash))
        LOG_FAIL("reducer",
                 "trusted-base pair malformed height_found=%d "
                 "hash_found=%d hash_len=%zu",
                 height_found ? 1 : 0, hash_found ? 1 : 0, hash_size);
    memcpy(hash, stored_hash, sizeof(stored_hash));
    *found = true;
    return true;
}

bool reducer_frontier_trusted_base_matches(sqlite3 *db, int32_t height,
                                           const uint8_t hash[32])
{
    if (!hash)
        LOG_FAIL("reducer", "trusted-base match requires a hash");
    int32_t stored_height = -1;
    uint8_t stored_hash[32] = {0};
    bool found = false;
    if (!reducer_frontier_trusted_base_read(db, &stored_height, stored_hash,
                                            &found))
        return false; /* raw-return-ok:callee logged the read failure */
    return found && stored_height == height &&
           memcmp(stored_hash, hash, sizeof(stored_hash)) == 0;
}

bool reducer_frontier_coin_authority_covers(sqlite3 *db, int32_t height)
{
    int32_t applied = -1;
    return db && height >= 0 &&
           coins_kv_is_proven_authority(db, &applied) && applied > height;
}

bool reducer_seed_floor_height_read(sqlite3 *db, int32_t *out, bool *found)
{
    if (!db || !out || !found)
        LOG_FAIL("reducer", "seed-floor height read requires outputs");
    *found = false;
    uint8_t blob[8] = {0};
    size_t n = 0;
    bool present = false;
    if (!progress_meta_get_blob_exact(db, REDUCER_SEED_FLOOR_HEIGHT_KEY,
                                      blob, sizeof(blob), &n, &present))
        LOG_FAIL("reducer", "seed-floor height read failed");
    if (!present)
        return true;
    if (n != sizeof(blob))
        LOG_FAIL("reducer", "seed-floor height malformed len=%zu", n);

    uint64_t value = 0;
    for (int i = 7; i >= 0; i--)
        value = (value << 8) | blob[i];
    if (value > INT32_MAX)
        LOG_FAIL("reducer", "seed-floor height out of range=%llu",
                 (unsigned long long)value);
    *out = (int32_t)value;
    *found = true;
    return true;
}

bool reducer_seed_floor_declare_if_absent(sqlite3 *db, int32_t height)
{
    if (!db || height < 0)
        LOG_FAIL("reducer", "seed-floor declare requires db and height >= 0");
    int32_t existing = 0;
    bool found = false;
    if (!reducer_seed_floor_height_read(db, &existing, &found))
        return false; /* raw-return-ok:callee logged the read failure */
    if (found)
        return true; /* the FIRST seed defines the seeded extent */
    uint8_t blob[8] = {0};
    uint64_t v = (uint64_t)height;
    for (int i = 0; i < 8; i++) {
        blob[i] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
    if (!progress_meta_set_in_tx(db, REDUCER_SEED_FLOOR_HEIGHT_KEY,
                                 blob, sizeof(blob)))
        LOG_FAIL("reducer", "seed-floor declare write failed h=%d", height);
    return true;
}
