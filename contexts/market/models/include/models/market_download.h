/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: durable buyer-side paid-file assembly progress. */

#ifndef ZCL_DB_MODEL_MARKET_DOWNLOAD_H
#define ZCL_DB_MODEL_MARKET_DOWNLOAD_H

#include "models/activerecord.h"
#include "models/database.h"

#include <stdbool.h>
#include <stdint.h>

#define MARKET_DOWNLOAD_PATH_MAX 4096u
#define MARKET_DOWNLOAD_MAX_CHUNKS 4096u

enum market_download_state {
    MARKET_DOWNLOAD_FETCHING = 0,
    MARKET_DOWNLOAD_COMPLETE = 1,
    MARKET_DOWNLOAD_FAILED = 2,
};

struct market_download_record {
    uint8_t plan_id[32];
    uint8_t offer_id[32];
    uint8_t root_hash[32];
    char private_destination[MARKET_DOWNLOAD_PATH_MAX];
    char private_staging[MARKET_DOWNLOAD_PATH_MAX];
    uint64_t size_bytes;
    uint32_t num_chunks;
    uint32_t chunks_received;
    uint64_t bytes_received;
    enum market_download_state state;
    int64_t created_at;
    int64_t updated_at;
};

struct market_download_chunk_record {
    uint8_t plan_id[32];
    uint32_t chunk_index;
    uint32_t size_bytes;
    uint8_t chunk_sha3[32];
    int64_t created_at;
};

struct ar_callbacks *db_market_download_callbacks(void);
struct ar_callbacks *db_market_download_chunk_callbacks(void);
bool db_market_download_validate(const struct market_download_record *record,
                                 struct ar_errors *errors);
bool db_market_download_chunk_validate(
    const struct market_download_chunk_record *record,
    struct ar_errors *errors);
bool db_market_download_save(struct node_db *ndb,
                             const struct market_download_record *record);
bool db_market_download_find(struct node_db *ndb,
                             const uint8_t plan_id[32],
                             struct market_download_record *out);
bool db_market_download_chunk_save(
    struct node_db *ndb,
    const struct market_download_chunk_record *record);
bool db_market_download_chunk_find(
    struct node_db *ndb, const uint8_t plan_id[32], uint32_t chunk_index,
    struct market_download_chunk_record *out);
int db_market_download_chunk_count(struct node_db *ndb,
                                   const uint8_t plan_id[32]);
const char *market_download_state_name(enum market_download_state state);

#endif
