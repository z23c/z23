/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private seller content bound to an authenticated file-market offer. */

#ifndef ZCL_DB_MODEL_MARKET_CONTENT_H
#define ZCL_DB_MODEL_MARKET_CONTENT_H

#include "models/activerecord.h"
#include "models/database.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MARKET_CONTENT_PATH_MAX 4096u
#define MARKET_CONTENT_MAX_CHUNKS 4096u

struct market_content_record {
    uint8_t offer_id[32];
    uint8_t root_hash[32];
    char private_path[MARKET_CONTENT_PATH_MAX];
    uint64_t size_bytes;
    uint32_t num_chunks;
    const uint8_t *chunk_hashes;
    size_t chunk_hashes_len;
    int64_t registered_at;
};

/* Path-free projection safe for operator/native/REST status output. */
struct market_content_public_record {
    uint8_t offer_id[32];
    uint8_t root_hash[32];
    uint64_t size_bytes;
    uint32_t num_chunks;
    int64_t registered_at;
};

/* One exact chunk relationship, including the private path used only by the
 * seller-side service. Callers must never render private_path. */
struct market_content_chunk_record {
    struct market_content_public_record content;
    char private_path[MARKET_CONTENT_PATH_MAX];
    uint32_t chunk_index;
    uint8_t chunk_sha3[32];
};

enum market_content_state_result {
    MARKET_CONTENT_STATE_ERROR = -1,
    MARKET_CONTENT_STATE_ABSENT = 0,
    MARKET_CONTENT_STATE_PRESENT = 1,
};

struct ar_callbacks *db_market_content_callbacks(void);
bool db_market_content_validate(const struct market_content_record *record,
                                struct ar_errors *errors);
bool db_market_content_save(struct node_db *ndb,
                            const struct market_content_record *record);
bool db_market_content_find_chunk(
    struct node_db *ndb, const uint8_t offer_id[32], uint32_t chunk_index,
    struct market_content_chunk_record *out);
int db_market_content_list(struct node_db *ndb,
                           struct market_content_public_record *out,
                           size_t max);
/* One statement returns the bounded rows and uncapped total from the same
 * SQLite snapshot. Errors are distinct from an empty registry. */
int db_market_content_list_snapshot(
    struct node_db *ndb, struct market_content_public_record *out, size_t max,
    int *total_out);
/* Tri-state read of the complete durable row identity. Absence is distinct
 * from a read error; every persisted field contributes canonical bytes. */
enum market_content_state_result db_market_content_registration_identity(
    struct node_db *ndb, const uint8_t offer_id[32], uint8_t identity[32]);
/* Uncapped row total. -1 only when the registry is unreadable. */
int db_market_content_count(struct node_db *ndb);

#endif
