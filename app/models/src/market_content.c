/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * ActiveRecord owner for the private paid-file content registry. */

#include "models/market_content.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "net/file_market.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <limits.h>
#include <string.h>

DEFINE_MODEL_CALLBACKS(market_content)

bool db_market_content_validate(const struct market_content_record *record,
                                struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!record) {
        ar_errors_add(errors, "record", "is NULL");
        return false;
    }
    uint32_t expected_chunks = 0;
    validates_custom(errors, zcl_bytes_any_set(record->offer_id, 32),
                     "offer_id", "can't be all zero");
    validates_custom(errors, zcl_bytes_any_set(record->root_hash, 32),
                     "root_hash", "can't be all zero");
    validates_custom(errors, record->private_path[0] == '/' &&
        strnlen(record->private_path, MARKET_CONTENT_PATH_MAX) <
            MARKET_CONTENT_PATH_MAX,
        "private_path", "must be a bounded absolute canonical path");
    validates_positive(errors, record, size_bytes);
    validates_custom(errors,
        file_market_num_chunks_for_size(record->size_bytes,
                                        &expected_chunks) &&
        expected_chunks == record->num_chunks &&
        record->num_chunks <= MARKET_CONTENT_MAX_CHUNKS,
        "num_chunks", "must exactly cover the bounded content size");
    validates_custom(errors, record->chunk_hashes &&
        record->chunk_hashes_len == (size_t)record->num_chunks * 32u,
        "chunk_hashes", "must contain one digest per chunk");
    validates_positive(errors, record, registered_at);
    if (record->chunk_hashes &&
        record->chunk_hashes_len == (size_t)record->num_chunks * 32u) {
        uint8_t root[32];
        sha3_256(record->chunk_hashes, record->chunk_hashes_len, root);
        validates_custom(errors, memcmp(root, record->root_hash, 32) == 0,
                         "root_hash", "must commit the complete manifest");
    }
    return !ar_errors_any(errors);
}

bool db_market_content_save(struct node_db *ndb,
                            const struct market_content_record *record)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("market", "market content save: database is not open");
    if (!record)
        LOG_FAIL("market", "market content save: record is NULL");

    sqlite3_stmt *s = NULL;
    struct ar_callbacks *cbs = db_market_content_callbacks();
    AR_ADHOC_SAVE(ndb, s,
        "INSERT INTO market_contents(offer_id,root_hash,private_path,"
        "size_bytes,num_chunks,chunk_hashes,registered_at)"
        " VALUES(?,?,?,?,?,?,?) ON CONFLICT(offer_id) DO UPDATE SET "
        "root_hash=excluded.root_hash,private_path=excluded.private_path,"
        "size_bytes=excluded.size_bytes,num_chunks=excluded.num_chunks,"
        "chunk_hashes=excluded.chunk_hashes,"
        "registered_at=excluded.registered_at",
        cbs, "market_content", record, db_market_content_validate,
        AR_BIND_BLOB(s, 1, record->offer_id, 32);
        AR_BIND_BLOB(s, 2, record->root_hash, 32);
        AR_BIND_TEXT(s, 3, record->private_path);
        AR_BIND_INT(s, 4, (int64_t)record->size_bytes);
        AR_BIND_INT(s, 5, record->num_chunks);
        AR_BIND_BLOB(s, 6, record->chunk_hashes,
                     (int)record->chunk_hashes_len);
        AR_BIND_INT(s, 7, record->registered_at));
}

static bool market_content_read_public(
    sqlite3_stmt *s, int base, struct market_content_public_record *out)
{
    if (sqlite3_column_bytes(s, base) != 32 ||
        sqlite3_column_bytes(s, base + 1) != 32)
        LOG_FAIL("market", "market content row has malformed hash lengths");
    memset(out, 0, sizeof(*out));
    AR_READ_BLOB(s, base, out->offer_id, 32);
    AR_READ_BLOB(s, base + 1, out->root_hash, 32);
    out->size_bytes = (uint64_t)AR_COL_INT(s, base + 2);
    out->num_chunks = (uint32_t)AR_COL_INT(s, base + 3);
    out->registered_at = AR_COL_INT(s, base + 4);
    uint32_t expected = 0;
    return out->size_bytes > 0 && out->registered_at > 0 &&
        file_market_num_chunks_for_size(out->size_bytes, &expected) &&
        expected == out->num_chunks &&
        out->num_chunks <= MARKET_CONTENT_MAX_CHUNKS;
}

bool db_market_content_find_chunk(
    struct node_db *ndb, const uint8_t offer_id[32], uint32_t chunk_index,
    struct market_content_chunk_record *out)
{
    if (!ndb || !ndb->open || !offer_id || !out)
        LOG_FAIL("market", "market content chunk find: invalid arguments");
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT offer_id,root_hash,size_bytes,num_chunks,registered_at,"
        "private_path,substr(chunk_hashes,(? * 32) + 1,32) "
        "FROM market_contents WHERE offer_id=? AND ? < num_chunks",
        AR_BIND_INT(s, 1, chunk_index);
        AR_BIND_BLOB(s, 2, offer_id, 32);
        AR_BIND_INT(s, 3, chunk_index),
        memset(out, 0, sizeof(*out));
        if (!market_content_read_public(s, 0, &out->content) ||
            sqlite3_column_bytes(s, 6) != 32) {
            AR_FINALIZE(s);
            return false;
        }
        AR_READ_STR(s, 5, out->private_path, sizeof(out->private_path));
        AR_READ_BLOB(s, 6, out->chunk_sha3, 32);
        out->chunk_index = chunk_index;
        if (out->private_path[0] != '/') {
            AR_FINALIZE(s);
            return false;
        });
}

int db_market_content_list(struct node_db *ndb,
                           struct market_content_public_record *out,
                           size_t max)
{
    if (!ndb || !ndb->open || (!out && max > 0))
        LOG_RETURN(0, "market", "market content list: invalid arguments");
    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT offer_id,root_hash,size_bytes,num_chunks,registered_at "
        "FROM market_contents ORDER BY registered_at DESC LIMIT ?",
        out, max,
        AR_BIND_INT(s, 1, (int64_t)max),
        if (!market_content_read_public(s, 0, &out[count])) continue);
}

int db_market_content_list_snapshot(
    struct node_db *ndb, struct market_content_public_record *out, size_t max,
    int *total_out)
{
    if (total_out)
        *total_out = -1;
    if (!ndb || !ndb->open || !out || max == 0 || !total_out) {
        LOG_ERROR("market", "market content snapshot: invalid arguments");
        return -1;
    }
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT offer_id,root_hash,size_bytes,num_chunks,registered_at,"
            "(SELECT count(*) FROM market_contents) "
            "FROM market_contents ORDER BY registered_at DESC LIMIT ?",
            -1, &s, NULL) != SQLITE_OK || !s) {
        LOG_ERROR("market", "market content snapshot prepare failed: %s",
                  sqlite3_errmsg(ndb->db));
        return -1;
    }
    if (sqlite3_bind_int64(s, 1, (sqlite3_int64)max) != SQLITE_OK) {
        LOG_ERROR("market", "market content snapshot bind failed: %s",
                  sqlite3_errmsg(ndb->db));
        AR_FINALIZE(s);
        return -1;
    }

    int count = 0;
    int rc = SQLITE_OK;
    while ((rc = AR_STEP_ROW_READONLY(s)) == SQLITE_ROW) {
        int64_t total = sqlite3_column_int64(s, 5);
        if (total < 0 || total > INT_MAX) {
            LOG_ERROR("market", "market content snapshot total is invalid");
            AR_FINALIZE(s);
            return -1;
        }
        *total_out = (int)total;
        if (!market_content_read_public(s, 0, &out[count]))
            continue;
        count++;
    }
    if (rc != SQLITE_DONE) {
        LOG_ERROR("market", "market content snapshot read failed: %s",
                  sqlite3_errmsg(ndb->db));
        AR_FINALIZE(s);
        *total_out = -1;
        return -1;
    }
    AR_FINALIZE(s);
    if (*total_out < 0)
        *total_out = 0;
    return count;
}

enum market_content_state_result db_market_content_registration_identity(
    struct node_db *ndb, const uint8_t offer_id[32], uint8_t identity[32])
{
    if (identity)
        memset(identity, 0, 32);
    if (!ndb || !ndb->open || !offer_id || !identity) {
        LOG_ERROR("market", "market content identity: invalid arguments");
        return MARKET_CONTENT_STATE_ERROR;
    }
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT root_hash,private_path,size_bytes,num_chunks,"
            "chunk_hashes,registered_at FROM market_contents WHERE offer_id=?",
            -1, &s, NULL) != SQLITE_OK || !s) {
        LOG_ERROR("market", "market content identity prepare failed: %s",
                  sqlite3_errmsg(ndb->db));
        return MARKET_CONTENT_STATE_ERROR;
    }
    if (sqlite3_bind_blob(s, 1, offer_id, 32, SQLITE_STATIC) != SQLITE_OK) {
        LOG_ERROR("market", "market content identity bind failed: %s",
                  sqlite3_errmsg(ndb->db));
        AR_FINALIZE(s);
        return MARKET_CONTENT_STATE_ERROR;
    }
    int rc = AR_STEP_ROW_READONLY(s);
    if (rc == SQLITE_DONE) {
        AR_FINALIZE(s);
        return MARKET_CONTENT_STATE_ABSENT;
    }
    if (rc != SQLITE_ROW) {
        LOG_ERROR("market", "market content identity read failed: %s",
                  sqlite3_errmsg(ndb->db));
        AR_FINALIZE(s);
        return MARKET_CONTENT_STATE_ERROR;
    }

    const uint8_t *root_hash = sqlite3_column_blob(s, 0);
    const uint8_t *path = sqlite3_column_text(s, 1);
    const uint8_t *chunk_hashes = sqlite3_column_blob(s, 4);
    int root_len = sqlite3_column_bytes(s, 0);
    int path_len = sqlite3_column_bytes(s, 1);
    int chunks_len = sqlite3_column_bytes(s, 4);
    int64_t size_bytes = sqlite3_column_int64(s, 2);
    int64_t num_chunks = sqlite3_column_int64(s, 3);
    int64_t registered_at = sqlite3_column_int64(s, 5);
    if (!root_hash || root_len != 32 || !path || path_len <= 0 ||
        path_len >= (int)MARKET_CONTENT_PATH_MAX || !chunk_hashes ||
        chunks_len <= 0 || num_chunks <= 0 ||
        num_chunks > MARKET_CONTENT_MAX_CHUNKS ||
        chunks_len != num_chunks * 32 || size_bytes <= 0 ||
        registered_at <= 0) {
        LOG_ERROR("market", "market content identity row is malformed");
        AR_FINALIZE(s);
        return MARKET_CONTENT_STATE_ERROR;
    }

    static const char domain[] = "zcl.market.content.row.v1";
    uint8_t encoded[8];
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, offer_id, 32);
    sha3_256_write(&sha, root_hash, 32);
    zcl_write_u64_le(encoded, (uint64_t)path_len);
    sha3_256_write(&sha, encoded, sizeof(encoded));
    sha3_256_write(&sha, path, (size_t)path_len);
    zcl_write_u64_le(encoded, (uint64_t)size_bytes);
    sha3_256_write(&sha, encoded, sizeof(encoded));
    zcl_write_u64_le(encoded, (uint64_t)num_chunks);
    sha3_256_write(&sha, encoded, sizeof(encoded));
    zcl_write_u64_le(encoded, (uint64_t)chunks_len);
    sha3_256_write(&sha, encoded, sizeof(encoded));
    sha3_256_write(&sha, chunk_hashes, (size_t)chunks_len);
    zcl_write_u64_le(encoded, (uint64_t)registered_at);
    sha3_256_write(&sha, encoded, sizeof(encoded));
    sha3_256_finalize(&sha, identity);
    AR_FINALIZE(s);
    return MARKET_CONTENT_STATE_PRESENT;
}

int db_market_content_count(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        LOG_RETURN(-1, "market", "db_market_content_count: db not open");
    sqlite3_stmt *s = NULL;
    int64_t count = 0;
    AR_PREPARE_RET(ndb, s, "SELECT count(*) FROM market_contents", -1);
    if (AR_STEP_ROW_READONLY(s) != SQLITE_ROW) {
        AR_FINALIZE(s);
        LOG_RETURN(-1, "market", "db_market_content_count: count step failed");
    }
    count = AR_COL_INT(s, 0);
    AR_FINALIZE(s);
    return count > INT_MAX ? INT_MAX : (int)count;
}
