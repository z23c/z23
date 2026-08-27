/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * ActiveRecord owner for the private paid-file content registry. */

#include "models/market_content.h"

#include "crypto/sha3.h"
#include "net/file_market.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <limits.h>
#include <string.h>

DEFINE_MODEL_CALLBACKS(market_content)

static bool market_content_nonzero(const uint8_t value[32])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 32; i++)
        any |= value[i];
    return any != 0;
}

bool db_market_content_validate(const struct market_content_record *record,
                                struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!record) {
        ar_errors_add(errors, "record", "is NULL");
        return false;
    }
    uint32_t expected_chunks = 0;
    validates_custom(errors, market_content_nonzero(record->offer_id),
                     "offer_id", "can't be all zero");
    validates_custom(errors, market_content_nonzero(record->root_hash),
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
