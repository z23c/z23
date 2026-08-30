/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * ActiveRecord owner for restart-safe buyer file assembly. */

#include "models/market_download.h"

#include "models/model_fields.h"
#include "models/def/market_download_fields.def"

#include "net/file_market.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <string.h>

DEFINE_MODEL_CALLBACKS(market_download)
DEFINE_MODEL_CALLBACKS(market_download_chunk)

/* ── Column mapping ───────────────────────────────────────────────────────
 * SQL column list, read index and bind position all come from the field
 * lists in models/def/market_download_fields.def. The blob-width guards
 * below reference columns by derived name, so not even those spell an
 * index. */
#define MARKET_DOWNLOAD_COLUMNS ZCL_MODEL_COLUMNS(MARKET_DOWNLOAD_FIELDS)
#define MARKET_DOWNLOAD_VALUES  ZCL_MODEL_PLACEHOLDERS(MARKET_DOWNLOAD_FIELDS)
#define MARKET_DOWNLOAD_CHUNK_COLUMNS \
    ZCL_MODEL_COLUMNS(MARKET_DOWNLOAD_CHUNK_FIELDS)
#define MARKET_DOWNLOAD_CHUNK_VALUES \
    ZCL_MODEL_PLACEHOLDERS(MARKET_DOWNLOAD_CHUNK_FIELDS)

#define MD_IX(kind, col, member, extra) MD_IX_##col,
enum { ZCL_MODEL_EXPAND(MD_IX, MARKET_DOWNLOAD_FIELDS) MD_IX_COUNT };
#define MDC_IX(kind, col, member, extra) MDC_IX_##col,
enum { ZCL_MODEL_EXPAND(MDC_IX, MARKET_DOWNLOAD_CHUNK_FIELDS) MDC_IX_COUNT };

ZCL_MODEL_READ_ROW_FN(market_download_read_row,
                      struct market_download_record, MARKET_DOWNLOAD_FIELDS)
ZCL_MODEL_BIND_FN(market_download_bind, struct market_download_record,
                  MARKET_DOWNLOAD_FIELDS)

ZCL_MODEL_READ_ROW_FN(market_download_chunk_read_row,
                      struct market_download_chunk_record,
                      MARKET_DOWNLOAD_CHUNK_FIELDS)
ZCL_MODEL_BIND_FN(market_download_chunk_bind,
                  struct market_download_chunk_record,
                  MARKET_DOWNLOAD_CHUNK_FIELDS)

static bool market_download_nonzero(const uint8_t value[32])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 32; i++)
        any |= value[i];
    return any != 0;
}

const char *market_download_state_name(enum market_download_state state)
{
    switch (state) {
    case MARKET_DOWNLOAD_FETCHING: return "fetching";
    case MARKET_DOWNLOAD_COMPLETE: return "complete";
    case MARKET_DOWNLOAD_FAILED: return "failed";
    }
    return "failed";
}

bool db_market_download_validate(const struct market_download_record *record,
                                 struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!record) {
        ar_errors_add(errors, "record", "is NULL");
        return false;
    }
    uint32_t expected_chunks = 0;
    validates_custom(errors, market_download_nonzero(record->plan_id),
                     "plan_id", "can't be all zero");
    validates_custom(errors, market_download_nonzero(record->offer_id),
                     "offer_id", "can't be all zero");
    validates_custom(errors, market_download_nonzero(record->root_hash),
                     "root_hash", "can't be all zero");
    validates_custom(errors, record->private_destination[0] == '/' &&
        strnlen(record->private_destination, MARKET_DOWNLOAD_PATH_MAX) <
            MARKET_DOWNLOAD_PATH_MAX,
        "private_destination", "must be a bounded absolute path");
    validates_custom(errors, record->private_staging[0] == '/' &&
        strnlen(record->private_staging, MARKET_DOWNLOAD_PATH_MAX) <
            MARKET_DOWNLOAD_PATH_MAX,
        "private_staging", "must be a bounded absolute path");
    validates_positive(errors, record, size_bytes);
    validates_custom(errors,
        file_market_num_chunks_for_size(record->size_bytes,
                                        &expected_chunks) &&
        expected_chunks == record->num_chunks &&
        record->num_chunks <= MARKET_DOWNLOAD_MAX_CHUNKS,
        "num_chunks", "must exactly cover the bounded file size");
    validates_custom(errors, record->chunks_received <= record->num_chunks,
                     "chunks_received", "exceeds the manifest");
    validates_custom(errors, record->bytes_received <= record->size_bytes,
                     "bytes_received", "exceeds the file size");
    validates_range(errors, record, state, MARKET_DOWNLOAD_FETCHING,
                    MARKET_DOWNLOAD_FAILED);
    validates_positive(errors, record, created_at);
    validates_positive(errors, record, updated_at);
    if (record->state == MARKET_DOWNLOAD_COMPLETE) {
        validates_custom(errors,
            record->chunks_received == record->num_chunks &&
            record->bytes_received == record->size_bytes,
            "state", "complete requires every exact byte and chunk");
    }
    return !ar_errors_any(errors);
}

bool db_market_download_chunk_validate(
    const struct market_download_chunk_record *record,
    struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!record) {
        ar_errors_add(errors, "record", "is NULL");
        return false;
    }
    validates_custom(errors, market_download_nonzero(record->plan_id),
                     "plan_id", "can't be all zero");
    validates_max(errors, record, chunk_index,
                  MARKET_DOWNLOAD_MAX_CHUNKS - 1u);
    validates_range(errors, record, size_bytes, 1,
                    FILE_MARKET_CHUNK_SIZE);
    validates_custom(errors, market_download_nonzero(record->chunk_sha3),
                     "chunk_sha3", "can't be all zero");
    validates_positive(errors, record, created_at);
    return !ar_errors_any(errors);
}

bool db_market_download_save(struct node_db *ndb,
                             const struct market_download_record *record)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("market", "download save: database is not open");
    if (!record)
        LOG_FAIL("market", "download save: record is NULL");
    sqlite3_stmt *s = NULL;
    struct ar_callbacks *cbs = db_market_download_callbacks();
    AR_ADHOC_SAVE(ndb, s,
        "INSERT INTO market_downloads(" MARKET_DOWNLOAD_COLUMNS ")"
        " VALUES(" MARKET_DOWNLOAD_VALUES ")"
        " ON CONFLICT(plan_id) DO UPDATE SET "
        "chunks_received=excluded.chunks_received,"
        "bytes_received=excluded.bytes_received,state=excluded.state,"
        "updated_at=excluded.updated_at",
        cbs, "market_download", record, db_market_download_validate,
        market_download_bind(s, record));
}

bool db_market_download_find(struct node_db *ndb,
                             const uint8_t plan_id[32],
                             struct market_download_record *out)
{
    if (!ndb || !ndb->open || !plan_id || !out)
        LOG_FAIL("market", "download find: invalid arguments");
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT " MARKET_DOWNLOAD_COLUMNS " FROM market_downloads "
        "WHERE plan_id=?",
        AR_BIND_BLOB(s, 1, plan_id, 32),
        if (sqlite3_column_bytes(s, MD_IX_plan_id) != 32 ||
            sqlite3_column_bytes(s, MD_IX_offer_id) != 32 ||
            sqlite3_column_bytes(s, MD_IX_root_hash) != 32) {
            memset(out, 0, sizeof(*out));
            AR_FINALIZE(s);
            return false;
        }
        market_download_read_row(out, s));
}

bool db_market_download_chunk_find(
    struct node_db *ndb, const uint8_t plan_id[32], uint32_t chunk_index,
    struct market_download_chunk_record *out)
{
    if (!ndb || !ndb->open || !plan_id || !out)
        LOG_FAIL("market", "download chunk find: invalid arguments");
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT " MARKET_DOWNLOAD_CHUNK_COLUMNS " FROM market_download_chunks "
        "WHERE plan_id=? AND chunk_index=?",
        AR_BIND_BLOB(s, 1, plan_id, 32);
        AR_BIND_INT(s, 2, chunk_index),
        if (sqlite3_column_bytes(s, MDC_IX_plan_id) != 32 ||
            sqlite3_column_bytes(s, MDC_IX_chunk_sha3) != 32) {
            memset(out, 0, sizeof(*out));
            AR_FINALIZE(s);
            return false;
        }
        market_download_chunk_read_row(out, s));
}

bool db_market_download_chunk_save(
    struct node_db *ndb,
    const struct market_download_chunk_record *record)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("market", "download chunk save: database is not open");
    if (!record)
        LOG_FAIL("market", "download chunk save: record is NULL");
    struct market_download_record parent;
    if (!db_market_download_find(ndb, record->plan_id, &parent) ||
        record->chunk_index >= parent.num_chunks)
        LOG_FAIL("market", "download chunk save: parent relationship missing");
    sqlite3_stmt *s = NULL;
    struct ar_callbacks *cbs = db_market_download_chunk_callbacks();
    AR_ADHOC_SAVE(ndb, s,
        "INSERT INTO market_download_chunks(" MARKET_DOWNLOAD_CHUNK_COLUMNS ")"
        " VALUES(" MARKET_DOWNLOAD_CHUNK_VALUES ") "
        "ON CONFLICT(plan_id,chunk_index) DO NOTHING",
        cbs, "market_download_chunk", record,
        db_market_download_chunk_validate,
        market_download_chunk_bind(s, record));
}

int db_market_download_chunk_count(struct node_db *ndb,
                                   const uint8_t plan_id[32])
{
    if (!ndb || !ndb->open || !plan_id)
        LOG_RETURN(0, "market", "download chunk count: invalid arguments");
    sqlite3_stmt *s = NULL;
    AR_QUERY_COUNT_BOUND(ndb, s,
        "SELECT count(*) FROM market_download_chunks WHERE plan_id=?",
        AR_BIND_BLOB(s, 1, plan_id, 32));
}
