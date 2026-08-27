/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord model: Zmsg (encrypted P2P messages)
 *
 * Wires callbacks, validation, and SQLite persistence for the
 * `zmsg_messages` table. The P2P serialization and in-memory delivery
 * cache live in lib/net/src/zmsg.c.
 *
 * Record type is `struct zmsg_message` from net/zmsg.h — reused
 * rather than duplicated so wire / runtime / at-rest representations
 * stay byte-aligned. */

#include "models/zmsg.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "crypto/sha3.h"
#include "platform/time_compat.h"

#include <sqlite3.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

DEFINE_MODEL_CALLBACKS(zmsg)

#ifdef ZCL_TESTING
static int (*g_zmsg_count_step_fn)(void *) = NULL;
void db_zmsg_test_set_count_step(int (*step_fn)(void *stmt))
{
    g_zmsg_count_step_fn = step_fn;
}
#define ZMSG_COUNT_STEP(stmt) \
    (g_zmsg_count_step_fn ? g_zmsg_count_step_fn(stmt) \
                          : AR_STEP_ROW_READONLY(stmt))
#else
#define ZMSG_COUNT_STEP(stmt) AR_STEP_ROW_READONLY(stmt)
#endif

static bool read_zmsg_blob(sqlite3_stmt *s, int col, void *dest,
                           int expected_len, const char *column)
{
    int got = sqlite3_column_bytes(s, col);
    const void *blob = sqlite3_column_blob(s, col);
    if (!blob || got != expected_len)
        LOG_FAIL("zmsg",
                 "zmsg_messages.%s blob length mismatch: got=%d expected=%d",
                 column, got, expected_len);

    AR_READ_BLOB(s, col, dest, expected_len);
    return true;
}

static bool read_zmsg_optional_blob(sqlite3_stmt *s, int col, void *dest,
                                    int expected_len, const char *column)
{
    if (sqlite3_column_type(s, col) == SQLITE_NULL) {
        memset(dest, 0, (size_t)expected_len);
        return true;
    }

    return read_zmsg_blob(s, col, dest, expected_len, column);
}

bool db_zmsg_validate(const struct zmsg_message *msg,
                      struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!msg) {
        ar_errors_add(errors, "msg", "is NULL");
        return false;
    }

    static const uint8_t zero32[32] = {0};

    validates_custom(errors,
        memcmp(msg->msg_id, zero32, 32) != 0,
        "msg_id", "can't be all zero (pre-compute via zmsg_compute_id)");
    validates_presence_of(errors, msg, sender);
    validates_presence_of(errors, msg, recipient);
    validates_presence_of(errors, msg, body);
    validates_inclusion_of(errors, msg, direction,
        ((int[]){ZMSG_INBOUND, ZMSG_OUTBOUND}), 2);
    validates_inclusion_of(errors, msg, channel,
        ((int[]){ZMSG_CHANNEL_ONCHAIN, ZMSG_CHANNEL_P2P}), 2);
    validates_non_negative(errors, msg, timestamp);
    validates_custom(errors,
        strnlen(msg->body, ZMSG_MAX_BODY + 1) <= ZMSG_MAX_BODY,
        "body", "exceeds ZMSG_MAX_BODY");

    return !ar_errors_any(errors);
}

bool db_zmsg_save(struct node_db *ndb, const struct zmsg_message *msg)
{
    if (!ndb || !ndb->open) LOG_FAIL("zmsg", "db_zmsg_save: db not open");
    if (!msg) LOG_FAIL("zmsg", "db_zmsg_save: msg is NULL");

    struct ar_callbacks *cbs = db_zmsg_callbacks();
    sqlite3_stmt *s = NULL;
    static const uint8_t zero[32] = {0};
    AR_ADHOC_SAVE(ndb, s,
        "INSERT OR IGNORE INTO zmsg_messages"
        "(msg_id,direction,channel,sender,recipient,body,"
        "timestamp,txid,read)"
        " VALUES(?,?,?,?,?,?,?,?,?)",
        cbs, "zmsg", msg, db_zmsg_validate,
        AR_BIND_BLOB(s, 1, msg->msg_id, 32);
        AR_BIND_INT(s, 2, msg->direction);
        AR_BIND_INT(s, 3, msg->channel);
        AR_BIND_TEXT(s, 4, msg->sender);
        AR_BIND_TEXT(s, 5, msg->recipient);
        AR_BIND_TEXT(s, 6, msg->body);
        AR_BIND_INT(s, 7, msg->timestamp);
        if (memcmp(msg->txid, zero, 32) != 0)
            AR_BIND_BLOB(s, 8, msg->txid, 32);
        else
            AR_BIND_NULL(s, 8);
        AR_BIND_INT(s, 9, msg->read ? 1 : 0));
}

static bool row_to_zmsg(sqlite3_stmt *s, struct zmsg_message *out)
{
    memset(out, 0, sizeof(*out));
    if (!read_zmsg_blob(s, 0, out->msg_id, 32, "msg_id"))
        LOG_FAIL("zmsg", "zmsg_messages.msg_id rejected");

    out->direction = sqlite3_column_int(s, 1);
    out->channel = sqlite3_column_int(s, 2);

    const char *str = (const char *)sqlite3_column_text(s, 3);
    if (str) snprintf(out->sender, sizeof(out->sender), "%s", str);

    str = (const char *)sqlite3_column_text(s, 4);
    if (str) snprintf(out->recipient, sizeof(out->recipient), "%s", str);

    str = (const char *)sqlite3_column_text(s, 5);
    if (str) snprintf(out->body, sizeof(out->body), "%s", str);

    out->timestamp = sqlite3_column_int64(s, 6);

    if (!read_zmsg_optional_blob(s, 7, out->txid, 32, "txid"))
        LOG_FAIL("zmsg", "zmsg_messages.txid rejected");

    out->read = sqlite3_column_int(s, 8) != 0;
    return true;
}

int db_zmsg_list(struct node_db *ndb, struct zmsg_message *out,
                 size_t max, bool unread_only)
{
    if (!ndb || !ndb->open) return 0;
    if (!out && max > 0)
        LOG_RETURN(0, "zmsg", "db_zmsg_list: out is NULL");

    const char *sql = unread_only
        ? "SELECT msg_id,direction,channel,sender,recipient,body,"
          "timestamp,txid,read FROM zmsg_messages "
          "WHERE read=0 ORDER BY timestamp DESC LIMIT ?"
        : "SELECT msg_id,direction,channel,sender,recipient,body,"
          "timestamp,txid,read FROM zmsg_messages "
          "ORDER BY timestamp DESC LIMIT ?";

    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s, sql, out, max,
        AR_BIND_INT(s, 1, (int)max),
        if (!row_to_zmsg(s, &out[count])) continue);
}

int db_zmsg_count(struct node_db *ndb, bool unread_only)
{
    if (!ndb || !ndb->open)
        LOG_RETURN(-1, "zmsg", "db_zmsg_count: db not open");

    const char *sql = unread_only
        ? "SELECT count(*) FROM zmsg_messages WHERE read=0"
        : "SELECT count(*) FROM zmsg_messages";

    sqlite3_stmt *s = NULL;
    int64_t count = 0;
    AR_PREPARE_RET(ndb, s, sql, -1);
    if (ZMSG_COUNT_STEP(s) != SQLITE_ROW) {
        AR_FINALIZE(s);
        LOG_RETURN(-1, "zmsg", "db_zmsg_count: count step failed");
    }
    count = sqlite3_column_int64(s, 0);
    AR_FINALIZE(s);
    return count > INT_MAX ? INT_MAX : (int)count;
}

bool db_zmsg_mark_read(struct node_db *ndb, const uint8_t msg_id[32])
{
    if (!ndb || !ndb->open) LOG_FAIL("zmsg", "db_zmsg_mark_read: db not open");
    if (!msg_id) LOG_FAIL("zmsg", "db_zmsg_mark_read: msg_id is NULL");

    sqlite3_stmt *s = NULL;
    AR_EXEC_BOOL(ndb, s,
        "UPDATE zmsg_messages SET read=1 WHERE msg_id=?",
        AR_BIND_BLOB(s, 1, msg_id, 32));
}

bool zmsg_ingest_onchain_note(struct node_db *ndb,
                              const uint8_t memo[ZMSG_MEMO_LEN],
                              const uint8_t txid[32])
{
    if (!memo || !txid) LOG_FAIL("zmsg", "ingest_onchain_note: NULL arg");

    struct zmsg_memo parsed;
    if (!zmsg_memo_decode(memo, &parsed))
        return false;   // raw-return-ok: memo is not a ZMSG (the common, benign case for every non-ZMSG shielded note); logging here would spam every decrypted memo

    struct zmsg_message m;
    memset(&m, 0, sizeof(m));
    m.direction = ZMSG_INBOUND;
    m.channel = ZMSG_CHANNEL_ONCHAIN;
    m.timestamp = (int64_t)platform_time_wall_time_t();
    snprintf(m.sender, sizeof(m.sender), "onchain");
    snprintf(m.recipient, sizeof(m.recipient), "self");
    memcpy(m.txid, txid, 32);

    size_t blen = parsed.payload_len;
    if (blen > ZMSG_MAX_BODY - 1) blen = ZMSG_MAX_BODY - 1;
    memcpy(m.body, parsed.payload, blen);
    m.body[blen] = '\0';

    /* Deterministic id = SHA3(txid || full 512-byte memo) so a re-scan or
     * reorg re-ingest of the same note maps to the SAME msg_id (both stores
     * dedup on it). Independent of the wall-clock timestamp above, which is
     * display/ordering metadata only. */
    struct sha3_256_ctx sha3;
    sha3_256_init(&sha3);
    sha3_256_write(&sha3, txid, 32);
    sha3_256_write(&sha3, memo, ZMSG_MEMO_LEN);
    sha3_256_finalize(&sha3, m.msg_id);

    zmsg_store_add(&m);   /* in-memory store dedups by msg_id */
    if (ndb)
        return db_zmsg_save(ndb, &m);   /* SQLite INSERT OR IGNORE on msg_id PK */
    return true;
}
