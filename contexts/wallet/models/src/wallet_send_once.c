/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * ActiveRecord model for the once-only keyed wallet send record. */

#include "models/wallet_send_once.h"

#include "util/log_macros.h"

#include <string.h>

DEFINE_MODEL_CALLBACKS(wallet_send_once)

bool db_wallet_send_once_validate(const struct wallet_send_once_row *row,
                                  struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!row) {
        ar_errors_add(errors, "row", "is NULL");
        return false;
    }
    validates_presence_of(errors, row, key_hash);
    validates_presence_of(errors, row, digest);
    validates_range(errors, row, state, WALLET_SEND_ONCE_STARTED,
                    WALLET_SEND_ONCE_COMMITTED);
    validates_positive(errors, row, created_at);
    validates_custom(errors, row->updated_at >= row->created_at, "updated_at",
                     "must not precede created_at");
    validates_custom(errors, row->has_txid ==
                     (row->state != WALLET_SEND_ONCE_STARTED), "txid",
                     "is present exactly once the transaction is built");
    return !ar_errors_any(errors);
}

bool db_wallet_send_once_insert(struct node_db *ndb,
                                const struct wallet_send_once_row *row)
{
    if (!ndb || !ndb->open || !row)
        LOG_FAIL("wallet_send_once", "insert: invalid argument");
    sqlite3_stmt *s = NULL;
    AR_ADHOC_SAVE(ndb, s,
        "INSERT INTO wallet_send_once"
        "(key_hash,digest,state,txid,created_at,updated_at) "
        "VALUES(?,?,?,?,?,?)",
        db_wallet_send_once_callbacks(), "wallet_send_once", row,
        db_wallet_send_once_validate,
        AR_BIND_BLOB(s, 1, row->key_hash, 32);
        AR_BIND_BLOB(s, 2, row->digest, 32);
        AR_BIND_INT(s, 3, row->state);
        if (row->has_txid) AR_BIND_BLOB(s, 4, row->txid, 32);
        else AR_BIND_NULL(s, 4);
        AR_BIND_INT(s, 5, row->created_at);
        AR_BIND_INT(s, 6, row->updated_at));
}

bool db_wallet_send_once_find(struct node_db *ndb, const uint8_t key_hash[32],
                              struct wallet_send_once_row *out)
{
    if (!ndb || !ndb->open || !key_hash || !out)
        LOG_FAIL("wallet_send_once", "find: invalid argument");
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT digest,state,txid,created_at,updated_at "
        "FROM wallet_send_once WHERE key_hash=?",
        AR_BIND_BLOB(s, 1, key_hash, 32),
        memcpy(out->key_hash, key_hash, 32);
        AR_READ_BLOB(s, 0, out->digest, 32);
        out->state = (enum wallet_send_once_state)AR_COL_INT(s, 1);
        out->has_txid = sqlite3_column_type(s, 2) == SQLITE_BLOB;
        if (out->has_txid) AR_READ_BLOB(s, 2, out->txid, 32);
        out->created_at = AR_COL_INT(s, 3);
        out->updated_at = AR_COL_INT(s, 4));
}

bool db_wallet_send_once_advance(struct node_db *ndb,
                                 const uint8_t key_hash[32],
                                 enum wallet_send_once_state state,
                                 const uint8_t *txid, int64_t now)
{
    if (!ndb || !ndb->open || !key_hash || !txid || now <= 0 ||
        state <= WALLET_SEND_ONCE_STARTED || state > WALLET_SEND_ONCE_COMMITTED)
        LOG_FAIL("wallet_send_once", "advance: invalid argument");
    sqlite3_stmt *s = NULL;
    AR_EXEC_CHANGED_BOOL(ndb, s,
        "UPDATE wallet_send_once SET state=?,txid=?,updated_at=? "
        "WHERE key_hash=? AND state<? AND (txid IS NULL OR txid=?)",
        AR_BIND_INT(s, 1, state);
        AR_BIND_BLOB(s, 2, txid, 32);
        AR_BIND_INT(s, 3, now);
        AR_BIND_BLOB(s, 4, key_hash, 32);
        AR_BIND_INT(s, 5, state);
        AR_BIND_BLOB(s, 6, txid, 32));
}

bool db_wallet_send_once_release(struct node_db *ndb,
                                 const uint8_t key_hash[32])
{
    if (!ndb || !ndb->open || !key_hash)
        LOG_FAIL("wallet_send_once", "release: invalid argument");
    struct wallet_send_once_row row = {0};
    sqlite3_stmt *s = NULL;
    AR_ADHOC_DESTROY(ndb, s,
        "DELETE FROM wallet_send_once WHERE key_hash=? AND state<>3",
        db_wallet_send_once_callbacks(), &row,
        AR_BIND_BLOB(s, 1, key_hash, 32));
}

int db_wallet_send_once_count(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        return 0;
    AR_QUERY_COUNT_SQL(ndb, "SELECT COUNT(*) FROM wallet_send_once");
}

bool db_wallet_send_once_prune(struct node_db *ndb, int64_t now)
{
    if (!ndb || !ndb->open || now <= 0)
        LOG_FAIL("wallet_send_once", "prune: invalid argument");
    sqlite3_stmt *s = NULL;
    AR_EXEC_BOOL(ndb, s,
        "DELETE FROM wallet_send_once WHERE "
        "(state=3 AND created_at<?) OR (state<>3 AND created_at<?)",
        AR_BIND_INT(s, 1, now - WALLET_SEND_ONCE_COMMITTED_RETAIN_SEC);
        AR_BIND_INT(s, 2, now - WALLET_SEND_ONCE_UNRESOLVED_RETAIN_SEC));
}

int db_wallet_send_once_sync_level(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        return -1;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db, "PRAGMA synchronous", -1, &s, NULL) !=
        SQLITE_OK) {
        LOG_ERROR("wallet_send_once", "sync level: %s",
                  sqlite3_errmsg(ndb->db));
        return -1;
    }
    int level = sqlite3_step(s) == SQLITE_ROW ? sqlite3_column_int(s, 0) : -1;
    sqlite3_finalize(s);
    return level;
}
