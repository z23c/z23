/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * ActiveRecord model for the once-only keyed wallet send record. */

#include "models/wallet_send_once.h"

#include "models/query_builder.h"
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

/* Column order of the wallet_send_once row reads. */
enum wso_col { WSO_COL_DIGEST, WSO_COL_STATE, WSO_COL_TXID,
               WSO_COL_CREATED, WSO_COL_UPDATED, WSO_COL_COUNT };

bool db_wallet_send_once_insert(struct node_db *ndb,
                                const struct wallet_send_once_row *row)
{
    if (!ndb || !ndb->open || !row)
        LOG_FAIL("wallet_send_once", "insert: invalid argument");
    struct qb q;
    qb_insert(&q, QB_T_wallet_send_once, QB_INSERT_PLAIN);
    qb_value_blob(&q, QB_C_wallet_send_once_key_hash, row->key_hash, 32);
    qb_value_blob(&q, QB_C_wallet_send_once_digest, row->digest, 32);
    qb_value_int(&q, QB_C_wallet_send_once_state, row->state);
    if (row->has_txid)
        qb_value_blob(&q, QB_C_wallet_send_once_txid, row->txid, 32);
    else
        qb_value_null(&q, QB_C_wallet_send_once_txid);
    qb_value_int(&q, QB_C_wallet_send_once_created_at, row->created_at);
    qb_value_int(&q, QB_C_wallet_send_once_updated_at, row->updated_at);
    QB_ADHOC_SAVE(ndb, &q, s, db_wallet_send_once_callbacks(),
                  "wallet_send_once", row, db_wallet_send_once_validate);
}

bool db_wallet_send_once_find(struct node_db *ndb, const uint8_t key_hash[32],
                              struct wallet_send_once_row *out)
{
    if (!ndb || !ndb->open || !key_hash || !out)
        LOG_FAIL("wallet_send_once", "find: invalid argument");
    memset(out, 0, sizeof(*out));
    static const enum qb_column cols[WSO_COL_COUNT] = {
        [WSO_COL_DIGEST] = QB_C_wallet_send_once_digest,
        [WSO_COL_STATE] = QB_C_wallet_send_once_state,
        [WSO_COL_TXID] = QB_C_wallet_send_once_txid,
        [WSO_COL_CREATED] = QB_C_wallet_send_once_created_at,
        [WSO_COL_UPDATED] = QB_C_wallet_send_once_updated_at,
    };
    struct qb q;
    qb_select(&q, QB_T_wallet_send_once);
    qb_select_columns(&q, cols, WSO_COL_COUNT);
    qb_where_blob(&q, QB_C_wallet_send_once_key_hash, QB_EQ, key_hash, 32);
    QB_QUERY_ONE_BOOL(ndb, &q, s,
        memcpy(out->key_hash, key_hash, 32);
        AR_READ_BLOB(s, WSO_COL_DIGEST, out->digest, 32);
        out->state = (enum wallet_send_once_state)AR_COL_INT(s, WSO_COL_STATE);
        out->has_txid = sqlite3_column_type(s, WSO_COL_TXID) == SQLITE_BLOB;
        if (out->has_txid) AR_READ_BLOB(s, WSO_COL_TXID, out->txid, 32);
        out->created_at = AR_COL_INT(s, WSO_COL_CREATED);
        out->updated_at = AR_COL_INT(s, WSO_COL_UPDATED));
}

bool db_wallet_send_once_advance(struct node_db *ndb,
                                 const uint8_t key_hash[32],
                                 enum wallet_send_once_state state,
                                 const uint8_t *txid, int64_t now)
{
    if (!ndb || !ndb->open || !key_hash || !txid || now <= 0 ||
        state <= WALLET_SEND_ONCE_STARTED || state > WALLET_SEND_ONCE_COMMITTED)
        LOG_FAIL("wallet_send_once", "advance: invalid argument");
    struct qb q;
    qb_update(&q, QB_T_wallet_send_once);
    qb_set_int(&q, QB_C_wallet_send_once_state, state);
    qb_set_blob(&q, QB_C_wallet_send_once_txid, txid, 32);
    qb_set_int(&q, QB_C_wallet_send_once_updated_at, now);
    qb_where_blob(&q, QB_C_wallet_send_once_key_hash, QB_EQ, key_hash, 32);
    qb_where_int(&q, QB_C_wallet_send_once_state, QB_LT, state);
    qb_group_begin(&q, QB_OR);
    qb_where_null(&q, QB_C_wallet_send_once_txid, true);
    qb_where_blob(&q, QB_C_wallet_send_once_txid, QB_EQ, txid, 32);
    qb_group_end(&q);
    QB_EXEC_CHANGED_BOOL(ndb, &q, s);
}

bool db_wallet_send_once_release(struct node_db *ndb,
                                 const uint8_t key_hash[32])
{
    if (!ndb || !ndb->open || !key_hash)
        LOG_FAIL("wallet_send_once", "release: invalid argument");
    struct wallet_send_once_row row = {0};
    struct qb q;
    qb_delete(&q, QB_T_wallet_send_once);
    qb_where_blob(&q, QB_C_wallet_send_once_key_hash, QB_EQ, key_hash, 32);
    qb_where_int(&q, QB_C_wallet_send_once_state, QB_NE,
                 WALLET_SEND_ONCE_COMMITTED);
    QB_ADHOC_DESTROY(ndb, &q, s, db_wallet_send_once_callbacks(), &row);
}

int db_wallet_send_once_count(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        return 0;
    struct qb q;
    qb_select(&q, QB_T_wallet_send_once);
    qb_select_count_star(&q);
    QB_QUERY_COUNT(ndb, &q, s);
}

/* Two statements: committed rows age out on the short window, every other
 * state on the long one. Each is idempotent, so a partial run is harmless. */
static bool wso_prune_state(struct node_db *ndb, enum qb_op op, int64_t before)
{
    struct qb q;
    qb_delete(&q, QB_T_wallet_send_once);
    qb_where_int(&q, QB_C_wallet_send_once_state, op,
                 WALLET_SEND_ONCE_COMMITTED);
    qb_where_int(&q, QB_C_wallet_send_once_created_at, QB_LT, before);
    QB_EXEC_BOOL(ndb, &q, s);
}

bool db_wallet_send_once_prune(struct node_db *ndb, int64_t now)
{
    if (!ndb || !ndb->open || now <= 0)
        LOG_FAIL("wallet_send_once", "prune: invalid argument");
    bool committed = wso_prune_state(ndb, QB_EQ,
                                     now - WALLET_SEND_ONCE_COMMITTED_RETAIN_SEC);
    bool other = wso_prune_state(ndb, QB_NE,
                                 now - WALLET_SEND_ONCE_UNRESOLVED_RETAIN_SEC);
    return committed && other;
}

int db_wallet_send_once_sync_level(struct node_db *ndb)
{
    return node_db_synchronous_level(ndb);
}
