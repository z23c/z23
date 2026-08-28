/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord model for the ZSLP per-(token, outpoint) ledger
 * (zslp_ledger) — the debit-correct, chain-derived token-balance
 * projection. See models/zslp_ledger.h for the field semantics, the
 * SLP-validity divergence, and the threading contract.
 *
 * All writes go through the AR lifecycle: row creates via AR_ADHOC_SAVE
 * (locally-prepared INSERT OR IGNORE), spend marks via AR_EXEC_CHANGED_BOOL
 * (a deterministic single-outpoint UPDATE, the same shape wallet spend uses).
 * node.db ONLY; never consulted by consensus. */

#include "models/zslp_ledger.h"
#include "models/zslp_validity.h"

#include "models/database.h"
#include "models/activerecord.h"
#include "primitives/transaction.h"
#include "zslp/slp.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>
#include <string.h>

#define ZSLP_LEDGER_CURSOR_KEY "zslp_ledger_cursor_height"
#define ZSLP_LEDGER_DIGEST_KEY "zslp_ledger_digest"

DEFINE_MODEL_CALLBACKS(zslp_ledger)

/* ── Row model ─────────────────────────────────────────────────────── */

struct zslp_ledger_row {
    uint8_t  token_id[32];
    uint8_t  txid[32];
    int32_t  vout;
    int64_t  amount;         /* clamped token base units, >= 0 */
    uint8_t  address[20];
    bool     has_address;
    int32_t  created_height;
    int32_t  role;
};

static bool zslp_ledger_validate(const struct zslp_ledger_row *r,
                                 struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!r) {
        ar_errors_add(errors, "row", "is NULL");
        return false;
    }
    validates_non_negative(errors, r, vout);
    validates_non_negative(errors, r, amount);
    validates_non_negative(errors, r, created_height);
    if (r->role != ZSLP_LEDGER_TOKEN &&
        r->role != ZSLP_LEDGER_MINT_BATON)
        ar_errors_add(errors, "role", "is invalid");
    return !ar_errors_any(errors);
}

static bool zslp_ledger_save(struct node_db *ndb,
                             const struct zslp_ledger_row *row)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("zslp_ledger", "zslp_ledger_save: db not open");
    if (!row)
        LOG_FAIL("zslp_ledger", "zslp_ledger_save: row is NULL");

    struct ar_callbacks *cbs = db_zslp_ledger_callbacks();
    sqlite3_stmt *s = NULL;
    AR_ADHOC_SAVE(ndb, s,
        "INSERT OR IGNORE INTO zslp_ledger"
        "(token_id,txid,vout,amount,address,created_height,role)"
        " VALUES(?,?,?,?,?,?,?)",
        cbs, "zslp_ledger", row, zslp_ledger_validate,
        AR_BIND_BLOB(s, 1, row->token_id, 32);
        AR_BIND_BLOB(s, 2, row->txid, 32);
        AR_BIND_INT(s, 3, row->vout);
        AR_BIND_INT(s, 4, row->amount);
        if (row->has_address)
            AR_BIND_BLOB(s, 5, row->address, 20);
        else
            AR_BIND_NULL(s, 5);
        AR_BIND_INT(s, 6, row->created_height);
        AR_BIND_INT(s, 7, row->role));
}

/* Mark the ledger outpoint (txid,vout) spent by `spender` at `height`.
 * Deterministic: an outpoint is consumed by exactly one input on the
 * canonical chain, so this UPDATE is idempotent under re-derive. Returns
 * true iff a token-bearing outpoint actually matched (a non-token outpoint
 * has no row and changes()==0) — the caller uses that to decide whether the
 * spend participates in the running digest. */
bool zslp_ledger_mark_valid_spent(struct node_db *ndb,
                                   const uint8_t prev_txid[32],
                                   int32_t prev_vout,
                                   const uint8_t spender_txid[32],
                                   int32_t height)
{
    if (!ndb || !ndb->open) return false;
    sqlite3_stmt *s = NULL;
    AR_EXEC_CHANGED_BOOL(ndb, s,
        "UPDATE zslp_ledger SET spent_by_txid=?,spent_height=?"
        " WHERE txid=? AND vout=?",
        AR_BIND_BLOB(s, 1, spender_txid, 32);
        AR_BIND_INT(s, 2, height);
        AR_BIND_BLOB(s, 3, prev_txid, 32);
        AR_BIND_INT(s, 4, prev_vout));
}

bool zslp_ledger_record_valid_output(struct node_db *ndb,
    const uint8_t token_id[32], const uint8_t txid[32], int32_t vout,
    int64_t amount, const uint8_t *address_or_null, int32_t created_height,
    int role)
{
    if (!ndb || !token_id || !txid || vout < 0 || amount < 0 ||
        created_height < 0)
        LOG_FAIL("zslp_ledger", "record_valid_output: invalid argument");
    struct zslp_ledger_row row;
    memset(&row, 0, sizeof(row));
    memcpy(row.token_id, token_id, 32);
    memcpy(row.txid, txid, 32);
    row.vout = vout;
    row.amount = amount;
    row.created_height = created_height;
    row.role = role;
    if (address_or_null) {
        memcpy(row.address, address_or_null, 20);
        row.has_address = true;
    }
    return zslp_ledger_save(ndb, &row);
}

/* ── Live per-block hook ───────────────────────────────────────────── */

bool zslp_ledger_apply_slp_live(struct node_db *ndb,
                                const struct transaction *tx,
                                const struct slp_message *m, int height)
{
    return zslp_validity_apply_live(ndb, tx, m, height);
}

/* ── Backfill: one height from node.db projections + digest fold ───── */

bool zslp_ledger_apply_height(struct node_db *ndb, int32_t height,
                              const uint8_t prev_digest[32],
                              uint8_t out_digest[32])
{
    return zslp_validity_apply_height(ndb, height, prev_digest, out_digest);
}

/* ── Cursor / digest state ─────────────────────────────────────────── */

bool zslp_ledger_get_cursor(struct node_db *ndb, int32_t *out_height,
                            uint8_t out_digest[32])
{
    if (!ndb || !ndb->open) return false;
    int64_t h = -1;
    bool found = node_db_state_get_int(ndb, ZSLP_LEDGER_CURSOR_KEY, &h);
    if (out_height) *out_height = found ? (int32_t)h : -1;
    if (out_digest) {
        size_t len = 0;
        if (!found ||
            !node_db_state_get(ndb, ZSLP_LEDGER_DIGEST_KEY, out_digest, 32,
                               &len) || len != 32)
            memset(out_digest, 0, 32);
    }
    /* "nothing folded yet" is a valid state, not a failure. */
    return true;
}

bool zslp_ledger_set_cursor(struct node_db *ndb, int32_t height,
                            const uint8_t digest[32])
{
    if (!ndb || !ndb->open || !digest)
        LOG_FAIL("zslp_ledger", "set_cursor: invalid args");
    if (!node_db_state_set_int(ndb, ZSLP_LEDGER_CURSOR_KEY, (int64_t)height))
        LOG_FAIL("zslp_ledger", "set_cursor: failed to persist height=%d",
                 height);
    if (!node_db_state_set(ndb, ZSLP_LEDGER_DIGEST_KEY, digest, 32))
        LOG_FAIL("zslp_ledger", "set_cursor: failed to persist digest at h=%d",
                 height);
    return true;
}

bool zslp_ledger_truncate(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("zslp_ledger", "truncate: db not open");
    if (!node_db_exec(ndb, "DELETE FROM zslp_ledger"))
        LOG_FAIL("zslp_ledger", "truncate: DELETE failed");
    if (!node_db_exec(ndb, "DELETE FROM zslp_validity"))
        LOG_FAIL("zslp_ledger", "truncate: validity DELETE failed");
    uint8_t zero[32] = {0};
    if (!node_db_state_set_int(ndb, ZSLP_LEDGER_CURSOR_KEY, -1))
        LOG_FAIL("zslp_ledger", "truncate: failed to reset cursor");
    if (!node_db_state_set(ndb, ZSLP_LEDGER_DIGEST_KEY, zero, 32))
        LOG_FAIL("zslp_ledger", "truncate: failed to reset digest");
    return true;
}

/* ── Queries ───────────────────────────────────────────────────────── */

int64_t zslp_ledger_balance(struct node_db *ndb, const uint8_t token_id[32],
                            const uint8_t address[20])
{
    if (!ndb || !ndb->open || !token_id || !address) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_INT64_BOUND(ndb, s,
        "SELECT COALESCE(SUM(amount),0) FROM zslp_ledger "
        "WHERE token_id=? AND address=? AND role=1 "
        "AND spent_by_txid IS NULL",
        AR_BIND_BLOB(s, 1, token_id, 32);
        AR_BIND_BLOB(s, 2, address, 20));
}

struct zslp_outpoint_read {
    uint8_t token_id[32];
    int token_id_len;
    int64_t amount;
    int role;
    bool spent;
};

static int zslp_ledger_read_outpoint(struct node_db *ndb,
                                     const uint8_t txid[32], uint32_t vout,
                                     struct zslp_outpoint_read out[2])
{
    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT token_id,amount,role,spent_by_txid FROM zslp_ledger "
        "WHERE txid=? AND vout=? LIMIT 2", out, 2,
        AR_BIND_BLOB(s, 1, txid, 32);
        AR_BIND_INT(s, 2, vout),
        out[count].token_id_len = AR_COL_BYTES(s, 0);
        if (out[count].token_id_len == 32)
            AR_READ_BLOB(s, 0, out[count].token_id, 32);
        out[count].amount = AR_COL_INT(s, 1);
        out[count].role = (int)AR_COL_INT(s, 2);
        out[count].spent = sqlite3_column_type(s, 3) != SQLITE_NULL);
}

enum zslp_ledger_outpoint_state zslp_ledger_token_outpoint_state(
    struct node_db *ndb, const uint8_t txid[32], uint32_t vout,
    const uint8_t token_id[32], uint64_t amount)
{
    if (!ndb || !ndb->open || !txid || !token_id || amount > INT64_MAX) {
        LOG_WARN("zslp_ledger", "outpoint lookup rejected invalid arguments");
        return ZSLP_LEDGER_OUTPOINT_ERROR;
    }
    struct zslp_outpoint_read rows[2];
    int count = zslp_ledger_read_outpoint(ndb, txid, vout, rows);
    if (count == 0)
        return ZSLP_LEDGER_OUTPOINT_ABSENT;
    if (count != 1 || rows[0].token_id_len != 32 ||
        memcmp(rows[0].token_id, token_id, 32) != 0 ||
        rows[0].amount != (int64_t)amount ||
        rows[0].role != ZSLP_LEDGER_TOKEN)
        return ZSLP_LEDGER_OUTPOINT_MISMATCH;
    return rows[0].spent ? ZSLP_LEDGER_OUTPOINT_SPENT
                         : ZSLP_LEDGER_OUTPOINT_UNSPENT_TOKEN;
}

/* ── as-of-height reads (the reproducible half of a token gate) ────────
 *
 * Every row already carries created_height and (once consumed) spent_height,
 * so "what did this holder own at height H" is a pure filter over the same
 * rows the live balance reads — no snapshot table, no second ledger, and no
 * dependence on when the query runs. A row counts at H when it was created at
 * or below H and was either never spent or spent strictly above H.
 *
 * The caller is responsible for one thing this query cannot know: the ledger
 * must have folded past H (zslp_ledger_get_cursor) or the answer is merely
 * "what has been indexed so far", not "what was true at H". Gate evaluators
 * check the cursor and fail closed; see services/service_token_gate.h. */
#define ZSLP_AS_OF_HEIGHT                                                    \
    " AND created_height<=?"                                                 \
    " AND (spent_height IS NULL OR spent_height>?)"

int64_t zslp_ledger_balance_at_height(struct node_db *ndb,
                                      const uint8_t token_id[32],
                                      const uint8_t address[20],
                                      int32_t height)
{
    if (!ndb || !ndb->open || !token_id || !address || height < 0) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_INT64_BOUND(ndb, s,
        "SELECT COALESCE(SUM(amount),0) FROM zslp_ledger "
        "WHERE token_id=? AND address=? AND role=1" ZSLP_AS_OF_HEIGHT,
        AR_BIND_BLOB(s, 1, token_id, 32);
        AR_BIND_BLOB(s, 2, address, 20);
        AR_BIND_INT(s, 3, (int64_t)height);
        AR_BIND_INT(s, 4, (int64_t)height));
}

int64_t zslp_ledger_count(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_INT64_BOUND(ndb, s, "SELECT COUNT(*) FROM zslp_ledger", (void)0);
}

int64_t zslp_ledger_unspent_count(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_INT64_BOUND(ndb, s,
        "SELECT COUNT(*) FROM zslp_ledger WHERE spent_by_txid IS NULL",
        (void)0);
}

/* ── Wallet-wide sweep ─────────────────────────────────────────────────
 *
 * "Which addresses are mine" is a node.db question with a node.db answer:
 * wallet_keys holds every spendable 20-byte pubkey hash and
 * wallet_watch_only every imported one, and both live in the SAME database
 * as zslp_ledger. So the wallet-wide fold is one indexed statement — no C
 * address list, no per-address round trip, and no second source of truth
 * about what the wallet owns. Rows with a NULL address (a token output
 * whose recipient script was not address-shaped) can belong to no wallet
 * and are excluded by the join. */
#define ZSLP_WALLET_ADDRESS_SET                                              \
    "SELECT pubkey_hash FROM wallet_keys"                                    \
    " UNION SELECT address_hash FROM wallet_watch_only"

#define ZSLP_WALLET_OWNS_ADDRESS                                             \
    " AND address IS NOT NULL AND address IN (" ZSLP_WALLET_ADDRESS_SET ")"

int zslp_ledger_wallet_tokens(struct node_db *ndb,
                              struct zslp_wallet_token *out, size_t max)
{
    if (!ndb || !ndb->open) return 0;
    if (!out && max > 0)
        LOG_RETURN(0, "zslp_ledger", "wallet_tokens: out is NULL");

    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT token_id,COALESCE(SUM(amount),0),COUNT(*)"
        " FROM zslp_ledger"
        " WHERE role=1 AND spent_by_txid IS NULL" ZSLP_WALLET_OWNS_ADDRESS
        " GROUP BY token_id ORDER BY token_id LIMIT ?",
        out, max,
        AR_BIND_INT(s, 1, (int64_t)max),
        if (AR_COL_BYTES(s, 0) != 32) {
            LOG_WARN("zslp_ledger",
                     "wallet_tokens: skipping row with %d-byte token_id",
                     AR_COL_BYTES(s, 0));
            continue;
        }
        AR_READ_BLOB(s, 0, out[count].token_id, 32);
        out[count].balance = AR_COL_INT(s, 1);
        out[count].utxo_count = AR_COL_INT(s, 2));
}

int64_t zslp_ledger_wallet_balance(struct node_db *ndb,
                                   const uint8_t token_id[32])
{
    if (!ndb || !ndb->open || !token_id) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_INT64_BOUND(ndb, s,
        "SELECT COALESCE(SUM(amount),0) FROM zslp_ledger"
        " WHERE token_id=? AND role=1 AND spent_by_txid IS NULL"
        ZSLP_WALLET_OWNS_ADDRESS,
        AR_BIND_BLOB(s, 1, token_id, 32));
}

int64_t zslp_ledger_wallet_balance_at_height(struct node_db *ndb,
                                             const uint8_t token_id[32],
                                             int32_t height)
{
    if (!ndb || !ndb->open || !token_id || height < 0) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_INT64_BOUND(ndb, s,
        "SELECT COALESCE(SUM(amount),0) FROM zslp_ledger"
        " WHERE token_id=? AND role=1" ZSLP_AS_OF_HEIGHT
        ZSLP_WALLET_OWNS_ADDRESS,
        AR_BIND_BLOB(s, 1, token_id, 32);
        AR_BIND_INT(s, 2, (int64_t)height);
        AR_BIND_INT(s, 3, (int64_t)height));
}

int64_t zslp_ledger_wallet_address_count(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_INT64_BOUND(ndb, s,
        "SELECT COUNT(*) FROM (" ZSLP_WALLET_ADDRESS_SET ")", (void)0);
}
