/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord model: ZSLP Token & Transfer
 *
 * Token:
 *   validates :token_id, presence: true
 *   validates :ticker, presence: true, length: { max: 10 }
 *   validates :decimals, range: [0, 8]
 *   validates :genesis_height, numericality: { >= 0 }
 *   validates :initial_quantity, numericality: { >= 0 }
 *
 * Transfer:
 *   validates :txid, :token_id, presence: true
 *   validates :block_height, :amount, :vout, numericality: { >= 0 }
 *   validates :tx_type, range: [1, 3] */

#include "models/zslp.h"
#include "models/activerecord.h"
#include "models/model_text.h"
#include "core/uint256.h"
#include "event/event.h"
#include <limits.h>
#include <string.h>
#include <stdio.h>

/* ── Token-id byte order ───────────────────────────────────────── */

/* Contract and rationale: models/zslp.h, "Token-id byte order at the model
 * boundary". */
void db_zslp_token_id_render(const uint8_t token_id[32], char out[65])
{
    struct uint256 id;

    if (!token_id || !out)
        return;
    memcpy(id.data, token_id, 32);
    uint256_get_hex(&id, out);
}

bool db_zslp_token_id_to_bytes(const char *rendered, uint8_t out[32])
{
    struct uint256 id;

    if (!rendered || !out || strlen(rendered) != 64 ||
        !model_string_is_hex(rendered))
        return false;
    uint256_set_hex(&id, rendered);
    memcpy(out, id.data, 32);
    return true;
}

/* Read one identity result column (`token_id` or `txid`). A 32-byte blob is
 * a chain identity and renders in display order; anything else is an
 * application-local key and renders verbatim, upcased the way the key
 * columns are stored. */
static void zslp_read_id_column(sqlite3_stmt *s, int col, char *out,
                                size_t out_len)
{
    if (sqlite3_column_type(s, col) == SQLITE_BLOB &&
        sqlite3_column_bytes(s, col) == 32) {
        char hex[65];
        db_zslp_token_id_render(sqlite3_column_blob(s, col), hex);
        snprintf(out, out_len, "%s", hex);
        return;
    }
    AR_READ_STR(s, col, out, out_len);
    model_ascii_upcase(out);
}

/* Bind the two halves of a token_id WHERE clause: `blob_pos` matches the
 * 32 internal bytes a display-order key names (NULL, which matches nothing,
 * when the key is not a chain id), `text_pos` matches an application-local
 * key. `key_bytes` must outlive the step — AR_BIND_BLOB is SQLITE_STATIC. */
static void zslp_bind_token_key(sqlite3_stmt *s, int blob_pos, int text_pos,
                                const char *upcased_key, uint8_t key_bytes[32])
{
    if (db_zslp_token_id_to_bytes(upcased_key, key_bytes))
        AR_BIND_BLOB(s, blob_pos, key_bytes, 32);
    else
        AR_BIND_NULL(s, blob_pos);
    AR_BIND_TEXT(s, text_pos, upcased_key);
}

/* ── Callbacks ─────────────────────────────────────────────────── */

DEFINE_MODEL_CALLBACKS(zslp_token)
DEFINE_MODEL_CALLBACKS(zslp_transfer)
DEFINE_MODEL_CALLBACKS(zslp_balance)
static bool zslp_token_before_validate(void *record, void *ctx);

static bool zslp_balance_before_validate(void *record, void *ctx)
{
    (void)ctx;
    struct db_zslp_balance *b = (struct db_zslp_balance *)record;
    model_ascii_upcase(b->token_id);
    return true;
}

DEFINE_MODEL_BEFORE_VALIDATE_READY(zslp_token, zslp_token_before_validate)
DEFINE_MODEL_BEFORE_VALIDATE_READY(zslp_balance, zslp_balance_before_validate)

/* ── Token Validation ─────────────────────────────────────────── */

/* Use a temporary struct for validates_* macros */
struct zslp_token_record {
    uint8_t token_id[32];
    int decimals;
    int genesis_height;
    int64_t initial_quantity;
};

struct zslp_token_key_record {
    char token_id[ZSLP_TOKEN_KEY_MAX + 1];
    int decimals;
    int genesis_height;
    int64_t initial_quantity;
};

static bool zslp_token_before_validate(void *record, void *ctx)
{
    struct zslp_token_key_record *rec = (struct zslp_token_key_record *)record;
    (void)ctx;
    model_ascii_upcase(rec->token_id);
    return true;
}

bool db_zslp_token_validate_record(const struct zslp_token_record *rec,
                                    struct ar_errors *errors);

bool db_zslp_token_validate_record(const struct zslp_token_record *rec,
                                    struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_presence_of(errors, rec, token_id);
    validates_range(errors, rec, decimals, 0, 9);
    validates_non_negative(errors, rec, genesis_height);
    validates_non_negative(errors, rec, initial_quantity);
    return !ar_errors_any(errors);
}

bool db_zslp_token_key_validate_record(const struct zslp_token_key_record *rec,
                                        struct ar_errors *errors);

bool db_zslp_token_key_validate_record(const struct zslp_token_key_record *rec,
                                        struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_string_present(errors, rec->token_id, "token_id");
    validates_custom(errors,
        strlen(rec->token_id) <= ZSLP_TOKEN_KEY_MAX,
        "token_id", "exceeds max length 64");
    validates_custom(errors,
        model_string_is_alnum(rec->token_id) ||
        (strlen(rec->token_id) == 64 && model_string_is_hex(rec->token_id)),
        "token_id", "must be alphanumeric or 64-char hex");
    validates_range(errors, rec, decimals, 0, 9);
    validates_non_negative(errors, rec, genesis_height);
    validates_non_negative(errors, rec, initial_quantity);
    return !ar_errors_any(errors);
}

bool db_zslp_balance_validate(const struct db_zslp_balance *b,
                              struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_string_present(errors, b->token_id, "token_id");
    validates_string_present(errors, b->address, "address");
    validates_non_negative(errors, b, balance);
    validates_custom(errors,
        strlen(b->token_id) <= ZSLP_TOKEN_KEY_MAX,
        "token_id", "exceeds max length 64");
    validates_custom(errors,
        strlen(b->address) <= ZSLP_ADDRESS_MAX,
        "address", "exceeds max length 128");
    validates_custom(errors,
        model_string_is_printable(b->address),
        "address", "contains non-printable characters");
    validates_custom(errors,
        model_string_is_alnum(b->token_id) ||
        (strlen(b->token_id) == 64 && model_string_is_hex(b->token_id)),
        "token_id", "must be alphanumeric or 64-char hex");
    return !ar_errors_any(errors);
}

bool db_zslp_token_validate_key(const char *token_key,
                                struct ar_errors *errors)
{
    struct zslp_token_key_record rec;

    memset(&rec, 0, sizeof(rec));
    if (token_key)
        snprintf(rec.token_id, sizeof(rec.token_id), "%s", token_key);
    return db_zslp_token_key_validate_record(&rec, errors);
}

/* ── Transfer Validation ──────────────────────────────────────── */

struct zslp_transfer_record {
    uint8_t txid[32];
    uint8_t token_id[32];
    int block_height;
    int tx_type;
    int64_t amount;
    int vout;
};

bool db_zslp_transfer_validate_record(const struct zslp_transfer_record *rec,
                                       struct ar_errors *errors);

bool db_zslp_transfer_validate_record(const struct zslp_transfer_record *rec,
                                       struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_presence_of(errors, rec, txid);
    validates_presence_of(errors, rec, token_id);
    validates_non_negative(errors, rec, block_height);
    validates_range(errors, rec, tx_type, 1, 3);
    validates_non_negative(errors, rec, amount);
    validates_non_negative(errors, rec, vout);
    return !ar_errors_any(errors);
}

/* ── CRUD ──────────────────────────────────────────────────────── */

bool db_zslp_token_save(struct node_db *ndb, const uint8_t token_id[32],
                         const char *ticker, const char *name,
                         int decimals, const char *document_url,
                         int genesis_height, int64_t initial_quantity)
{
    if (!ndb || !ndb->open) return false;
    struct zslp_token_record rec;
    memcpy(rec.token_id, token_id, 32);
    rec.decimals = decimals;
    rec.genesis_height = genesis_height;
    rec.initial_quantity = initial_quantity;
    struct ar_callbacks *cbs = db_zslp_token_callbacks();
    /* Indexer path: accept an empty ticker (legal on-chain — ~22% of real
     * ZClassic SLP tokens carry none; the view renders them "(unnamed)") so
     * every GENESIS gets a row. Reject only NULL or an over-long ticker. */
    if (!ticker || strlen(ticker) > ZSLP_TICKER_MAX) {
        fprintf(stderr, "zslp_token validation FAILED: ticker invalid\n");
        return false;
    }
    AR_BEGIN_SAVE(cbs, "zslp_token", &rec, db_zslp_token_validate_record);

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "INSERT OR IGNORE INTO zslp_tokens"
            "(token_id,ticker,name,decimals,document_url,"
            "genesis_height,total_minted) VALUES(?,?,?,?,?,?,?)",
            -1, &s, NULL) != SQLITE_OK || !s)
        return false;

    AR_BIND_BLOB(s, 1, token_id, 32);
    AR_BIND_TEXT(s, 2, ticker);
    AR_BIND_TEXT(s, 3, name ? name : "");
    AR_BIND_INT(s, 4, decimals);
    AR_BIND_TEXT(s, 5, document_url ? document_url : "");
    AR_BIND_INT(s, 6, genesis_height);
    AR_BIND_INT(s, 7, initial_quantity);

    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    if (ok)
        event_emitf(EV_MODEL_SAVED, 0, "model=zslp_token ticker=%s", ticker);
    else
        fprintf(stderr, "zslp_token save failed: %s\n", sqlite3_errmsg(ndb->db));
    AR_FINISH_SAVE(cbs, &rec, ok);
}

bool db_zslp_token_save_key(struct node_db *ndb, const char *token_key,
                            const char *ticker, const char *name,
                            int decimals, const char *document_url,
                            int genesis_height, int64_t initial_quantity)
{
    sqlite3_stmt *s = NULL;
    struct ar_callbacks *cbs;
    struct zslp_token_key_record rec;

    if (!ndb || !ndb->open || !token_key)
        return false;

    memset(&rec, 0, sizeof(rec));
    snprintf(rec.token_id, sizeof(rec.token_id), "%s", token_key);
    rec.decimals = decimals;
    rec.genesis_height = genesis_height;
    rec.initial_quantity = initial_quantity;
    cbs = zslp_token_callbacks_ready();
    if (!ticker || ticker[0] == '\0' || strlen(ticker) > ZSLP_TICKER_MAX) {
        fprintf(stderr, "zslp_token validation FAILED: ticker invalid\n");
        return false;
    }
    AR_BEGIN_SAVE(cbs, "zslp_token", &rec,
                  db_zslp_token_key_validate_record);

    if (sqlite3_prepare_v2(ndb->db,
            "INSERT OR REPLACE INTO zslp_tokens"
            "(token_id,ticker,name,decimals,document_url,"
            "genesis_height,total_minted) VALUES(?,?,?,?,?,?,?)",
            -1, &s, NULL) != SQLITE_OK || !s)
        return false;

    AR_BIND_TEXT(s, 1, rec.token_id);
    AR_BIND_TEXT(s, 2, ticker);
    AR_BIND_TEXT(s, 3, name ? name : "");
    AR_BIND_INT(s, 4, decimals);
    AR_BIND_TEXT(s, 5, document_url ? document_url : "");
    AR_BIND_INT(s, 6, genesis_height);
    AR_BIND_INT(s, 7, initial_quantity);

    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    if (!ok) {
        fprintf(stderr, "zslp_token save_key failed: %s\n", sqlite3_errmsg(ndb->db));
    } else {
        event_emitf(EV_MODEL_SAVED, 0, "model=zslp_token token_id=%s", rec.token_id);
    }
    AR_FINISH_SAVE(cbs, &rec, ok);
}

bool db_zslp_transfer_save(struct node_db *ndb, const uint8_t txid[32],
                            int block_height, const uint8_t token_id[32],
                            int tx_type, int64_t amount, int vout,
                            const uint8_t *to_addr)
{
    if (!ndb || !ndb->open) return false;
    struct zslp_transfer_record rec;
    memcpy(rec.txid, txid, 32);
    memcpy(rec.token_id, token_id, 32);
    rec.block_height = block_height;
    rec.tx_type = tx_type;
    rec.amount = amount;
    rec.vout = vout;
    struct ar_callbacks *cbs = db_zslp_transfer_callbacks();
    AR_BEGIN_SAVE(cbs, "zslp_transfer", &rec,
                  db_zslp_transfer_validate_record);

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "INSERT OR IGNORE INTO zslp_transfers"
            "(txid,block_height,token_id,tx_type,amount,vout,to_addr)"
            " VALUES(?,?,?,?,?,?,?)",
            -1, &s, NULL) != SQLITE_OK || !s)
        return false;

    AR_BIND_BLOB(s, 1, txid, 32);
    AR_BIND_INT(s, 2, block_height);
    AR_BIND_BLOB(s, 3, token_id, 32);
    AR_BIND_INT(s, 4, tx_type);
    AR_BIND_INT(s, 5, amount);
    AR_BIND_INT(s, 6, vout);
    if (to_addr)
        AR_BIND_BLOB(s, 7, to_addr, 20);
    else
        AR_BIND_NULL(s, 7);

    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    if (!ok)
        // obs-ok:caller-logs — callers (explorer_index_zslp.c) LOG_WARN the
        // false return with height+vout+type, so the failure is observable.
        fprintf(stderr, "zslp_transfer save failed: %s\n", sqlite3_errmsg(ndb->db));
    AR_FINISH_SAVE(cbs, &rec, ok);
}

bool db_zslp_balance_save(struct node_db *ndb, const struct db_zslp_balance *b)
{
    sqlite3_stmt *s = NULL;
    struct ar_callbacks *cbs;

    if (!ndb || !ndb->open || !b)
        return false;

    cbs = zslp_balance_callbacks_ready();
    AR_BEGIN_SAVE(cbs, "zslp_balance", b, db_zslp_balance_validate);

    if (sqlite3_prepare_v2(ndb->db,
            "INSERT INTO zslp_balances (token_id,address,balance) "
            "VALUES(?,?,?) "
            "ON CONFLICT(token_id,address) DO UPDATE SET balance=excluded.balance",
            -1, &s, NULL) != SQLITE_OK || !s)
        return false;

    AR_BIND_TEXT(s, 1, b->token_id);
    AR_BIND_TEXT(s, 2, b->address);
    AR_BIND_INT(s, 3, b->balance);

    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    if (!ok) {
        fprintf(stderr, "zslp_balance save failed: %s\n", sqlite3_errmsg(ndb->db));
    } else {
        event_emitf(EV_MODEL_SAVED, 0, "model=zslp_balance token_id=%s", b->token_id);
    }
    AR_FINISH_SAVE(cbs, b, ok);
}

bool db_zslp_balance_find(struct node_db *ndb, const char *token_id,
                          const char *address, struct db_zslp_balance *out)
{
    sqlite3_stmt *s = NULL;
    struct db_zslp_balance lookup;

    if (!ndb || !ndb->open || !token_id || !address || !out)
        return false;

    memset(&lookup, 0, sizeof(lookup));
    snprintf(lookup.token_id, sizeof(lookup.token_id), "%s", token_id);
    snprintf(lookup.address, sizeof(lookup.address), "%s", address);
    model_ascii_upcase(lookup.token_id);

    if (sqlite3_prepare_v2(ndb->db,
            "SELECT token_id,address,balance FROM zslp_balances "
            "WHERE token_id=? AND address=?",
            -1, &s, NULL) != SQLITE_OK || !s)
        return false;

    AR_BIND_TEXT(s, 1, lookup.token_id);
    AR_BIND_TEXT(s, 2, lookup.address);
    if (!AR_STEP_ROW(s)) {
        AR_FINALIZE(s);
        return false;
    }

    memset(out, 0, sizeof(*out));
    AR_READ_STR(s, 0, out->token_id, sizeof(out->token_id));
    AR_READ_STR(s, 1, out->address, sizeof(out->address));
    out->balance = AR_COL_INT(s, 2);
    AR_FINALIZE(s);
    return true;
}

bool db_zslp_token_find(struct node_db *ndb, const char *token_key,
                        struct db_zslp_token_info *out)
{
    sqlite3_stmt *s = NULL;
    char lookup[ZSLP_TOKEN_KEY_MAX + 1];
    uint8_t key_bytes[32];

    if (!ndb || !ndb->open || !token_key || !out)
        return false;

    memset(lookup, 0, sizeof(lookup));
    snprintf(lookup, sizeof(lookup), "%s", token_key);
    model_ascii_upcase(lookup);

    if (sqlite3_prepare_v2(ndb->db,
            "SELECT token_id,"
            "       ticker,name,decimals,genesis_height,total_minted "
            "FROM zslp_tokens "
            "WHERE (typeof(token_id)='blob' AND token_id=?) "
            "   OR (typeof(token_id)!='blob' AND upper(CAST(token_id AS TEXT))=?) "
            "LIMIT 1",
            -1, &s, NULL) != SQLITE_OK || !s)
        return false;

    zslp_bind_token_key(s, 1, 2, lookup, key_bytes);
    if (!AR_STEP_ROW(s)) {
        AR_FINALIZE(s);
        return false;
    }

    memset(out, 0, sizeof(*out));
    zslp_read_id_column(s, 0, out->token_id, sizeof(out->token_id));
    AR_READ_STR(s, 1, out->ticker, sizeof(out->ticker));
    AR_READ_STR(s, 2, out->name, sizeof(out->name));
    out->decimals = (int)AR_COL_INT(s, 3);
    out->genesis_height = (int)AR_COL_INT(s, 4);
    out->total_minted = AR_COL_INT(s, 5);
    AR_FINALIZE(s);
    return true;
}

int db_zslp_token_list(struct node_db *ndb,
                       struct db_zslp_token_info *out, size_t max_out)
{
    sqlite3_stmt *s = NULL;
    int count = 0;

    if (!ndb || !ndb->open || !out || max_out == 0)
        return 0;

    if (sqlite3_prepare_v2(ndb->db,
            "SELECT token_id,"
            "       ticker,name,decimals,genesis_height,total_minted "
            "FROM zslp_tokens "
            "ORDER BY ticker ASC, genesis_height DESC "
            "LIMIT ?",
            -1, &s, NULL) != SQLITE_OK || !s)
        return 0;

    AR_BIND_INT(s, 1, (int)max_out);
    while (count < (int)max_out && AR_STEP_ROW(s)) {
        memset(&out[count], 0, sizeof(out[count]));
        zslp_read_id_column(s, 0, out[count].token_id,
                           sizeof(out[count].token_id));
        AR_READ_STR(s, 1, out[count].ticker, sizeof(out[count].ticker));
        AR_READ_STR(s, 2, out[count].name, sizeof(out[count].name));
        out[count].decimals = (int)AR_COL_INT(s, 3);
        out[count].genesis_height = (int)AR_COL_INT(s, 4);
        out[count].total_minted = AR_COL_INT(s, 5);
        count++;
    }
    AR_FINALIZE(s);
    return count;
}

/* The property catalog must not mistake the store's application-local token
 * keys (for example ZCL23ACCESS) for chain assets.  These three reads keep
 * the filter model-owned and return only identities that can be represented
 * by the immutable 32-byte ZSLP GENESIS root. */
#define ZSLP_CHAIN_ASSET_WHERE                                             \
    "((typeof(token_id)='blob' AND length(token_id)=32) "                  \
    "OR (typeof(token_id)!='blob' AND length(CAST(token_id AS TEXT))=64))"

int db_zslp_asset_lookup(struct node_db *ndb, const uint8_t token_id[32],
                         struct db_zslp_token_info *out)
{
    sqlite3_stmt *s = NULL;
    char key[65];

    if (!ndb || !ndb->open || !token_id || !out)
        return -1;
    /* A TEXT chain-asset row was written from a broadcast txid string
     * (zslp_command_finalize_genesis), so it too is display order. */
    db_zslp_token_id_render(token_id, key);
    model_ascii_upcase(key);
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT token_id,"
            "       ticker,name,decimals,genesis_height,total_minted "
            "FROM zslp_tokens WHERE " ZSLP_CHAIN_ASSET_WHERE " AND "
            "((typeof(token_id)='blob' AND token_id=?) OR "
            " (typeof(token_id)!='blob' AND "
            "  upper(CAST(token_id AS TEXT))=?)) LIMIT 1",
            -1, &s, NULL) != SQLITE_OK || !s)
        return -1;
    AR_BIND_BLOB(s, 1, token_id, 32);
    AR_BIND_TEXT(s, 2, key);
    if (!AR_STEP_ROW(s)) {
        int rc = sqlite3_errcode(ndb->db);
        AR_FINALIZE(s);
        return rc == SQLITE_OK || rc == SQLITE_DONE ? 0 : -1;
    }
    memset(out, 0, sizeof(*out));
    zslp_read_id_column(s, 0, out->token_id, sizeof(out->token_id));
    AR_READ_STR(s, 1, out->ticker, sizeof(out->ticker));
    AR_READ_STR(s, 2, out->name, sizeof(out->name));
    out->decimals = (int)AR_COL_INT(s, 3);
    out->genesis_height = (int)AR_COL_INT(s, 4);
    out->total_minted = AR_COL_INT(s, 5);
    AR_FINALIZE(s);
    return 1;
}

bool db_zslp_asset_count(struct node_db *ndb, size_t *out)
{
    sqlite3_stmt *s = NULL;
    int64_t count;

    if (out)
        *out = 0;
    if (!ndb || !ndb->open || !out ||
        sqlite3_prepare_v2(ndb->db,
            "SELECT COUNT(*) FROM zslp_tokens WHERE "
            ZSLP_CHAIN_ASSET_WHERE, -1, &s, NULL) != SQLITE_OK || !s)
        return false;
    if (!AR_STEP_ROW(s)) {
        AR_FINALIZE(s);
        return false;
    }
    count = AR_COL_INT(s, 0);
    AR_FINALIZE(s);
    if (count < 0 || (uint64_t)count > (uint64_t)SIZE_MAX)
        return false;
    *out = (size_t)count;
    return true;
}

int db_zslp_asset_list(struct node_db *ndb,
                       struct db_zslp_token_info *out, size_t max_out)
{
    sqlite3_stmt *s = NULL;
    int count = 0;

    if (!ndb || !ndb->open || !out || max_out == 0)
        return 0;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT token_id,"
            "       ticker,name,decimals,genesis_height,total_minted "
            "FROM zslp_tokens WHERE " ZSLP_CHAIN_ASSET_WHERE " "
            "ORDER BY ticker ASC, genesis_height DESC LIMIT ?",
            -1, &s, NULL) != SQLITE_OK || !s)
        return 0;
    AR_BIND_INT(s, 1, (int64_t)max_out);
    while ((size_t)count < max_out && AR_STEP_ROW(s)) {
        memset(&out[count], 0, sizeof(out[count]));
        zslp_read_id_column(s, 0, out[count].token_id,
                           sizeof(out[count].token_id));
        AR_READ_STR(s, 1, out[count].ticker, sizeof(out[count].ticker));
        AR_READ_STR(s, 2, out[count].name, sizeof(out[count].name));
        out[count].decimals = (int)AR_COL_INT(s, 3);
        out[count].genesis_height = (int)AR_COL_INT(s, 4);
        out[count].total_minted = AR_COL_INT(s, 5);
        count++;
    }
    AR_FINALIZE(s);
    return count;
}

#undef ZSLP_CHAIN_ASSET_WHERE

int db_zslp_transfer_list_by_token(struct node_db *ndb, const char *token_key,
                                   struct db_zslp_transfer_info *out,
                                   size_t max_out)
{
    sqlite3_stmt *s = NULL;
    char lookup[ZSLP_TOKEN_KEY_MAX + 1];
    uint8_t key_bytes[32];
    int count = 0;

    if (!ndb || !ndb->open || !token_key || !out || max_out == 0)
        return 0;

    memset(lookup, 0, sizeof(lookup));
    snprintf(lookup, sizeof(lookup), "%s", token_key);
    model_ascii_upcase(lookup);

    /* txid renders in display order for the same reason token_id does: it is
     * the string an operator pastes into getrawtransaction. */
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT txid,"
            "       token_id,"
            "       block_height,tx_type,amount,vout,"
            "       CASE WHEN to_addr IS NULL THEN '' ELSE hex(to_addr) END "
            "FROM zslp_transfers "
            "WHERE (typeof(token_id)='blob' AND token_id=?) "
            "   OR (typeof(token_id)!='blob' AND upper(CAST(token_id AS TEXT))=?) "
            "ORDER BY block_height DESC, vout ASC "
            "LIMIT ?",
            -1, &s, NULL) != SQLITE_OK || !s)
        return 0;

    zslp_bind_token_key(s, 1, 2, lookup, key_bytes);
    AR_BIND_INT(s, 3, (int)max_out);
    while (count < (int)max_out && AR_STEP_ROW(s)) {
        memset(&out[count], 0, sizeof(out[count]));
        zslp_read_id_column(s, 0, out[count].txid, sizeof(out[count].txid));
        zslp_read_id_column(s, 1, out[count].token_id,
                           sizeof(out[count].token_id));
        out[count].block_height = AR_COL_INT(s, 2);
        out[count].tx_type = AR_COL_INT(s, 3);
        out[count].amount = AR_COL_INT(s, 4);
        out[count].vout = AR_COL_INT(s, 5);
        AR_READ_STR(s, 6, out[count].to_addr_hex, sizeof(out[count].to_addr_hex));
        count++;
    }
    AR_FINALIZE(s);
    return count;
}

int db_zslp_max_height(struct node_db *ndb)
{
    sqlite3_stmt *s = NULL;
    int h = -1;

    if (!ndb || !ndb->open)
        return -1;
    AR_PREPARE_RET(ndb, s,
        "SELECT MAX(h) FROM ("
        "  SELECT genesis_height AS h FROM zslp_tokens"
        "  UNION ALL "
        "  SELECT block_height AS h FROM zslp_transfers"
        ")",
        -1);
    if (AR_STEP_ROW(s))
        h = (int)AR_COL_INT(s, 0);
    AR_FINALIZE(s);
    return h;
}

bool db_zslp_balance_credit(struct node_db *ndb, const char *token_id,
                            const char *address, int64_t amount)
{
    struct db_zslp_balance rec;
    struct db_zslp_balance existing;

    if (!ndb || !ndb->open || !token_id || !address || amount <= 0)
        return false;

    memset(&rec, 0, sizeof(rec));
    snprintf(rec.token_id, sizeof(rec.token_id), "%s", token_id);
    snprintf(rec.address, sizeof(rec.address), "%s", address);

    if (db_zslp_balance_find(ndb, rec.token_id, rec.address, &existing)) {
        if (existing.balance > INT64_MAX - amount)
            return false;
        rec.balance = existing.balance + amount;
    } else {
        rec.balance = amount;
    }

    return db_zslp_balance_save(ndb, &rec);
}

void db_zslp_clear_all(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return;
    node_db_exec(ndb, "DELETE FROM zslp_tokens");
    node_db_exec(ndb, "DELETE FROM zslp_transfers");
}
