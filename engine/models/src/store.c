/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "models/store.h"
#include "models/model_text.h"
#include <string.h>
#include <time.h>

DEFINE_MODEL_CALLBACKS(store_product)
DEFINE_MODEL_CALLBACKS(store_order)

/* Read the optional content_hash column into a product row. Defined
 * below db_store_product_find_active; forward-declared so the finders
 * can share it. */
static void store_product_read_content(sqlite3_stmt *s, int col,
                                       struct db_store_product *out);

static bool store_product_before_validate(void *record, void *ctx)
{
    struct db_store_product *p = (struct db_store_product *)record;
    (void)ctx;
    model_trim_ascii(p->name);
    model_trim_ascii(p->description);
    model_trim_ascii(p->token_id);
    model_ascii_upcase(p->token_id);
    return true;
}

static bool store_order_before_validate(void *record, void *ctx)
{
    struct db_store_order *o = (struct db_store_order *)record;
    (void)ctx;
    model_trim_ascii(o->customer_addr);
    model_trim_ascii(o->payment_addr);
    model_trim_ascii(o->payment_txid);
    model_trim_ascii(o->mint_txid);
    return true;
}

DEFINE_MODEL_BEFORE_VALIDATE_READY(store_product, store_product_before_validate)
DEFINE_MODEL_BEFORE_VALIDATE_READY(store_order, store_order_before_validate)

bool db_store_product_validate(const struct db_store_product *p,
                               struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_string_present(errors, p->name, "name");
    validates_positive(errors, p, price_zatoshi);
    validates_positive(errors, p, tokens_per_purchase);
    validates_custom(errors,
        strlen(p->name) <= STORE_PRODUCT_NAME_MAX,
        "name", "exceeds max length 255");
    validates_custom(errors,
        strlen(p->description) <= STORE_PRODUCT_DESC_MAX,
        "description", "exceeds max length 1023");
    validates_custom(errors,
        strlen(p->token_id) <= STORE_PRODUCT_TOKEN_MAX,
        "token_id", "exceeds max length 64");
    validates_custom(errors,
        model_string_is_printable(p->name),
        "name", "contains non-printable characters");
    /* An ABSENT description is legal — the column is nullable, the storefront
     * renders the card without one, and neither writer requires it. Only
     * `name` is validates_string_present. model_string_is_printable("")
     * returns false, so without the empty-string escape (the same one
     * token_id already carries below) every product without a description
     * was rejected as "contains non-printable characters": products.json
     * entries with no description were silently dropped by the loader, and
     * app.store.list-product refused them outright. */
    validates_custom(errors,
        model_string_is_printable(p->description) || p->description[0] == '\0',
        "description", "contains non-printable characters");
    validates_custom(errors,
        model_string_is_printable(p->token_id) || p->token_id[0] == '\0',
        "token_id", "contains non-printable characters");
    return !ar_errors_any(errors);
}

bool db_store_order_validate(const struct db_store_order *o,
                             struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_positive(errors, o, product_id);
    validates_string_present(errors, o->payment_addr, "payment_addr");
    validates_positive(errors, o, amount_zatoshi);
    validates_non_negative(errors, o, status);
    validates_non_negative(errors, o, created_at);
    validates_custom(errors,
        strlen(o->customer_addr) <= STORE_ORDER_ADDR_MAX,
        "customer_addr", "exceeds max length 127");
    validates_custom(errors,
        strlen(o->payment_addr) <= STORE_ORDER_ADDR_MAX,
        "payment_addr", "exceeds max length 127");
    validates_custom(errors,
        strlen(o->payment_txid) <= STORE_ORDER_TXID_MAX,
        "payment_txid", "exceeds max length 127");
    validates_custom(errors,
        strlen(o->mint_txid) <= STORE_ORDER_TXID_MAX,
        "mint_txid", "exceeds max length 127");
    validates_custom(errors,
        model_string_is_printable(o->customer_addr),
        "customer_addr", "contains non-printable characters");
    validates_custom(errors,
        model_string_is_printable(o->payment_addr),
        "payment_addr", "contains non-printable characters");
    validates_custom(errors,
        model_string_is_printable(o->payment_txid) || o->payment_txid[0] == '\0',
        "payment_txid", "contains non-printable characters");
    validates_custom(errors,
        model_string_is_printable(o->mint_txid) || o->mint_txid[0] == '\0',
        "mint_txid", "contains non-printable characters");
    validates_custom(errors,
        o->status >= 0 && o->status <= 3,
        "status", "is out of range");
    return !ar_errors_any(errors);
}

bool db_store_product_save(struct node_db *ndb, const struct db_store_product *p)
{
    sqlite3_stmt *s = NULL;
    struct ar_callbacks *cbs;

    if (!ndb || !ndb->open || !p)
        return false;
    cbs = store_product_callbacks_ready();
    AR_BEGIN_SAVE(cbs, "store_product", p, db_store_product_validate);

    AR_PREPARE_BOOL(ndb, s,
        "INSERT INTO products "
        "(name,description,price_zatoshi,token_id,tokens_per_purchase,active,"
        "content_hash) "
        "VALUES (?,?,?,?,?,?,?)");

    AR_BIND_TEXT(s, 1, p->name);
    AR_BIND_TEXT(s, 2, p->description);
    AR_BIND_INT(s, 3, p->price_zatoshi);
    AR_BIND_TEXT(s, 4, p->token_id);
    AR_BIND_INT(s, 5, p->tokens_per_purchase);
    AR_BIND_INT(s, 6, p->active ? 1 : 0);
    if (p->has_content)
        AR_BIND_BLOB(s, 7, p->content_hash, sizeof(p->content_hash));
    else
        AR_BIND_NULL(s, 7);
    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    if (!ok) {
        LOG_WARN("model", "store_product save failed: %s", sqlite3_errmsg(ndb->db));
    }
    AR_FINISH_SAVE(cbs, p, ok);
}

bool db_store_product_find_active(struct node_db *ndb, int64_t id,
                                  struct db_store_product *out)
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open || !out || id <= 0)
        return false;
    memset(out, 0, sizeof(*out));
    AR_PREPARE_BOOL(ndb, s,
        "SELECT id,name,description,price_zatoshi,token_id,"
        "tokens_per_purchase,active,content_hash "
        "FROM products WHERE id=? AND active=1");

    AR_BIND_INT(s, 1, id);
    if (!AR_STEP_ROW(s)) {
        AR_FINALIZE(s);
        return false;
    }
    out->id = AR_COL_INT(s, 0);
    AR_READ_STR(s, 1, out->name, sizeof(out->name));
    AR_READ_STR(s, 2, out->description, sizeof(out->description));
    out->price_zatoshi = AR_COL_INT(s, 3);
    AR_READ_STR(s, 4, out->token_id, sizeof(out->token_id));
    out->tokens_per_purchase = AR_COL_INT(s, 5);
    out->active = AR_COL_INT(s, 6) != 0;
    store_product_read_content(s, 7, out);
    AR_FINALIZE(s);
    return true;
}

/* Read the optional content_hash column (NULL ⇒ no payload). A non-NULL
 * column must be exactly 32 bytes to count as an attached blob; any other
 * length is treated as "no content" (defensive against schema drift). */
static void store_product_read_content(sqlite3_stmt *s, int col,
                                       struct db_store_product *out)
{
    out->has_content = false;
    memset(out->content_hash, 0, sizeof(out->content_hash));
    if (sqlite3_column_type(s, col) == SQLITE_NULL)
        return;
    const void *blob = sqlite3_column_blob(s, col);
    int len = sqlite3_column_bytes(s, col);
    if (blob && len == (int)sizeof(out->content_hash)) {
        memcpy(out->content_hash, blob, sizeof(out->content_hash));
        out->has_content = true;
    }
}

bool db_store_product_find_by_token(struct node_db *ndb, const char *token_id,
                                    struct db_store_product *out)
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open || !out || !token_id || !token_id[0])
        return false;
    memset(out, 0, sizeof(*out));
    /* token ids are stored upcased by store_product_before_validate; compare
     * case-insensitively so a lowercase query token still resolves. */
    AR_PREPARE_BOOL(ndb, s,
        "SELECT id,name,description,price_zatoshi,token_id,"
        "tokens_per_purchase,active,content_hash "
        "FROM products WHERE token_id=upper(?) AND active=1 "
        "ORDER BY id LIMIT 1");

    AR_BIND_TEXT(s, 1, token_id);
    if (!AR_STEP_ROW(s)) {
        AR_FINALIZE(s);
        return false;
    }
    out->id = AR_COL_INT(s, 0);
    AR_READ_STR(s, 1, out->name, sizeof(out->name));
    AR_READ_STR(s, 2, out->description, sizeof(out->description));
    out->price_zatoshi = AR_COL_INT(s, 3);
    AR_READ_STR(s, 4, out->token_id, sizeof(out->token_id));
    out->tokens_per_purchase = AR_COL_INT(s, 5);
    out->active = AR_COL_INT(s, 6) != 0;
    store_product_read_content(s, 7, out);
    AR_FINALIZE(s);
    return true;
}

bool db_store_product_save_content(struct node_db *ndb, int64_t id,
                                   const uint8_t content_hash[32])
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open || id <= 0)
        return false;
    AR_PREPARE_BOOL(ndb, s,
        "UPDATE products SET content_hash=? WHERE id=?");
    if (content_hash)
        AR_BIND_BLOB(s, 1, content_hash, 32);
    else
        AR_BIND_NULL(s, 1);
    AR_BIND_INT(s, 2, id);
    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    if (!ok)
        LOG_FAIL("model", "store_product save_content failed: %s",
                 sqlite3_errmsg(ndb->db));
    return true;
}

int db_store_product_list_active(struct node_db *ndb,
                                 struct db_store_product *out, size_t max)
{
    sqlite3_stmt *s = NULL;
    int count = 0;

    if (!ndb || !ndb->open || !out || max == 0)
        return 0;
    AR_PREPARE_RET(ndb, s,
        "SELECT id,name,description,price_zatoshi,token_id,"
        "tokens_per_purchase,active "
        "FROM products WHERE active=1 ORDER BY id",
        0);

    AR_LIST_ROWS(s, out, max,
        out[count].id = AR_COL_INT(s, 0);
        AR_READ_STR(s, 1, out[count].name, sizeof(out[count].name));
        AR_READ_STR(s, 2, out[count].description, sizeof(out[count].description));
        out[count].price_zatoshi = AR_COL_INT(s, 3);
        AR_READ_STR(s, 4, out[count].token_id, sizeof(out[count].token_id));
        out[count].tokens_per_purchase = AR_COL_INT(s, 5);
        out[count].active = AR_COL_INT(s, 6) != 0;
        /* The list query does not select content_hash; the list view
         * never streams payloads. Zero the payload fields so callers see
         * a defined has_content=false rather than stack garbage. */
        out[count].has_content = false;
        memset(out[count].content_hash, 0, sizeof(out[count].content_hash)));
    AR_FINALIZE(s);
    return count;
}

int db_store_product_count(struct node_db *ndb)
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open)
        return 0;
    AR_QUERY_COUNT_BOUND(ndb, s, "SELECT count(*) FROM products", (void)0);
}

bool db_store_order_save(struct node_db *ndb, struct db_store_order *o)
{
    sqlite3_stmt *s = NULL;
    struct ar_callbacks *cbs;

    if (!ndb || !ndb->open || !o)
        return false;
    if (o->created_at == 0)
        o->created_at = (int64_t)platform_time_wall_time_t();

    cbs = store_order_callbacks_ready();
    AR_BEGIN_SAVE(cbs, "store_order", o, db_store_order_validate);

    AR_PREPARE_BOOL(ndb, s,
        "INSERT INTO orders "
        "(product_id,customer_addr,payment_addr,amount_zatoshi,payment_txid,"
        "mint_txid,status,created_at,paid_at) VALUES (?,?,?,?,?,?,?,?,?)");

    AR_BIND_INT(s, 1, o->product_id);
    AR_BIND_TEXT(s, 2, o->customer_addr);
    AR_BIND_TEXT(s, 3, o->payment_addr);
    AR_BIND_INT(s, 4, o->amount_zatoshi);
    AR_BIND_TEXT(s, 5, o->payment_txid);
    AR_BIND_TEXT(s, 6, o->mint_txid);
    AR_BIND_INT(s, 7, o->status);
    AR_BIND_INT(s, 8, o->created_at);
    if (o->has_paid_at)
        AR_BIND_INT(s, 9, o->paid_at);
    else
        AR_BIND_NULL(s, 9);
    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    if (!ok) {
        fprintf(stderr, "store_order save failed: %s\n", sqlite3_errmsg(ndb->db));
        return false;
    }
    o->id = sqlite3_last_insert_rowid(ndb->db);
    AR_FINISH_SAVE(cbs, o, true);
}

bool db_store_order_find_view(struct node_db *ndb, int64_t id,
                              struct db_store_order_view *out)
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open || !out || id <= 0)
        return false;
    memset(out, 0, sizeof(*out));
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT o.id,o.status,o.amount_zatoshi,o.payment_addr,"
            "o.customer_addr,o.payment_txid,o.mint_txid,p.name "
            "FROM orders o LEFT JOIN products p ON o.product_id = p.id "
            "WHERE o.id=?",
            -1, &s, NULL) != SQLITE_OK || !s)
        return false;

    AR_BIND_INT(s, 1, id);
    if (!AR_STEP_ROW(s)) {
        AR_FINALIZE(s);
        return false;
    }
    out->id = AR_COL_INT(s, 0);
    out->status = AR_COL_INT(s, 1);
    out->amount_zatoshi = AR_COL_INT(s, 2);
    AR_READ_STR(s, 3, out->payment_addr, sizeof(out->payment_addr));
    AR_READ_STR(s, 4, out->customer_addr, sizeof(out->customer_addr));
    AR_READ_STR(s, 5, out->payment_txid, sizeof(out->payment_txid));
    AR_READ_STR(s, 6, out->mint_txid, sizeof(out->mint_txid));
    AR_READ_STR(s, 7, out->product_name, sizeof(out->product_name));
    AR_FINALIZE(s);
    return true;
}

int db_store_order_list_recent(struct node_db *ndb,
                               struct db_store_order_summary *out, size_t max)
{
    sqlite3_stmt *s = NULL;
    int count = 0;

    if (!ndb || !ndb->open || !out || max == 0)
        return 0;
    AR_PREPARE_RET(ndb, s,
            "SELECT o.id,o.status,o.amount_zatoshi,p.name "
            "FROM orders o LEFT JOIN products p ON o.product_id = p.id "
            "ORDER BY o.created_at DESC LIMIT ?",
            0);

    AR_BIND_INT(s, 1, (int)max);
    AR_LIST_ROWS(s, out, max,
        out[count].id = AR_COL_INT(s, 0);
        out[count].status = AR_COL_INT(s, 1);
        out[count].amount_zatoshi = AR_COL_INT(s, 2);
        AR_READ_STR(s, 3, out[count].product_name,
                    sizeof(out[count].product_name)));
    AR_FINALIZE(s);
    return count;
}

int db_store_order_list_pending_payments(struct node_db *ndb,
                                         struct db_store_pending_payment *out,
                                         size_t max,
                                         int64_t min_created_at)
{
    sqlite3_stmt *s = NULL;
    int count = 0;

    if (!ndb || !ndb->open || !out || max == 0)
        return 0;
    AR_PREPARE_RET(ndb, s,
            "SELECT o.id,o.payment_addr,o.amount_zatoshi,o.customer_addr,"
            "p.token_id,p.tokens_per_purchase "
            "FROM orders o JOIN products p ON o.product_id = p.id "
            "WHERE o.status = ? AND o.created_at > ?",
            0);

    AR_BIND_INT(s, 1, STORE_ORDER_PENDING);
    AR_BIND_INT(s, 2, min_created_at);
    AR_LIST_ROWS(s, out, max,
        out[count].id = AR_COL_INT(s, 0);
        AR_READ_STR(s, 1, out[count].payment_addr, sizeof(out[count].payment_addr));
        out[count].amount_zatoshi = AR_COL_INT(s, 2);
        AR_READ_STR(s, 3, out[count].customer_addr, sizeof(out[count].customer_addr));
        AR_READ_STR(s, 4, out[count].token_id, sizeof(out[count].token_id));
        out[count].tokens_per_purchase = AR_COL_INT(s, 5));
    AR_FINALIZE(s);
    return count;
}

bool db_store_order_mark_paid(struct node_db *ndb, int64_t id, int status)
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open || id <= 0 || status < 0 || status > 3)
        return false;

    if (sqlite3_prepare_v2(ndb->db,
            "UPDATE orders SET status=?, paid_at=strftime('%s','now') "
            "WHERE id=?",
            -1, &s, NULL) != SQLITE_OK || !s)
        return false;
    AR_BIND_INT(s, 1, status);
    AR_BIND_INT(s, 2, id);
    if (!AR_STEP_DONE(s)) {
        AR_FINALIZE(s);
        return false;
    }
    AR_FINALIZE(s);
    return true;
}

int db_store_order_count_pending(struct node_db *ndb)
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open)
        return 0;
    AR_QUERY_COUNT_BOUND(ndb, s,
        "SELECT count(*) FROM orders WHERE status=?",
        AR_BIND_INT(s, 1, STORE_ORDER_PENDING));
}

int db_store_order_count_pending_for_product(struct node_db *ndb,
                                             int64_t product_id)
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open || product_id <= 0)
        return 0;
    AR_QUERY_COUNT_BOUND(ndb, s,
        "SELECT count(*) FROM orders WHERE status=? AND product_id=?",
        (AR_BIND_INT(s, 1, STORE_ORDER_PENDING),
         AR_BIND_INT(s, 2, product_id)));
}

int db_store_order_prune_expired(struct node_db *ndb, int64_t max_age_secs)
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open || max_age_secs < 0)
        return 0;
    int64_t cutoff = (int64_t)platform_time_wall_time_t() - max_age_secs;
    AR_PREPARE_RET(ndb, s,
        "DELETE FROM orders WHERE status=? AND created_at < ?", 0);
    AR_BIND_INT(s, 1, STORE_ORDER_PENDING);
    AR_BIND_INT(s, 2, cutoff);
    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    if (!ok) {
        LOG_WARN("model", "store_order prune_expired failed: %s",
                 sqlite3_errmsg(ndb->db));
        return 0;
    }
    return sqlite3_changes(ndb->db);
}

int64_t db_store_chain_tip_height(struct node_db *ndb)
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open)
        return 0;
    AR_QUERY_INT64_BOUND(ndb, s, "SELECT MAX(height) FROM blocks", (void)0);
}

int64_t db_store_received_payment(struct node_db *ndb, const char *pay_addr,
                                  int64_t max_height)
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open || !pay_addr || !pay_addr[0])
        return 0;
    AR_QUERY_INT64_BOUND(ndb, s,
        "SELECT COALESCE(SUM(value), 0) FROM wallet_sapling_notes "
        "WHERE spent_txid IS NULL AND address = ? "
        "AND block_height IS NOT NULL AND block_height <= ?",
        (AR_BIND_TEXT(s, 1, pay_addr), AR_BIND_INT(s, 2, max_height)));
}

int64_t db_store_received_payment_for_memo(struct node_db *ndb,
                                           const char *pay_addr,
                                           int64_t order_id,
                                           int64_t max_height)
{
    sqlite3_stmt *s = NULL;
    int64_t total = 0;
    char tok[64];
    int toklen;

    if (!ndb || !ndb->open || !pay_addr || !pay_addr[0] || order_id < 0)
        return 0;

    /* The order-binding token a payer must place at the head of the memo. */
    toklen = snprintf(tok, sizeof(tok), "ZCL23ORDER:%lld", (long long)order_id);
    if (toklen <= 0 || (size_t)toklen >= sizeof(tok))
        return 0;

    /* Row-scan (memo decode happens in C, not SQL) — same confirmed/unspent
     * filter as db_store_received_payment, then a memo-prefix test per row. */
    AR_PREPARE_RET(ndb, s,
        "SELECT value, memo FROM wallet_sapling_notes "
        "WHERE spent_txid IS NULL AND address = ? "
        "AND block_height IS NOT NULL AND block_height <= ?",
        0);
    AR_BIND_TEXT(s, 1, pay_addr);
    AR_BIND_INT(s, 2, max_height);

    while (AR_STEP_ROW(s)) {
        int64_t value = AR_COL_INT(s, 0);
        int memo_len = AR_COL_BYTES(s, 1);
        const unsigned char *memo = sqlite3_column_blob(s, 1);
        /* Match the order token at the memo head, terminated by NUL (the
         * 512-byte memo's zero padding) or an explicit ';' delimiter — so
         * order 1 can never be satisfied by order 12's memo. */
        if (memo && memo_len >= toklen &&
            memcmp(memo, tok, (size_t)toklen) == 0 &&
            (memo_len == toklen || memo[toklen] == '\0' || memo[toklen] == ';'))
            total += value;
    }
    AR_FINALIZE(s);
    return total;
}

int64_t db_store_received_payment_taddr(struct node_db *ndb,
                                        const uint8_t address_hash[20],
                                        int64_t max_height)
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open || !address_hash)
        return 0;

    /* `height > 0` keeps this to value some connected block actually paid.
     * wallet_utxos is written only from connected blocks (sync_controller_
     * writers.c, wallet_scan_service.c), so there is no mempool row to
     * exclude today — but a 0 height would sail past the `<= max_height`
     * confirmation ceiling if one ever appeared, which is the whole control.
     * `is_coinbase = 0` because a coinbase crediting the order address is
     * block subsidy, not a buyer's payment, and excluding it also sidesteps
     * coinbase maturity entirely. */
    AR_QUERY_INT64_BOUND(ndb, s,
        "SELECT COALESCE(SUM(value), 0) FROM wallet_utxos "
        "WHERE spent_txid IS NULL AND address_hash = ? "
        "AND is_coinbase = 0 AND height > 0 AND height <= ?",
        (AR_BIND_BLOB(s, 1, address_hash, 20),
         AR_BIND_INT(s, 2, max_height)));
}
