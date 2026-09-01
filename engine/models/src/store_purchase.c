/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Store PURCHASE model — buyer-side ledger row. See models/store_purchase.h
 * for why the buyer keeps its own row instead of reading the merchant's
 * `orders` table: a purchase can be paid and undelivered, and that state has
 * to survive a restart with a name on it. */

#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "models/store_purchase.h"
#include "models/model_text.h"
#include <string.h>
#include <time.h>

DEFINE_MODEL_CALLBACKS(store_purchase)

static bool store_purchase_before_validate(void *record, void *ctx)
{
    struct db_store_purchase *p = (struct db_store_purchase *)record;
    (void)ctx;
    model_trim_ascii(p->product_name);
    model_trim_ascii(p->token_id);
    model_ascii_upcase(p->token_id);
    model_trim_ascii(p->payment_addr);
    model_trim_ascii(p->customer_addr);
    model_trim_ascii(p->memo);
    model_trim_ascii(p->operation_id);
    return true;
}

DEFINE_MODEL_BEFORE_VALIDATE_READY(store_purchase,
                                   store_purchase_before_validate)

const char *store_purchase_stage_name(int stage)
{
    switch (stage) {
    case STORE_PURCHASE_CREATED:   return "created";
    case STORE_PURCHASE_PAYING:    return "paying";
    case STORE_PURCHASE_PAID:      return "paid";
    case STORE_PURCHASE_DELIVERED: return "delivered";
    case STORE_PURCHASE_FAILED:    return "failed";
    default:                       return "unknown";
    }
}

bool db_store_purchase_validate(const struct db_store_purchase *p,
                                struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_positive(errors, p, order_id);
    validates_positive(errors, p, product_id);
    validates_positive(errors, p, amount_zatoshi);
    validates_string_present(errors, p->payment_addr, "payment_addr");
    validates_string_present(errors, p->memo, "memo");
    validates_non_negative(errors, p, created_at);
    validates_custom(errors,
        p->stage >= STORE_PURCHASE_CREATED && p->stage <= STORE_PURCHASE_FAILED,
        "stage", "is out of range");
    validates_custom(errors,
        strlen(p->product_name) <= STORE_PURCHASE_NAME_MAX,
        "product_name", "exceeds max length 255");
    validates_custom(errors,
        strlen(p->token_id) <= STORE_PURCHASE_TOKEN_MAX,
        "token_id", "exceeds max length 64");
    validates_custom(errors,
        strlen(p->payment_addr) <= STORE_PURCHASE_ADDR_MAX,
        "payment_addr", "exceeds max length 127");
    validates_custom(errors,
        strlen(p->customer_addr) <= STORE_PURCHASE_ADDR_MAX,
        "customer_addr", "exceeds max length 127");
    validates_custom(errors,
        strlen(p->memo) <= STORE_PURCHASE_MEMO_MAX,
        "memo", "exceeds max length 63");
    validates_custom(errors,
        strlen(p->output_path) <= STORE_PURCHASE_PATH_MAX,
        "output_path", "exceeds max length 511");
    validates_custom(errors,
        strlen(p->operation_id) <= STORE_PURCHASE_OPID_MAX,
        "operation_id", "exceeds max length 127");
    validates_custom(errors,
        strlen(p->last_error) <= STORE_PURCHASE_ERROR_MAX,
        "last_error", "exceeds max length 191");
    validates_custom(errors,
        model_string_is_printable(p->payment_addr),
        "payment_addr", "contains non-printable characters");
    validates_custom(errors,
        model_string_is_printable(p->memo),
        "memo", "contains non-printable characters");
    validates_custom(errors,
        model_string_is_printable(p->customer_addr) ||
            p->customer_addr[0] == '\0',
        "customer_addr", "contains non-printable characters");
    validates_custom(errors,
        model_string_is_printable(p->token_id) || p->token_id[0] == '\0',
        "token_id", "contains non-printable characters");
    return !ar_errors_any(errors);
}

/* Bind the columns shared by the INSERT and the UPDATE, in the order both
 * statements list them (1..14). Keeping one binder means an added column
 * cannot be bound in the insert and forgotten in the update. */
static void store_purchase_bind_common(sqlite3_stmt *s,
                                       const struct db_store_purchase *p)
{
    AR_BIND_INT(s, 1, p->order_id);
    AR_BIND_INT(s, 2, p->product_id);
    AR_BIND_TEXT(s, 3, p->product_name);
    AR_BIND_TEXT(s, 4, p->token_id);
    AR_BIND_TEXT(s, 5, p->payment_addr);
    AR_BIND_TEXT(s, 6, p->customer_addr);
    AR_BIND_TEXT(s, 7, p->memo);
    AR_BIND_INT(s, 8, p->amount_zatoshi);
    if (p->has_content_hash)
        AR_BIND_BLOB(s, 9, p->content_hash, sizeof(p->content_hash));
    else
        AR_BIND_NULL(s, 9);
    AR_BIND_TEXT(s, 10, p->output_path);
    AR_BIND_TEXT(s, 11, p->operation_id);
    AR_BIND_INT(s, 12, p->stage);
    AR_BIND_TEXT(s, 13, p->last_error);
    AR_BIND_INT(s, 14, p->updated_at);
}

bool db_store_purchase_save(struct node_db *ndb, struct db_store_purchase *p)
{
    sqlite3_stmt *s = NULL;
    struct ar_callbacks *cbs;

    if (!ndb || !ndb->open || !p)
        return false;

    int64_t now = (int64_t)platform_time_wall_time_t();
    if (p->created_at <= 0)
        p->created_at = now;
    p->updated_at = now;

    cbs = store_purchase_callbacks_ready();
    AR_BEGIN_SAVE(cbs, "store_purchase", p, db_store_purchase_validate);

    bool ok = false;
    if (p->id > 0) {
        AR_PREPARE_BOOL(ndb, s,
            "UPDATE store_purchases SET "
            "order_id=?,product_id=?,product_name=?,token_id=?,"
            "payment_addr=?,customer_addr=?,memo=?,amount_zatoshi=?,"
            "content_hash=?,output_path=?,operation_id=?,stage=?,"
            "last_error=?,updated_at=? WHERE id=?");
        store_purchase_bind_common(s, p);
        AR_BIND_INT(s, 15, p->id);
        AR_FINALIZE_STEP_DONE(s, ok);
    } else {
        AR_PREPARE_BOOL(ndb, s,
            "INSERT INTO store_purchases "
            "(order_id,product_id,product_name,token_id,payment_addr,"
            "customer_addr,memo,amount_zatoshi,content_hash,output_path,"
            "operation_id,stage,last_error,updated_at,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
        store_purchase_bind_common(s, p);
        AR_BIND_INT(s, 15, p->created_at);
        AR_FINALIZE_STEP_DONE(s, ok);
        if (ok)
            p->id = sqlite3_last_insert_rowid(ndb->db);
    }
    if (!ok)
        LOG_WARN("model", "store_purchase save failed: %s",
                 sqlite3_errmsg(ndb->db));
    AR_FINISH_SAVE(cbs, p, ok);
}

#define STORE_PURCHASE_COLUMNS \
    "id,order_id,product_id,product_name,token_id,payment_addr," \
    "customer_addr,memo,amount_zatoshi,content_hash,output_path," \
    "operation_id,stage,last_error,created_at,updated_at"

static void store_purchase_read_row(sqlite3_stmt *s,
                                    struct db_store_purchase *out)
{
    memset(out, 0, sizeof(*out));
    out->id = AR_COL_INT(s, 0);
    out->order_id = AR_COL_INT(s, 1);
    out->product_id = AR_COL_INT(s, 2);
    AR_READ_STR(s, 3, out->product_name, sizeof(out->product_name));
    AR_READ_STR(s, 4, out->token_id, sizeof(out->token_id));
    AR_READ_STR(s, 5, out->payment_addr, sizeof(out->payment_addr));
    AR_READ_STR(s, 6, out->customer_addr, sizeof(out->customer_addr));
    AR_READ_STR(s, 7, out->memo, sizeof(out->memo));
    out->amount_zatoshi = AR_COL_INT(s, 8);
    /* A non-NULL content_hash must be exactly 32 bytes to count; any other
     * length is treated as absent so schema drift cannot hand the delivery
     * path a short hash to compare against. */
    if (sqlite3_column_type(s, 9) != SQLITE_NULL) {
        const void *blob = sqlite3_column_blob(s, 9);
        int len = sqlite3_column_bytes(s, 9);
        if (blob && len == (int)sizeof(out->content_hash)) {
            memcpy(out->content_hash, blob, sizeof(out->content_hash));
            out->has_content_hash = true;
        }
    }
    AR_READ_STR(s, 10, out->output_path, sizeof(out->output_path));
    AR_READ_STR(s, 11, out->operation_id, sizeof(out->operation_id));
    out->stage = (int)AR_COL_INT(s, 12);
    AR_READ_STR(s, 13, out->last_error, sizeof(out->last_error));
    out->created_at = AR_COL_INT(s, 14);
    out->updated_at = AR_COL_INT(s, 15);
}

bool db_store_purchase_find(struct node_db *ndb, int64_t id,
                            struct db_store_purchase *out)
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open || !out || id <= 0)
        return false;
    memset(out, 0, sizeof(*out));
    AR_PREPARE_BOOL(ndb, s,
        "SELECT " STORE_PURCHASE_COLUMNS " FROM store_purchases WHERE id=?");
    AR_BIND_INT(s, 1, id);
    if (!AR_STEP_ROW(s)) {
        AR_FINALIZE(s);
        return false;
    }
    store_purchase_read_row(s, out);
    AR_FINALIZE(s);
    return true;
}

bool db_store_purchase_find_by_order(struct node_db *ndb, int64_t order_id,
                                     struct db_store_purchase *out)
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open || !out || order_id <= 0)
        return false;
    memset(out, 0, sizeof(*out));
    AR_PREPARE_BOOL(ndb, s,
        "SELECT " STORE_PURCHASE_COLUMNS
        " FROM store_purchases WHERE order_id=?");
    AR_BIND_INT(s, 1, order_id);
    if (!AR_STEP_ROW(s)) {
        AR_FINALIZE(s);
        return false;
    }
    store_purchase_read_row(s, out);
    AR_FINALIZE(s);
    return true;
}

int db_store_purchase_list(struct node_db *ndb, struct db_store_purchase *out,
                           size_t max)
{
    sqlite3_stmt *s = NULL;
    int count = 0;

    if (!ndb || !ndb->open || !out || max == 0)
        return 0;
    AR_PREPARE_RET(ndb, s,
        "SELECT " STORE_PURCHASE_COLUMNS
        " FROM store_purchases ORDER BY id DESC", 0);
    while (count < (int)max && AR_STEP_ROW(s))
        store_purchase_read_row(s, &out[count++]);
    AR_FINALIZE(s);
    return count;
}

int db_store_purchase_count_unfinished(struct node_db *ndb)
{
    sqlite3_stmt *s = NULL;
    int count = 0;

    if (!ndb || !ndb->open)
        return 0;
    AR_PREPARE_RET(ndb, s,
        "SELECT COUNT(*) FROM store_purchases WHERE stage IN (?,?,?)", 0);
    AR_BIND_INT(s, 1, STORE_PURCHASE_CREATED);
    AR_BIND_INT(s, 2, STORE_PURCHASE_PAYING);
    AR_BIND_INT(s, 3, STORE_PURCHASE_PAID);
    if (AR_STEP_ROW(s))
        count = (int)AR_COL_INT(s, 0);
    AR_FINALIZE(s);
    return count;
}
