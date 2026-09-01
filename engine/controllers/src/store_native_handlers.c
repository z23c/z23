/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Store listing: the native command handlers for `app.store.list-product`
 * and `app.store.products` — the typed, agent-drivable half of "operator
 * lists a product" (MVP criterion #5).
 *
 * Before this file the ONLY way to put a product in the store was to drop a
 * `<datadir>/store/products.json` file and have store_ensure_schema()
 * (store_controller_schema.c) parse it on the first /store request against an
 * empty `products` table. That path still works and is untouched; this file is
 * a SECOND writer of the SAME `db_store_product` record, through the same
 * ActiveRecord model, so nothing here duplicates the product shape, its
 * validations, or its SQL.
 *
 * Three things this writer does that the JSON loader deliberately does not:
 *
 *   1. It is typed. Every refusal is a distinct machine-readable code
 *      (CONTENT_UNREADABLE, DUPLICATE_TOKEN_ID, BAD_PRICE, ...) instead of a
 *      log line and a silently skipped row.
 *   2. It refuses a duplicate token id. `db_store_product_find_by_token`
 *      resolves a token to a product with `ORDER BY id LIMIT 1`, so two
 *      ACTIVE products sharing a token id would serve the lower id's file for
 *      both — a buyer of the expensive one would receive the cheap one's
 *      bytes. The store surface still has that ambiguity for rows written by
 *      other paths; this writer will not create it.
 *   3. Attaching a file is all-or-nothing. The JSON loader treats an
 *      unreadable/oversized `content_path` as best-effort and lists the
 *      product without a payload; a merchant who asked for a file and got a
 *      product that cannot deliver one has been lied to, so here the whole
 *      command fails and nothing is written.
 *
 * The content hash is SHA3-256 of the FILE BYTES (db_store_blob_put hashes
 * the buffer it stores, and db_store_blob_find re-hashes on read), never of
 * the path or the size.
 *
 * The store's own HTTP surface opens `<datadir>/node.db` per request
 * (store_handle_request → node_db_open_runtime), so a product committed here
 * is visible to /store on the very next request with no node restart. These
 * handlers open the same file the same way, which also means the command
 * works against a stopped node's datadir.
 *
 * Bound by engine/composition/commands/app_features.def. */

#include "kernel/command_registry.h"
#include "command/native_command.h"
#include "controllers/native_handler_body.h"
#include "core/amount.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "models/database.h"
#include "models/model_text.h"
#include "models/store.h"
#include "models/store_blob.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <math.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Bound on how many products `app.store.products` returns. The reply rides
 * ZCL_COMMAND_LIST_BUDGET (8 KiB), so the practical limit is the budget, not
 * this number; it exists so the stack array is fixed. */
#define SN_PRODUCT_LIST_MAX 64

/* A token id is echoed verbatim into `/store/access?token=...` and into the
 * ZSLP balance lookup behind the download gate, so keep it to the character
 * set that survives both without quoting: A-Z, 0-9, '-', '_' (the model
 * upcases it before storing). */
static bool sn_token_charset_ok(const char *s)
{
    if (!s || !s[0])
        return false;   // raw-return-ok:caller-reports-BAD_TOKEN_ID
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        bool ok = (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
                  *p == '-' || *p == '_';
        if (!ok)
            return false;   // raw-return-ok:caller-reports-BAD_TOKEN_ID
    }
    return true;
}

/* Uniform failure body — same shape as account_controller.c's acc_fail(). */
static void sn_fail(struct zcl_command_reply *reply,
                    enum zcl_command_exit exit_code, const char *code,
                    const char *message, const char *evidence)
{
    enum zcl_command_status status =
        exit_code == ZCL_COMMAND_EXIT_BLOCKED ? ZCL_COMMAND_STATUS_BLOCKED
                                              : ZCL_COMMAND_STATUS_FAILED;
    zcl_command_reply_fail(reply, status, exit_code, code, "handle",
                           false, false, message, evidence ? evidence : "");
}

/* Explicit input.datadir wins, else the CLI's --datadir. NULL when neither
 * is set. */
static const char *sn_datadir(const struct zcl_command_request *request)
{
    const char *dd = json_get_str(json_get(request->input, "datadir"));
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

/* Open `<datadir>/node.db` for a read/write store operation.
 *
 * The file must already EXIST: node_db_open_runtime would happily create and
 * migrate a fresh database, which on a mistyped datadir would leave an empty
 * node.db somewhere and report success for a listing no store will ever
 * serve. A missing file is reported as STORE_NOT_INITIALISED instead.
 *
 * On failure the reply is already filled and false is returned. On success
 * the caller owns `ndb` and must node_db_close() it. */
static bool sn_open_db(const char *datadir, struct zcl_command_reply *reply,
                       struct node_db *ndb, const char *reason)
{
    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/node.db", datadir);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        sn_fail(reply, ZCL_COMMAND_EXIT_INVALID, "DATADIR_PATH_TOO_LONG",
                "datadir path is too long to address node.db", datadir);
        return false;
    }
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        sn_fail(reply, ZCL_COMMAND_EXIT_BLOCKED, "STORE_NOT_INITIALISED",
                "no node.db at this datadir — boot the node once to create "
                "the store schema, or pass the right datadir", path);
        return false;
    }
    memset(ndb, 0, sizeof(*ndb));
    if (!node_db_open_runtime(ndb, path, reason)) {
        sn_fail(reply, ZCL_COMMAND_EXIT_BLOCKED, "STORE_NOT_INITIALISED",
                "node.db exists but could not be opened for the store", path);
        return false;
    }
    return true;
}

/* ── price parsing ──────────────────────────────────────────────────
 *
 * A price arrives as EITHER `price_zcl` (decimal ZCL) or `price_zatoshi`
 * (integer zatoshi), never both — two units for one field is exactly how a
 * "0.5" meant as ZCL gets stored as 0.5 zatoshi. Both accept a JSON number
 * or a numeric string; a string with any trailing text (a currency suffix
 * like "0.5 BTC", a stray unit) is refused rather than silently truncated by
 * strtod. */
enum sn_price_status {
    SN_PRICE_OK = 0,
    SN_PRICE_MISSING,
    SN_PRICE_CONFLICT,
    SN_PRICE_MALFORMED,
    SN_PRICE_OUT_OF_RANGE
};

/* Read a JSON number-or-numeric-string as a double. Returns false when the
 * value is not a number, not a fully-consumed numeric string, or not finite. */
static bool sn_real_of(const struct json_value *v, double *out)
{
    if (!v)
        return false;   // raw-return-ok:absent-optional-key
    if (v->type == JSON_INT) {
        *out = (double)json_get_int(v);
        return true;
    }
    if (v->type == JSON_REAL) {
        *out = json_get_real(v);
        return isfinite(*out);
    }
    if (v->type == JSON_STR) {
        const char *s = json_get_str(v);
        if (!s || !s[0])
            return false;   // raw-return-ok:empty-string-is-not-a-number
        char *end = NULL;
        errno = 0;
        double d = strtod(s, &end);
        if (errno != 0 || !end || *end != '\0' || !isfinite(d))
            return false;   // raw-return-ok:caller-reports-BAD_PRICE
        *out = d;
        return true;
    }
    return false;   // raw-return-ok:wrong-json-type
}

static enum sn_price_status sn_parse_price(const struct json_value *in,
                                           int64_t *out_zat)
{
    const struct json_value *zcl_v = json_get(in, "price_zcl");
    const struct json_value *zat_v = json_get(in, "price_zatoshi");

    if (zcl_v && zat_v)
        return SN_PRICE_CONFLICT;
    if (!zcl_v && !zat_v)
        return SN_PRICE_MISSING;

    double d = 0.0;
    if (!sn_real_of(zcl_v ? zcl_v : zat_v, &d))
        return SN_PRICE_MALFORMED;

    /* price_zatoshi must be a whole number of zatoshi; price_zcl converts. */
    double zat = zcl_v ? (d * (double)COIN) : d;
    if (zat_v && zat != floor(zat))
        return SN_PRICE_MALFORMED;
    /* Round to the nearest zatoshi so 0.07 ZCL does not land on 6999999
     * through binary floating point. */
    zat = floor(zat + 0.5);
    if (!(zat >= 1.0) || zat > (double)MAX_MONEY)
        return SN_PRICE_OUT_OF_RANGE;
    *out_zat = (int64_t)zat;
    return SN_PRICE_OK;
}

/* ── content payload ────────────────────────────────────────────────── */
enum sn_content_status {
    SN_CONTENT_NONE = 0,        /* no content_path given — a token-only product */
    SN_CONTENT_OK,
    SN_CONTENT_UNREADABLE,
    SN_CONTENT_EMPTY,
    SN_CONTENT_TOO_LARGE,
    SN_CONTENT_ALLOC
};

struct sn_content {
    uint8_t *bytes;
    size_t len;
};

/* Read the whole file at `path` into a caller-freed buffer, refusing an
 * unreadable, empty, or over-cap file. The cap is STORE_BLOB_INLINE_MAX: a
 * larger payload is stored fine but serve_gated_content cannot stream it (the
 * onion response buffer is 64 KiB) and falls back to an HTML description
 * page, so listing one would promise a download the store cannot deliver. */
static enum sn_content_status sn_read_content(const char *path,
                                              struct sn_content *out)
{
    out->bytes = NULL;
    out->len = 0;

    FILE *f = fopen(path, "rb");
    if (!f)
        return SN_CONTENT_UNREADABLE;

    uint8_t *buf = zcl_malloc(STORE_BLOB_INLINE_MAX, "store_list_content");
    if (!buf) {
        fclose(f);
        return SN_CONTENT_ALLOC;
    }
    size_t got = fread(buf, 1, STORE_BLOB_INLINE_MAX, f);
    int more = fgetc(f);        /* any byte past the cap ⇒ oversize */
    bool read_error = (ferror(f) != 0);
    fclose(f);

    if (read_error) {
        free(buf);
        return SN_CONTENT_UNREADABLE;
    }
    if (more != EOF) {
        free(buf);
        return SN_CONTENT_TOO_LARGE;
    }
    if (got == 0) {
        free(buf);
        return SN_CONTENT_EMPTY;
    }
    out->bytes = buf;
    out->len = got;
    return SN_CONTENT_OK;
}

/* ── rendering ──────────────────────────────────────────────────────── */
static void sn_render_product(struct json_value *into,
                              const struct db_store_product *p)
{
    (void)json_push_kv_int(into, "id", p->id);
    (void)json_push_kv_str(into, "name", p->name);
    (void)json_push_kv_str(into, "description", p->description);
    (void)json_push_kv_int(into, "price_zatoshi", p->price_zatoshi);
    (void)json_push_kv_real(into, "price_zcl",
                            (double)p->price_zatoshi / (double)COIN);
    (void)json_push_kv_str(into, "token_id", p->token_id);
    (void)json_push_kv_int(into, "tokens_per_purchase",
                           p->tokens_per_purchase);
    (void)json_push_kv_bool(into, "active", p->active);
    (void)json_push_kv_bool(into, "has_content", p->has_content);
    if (p->has_content) {
        char hex[2 * 32 + 1];
        HexStr(p->content_hash, sizeof(p->content_hash), false, hex,
               sizeof(hex));
        (void)json_push_kv_str(into, "content_hash", hex);
    }
}

/* ── app.store.list-product ─────────────────────────────────────────── */
void zcl_native_handle_store_list_product(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const struct json_value *in = request->input;

    /* name */
    const char *name_in = json_get_str(json_get(in, "name"));
    if (!name_in || !name_in[0]) {
        sn_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_NAME",
                "name is required", "name");
        return;
    }
    if (strlen(name_in) > STORE_PRODUCT_NAME_MAX) {
        sn_fail(reply, ZCL_COMMAND_EXIT_INVALID, "NAME_TOO_LONG",
                "name exceeds the 255-character product-name limit", "name");
        return;
    }

    /* token_id — the buyer-visible identity. `/store/access?token=X` resolves
     * a token to exactly one product, so this is the field a duplicate would
     * make ambiguous, and it is required here even though the model allows
     * it to be empty. */
    const char *token_in = json_get_str(json_get(in, "token_id"));
    if (!token_in || !token_in[0]) {
        sn_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_TOKEN_ID",
                "token_id is required — it is the id a buyer's "
                "/store/access request resolves to this product",
                "token_id");
        return;
    }
    char token_id[STORE_PRODUCT_TOKEN_MAX + 1];
    if (strlen(token_in) > STORE_PRODUCT_TOKEN_MAX) {
        sn_fail(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_TOKEN_ID",
                "token_id exceeds the 64-character limit", "token_id");
        return;
    }
    (void)snprintf(token_id, sizeof(token_id), "%s", token_in);
    /* Normalize exactly as the model's before_validate hook does, so the
     * duplicate check below tests the value that will actually be stored. */
    model_trim_ascii(token_id);
    model_ascii_upcase(token_id);
    if (!sn_token_charset_ok(token_id)) {
        sn_fail(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_TOKEN_ID",
                "token_id must be non-empty and use only letters, digits, "
                "'-' or '_' (it is upcased and used verbatim in "
                "/store/access?token=...)", token_in);
        return;
    }

    /* price */
    int64_t price_zat = 0;
    switch (sn_parse_price(in, &price_zat)) {
    case SN_PRICE_OK:
        break;
    case SN_PRICE_MISSING:
        sn_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_PRICE",
                "a price is required: pass price_zcl (decimal ZCL) or "
                "price_zatoshi (integer zatoshi)", "price_zcl");
        return;
    case SN_PRICE_CONFLICT:
        sn_fail(reply, ZCL_COMMAND_EXIT_INVALID, "PRICE_CONFLICT",
                "pass price_zcl or price_zatoshi, not both — one price, one "
                "unit", "price_zcl,price_zatoshi");
        return;
    case SN_PRICE_MALFORMED:
        sn_fail(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_PRICE",
                "price must be a plain number in the unit its key names: "
                "price_zcl accepts decimals, price_zatoshi whole zatoshi. No "
                "currency suffix or other trailing text is accepted.",
                "price");
        return;
    case SN_PRICE_OUT_OF_RANGE:
        sn_fail(reply, ZCL_COMMAND_EXIT_INVALID, "PRICE_OUT_OF_RANGE",
                "price must be at least 1 zatoshi and at most MAX_MONEY",
                "price");
        return;
    }

    /* tokens_per_purchase */
    int64_t tokens = json_get_int_or(in, "tokens_per_purchase", 1);
    if (tokens < 1 || tokens > 10000) {
        sn_fail(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_TOKENS_PER_PURCHASE",
                "tokens_per_purchase must be between 1 and 10000",
                "tokens_per_purchase");
        return;
    }

    /* description (optional) */
    const char *desc = json_get_str_or(in, "description", "");
    if (desc && strlen(desc) > STORE_PRODUCT_DESC_MAX) {
        sn_fail(reply, ZCL_COMMAND_EXIT_INVALID, "DESCRIPTION_TOO_LONG",
                "description exceeds the 1023-character limit", "description");
        return;
    }

    const char *datadir = sn_datadir(request);
    if (!datadir) {
        sn_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                "no datadir given and no --datadir default", "datadir");
        return;
    }

    /* content (optional, but all-or-nothing when asked for) — read BEFORE
     * opening the database so an unreadable file costs no write lock. */
    const char *content_path = json_get_str_or(in, "content_path", NULL);
    struct sn_content content = { .bytes = NULL, .len = 0 };
    if (content_path && content_path[0]) {
        switch (sn_read_content(content_path, &content)) {
        case SN_CONTENT_OK:
            break;
        case SN_CONTENT_UNREADABLE:
            sn_fail(reply, ZCL_COMMAND_EXIT_INVALID, "CONTENT_UNREADABLE",
                    "content_path could not be opened or read", content_path);
            return;
        case SN_CONTENT_EMPTY:
            sn_fail(reply, ZCL_COMMAND_EXIT_INVALID, "CONTENT_EMPTY",
                    "content_path is an empty file — there is nothing to "
                    "deliver to a buyer", content_path);
            return;
        case SN_CONTENT_TOO_LARGE: {
            char ev[128];
            (void)snprintf(ev, sizeof(ev),
                           "%s (cap %d bytes)", content_path,
                           STORE_BLOB_INLINE_MAX);
            sn_fail(reply, ZCL_COMMAND_EXIT_INVALID, "CONTENT_TOO_LARGE",
                    "content_path exceeds the inline-serve cap; the store "
                    "could not stream it to a buyer, so the product is "
                    "refused rather than listed undeliverable", ev);
            return;
        }
        case SN_CONTENT_ALLOC:
            sn_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "CONTENT_ALLOC_FAILED",
                    "could not allocate the content read buffer",
                    content_path);
            return;
        case SN_CONTENT_NONE:
        default:
            sn_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "CONTENT_UNKNOWN",
                    "content read returned an unexpected status",
                    content_path);
            return;
        }
    }

    struct node_db ndb;
    if (!sn_open_db(datadir, reply, &ndb, "store.list_product")) {
        free(content.bytes);
        return;
    }

    /* duplicate token id */
    struct db_store_product existing;
    if (db_store_product_find_by_token(&ndb, token_id, &existing)) {
        char ev[128];
        (void)snprintf(ev, sizeof(ev), "%s (product id %lld)", token_id,
                       (long long)existing.id);
        node_db_close(&ndb);
        free(content.bytes);
        sn_fail(reply, ZCL_COMMAND_EXIT_INVALID, "DUPLICATE_TOKEN_ID",
                "an active product already carries this token_id; a buyer's "
                "/store/access request could not tell the two apart", ev);
        return;
    }

    struct db_store_product product;
    memset(&product, 0, sizeof(product));
    (void)snprintf(product.name, sizeof(product.name), "%s", name_in);
    (void)snprintf(product.description, sizeof(product.description), "%s",
                   desc ? desc : "");
    (void)snprintf(product.token_id, sizeof(product.token_id), "%s", token_id);
    product.price_zatoshi = price_zat;
    product.tokens_per_purchase = (int)tokens;
    product.active = true;

    /* Store the bytes first: the blob is content-addressed and INSERT OR
     * IGNORE, so a blob with no product pointing at it is inert and a repeat
     * of the same file dedupes. Stamping the hash onto the product record
     * BEFORE the insert means the product row is never briefly visible to
     * /store without its payload. */
    if (content.bytes) {
        if (!db_store_blob_put(&ndb, content.bytes, content.len,
                               json_get_str_or(in, "content_type", NULL),
                               json_get_str_or(in, "content_filename", NULL),
                               product.content_hash)) {
            node_db_close(&ndb);
            free(content.bytes);
            sn_fail(reply, ZCL_COMMAND_EXIT_FAILED, "BLOB_STORE_FAILED",
                    "the file payload could not be stored", content_path);
            return;
        }
        product.has_content = true;
    }

    if (!db_store_product_save(&ndb, &product)) {
        node_db_close(&ndb);
        free(content.bytes);
        sn_fail(reply, ZCL_COMMAND_EXIT_FAILED, "SAVE_FAILED",
                "the product did not validate or persist", token_id);
        return;
    }
    int64_t product_id = sqlite3_last_insert_rowid(ndb.db);

    /* Read the row back so the reply describes what the store will serve,
     * not what the caller asked for. */
    struct db_store_product saved;
    bool reread = db_store_product_find_active(&ndb, product_id, &saved);
    node_db_close(&ndb);
    free(content.bytes);

    if (!reread) {
        sn_fail(reply, ZCL_COMMAND_EXIT_FAILED, "SAVE_UNCONFIRMED",
                "the product was written but could not be read back as an "
                "active product", token_id);
        return;
    }

    sn_render_product(&reply->data, &saved);
    if (saved.has_content)
        (void)json_push_kv_int(&reply->data, "content_bytes",
                               (int64_t)content.len);
    (void)json_push_kv_str(&reply->data, "datadir", datadir);
    reply->error.mutated = true;
}

/* ── app.store.products ─────────────────────────────────────────────── */
void zcl_native_handle_store_products(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *datadir = sn_datadir(request);
    if (!datadir) {
        sn_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                "no datadir given and no --datadir default", "datadir");
        return;
    }
    /* READ-ONLY, and not sn_open_db.
     *
     * This leaf is declared ZCL_COMMAND_READY_READ and its `datadir` falls
     * back to the CLI's resolved one — the operator's LIVE node when nobody
     * passed a path. It used to open through sn_open_db -> node_db_open_
     * runtime, which is SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE and then
     * runs create_schema() and node_db_migrate(). The stat() guard there
     * meant it would not MINT a node.db, but pointed at any real SQLite file
     * sitting at <datadir>/node.db it installed the node's 67 tables into it
     * and answered "returned": 0 — a listing command rewriting the schema of
     * a file it was only asked to read. Listing products needs SELECT and
     * nothing else, so it gets a handle that can do nothing else:
     * SQLITE_OPEN_READONLY plus PRAGMA query_only=ON, no CREATE, no schema,
     * no migrate. app.store.list-product is a declared writer and keeps
     * sn_open_db. See test_read_leaf_no_datadir_write.c. */
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!zcl_native_node_db_require_readonly(datadir, reply,
                                             "the store's product list",
                                             &db, &ndb))
        return;

    struct db_store_product rows[SN_PRODUCT_LIST_MAX];
    int n = db_store_product_list_active(&ndb, rows, SN_PRODUCT_LIST_MAX);

    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (int i = 0; i < n; i++) {
        /* db_store_product_list_active does not SELECT content_hash, so
         * re-find each row to report the payload truthfully rather than
         * reporting has_content=false for every product. Bounded by
         * SN_PRODUCT_LIST_MAX. */
        struct db_store_product full;
        if (!db_store_product_find_active(&ndb, rows[i].id, &full))
            full = rows[i];
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        sn_render_product(&item, &full);
        (void)json_push_back(&arr, &item);
        json_free(&item);
    }
    /* The read-only shim borrows the handle and owns no prepared statements,
     * so it is closed with its own closer, never node_db_close(). */
    zcl_native_node_db_close_readonly(&db, &ndb);

    (void)json_push_kv_int(&reply->data, "returned", n);
    (void)json_push_kv(&reply->data, "products", &arr);
    json_free(&arr);
    (void)json_push_kv_str(&reply->data, "datadir", datadir);
}
