/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Typed store listing: the merchant half of MVP criterion #5.
 *
 * Proves `app.store.list-product` / `app.store.products`
 * (engine/controllers/src/store_native_handlers.c) are a real, agent-drivable
 * writer of the SAME product record the storefront serves:
 *
 *   1. a listed product is visible to the /store surface with NO restart —
 *      the assertion runs store_handle_request() in the same process, right
 *      after the command returns
 *   2. the stored content hash is SHA3-256 of the FILE BYTES: the test hashes
 *      the file itself and compares, then loads the blob back through the
 *      model and compares the bytes one by one (a hash of the path or the
 *      size fails both halves)
 *   3. a duplicate token_id is refused, and refused WITHOUT writing — the
 *      product count is re-counted after the refusal
 *   4. an unreadable content_path is refused, likewise without writing
 *   5. price and initialisation failures come back as distinct typed codes,
 *      not one generic error
 *   6. the products.json loader still works on a datadir the command never
 *      touched, and app.store.products reads those rows back — one record,
 *      two writers
 *
 * No node, no network, no wallet: every case is an in-process call against a
 * fixture datadir under ./test-tmp. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "controllers/store_controller.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "models/database.h"
#include "models/store.h"
#include "models/store_blob.h"

#define SL_CHECK(name, expr) do {                                      \
    printf("store_listing: %s... ", (name));                           \
    if (expr) { printf("OK\n"); }                                      \
    else { printf("FAIL\n"); failures++; }                             \
} while (0)

/* The payload a buyer must eventually receive. It carries an embedded NUL and
 * high bytes so a hash taken over anything but the real bytes cannot match by
 * accident. */
static const uint8_t SL_FILE[] = {
    'f','i','e','l','d',' ','g','u','i','d','e', 0x00,
    0xC0, 0xFF, 0xEE, 0x01, 0x02, 0x03
};

/* ── fixture ──────────────────────────────────────────────────────── */

/* Create <dir> with a migrated node.db inside it. */
static bool sl_mk_datadir(char *dir, size_t dir_size, const char *tag)
{
    test_make_tmpdir(dir, dir_size, "store_listing", tag);
    char path[512];
    snprintf(path, sizeof(path), "%s/node.db", dir);
    struct node_db ndb;
    if (!node_db_open(&ndb, path))
        return false;
    node_db_close(&ndb);
    return true;
}

static bool sl_write_file(const char *path, const uint8_t *bytes, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    size_t w = len ? fwrite(bytes, 1, len, f) : 0;
    fclose(f);
    return w == len;
}

/* Run one handler and hand the reply back; the caller owns both. */
static void sl_call(void (*fn)(const struct zcl_command_request *,
                               struct zcl_command_reply *),
                    struct json_value *input,
                    struct zcl_command_reply *reply)
{
    struct zcl_command_request request = { .input = input };
    zcl_command_reply_init(reply, "zcl.test.v1");
    fn(&request, reply);
}

static void sl_input_open(struct json_value *input, const char *dir)
{
    json_init(input);
    json_set_object(input);
    if (dir)
        (void)json_push_kv_str(input, "datadir", dir);
}

static const char *sl_str(const struct zcl_command_reply *reply,
                          const char *key)
{
    const char *s = json_get_str(json_get(&reply->data, key));
    return s ? s : "";
}

/* Is there a node.db in this fixture at all? node_db_open_runtime CREATES
 * one, so the count helper below cannot answer this — it would manufacture
 * the very file the assertion is checking for. */
static bool sl_has_node_db(const char *dir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/node.db", dir);
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* Count every product row (active or not) in the fixture. Used to prove a
 * refusal wrote NOTHING, so the model's own counter is the witness rather
 * than the handler's word for it. */
static int sl_product_count(const char *dir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/node.db", dir);
    struct node_db ndb;
    if (!node_db_open_runtime(&ndb, path, "test.store_listing.count"))
        return -1;
    int n = db_store_product_count(&ndb);
    node_db_close(&ndb);
    return n;
}

/* Post one minimal, valid listing. `extra_key`/`extra_str` optionally add a
 * single string field (used for content_path). */
static void sl_list_product(const char *dir, const char *name,
                            const char *token, double price_zcl,
                            const char *extra_key, const char *extra_str,
                            struct zcl_command_reply *reply)
{
    struct json_value input;
    sl_input_open(&input, dir);
    (void)json_push_kv_str(&input, "name", name);
    (void)json_push_kv_str(&input, "token_id", token);
    (void)json_push_kv_real(&input, "price_zcl", price_zcl);
    if (extra_key && extra_str)
        (void)json_push_kv_str(&input, extra_key, extra_str);
    sl_call(zcl_native_handle_store_list_product, &input, reply);
    json_free(&input);
}

/* ── (1) list a product with a file, and see it on /store ─────────── */

static int t_list_and_serve(void)
{
    int failures = 0;
    char dir[256];
    SL_CHECK("fixture datadir", sl_mk_datadir(dir, sizeof(dir), "serve"));

    char file[512];
    snprintf(file, sizeof(file), "%s/guide.bin", dir);
    SL_CHECK("fixture payload file",
             sl_write_file(file, SL_FILE, sizeof(SL_FILE)));

    struct json_value input;
    struct zcl_command_reply reply;
    sl_input_open(&input, dir);
    (void)json_push_kv_str(&input, "name", "Field Guide");
    (void)json_push_kv_str(&input, "description", "A short field guide.");
    (void)json_push_kv_str(&input, "token_id", "guide");   /* lowercase in */
    (void)json_push_kv_real(&input, "price_zcl", 0.25);
    (void)json_push_kv_int(&input, "tokens_per_purchase", 2);
    (void)json_push_kv_str(&input, "content_path", file);
    (void)json_push_kv_str(&input, "content_type", "engine/application/octet-stream");
    (void)json_push_kv_str(&input, "content_filename", "guide.bin");
    sl_call(zcl_native_handle_store_list_product, &input, &reply);
    json_free(&input);

    SL_CHECK("list-product: exit OK", reply.exit_code == ZCL_COMMAND_EXIT_OK);
    SL_CHECK("list-product: reports a mutation", reply.error.mutated);
    int64_t product_id = json_get_int(json_get(&reply.data, "id"));
    SL_CHECK("list-product: assigned a product id", product_id > 0);
    SL_CHECK("list-product: token_id upcased",
             strcmp(sl_str(&reply, "token_id"), "GUIDE") == 0);
    SL_CHECK("list-product: price converted to zatoshi",
             json_get_int(json_get(&reply.data, "price_zatoshi")) == 25000000);
    SL_CHECK("list-product: tokens_per_purchase echoed from the row",
             json_get_int(json_get(&reply.data,
                                   "tokens_per_purchase")) == 2);
    SL_CHECK("list-product: has_content",
             json_get_bool(json_get(&reply.data, "has_content")));
    SL_CHECK("list-product: content_bytes is the real file size",
             json_get_int(json_get(&reply.data, "content_bytes")) ==
                 (int64_t)sizeof(SL_FILE));

    /* The content hash must be SHA3-256 of the FILE BYTES. Hash the payload
     * independently here; a hash of the path or of "path:size" cannot match. */
    uint8_t want[32];
    zcl_sha3_256(SL_FILE, sizeof(SL_FILE), want);
    char want_hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(want_hex + i * 2, 3, "%02x", want[i]);
    SL_CHECK("list-product: content_hash is SHA3-256 of the file bytes",
             strcmp(sl_str(&reply, "content_hash"), want_hex) == 0);
    zcl_command_reply_free(&reply);

    /* THE no-restart assertion: the same process, no reboot, no
     * store_ensure_schema seeding — just the storefront's own request path. */
    uint8_t page[65536];
    size_t n = store_handle_request("GET", "/store", NULL, 0, page,
                                    sizeof(page), dir);
    page[n < sizeof(page) ? n : sizeof(page) - 1] = '\0';
    SL_CHECK("store surface: serves a page", n > 0);
    SL_CHECK("store surface: the listed product is visible with no restart",
             strstr((char *)page, "Field Guide") != NULL);
    /* store_ensure_schema seeds three demo products only into an EMPTY
     * products table; the listing must have pre-empted that. */
    SL_CHECK("store surface: demo seed did not run over the listing",
             strstr((char *)page, "ZCL23 Access Token") == NULL);

    /* The payload the storefront would deliver, resolved the way the gated
     * download does: token -> product -> blob. */
    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/node.db", dir);
    struct node_db ndb;
    bool opened = node_db_open_runtime(&ndb, db_path, "test.store_listing");
    SL_CHECK("blob check: reopened node.db", opened);
    if (opened) {
        struct db_store_product byname;
        bool found = db_store_product_find_by_token(&ndb, "GUIDE", &byname);
        SL_CHECK("blob check: token resolves to the product", found);
        SL_CHECK("blob check: product carries content", found &&
                 byname.has_content);
        struct db_store_blob blob;
        memset(&blob, 0, sizeof(blob));
        bool got = found && byname.has_content &&
                   db_store_blob_find(&ndb, byname.content_hash, &blob);
        SL_CHECK("blob check: blob loads under its content hash", got);
        SL_CHECK("blob check: stored bytes are byte-exact",
                 got && blob.data_len == sizeof(SL_FILE) &&
                 memcmp(blob.data, SL_FILE, sizeof(SL_FILE)) == 0);
        SL_CHECK("blob check: filename round-tripped",
                 got && strcmp(blob.filename, "guide.bin") == 0);
        db_store_blob_free(&blob);
        node_db_close(&ndb);
    }

    /* app.store.products reads the same row back. */
    struct json_value pin;
    struct zcl_command_reply preply;
    sl_input_open(&pin, dir);
    sl_call(zcl_native_handle_store_products, &pin, &preply);
    json_free(&pin);
    SL_CHECK("products: exit OK", preply.exit_code == ZCL_COMMAND_EXIT_OK);
    SL_CHECK("products: exactly the one listed product",
             json_get_int(json_get(&preply.data, "returned")) == 1);
    const struct json_value *arr = json_get(&preply.data, "products");
    const struct json_value *first = arr ? json_at(arr, 0) : NULL;
    SL_CHECK("products: name matches",
             first && json_get_str(json_get(first, "name")) &&
             strcmp(json_get_str(json_get(first, "name")),
                    "Field Guide") == 0);
    SL_CHECK("products: reports the attached payload",
             first && json_get_bool(json_get(first, "has_content")));
    zcl_command_reply_free(&preply);

    test_rm_rf(dir);
    return failures;
}

/* ── (2) refusals write nothing ───────────────────────────────────── */

static int t_refusals(void)
{
    int failures = 0;
    char dir[256];
    SL_CHECK("refusal fixture datadir",
             sl_mk_datadir(dir, sizeof(dir), "refuse"));

    struct zcl_command_reply reply;

    /* Seed one real product so the duplicate case has something to collide
     * with (and so the count baseline is non-zero). */
    sl_list_product(dir, "First", "DUPE", 0.5, NULL, NULL, &reply);
    SL_CHECK("refusal fixture: seed listing succeeded",
             reply.exit_code == ZCL_COMMAND_EXIT_OK);
    zcl_command_reply_free(&reply);
    int baseline = sl_product_count(dir);
    SL_CHECK("refusal fixture: one product on record", baseline == 1);

    /* duplicate token id */
    sl_list_product(dir, "Second", "dupe", 1.0, NULL, NULL, &reply);
    SL_CHECK("duplicate token: refused",
             reply.exit_code != ZCL_COMMAND_EXIT_OK);
    SL_CHECK("duplicate token: typed DUPLICATE_TOKEN_ID",
             strcmp(reply.error.code, "DUPLICATE_TOKEN_ID") == 0);
    SL_CHECK("duplicate token: names the colliding product",
             strstr(reply.error.evidence, "DUPE") != NULL);
    zcl_command_reply_free(&reply);
    SL_CHECK("duplicate token: wrote nothing",
             sl_product_count(dir) == baseline);

    /* unreadable content_path */
    char missing[512];
    snprintf(missing, sizeof(missing), "%s/not-here.bin", dir);
    sl_list_product(dir, "Ghost", "GHOST", 0.5, "content_path", missing,
                    &reply);
    SL_CHECK("unreadable content: refused",
             reply.exit_code != ZCL_COMMAND_EXIT_OK);
    SL_CHECK("unreadable content: typed CONTENT_UNREADABLE",
             strcmp(reply.error.code, "CONTENT_UNREADABLE") == 0);
    zcl_command_reply_free(&reply);
    SL_CHECK("unreadable content: wrote nothing",
             sl_product_count(dir) == baseline);

    /* empty file */
    char empty[512];
    snprintf(empty, sizeof(empty), "%s/empty.bin", dir);
    SL_CHECK("empty-file fixture", sl_write_file(empty, NULL, 0));
    sl_list_product(dir, "Nothing", "EMPTYP", 0.5, "content_path", empty,
                    &reply);
    SL_CHECK("empty content: typed CONTENT_EMPTY",
             strcmp(reply.error.code, "CONTENT_EMPTY") == 0);
    zcl_command_reply_free(&reply);

    /* over the inline-serve cap */
    char big_path[512];
    snprintf(big_path, sizeof(big_path), "%s/big.bin", dir);
    size_t big_len = (size_t)STORE_BLOB_INLINE_MAX + 1;
    uint8_t *big = malloc(big_len);
    SL_CHECK("oversize fixture: alloc", big != NULL);
    if (big) {
        memset(big, 'x', big_len);
        SL_CHECK("oversize fixture: written",
                 sl_write_file(big_path, big, big_len));
        free(big);
        sl_list_product(dir, "Too Big", "TOOBIG", 0.5, "content_path",
                        big_path, &reply);
        SL_CHECK("oversize content: typed CONTENT_TOO_LARGE",
                 strcmp(reply.error.code, "CONTENT_TOO_LARGE") == 0);
        zcl_command_reply_free(&reply);
    }
    SL_CHECK("content refusals: still wrote nothing",
             sl_product_count(dir) == baseline);

    test_rm_rf(dir);
    return failures;
}

/* ── (3) typed input errors ───────────────────────────────────────── */

static int t_input_errors(void)
{
    int failures = 0;
    char dir[256];
    SL_CHECK("input-error fixture datadir",
             sl_mk_datadir(dir, sizeof(dir), "input"));

    struct json_value input;
    struct zcl_command_reply reply;

    /* no price at all */
    sl_input_open(&input, dir);
    (void)json_push_kv_str(&input, "name", "Priceless");
    (void)json_push_kv_str(&input, "token_id", "NOPRICE");
    sl_call(zcl_native_handle_store_list_product, &input, &reply);
    json_free(&input);
    SL_CHECK("no price: typed MISSING_PRICE",
             strcmp(reply.error.code, "MISSING_PRICE") == 0);
    zcl_command_reply_free(&reply);

    /* both units at once */
    sl_input_open(&input, dir);
    (void)json_push_kv_str(&input, "name", "Two Units");
    (void)json_push_kv_str(&input, "token_id", "TWOUNIT");
    (void)json_push_kv_real(&input, "price_zcl", 0.5);
    (void)json_push_kv_int(&input, "price_zatoshi", 50000000);
    sl_call(zcl_native_handle_store_list_product, &input, &reply);
    json_free(&input);
    SL_CHECK("two price units: typed PRICE_CONFLICT",
             strcmp(reply.error.code, "PRICE_CONFLICT") == 0);
    zcl_command_reply_free(&reply);

    /* a price carrying a currency, i.e. the wrong unit spelled out */
    sl_input_open(&input, dir);
    (void)json_push_kv_str(&input, "name", "Wrong Currency");
    (void)json_push_kv_str(&input, "token_id", "WRONGCUR");
    (void)json_push_kv_str(&input, "price_zcl", "0.5 BTC");
    sl_call(zcl_native_handle_store_list_product, &input, &reply);
    json_free(&input);
    SL_CHECK("currency suffix: typed BAD_PRICE",
             strcmp(reply.error.code, "BAD_PRICE") == 0);
    zcl_command_reply_free(&reply);

    /* zero / negative */
    sl_input_open(&input, dir);
    (void)json_push_kv_str(&input, "name", "Free");
    (void)json_push_kv_str(&input, "token_id", "FREE");
    (void)json_push_kv_real(&input, "price_zcl", 0.0);
    sl_call(zcl_native_handle_store_list_product, &input, &reply);
    json_free(&input);
    SL_CHECK("zero price: typed PRICE_OUT_OF_RANGE",
             strcmp(reply.error.code, "PRICE_OUT_OF_RANGE") == 0);
    zcl_command_reply_free(&reply);

    /* missing name / token */
    sl_input_open(&input, dir);
    (void)json_push_kv_str(&input, "token_id", "NONAME");
    (void)json_push_kv_real(&input, "price_zcl", 0.5);
    sl_call(zcl_native_handle_store_list_product, &input, &reply);
    json_free(&input);
    SL_CHECK("no name: typed MISSING_NAME",
             strcmp(reply.error.code, "MISSING_NAME") == 0);
    zcl_command_reply_free(&reply);

    sl_input_open(&input, dir);
    (void)json_push_kv_str(&input, "name", "Tokenless");
    (void)json_push_kv_real(&input, "price_zcl", 0.5);
    sl_call(zcl_native_handle_store_list_product, &input, &reply);
    json_free(&input);
    SL_CHECK("no token_id: typed MISSING_TOKEN_ID",
             strcmp(reply.error.code, "MISSING_TOKEN_ID") == 0);
    zcl_command_reply_free(&reply);

    /* a token id that would not survive a /store/access query string */
    sl_input_open(&input, dir);
    (void)json_push_kv_str(&input, "name", "Spacey");
    (void)json_push_kv_str(&input, "token_id", "BAD TOKEN&x");
    (void)json_push_kv_real(&input, "price_zcl", 0.5);
    sl_call(zcl_native_handle_store_list_product, &input, &reply);
    json_free(&input);
    SL_CHECK("bad token charset: typed BAD_TOKEN_ID",
             strcmp(reply.error.code, "BAD_TOKEN_ID") == 0);
    zcl_command_reply_free(&reply);

    /* tokens_per_purchase out of range */
    sl_input_open(&input, dir);
    (void)json_push_kv_str(&input, "name", "Too Many");
    (void)json_push_kv_str(&input, "token_id", "TOOMANY");
    (void)json_push_kv_real(&input, "price_zcl", 0.5);
    (void)json_push_kv_int(&input, "tokens_per_purchase", 999999);
    sl_call(zcl_native_handle_store_list_product, &input, &reply);
    json_free(&input);
    SL_CHECK("tokens_per_purchase: typed BAD_TOKENS_PER_PURCHASE",
             strcmp(reply.error.code, "BAD_TOKENS_PER_PURCHASE") == 0);
    zcl_command_reply_free(&reply);

    SL_CHECK("input errors: nothing was written", sl_product_count(dir) == 0);

    /* price_zatoshi is the exact-unit path and must accept a whole number */
    sl_input_open(&input, dir);
    (void)json_push_kv_str(&input, "name", "Exact");
    (void)json_push_kv_str(&input, "token_id", "EXACT");
    (void)json_push_kv_int(&input, "price_zatoshi", 1234567);
    sl_call(zcl_native_handle_store_list_product, &input, &reply);
    json_free(&input);
    SL_CHECK("price_zatoshi: accepted",
             reply.exit_code == ZCL_COMMAND_EXIT_OK);
    SL_CHECK("price_zatoshi: stored verbatim",
             json_get_int(json_get(&reply.data, "price_zatoshi")) == 1234567);
    /* No description was supplied. db_store_product_validate used to reject
     * that as "contains non-printable characters" (an empty string is not
     * printable), which silently dropped products.json rows with no
     * description too — see the empty-string escape in store.c. */
    SL_CHECK("no description: a product lists without one",
             strcmp(sl_str(&reply, "description"), "") == 0);
    zcl_command_reply_free(&reply);

    test_rm_rf(dir);

    /* store not initialised: a directory with no node.db in it */
    char bare[256];
    test_make_tmpdir(bare, sizeof(bare), "store_listing", "bare");
    SL_CHECK("bare fixture: starts with no node.db", !sl_has_node_db(bare));
    sl_list_product(bare, "Orphan", "ORPHAN", 0.5, NULL, NULL, &reply);
    SL_CHECK("no node.db: typed STORE_NOT_INITIALISED",
             strcmp(reply.error.code, "STORE_NOT_INITIALISED") == 0);
    SL_CHECK("no node.db: BLOCKED, not a plain failure",
             reply.exit_code == ZCL_COMMAND_EXIT_BLOCKED);
    zcl_command_reply_free(&reply);
    SL_CHECK("no node.db: the command did not create one",
             !sl_has_node_db(bare));
    test_rm_rf(bare);

    /* no datadir at all */
    struct json_value nodd;
    json_init(&nodd);
    json_set_object(&nodd);
    (void)json_push_kv_str(&nodd, "name", "Nowhere");
    (void)json_push_kv_str(&nodd, "token_id", "NOWHERE");
    (void)json_push_kv_real(&nodd, "price_zcl", 0.5);
    sl_call(zcl_native_handle_store_list_product, &nodd, &reply);
    json_free(&nodd);
    /* zcl_native_command_datadir() is empty in the test process, so this is
     * the no-default branch; if a default were ever set, the command would
     * legitimately reach the DB instead. */
    SL_CHECK("no datadir: typed MISSING_DATADIR or a store-level refusal",
             strcmp(reply.error.code, "MISSING_DATADIR") == 0 ||
             strcmp(reply.error.code, "STORE_NOT_INITIALISED") == 0);
    zcl_command_reply_free(&reply);

    return failures;
}

/* ── (4) the products.json path still works ──────────────────────── */

static int t_json_path_still_works(void)
{
    int failures = 0;
    char dir[256];
    SL_CHECK("json fixture datadir", sl_mk_datadir(dir, sizeof(dir), "json"));

    char store_dir[512];
    snprintf(store_dir, sizeof(store_dir), "%s/store", dir);
    mkdir(store_dir, 0755);
    char json_path[600];
    snprintf(json_path, sizeof(json_path), "%s/products.json", store_dir);
    FILE *f = fopen(json_path, "w");
    SL_CHECK("json fixture: products.json created", f != NULL);
    if (f) {
        fprintf(f, "[{\"name\":\"Legacy JSON Product\","
                   "\"description\":\"Dropped in as a file\","
                   "\"price_zcl\":0.75,"
                   "\"token_id\":\"LEGACYJSON\","
                   "\"tokens_per_purchase\":4}]");
        fclose(f);
    }

    /* The loader fires on the first /store request against an empty products
     * table — unchanged by this lane. */
    uint8_t page[65536];
    size_t n = store_handle_request("GET", "/store", NULL, 0, page,
                                    sizeof(page), dir);
    page[n < sizeof(page) ? n : sizeof(page) - 1] = '\0';
    SL_CHECK("json path: product reaches the storefront",
             n > 0 && strstr((char *)page, "Legacy JSON Product") != NULL);

    /* And the typed read sees exactly the same record — one product shape,
     * two writers. */
    struct json_value pin;
    struct zcl_command_reply reply;
    sl_input_open(&pin, dir);
    sl_call(zcl_native_handle_store_products, &pin, &reply);
    json_free(&pin);
    SL_CHECK("json path: products read OK",
             reply.exit_code == ZCL_COMMAND_EXIT_OK);
    const struct json_value *arr = json_get(&reply.data, "products");
    const struct json_value *first = arr ? json_at(arr, 0) : NULL;
    SL_CHECK("json path: typed read reports the JSON-loaded product",
             first && json_get_str(json_get(first, "name")) &&
             strcmp(json_get_str(json_get(first, "name")),
                    "Legacy JSON Product") == 0);
    SL_CHECK("json path: token_id upcased by the same model hook",
             first && json_get_str(json_get(first, "token_id")) &&
             strcmp(json_get_str(json_get(first, "token_id")),
                    "LEGACYJSON") == 0);
    zcl_command_reply_free(&reply);

    /* The typed writer can then add to a JSON-seeded store. */
    struct zcl_command_reply add;
    sl_list_product(dir, "Added By Command", "ADDEDCMD", 0.1, NULL, NULL,
                    &add);
    SL_CHECK("json path: typed listing joins the JSON-seeded catalog",
             add.exit_code == ZCL_COMMAND_EXIT_OK);
    zcl_command_reply_free(&add);
    SL_CHECK("json path: both products on record", sl_product_count(dir) == 2);

    unlink(json_path);
    rmdir(store_dir);
    test_rm_rf(dir);
    return failures;
}

int test_store_listing(void)
{
    int failures = 0;
    printf("\n=== Store listing (typed merchant surface) ===\n");
    failures += t_list_and_serve();
    failures += t_refusals();
    failures += t_input_errors();
    failures += t_json_path_still_works();
    printf("Store listing: %d failures\n", failures);
    return failures;
}
