/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Store SQLite schema bootstrap and default product seeding. */

#include "controllers/store_controller_internal.h"
#include "models/store_blob.h"
#include "util/safe_alloc.h"

/* Attach a file payload to a just-saved product from a `content_path`
 * (a filesystem path under the operator's control, e.g. referenced from
 * products.json). Reads up to STORE_BLOB_INLINE_MAX bytes, stores them as
 * a content-addressed blob, and stamps products.content_hash. Best-effort:
 * a missing/oversized file logs a warning and leaves the product without a
 * payload (it still serves the HTML access page). */
static void store_attach_content_from_path(struct node_db *ndb,
                                            int64_t product_id,
                                            const char *content_path,
                                            const char *content_type,
                                            const char *filename)
{
    if (!ndb || !ndb->open || product_id <= 0 ||
        !content_path || !content_path[0])
        return;

    FILE *cf = fopen(content_path, "rb");
    if (!cf) {
        LOG_WARN("store", "content_path not readable: %s", content_path);
        return;
    }
    uint8_t *buf = zcl_malloc(STORE_BLOB_INLINE_MAX, "store_content");
    if (!buf) {
        fclose(cf);
        return;
    }
    size_t got = fread(buf, 1, STORE_BLOB_INLINE_MAX, cf);
    int more = fgetc(cf);   /* detect oversize: any byte past the cap */
    fclose(cf);
    if (got == 0 || more != EOF) {
        if (more != EOF)
            LOG_WARN("store", "content_path exceeds inline cap %d: %s",
                     STORE_BLOB_INLINE_MAX, content_path);
        free(buf);
        return;
    }

    uint8_t hash[32];
    if (db_store_blob_put(ndb, buf, got,
                          content_type && content_type[0] ? content_type : NULL,
                          filename && filename[0] ? filename : NULL, hash)) {
        if (db_store_product_save_content(ndb, product_id, hash))
            printf("Store: attached %zu-byte payload to product %lld\n",
                   got, (long long)product_id);
    }
    free(buf);
}

/* Extract a quoted JSON string value for `key` (the key including its
 * quotes, e.g. "\"name\"") from the object slice [p, end). Bounded: never
 * scans past `end`, so a key that only appears in a later object cannot
 * leak that object's value into this one. On success copies the value
 * into `out` (NUL-terminated) and returns true; on any miss (key absent
 * in the slice, quotes malformed, value >= cap) leaves `out` empty and
 * returns false. */
static bool extract_str_field(const char *p, const char *end,
                              const char *key, char *out, size_t cap)
{
    if (cap == 0)
        return false;
    out[0] = '\0';
    const char *q = strstr(p, key);
    if (!q || q >= end)
        return false;
    q += strlen(key);
    while (q < end && *q != '"')    /* opening quote of the value */
        q++;
    if (q >= end)
        return false;
    q++;
    const char *e = q;
    while (e < end && *e != '"')    /* closing quote of the value */
        e++;
    if (e >= end || (size_t)(e - q) >= cap)
        return false;
    memcpy(out, q, (size_t)(e - q));
    out[e - q] = '\0';
    return true;
}

/* Ensure store tables exist */
void store_ensure_schema(sqlite3 *db, const char *datadir)
{
    /* Load products from {datadir}/store/products.json if it exists,
     * otherwise seed with demo products. This lets node operators
     * customize their store by editing a simple JSON file. */
    struct node_db cnt_ndb = { .db = db, .open = true };
    bool empty = (db_store_product_count(&cnt_ndb) == 0);

    if (empty && datadir) {
        char json_path[1024];
        snprintf(json_path, sizeof(json_path), "%s/store/products.json", datadir);
        FILE *f = fopen(json_path, "r");
        if (f) {
            /* Parse simple JSON array of products:
             * [{"name":"...","description":"...","price_zcl":0.01,
             *   "token_id":"...","tokens_per_purchase":1}, ...] */
            char buf[16384];
            size_t len = fread(buf, 1, sizeof(buf) - 1, f);
            buf[len] = '\0';
            fclose(f);

            /* Simple JSON array parser — find each {...} object */
            const char *p = buf;
            int loaded = 0;
            while ((p = strchr(p, '{')) != NULL) {
                const char *end = strchr(p, '}');
                if (!end) break;

                /* Extract fields with simple string search */
                /* token[65]: the canonical token key is a 64-hex-char txid;
                 * extract_str_field refuses values that do not fit +NUL, so
                 * token[64] silently DROPPED a full-txid token_id here and
                 * the product loaded unbound. */
                char name[256] = "", desc[1024] = "", token[65] = "";
                char content_path[1024] = "", content_type[128] = "";
                char content_filename[256] = "";
                double price_zcl = 0.0;
                int tokens = 1;

                extract_str_field(p, end, "\"name\"", name, sizeof(name));
                extract_str_field(p, end, "\"description\"",
                                  desc, sizeof(desc));
                extract_str_field(p, end, "\"token_id\"",
                                  token, sizeof(token));
                /* price_zcl */
                const char *q = strstr(p, "\"price_zcl\"");
                if (q && q < end) {
                    q += 11; while (*q == ':' || *q == ' ') q++;
                    price_zcl = strtod(q, NULL);
                }
                /* tokens_per_purchase */
                q = strstr(p, "\"tokens_per_purchase\"");
                if (q && q < end) {
                    q += 20; while (*q == ':' || *q == ' ') q++;
                    long tval = strtol(q, NULL, 10);
                    tokens = (tval > 0 && tval <= 10000) ? (int)tval : 1;
                }
                /* Optional file payload: path, MIME type, download name */
                extract_str_field(p, end, "\"content_path\"",
                                  content_path, sizeof(content_path));
                extract_str_field(p, end, "\"content_type\"",
                                  content_type, sizeof(content_type));
                extract_str_field(p, end, "\"content_filename\"",
                                  content_filename, sizeof(content_filename));

                if (name[0] && price_zcl > 0) {
                    struct node_db ndb;
                    struct db_store_product product;
                    memset(&ndb, 0, sizeof(ndb));
                    ndb.db = db;
                    ndb.open = true;
                    memset(&product, 0, sizeof(product));
                    snprintf(product.name, sizeof(product.name), "%s", name);
                    snprintf(product.description, sizeof(product.description), "%s", desc);
                    snprintf(product.token_id, sizeof(product.token_id), "%s", token);
                    product.price_zatoshi =
                        (int64_t)(price_zcl * (double)ZATOSHI_PER_ZCL);
                    product.tokens_per_purchase = tokens;
                    product.active = true;
                    if (!db_store_product_save(&ndb, &product)) {
                        p = end + 1;
                        continue;
                    }
                    if (content_path[0]) {
                        int64_t pid = sqlite3_last_insert_rowid(db);
                        store_attach_content_from_path(&ndb, pid, content_path,
                                                       content_type,
                                                       content_filename);
                    }
                    loaded++;
                }
                p = end + 1;
            }
            if (loaded > 0)
                printf("Store: loaded %d products from %s\n", loaded, json_path);
            else
                printf("Store: %s exists but no valid products found\n", json_path);
            fflush(stdout);
            empty = (loaded == 0);
        }
    }

    /* Fallback: seed demo products if still empty */
    if (empty) {
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        ndb.db = db;
        ndb.open = true;
        struct db_store_product products[] = {
            {
                .name = "ZCL23 Access Token",
                .description =
                    "1 token grants access to premium .onion services on the "
                    "Z23 network. Tokens are ZSLP tokens on the ZClassic "
                    "blockchain.",
                .price_zatoshi = 1000000,
                .token_id = "ZCL23ACCESS",
                .tokens_per_purchase = 10,
                .active = true
            },
            {
                .name = "VPN Credit (1 month)",
                .description =
                    "Route traffic through the Z23 onion network. "
                    "1 month of encrypted relay service.",
                .price_zatoshi = 5000000,
                .token_id = "ZCL23VPN",
                .tokens_per_purchase = 1,
                .active = true
            },
            {
                .name = "Storage (1 GB)",
                .description =
                    "Encrypted storage on the Z23 distributed network. "
                    "Data replicated across multiple .onion nodes.",
                .price_zatoshi = 2000000,
                .token_id = "ZCL23STORE",
                .tokens_per_purchase = 1,
                .active = true
            }
        };
        for (size_t i = 0; i < sizeof(products) / sizeof(products[0]); i++) {
            /* Log-and-continue: a failed default-product seed must be
             * observable, but one bad seed should not abort store setup. */
            if (!db_store_product_save(&ndb, &products[i]))
                LOG_WARN("store", "default product seed failed: name=%s",
                         products[i].name);
        }
    }
}

/* Get the .onion address from the onion service layer (may be NULL). */
