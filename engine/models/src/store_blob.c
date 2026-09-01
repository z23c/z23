/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Store BLOB model — content-addressed product file payloads.
 * See models/store_blob.h for the contract.
 *
 * ar-validate-skip:content-addressed — this model stores opaque bytes
 * keyed by their own SHA3-256 hash. There are no user-supplied fields to
 * validate; integrity is enforced structurally (the content hash is the
 * primary key, and find() re-hashes and compares before returning bytes),
 * so the AR field-validation lifecycle does not apply. */

#include "models/store_blob.h"
#include "models/activerecord.h"
#include "crypto/sha3.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"
#include <string.h>

bool db_store_blob_put(struct node_db *ndb, const uint8_t *data, size_t len,
                       const char *content_type, const char *filename,
                       uint8_t out_hash[STORE_BLOB_HASH_LEN])
{
    sqlite3_stmt *s = NULL;
    uint8_t hash[STORE_BLOB_HASH_LEN];
    const char *ctype;

    if (!ndb || !ndb->open || !data || len == 0 || !out_hash)
        LOG_FAIL("store_blob", "put: bad args (len=%zu)", len);

    ctype = (content_type && content_type[0]) ? content_type
                                              : "engine/application/octet-stream";

    zcl_sha3_256(data, len, hash);

    AR_PREPARE_BOOL(ndb, s,
        "INSERT OR IGNORE INTO store_blobs "
        "(content_hash,content_type,filename,size_bytes,data) "
        "VALUES (?,?,?,?,?)");

    AR_BIND_BLOB(s, 1, hash, STORE_BLOB_HASH_LEN);
    AR_BIND_TEXT(s, 2, ctype);
    if (filename && filename[0])
        AR_BIND_TEXT(s, 3, filename);
    else
        AR_BIND_NULL(s, 3);
    AR_BIND_INT(s, 4, (int64_t)len);
    AR_BIND_BLOB(s, 5, data, len);

    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    if (!ok)
        LOG_FAIL("store_blob", "put: insert failed: %s",
                 sqlite3_errmsg(ndb->db));

    memcpy(out_hash, hash, STORE_BLOB_HASH_LEN);
    return true;
}

bool db_store_blob_find(struct node_db *ndb,
                        const uint8_t content_hash[STORE_BLOB_HASH_LEN],
                        struct db_store_blob *out)
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open || !content_hash || !out)
        LOG_FAIL("store_blob", "find: bad args");
    memset(out, 0, sizeof(*out));

    AR_PREPARE_BOOL(ndb, s,
        "SELECT content_hash,content_type,filename,size_bytes,data "
        "FROM store_blobs WHERE content_hash=?");

    AR_BIND_BLOB(s, 1, content_hash, STORE_BLOB_HASH_LEN);
    if (!AR_STEP_ROW(s)) {
        AR_FINALIZE(s);
        return false;   /* no such blob — not an error */
    }

    AR_READ_BLOB(s, 0, out->content_hash, STORE_BLOB_HASH_LEN);
    AR_READ_STR(s, 1, out->content_type, sizeof(out->content_type));
    AR_READ_STR(s, 2, out->filename, sizeof(out->filename));
    out->size_bytes = AR_COL_INT(s, 3);

    int blen = sqlite3_column_bytes(s, 4);
    const void *bdata = sqlite3_column_blob(s, 4);
    if (blen <= 0 || !bdata) {
        AR_FINALIZE(s);
        LOG_FAIL("store_blob", "find: empty data column");
    }

    uint8_t *buf = zcl_malloc((size_t)blen, "store_blob");
    if (!buf) {
        AR_FINALIZE(s);
        LOG_FAIL("store_blob", "find: alloc %d bytes failed", blen);
    }
    memcpy(buf, bdata, (size_t)blen);
    AR_FINALIZE(s);

    out->data = buf;
    out->data_len = (size_t)blen;

    /* Defence-in-depth: stored bytes must re-hash to the content key. */
    uint8_t check[STORE_BLOB_HASH_LEN];
    zcl_sha3_256(out->data, out->data_len, check);
    if (memcmp(check, content_hash, STORE_BLOB_HASH_LEN) != 0) {
        db_store_blob_free(out);
        LOG_FAIL("store_blob", "find: content hash mismatch (corruption)");
    }

    return true;
}

void db_store_blob_free(struct db_store_blob *b)
{
    if (!b)
        return;
    free(b->data);  /* zcl_malloc'd; free(NULL) is safe */
    b->data = NULL;
    b->data_len = 0;
}
