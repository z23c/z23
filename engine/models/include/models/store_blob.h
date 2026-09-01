/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Store BLOB model — content-addressed file payloads for products.
 *
 * A store product may attach a downloadable file. The bytes live in the
 * `store_blobs` table keyed by their SHA3-256 content hash (so identical
 * payloads dedupe), and `products.content_hash` references the blob. The
 * gated-download path (views/store_view.c serve_gated_content) resolves
 * a token id to its product, reads the product's content_hash, loads the
 * blob, and streams the real bytes to a customer who holds the token.
 *
 * Schema lives in migration v20 (engine/models/src/database_migrate.c). */

#ifndef ZCL_DB_MODEL_STORE_BLOB_H
#define ZCL_DB_MODEL_STORE_BLOB_H

#include "models/database.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define STORE_BLOB_HASH_LEN 32          /* SHA3-256 digest length */
#define STORE_BLOB_TYPE_MAX 127         /* MIME content-type, excl NUL */
#define STORE_BLOB_NAME_MAX 255         /* download filename, excl NUL */

/* Inline-serve cap on the live onion path. The dynhost webserver
 * allocates a fixed 64 KiB response buffer; a blob served inline over
 * .onion must fit under that minus HTTP headers. Blobs larger than this
 * are not truncated — serve_gated_content falls back to an honest HTML
 * page describing size + content hash instead of streaming bytes. */
#define STORE_BLOB_INLINE_MAX (60 * 1024)

struct db_store_blob {
    uint8_t  content_hash[STORE_BLOB_HASH_LEN];
    char     content_type[STORE_BLOB_TYPE_MAX + 1];
    char     filename[STORE_BLOB_NAME_MAX + 1];
    int64_t  size_bytes;
    uint8_t *data;        /* find() allocates; release via db_store_blob_free */
    size_t   data_len;
};

/* Hash `data[0..len)` with SHA3-256 and store it under that hash.
 * Idempotent: re-storing identical bytes is a no-op (INSERT OR IGNORE).
 * Writes the 32-byte content hash to out_hash on success. `content_type`
 * defaults to engine/application/octet-stream when NULL/empty; `filename` may be
 * NULL. Returns false on bad args or a DB error. */
bool db_store_blob_put(struct node_db *ndb, const uint8_t *data, size_t len,
                       const char *content_type, const char *filename,
                       uint8_t out_hash[STORE_BLOB_HASH_LEN]);

/* Load the blob stored under `content_hash`. On success allocates
 * out->data (caller must db_store_blob_free) and fills the metadata.
 * Re-hashes the loaded bytes and compares against content_hash as a
 * defence-in-depth corruption guard; returns false (and frees) on a
 * mismatch. Returns false if no such blob. */
bool db_store_blob_find(struct node_db *ndb,
                        const uint8_t content_hash[STORE_BLOB_HASH_LEN],
                        struct db_store_blob *out);

/* Release a blob loaded by db_store_blob_find. Safe on a zeroed/NULL
 * struct; clears data/data_len so double-free is benign. */
void db_store_blob_free(struct db_store_blob *b);

#endif /* ZCL_DB_MODEL_STORE_BLOB_H */
