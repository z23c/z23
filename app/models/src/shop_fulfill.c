/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Signed shop-fulfillment codec and schema-v67 ActiveRecord projection. */

#include "models/shop_fulfill.h"

#include "base/cleanse.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "models/review_state.h"
#include "sha3/sha3.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <string.h>
#include <limits.h>

DEFINE_MODEL_CALLBACKS(shop_fulfill)

static const uint8_t fulfill_magic[8] = {'Z','S','H','P','F','L','\r','\n'};

static bool fulfill_nonzero(const uint8_t *bytes, size_t len)
{
    uint8_t any = 0;
    if (!bytes) return false;
    for (size_t i = 0; i < len; i++) any |= bytes[i];
    return any != 0;
}

const char *shop_fulfill_error_string(enum shop_fulfill_error error)
{
    switch (error) {
    case SHOP_FULFILL_OK: return "ok";
    case SHOP_FULFILL_ERR_NULL: return "null-argument";
    case SHOP_FULFILL_ERR_VERSION: return "schema-version";
    case SHOP_FULFILL_ERR_WIRE_SIZE: return "wire-size";
    case SHOP_FULFILL_ERR_WIRE_MAGIC: return "wire-magic";
    case SHOP_FULFILL_ERR_WANT_ZERO: return "want-id-zero";
    case SHOP_FULFILL_ERR_PUBKEY_ZERO: return "pubkey-zero";
    case SHOP_FULFILL_ERR_NONCE: return "nonce-zero";
    case SHOP_FULFILL_ERR_ARTIFACT_ZERO: return "artifact-root-zero";
    case SHOP_FULFILL_ERR_CONTENT_ZERO: return "content-root-zero";
    case SHOP_FULFILL_ERR_TIME_ORDER: return "time-order-invalid";
    case SHOP_FULFILL_ERR_LIFETIME: return "lifetime-too-long";
    case SHOP_FULFILL_ERR_SIGNATURE: return "signature-invalid";
    case SHOP_FULFILL_ERR_KEY_MISMATCH: return "key-mismatch";
    }
    return "unknown";
}

enum shop_fulfill_error shop_fulfill_validate(
    const struct shop_fulfill_v1 *fulfill)
{
    if (!fulfill) return SHOP_FULFILL_ERR_NULL;
    if (fulfill->schema_version != SHOP_FULFILL_VERSION)
        return SHOP_FULFILL_ERR_VERSION;
    if (!fulfill_nonzero(fulfill->want_id, 32))
        return SHOP_FULFILL_ERR_WANT_ZERO;
    if (!fulfill_nonzero(fulfill->seller_pubkey, 32))
        return SHOP_FULFILL_ERR_PUBKEY_ZERO;
    if (fulfill->nonce == 0)
        return SHOP_FULFILL_ERR_NONCE;
    if (!fulfill_nonzero(fulfill->artifact_root, 32))
        return SHOP_FULFILL_ERR_ARTIFACT_ZERO;
    if (!fulfill_nonzero(fulfill->content_root, 32))
        return SHOP_FULFILL_ERR_CONTENT_ZERO;
    if (fulfill->issued_unix <= 0 ||
        fulfill->expires_unix <= fulfill->issued_unix)
        return SHOP_FULFILL_ERR_TIME_ORDER;
    if (fulfill->expires_unix - fulfill->issued_unix >
        SHOP_FULFILL_MAX_LIFETIME_SECS)
        return SHOP_FULFILL_ERR_LIFETIME;
    if (!fulfill_nonzero(fulfill->seller_signature, 64))
        return SHOP_FULFILL_ERR_SIGNATURE;
    return SHOP_FULFILL_OK;
}

static size_t fulfill_body(const struct shop_fulfill_v1 *f, uint8_t *out)
{
    size_t off = 0;
    memcpy(out + off, fulfill_magic, 8); off += 8;
    zcl_write_u16_le(out + off, f->schema_version); off += 2;
    memcpy(out + off, f->want_id, 32); off += 32;
    memcpy(out + off, f->seller_pubkey, 32); off += 32;
    zcl_write_u64_le(out + off, f->nonce); off += 8;
    memcpy(out + off, f->artifact_root, 32); off += 32;
    memcpy(out + off, f->content_root, 32); off += 32;
    memcpy(out + off, f->build_receipt_id, 32); off += 32;
    memcpy(out + off, f->fuzz_receipt_id, 32); off += 32;
    memcpy(out + off, f->bench_receipt_id, 32); off += 32;
    zcl_write_i64_le(out + off, f->issued_unix); off += 8;
    zcl_write_i64_le(out + off, f->expires_unix); off += 8;
    return off;
}

enum shop_fulfill_error shop_fulfill_encode(
    const struct shop_fulfill_v1 *fulfill,
    uint8_t out[SHOP_FULFILL_WIRE_BYTES])
{
    if (!fulfill || !out) return SHOP_FULFILL_ERR_NULL;
    enum shop_fulfill_error error = shop_fulfill_validate(fulfill);
    if (error != SHOP_FULFILL_OK) return error;
    size_t off = fulfill_body(fulfill, out);
    if (off != SHOP_FULFILL_BODY_BYTES)
        return SHOP_FULFILL_ERR_WIRE_SIZE;
    memcpy(out + off, fulfill->seller_signature, 64);
    return SHOP_FULFILL_OK;
}

enum shop_fulfill_error shop_fulfill_decode(
    const uint8_t *wire, size_t wire_len, struct shop_fulfill_v1 *out)
{
    if (!wire || !out) return SHOP_FULFILL_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != SHOP_FULFILL_WIRE_BYTES)
        return SHOP_FULFILL_ERR_WIRE_SIZE;
    if (memcmp(wire, fulfill_magic, 8) != 0)
        return SHOP_FULFILL_ERR_WIRE_MAGIC;
    size_t off = 8;
    out->schema_version = zcl_read_u16_le(wire + off); off += 2;
    memcpy(out->want_id, wire + off, 32); off += 32;
    memcpy(out->seller_pubkey, wire + off, 32); off += 32;
    out->nonce = zcl_read_u64_le(wire + off); off += 8;
    memcpy(out->artifact_root, wire + off, 32); off += 32;
    memcpy(out->content_root, wire + off, 32); off += 32;
    memcpy(out->build_receipt_id, wire + off, 32); off += 32;
    memcpy(out->fuzz_receipt_id, wire + off, 32); off += 32;
    memcpy(out->bench_receipt_id, wire + off, 32); off += 32;
    out->issued_unix = zcl_read_i64_le(wire + off); off += 8;
    out->expires_unix = zcl_read_i64_le(wire + off); off += 8;
    memcpy(out->seller_signature, wire + off, 64);
    enum shop_fulfill_error error = shop_fulfill_validate(out);
    if (error != SHOP_FULFILL_OK) memset(out, 0, sizeof(*out));
    return error;
}

static void fulfill_hash(const char *domain, size_t domain_len,
                         const uint8_t *bytes, size_t len, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, domain_len);
    sha3_256_write(&sha, bytes, len);
    sha3_256_finalize(&sha, out);
}

enum shop_fulfill_error shop_fulfill_body_root(
    const struct shop_fulfill_v1 *fulfill, uint8_t out[32])
{
    if (!fulfill || !out) return SHOP_FULFILL_ERR_NULL;
    uint8_t body[SHOP_FULFILL_BODY_BYTES];
    if (fulfill_body(fulfill, body) != sizeof(body))
        return SHOP_FULFILL_ERR_WIRE_SIZE;
    static const char domain[] = SHOP_FULFILL_DOMAIN;
    fulfill_hash(domain, sizeof(domain), body, sizeof(body), out);
    return SHOP_FULFILL_OK;
}

enum shop_fulfill_error shop_fulfill_root(
    const struct shop_fulfill_v1 *fulfill, uint8_t out[32])
{
    if (!fulfill || !out) return SHOP_FULFILL_ERR_NULL;
    uint8_t wire[SHOP_FULFILL_WIRE_BYTES];
    enum shop_fulfill_error error = shop_fulfill_encode(fulfill, wire);
    if (error != SHOP_FULFILL_OK) return error;
    static const char domain[] = SHOP_FULFILL_ROOT_DOMAIN;
    fulfill_hash(domain, sizeof(domain), wire, sizeof(wire), out);
    return SHOP_FULFILL_OK;
}

enum shop_fulfill_error shop_fulfill_seal(
    struct shop_fulfill_v1 *fulfill, const uint8_t seller_secret[32])
{
    if (!fulfill || !seller_secret) return SHOP_FULFILL_ERR_NULL;
    uint8_t pubkey[32], secret[32];
    ed25519_keypair(pubkey, secret, seller_secret);
    if (memcmp(pubkey, fulfill->seller_pubkey, 32) != 0) {
        memory_cleanse(secret, sizeof(secret));
        return SHOP_FULFILL_ERR_KEY_MISMATCH;
    }
    uint8_t root[32];
    enum shop_fulfill_error error = shop_fulfill_body_root(fulfill, root);
    if (error == SHOP_FULFILL_OK)
        ed25519_sign(fulfill->seller_signature, root, sizeof(root), secret,
                     pubkey);
    memory_cleanse(secret, sizeof(secret));
    memory_cleanse(root, sizeof(root));
    return error;
}

enum shop_fulfill_error shop_fulfill_verify(
    const struct shop_fulfill_v1 *fulfill)
{
    enum shop_fulfill_error error = shop_fulfill_validate(fulfill);
    if (error != SHOP_FULFILL_OK) return error;
    uint8_t root[32];
    error = shop_fulfill_body_root(fulfill, root);
    if (error != SHOP_FULFILL_OK) return error;
    if (!ed25519_verify(fulfill->seller_signature, root, sizeof(root),
                        fulfill->seller_pubkey))
        return SHOP_FULFILL_ERR_SIGNATURE;
    return SHOP_FULFILL_OK;
}

bool db_shop_fulfill_validate(const struct shop_fulfill *row,
                              struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!row) {
        ar_errors_add(errors, "row", "is NULL");
        return false;
    }
    validates_custom(errors, fulfill_nonzero(row->fulfill_id, 32),
                     "fulfill_id", "can't be all zero");
    uint8_t canonical_id[32];
    validates_custom(errors,
                     shop_fulfill_root(&row->fulfill, canonical_id) ==
                         SHOP_FULFILL_OK &&
                     memcmp(canonical_id, row->fulfill_id, 32) == 0,
                     "fulfill_id", "must equal the signed wire root");
    validates_custom(errors,
                     shop_fulfill_verify(&row->fulfill) == SHOP_FULFILL_OK,
                     "wire", "must carry a valid signed fulfillment");
    validates_custom(errors, market_review_state_valid(row->review_state),
                     "review_state", "not a canonical moderation state");
    validates_custom(errors, row->withdrawn_unix >= 0,
                     "withdrawn_unix", "can't be negative");
    validates_positive(errors, row, posted_unix);
    return !ar_errors_any(errors);
}

bool db_shop_fulfill_save(struct node_db *ndb,
                          const struct shop_fulfill *row)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("shop", "db_shop_fulfill_save: db not open");
    if (!row) LOG_FAIL("shop", "db_shop_fulfill_save: row is NULL");
    uint8_t wire[SHOP_FULFILL_WIRE_BYTES];
    if (shop_fulfill_encode(&row->fulfill, wire) != SHOP_FULFILL_OK)
        LOG_FAIL("shop", "db_shop_fulfill_save: re-encode failed");
    const char *review = market_review_state_string(
        (enum market_review_state)row->review_state);
    if (!review) LOG_FAIL("shop", "db_shop_fulfill_save: bad review state");

    sqlite3_stmt *s = NULL;
    AR_ADHOC_SAVE(ndb, s,
        "INSERT INTO shop_fulfills(fulfill_id,want_id,wire,seller_pubkey,"
        "nonce,artifact_root,content_root,build_receipt_id,fuzz_receipt_id,"
        "bench_receipt_id,issued_unix,expires_unix,review_state,"
        "withdrawn_unix,posted_unix) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        " ON CONFLICT(fulfill_id) DO NOTHING",
        db_shop_fulfill_callbacks(), "shop_fulfill", row,
        db_shop_fulfill_validate,
        AR_BIND_BLOB(s, 1, row->fulfill_id, 32);
        AR_BIND_BLOB(s, 2, row->fulfill.want_id, 32);
        AR_BIND_BLOB(s, 3, wire, sizeof(wire));
        AR_BIND_BLOB(s, 4, row->fulfill.seller_pubkey, 32);
        AR_BIND_INT(s, 5, (int64_t)row->fulfill.nonce);
        AR_BIND_BLOB(s, 6, row->fulfill.artifact_root, 32);
        AR_BIND_BLOB(s, 7, row->fulfill.content_root, 32);
        AR_BIND_BLOB(s, 8, row->fulfill.build_receipt_id, 32);
        AR_BIND_BLOB(s, 9, row->fulfill.fuzz_receipt_id, 32);
        AR_BIND_BLOB(s, 10, row->fulfill.bench_receipt_id, 32);
        AR_BIND_INT(s, 11, row->fulfill.issued_unix);
        AR_BIND_INT(s, 12, row->fulfill.expires_unix);
        AR_BIND_TEXT(s, 13, review);
        AR_BIND_INT(s, 14, row->withdrawn_unix);
        AR_BIND_INT(s, 15, row->posted_unix));
}

static bool row_to_shop_fulfill(sqlite3_stmt *s, struct shop_fulfill *out)
{
    memset(out, 0, sizeof(*out));
    AR_READ_BLOB(s, 0, out->fulfill_id, 32);
    const void *wire = sqlite3_column_blob(s, 1);
    int wire_len = sqlite3_column_bytes(s, 1);
    if (!wire || wire_len != (int)SHOP_FULFILL_WIRE_BYTES)
        LOG_FAIL("shop", "shop_fulfills.wire length invalid: %d", wire_len);
    if (shop_fulfill_decode(wire, (size_t)wire_len, &out->fulfill) !=
        SHOP_FULFILL_OK)
        LOG_FAIL("shop", "shop_fulfills.wire failed to decode");
    uint8_t canonical_id[32];
    if (shop_fulfill_root(&out->fulfill, canonical_id) != SHOP_FULFILL_OK ||
        memcmp(canonical_id, out->fulfill_id, 32) != 0)
        LOG_FAIL("shop", "shop_fulfills.fulfill_id does not match wire");
    const char *review = AR_COL_TEXT(s, 2);
    out->review_state = market_review_state_from_string(review);
    if (out->review_state < 0)
        LOG_FAIL("shop", "shop_fulfills.review_state invalid");
    out->withdrawn_unix = AR_COL_INT(s, 3);
    out->posted_unix = AR_COL_INT(s, 4);
    return true;
}

bool db_shop_fulfill_find(struct node_db *ndb,
                          const uint8_t fulfill_id[32],
                          struct shop_fulfill *out)
{
    if (!ndb || !ndb->open || !fulfill_id || !out) return false;
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT fulfill_id,wire,review_state,withdrawn_unix,posted_unix"
        " FROM shop_fulfills WHERE fulfill_id=?",
        AR_BIND_BLOB(s, 1, fulfill_id, 32),
        if (!row_to_shop_fulfill(s, out)) { AR_FINALIZE(s); return false; });
}

bool db_shop_fulfill_find_seller_nonce(struct node_db *ndb,
                                       const uint8_t seller_pubkey[32],
                                       uint64_t nonce,
                                       struct shop_fulfill *out)
{
    if (!ndb || !ndb->open || !seller_pubkey || !out || nonce == 0)
        return false;
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT fulfill_id,wire,review_state,withdrawn_unix,posted_unix"
        " FROM shop_fulfills WHERE seller_pubkey=? AND nonce=?",
        AR_BIND_BLOB(s, 1, seller_pubkey, 32);
        AR_BIND_INT(s, 2, (int64_t)nonce),
        if (!row_to_shop_fulfill(s, out)) { AR_FINALIZE(s); return false; });
}

int db_shop_fulfill_list_for_want(struct node_db *ndb,
                                  const uint8_t want_id[32],
                                  int64_t now_unix, bool include_closed,
                                  struct shop_fulfill *out, size_t max)
{
    if (!ndb || !ndb->open || !want_id || (!out && max > 0)) return 0;
    if (max > SHOP_FULFILL_QUERY_CAP) max = SHOP_FULFILL_QUERY_CAP;
    sqlite3_stmt *s = NULL;
    if (include_closed) {
        AR_PREPARE_RET(ndb, s,
            "SELECT fulfill_id,wire,review_state,withdrawn_unix,posted_unix"
            " FROM shop_fulfills WHERE want_id=?"
            " ORDER BY posted_unix DESC LIMIT ?", 0);
        AR_BIND_BLOB(s, 1, want_id, 32);
        AR_BIND_INT(s, 2, (int64_t)max);
    } else {
        AR_PREPARE_RET(ndb, s,
            "SELECT fulfill_id,wire,review_state,withdrawn_unix,posted_unix"
            " FROM shop_fulfills WHERE want_id=? AND expires_unix>?"
            " AND withdrawn_unix=0 ORDER BY posted_unix DESC LIMIT ?", 0);
        AR_BIND_BLOB(s, 1, want_id, 32);
        AR_BIND_INT(s, 2, now_unix);
        AR_BIND_INT(s, 3, (int64_t)max);
    }
    size_t n = 0;
    while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW && n < max)
        if (row_to_shop_fulfill(s, &out[n])) n++;
    AR_FINALIZE(s);
    return (int)n;
}

/* The list's WHERE clause with no window — keep the two textually
 * parallel so the total can never drift from what the window shows. */
int db_shop_fulfill_list_count_for_want(struct node_db *ndb,
                                        const uint8_t want_id[32],
                                        int64_t now_unix,
                                        bool include_closed)
{
    if (!ndb || !ndb->open || !want_id)
        LOG_RETURN(-1, "shop",
                   "db_shop_fulfill_list_count_for_want: bad input");
    sqlite3_stmt *s = NULL;
    int64_t count = 0;
    if (include_closed) {
        AR_PREPARE_RET(ndb, s,
            "SELECT count(*) FROM shop_fulfills WHERE want_id=?", -1);
        AR_BIND_BLOB(s, 1, want_id, 32);
    } else {
        AR_PREPARE_RET(ndb, s,
            "SELECT count(*) FROM shop_fulfills"
            " WHERE want_id=? AND expires_unix>? AND withdrawn_unix=0",
            -1);
        AR_BIND_BLOB(s, 1, want_id, 32);
        AR_BIND_INT(s, 2, now_unix);
    }
    if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
        count = sqlite3_column_int64(s, 0);
    AR_FINALIZE(s);
    return count > INT_MAX ? INT_MAX : (int)count;
}

int64_t db_shop_fulfill_count_for_want(struct node_db *ndb,
                                       const uint8_t want_id[32])
{
    if (!ndb || !ndb->open || !want_id) return -1;
    sqlite3_stmt *s = NULL;
    int64_t count = 0;
    AR_PREPARE_RET(ndb, s,
        "SELECT count(*) FROM shop_fulfills WHERE want_id=?", -1);
    AR_BIND_BLOB(s, 1, want_id, 32);
    if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
        count = sqlite3_column_int64(s, 0);
    AR_FINALIZE(s);
    return count;
}

bool db_shop_fulfill_mark_withdrawn(struct node_db *ndb,
                                    const uint8_t fulfill_id[32],
                                    int64_t withdrawn_unix)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("shop", "db_shop_fulfill_mark_withdrawn: db not open");
    if (!fulfill_id || withdrawn_unix <= 0)
        LOG_FAIL("shop", "db_shop_fulfill_mark_withdrawn: bad input");
    sqlite3_stmt *s = NULL;
    AR_EXEC_CHANGED_BOOL(ndb, s,
        "UPDATE shop_fulfills SET withdrawn_unix=?"
        " WHERE fulfill_id=? AND withdrawn_unix=0",
        AR_BIND_INT(s, 1, withdrawn_unix);
        AR_BIND_BLOB(s, 2, fulfill_id, 32));
}

bool db_shop_fulfill_set_review_state(struct node_db *ndb,
                                      const uint8_t fulfill_id[32],
                                      const char *review_state)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("shop", "db_shop_fulfill_set_review_state: db not open");
    if (!fulfill_id)
        LOG_FAIL("shop", "db_shop_fulfill_set_review_state: id NULL");
    if (!review_state || market_review_state_from_string(review_state) < 0)
        LOG_FAIL("shop", "db_shop_fulfill_set_review_state: bad state");
    sqlite3_stmt *s = NULL;
    AR_EXEC_CHANGED_BOOL(ndb, s,
        "UPDATE shop_fulfills SET review_state=? WHERE fulfill_id=?",
        AR_BIND_TEXT(s, 1, review_state);
        AR_BIND_BLOB(s, 2, fulfill_id, 32));
}
