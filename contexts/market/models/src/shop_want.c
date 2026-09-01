/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shop WANT ads — codec + ActiveRecord model for the buyer-posted demand
 * board (slice D of docs/work/SHOP_COMMAND.md).
 *
 * The codec half is the zswap_quote.v1 shape with the terms reversed:
 * canonical little-endian body, Ed25519 over the domain-separated body
 * root, want id committing the full signed wire. The persistence half is
 * the shop_wants projection (migration v66): rows are written only for
 * wires the handler verified at ingress, the open board filters expired
 * and cancelled rows (never deletes), and review_state is the same
 * LOCAL-ONLY community content moderation mark as file_offers v65 —
 * never gossiped, never part of the signed wire, a hidden want stays
 * stored.
 */

#include "models/shop_want.h"

#include "base/bytes.h"
#include "base/cleanse.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "models/review_state.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

DEFINE_MODEL_CALLBACKS(shop_want)

static const uint8_t want_magic[8] = {'Z','S','H','P','W','T','\r','\n'};

const char *shop_want_error_string(enum shop_want_error error)
{
    switch (error) {
    case SHOP_WANT_OK: return "ok";
    case SHOP_WANT_ERR_NULL: return "null-argument";
    case SHOP_WANT_ERR_VERSION: return "schema-version";
    case SHOP_WANT_ERR_WIRE_SIZE: return "wire-size";
    case SHOP_WANT_ERR_WIRE_MAGIC: return "wire-magic";
    case SHOP_WANT_ERR_PUBKEY_ZERO: return "pubkey-zero";
    case SHOP_WANT_ERR_NONCE: return "nonce-zero";
    case SHOP_WANT_ERR_AMOUNT: return "amount-zero";
    case SHOP_WANT_ERR_CRITERIA: return "criteria-invalid";
    case SHOP_WANT_ERR_TIME_ORDER: return "time-order-invalid";
    case SHOP_WANT_ERR_LIFETIME: return "lifetime-too-long";
    case SHOP_WANT_ERR_SIGNATURE: return "signature-invalid";
    case SHOP_WANT_ERR_KEY_MISMATCH: return "key-mismatch";
    }
    return "unknown";
}

/* The criteria carry the objectively checkable terms as text: non-empty,
 * bounded, and free of NUL bytes (the projection stores them as TEXT). */
static bool criteria_valid(const struct shop_want_v1 *want)
{
    if (want->criteria_len == 0 ||
        want->criteria_len > SHOP_WANT_CRITERIA_MAX)
        return false;
    for (uint16_t i = 0; i < want->criteria_len; i++)
        if (want->criteria[i] == 0)
            return false;
    return true;
}

enum shop_want_error shop_want_validate(const struct shop_want_v1 *want)
{
    if (!want) return SHOP_WANT_ERR_NULL;
    if (want->schema_version != SHOP_WANT_VERSION)
        return SHOP_WANT_ERR_VERSION;
    if (!zcl_bytes_any_set(want->buyer_pubkey, 32))
        return SHOP_WANT_ERR_PUBKEY_ZERO;
    if (want->nonce == 0)
        return SHOP_WANT_ERR_NONCE;
    if (want->amount_zatoshi == 0)
        return SHOP_WANT_ERR_AMOUNT;
    if (!criteria_valid(want))
        return SHOP_WANT_ERR_CRITERIA;
    if (want->issued_unix <= 0 || want->expires_unix <= want->issued_unix)
        return SHOP_WANT_ERR_TIME_ORDER;
    if (want->expires_unix - want->issued_unix > SHOP_WANT_MAX_LIFETIME_SECS)
        return SHOP_WANT_ERR_LIFETIME;
    if (!zcl_bytes_any_set(want->buyer_signature, 64))
        return SHOP_WANT_ERR_SIGNATURE;
    return SHOP_WANT_OK;
}

/* The canonical body: every signed field in wire order. */
static size_t want_body(const struct shop_want_v1 *want, uint8_t *out)
{
    size_t off = 0;
    memcpy(out + off, want_magic, 8); off += 8;
    zcl_write_u16_le(out + off, want->schema_version); off += 2;
    memcpy(out + off, want->buyer_pubkey, 32); off += 32;
    zcl_write_u64_le(out + off, want->nonce); off += 8;
    zcl_write_u64_le(out + off, want->amount_zatoshi); off += 8;
    memcpy(out + off, want->spec_hash, 32); off += 32;
    zcl_write_u16_le(out + off, want->criteria_len); off += 2;
    memcpy(out + off, want->criteria, want->criteria_len);
    off += want->criteria_len;
    zcl_write_i64_le(out + off, want->issued_unix); off += 8;
    zcl_write_i64_le(out + off, want->expires_unix); off += 8;
    return off;
}

enum shop_want_error shop_want_encode(const struct shop_want_v1 *want,
                                      uint8_t *out, size_t out_cap,
                                      size_t *out_len)
{
    if (!want || !out || !out_len)
        return SHOP_WANT_ERR_NULL;
    enum shop_want_error error = shop_want_validate(want);
    if (error != SHOP_WANT_OK)
        return error;
    size_t body_len = SHOP_WANT_BODY_PREFIX_BYTES + want->criteria_len +
                      SHOP_WANT_BODY_SUFFIX_BYTES;
    if (out_cap < body_len + 64u)
        return SHOP_WANT_ERR_WIRE_SIZE;
    size_t written = want_body(want, out);
    memcpy(out + written, want->buyer_signature, 64);
    *out_len = written + 64u;
    return SHOP_WANT_OK;
}

enum shop_want_error shop_want_decode(const uint8_t *wire, size_t wire_len,
                                      struct shop_want_v1 *out)
{
    if (!wire || !out)
        return SHOP_WANT_ERR_NULL;
    memset(out, 0, sizeof(*out));
    size_t min_len = SHOP_WANT_BODY_PREFIX_BYTES + 1u +
                     SHOP_WANT_BODY_SUFFIX_BYTES + 64u;
    if (wire_len < min_len || wire_len > SHOP_WANT_WIRE_MAX_BYTES)
        return SHOP_WANT_ERR_WIRE_SIZE;
    if (memcmp(wire, want_magic, 8) != 0)
        return SHOP_WANT_ERR_WIRE_MAGIC;
    size_t off = 8;
    out->schema_version = zcl_read_u16_le(wire + off); off += 2;
    memcpy(out->buyer_pubkey, wire + off, 32); off += 32;
    out->nonce = zcl_read_u64_le(wire + off); off += 8;
    out->amount_zatoshi = zcl_read_u64_le(wire + off); off += 8;
    memcpy(out->spec_hash, wire + off, 32); off += 32;
    out->criteria_len = zcl_read_u16_le(wire + off); off += 2;
    /* Exact-length: the wire must end right after the signature, so the
     * declared criteria_len is cross-checked against the buffer. */
    size_t expected = SHOP_WANT_BODY_PREFIX_BYTES + out->criteria_len +
                      SHOP_WANT_BODY_SUFFIX_BYTES + 64u;
    if (wire_len != expected) {
        memset(out, 0, sizeof(*out));
        return SHOP_WANT_ERR_WIRE_SIZE;
    }
    memcpy(out->criteria, wire + off, out->criteria_len);
    off += out->criteria_len;
    out->issued_unix = zcl_read_i64_le(wire + off); off += 8;
    out->expires_unix = zcl_read_i64_le(wire + off); off += 8;
    memcpy(out->buyer_signature, wire + off, 64);
    enum shop_want_error error = shop_want_validate(out);
    if (error != SHOP_WANT_OK)
        memset(out, 0, sizeof(*out));
    return error;
}

static void want_root_hash(const char *domain, size_t domain_len,
                           const uint8_t *bytes, size_t len, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, domain_len);
    sha3_256_write(&sha, bytes, len);
    sha3_256_finalize(&sha, out);
}

enum shop_want_error shop_want_body_root(const struct shop_want_v1 *want,
                                         uint8_t out[32])
{
    if (!want || !out)
        return SHOP_WANT_ERR_NULL;
    uint8_t body[SHOP_WANT_BODY_MAX_BYTES];
    size_t body_len = want_body(want, body);
    static const char domain[] = SHOP_WANT_DOMAIN;
    want_root_hash(domain, sizeof(domain), body, body_len, out);
    return SHOP_WANT_OK;
}

enum shop_want_error shop_want_root(const struct shop_want_v1 *want,
                                    uint8_t out[32])
{
    if (!want || !out)
        return SHOP_WANT_ERR_NULL;
    uint8_t wire[SHOP_WANT_WIRE_MAX_BYTES];
    size_t wire_len = 0;
    enum shop_want_error error =
        shop_want_encode(want, wire, sizeof(wire), &wire_len);
    if (error != SHOP_WANT_OK)
        return error;
    static const char domain[] = SHOP_WANT_ROOT_DOMAIN;
    want_root_hash(domain, sizeof(domain), wire, wire_len, out);
    return SHOP_WANT_OK;
}

enum shop_want_error shop_want_seal(struct shop_want_v1 *want,
                                    const uint8_t buyer_secret[32])
{
    if (!want || !buyer_secret)
        return SHOP_WANT_ERR_NULL;
    uint8_t pubkey[32], secret[32];
    ed25519_keypair(pubkey, secret, buyer_secret);
    if (memcmp(pubkey, want->buyer_pubkey, 32) != 0) {
        memory_cleanse(secret, sizeof(secret));
        return SHOP_WANT_ERR_KEY_MISMATCH;
    }
    uint8_t root[32];
    enum shop_want_error error = shop_want_body_root(want, root);
    if (error == SHOP_WANT_OK)
        ed25519_sign(want->buyer_signature, root, sizeof(root), secret,
                     pubkey);
    memory_cleanse(secret, sizeof(secret));
    memory_cleanse(root, sizeof(root));
    return error;
}

enum shop_want_error shop_want_verify(const struct shop_want_v1 *want)
{
    enum shop_want_error error = shop_want_validate(want);
    if (error != SHOP_WANT_OK)
        return error;
    uint8_t root[32];
    error = shop_want_body_root(want, root);
    if (error != SHOP_WANT_OK)
        return error;
    if (!ed25519_verify(want->buyer_signature, root, sizeof(root),
                        want->buyer_pubkey))
        return SHOP_WANT_ERR_SIGNATURE;
    return SHOP_WANT_OK;
}

/* ── persistence ────────────────────────────────────────────────────── */

bool db_shop_want_validate(const struct shop_want *row,
                           struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!row) {
        ar_errors_add(errors, "row", "is NULL");
        return false;
    }
    validates_custom(errors, zcl_bytes_any_set(row->want_id, 32),
                     "want_id", "can't be all zero");
    validates_custom(errors, zcl_bytes_any_set(row->want.buyer_pubkey, 32),
                     "buyer_pubkey", "can't be all zero");
    validates_custom(errors, row->want.nonce != 0,
                     "nonce", "can't be zero");
    validates_positive(errors, row, want.amount_zatoshi);
    validates_custom(errors,
                     row->want.criteria_len >= 1 &&
                         row->want.criteria_len <= SHOP_WANT_CRITERIA_MAX,
                     "criteria_len", "out of bounds");
    validates_custom(errors,
                     row->want.issued_unix > 0 &&
                         row->want.expires_unix > row->want.issued_unix,
                     "expires_unix", "must be after issued_unix");
    validates_custom(errors,
                     row->want.expires_unix - row->want.issued_unix <=
                         SHOP_WANT_MAX_LIFETIME_SECS,
                     "expires_unix", "lifetime exceeds the structural cap");
    validates_custom(errors,
                     market_review_state_valid(row->review_state),
                     "review_state", "not a canonical moderation state");
    validates_custom(errors, row->cancelled_unix >= 0,
                     "cancelled_unix", "can't be negative");
    validates_positive(errors, row, posted_unix);
    return !ar_errors_any(errors);
}

bool db_shop_want_save(struct node_db *ndb, const struct shop_want *row)
{
    if (!ndb || !ndb->open) LOG_FAIL("shop", "db_shop_want_save: db not open");
    if (!row) LOG_FAIL("shop", "db_shop_want_save: row is NULL");

    /* The stored wire is the exact bytes the buyer signed — re-encoded
     * from the verified struct (Ed25519 sealing + the codec are byte
     * deterministic, so this reproduces the posted wire exactly). */
    uint8_t wire[SHOP_WANT_WIRE_MAX_BYTES];
    size_t wire_len = 0;
    if (shop_want_encode(&row->want, wire, sizeof(wire), &wire_len) !=
        SHOP_WANT_OK)
        LOG_FAIL("shop", "db_shop_want_save: want re-encode failed");
    char criteria[SHOP_WANT_CRITERIA_MAX + 1u];
    memcpy(criteria, row->want.criteria, row->want.criteria_len);
    criteria[row->want.criteria_len] = '\0';
    const char *review =
        market_review_state_string((enum market_review_state)row->review_state);
    if (!review)
        LOG_FAIL("shop", "db_shop_want_save: bad review_state %d",
                 row->review_state);

    struct ar_callbacks *cbs = db_shop_want_callbacks();
    sqlite3_stmt *s = NULL;
    /* Dedup on the id: a byte-identical re-post is a no-op (the same
     * dedup-on-root rule as the zswap ads projection). */
    AR_ADHOC_SAVE(ndb, s,
        "INSERT INTO shop_wants"
        "(want_id,wire,buyer_pubkey,amount_zatoshi,criteria,spec_hash,"
        "issued_unix,expires_unix,review_state,cancelled_unix,posted_unix)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)"
        " ON CONFLICT(want_id) DO NOTHING",
        cbs, "shop_want", row, db_shop_want_validate,
        AR_BIND_BLOB(s, 1, row->want_id, 32);
        AR_BIND_BLOB(s, 2, wire, wire_len);
        AR_BIND_BLOB(s, 3, row->want.buyer_pubkey, 32);
        AR_BIND_INT(s, 4, (int64_t)row->want.amount_zatoshi);
        AR_BIND_TEXT(s, 5, criteria);
        AR_BIND_BLOB(s, 6, row->want.spec_hash, 32);
        AR_BIND_INT(s, 7, row->want.issued_unix);
        AR_BIND_INT(s, 8, row->want.expires_unix);
        AR_BIND_TEXT(s, 9, review);
        AR_BIND_INT(s, 10, row->cancelled_unix);
        AR_BIND_INT(s, 11, row->posted_unix));
}

/* Rebuild the record from the stored wire (single source of truth for the
 * signed fields) plus the local-only columns. */
static bool row_to_shop_want(sqlite3_stmt *s, struct shop_want *out)
{
    memset(out, 0, sizeof(*out));
    AR_READ_BLOB(s, 0, out->want_id, 32);

    int wire_len = sqlite3_column_bytes(s, 1);
    const void *wire = sqlite3_column_blob(s, 1);
    if (!wire || wire_len <= 0 || (size_t)wire_len > SHOP_WANT_WIRE_MAX_BYTES)
        LOG_FAIL("shop", "shop_wants.wire length out of bounds: %d",
                 wire_len);
    if (shop_want_decode(wire, (size_t)wire_len, &out->want) != SHOP_WANT_OK)
        LOG_FAIL("shop", "shop_wants.wire failed to decode");

    const char *review = AR_COL_TEXT(s, 2);
    out->review_state = market_review_state_from_string(review);
    if (out->review_state < 0)
        LOG_FAIL("shop", "shop_wants.review_state not canonical: %s",
                 review ? review : "(null)");
    out->cancelled_unix = sqlite3_column_int64(s, 3);
    out->posted_unix = sqlite3_column_int64(s, 4);
    return true;
}

bool db_shop_want_find(struct node_db *ndb, const uint8_t want_id[32],
                       struct shop_want *out)
{
    if (!ndb || !ndb->open) LOG_FAIL("shop", "db_shop_want_find: db not open");
    if (!want_id) LOG_FAIL("shop", "db_shop_want_find: want_id is NULL");
    if (!out) LOG_FAIL("shop", "db_shop_want_find: out is NULL");

    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT want_id,wire,review_state,cancelled_unix,posted_unix"
        " FROM shop_wants WHERE want_id=?",
        AR_BIND_BLOB(s, 1, want_id, 32),
        if (!row_to_shop_want(s, out)) { AR_FINALIZE(s); return false; });
}

int db_shop_want_list(struct node_db *ndb, int64_t now_unix,
                      bool include_closed, struct shop_want *out, size_t max)
{
    if (!ndb || !ndb->open) return 0;
    if (!out && max > 0)
        LOG_RETURN(0, "shop", "db_shop_want_list: NULL out");
    if (max > SHOP_WANT_QUERY_CAP)
        max = SHOP_WANT_QUERY_CAP;

    /* Expired and cancelled rows are filtered by the WHERE clause, not
     * deleted — storage keeps what was valid at ingress. */
    sqlite3_stmt *s = NULL;
    if (include_closed) {
        AR_PREPARE_RET(ndb, s,
            "SELECT want_id,wire,review_state,cancelled_unix,posted_unix"
            " FROM shop_wants ORDER BY posted_unix DESC LIMIT ?",
            0);
    } else {
        AR_PREPARE_RET(ndb, s,
            "SELECT want_id,wire,review_state,cancelled_unix,posted_unix"
            " FROM shop_wants WHERE expires_unix>? AND cancelled_unix=0"
            " ORDER BY posted_unix DESC LIMIT ?",
            0);
    }
    AR_BIND_INT(s, 1, include_closed ? (int64_t)max : now_unix);
    if (!include_closed)
        AR_BIND_INT(s, 2, (int64_t)max);
    size_t n = 0;
    while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW && n < max) {
        if (row_to_shop_want(s, &out[n])) n++;
    }
    AR_FINALIZE(s);
    return (int)n;
}

/* Count with the list's WHERE clause but no window. The two must stay
 * textually parallel: a total that disagrees with what the window would
 * eventually show is exactly the lie this counter exists to prevent. */
int db_shop_want_count(struct node_db *ndb, int64_t now_unix,
                       bool include_closed)
{
    if (!ndb || !ndb->open)
        LOG_RETURN(-1, "shop", "db_shop_want_count: db not open");
    sqlite3_stmt *s = NULL;
    int64_t count = 0;
    if (include_closed) {
        AR_PREPARE_RET(ndb, s,
            "SELECT count(*) FROM shop_wants", -1);
    } else {
        AR_PREPARE_RET(ndb, s,
            "SELECT count(*) FROM shop_wants"
            " WHERE expires_unix>? AND cancelled_unix=0",
            -1);
        AR_BIND_INT(s, 1, now_unix);
    }
    int step_rc = AR_STEP_ROW_READONLY(s);
    if (step_rc != SQLITE_ROW) {
        AR_FINALIZE(s);
        LOG_RETURN(-1, "shop",
                   "db_shop_want_count: count step failed rc=%d: %s",
                   step_rc, sqlite3_errmsg(ndb->db));
    }
    count = sqlite3_column_int64(s, 0);
    AR_FINALIZE(s);
    return count > INT_MAX ? INT_MAX : (int)count;
}

bool db_shop_want_mark_cancelled(struct node_db *ndb,
                                 const uint8_t want_id[32],
                                 int64_t cancelled_unix)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("shop", "db_shop_want_mark_cancelled: db not open");
    if (!want_id)
        LOG_FAIL("shop", "db_shop_want_mark_cancelled: want_id NULL");

    sqlite3_stmt *s = NULL;
    AR_EXEC_CHANGED_BOOL(ndb, s,
        "UPDATE shop_wants SET cancelled_unix=?"
        " WHERE want_id=? AND cancelled_unix=0",
        AR_BIND_INT(s, 1, cancelled_unix);
        AR_BIND_BLOB(s, 2, want_id, 32));
}

bool db_shop_want_set_review_state(struct node_db *ndb,
                                   const uint8_t want_id[32],
                                   const char *review_state)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("shop", "db_shop_want_set_review_state: db not open");
    if (!want_id)
        LOG_FAIL("shop", "db_shop_want_set_review_state: want_id NULL");
    if (!review_state || market_review_state_from_string(review_state) < 0)
        LOG_FAIL("shop", "db_shop_want_set_review_state: state not canonical");

    sqlite3_stmt *s = NULL;
    AR_EXEC_CHANGED_BOOL(ndb, s,
        "UPDATE shop_wants SET review_state=? WHERE want_id=?",
        AR_BIND_TEXT(s, 1, review_state);
        AR_BIND_BLOB(s, 2, want_id, 32));
}
