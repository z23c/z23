/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord persistence for immutable signed Blog posts and their
 * reorg-aware full-node publication receipts. */

#include "models/blog_post.h"

#include "models/model_fields.h"
#include "models/def/blog_post_fields.def"

#include "chain/chainparams.h"
#include "keys/key_io.h"
#include "keys/pubkey.h"
#include "script/standard.h"
#include "util/log_macros.h"
#include "znam/znam.h"

#include <limits.h>
#include <sqlite3.h>
#include <string.h>

DEFINE_MODEL_CALLBACKS(blog_post)
DEFINE_MODEL_CALLBACKS(blog_publication_receipt)

/* ── Column mapping ───────────────────────────────────────────────────────
 * Every spelling below is derived from the field lists in
 * models/def/blog_post_fields.def: the SQL column list, the SELECT read
 * index, the INSERT placeholder count, and the bind position. None of them
 * is written down, so none of them can drift out of step with the others. */
#define BLOG_POST_COLUMNS ZCL_MODEL_COLUMNS(BLOG_POST_FIELDS)
#define BLOG_POST_VALUES  ZCL_MODEL_PLACEHOLDERS(BLOG_POST_FIELDS)

#define BLOG_POST_SUMMARY_COLUMNS ZCL_MODEL_COLUMNS(BLOG_POST_SUMMARY_FIELDS)

#define BLOG_RECEIPT_COLUMNS \
    ZCL_MODEL_COLUMNS(BLOG_PUBLICATION_RECEIPT_FIELDS)
#define BLOG_RECEIPT_VALUES \
    ZCL_MODEL_PLACEHOLDERS(BLOG_PUBLICATION_RECEIPT_FIELDS)

ZCL_MODEL_READ_ROW_FN(blog_post_read_row, struct db_blog_post,
                      BLOG_POST_FIELDS)
ZCL_MODEL_BIND_FN(blog_post_bind, struct db_blog_post, BLOG_POST_FIELDS)

ZCL_MODEL_READ_ROW_FN(blog_summary_read_row, struct db_blog_post_summary,
                      BLOG_POST_SUMMARY_FIELDS)

#define BLOG_CHAIN_ANCHOR_COLUMNS ZCL_MODEL_COLUMNS(BLOG_CHAIN_ANCHOR_FIELDS)
#define BCA_IX(kind, col, member, extra) BCA_IX_##member,
enum { ZCL_MODEL_EXPAND(BCA_IX, BLOG_CHAIN_ANCHOR_FIELDS) BCA_IX_COUNT };

ZCL_MODEL_READ_ROW_FN(blog_receipt_read_row,
                      struct db_blog_publication_receipt,
                      BLOG_PUBLICATION_RECEIPT_FIELDS)
ZCL_MODEL_BIND_FN(blog_receipt_bind, struct db_blog_publication_receipt,
                  BLOG_PUBLICATION_RECEIPT_FIELDS)

static bool bytes_nonzero(const uint8_t *bytes, size_t len)
{
    uint8_t any = 0;
    for (size_t i = 0; i < len; i++)
        any |= bytes[i];
    return any != 0;
}

static bool bounded_utf8_text(const char *text, size_t max_len,
                              bool allow_multiline)
{
    if (!text)
        return false;
    const char *end = memchr(text, 0, max_len + 1);
    if (!end || end == text)
        return false;
    const unsigned char *p = (const unsigned char *)text;
    const unsigned char *limit = (const unsigned char *)end;
    while (p < limit) {
        uint32_t cp = 0;
        size_t width = 0;
        if (*p < 0x80) {
            cp = *p;
            width = 1;
        } else if (*p >= 0xc2 && *p <= 0xdf) {
            cp = (uint32_t)(*p & 0x1f);
            width = 2;
        } else if (*p >= 0xe0 && *p <= 0xef) {
            cp = (uint32_t)(*p & 0x0f);
            width = 3;
        } else if (*p >= 0xf0 && *p <= 0xf4) {
            cp = (uint32_t)(*p & 0x07);
            width = 4;
        } else {
            return false;
        }
        if ((size_t)(limit - p) < width)
            return false;
        for (size_t i = 1; i < width; i++) {
            if ((p[i] & 0xc0) != 0x80)
                return false;
            cp = (cp << 6) | (uint32_t)(p[i] & 0x3f);
        }
        if ((width == 2 && cp < 0x80) ||
            (width == 3 && cp < 0x800) ||
            (width == 4 && cp < 0x10000) ||
            cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
            return false;
        if (cp < 0x20) {
            if (!(allow_multiline && (cp == '\n' || cp == '\t')))
                return false;
        } else if (cp == 0x7f || (cp >= 0x80 && cp <= 0x9f) ||
                   (cp >= 0x200b && cp <= 0x200f) ||
                   (cp >= 0x202a && cp <= 0x202e) ||
                   (cp >= 0x2066 && cp <= 0x2069) || cp == 0xfeff) {
            /* Reject invisible/bidirectional controls that can spoof source,
             * links, names, or proof text in HTML and Markdown renderers. */
            return false;
        }
        p += width;
    }
    return true;
}

bool db_blog_slug_valid(const char *slug)
{
    if (!slug)
        return false;
    const char *end = memchr(slug, 0, BLOG_SLUG_MAX + 1);
    if (!end || end == slug || *slug == '-' || end[-1] == '-')
        return false;
    for (const unsigned char *p = (const unsigned char *)slug;
         p < (const unsigned char *)end; p++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
            *p == '-')
            continue;
        return false;
    }
    return true;
}

bool db_blog_title_valid(const char *title)
{
    return bounded_utf8_text(title, BLOG_TITLE_MAX, false);
}

bool db_blog_body_valid(const char *body)
{
    return bounded_utf8_text(body, BLOG_BODY_MAX, true);
}

bool db_blog_sequence_shape_valid(uint64_t sequence,
                                  const uint8_t previous_event_id[32])
{
    if (!previous_event_id || sequence == 0 || sequence > INT64_MAX)
        return false;
    bool has_previous = bytes_nonzero(previous_event_id, 32);
    return (sequence == 1 && !has_previous) ||
           (sequence > 1 && has_previous);
}

static bool blog_author_identity_valid(const struct db_blog_post *post)
{
    struct pubkey pubkey;
    pubkey_init(&pubkey);
    pubkey_set(&pubkey, post->author_pubkey, sizeof(post->author_pubkey));
    if (!pubkey_is_compressed(&pubkey) || !pubkey_is_fully_valid(&pubkey))
        return false; /* raw-return-ok:model-validator-predicate-negative */
    struct key_id key_id = pubkey_get_id(&pubkey);
    if (memcmp(key_id.id.data, post->author_key_id, 20) != 0)
        return false;
    const struct chain_params *params = chain_params_get();
    if (!params)
        return false;
    size_t pub_len = 0, script_len = 0;
    const unsigned char *pub = chain_params_base58_prefix(
        params, B58_PUBKEY_ADDRESS, &pub_len);
    const unsigned char *script = chain_params_base58_prefix(
        params, B58_SCRIPT_ADDRESS, &script_len);
    struct tx_destination destination;
    if (!decode_destination(post->author_address, pub, pub_len,
                            script, script_len, &destination) ||
        destination.type != DEST_KEY_ID)
        return false;
    return memcmp(destination.id.key.id.data, post->author_key_id, 20) == 0;
}

bool db_blog_post_validate(const struct db_blog_post *post,
                           struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!post) {
        validates_custom(errors, false, "post", "is null");
        return false;
    }
    validates_custom(errors, bytes_nonzero(post->event_id, 32),
                     "event_id", "is empty");
    validates_custom(errors, znam_validate_name(post->blog_name),
                     "blog_name", "is not a valid ZNAM name");
    validates_custom(errors, db_blog_slug_valid(post->slug),
                     "slug", "is not canonical");
    validates_custom(errors, db_blog_title_valid(post->title),
                     "title", "is empty or contains control bytes");
    validates_custom(errors, db_blog_body_valid(post->body),
                     "body", "is empty or contains control bytes");
    validates_custom(errors, bytes_nonzero(post->author_key_id, 20),
                     "author_key_id", "is empty");
    validates_custom(errors,
                     post->author_pubkey[0] == 0x02 ||
                     post->author_pubkey[0] == 0x03,
                     "author_pubkey", "is not compressed secp256k1");
    validates_custom(errors,
                     bounded_utf8_text(post->author_address,
                                       BLOG_AUTHOR_ADDRESS_MAX, false),
                     "author_address", "is invalid");
    validates_custom(errors, blog_author_identity_valid(post),
                     "author_identity",
                     "public key, key ID, and address do not match");
    validates_custom(errors, bytes_nonzero(post->chain_id, 32),
                     "chain_id", "is empty");
    validates_custom(errors,
                     db_blog_sequence_shape_valid(
                         post->sequence, post->previous_event_id),
                     "previous_event_id", "does not match sequence");
    validates_custom(errors, post->event_created_at > 0,
                     "event_created_at", "must be positive");
    validates_custom(errors,
                     post->signature_len >= 8 &&
                     post->signature_len <= BLOG_SIGNATURE_MAX,
                     "signature", "length is invalid");
    validates_custom(errors, post->stored_at > 0,
                     "stored_at", "must be positive");
    return !ar_errors_any(errors);
}

bool db_blog_publication_receipt_validate(
    const struct db_blog_publication_receipt *receipt,
    struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!receipt) {
        validates_custom(errors, false, "receipt", "is null");
        return false;
    }
    validates_custom(errors, bytes_nonzero(receipt->txid, 32),
                     "txid", "is empty");
    validates_custom(errors, bytes_nonzero(receipt->event_id, 32),
                     "event_id", "is empty");
    validates_custom(errors, znam_validate_name(receipt->blog_name),
                     "blog_name", "is not a valid ZNAM name");
    validates_custom(errors, bytes_nonzero(receipt->author_key_id, 20),
                     "author_key_id", "is empty");
    validates_custom(errors, bytes_nonzero(receipt->znam_reg_txid, 32),
                     "znam_reg_txid", "is empty");
    validates_custom(errors,
                     receipt->block_height >= -1 &&
                     receipt->block_height <= INT_MAX,
                     "block_height", "is outside range");
    validates_custom(errors,
                     receipt->status >= BLOG_PUBLICATION_UNRESOLVED &&
                     receipt->status <= BLOG_PUBLICATION_ORPHANED,
                     "status", "is unknown");
    if (receipt->status != BLOG_PUBLICATION_UNRESOLVED) {
        validates_custom(errors, bytes_nonzero(receipt->block_hash, 32),
                         "block_hash", "is required for final status");
        validates_custom(errors, receipt->block_height >= 0,
                         "block_height", "is required for final status");
    }
    validates_custom(errors, receipt->observed_at > 0,
                     "observed_at", "must be positive");
    return !ar_errors_any(errors);
}

static bool blog_post_same(const struct db_blog_post *a,
                           const struct db_blog_post *b)
{
    return memcmp(a->event_id, b->event_id, 32) == 0 &&
        strcmp(a->blog_name, b->blog_name) == 0 &&
        strcmp(a->slug, b->slug) == 0 &&
        strcmp(a->title, b->title) == 0 &&
        strcmp(a->body, b->body) == 0 &&
        memcmp(a->author_key_id, b->author_key_id, 20) == 0 &&
        memcmp(a->author_pubkey, b->author_pubkey, 33) == 0 &&
        strcmp(a->author_address, b->author_address) == 0 &&
        memcmp(a->chain_id, b->chain_id, 32) == 0 &&
        a->sequence == b->sequence &&
        memcmp(a->previous_event_id, b->previous_event_id, 32) == 0 &&
        a->event_created_at == b->event_created_at &&
        a->signature_len == b->signature_len &&
        memcmp(a->signature, b->signature, a->signature_len) == 0;
}

static bool blog_post_previous_matches(struct node_db *ndb,
                                       const struct db_blog_post *post)
{
    if (post->sequence == 1)
        return true;
    struct db_blog_post previous;
    if (!db_blog_post_find(ndb, post->previous_event_id, &previous))
        LOG_FAIL("blog_post", "sequence predecessor is not stored");
    if (previous.sequence == UINT64_MAX ||
        post->sequence != previous.sequence + 1 ||
        strcmp(post->blog_name, previous.blog_name) != 0 ||
        memcmp(post->author_key_id, previous.author_key_id, 20) != 0 ||
        memcmp(post->chain_id, previous.chain_id, 32) != 0)
        LOG_FAIL("blog_post", "sequence predecessor identity does not match");
    return true;
}

bool db_blog_post_save(struct node_db *ndb, const struct db_blog_post *post)
{
    sqlite3_stmt *s = NULL;
    if (!ndb || !ndb->open || !post)
        LOG_FAIL("blog_post", "save requires an open database and post");
    if (!blog_post_previous_matches(ndb, post))
        return false; /* raw-return-ok:relationship-helper-already-logged */
    struct db_blog_post existing;
    if (db_blog_post_find(ndb, post->event_id, &existing)) {
        if (!blog_post_same(post, &existing))
            LOG_FAIL("blog_post", "event_id already belongs to different content");
        return true; /* immutable idempotent replay */
    }
    struct ar_callbacks *cbs = db_blog_post_callbacks();
    AR_ADHOC_SAVE(ndb, s,
        "INSERT INTO blog_posts (" BLOG_POST_COLUMNS ") "
        "VALUES(" BLOG_POST_VALUES ") "
        "ON CONFLICT(event_id) DO NOTHING",
        cbs, "blog_post", post, db_blog_post_validate,
        blog_post_bind(s, post));
}

bool db_blog_post_find(struct node_db *ndb, const uint8_t event_id[32],
                       struct db_blog_post *out)
{
    sqlite3_stmt *s = NULL;
    if (!ndb || !ndb->open || !event_id || !out)
        LOG_FAIL("blog_post", "find requires valid arguments");
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT " BLOG_POST_COLUMNS " FROM blog_posts WHERE event_id=?",
        AR_BIND_BLOB(s, 1, event_id, 32),
        blog_post_read_row(out, s));
}

bool db_blog_post_find_by_slug(struct node_db *ndb, const char *blog_name,
                               const char *slug, struct db_blog_post *out)
{
    sqlite3_stmt *s = NULL;
    if (!ndb || !ndb->open || !blog_name || !slug || !out)
        LOG_FAIL("blog_post", "find_by_slug requires valid arguments");
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT " BLOG_POST_COLUMNS " FROM blog_posts "
        "WHERE blog_name=? AND slug=? ORDER BY event_id LIMIT 1",
        AR_BIND_TEXT(s, 1, blog_name);
        AR_BIND_TEXT(s, 2, slug),
        blog_post_read_row(out, s));
}

int db_blog_post_list(struct node_db *ndb, const char *blog_name,
                      struct db_blog_post *out, size_t max)
{
    sqlite3_stmt *s = NULL;
    if (!ndb || !ndb->open || !blog_name || !out || max == 0)
        return 0;
    AR_QUERY_LIST(ndb, s,
        "SELECT " BLOG_POST_COLUMNS " FROM blog_posts "
        "WHERE blog_name=? ORDER BY sequence DESC,event_id LIMIT ?",
        out, max,
        AR_BIND_TEXT(s, 1, blog_name);
        AR_BIND_INT(s, 2, (int64_t)max),
        blog_post_read_row(&out[count], s));
}

int db_blog_post_count(struct node_db *ndb, const char *blog_name)
{
    sqlite3_stmt *s = NULL;
    if (!ndb || !ndb->open || !blog_name)
        return 0;
    AR_QUERY_COUNT_BOUND(ndb, s,
        "SELECT COUNT(DISTINCT slug) FROM blog_posts WHERE blog_name=?",
        AR_BIND_TEXT(s, 1, blog_name));
}

int db_blog_post_recent_summaries(struct node_db *ndb,
                                  const char *blog_name_or_null,
                                  struct db_blog_post_summary *out,
                                  size_t max)
{
    sqlite3_stmt *s = NULL;
    if (!ndb || !ndb->open || !out || max == 0)
        return 0;
    if (blog_name_or_null && blog_name_or_null[0]) {
        AR_QUERY_LIST(ndb, s,
            "SELECT " BLOG_POST_SUMMARY_COLUMNS
            " FROM blog_posts p WHERE blog_name=? "
            "AND NOT EXISTS (SELECT 1 FROM blog_posts p2 "
            "WHERE p2.blog_name=p.blog_name AND p2.slug=p.slug "
            "AND p2.event_id<p.event_id) "
            "ORDER BY event_created_at DESC,event_id LIMIT ?",
            out, max,
            AR_BIND_TEXT(s, 1, blog_name_or_null);
            AR_BIND_INT(s, 2, (int64_t)max),
            blog_summary_read_row(&out[count], s));
    }
    AR_QUERY_LIST(ndb, s,
        "SELECT " BLOG_POST_SUMMARY_COLUMNS " FROM blog_posts p "
        "WHERE NOT EXISTS (SELECT 1 FROM blog_posts p2 "
        "WHERE p2.blog_name=p.blog_name AND p2.slug=p.slug "
        "AND p2.event_id<p.event_id) "
        "ORDER BY event_created_at DESC,event_id LIMIT ?",
        out, max,
        AR_BIND_INT(s, 1, (int64_t)max),
        blog_summary_read_row(&out[count], s));
}

static bool blog_receipt_parent_matches(
    struct node_db *ndb,
    const struct db_blog_publication_receipt *receipt)
{
    struct db_blog_post post;
    if (!db_blog_post_find(ndb, receipt->event_id, &post))
        LOG_FAIL("blog_receipt", "belongs_to BlogPost is missing");
    if (strcmp(receipt->blog_name, post.blog_name) != 0 ||
        memcmp(receipt->author_key_id, post.author_key_id, 20) != 0)
        LOG_FAIL("blog_receipt", "duplicated parent identity drifted");
    return true;
}

static bool blog_receipt_identity_same(
    const struct db_blog_publication_receipt *a,
    const struct db_blog_publication_receipt *b)
{
    return memcmp(a->txid, b->txid, 32) == 0 &&
        memcmp(a->event_id, b->event_id, 32) == 0 &&
        strcmp(a->blog_name, b->blog_name) == 0 &&
        memcmp(a->author_key_id, b->author_key_id, 20) == 0 &&
        memcmp(a->znam_reg_txid, b->znam_reg_txid, 32) == 0;
}

bool db_blog_publication_receipt_save(
    struct node_db *ndb,
    const struct db_blog_publication_receipt *receipt)
{
    sqlite3_stmt *s = NULL;
    if (!ndb || !ndb->open || !receipt)
        LOG_FAIL("blog_receipt", "save requires an open database and receipt");
    if (!blog_receipt_parent_matches(ndb, receipt))
        return false; /* raw-return-ok:relationship-helper-already-logged */
    struct db_blog_publication_receipt existing;
    if (db_blog_publication_receipt_find_by_txid(ndb, receipt->txid,
                                                 &existing) &&
        !blog_receipt_identity_same(receipt, &existing))
        LOG_FAIL("blog_receipt", "txid cannot be re-parented");
    struct ar_callbacks *cbs = db_blog_publication_receipt_callbacks();
    AR_ADHOC_SAVE(ndb, s,
        "INSERT INTO blog_publication_receipts (" BLOG_RECEIPT_COLUMNS ") "
        "VALUES(" BLOG_RECEIPT_VALUES ") "
        "ON CONFLICT(txid) DO UPDATE SET "
        "block_hash=excluded.block_hash,block_height=excluded.block_height,"
        "status=excluded.status,observed_at=excluded.observed_at "
        "WHERE event_id=excluded.event_id AND blog_name=excluded.blog_name "
        "AND author_key_id=excluded.author_key_id "
        "AND znam_reg_txid=excluded.znam_reg_txid",
        cbs, "blog_publication_receipt", receipt,
        db_blog_publication_receipt_validate,
        blog_receipt_bind(s, receipt));
}

bool db_blog_publication_receipt_find_by_event(
    struct node_db *ndb, const uint8_t event_id[32],
    struct db_blog_publication_receipt *out)
{
    sqlite3_stmt *s = NULL;
    if (!ndb || !ndb->open || !event_id || !out)
        LOG_FAIL("blog_receipt", "find_by_event requires valid arguments");
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT " BLOG_RECEIPT_COLUMNS
        " FROM blog_publication_receipts WHERE event_id=? "
        "ORDER BY observed_at DESC LIMIT 1",
        AR_BIND_BLOB(s, 1, event_id, 32),
        blog_receipt_read_row(out, s));
}

bool db_blog_publication_receipt_find_by_txid(
    struct node_db *ndb, const uint8_t txid[32],
    struct db_blog_publication_receipt *out)
{
    sqlite3_stmt *s = NULL;
    if (!ndb || !ndb->open || !txid || !out)
        LOG_FAIL("blog_receipt", "find_by_txid requires valid arguments");
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT " BLOG_RECEIPT_COLUMNS
        " FROM blog_publication_receipts WHERE txid=? LIMIT 1",
        AR_BIND_BLOB(s, 1, txid, 32),
        blog_receipt_read_row(out, s));
}

int db_blog_post_publication_receipts(
    struct node_db *ndb, const uint8_t event_id[32],
    struct db_blog_publication_receipt *out, size_t max)
{
    sqlite3_stmt *s = NULL;
    if (!ndb || !ndb->open || !event_id || !out || max == 0)
        return 0;
    AR_QUERY_LIST(ndb, s,
        "SELECT " BLOG_RECEIPT_COLUMNS
        " FROM blog_publication_receipts WHERE event_id=? "
        "ORDER BY observed_at DESC,txid LIMIT ?",
        out, max,
        AR_BIND_BLOB(s, 1, event_id, 32);
        AR_BIND_INT(s, 2, (int64_t)max),
        blog_receipt_read_row(&out[count], s));
}

bool db_blog_publication_receipt_post(
    struct node_db *ndb,
    const struct db_blog_publication_receipt *receipt,
    struct db_blog_post *out)
{
    if (!receipt)
        LOG_FAIL("blog_receipt", "belongs_to requires a receipt");
    return db_blog_post_find(ndb, receipt->event_id, out);
}

bool db_blog_post_previous(struct node_db *ndb,
                           const struct db_blog_post *post,
                           struct db_blog_post *out)
{
    if (!ndb || !ndb->open || !post || !out || post->sequence <= 1)
        return false;
    return db_blog_post_find(ndb, post->previous_event_id, out);
}

bool db_blog_chain_anchor_find(struct node_db *ndb,
                               const uint8_t *script, size_t script_len,
                               struct db_blog_chain_anchor *out)
{
    sqlite3_stmt *s = NULL;
    if (!ndb || !ndb->open || !script || script_len == 0 || !out)
        LOG_FAIL("blog_anchor", "find requires valid arguments");
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT " BLOG_CHAIN_ANCHOR_COLUMNS " "
        "FROM op_returns o "
        "LEFT JOIN transactions t ON t.txid=o.txid "
        "LEFT JOIN blocks b ON b.height=t.block_height AND b.status>=3 "
        "WHERE o.script=? ORDER BY o.block_height DESC,o.txid LIMIT 1",
        AR_BIND_BLOB(s, 1, script, script_len),
        memset(out, 0, sizeof(*out));
        AR_READ_BLOB(s, BCA_IX_txid, out->txid, 32);
        out->op_return_height = AR_COL_INT(s, BCA_IX_op_return_height);
        out->has_transaction =
            sqlite3_column_type(s, BCA_IX_transaction_block_hash)
                != SQLITE_NULL;
        if (out->has_transaction) {
            AR_READ_BLOB(s, BCA_IX_transaction_block_hash,
                         out->transaction_block_hash, 32);
            out->transaction_block_height =
                AR_COL_INT(s, BCA_IX_transaction_block_height);
        } else {
            out->transaction_block_height = -1;
        }
        out->has_canonical_block =
            sqlite3_column_type(s, BCA_IX_canonical_block_hash)
                != SQLITE_NULL;
        if (out->has_canonical_block)
            AR_READ_BLOB(s, BCA_IX_canonical_block_hash,
                         out->canonical_block_hash, 32));
}
