/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * BlogPost + BlogPublicationReceipt ActiveRecord models.
 *
 * BlogPost is an immutable, wallet-signed application event. A receipt is a
 * reorg-aware observation that an exact ZBLG OP_RETURN anchor appeared in the
 * full node's transaction/block projections. The post body is never placed on
 * chain; event_id commits to it and is the durable publication identity. */

#ifndef ZCL_DB_MODEL_BLOG_POST_H
#define ZCL_DB_MODEL_BLOG_POST_H

#include "models/activerecord.h"
#include "models/database.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    BLOG_NAME_MAX = 63,
    BLOG_SLUG_MAX = 80,
    BLOG_TITLE_MAX = 160,
    BLOG_BODY_MAX = 16384,
    BLOG_AUTHOR_ADDRESS_MAX = 95,
    BLOG_SIGNATURE_MAX = 72,
};

enum blog_publication_status {
    BLOG_PUBLICATION_UNRESOLVED = 0,
    BLOG_PUBLICATION_CONFIRMED = 1,
    BLOG_PUBLICATION_ORPHANED = 2,
};

struct db_blog_post {
    uint8_t event_id[32];
    char blog_name[BLOG_NAME_MAX + 1];
    char slug[BLOG_SLUG_MAX + 1];
    char title[BLOG_TITLE_MAX + 1];
    char body[BLOG_BODY_MAX + 1];
    uint8_t author_key_id[20];
    uint8_t author_pubkey[33];
    char author_address[BLOG_AUTHOR_ADDRESS_MAX + 1];
    uint8_t chain_id[32];
    uint64_t sequence;
    uint8_t previous_event_id[32];
    int64_t event_created_at;
    uint8_t signature[BLOG_SIGNATURE_MAX];
    uint32_t signature_len;
    int64_t stored_at;
};

struct db_blog_publication_receipt {
    uint8_t txid[32];
    uint8_t event_id[32];
    char blog_name[BLOG_NAME_MAX + 1];
    uint8_t author_key_id[20];
    uint8_t znam_reg_txid[32];
    uint8_t block_hash[32];
    int64_t block_height;
    enum blog_publication_status status;
    int64_t observed_at;
};

/* Compact index projection: no 16 KiB body/signature payload per row. */
struct db_blog_post_summary {
    uint8_t event_id[32];
    char blog_name[BLOG_NAME_MAX + 1];
    char slug[BLOG_SLUG_MAX + 1];
    char title[BLOG_TITLE_MAX + 1];
    char author_address[BLOG_AUTHOR_ADDRESS_MAX + 1];
    uint64_t sequence;
    int64_t event_created_at;
};

/* Read-only join result over op_returns -> transactions -> connected blocks.
 * `has_transaction=false` means the explorer retained an OP_RETURN projection
 * without the transaction index row. `has_canonical_block=false` means there
 * is currently no connected block at that height; neither case is confirmation. */
struct db_blog_chain_anchor {
    uint8_t txid[32];
    int64_t op_return_height;
    bool has_transaction;
    uint8_t transaction_block_hash[32];
    int64_t transaction_block_height;
    bool has_canonical_block;
    uint8_t canonical_block_hash[32];
};

struct ar_callbacks *db_blog_post_callbacks(void);
struct ar_callbacks *db_blog_publication_receipt_callbacks(void);

bool db_blog_post_validate(const struct db_blog_post *post,
                           struct ar_errors *errors);
bool db_blog_publication_receipt_validate(
    const struct db_blog_publication_receipt *receipt,
    struct ar_errors *errors);

bool db_blog_post_save(struct node_db *ndb, const struct db_blog_post *post);
bool db_blog_post_find(struct node_db *ndb, const uint8_t event_id[32],
                       struct db_blog_post *out);
bool db_blog_post_find_by_slug(struct node_db *ndb, const char *blog_name,
                               const char *slug, struct db_blog_post *out);
int db_blog_post_list(struct node_db *ndb, const char *blog_name,
                      struct db_blog_post *out, size_t max);
int db_blog_post_count(struct node_db *ndb, const char *blog_name);
int db_blog_post_recent_summaries(struct node_db *ndb,
                                  const char *blog_name_or_null,
                                  struct db_blog_post_summary *out,
                                  size_t max);

/* Canonical field validators are shared by the pre-sign service gate and the
 * ActiveRecord row validator so malformed content never reaches the wallet. */
bool db_blog_slug_valid(const char *slug);
bool db_blog_title_valid(const char *title);
bool db_blog_body_valid(const char *body);
bool db_blog_sequence_shape_valid(uint64_t sequence,
                                  const uint8_t previous_event_id[32]);

bool db_blog_publication_receipt_save(
    struct node_db *ndb,
    const struct db_blog_publication_receipt *receipt);
bool db_blog_publication_receipt_find_by_event(
    struct node_db *ndb, const uint8_t event_id[32],
    struct db_blog_publication_receipt *out);
bool db_blog_publication_receipt_find_by_txid(
    struct node_db *ndb, const uint8_t txid[32],
    struct db_blog_publication_receipt *out);

/* ── Relationships ─────────────────────────────────────────────────── */

/* BlogPost has_many :publication_receipts. */
int db_blog_post_publication_receipts(
    struct node_db *ndb, const uint8_t event_id[32],
    struct db_blog_publication_receipt *out, size_t max);

/* BlogPublicationReceipt belongs_to :blog_post. */
bool db_blog_publication_receipt_post(
    struct node_db *ndb,
    const struct db_blog_publication_receipt *receipt,
    struct db_blog_post *out);

/* BlogPost belongs_to :previous_post for sequence > 1. */
bool db_blog_post_previous(struct node_db *ndb,
                           const struct db_blog_post *post,
                           struct db_blog_post *out);

/* Exact-script lookup. This deliberately does not trust op_returns.height:
 * confirmation requires a transaction row and the same block hash at the
 * connected status>=3 height. */
bool db_blog_chain_anchor_find(struct node_db *ndb,
                               const uint8_t *script, size_t script_len,
                               struct db_blog_chain_anchor *out);

#endif /* ZCL_DB_MODEL_BLOG_POST_H */
