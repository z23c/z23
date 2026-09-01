/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Signed seller fulfillment claims for buyer-posted shop wants (Slice E).
 *
 * A fulfillment says "these content-addressed bytes answer this want". It
 * does not accept an award, move ZCL, mint ZC23, or claim that a build/fuzz/
 * benchmark passed merely because the seller says so. The signed wire binds
 * the want, the direct SHA3-256 of the delivered bytes, the content.v2 CAS
 * manifest root, and optional receipt ids that the controller independently
 * re-verifies against node-owned evidence.
 *
 * Fixed wire layout (little-endian integers):
 *   magic               8   {'Z','S','H','P','F','L','\r','\n'}
 *   schema_version      2   == SHOP_FULFILL_VERSION
 *   want_id            32
 *   seller_pubkey      32   Ed25519 signer
 *   nonce               8   nonzero replay boundary
 *   artifact_root      32   SHA3-256(delivered bytes)
 *   content_root       32   content.v2 CAS manifest root
 *   build_receipt_id   32   all-zero means absent
 *   fuzz_receipt_id    32   all-zero means absent
 *   bench_receipt_id   32   all-zero means absent
 *   issued_unix         8
 *   expires_unix        8
 *   seller_signature   64   Ed25519 over the body root
 *
 * Local-only projection columns (review_state, withdrawn_unix, posted_unix)
 * never enter the wire. review_state has exactly the file_offers/shop_wants
 * community-content-moderation semantics: local curation, never gossip.
 */

#ifndef ZCL_DB_MODEL_SHOP_FULFILL_H
#define ZCL_DB_MODEL_SHOP_FULFILL_H

#include "models/activerecord.h"
#include "models/database.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SHOP_FULFILL_VERSION 1u
#define SHOP_FULFILL_DOMAIN "zcl.shop.fulfill.v1"
#define SHOP_FULFILL_ROOT_DOMAIN "zcl.shop.fulfill.root.v1"
#define SHOP_FULFILL_BODY_BYTES 258u
#define SHOP_FULFILL_WIRE_BYTES (SHOP_FULFILL_BODY_BYTES + 64u)
#define SHOP_FULFILL_MAX_LIFETIME_SECS (30LL * 24LL * 60LL * 60LL)
#define SHOP_FULFILL_QUERY_CAP 64u

enum shop_fulfill_error {
    SHOP_FULFILL_OK = 0,
    SHOP_FULFILL_ERR_NULL,
    SHOP_FULFILL_ERR_VERSION,
    SHOP_FULFILL_ERR_WIRE_SIZE,
    SHOP_FULFILL_ERR_WIRE_MAGIC,
    SHOP_FULFILL_ERR_WANT_ZERO,
    SHOP_FULFILL_ERR_PUBKEY_ZERO,
    SHOP_FULFILL_ERR_NONCE,
    SHOP_FULFILL_ERR_ARTIFACT_ZERO,
    SHOP_FULFILL_ERR_CONTENT_ZERO,
    SHOP_FULFILL_ERR_TIME_ORDER,
    SHOP_FULFILL_ERR_LIFETIME,
    SHOP_FULFILL_ERR_SIGNATURE,
    SHOP_FULFILL_ERR_KEY_MISMATCH,
};

const char *shop_fulfill_error_string(enum shop_fulfill_error error);

struct shop_fulfill_v1 {
    uint16_t schema_version;
    uint8_t want_id[32];
    uint8_t seller_pubkey[32];
    uint64_t nonce;
    uint8_t artifact_root[32];
    uint8_t content_root[32];
    uint8_t build_receipt_id[32];
    uint8_t fuzz_receipt_id[32];
    uint8_t bench_receipt_id[32];
    int64_t issued_unix;
    int64_t expires_unix;
    uint8_t seller_signature[64];
};

struct shop_fulfill {
    struct shop_fulfill_v1 fulfill;
    uint8_t fulfill_id[32];
    int review_state;          /* enum market_review_state; local only */
    int64_t withdrawn_unix;    /* 0 = active */
    int64_t posted_unix;       /* this node's first observation */
};

enum shop_fulfill_error shop_fulfill_validate(
    const struct shop_fulfill_v1 *fulfill);
enum shop_fulfill_error shop_fulfill_encode(
    const struct shop_fulfill_v1 *fulfill,
    uint8_t out[SHOP_FULFILL_WIRE_BYTES]);
enum shop_fulfill_error shop_fulfill_decode(
    const uint8_t *wire, size_t wire_len, struct shop_fulfill_v1 *out);
enum shop_fulfill_error shop_fulfill_body_root(
    const struct shop_fulfill_v1 *fulfill, uint8_t out[32]);
enum shop_fulfill_error shop_fulfill_root(
    const struct shop_fulfill_v1 *fulfill, uint8_t out[32]);
enum shop_fulfill_error shop_fulfill_seal(
    struct shop_fulfill_v1 *fulfill, const uint8_t seller_secret[32]);
enum shop_fulfill_error shop_fulfill_verify(
    const struct shop_fulfill_v1 *fulfill);

struct ar_callbacks *db_shop_fulfill_callbacks(void);
bool db_shop_fulfill_validate(const struct shop_fulfill *row,
                              struct ar_errors *errors);
bool db_shop_fulfill_save(struct node_db *ndb,
                          const struct shop_fulfill *row);
bool db_shop_fulfill_find(struct node_db *ndb,
                          const uint8_t fulfill_id[32],
                          struct shop_fulfill *out);
bool db_shop_fulfill_find_seller_nonce(struct node_db *ndb,
                                       const uint8_t seller_pubkey[32],
                                       uint64_t nonce,
                                       struct shop_fulfill *out);
int db_shop_fulfill_list_for_want(struct node_db *ndb,
                                  const uint8_t want_id[32],
                                  int64_t now_unix, bool include_closed,
                                  struct shop_fulfill *out, size_t max);
/* Same match set as db_shop_fulfill_list_for_want, counted without the
 * fetch window: a board total is what the want has waiting, not however
 * many rows fit the query cap. -1 on a store error. (The unfiltered
 * db_shop_fulfill_count_for_want below stays an all-time fact for the
 * status leaf — different question, both honest.) */
int db_shop_fulfill_list_count_for_want(struct node_db *ndb,
                                        const uint8_t want_id[32],
                                        int64_t now_unix,
                                        bool include_closed);
int64_t db_shop_fulfill_count_for_want(struct node_db *ndb,
                                       const uint8_t want_id[32]);
bool db_shop_fulfill_mark_withdrawn(struct node_db *ndb,
                                    const uint8_t fulfill_id[32],
                                    int64_t withdrawn_unix);
bool db_shop_fulfill_set_review_state(struct node_db *ndb,
                                      const uint8_t fulfill_id[32],
                                      const char *review_state);

#endif /* ZCL_DB_MODEL_SHOP_FULFILL_H */
