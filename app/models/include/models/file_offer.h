/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_DB_MODEL_FILE_OFFER_H
#define ZCL_DB_MODEL_FILE_OFFER_H

#include "models/database.h"
#include "models/activerecord.h"
#include "net/file_market.h"
#include <stdbool.h>

/* ActiveRecord model: FileOffer (ZCL Market gossip)
 *
 * The record type is `struct file_offer` (defined in
 * net/file_market.h) — the same struct the P2P gossip layer and
 * SQLite persistence both use. The validator + callbacks live in
 * app/models/src/file_offer.c.
 *
 * Validation (db_file_offer_validate):
 *   - root_hash:    must be non-zero (a SHA3-256 manifest hash)
 *   - filename:     non-empty
 *   - size_bytes:   non-zero (no zero-size files in the market)
 *   - num_chunks:   positive (must cover at least one chunk)
 *   - price_per_mb: non-negative
 *   - paid offers:  canonical v1 seller signature, network, payment address,
 *                   endpoint, nonce, validity window, and offer id required
 *   - free offers:  legacy ROM-artifact compatibility only (auth_version=0)
 *   - last_seen:    non-negative
 *   - ttl:          1..FILE_MARKET_MAX_TTL inclusive
 */

struct ar_callbacks *db_file_offer_callbacks(void);
bool db_file_offer_validate(const struct file_offer *offer,
                            struct ar_errors *errors);
bool db_file_offer_save(struct node_db *ndb,
                        const struct file_offer *offer);
int db_file_offer_list(struct node_db *ndb,
                       struct file_offer *out, size_t max);
bool db_file_offer_find(struct node_db *ndb,
                        const uint8_t root_hash[32],
                        struct file_offer *out);
bool db_file_offer_find_by_id(struct node_db *ndb,
                              const uint8_t offer_id[32],
                              struct file_offer *out);
int db_file_offer_prune(struct node_db *ndb, int64_t max_age);

/* Compensating delete for a locally created offer whose later atomic step
 * failed (e.g. private content binding). Returns false on a DB error. */
bool db_file_offer_delete(struct node_db *ndb, const uint8_t root_hash[32]);

/* Local-only moderation state (schema v65 review_state column). This
 * metadata is per-node curation state: never gossiped, never part of the
 * signed offer wire, and never a deletion — a hidden offer stays stored
 * and keeps its signed wire; under the boot-default profile the node just
 * neither lists, serves, nor relays it. Values: unreviewed (ingest
 * default), reviewed_ok, sensitive. */
bool db_file_offer_get_review_state(struct node_db *ndb,
                                    const uint8_t root_hash[32],
                                    char *out, size_t out_len);
/* The node's own curation mark, addressed by signed offer_id. False when
 * no signed offer carries that id (or on a DB error). */
bool db_file_offer_set_review_state(struct node_db *ndb,
                                    const uint8_t offer_id[32],
                                    const char *review_state);
/* Atomic plan/commit compare-and-set. The expected mark is checked by the
 * same conditional UPDATE that writes the replacement, and UPDATED is
 * returned only when SQLite proves exactly one changed row. */
enum db_file_offer_review_cas_result {
    DB_FILE_OFFER_REVIEW_CAS_ERROR = -1,
    DB_FILE_OFFER_REVIEW_CAS_STALE = 0,
    DB_FILE_OFFER_REVIEW_CAS_UPDATED = 1
};
enum db_file_offer_review_cas_result
db_file_offer_compare_set_review_state(struct node_db *ndb,
                                       const uint8_t offer_id[32],
                                       const char *expected_review_state,
                                       const char *next_review_state);
/* Per-state row counts, indexed by enum market_review_state order
 * (unreviewed, reviewed_ok, sensitive). False on a DB error. */
bool db_file_offer_review_counts(struct node_db *ndb, int64_t counts[3]);

#endif
