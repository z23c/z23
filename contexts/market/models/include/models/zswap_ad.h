/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_DB_MODEL_ZSWAP_AD_H
#define ZCL_DB_MODEL_ZSWAP_AD_H

#include "models/database.h"
#include "models/activerecord.h"
#include "zswap/zswap_yardsale.h"
#include <stdbool.h>

/* ActiveRecord model: ZswapAd — the persisted half of the zswap YARDSALE.
 *
 * The record type is `struct zswap_yardsale_ad` (defined in
 * zswap/zswap_yardsale.h) — the same struct the gossip cache and the SQLite
 * projection both use, so the two layers agree on the at-rest
 * representation. The table `zswap_ads` (migration v48) stores one row per
 * verified signed ad: quote_root is the dedup id, wire is the exact
 * 210-byte zswap_quote.v1 the seller signed (the "verify evidence valid when
 * created" record — stored because it was valid at ingress), and the
 * first/last-seen/seen_count columns are local gossip bookkeeping.
 *
 * This is a rebuildable projection of ephemeral gossip, never a market or
 * a matching engine: queries filter by now (an expired sign stops being
 * browseable) and db_zswap_ad_prune_expired() reclaims rows whose validity
 * window has closed.
 *
 * Validation (db_zswap_ad_validate):
 *   - quote_root / seller_pubkey / token_id: non-zero
 *   - token_amount, zcl_amount: positive
 *   - expires_unix > issued_unix, lifetime within the structural cap
 *   - seen_count >= 1, first_seen_unix <= last_seen_unix
 */

struct ar_callbacks *db_zswap_ad_callbacks(void);
bool db_zswap_ad_validate(const struct zswap_yardsale_ad *ad,
                          struct ar_errors *errors);
/* Upsert on quote_root: a new ad inserts; a byte-identical re-gossip bumps
 * last_seen_unix and seen_count in place (first_seen_unix is kept). */
bool db_zswap_ad_save(struct node_db *ndb,
                      const struct zswap_yardsale_ad *ad);
bool db_zswap_ad_find(struct node_db *ndb,
                      const uint8_t quote_root[32],
                      struct zswap_yardsale_ad *out);
/* Explicit expiry maintenance: delete rows whose window has closed. */
int db_zswap_ad_prune_expired(struct node_db *ndb, int64_t now_unix);
/* Browse projection: ads for token_id still valid at now_unix (expired rows
 * are filtered, not deleted), sorted by ascending unit price with integer
 * math only (zswap_quote_unit_price_cmp), bounded to max results. */
int db_zswap_ad_best_for_token(struct node_db *ndb,
                               const uint8_t token_id[32],
                               int64_t now_unix,
                               struct zswap_yardsale_ad *out, size_t max);

/* Browse-everything sibling of db_zswap_ad_best_for_token: every live sign
 * (all tokens) still valid at now_unix, same integer-only unit-price
 * ordering, bounded to max results. Backs the /yardsale index page. */
int db_zswap_ad_list_live(struct node_db *ndb,
                          int64_t now_unix,
                          struct zswap_yardsale_ad *out, size_t max);

#endif
