/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_DB_MODEL_ZMSG_H
#define ZCL_DB_MODEL_ZMSG_H

#include "models/database.h"
#include "models/activerecord.h"
#include "net/zmsg.h"
#include <stdbool.h>

/* ActiveRecord model: Zmsg (encrypted P2P messages)
 *
 * The record type is `struct zmsg_message` (defined in net/zmsg.h) —
 * the same struct the P2P layer, the controllers, and the SQLite
 * persistence all use. The validator + callbacks live in
 * app/models/src/zmsg.c.
 *
 * Validation (db_zmsg_validate):
 *   - msg_id:    non-zero (SHA3 hash must be computed)
 *   - sender:    non-empty
 *   - recipient: non-empty
 *   - body:      non-empty, length ≤ ZMSG_MAX_BODY
 *   - direction: ZMSG_INBOUND or ZMSG_OUTBOUND
 *   - channel:   ZMSG_CHANNEL_ONCHAIN or ZMSG_CHANNEL_P2P
 *   - timestamp: non-negative
 */

struct ar_callbacks *db_zmsg_callbacks(void);
bool db_zmsg_validate(const struct zmsg_message *msg,
                      struct ar_errors *errors);
bool db_zmsg_save(struct node_db *ndb, const struct zmsg_message *msg);
int db_zmsg_list(struct node_db *ndb, struct zmsg_message *out,
                 size_t max, bool unread_only);
/* Uncapped total behind the db_zmsg_list window under the same unread
 * filter. -1 only when the store is unreadable. */
int db_zmsg_count(struct node_db *ndb, bool unread_only);

#ifdef ZCL_TESTING
/* Deterministic store-step fault seam for the uncapped count helper.
 * NULL restores the production readonly step. */
void db_zmsg_test_set_count_step(int (*step_fn)(void *stmt));
#endif
bool db_zmsg_mark_read(struct node_db *ndb, const uint8_t msg_id[32]);

/* Ingest a decrypted Sapling note memo as an inbound on-chain ZMSG.
 *
 * Parses `memo` (512 bytes) with zmsg_memo_decode; if it is a ZMSG, builds an
 * inbound message (channel = onchain, txid stamped) with a DETERMINISTIC
 * msg_id = SHA3(txid || memo) so a re-scan / reorg re-ingest maps to the same
 * id, then persists it to the in-memory store AND (if `ndb` non-NULL) SQLite —
 * both dedup by msg_id. Returns true when a ZMSG was ingested, false quietly
 * when the memo is not a ZMSG (the common case) or on a NULL arg. Called from
 * the note-decrypt path (app/jobs/src/tip_finalize_post_step.c). */
bool zmsg_ingest_onchain_note(struct node_db *ndb,
                              const uint8_t memo[ZMSG_MEMO_LEN],
                              const uint8_t txid[32]);

#endif
