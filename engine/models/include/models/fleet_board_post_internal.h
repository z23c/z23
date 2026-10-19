/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal helper contract shared between the fleet board store's source
 * files (fleet_board_post.c, fleet_board_post_scan.c, fleet_board_post_wiki.c,
 * fleet_board_post_quota.c). NOT part of the
 * public model API — callers must include models/fleet_board_post.h.
 *
 * The row layout is derived once, in fleet_board_post.c, from the field
 * list; these three helpers are how its sibling reads a whole row without
 * spelling that layout a second time. */

#ifndef ZCL_DB_MODEL_FLEET_BOARD_POST_INTERNAL_H
#define ZCL_DB_MODEL_FLEET_BOARD_POST_INTERNAL_H

#include "models/fleet_board_post.h"
#include "models/query_builder.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

/* Start `q` as a SELECT of every stored column of fleet_board_posts, in
 * the order fleet_board_row_read decodes them. */
void fleet_board_select_row(struct qb *q);

/* Decode the current row of a statement started by fleet_board_select_row
 * and verify the post's id and signature again. A row that fails is logged
 * and zeroed except for its arrival number, and false is returned. */
bool fleet_board_row_read(sqlite3_stmt *s, struct db_fleet_board_post *out);

/* Narrow `q` to rows still discoverable at `now`: TTL not run out, or a
 * wiki revision. */
void fleet_board_where_discoverable(struct qb *q, int64_t now);

/* Which per-key leg is spent. The window leg clears by itself; the stored
 * leg does not. */
enum board_quota {
    BOARD_QUOTA_OK,
    BOARD_QUOTA_WINDOW,
    BOARD_QUOTA_STORED,
    BOARD_QUOTA_ERROR,
};

/* Which per-key leg of the quota a new post would exceed. The wiki stored leg
 * is not decided here; see fleet_board_wiki_room. */
enum board_quota fleet_board_key_quota(struct node_db *ndb,
                                       const struct fleet_board_post *post,
                                       int64_t now);

/* One capped count of a key's rows in one scope, wiki rows only or every
 * other kind; `since < 0` drops the time floor. A query error returns false
 * rather than an empty count. Caller holds the board write lock. */
bool fleet_board_key_count(struct node_db *ndb, const uint8_t host_pubkey[32],
                           uint16_t scope, bool wiki, int64_t since,
                           int64_t *out);

/* Run a prepared aggregate that must return exactly one non-negative row. */
bool fleet_board_aggregate_checked(struct node_db *ndb, struct qb *q,
                                   int64_t *out);

/* The store's byte cap (a test seam may lower it). */
int64_t fleet_board_max_bytes(void);

/* The wiki ceilings in force: revisions per key per rolling window. */
int64_t fleet_board_wiki_window_max(void);

/* The wiki stored leg for `post`, decided under the board write lock: room
 * (FLEET_BOARD_OK, *evict false), the id of the key's own oldest superseded
 * revision to replace (OK, *evict true; failing that, its oldest plain
 * revision whose ttl has elapsed at `now`), or FLEET_BOARD_ERR_WIKI_FULL.
 * Other kinds and legacy-scope posts always get OK. */
enum fleet_board_result fleet_board_wiki_room(
    struct node_db *ndb, const struct fleet_board_post *post, int64_t now,
    bool *evict, uint8_t victim[32]);

/* True when `body_bytes` more of wiki rows still fit in half the byte cap. */
bool fleet_board_wiki_bytes_fit(struct node_db *ndb, int64_t body_bytes);

/* The node-wide cap on wiki replacements: whether one more may run at
 * `now` (the ingest clock), and the record of one that did. Caller holds
 * the board write lock. */
bool fleet_board_wiki_evict_allowed(int64_t now);
void fleet_board_wiki_evict_note(int64_t now);

/* Mutation sibling shares the canonical writer and AR insertion. The caller
 * owns the board lock and, for remove/append, its one database transaction. */
void fleet_board_write_lock(void);
void fleet_board_write_unlock(void);
int64_t fleet_board_arrival_checkpoint(void);
void fleet_board_arrival_restore(int64_t high);
enum fleet_board_result fleet_board_ingest_prepare(struct node_db *ndb,
    const struct fleet_board_post *post, int64_t now, size_t *body_len, bool *known);
enum fleet_board_result fleet_board_append_record(struct node_db *ndb,
    const struct fleet_board_post *post, int64_t now, size_t body_len);
bool fleet_board_remove_and_relink(struct node_db *ndb,
    const struct fleet_board_post *post, const uint8_t victim[32]);
#endif /* ZCL_DB_MODEL_FLEET_BOARD_POST_INTERNAL_H */
