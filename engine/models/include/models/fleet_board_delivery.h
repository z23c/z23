/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fleet board delivery record (schema v93): what each paired peer answered
 * when this box pushed it one of its own posts. One row per (post, peer),
 * replaced by the newest answer, and the table keeps only the newest
 * FLEET_BOARD_DELIVERY_KEEP rows. It is LOCAL evidence of a receipt, not an
 * authority: a "stored" row says the peer's receipt said so; the pull is
 * still the repair for everything that was not stored. Nothing in consensus
 * or in the board's admission reads it. */

#ifndef ZCL_DB_MODEL_FLEET_BOARD_DELIVERY_H
#define ZCL_DB_MODEL_FLEET_BOARD_DELIVERY_H

#include "models/activerecord.h"
#include "models/database.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    /* Rows kept across every post and peer; the oldest answers go first. */
    FLEET_BOARD_DELIVERY_KEEP = 4096,
    /* A reason is a short machine name (a board result or push code). */
    FLEET_BOARD_DELIVERY_REASON_MAX = 40,
    /* Peers one delivery read returns for one post. */
    FLEET_BOARD_DELIVERY_PEERS_MAX = 64,
};

/* The four answers a peer can give, in the push receipt's own order, and
 * UNKNOWN: no per-record answer came (no receipt by the deadline, a peer
 * that cannot take pushes, or a committed receipt that named no record), so
 * the peer may or may not hold the post. */
enum fleet_board_delivery_verdict {
    FLEET_BOARD_DELIVERY_STORED = 0,   /* the peer stored it now */
    FLEET_BOARD_DELIVERY_HELD = 1,     /* the peer already had it */
    FLEET_BOARD_DELIVERY_DEFERRED = 2, /* not now; the pull carries it later */
    FLEET_BOARD_DELIVERY_REFUSED = 3,  /* the peer will not keep it */
    FLEET_BOARD_DELIVERY_UNKNOWN = 4,  /* no answer came: state unknown */
    FLEET_BOARD_DELIVERY_VERDICTS
};

struct db_fleet_board_delivery {
    uint8_t post_id[32];
    uint8_t peer[32];   /* the peer's Noise static key: who answered */
    int64_t verdict;    /* enum fleet_board_delivery_verdict */
    char reason[FLEET_BOARD_DELIVERY_REASON_MAX + 1];
    int64_t at;         /* Unix seconds this box recorded the answer */
};

struct ar_callbacks *db_fleet_board_delivery_callbacks(void);

const char *fleet_board_delivery_verdict_name(int64_t verdict);

bool db_fleet_board_delivery_validate(const struct db_fleet_board_delivery *d,
                                      struct ar_errors *errors);

/* Insert or replace the answer for (post_id, peer). A DEFERRED or UNKNOWN
 * answer never replaces a recorded STORED or HELD one: the peer said it has
 * the post, and a later "not now" or silence does not take that back (the
 * call succeeds and keeps the known row). Refuses (false) while a
 * transaction is open on the handle, so a delivery note never joins somebody
 * else's transaction; the caller keeps the note and tries again later. */
bool db_fleet_board_delivery_save(struct node_db *ndb,
                                  const struct db_fleet_board_delivery *d);

/* Keep the newest `keep` rows by answer time (ties at the cut survive). */
bool db_fleet_board_delivery_prune(struct node_db *ndb, int keep);

int db_fleet_board_delivery_count(struct node_db *ndb);

/* The answers recorded for one post, newest first, at most `max`. Returns
 * the rows written, or -1 when the table could not be read. */
int db_fleet_board_delivery_for_post(struct node_db *ndb,
                                     const uint8_t post_id[32],
                                     struct db_fleet_board_delivery *out,
                                     size_t max);

#endif /* ZCL_DB_MODEL_FLEET_BOARD_DELIVERY_H */
