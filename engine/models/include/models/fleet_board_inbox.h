/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The inbox scan over the one board store: rows that answer an agent's own
 * posts, or that may be mail addressed to it, in this store's arrival order.
 * It is a query over fleet_board_posts and nothing else; there is no inbox
 * table. Every row handed on verified again first, exactly as a list row. */

#ifndef ZCL_DB_MODEL_FLEET_BOARD_INBOX_H
#define ZCL_DB_MODEL_FLEET_BOARD_INBOX_H

#include "models/fleet_board_post.h"

#include <stdbool.h>
#include <stdint.h>

/* The receipt a board-carried mail row travels under. */
#define FLEET_BOARD_MAIL_RECEIPT "z23.mail.v1"

struct fleet_board_inbox_query {
    const char *agent;   /* the reader's label: required, exact match */
    int64_t after;       /* arrival cursor, exclusive; 0 = from the start */
    unsigned limit;      /* candidate rows read at most (1..FLEET_BOARD_LIST_MAX) */
    /* Thread mode: only rows whose ref is this post (and not by `agent`). */
    bool ref_set;
    uint8_t ref[32];
};

/* Candidate rows with arrival > q->after, ascending, never written by
 * q->agent: a row whose ref names a stored post by q->agent, or a mail-
 * receipt note (the caller decides whether its `to` names the reader). In
 * thread mode only rows whose ref is q->ref. At most q->limit candidates
 * are read; `*scanned_out` ends at the arrival of the last one read, so a
 * caller that resumes from it repeats nothing and skips nothing. Returns the
 * rows the visitor accepted, or -1 when the store could not be read. */
int db_fleet_board_inbox_scan(struct node_db *ndb, int64_t now,
                              const struct fleet_board_inbox_query *q,
                              db_fleet_board_row_visit visit, void *ctx,
                              int64_t *scanned_out);

/* Bumped after every stored row (any scope or kind), so a waiter can sleep
 * on a counter instead of reading the store. Process-local. */
uint64_t db_fleet_board_arrival_generation(void);

#endif /* ZCL_DB_MODEL_FLEET_BOARD_INBOX_H */
