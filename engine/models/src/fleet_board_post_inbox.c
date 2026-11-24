/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fleet board store: the inbox scan and the arrival generation. See
 * models/fleet_board_inbox.h. The candidate predicate runs in SQL over the
 * arrival and ref indexes, so a call reads and re-verifies only rows that can
 * concern the reader, never the whole board.
 *
 * ar-validate-skip:read-only-scans — this file never writes a row; every
 * write, and its validation, is in fleet_board_post.c. */

#include "models/fleet_board_inbox.h"
#include "models/fleet_board_post_internal.h"

#include "base/safe_alloc.h"
#include "models/activerecord.h"
#include "models/query_builder.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

static _Atomic uint64_t s_board_arrival_gen;

void fleet_board_arrival_bump(void)
{
    atomic_fetch_add_explicit(&s_board_arrival_gen, 1, memory_order_release);
}

uint64_t db_fleet_board_arrival_generation(void)
{
    return atomic_load_explicit(&s_board_arrival_gen, memory_order_acquire);
}

/* The candidate predicate: a reply to one of the reader's posts, or a mail
 * note; in thread mode, a reply to the one post named. */
static void inbox_where(struct qb *q, struct qb *sub,
                        const struct fleet_board_inbox_query *iq)
{
    if (iq->ref_set) {
        qb_where_blob(q, QB_C_fleet_board_posts_ref, QB_EQ, iq->ref, 32);
        return;
    }
    qb_select(sub, QB_T_fleet_board_posts);
    qb_select_column(sub, QB_C_fleet_board_posts_id);
    qb_where_text(sub, QB_C_fleet_board_posts_agent, QB_EQ, iq->agent);
    qb_group_begin(q, QB_OR);
    qb_where_in_select(q, QB_C_fleet_board_posts_ref, false, sub);
    qb_where_text(q, QB_C_fleet_board_posts_receipt, QB_EQ,
                  FLEET_BOARD_MAIL_RECEIPT);
    qb_group_end(q);
}

static int inbox_walk(struct node_db *ndb, sqlite3_stmt *s,
                      struct db_fleet_board_post *row,
                      db_fleet_board_row_visit visit, void *ctx,
                      int64_t *scanned)
{
    int visited = 0;
    enum zcl_step step;
    while ((step = ar_step_checked(s, "fleet_board.inbox scan", NULL)) ==
           ZCL_STEP_ROW) {
        if (fleet_board_row_read(s, row)) {
            if (!visit(row, ctx))
                return visited;
            visited++;
        }
        *scanned = row->arrival;
    }
    if (step != ZCL_STEP_ERROR)
        return visited;
    LOG_WARN("fleet.board", "inbox scan failed: %s", sqlite3_errmsg(ndb->db));
    return -1;
}

int db_fleet_board_inbox_scan(struct node_db *ndb, int64_t now,
                              const struct fleet_board_inbox_query *iq,
                              db_fleet_board_row_visit visit, void *ctx,
                              int64_t *scanned_out)
{
    if (!ndb || !ndb->open || !iq || !iq->agent || !iq->agent[0] || !visit ||
        !scanned_out || iq->after < 0 || iq->limit == 0 ||
        iq->limit > FLEET_BOARD_LIST_MAX)
        return -1;
    *scanned_out = iq->after;
    struct qb q, sub;
    fleet_board_select_row(&q);
    qb_where_int(&q, QB_C_fleet_board_posts_arrival, QB_GT, iq->after);
    fleet_board_where_discoverable(&q, now);
    qb_where_text(&q, QB_C_fleet_board_posts_agent, QB_NE, iq->agent);
    inbox_where(&q, &sub, iq);
    qb_order_by(&q, QB_C_fleet_board_posts_arrival, QB_ASC);
    qb_limit(&q, (int64_t)iq->limit);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s)) {
        LOG_WARN("fleet.board", "inbox scan prepare failed: %s", qb_error(&q));
        return -1;
    }
    struct db_fleet_board_post *row =
        zcl_calloc(1, sizeof(*row), "fleet_board.inbox_scan");
    int64_t scanned = iq->after;
    int visited = row ? inbox_walk(ndb, s, row, visit, ctx, &scanned) : -1;
    sqlite3_finalize(s);
    free(row);
    if (visited >= 0)
        *scanned_out = scanned;
    return visited;
}
