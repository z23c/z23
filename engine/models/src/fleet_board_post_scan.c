/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fleet board store: the whole-table scans that page or enumerate rows rather
 * than find one — the FLEET-scope page the paired pull serves, the bare lines
 * under one fleet agent, and the list of keys this node is storing posts from.
 * See models/fleet_board_post.h. Rows are read through the shared row reader in
 * fleet_board_post.c, so every row handed on here verified again first; the bare
 * lines are the one exception, and their caller reads a row by id to act on it.
 *
 * ar-validate-skip:read-only-scans — this file never writes a row; every
 * write, and its validation, is in fleet_board_post.c. */

#include "models/fleet_board_post.h"
#include "models/fleet_board_post_internal.h"

#include "base/safe_alloc.h"
#include "models/activerecord.h"
#include "models/query_builder.h"
#include "util/log_macros.h"

#include <stdlib.h>
#include <string.h>

/* Step the prepared page, handing each verified row to `visit`. A row that
 * no longer verifies is logged by fleet_board_row_read and consumed without
 * being handed on — it will never verify later, and it must not wedge every row
 * behind it. Returns the rows visited, or -1 when the read itself failed;
 * `*scanned` ends at the last row consumed. */
static int board_fleet_page_walk(struct node_db *ndb, sqlite3_stmt *s,
                                 struct db_fleet_board_post *row,
                                 db_fleet_board_row_visit visit, void *ctx,
                                 int64_t *scanned)
{
    int visited = 0;
    while (AR_STEP_ROW(s)) {
        if (fleet_board_row_read(s, row)) {
            if (!visit(row, ctx))
                return visited;
            visited++;
        }
        *scanned = row->arrival;
    }
    if (sqlite3_reset(s) == SQLITE_OK)
        return visited;
    LOG_WARN("fleet.board", "fleet page read failed: %s",
             sqlite3_errmsg(ndb->db));
    return -1;
}

int db_fleet_board_fleet_after(struct node_db *ndb, int64_t now,
                               int64_t after_arrival, unsigned limit,
                               db_fleet_board_row_visit visit, void *ctx,
                               int64_t *scanned_out)
{
    if (!ndb || !ndb->open || !visit || !scanned_out || after_arrival < 0 ||
        limit == 0)
        return -1;
    *scanned_out = after_arrival;
    struct qb q;
    fleet_board_select_row(&q);
    qb_where_int(&q, QB_C_fleet_board_posts_arrival, QB_GT, after_arrival);
    qb_where_int(&q, QB_C_fleet_board_posts_scope, QB_EQ,
                 FLEET_BOARD_SCOPE_FLEET);
    fleet_board_where_discoverable(&q, now);
    qb_order_by(&q, QB_C_fleet_board_posts_arrival, QB_ASC);
    qb_limit(&q, (int64_t)limit);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s)) {
        LOG_WARN("fleet.board", "fleet page prepare failed: %s", qb_error(&q));
        return -1;
    }
    /* One row at a time on the heap: a wiki-sized row does not belong on
     * whatever thread stack a stream callback happens to run on. */
    struct db_fleet_board_post *row =
        zcl_calloc(1, sizeof(*row), "fleet_board.fleet_page");
    int64_t scanned = after_arrival;
    int visited = row ? board_fleet_page_walk(ndb, s, row, visit, ctx,
                                              &scanned)
                      : -1;
    sqlite3_finalize(s);
    free(row);
    if (visited >= 0)
        *scanned_out = scanned;
    return visited;
}

bool db_fleet_board_fleet_newest_of_agent(struct node_db *ndb, int64_t now,
                                          const char *agent,
                                          struct db_fleet_board_post *out)
{
    if (!ndb || !ndb->open || !agent || !out)
        return false;
    struct qb q;
    fleet_board_select_row(&q);
    qb_where_text(&q, QB_C_fleet_board_posts_agent, QB_EQ, agent);
    qb_where_int(&q, QB_C_fleet_board_posts_scope, QB_EQ,
                 FLEET_BOARD_SCOPE_FLEET);
    fleet_board_where_discoverable(&q, now);
    qb_order_by(&q, QB_C_fleet_board_posts_arrival, QB_DESC);
    qb_limit(&q, 1);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s)) {
        LOG_WARN("fleet.board", "fleet newest row prepare failed: %s",
                 qb_error(&q));
        return false;
    }
    bool found = AR_STEP_ROW(s) && fleet_board_row_read(s, out);
    sqlite3_finalize(s);
    return found;
}

bool db_fleet_board_fleet_lines(struct node_db *ndb, int64_t now,
                                const char *agent,
                                db_fleet_board_line_visit visit, void *ctx)
{
    if (!ndb || !ndb->open || !agent || !visit)
        return false;
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_column(&q, QB_C_fleet_board_posts_id);
    qb_select_column(&q, QB_C_fleet_board_posts_text);
    qb_where_text(&q, QB_C_fleet_board_posts_agent, QB_EQ, agent);
    qb_where_int(&q, QB_C_fleet_board_posts_kind, QB_EQ, FLEET_BOARD_KIND_NOTE);
    qb_where_int(&q, QB_C_fleet_board_posts_scope, QB_EQ,
                 FLEET_BOARD_SCOPE_FLEET);
    fleet_board_where_discoverable(&q, now);
    qb_order_by(&q, QB_C_fleet_board_posts_arrival, QB_DESC);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s)) {
        LOG_WARN("fleet.board", "fleet lines prepare failed: %s", qb_error(&q));
        return false;
    }
    bool whole = true;
    while (AR_STEP_ROW(s)) {
        const void *id = sqlite3_column_blob(s, 0);
        const unsigned char *text = sqlite3_column_text(s, 1);
        if (!id || sqlite3_column_bytes(s, 0) != 32 || !text) {
            whole = false; /* a row this read cannot tell apart */
            continue;
        }
        if (!visit(id, (const char *)text, (size_t)sqlite3_column_bytes(s, 1),
                   ctx))
            break;
    }
    return sqlite3_finalize(s) == SQLITE_OK && whole;
}

bool db_fleet_board_copy_near(struct node_db *ndb,
                              const struct fleet_board_post *post, int64_t gap,
                              bool *near_out)
{
    if (near_out)
        *near_out = false;
    if (!ndb || !ndb->open || !post || !near_out || gap <= 0)
        return false;
    if (post->created_at > (uint64_t)(INT64_MAX - gap))
        return true; /* no row is dated out there; the time check refuses it */
    const int64_t created = (int64_t)post->created_at;
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_count_star(&q);
    qb_where_blob(&q, QB_C_fleet_board_posts_host_pubkey, QB_EQ,
                  post->host_pubkey, 32);
    qb_where_text(&q, QB_C_fleet_board_posts_agent, QB_EQ, post->agent);
    qb_where_int(&q, QB_C_fleet_board_posts_scope, QB_EQ, post->scope);
    qb_where_int(&q, QB_C_fleet_board_posts_kind, QB_EQ, post->kind);
    qb_where_text(&q, QB_C_fleet_board_posts_text, QB_EQ, post->text);
    qb_where_int(&q, QB_C_fleet_board_posts_created_at, QB_GT, created - gap);
    qb_where_int(&q, QB_C_fleet_board_posts_created_at, QB_LT, created + gap);
    int64_t held = 0;
    if (!fleet_board_aggregate_checked(ndb, &q, &held)) {
        LOG_WARN("fleet.board", "copy count failed");
        return false;
    }
    *near_out = held > 0;
    return true;
}

/* ── who this node has been storing posts from ───────────────────────── */

/* Only rows that passed the role gate at ingest count here: fleet and
 * legacy scope. A public post is stored with no role check (anyone may
 * post in a public room), so it never earns a role, not even through
 * grandfathering at boot. Reported by CesareFI (Kimi review), 2026-10-24. */

/* One stored post by `key` that still verifies here. The whole list below
 * is built from a column read, which is fast; this is the signature check
 * that keeps a corrupted or hand-edited row from putting a key on it. */
static bool board_host_verifies(struct node_db *ndb, const uint8_t key[32])
{
    struct qb q;
    fleet_board_select_row(&q);
    qb_where_blob(&q, QB_C_fleet_board_posts_host_pubkey, QB_EQ, key, 32);
    qb_where_int(&q, QB_C_fleet_board_posts_scope, QB_NE,
                 FLEET_BOARD_SCOPE_PUBLIC);
    qb_order_by(&q, QB_C_fleet_board_posts_seq, QB_DESC);
    qb_limit(&q, 1);
    sqlite3_stmt *s = NULL;
    bool ok = false;
    if (!QB_PREPARE(ndb, &q, s)) {
        LOG_WARN("fleet.board",
                 "host verification query could not be prepared: %s",
                 sqlite3_errmsg(ndb->db));
        return false;
    }
    if (AR_STEP_ROW(s)) {
        struct db_fleet_board_post row;
        memset(&row, 0, sizeof(row));
        ok = fleet_board_row_read(s, &row);
    }
    sqlite3_finalize(s);
    return ok;
}

static bool board_host_seen(const uint8_t (*seen)[32], size_t count,
                            const uint8_t *key)
{
    for (size_t i = 0; i < count; i++)
        if (memcmp(seen[i], key, 32) == 0)
            return true;
    return false;
}

/* Newest first, one column, no signature work. A read that stops early
 * (end of table, or a read error) yields FEWER keys, never more, so the
 * caller's decision stays on the refusing side of any failure. */
static size_t board_collect_hosts(struct node_db *ndb, uint8_t (*out)[32],
                                  size_t max, bool *truncated)
{
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_column(&q, QB_C_fleet_board_posts_host_pubkey);
    qb_where_int(&q, QB_C_fleet_board_posts_scope, QB_NE,
                 FLEET_BOARD_SCOPE_PUBLIC);
    qb_order_by(&q, QB_C_fleet_board_posts_seq, QB_DESC);
    sqlite3_stmt *s = NULL;
    size_t count = 0;
    if (!QB_PREPARE(ndb, &q, s)) {
        LOG_WARN("fleet.board", "host scan could not be prepared: %s",
                 sqlite3_errmsg(ndb->db));
        return 0;
    }
    while (AR_STEP_ROW(s)) {
        const uint8_t *blob = sqlite3_column_blob(s, 0);
        if (!blob || sqlite3_column_bytes(s, 0) != 32 ||
            board_host_seen(out, count, blob))
            continue;
        /* One distinct key more than fits is the whole point of the
         * flag: the caller must be able to say the list is short. */
        if (count >= max) {
            *truncated = true;
            break;
        }
        memcpy(out[count++], blob, 32);
    }
    sqlite3_finalize(s);
    return count;
}

int db_fleet_board_distinct_hosts(struct node_db *ndb, uint8_t (*out)[32],
                                  size_t max, bool *truncated)
{
    if (truncated)
        *truncated = false;
    if (!ndb || !ndb->open || !out || max == 0)
        return -1;
    if (max > FLEET_BOARD_HOST_LIST_MAX)
        max = FLEET_BOARD_HOST_LIST_MAX;
    bool over = false;
    size_t count = board_collect_hosts(ndb, out, max, &over);
    if (truncated)
        *truncated = over;
    size_t kept = 0;
    for (size_t i = 0; i < count; i++) {
        if (!board_host_verifies(ndb, out[i]))
            continue;
        if (kept != i)
            memcpy(out[kept], out[i], 32);
        kept++;
    }
    return (int)kept;
}

