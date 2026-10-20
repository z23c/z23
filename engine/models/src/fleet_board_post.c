/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fleet board / wiki store. See models/fleet_board_post.h.
 *
 * Every write goes through the AR lifecycle and every statement is built with
 * the typed query builder, so no identifier or value here can reach SQLite as
 * concatenated text. The one rule the store adds on top of the codec is that a
 * post is verified BEFORE it is chained: an unsigned, tampered, expired, or
 * future-dated post never enters the ledger, so the chain only ever links
 * posts this node was willing to vouch for having seen. */

#include "models/fleet_board_post.h"
#include "models/fleet_board_post_internal.h"
#include "session/fleet_wiki_entry.h"

#include "util/fleet_role_check.h"
#include "base/safe_alloc.h"
#include "config/runtime.h"
#include "json/json.h"
/* model_fields.h defines the ZCL_MODEL_* constructors the field list is
 * written in, so it must precede the list it decodes. */
#include "models/model_fields.h"
#include "models/db_txn.h"
#include "models/def/fleet_board_post_fields.def"
#include "models/query_builder.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

DEFINE_MODEL_CALLBACKS(fleet_board_post)

static const uint8_t k_zero32[32] = {0};
static zcl_mutex_t s_board_write_lock;
static zcl_once_t s_board_write_once = ZCL_ONCE_INIT;

static void board_write_lock_init(void)
{
    zcl_mutex_init(&s_board_write_lock);
}

void fleet_board_write_lock(void)
{
    (void)zcl_once_call(&s_board_write_once, board_write_lock_init);
    zcl_mutex_lock(&s_board_write_lock);
}

#ifdef ZCL_TESTING
static int64_t s_test_max_posts;
static int64_t s_test_max_bytes;

void db_fleet_board_test_set_store_limits(int64_t max_posts,
                                          int64_t max_bytes)
{
    s_test_max_posts = max_posts > 0 ? max_posts : 0;
    s_test_max_bytes = max_bytes > 0 ? max_bytes : 0;
}
#endif

static int64_t board_max_posts(void)
{
#ifdef ZCL_TESTING
    if (s_test_max_posts > 0)
        return s_test_max_posts;
#endif
    return FLEET_BOARD_STORE_MAX_POSTS;
}

int64_t fleet_board_max_bytes(void)
{
#ifdef ZCL_TESTING
    if (s_test_max_bytes > 0)
        return s_test_max_bytes;
#endif
    return FLEET_BOARD_STORE_MAX_BYTES;
}

/* The stored projection and the row reader are BOTH derived from the one
 * field list, so the query builder's column order and the read indices
 * cannot drift apart — neither is written down. */
#define FB_QB_COLUMN(kind, col, member, extra) \
    ZCL_MF_CAT(QB_C_fleet_board_posts_, col),
static const enum qb_column k_board_cols[] = {
    ZCL_MODEL_EXPAND(FB_QB_COLUMN, FLEET_BOARD_POST_FIELDS)
};
#define BOARD_NCOLS (sizeof(k_board_cols) / sizeof(k_board_cols[0]))

ZCL_MODEL_READ_ROW_FN(board_read_row, struct db_fleet_board_post,
                      FLEET_BOARD_POST_FIELDS)

bool fleet_board_row_read(sqlite3_stmt *s, struct db_fleet_board_post *out)
{
    board_read_row(out, s);
    /* text_len is the exact SIGNED byte count, so it is re-derived from the
     * bytes that came back rather than stored a second time and trusted. */
    out->post.text_len = (uint32_t)strlen(out->post.text);

    /* Stored bytes remain inert until both their canonical id and signature
     * verify again. A corrupted row is logged, zeroed, and refused to every
     * read caller. */
    enum fleet_board_result verified = fleet_board_post_verify(&out->post);
    if (verified != FLEET_BOARD_OK) {
        LOG_WARN("fleet.board",
                 "stored post seq=%lld failed read verification: %s",
                 (long long)out->seq, fleet_board_result_string(verified));
        /* The arrival number is this node's own bookkeeping, not post
         * content: kept so a page walk can step past the row. */
        int64_t arrival = out->arrival;
        memset(out, 0, sizeof(*out));
        out->arrival = arrival;
        return false;
    }
    return true;
}

void fleet_board_select_row(struct qb *q)
{
    qb_select(q, QB_T_fleet_board_posts);
    qb_select_columns(q, k_board_cols, BOARD_NCOLS);
}

/* The three narrow projections. Each one names its columns through the same
 * constructors as the full row, so inserting a column into the table cannot
 * silently re-point a read here either. */
struct fleet_board_chain_ref {
    uint8_t id[32];
    uint8_t chain_prev[32];
    uint8_t chain_hash[32];
};
#define FB_QB_CHAIN_COLUMN(kind, col, member, extra) \
    ZCL_MF_CAT(QB_C_fleet_board_posts_, col),
static const enum qb_column k_board_chain_cols[] = {
    ZCL_MODEL_EXPAND(FB_QB_CHAIN_COLUMN, FLEET_BOARD_CHAIN_FIELDS)
};
#define BOARD_CHAIN_NCOLS \
    (sizeof(k_board_chain_cols) / sizeof(k_board_chain_cols[0]))
ZCL_MODEL_READ_ROW_FN(board_read_chain_ref, struct fleet_board_chain_ref,
                      FLEET_BOARD_CHAIN_FIELDS)

struct fleet_board_room_ref {
    char room[FLEET_BOARD_ROOM_MAX + 1];
};
#define FB_QB_ROOM_COLUMN(kind, col, member, extra) \
    ZCL_MF_CAT(QB_C_fleet_board_posts_, col),
static const enum qb_column k_board_room_cols[] = {
    ZCL_MODEL_EXPAND(FB_QB_ROOM_COLUMN, FLEET_BOARD_ROOM_FIELDS)
};
#define BOARD_ROOM_NCOLS \
    (sizeof(k_board_room_cols) / sizeof(k_board_room_cols[0]))
ZCL_MODEL_READ_ROW_FN(board_read_room_ref, struct fleet_board_room_ref,
                      FLEET_BOARD_ROOM_FIELDS)

bool db_fleet_board_post_validate(const struct db_fleet_board_post *record,
                                  struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!record) {
        validates_custom(errors, false, "record", "is null");
        return false;
    }
    validates_custom(errors,
        fleet_board_post_validate(&record->post) == FLEET_BOARD_OK,
        "post", "is not a shape-valid board post");
    validates_custom(errors, record->seq > 0, "seq", "must be positive");
    validates_custom(errors,
        record->expires_at ==
            (int64_t)record->post.created_at + (int64_t)record->post.ttl,
        "expires_at", "must equal created_at + ttl");
    validates_custom(errors, record->received_at >= 0,
        "received_at", "must not be negative");
    validates_custom(errors, record->arrival > 0, "arrival",
        "must be positive");
    validates_custom(errors,
        record->body_bytes > 0 &&
            record->body_bytes <= (int64_t)FLEET_BOARD_BODY_MAX,
        "body_bytes", "must be the canonical encoded size");
    validates_custom(errors,
        memcmp(record->post.id, k_zero32, sizeof(k_zero32)) != 0,
        "id", "must be the computed post id");
    return !ar_errors_any(errors);
}

static bool board_next_seq(struct node_db *ndb, int64_t *out)
{
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_agg(&q, QB_MAX, QB_C_fleet_board_posts_seq, true);
    int64_t top = 0;
    if (!fleet_board_aggregate_checked(ndb, &q, &top) || top == INT64_MAX) {
        LOG_WARN("fleet.board", "sequence aggregate failed or exhausted");
        return false;
    }
    *out = top + 1;
    return true;
}

static bool board_head_chain(struct node_db *ndb, uint8_t out[32], bool *found)
{
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_columns(&q, k_board_chain_cols, BOARD_CHAIN_NCOLS);
    qb_order_by(&q, QB_C_fleet_board_posts_seq, QB_DESC);
    qb_limit(&q, 1);
    sqlite3_stmt *s = NULL;
    *found = false;
    if (!QB_PREPARE(ndb, &q, s)) {
        LOG_WARN("fleet.board", "chain head prepare failed: %s", qb_error(&q));
        return false;
    }
    if (AR_STEP_ROW(s)) {
        struct fleet_board_chain_ref head;
        board_read_chain_ref(&head, s);
        memcpy(out, head.chain_hash, 32);
        *found = true;
    }
    int rc = sqlite3_reset(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_OK) LOG_WARN("fleet.board", "chain head step failed: %d", rc);
    return rc == SQLITE_OK;
}

bool db_fleet_board_have(struct node_db *ndb, const uint8_t id[32])
{
    if (!ndb || !ndb->open || !id)
        return false;
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_one(&q);
    qb_where_blob(&q, QB_C_fleet_board_posts_id, QB_EQ, id, 32);
    QB_QUERY_EXISTS(ndb, &q, s);
}

int db_fleet_board_room_list(struct node_db *ndb,
                             char (*rooms)[FLEET_BOARD_ROOM_MAX + 1],
                             size_t max)
{
    if (!ndb || !ndb->open || !rooms || max == 0)
        return 0;
    if (max > FLEET_BOARD_ROOM_LIST_MAX)
        max = FLEET_BOARD_ROOM_LIST_MAX;
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_columns(&q, k_board_room_cols, BOARD_ROOM_NCOLS);
    qb_where_int(&q, QB_C_fleet_board_posts_scope, QB_NE,
                 FLEET_BOARD_SCOPE_FLEET);
    qb_order_by(&q, QB_C_fleet_board_posts_room, QB_ASC);
    sqlite3_stmt *s = NULL;
    size_t count = 0;
    if (!QB_PREPARE(ndb, &q, s))
        return 0;
    /* The walk is bounded by the store's own post ceiling. The raw column is
     * ordered, but the effective name maps '' onto the default room, so
     * duplicates are not guaranteed adjacent and the dedupe is a scan. The
     * single-column read is not signature-verified; it is an advisory index,
     * and the room page itself lists only fully re-verified rows. */
    while (AR_STEP_ROW(s) && count < max) {
        struct fleet_board_room_ref row;
        board_read_room_ref(&row, s);
        const char *name =
            row.room[0] ? row.room : FLEET_BOARD_ROOM_DEFAULT;
        bool seen = false;
        for (size_t i = 0; i < count; i++)
            if (strcmp(rooms[i], name) == 0) {
                seen = true;
                break;
            }
        if (!seen)
            (void)snprintf(rooms[count++], FLEET_BOARD_ROOM_MAX + 1, "%s",
                           name);
    }
    sqlite3_finalize(s);
    return (int)count;
}

/* The AR-lifecycle insert. Split out so ingest can keep its decision logic
 * readable and its one write in one place. */
/* A post the store refused for a reason that will not change by itself.
 * Gossip re-offers the same ids every round, so without this the board would
 * spend every round re-failing one post. The ring is deliberately small and
 * in-memory: it exists to stop a hot loop, not to remember a verdict, and a
 * restart legitimately gives the post another chance. Guarded by the board
 * write lock, which every caller below already holds. */
#define BOARD_QUARANTINE_SLOTS 64u
static uint8_t s_board_quarantine[BOARD_QUARANTINE_SLOTS][32];
static unsigned s_board_quarantine_next;
static unsigned s_board_quarantine_used;

/* Caller holds the board write lock. */
static bool board_quarantined(const uint8_t id[32])
{
    for (unsigned i = 0; i < s_board_quarantine_used; i++)
        if (memcmp(s_board_quarantine[i], id, 32) == 0)
            return true;
    return false;
}

/* Caller holds the board write lock. */
static void board_quarantine_add(const uint8_t id[32])
{
    memcpy(s_board_quarantine[s_board_quarantine_next], id, 32);
    s_board_quarantine_next = (s_board_quarantine_next + 1u) %
                              BOARD_QUARANTINE_SLOTS;
    if (s_board_quarantine_used < BOARD_QUARANTINE_SLOTS)
        s_board_quarantine_used++;
}

#ifdef ZCL_TESTING
void db_fleet_board_test_clear_quarantine(void)
{
    fleet_board_write_lock();
    s_board_quarantine_next = 0;
    s_board_quarantine_used = 0;
    zcl_mutex_unlock(&s_board_write_lock);
}
#endif

/* The write lock this node holds only serialises ITS OWN board writers. The
 * node database is shared with every other subsystem and with the runtime
 * reopens, so a perfectly good append still meets SQLITE_BUSY when one of
 * them holds the write lock. That is a moment to retry, not a fault in the
 * post and not a fault in the caller's arguments. Anything else means the
 * store rejected the row itself and re-offering it will fail identically. */
static enum fleet_board_result board_insert_result(int rc)
{
    if (rc == SQLITE_BUSY || rc == SQLITE_LOCKED)
        return FLEET_BOARD_ERR_BUSY;
    return FLEET_BOARD_ERR_STORAGE;
}

static bool board_insert_stmt(struct node_db *ndb,
                              const struct db_fleet_board_post *record)
{
    struct ar_callbacks *cbs = db_fleet_board_post_callbacks();
    struct qb q;
    qb_insert(&q, QB_T_fleet_board_posts, QB_INSERT_PLAIN);
    qb_value_blob(&q, QB_C_fleet_board_posts_id, record->post.id, 32);
    qb_value_int(&q, QB_C_fleet_board_posts_seq, record->seq);
    qb_value_int(&q, QB_C_fleet_board_posts_kind, record->post.kind);
    qb_value_int(&q, QB_C_fleet_board_posts_created_at,
                 (int64_t)record->post.created_at);
    qb_value_int(&q, QB_C_fleet_board_posts_ttl, (int64_t)record->post.ttl);
    qb_value_int(&q, QB_C_fleet_board_posts_expires_at, record->expires_at);
    qb_value_blob(&q, QB_C_fleet_board_posts_ref, record->post.ref, 32);
    qb_value_blob(&q, QB_C_fleet_board_posts_host_pubkey,
                  record->post.host_pubkey, 32);
    qb_value_text(&q, QB_C_fleet_board_posts_agent, record->post.agent);
    qb_value_text(&q, QB_C_fleet_board_posts_slug, record->post.slug);
    qb_value_text(&q, QB_C_fleet_board_posts_title, record->post.title);
    qb_value_blob(&q, QB_C_fleet_board_posts_supersedes,
                  record->post.supersedes, 32);
    qb_value_text(&q, QB_C_fleet_board_posts_receipt, record->post.receipt);
    qb_value_text(&q, QB_C_fleet_board_posts_text, record->post.text);
    qb_value_int(&q, QB_C_fleet_board_posts_body_bytes, record->body_bytes);
    qb_value_blob(&q, QB_C_fleet_board_posts_signature,
                  record->post.signature, 64);
    qb_value_blob(&q, QB_C_fleet_board_posts_chain_prev, record->chain_prev, 32);
    qb_value_blob(&q, QB_C_fleet_board_posts_chain_hash, record->chain_hash, 32);
    qb_value_int(&q, QB_C_fleet_board_posts_received_at, record->received_at);
    qb_value_int(&q, QB_C_fleet_board_posts_scope, record->post.scope);
    qb_value_text(&q, QB_C_fleet_board_posts_room, record->post.room);
    qb_value_int(&q, QB_C_fleet_board_posts_arrival, record->arrival);
    /* ar-lifecycle-ok:qb-adhoc-save-expands-to-AR_BEGIN_SAVE-and-AR_FINISH_SAVE */
    QB_ADHOC_SAVE(ndb, &q, s, cbs, "fleet_board_post", record,
                  db_fleet_board_post_validate);
}

/* Same append, with the database's own verdict carried back out. The two
 * checked reads the caller runs immediately before this (have / append_fits)
 * both complete successfully on this connection, so the connection's error
 * code is SQLITE_OK on entry and any code left behind by a failure here is
 * this statement's own. */
static bool board_insert(struct node_db *ndb,
                         const struct db_fleet_board_post *record,
                         int *rc_out)
{
    if (rc_out)
        *rc_out = SQLITE_OK;
    if (board_insert_stmt(ndb, record))
        return true;
    if (rc_out)
        *rc_out = sqlite3_errcode(ndb->db);
    return false;
}

/* True when this id needs no append at all: the board already holds it, or
 * the store has already refused it in a way that will not change. Caller
 * holds the board write lock. */
static bool board_skip_known_id(struct node_db *ndb, const uint8_t id[32],
                                enum fleet_board_result *out)
{
    if (db_fleet_board_have(ndb, id)) {
        *out = FLEET_BOARD_OK;
        return true;
    }
    if (board_quarantined(id)) {
        *out = FLEET_BOARD_ERR_STORAGE;
        return true;
    }
    return false;
}

/* The append failed. Say which of the two failures it was, put the database's
 * own code and message in the log so the cause is never guessed from the
 * outside again, and quarantine the post when re-offering it would fail
 * identically. Caller holds the board write lock. */
static enum fleet_board_result board_append_failed(
    struct node_db *ndb, const struct db_fleet_board_post *record,
    int insert_rc)
{
    enum fleet_board_result why = board_insert_result(insert_rc);
    char id_hex[65];
    fleet_board_id_to_hex(record->post.id, id_hex);
    LOG_WARN("fleet.board",
             "post seq=%lld id=%.16s could not be appended: %s "
             "(sqlite rc=%d: %s)",
             (long long)record->seq, id_hex, fleet_board_result_string(why),
             insert_rc, sqlite3_errmsg(ndb->db));
    if (why == FLEET_BOARD_ERR_STORAGE) {
        board_quarantine_add(record->post.id);
        LOG_WARN("fleet.board",
                 "quarantined post id=%.16s: the store rejected it and will "
                 "reject it again; the board keeps ingesting every other "
                 "post", id_hex);
    }
    return why;
}

bool fleet_board_aggregate_checked(struct node_db *ndb, struct qb *q,
                                    int64_t *out)
{
    sqlite3_stmt *s = NULL;
    if (!out) {
        LOG_WARN("fleet.board", "capacity aggregate has no output target");
        return false;
    }
    if (!QB_PREPARE(ndb, q, s)) {
        LOG_WARN("fleet.board", "capacity aggregate prepare failed: %s",
                 qb_error(q));
        return false;
    }
    if (!AR_STEP_ROW(s)) {
        LOG_WARN("fleet.board", "capacity aggregate did not return a row: %s",
                 sqlite3_errmsg(ndb->db));
        sqlite3_finalize(s);
        return false;
    }
    int64_t value = sqlite3_column_int64(s, 0);
    bool done = AR_STEP_DONE(s);
    sqlite3_finalize(s);
    if (!done || value < 0) {
        LOG_WARN("fleet.board", "capacity aggregate did not finish cleanly");
        return false;
    }
    *out = value;
    return true;
}

/* The only quota projection on ingress: two checked aggregates. A
 * query error is a refusal, never an empty store. Caller holds board lock. */
static bool board_append_fits(struct node_db *ndb, int64_t body_bytes)
{
    struct qb q;
    int64_t posts = 0;
    int64_t bytes = 0;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_count_star(&q);
    if (!fleet_board_aggregate_checked(ndb, &q, &posts)) {
        LOG_WARN("fleet.board", "append capacity post-count aggregate failed");
        return false;
    }
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_agg(&q, QB_SUM, QB_C_fleet_board_posts_body_bytes, true);
    if (!fleet_board_aggregate_checked(ndb, &q, &bytes)) {
        LOG_WARN("fleet.board", "append capacity byte-sum aggregate failed");
        return false;
    }
    int64_t max_posts = board_max_posts();
    int64_t max_bytes = fleet_board_max_bytes();
    return posts < max_posts && body_bytes > 0 && body_bytes <= max_bytes &&
           bytes <= max_bytes - body_bytes;
}

/* The highest arrival number this process has handed out, across every
 * store it has written. Guarded by s_board_write_lock. */
static int64_t s_board_arrival_high;

void fleet_board_write_unlock(void)
{
    zcl_mutex_unlock(&s_board_write_lock);
}
int64_t fleet_board_arrival_checkpoint(void)
{
    return s_board_arrival_high;
}
void fleet_board_arrival_restore(int64_t high)
{
    s_board_arrival_high = high;
}

/* The next arrival number: strictly above everything stored and everything
 * this process has already assigned, so a reclaim that deletes the newest
 * rows can never hand a number out twice while this process lives. Numbers
 * are assigned and committed under the one board write lock, so every
 * reader sees them land in increasing order with no hole a later commit
 * fills. A restart may reuse a number whose row was reclaimed; the fleet
 * pull names this process in every answer for exactly that reason. Caller
 * holds the board write lock; a query error refuses. */
static bool board_next_arrival(struct node_db *ndb, int64_t *out)
{
    struct qb q;
    int64_t stored_high = 0;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_agg(&q, QB_MAX, QB_C_fleet_board_posts_arrival, true);
    if (!fleet_board_aggregate_checked(ndb, &q, &stored_high)) {
        LOG_WARN("fleet.board", "arrival high-water aggregate failed");
        return false;
    }
    int64_t high = stored_high > s_board_arrival_high ? stored_high
                                                      : s_board_arrival_high;
    if (high == INT64_MAX)
        return false;
    *out = high + 1;
    return true;
}

/* Does the key that signed this post hold a role granting a post of this
 * KIND on this node? Asked through util/fleet_role_check.h, so this model
 * never learns where the grant store lives — and refused outright when
 * nothing is installed to answer.
 *
 * The refusal names the key by the fingerprint prefix the operator would
 * type into `z23 fleet roles grant`, and nothing else about the post: the
 * body is somebody's writing and a log is not the board. */
static bool board_role_allows(const struct fleet_board_post *post)
{
    char why[ZCL_FLEET_ROLE_WHY_MAX];
    if (zcl_fleet_role_allows(post->host_pubkey, ZCL_FLEET_LEAF_BOARD_POST,
                              fleet_board_kind_name(post->kind), why,
                              sizeof why))
        return true;
    LOG_WARN("fleet.board", "%s", why);
    return false;
}

/* What "still discoverable" means, in one place. A row is live while its
 * own signed TTL has not run out; a wiki revision is durable history and
 * never stops being live. The list and the inventory ask exactly this
 * question, so neither can drift into a different idea of what the board
 * still shows. board_where_reclaimable below is its complement, plus an
 * arrival floor the quota needs. */
void fleet_board_where_discoverable(struct qb *q, int64_t now)
{
    qb_group_begin(q, QB_OR);
    qb_where_int(q, QB_C_fleet_board_posts_expires_at, QB_GT, now);
    qb_where_int(q, QB_C_fleet_board_posts_kind, QB_EQ, FLEET_BOARD_KIND_WIKI);
    qb_group_end(q);
}

/* Everything that must hold before a post is even considered for storage,
 * cheapest question first: shape, then time, then signature, then the role
 * the verified key holds here (every scope but PUBLIC, which needs none),
 * then whether the board already holds this id (a held post is settled and
 * is never charged against a quota), then the per-key quota (PUBLIC and
 * FLEET; a legacy post is admitted by its role alone, as it always was).
 * The first two reject the bulk of a flood before any curve arithmetic,
 * and the admission questions come last because each is only meaningful
 * once the key is proven to have signed these bytes. The held-id lookup is
 * one primary-key probe. */
static enum fleet_board_result board_ingest_admissible(
    struct node_db *ndb, const struct fleet_board_post *post, int64_t now,
    bool *known_out)
{
    *known_out = false;
    enum fleet_board_result r = fleet_board_post_validate(post);
    if (r != FLEET_BOARD_OK)
        return r;
    r = fleet_board_post_check_time(post, now);
    if (r != FLEET_BOARD_OK)
        return r;
    r = fleet_board_post_verify(post);
    if (r != FLEET_BOARD_OK)
        return r;
    if (post->scope != FLEET_BOARD_SCOPE_PUBLIC && !board_role_allows(post))
        return FLEET_BOARD_ERR_ROLE;
    if (db_fleet_board_have(ndb, post->id)) {
        *known_out = true;
        return FLEET_BOARD_OK;
    }
    if (post->scope == FLEET_BOARD_SCOPE_LEGACY_PUBLIC)
        return FLEET_BOARD_OK;
    enum board_quota q = fleet_board_key_quota(ndb, post, now);
    if (q == BOARD_QUOTA_OK)
        return FLEET_BOARD_OK;
    if (post->kind == FLEET_BOARD_KIND_WIKI)
        return FLEET_BOARD_ERR_WIKI_QUOTA;
    return FLEET_BOARD_ERR_QUOTA;
}

/* Every refusal that can be decided before the board write lock is taken:
 * admissibility, then the canonical body size the ledger stores alongside the
 * row. The canonical size is measured once and needs no buffer — canonical()
 * reports the size it would have written. */
enum fleet_board_result fleet_board_ingest_prepare(
    struct node_db *ndb, const struct fleet_board_post *post, int64_t now,
    size_t *body_len_out, bool *known_out)
{
    if (!fleet_board_review_shape(post)) return FLEET_BOARD_ERR_TEXT;
    enum fleet_board_result r =
        board_ingest_admissible(ndb, post, now, known_out);
    if (r != FLEET_BOARD_OK || *known_out)
        return r;
    size_t body_len = 0;
    (void)fleet_board_post_canonical(post, NULL, 0, &body_len);
    if (body_len == 0 || body_len > FLEET_BOARD_BODY_MAX)
        return FLEET_BOARD_ERR_CAPACITY;
    *body_len_out = body_len;
    return FLEET_BOARD_OK;
}

/* The capacity checks and the append itself. Caller holds the board write
 * lock (and, on the eviction path, the open transaction). */
enum fleet_board_result fleet_board_append_record(
    struct node_db *ndb, const struct fleet_board_post *post, int64_t now,
    size_t body_len)
{
    if (!board_append_fits(ndb, (int64_t)body_len))
        return FLEET_BOARD_ERR_CAPACITY;
    if (post->kind == FLEET_BOARD_KIND_WIKI &&
        !fleet_board_wiki_bytes_fit(ndb, (int64_t)body_len))
        return FLEET_BOARD_ERR_CAPACITY;

    struct db_fleet_board_post record;
    memset(&record, 0, sizeof(record));
    if (!board_next_arrival(ndb, &record.arrival))
        return FLEET_BOARD_ERR_STORAGE;
    record.post = *post;
    if (!board_next_seq(ndb, &record.seq)) return FLEET_BOARD_ERR_STORAGE;
    record.expires_at = (int64_t)post->created_at + (int64_t)post->ttl;
    record.body_bytes = (int64_t)body_len;
    record.received_at = now;
    bool head_found = false;
    if (!board_head_chain(ndb, record.chain_prev, &head_found)) return FLEET_BOARD_ERR_STORAGE;
    if (!head_found)
        memset(record.chain_prev, 0, sizeof(record.chain_prev));
    fleet_board_chain_step(record.chain_prev, record.post.id,
                           record.chain_hash);

    int insert_rc = SQLITE_OK;
    if (!board_insert(ndb, &record, &insert_rc))
        return board_append_failed(ndb, &record, insert_rc);
    s_board_arrival_high = record.arrival;
    return FLEET_BOARD_OK;
}

static enum fleet_board_result board_append_evicting(
    struct node_db *ndb, const struct fleet_board_post *post, int64_t now,
    size_t body_len, const uint8_t victim[32]);

/* Room check, then the plain or the replacing append. Caller holds the
 * board write lock. */
static enum fleet_board_result board_append_locked(
    struct node_db *ndb, const struct fleet_board_post *post, int64_t now,
    size_t body_len)
{
    bool evict = false;
    uint8_t victim[32];
    enum fleet_board_result r = fleet_board_wiki_room(ndb, post, now, &evict, victim);
    if (r != FLEET_BOARD_OK)
        return r;
    if (!evict)
        return fleet_board_append_record(ndb, post, now, body_len);
    if (!fleet_board_wiki_evict_allowed(now))
        return FLEET_BOARD_ERR_WIKI_QUOTA;
    r = board_append_evicting(ndb, post, now, body_len, victim);
    if (r == FLEET_BOARD_OK)
        fleet_board_wiki_evict_note(now);
    return r;
}

enum fleet_board_result db_fleet_board_post_ingest(
    struct node_db *ndb, const struct fleet_board_post *post, int64_t now,
    bool *stored_out)
{
    if (stored_out)
        *stored_out = false;
    if (!ndb || !ndb->open || !post)
        return FLEET_BOARD_ERR_ARGS;

    size_t body_len = 0;
    bool held = false;
    enum fleet_board_result r = fleet_board_ingest_prepare(ndb, post, now,
                                                     &body_len, &held);
    if (r != FLEET_BOARD_OK || held)
        return r;

    /* Serialize only board writers in-process. This avoids BEGIN IMMEDIATE's
     * node-wide busy wait and never joins an open consensus transaction. */
    struct node_db_status db_status;
    node_db_get_status(ndb, &db_status);
    if (db_status.tx_open)
        return FLEET_BOARD_ERR_BUSY;
    fleet_board_write_lock();
    node_db_get_status(ndb, &db_status);
    if (db_status.tx_open) {
        zcl_mutex_unlock(&s_board_write_lock);
        return FLEET_BOARD_ERR_BUSY;
    }
    enum fleet_board_result known = FLEET_BOARD_OK;
    if (board_skip_known_id(ndb, post->id, &known)) {
        zcl_mutex_unlock(&s_board_write_lock);
        return known;
    }
    r = board_append_locked(ndb, post, now, body_len);
    zcl_mutex_unlock(&s_board_write_lock);
    if (r == FLEET_BOARD_OK && stored_out)
        *stored_out = true;
    return r;
}

/* What a reclaim pass is allowed to take back, written once so the count
 * and the delete can never key on different rows.
 *
 * Three conditions, all necessary. The TTL has run out and the row is not
 * durable wiki history — that is fleet_board_where_discoverable read the
 * other way round. And the row arrived longer ago than the public quota's
 * rolling window: that leg counts EVERY arrival in the window regardless
 * of TTL, so a pass that deleted a row while its own window was still open
 * would hand the key the same slot twice. Without this floor a key posts
 * WINDOW_MAX one-second notes, waits for a reclaim, and posts WINDOW_MAX
 * more inside the same window — twice the arrivals the burst ceiling
 * states, sustained for as often as the reclaim runs. Holding a window's
 * worth of dead rows costs at most WINDOW_MAX rows per key and makes the
 * burst ceiling an invariant no maintenance pass can lift. */
static void board_where_reclaimable(struct qb *q, int64_t now)
{
    qb_where_int(q, QB_C_fleet_board_posts_expires_at, QB_LE, now);
    qb_where_int(q, QB_C_fleet_board_posts_kind, QB_NE,
                 FLEET_BOARD_KIND_WIKI);
    qb_where_int(q, QB_C_fleet_board_posts_received_at, QB_LE,
                 now - (int64_t)FLEET_BOARD_PUBLIC_QUOTA_WINDOW_SECONDS);
}

/* How many rows the reclaim below is about to take back. Asked as its own
 * checked aggregate so the count the caller reports is the store's own
 * answer, and so an unreadable table refuses the whole pass instead of
 * reporting "removed 0" over a table it could not read. Caller holds the
 * board write lock. */
static bool board_expired_count(struct node_db *ndb, int64_t now,
                                int64_t *out)
{
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_count_star(&q);
    board_where_reclaimable(&q, now);
    return fleet_board_aggregate_checked(ndb, &q, out);
}

/* How many rows the table holds right now — the relink's expected length,
 * counted rather than discovered, so a short scan is detectable. Caller
 * holds the board write lock. */
static bool board_stored_count(struct node_db *ndb, int64_t *out)
{
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_count_star(&q);
    return fleet_board_aggregate_checked(ndb, &q, out);
}

/* The delete leg, over exactly the rows board_where_reclaimable names — the
 * same predicate the count above asked, so the number the pass reports is
 * the number of rows it removed. Caller holds the board write lock and an
 * open transaction. */
static bool board_delete_expired(struct node_db *ndb, int64_t now)
{
    struct qb q;
    qb_delete(&q, QB_T_fleet_board_posts);
    board_where_reclaimable(&q, now);
    QB_EXEC_BOOL(ndb, &q, s);
}

/* One row's worth of the relink, kept separate so the loop below stays flat.
 * Assigning seq i to the i-th surviving row in ascending seq order never
 * collides with the UNIQUE seq index: every row not yet rewritten still
 * holds a seq strictly greater than i. */
static bool board_set_chain(struct node_db *ndb, const uint8_t id[32],
                            int64_t seq, const uint8_t prev[32],
                            const uint8_t hash[32])
{
    struct qb q;
    qb_update(&q, QB_T_fleet_board_posts);
    qb_set_int(&q, QB_C_fleet_board_posts_seq, seq);
    qb_set_blob(&q, QB_C_fleet_board_posts_chain_prev, prev, 32);
    qb_set_blob(&q, QB_C_fleet_board_posts_chain_hash, hash, 32);
    qb_where_blob(&q, QB_C_fleet_board_posts_id, QB_EQ, id, 32);
    QB_EXEC_CHANGED_BOOL(ndb, &q, s);
}

/* Relink the whole stored table after a reclaim. The chain is LOCAL evidence
 * of arrival order over the rows this node still holds (docs/agent/FLEET_BOARD.md,
 * Storage): it is never gossiped and orders the board for nobody else, so
 * rebuilding it over the survivors preserves exactly what it ever claimed —
 * and leaves the table in a state db_fleet_board_chain_verify accepts with
 * no change to that verifier at all. Reads ids in one pass into a bounded
 * buffer (FLEET_BOARD_STORE_MAX_POSTS caps the table, so the walk is bounded
 * by construction, and a table somehow past that cap refuses the pass rather
 * than relinking a prefix). Caller holds the board write lock and an open
 * transaction. */
/* The chain hash of the row just below `seq`, or all zeros when there is none
 * (genesis). Caller holds the board write lock. */
static bool board_chain_before(struct node_db *ndb, int64_t seq,
                               uint8_t prev[32])
{
    memset(prev, 0, 32);
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_columns(&q, k_board_chain_cols, BOARD_CHAIN_NCOLS);
    qb_where_int(&q, QB_C_fleet_board_posts_seq, QB_LT, seq);
    qb_order_by(&q, QB_C_fleet_board_posts_seq, QB_DESC);
    qb_limit(&q, 1);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s)) {
        LOG_WARN("fleet.board", "rechain predecessor scan failed: %s",
                 qb_error(&q));
        return false;
    }
    if (AR_STEP_ROW(s)) {
        struct fleet_board_chain_ref row;
        board_read_chain_ref(&row, s);
        memcpy(prev, row.chain_hash, 32);
    }
    sqlite3_finalize(s);
    return true;
}

static bool board_rechain_survivors(struct node_db *ndb, int64_t from_seq,
                                    int64_t expected)
{
    if (expected < 0 || expected > FLEET_BOARD_STORE_MAX_POSTS) {
        LOG_WARN("fleet.board",
                 "reclaim rechain refused: %lld survivors is outside the "
                 "store's own ceiling", (long long)expected);
        return false;
    }
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_columns(&q, k_board_chain_cols, BOARD_CHAIN_NCOLS);
    qb_where_int(&q, QB_C_fleet_board_posts_seq, QB_GE, from_seq);
    qb_order_by(&q, QB_C_fleet_board_posts_seq, QB_ASC);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s)) {
        LOG_WARN("fleet.board", "reclaim rechain scan failed: %s",
                 qb_error(&q));
        return false;
    }
    /* Static, not stack: 320 KiB of ids has no business on a thread stack,
     * and the board write lock the caller holds is what makes one shared
     * buffer safe. */
    static uint8_t ids[FLEET_BOARD_STORE_MAX_POSTS][32];
    int n = 0;
    while (n < (int)expected && AR_STEP_ROW(s)) {
        struct fleet_board_chain_ref row;
        board_read_chain_ref(&row, s);
        memcpy(ids[n++], row.id, 32);
    }
    sqlite3_finalize(s);
    /* A short read is a read that went wrong. Relinking a PREFIX would
     * leave the rows past it holding chain fields nothing points at, so a
     * scan that did not deliver every counted survivor refuses the whole
     * pass and the transaction rolls back. */
    if ((int64_t)n != expected) {
        LOG_WARN("fleet.board",
                 "reclaim rechain read %d of %lld survivors", n,
                 (long long)expected);
        return false;
    }
    uint8_t prev[32];
    if (!board_chain_before(ndb, from_seq, prev)) {
        LOG_WARN("fleet.board", "rechain predecessor lookup failed");
        return false;
    }
    for (int i = 0; i < n; i++) {
        uint8_t hash[32];
        fleet_board_chain_step(prev, ids[i], hash);
        if (!board_set_chain(ndb, ids[i], from_seq + i, prev, hash)) {
            LOG_WARN("fleet.board", "reclaim rechain write failed at %d/%d",
                     i, n);
            return false;
        }
        memcpy(prev, hash, 32);
    }
    return true;
}

/* Delete one of this key's own wiki rows. The key, scope and kind are part
 * of the predicate, so the delete can never remove another key's row. */
static bool board_delete_own_wiki(struct node_db *ndb,
                                  const struct fleet_board_post *post,
                                  const uint8_t victim[32])
{
    struct qb q;
    qb_delete(&q, QB_T_fleet_board_posts);
    qb_where_blob(&q, QB_C_fleet_board_posts_id, QB_EQ, victim, 32);
    qb_where_blob(&q, QB_C_fleet_board_posts_host_pubkey, QB_EQ,
                  post->host_pubkey, 32);
    qb_where_int(&q, QB_C_fleet_board_posts_scope, QB_EQ, post->scope);
    qb_where_int(&q, QB_C_fleet_board_posts_kind, QB_EQ,
                 FLEET_BOARD_KIND_WIKI);
    QB_EXEC_CHANGED_BOOL(ndb, &q, s);
}

/* Rows at or above `seq`, counted. Caller holds the board write lock. */
static bool board_count_from(struct node_db *ndb, int64_t seq, int64_t *out)
{
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_count_star(&q);
    qb_where_int(&q, QB_C_fleet_board_posts_seq, QB_GE, seq);
    return fleet_board_aggregate_checked(ndb, &q, out);
}

/* The seq of one stored row, 0 when it is not stored. */
static bool board_seq_of(struct node_db *ndb, const uint8_t id[32],
                         int64_t *out)
{
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_agg(&q, QB_MAX, QB_C_fleet_board_posts_seq, true);
    qb_where_blob(&q, QB_C_fleet_board_posts_id, QB_EQ, id, 32);
    return fleet_board_aggregate_checked(ndb, &q, out);
}

/* Delete the victim and relink only the rows after it: rows below it keep
 * their seq and chain values, so the work is bounded by the rows above the
 * victim rather than the whole table. Caller holds the board write lock
 * and an open transaction. */
bool fleet_board_remove_and_relink(struct node_db *ndb,
                                    const struct fleet_board_post *post,
                                    const uint8_t victim[32])
{
    int64_t seq = 0;
    int64_t tail = 0;
    if (!board_seq_of(ndb, victim, &seq) || seq < 1 ||
        !board_delete_own_wiki(ndb, post, victim) ||
        !board_count_from(ndb, seq, &tail)) {
        LOG_WARN("fleet.board", "wiki replacement could not remove the victim");
        return false;
    }
    return tail == 0 || board_rechain_survivors(ndb, seq, tail);
}

static enum fleet_board_result board_replace_and_append(
    struct node_db *ndb, const struct fleet_board_post *post, int64_t now,
    size_t body_len, const uint8_t victim[32])
{
    DB_TXN_SCOPE(txn, ndb, "fleet_board.wiki_replace");
    if (!txn)
        return FLEET_BOARD_ERR_BUSY;
    if (!fleet_board_remove_and_relink(ndb, post, victim))
        return FLEET_BOARD_ERR_STORAGE;
    enum fleet_board_result r = fleet_board_append_record(ndb, post, now, body_len);
    if (r != FLEET_BOARD_OK)
        return r;
    return db_txn_commit(txn) ? FLEET_BOARD_OK : FLEET_BOARD_ERR_STORAGE;
}

/* A key at its wiki ceiling replaces its own oldest superseded revision:
 * delete it, relink the rows after it, and append the new revision, all in
 * one transaction so the ledger is never observable half-way. A failure
 * rolls the transaction back and leaves the arrival high-water mark where
 * it was. Caller holds the board write lock. */
static enum fleet_board_result board_append_evicting(
    struct node_db *ndb, const struct fleet_board_post *post, int64_t now,
    size_t body_len, const uint8_t victim[32])
{
    const int64_t high = s_board_arrival_high;
    enum fleet_board_result r =
        board_replace_and_append(ndb, post, now, body_len, victim);
    if (r != FLEET_BOARD_OK)
        s_board_arrival_high = high;
    return r;
}

/* Delete then relink, all inside one transaction, so the ledger is never
 * observable with the rows gone and the chain still describing them.
 * Caller holds the board write lock. */
static bool board_reclaim_locked(struct node_db *ndb, int64_t now,
                                 int64_t *removed_out)
{
    int64_t expired = 0;
    if (!board_expired_count(ndb, now, &expired)) {
        LOG_WARN("fleet.board", "reclaim expired-count aggregate failed");
        return false;
    }
    if (expired == 0)
        return true;
    DB_TXN_SCOPE(txn, ndb, "fleet_board.reclaim_expired");
    if (!txn)
        return false;
    if (!board_delete_expired(ndb, now)) {
        LOG_WARN("fleet.board", "reclaim delete failed");
        return false;
    }
    int64_t survivors = 0;
    if (!board_stored_count(ndb, &survivors)) {
        LOG_WARN("fleet.board", "reclaim survivor count failed");
        return false;
    }
    if (!board_rechain_survivors(ndb, 1, survivors))
        return false; // raw-return-ok:board_rechain_survivors already logged its own reason
    if (!db_txn_commit(txn)) {
        LOG_WARN("fleet.board", "reclaim transaction commit failed");
        return false;
    }
    *removed_out = expired;
    return true;
}

/* The separately bounded maintenance path docs/agent/FLEET_BOARD.md reserves:
 * expired discussion rows are physically removed and the survivors are
 * re-seq'd and re-chained, so the store the lifetime quota counts and the
 * bytes the node actually carries say the same thing.
 *
 * Expiry reclaim is never reachable from ingress: the only caller is the
 * local db_maintenance scheduler's "board-reclaim" op (and the tests that
 * drive it directly). The one thing ingress can cause is the wiki
 * replacement in board_append_evicting: an accepted wiki revision from a key
 * at its stored wiki ceiling deletes that same key's own oldest superseded
 * revision and relinks only the rows stored after it. It is bounded by the
 * per-key wiki window (20 per 600 s) and by the node-wide cap of
 * FLEET_BOARD_WIKI_EVICT_MAX replacements per FLEET_BOARD_WIKI_EVICT_SECONDS
 * across all keys. Gossip cannot undo a reclaim pass either — ingest refuses an
 * already-expired discussion post, so a row taken back here cannot be
 * re-ingested from a peer. */
enum fleet_board_reclaim db_fleet_board_reclaim_expired(
    struct node_db *ndb, int64_t now, int64_t *removed_out)
{
    if (removed_out)
        *removed_out = 0;
    if (!ndb || !ndb->open)
        return FLEET_BOARD_RECLAIM_FAILED;
    /* Same rule ingest uses: this path owns its whole transaction, so it
     * refuses to run inside somebody else's rather than joining it. That
     * refusal is DEFERRED, not FAILED — the node's own writers hold a
     * transaction open all the time, and housekeeping that steps aside for
     * them has not gone wrong. */
    struct node_db_status st;
    node_db_get_status(ndb, &st);
    if (st.tx_open)
        return FLEET_BOARD_RECLAIM_DEFERRED;
    fleet_board_write_lock();
    node_db_get_status(ndb, &st);
    if (st.tx_open) {
        zcl_mutex_unlock(&s_board_write_lock);
        return FLEET_BOARD_RECLAIM_DEFERRED;
    }
    int64_t removed = 0;
    bool ok = board_reclaim_locked(ndb, now, &removed);
    zcl_mutex_unlock(&s_board_write_lock);
    if (!ok)
        return FLEET_BOARD_RECLAIM_FAILED;
    if (removed > 0)
        LOG_INFO("fleet.board",
                 "reclaimed %lld expired post(s); survivors re-chained",
                 (long long)removed);
    if (removed_out)
        *removed_out = removed;
    return FLEET_BOARD_RECLAIM_DONE;
}

bool db_fleet_board_post_find(struct node_db *ndb, const uint8_t id[32],
                              struct db_fleet_board_post *out)
{
    if (!ndb || !ndb->open || !id || !out)
        return false;
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_columns(&q, k_board_cols, BOARD_NCOLS);
    qb_where_blob(&q, QB_C_fleet_board_posts_id, QB_EQ, id, 32);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s)) {
        LOG_WARN("fleet.board", "post lookup prepare failed: %s",
                 qb_error(&q));
        return false;
    }
    bool found = AR_STEP_ROW(s) && fleet_board_row_read(s, out);
    sqlite3_finalize(s);
    return found;
}

/* The `--open` predicate as a subquery: the set of ids that some claim or
 * result already references. Built here so both the list and the status count
 * ask the same question. */
static void board_answered_subquery(struct qb *sub)
{
    static const int64_t k_answer_kinds[] = {
        FLEET_BOARD_KIND_CLAIM, FLEET_BOARD_KIND_RESULT,
    };
    qb_select(sub, QB_T_fleet_board_posts);
    qb_select_column(sub, QB_C_fleet_board_posts_ref);
    qb_where_in_int(sub, QB_C_fleet_board_posts_kind, k_answer_kinds,
                    sizeof(k_answer_kinds) / sizeof(k_answer_kinds[0]));
}

static void board_apply_filter(struct qb *q,
                               const struct fleet_board_filter *filter,
                               int64_t now, struct qb *sub_storage)
{
    fleet_board_where_discoverable(q, now);
    if (!filter)
        return;
    if (filter->kind)
        qb_where_int(q, QB_C_fleet_board_posts_kind, QB_EQ, filter->kind);
    if (filter->host_set)
        qb_where_blob(q, QB_C_fleet_board_posts_host_pubkey, QB_EQ,
                      filter->host_pubkey, 32);
    if (filter->since > 0)
        qb_where_int(q, QB_C_fleet_board_posts_created_at, QB_GT,
                     filter->since);
    if (filter->slug[0])
        qb_where_text(q, QB_C_fleet_board_posts_slug, QB_EQ, filter->slug);
    if (filter->agent[0])
        qb_where_text(q, QB_C_fleet_board_posts_agent, QB_EQ, filter->agent);
    if (filter->scope_set)
        qb_where_int(q, QB_C_fleet_board_posts_scope, QB_EQ, filter->scope);
    if (filter->room[0]) {
        /* The default room is where legacy posts live: their signed room is
         * empty, and the room they read as is the default. Asking for the
         * default must find them, or the pre-scope board would vanish from
         * its own room. */
        if (strcmp(filter->room, FLEET_BOARD_ROOM_DEFAULT) == 0) {
            /* scope-0 rows always read as the default room (their signed
             * room is empty), and no fleet-scoped row has either property,
             * so this pair is exact without a nested group. */
            qb_group_begin(q, QB_OR);
            qb_where_text(q, QB_C_fleet_board_posts_room, QB_EQ,
                          filter->room);
            qb_where_int(q, QB_C_fleet_board_posts_scope, QB_EQ,
                         FLEET_BOARD_SCOPE_LEGACY_PUBLIC);
            qb_group_end(q);
        } else {
            qb_where_text(q, QB_C_fleet_board_posts_room, QB_EQ,
                          filter->room);
        }
    }
    if (filter->open_only) {
        static const int64_t k_open_kinds[] = {
            FLEET_BOARD_KIND_PROBLEM, FLEET_BOARD_KIND_NEED,
        };
        qb_where_in_int(q, QB_C_fleet_board_posts_kind, k_open_kinds,
                        sizeof(k_open_kinds) / sizeof(k_open_kinds[0]));
        board_answered_subquery(sub_storage);
        qb_where_in_select(q, QB_C_fleet_board_posts_id, true, sub_storage);
    }
}

int db_fleet_board_list_checked(struct node_db *ndb,
                                const struct fleet_board_filter *filter,
                                int64_t now, struct db_fleet_board_post *out,
                                size_t max, bool *complete)
{
    bool clean = true;
    if (complete)
        *complete = false;
    if (!ndb || !ndb->open || !out || max == 0)
        return 0;
    if (max > FLEET_BOARD_LIST_MAX)
        max = FLEET_BOARD_LIST_MAX;
    struct qb q, sub;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_columns(&q, k_board_cols, BOARD_NCOLS);
    board_apply_filter(&q, filter, now, &sub);
    qb_order_by(&q, QB_C_fleet_board_posts_created_at, QB_DESC);
    qb_order_by(&q, QB_C_fleet_board_posts_id, QB_DESC);
    qb_limit(&q, (int64_t)max);
    sqlite3_stmt *s = NULL;
    int count = 0;
    if (!QB_PREPARE(ndb, &q, s))
        return 0;
    while (AR_STEP_ROW(s) && (size_t)count < max) {
        struct db_fleet_board_post row;
        memset(&row, 0, sizeof(row));
        if (fleet_board_row_read(s, &row))
            out[count++] = row;
        else
            clean = false;
    }
    clean = sqlite3_finalize(s) == SQLITE_OK && clean; /* last step's error */
    if (complete)
        *complete = clean;
    return count;
}


int db_fleet_board_wiki_history(struct node_db *ndb, const char *slug,
                                struct db_fleet_board_post *out, size_t max)
{
    if (!ndb || !ndb->open || !out || max == 0 ||
        !fleet_board_slug_valid(slug))
        return 0;
    if (max > FLEET_BOARD_LIST_MAX)
        max = FLEET_BOARD_LIST_MAX;
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_columns(&q, k_board_cols, BOARD_NCOLS);
    qb_where_int(&q, QB_C_fleet_board_posts_kind, QB_EQ,
                 FLEET_BOARD_KIND_WIKI);
    qb_where_text(&q, QB_C_fleet_board_posts_slug, QB_EQ, slug);
    qb_order_by(&q, QB_C_fleet_board_posts_created_at, QB_DESC);
    qb_order_by(&q, QB_C_fleet_board_posts_id, QB_DESC);
    qb_limit(&q, (int64_t)max);
    sqlite3_stmt *s = NULL;
    int count = 0;
    if (!QB_PREPARE(ndb, &q, s))
        return 0;
    while (AR_STEP_ROW(s) && (size_t)count < max) {
        struct db_fleet_board_post row;
        memset(&row, 0, sizeof(row));
        if (!fleet_board_row_read(s, &row))
            continue;
        out[count++] = row;
    }
    sqlite3_finalize(s);
    return count;
}

int db_fleet_board_wiki_list(struct node_db *ndb,
                             struct db_fleet_board_post *out, size_t max)
{
    return db_fleet_board_wiki_list_after(ndb, "", out, max, NULL, NULL);
}

int db_fleet_board_ids_before(struct node_db *ndb, int64_t now,
                              int64_t before_seq, bool public_only,
                              uint8_t (*ids)[32], size_t max,
                              int64_t *last_seq_out)
{
    if (last_seq_out)
        *last_seq_out = 0;
    if (!ndb || !ndb->open || !ids || max == 0 || before_seq < 0)
        return -1;
    if (max > FLEET_BOARD_LIST_MAX)
        max = FLEET_BOARD_LIST_MAX;
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_columns(&q, k_board_cols, BOARD_NCOLS);
    fleet_board_where_discoverable(&q, now);
    if (public_only)
        qb_where_int(&q, QB_C_fleet_board_posts_scope, QB_NE,
                     FLEET_BOARD_SCOPE_FLEET);
    if (before_seq > 0)
        qb_where_int(&q, QB_C_fleet_board_posts_seq, QB_LT, before_seq);
    qb_order_by(&q, QB_C_fleet_board_posts_seq, QB_DESC);
    qb_limit(&q, (int64_t)max);
    sqlite3_stmt *s = NULL;
    int count = 0;
    if (!QB_PREPARE(ndb, &q, s))
        return -1;
    for (;;) {
        if (!AR_STEP_ROW(s)) {
            /* reset returns the preceding statement's error, so clean EOF
             * remains distinguishable from a failed read through AR. */
            if (sqlite3_reset(s) == SQLITE_OK)
                break;
            LOG_WARN("fleet.board", "inventory page read failed: %s",
                     sqlite3_errmsg(ndb->db));
            sqlite3_finalize(s);
            memset(ids, 0, max * sizeof(ids[0]));
            if (last_seq_out)
                *last_seq_out = 0;
            return -1;
        }
        struct db_fleet_board_post row;
        memset(&row, 0, sizeof(row));
        if (!fleet_board_row_read(s, &row)) {
            sqlite3_finalize(s);
            memset(ids, 0, max * sizeof(ids[0]));
            if (last_seq_out)
                *last_seq_out = 0;
            return -1;
        }
        memcpy(ids[count], row.post.id, 32);
        if (last_seq_out)
            *last_seq_out = row.seq;
        count++;
    }
    sqlite3_finalize(s);
    return count;
}

int db_fleet_board_recent_ids(struct node_db *ndb, int64_t now,
                              bool public_only, uint8_t (*ids)[32], size_t max)
{
    return db_fleet_board_ids_before(ndb, now, 0, public_only, ids, max,
                                     NULL);
}

static int64_t board_scalar(struct node_db *ndb, struct qb *q)
{
    sqlite3_stmt *s = NULL;
    int64_t v = 0;
    if (!QB_PREPARE(ndb, q, s))
        return 0;
    if (AR_STEP_ROW(s))
        v = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return v;
}

bool db_fleet_board_status(struct node_db *ndb, int64_t now,
                           struct fleet_board_status *out)
{
    if (!ndb || !ndb->open || !out)
        return false;
    memset(out, 0, sizeof(*out));
    struct qb q;

    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_count_star(&q);
    out->posts = board_scalar(ndb, &q);

    /* Each row stores the canonical size it was measured at on ingest, so
     * the footprint is one aggregate rather than a walk of every row. */
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_agg(&q, QB_SUM, QB_C_fleet_board_posts_body_bytes, true);
    out->bytes = board_scalar(ndb, &q);

    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_agg(&q, QB_MIN, QB_C_fleet_board_posts_created_at, true);
    out->oldest_created_at = board_scalar(ndb, &q);

    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_agg(&q, QB_MAX, QB_C_fleet_board_posts_created_at, true);
    out->newest_created_at = board_scalar(ndb, &q);

    {
        struct qb sub;
        struct fleet_board_filter open_filter;
        memset(&open_filter, 0, sizeof(open_filter));
        open_filter.open_only = true;
        qb_select(&q, QB_T_fleet_board_posts);
        qb_select_count_star(&q);
        board_apply_filter(&q, &open_filter, now, &sub);
        out->open_questions = board_scalar(ndb, &q);
    }

    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_agg(&q, QB_COUNT_DISTINCT, QB_C_fleet_board_posts_slug, true);
    qb_where_int(&q, QB_C_fleet_board_posts_kind, QB_EQ,
                 FLEET_BOARD_KIND_WIKI);
    out->wiki_pages = board_scalar(ndb, &q);

    return board_head_chain(ndb, out->head_chain, &out->head_chain_set);
}

bool db_fleet_board_chain_verify(struct node_db *ndb, int64_t *checked_out)
{
    if (checked_out)
        *checked_out = 0;
    if (!ndb || !ndb->open)
        return false;
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_columns(&q, k_board_cols, BOARD_NCOLS);
    qb_order_by(&q, QB_C_fleet_board_posts_seq, QB_ASC);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s)) {
        /* A chain the node cannot READ is reported as not intact, and the
         * reason is logged: "the chain is broken" and "I could not look" are
         * different findings and must not answer the same way silently. */
        LOG_WARN("fleet.board",
                 "chain verify could not read the ledger: %s", qb_error(&q));
        return false;
    }

    uint8_t expect_prev[32];
    memset(expect_prev, 0, sizeof(expect_prev));
    bool ok = true;
    int64_t checked = 0;
    while (ok && AR_STEP_ROW(s)) {
        struct db_fleet_board_post row;
        uint8_t want[32];
        memset(&row, 0, sizeof(row));
        if (!fleet_board_row_read(s, &row)) {
            ok = false;
            break;
        }
        if (memcmp(row.chain_prev, expect_prev, 32) != 0) {
            ok = false;
            break;
        }
        fleet_board_chain_step(row.chain_prev, row.post.id, want);
        if (memcmp(want, row.chain_hash, 32) != 0) {
            ok = false;
            break;
        }
        memcpy(expect_prev, row.chain_hash, 32);
        checked++;
    }
    sqlite3_finalize(s);
    if (checked_out)
        *checked_out = checked;
    return ok;
}

