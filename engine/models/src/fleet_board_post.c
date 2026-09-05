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

#include "config/runtime.h"
#include "json/json.h"
/* model_fields.h defines the ZCL_MODEL_* constructors the field list is
 * written in, so it must precede the list it decodes. */
#include "models/model_fields.h"
#include "models/def/fleet_board_post_fields.def"
#include "models/query_builder.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

DEFINE_MODEL_CALLBACKS(fleet_board_post)

static const uint8_t k_zero32[32] = {0};
static zcl_mutex_t s_board_write_lock;
static zcl_once_t s_board_write_once = ZCL_ONCE_INIT;

static void board_write_lock_init(void)
{
    zcl_mutex_init(&s_board_write_lock);
}

static void board_write_lock(void)
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

static int64_t board_max_bytes(void)
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

static bool board_row(sqlite3_stmt *s, struct db_fleet_board_post *out)
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
        memset(out, 0, sizeof(*out));
        return false;
    }
    return true;
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

struct fleet_board_slug_ref {
    char slug[FLEET_BOARD_SLUG_MAX + 1];
};
#define FB_QB_SLUG_COLUMN(kind, col, member, extra) \
    ZCL_MF_CAT(QB_C_fleet_board_posts_, col),
static const enum qb_column k_board_slug_cols[] = {
    ZCL_MODEL_EXPAND(FB_QB_SLUG_COLUMN, FLEET_BOARD_SLUG_FIELDS)
};
#define BOARD_SLUG_NCOLS \
    (sizeof(k_board_slug_cols) / sizeof(k_board_slug_cols[0]))
ZCL_MODEL_READ_ROW_FN(board_read_slug_ref, struct fleet_board_slug_ref,
                      FLEET_BOARD_SLUG_FIELDS)

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
    validates_custom(errors,
        record->body_bytes > 0 &&
            record->body_bytes <= (int64_t)FLEET_BOARD_BODY_MAX,
        "body_bytes", "must be the canonical encoded size");
    validates_custom(errors,
        memcmp(record->post.id, k_zero32, sizeof(k_zero32)) != 0,
        "id", "must be the computed post id");
    return !ar_errors_any(errors);
}

static int64_t board_next_seq(struct node_db *ndb)
{
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_agg(&q, QB_MAX, QB_C_fleet_board_posts_seq, true);
    sqlite3_stmt *s = NULL;
    int64_t top = 0;
    if (!QB_PREPARE(ndb, &q, s))
        return 0;
    if (AR_STEP_ROW(s))
        top = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return top + 1;
}

static bool board_head_chain(struct node_db *ndb, uint8_t out[32])
{
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_columns(&q, k_board_chain_cols, BOARD_CHAIN_NCOLS);
    qb_order_by(&q, QB_C_fleet_board_posts_seq, QB_DESC);
    qb_limit(&q, 1);
    sqlite3_stmt *s = NULL;
    bool found = false;
    /* raw-return-ok:no-head-means-genesis — the caller answers a missing
     * head by chaining from 32 zero bytes, which is the correct first
     * link, so an unreadable head is not an error to report twice. */
    if (!QB_PREPARE(ndb, &q, s))
        return false; // raw-return-ok:no-head-means-genesis
    if (AR_STEP_ROW(s)) {
        struct fleet_board_chain_ref head;
        board_read_chain_ref(&head, s);
        memcpy(out, head.chain_hash, 32);
        found = true;
    }
    sqlite3_finalize(s);
    return found;
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

/* The AR-lifecycle insert. Split out so ingest can keep its decision logic
 * readable and its one write in one place. */
static bool board_insert(struct node_db *ndb,
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
    /* ar-lifecycle-ok:qb-adhoc-save-expands-to-AR_BEGIN_SAVE-and-AR_FINISH_SAVE */
    QB_ADHOC_SAVE(ndb, &q, s, cbs, "fleet_board_post", record,
                  db_fleet_board_post_validate);
}

static bool board_aggregate_checked(struct node_db *ndb, struct qb *q,
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
    if (!board_aggregate_checked(ndb, &q, &posts)) {
        LOG_WARN("fleet.board", "append capacity post-count aggregate failed");
        return false;
    }
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_agg(&q, QB_SUM, QB_C_fleet_board_posts_body_bytes, true);
    if (!board_aggregate_checked(ndb, &q, &bytes)) {
        LOG_WARN("fleet.board", "append capacity byte-sum aggregate failed");
        return false;
    }
    int64_t max_posts = board_max_posts();
    int64_t max_bytes = board_max_bytes();
    return posts < max_posts && body_bytes > 0 && body_bytes <= max_bytes &&
           bytes <= max_bytes - body_bytes;
}

enum fleet_board_result db_fleet_board_post_ingest(
    struct node_db *ndb, const struct fleet_board_post *post, int64_t now,
    bool *stored_out)
{
    if (stored_out)
        *stored_out = false;
    if (!ndb || !ndb->open || !post)
        return FLEET_BOARD_ERR_ARGS;

    /* Order matters: shape, then time, then signature. The first two are
     * cheap and reject the bulk of a flood before any curve arithmetic. */
    enum fleet_board_result r = fleet_board_post_validate(post);
    if (r != FLEET_BOARD_OK)
        return r;
    r = fleet_board_post_check_time(post, now);
    if (r != FLEET_BOARD_OK)
        return r;
    r = fleet_board_post_verify(post);
    if (r != FLEET_BOARD_OK)
        return r;

    /* The canonical size is measured once here and stored, so the ledger can
     * cap and report its own footprint with one SQL aggregate. Measuring it
     * needs no buffer: canonical() reports the size it would have written. */
    size_t body_len = 0;
    (void)fleet_board_post_canonical(post, NULL, 0, &body_len);
    if (body_len == 0 || body_len > FLEET_BOARD_BODY_MAX)
        return FLEET_BOARD_ERR_CAPACITY;

    /* Serialize only board writers in-process. This avoids BEGIN IMMEDIATE's
     * node-wide busy wait and never joins an open consensus transaction. */
    struct node_db_status db_status;
    node_db_get_status(ndb, &db_status);
    if (db_status.tx_open)
        return FLEET_BOARD_ERR_CAPACITY;
    board_write_lock();
    node_db_get_status(ndb, &db_status);
    if (db_status.tx_open) {
        zcl_mutex_unlock(&s_board_write_lock);
        return FLEET_BOARD_ERR_CAPACITY;
    }
    if (db_fleet_board_have(ndb, post->id)) {
        zcl_mutex_unlock(&s_board_write_lock);
        return FLEET_BOARD_OK;
    }
    if (!board_append_fits(ndb, (int64_t)body_len)) {
        zcl_mutex_unlock(&s_board_write_lock);
        return FLEET_BOARD_ERR_CAPACITY;
    }

    struct db_fleet_board_post record;
    memset(&record, 0, sizeof(record));
    record.post = *post;
    record.seq = board_next_seq(ndb);
    record.expires_at = (int64_t)post->created_at + (int64_t)post->ttl;
    record.body_bytes = (int64_t)body_len;
    record.received_at = now;
    if (!board_head_chain(ndb, record.chain_prev))
        memset(record.chain_prev, 0, sizeof(record.chain_prev));
    fleet_board_chain_step(record.chain_prev, record.post.id,
                           record.chain_hash);

    if (!board_insert(ndb, &record)) {
        LOG_WARN("fleet.board", "post seq=%lld could not be appended",
                 (long long)record.seq);
        zcl_mutex_unlock(&s_board_write_lock);
        return FLEET_BOARD_ERR_ARGS;
    }
    zcl_mutex_unlock(&s_board_write_lock);
    if (stored_out)
        *stored_out = true;
    return FLEET_BOARD_OK;
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
    bool found = AR_STEP_ROW(s) && board_row(s, out);
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

static void board_where_discoverable(struct qb *q, int64_t now)
{
    qb_group_begin(q, QB_OR);
    qb_where_int(q, QB_C_fleet_board_posts_expires_at, QB_GT, now);
    qb_where_int(q, QB_C_fleet_board_posts_kind, QB_EQ, FLEET_BOARD_KIND_WIKI);
    qb_group_end(q);
}

static void board_apply_filter(struct qb *q,
                               const struct fleet_board_filter *filter,
                               int64_t now, struct qb *sub_storage)
{
    board_where_discoverable(q, now);
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

int db_fleet_board_list(struct node_db *ndb,
                        const struct fleet_board_filter *filter, int64_t now,
                        struct db_fleet_board_post *out, size_t max)
{
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
        if (!board_row(s, &row))
            continue;
        out[count++] = row;
    }
    sqlite3_finalize(s);
    return count;
}

bool db_fleet_board_wiki_read(struct node_db *ndb, const char *slug,
                              struct db_fleet_board_post *out)
{
    /* raw-return-ok:absent-page-is-not-an-error — an illegal or unknown slug
     * has no page, and saying so in the log on every miss would drown the
     * one line that matters. */
    if (!ndb || !ndb->open || !out || !fleet_board_slug_valid(slug))
        return false; // raw-return-ok:absent-page-is-not-an-error
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_columns(&q, k_board_cols, BOARD_NCOLS);
    qb_where_int(&q, QB_C_fleet_board_posts_kind, QB_EQ,
                 FLEET_BOARD_KIND_WIKI);
    qb_where_text(&q, QB_C_fleet_board_posts_slug, QB_EQ, slug);
    /* Newest created_at wins; the larger id breaks a tie, so two nodes
     * holding the same revisions always resolve the same page. */
    qb_order_by(&q, QB_C_fleet_board_posts_created_at, QB_DESC);
    qb_order_by(&q, QB_C_fleet_board_posts_id, QB_DESC);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s)) {
        LOG_WARN("fleet.board", "wiki latest prepare failed slug=%s: %s",
                 slug, qb_error(&q));
        return false;
    }
    bool found = false;
    while (!found && AR_STEP_ROW(s))
        found = board_row(s, out);
    sqlite3_finalize(s);
    return found;
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
        if (!board_row(s, &row))
            continue;
        out[count++] = row;
    }
    sqlite3_finalize(s);
    return count;
}

int db_fleet_board_wiki_list(struct node_db *ndb,
                             struct db_fleet_board_post *out, size_t max)
{
    if (!ndb || !ndb->open || !out || max == 0)
        return 0;
    if (max > FLEET_BOARD_LIST_MAX)
        max = FLEET_BOARD_LIST_MAX;

    /* Two bounded steps rather than one GROUP BY: collect the distinct slugs
     * in order, then resolve each one through the same latest-revision rule
     * `wiki read` uses. One rule, one place. */
    char slugs[FLEET_BOARD_LIST_MAX][FLEET_BOARD_SLUG_MAX + 1];
    size_t n_slugs = 0;
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_columns(&q, k_board_slug_cols, BOARD_SLUG_NCOLS);
    qb_where_int(&q, QB_C_fleet_board_posts_kind, QB_EQ,
                 FLEET_BOARD_KIND_WIKI);
    qb_order_by(&q, QB_C_fleet_board_posts_slug, QB_ASC);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s))
        return 0;
    while (AR_STEP_ROW(s) && n_slugs < max) {
        struct fleet_board_slug_ref row;
        board_read_slug_ref(&row, s);
        if (n_slugs && strcmp(slugs[n_slugs - 1], row.slug) == 0)
            continue;               /* ordered, so a repeat is adjacent */
        (void)snprintf(slugs[n_slugs], sizeof(slugs[n_slugs]), "%s", row.slug);
        n_slugs++;
    }
    sqlite3_finalize(s);

    int written = 0;
    for (size_t i = 0; i < n_slugs; i++) {
        if (db_fleet_board_wiki_read(ndb, slugs[i], &out[written]))
            written++;
    }
    return written;
}

int db_fleet_board_ids_before(struct node_db *ndb, int64_t now,
                              int64_t before_seq, uint8_t (*ids)[32],
                              size_t max, int64_t *last_seq_out)
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
    board_where_discoverable(&q, now);
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
        if (!board_row(s, &row)) {
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
                              uint8_t (*ids)[32], size_t max)
{
    return db_fleet_board_ids_before(ndb, now, 0, ids, max, NULL);
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

    out->head_chain_set = board_head_chain(ndb, out->head_chain);
    return true;
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
        if (!board_row(s, &row)) {
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

bool fleet_board_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    struct node_db *ndb = app_runtime_node_db();
    json_push_kv_bool(out, "db_open", ndb && ndb->open);
    if (!ndb || !ndb->open)
        return true;
    struct fleet_board_status status;
    int64_t now = (int64_t)platform_time_wall_time_t();
    if (!db_fleet_board_status(ndb, now, &status))
        return true;
    json_push_kv_int(out, "posts", status.posts);
    json_push_kv_int(out, "bytes", status.bytes);
    json_push_kv_int(out, "open_questions", status.open_questions);
    json_push_kv_int(out, "wiki_pages", status.wiki_pages);
    json_push_kv_int(out, "oldest_created_at", status.oldest_created_at);
    json_push_kv_int(out, "newest_created_at", status.newest_created_at);
    return true;
}
