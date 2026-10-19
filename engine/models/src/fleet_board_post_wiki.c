/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fleet board store: bounded wiki reads and the wiki budget's read-only half. The per-key wiki
 * ceilings (and the test seam that lowers them), the decision under the
 * board write lock of whether a key at its stored ceiling may replace one of
 * its own superseded revisions, and the bound that keeps all wiki rows
 * within half of the store's byte cap. See models/fleet_board_post.h. The
 * replacement itself, like every write, is in fleet_board_post.c.
 *
 * ar-validate-skip:read-only-queries — this file never writes a row. */

#include "models/fleet_board_post.h"
#include "models/fleet_board_post_internal.h"

#include "models/model_fields.h"
#include "models/def/fleet_board_post_fields.def"
#include "models/activerecord.h"
#include "models/query_builder.h"
#include "session/fleet_wiki_entry.h"
#include "base/safe_alloc.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef ZCL_TESTING
static int64_t s_test_wiki_window_max;
static int64_t s_test_wiki_stored_max;

void db_fleet_board_test_set_wiki_limits(int64_t window_max,
                                         int64_t stored_max)
{
    s_test_wiki_window_max = window_max > 0 ? window_max : 0;
    s_test_wiki_stored_max = stored_max > 0 ? stored_max : 0;
}
#endif

int64_t fleet_board_wiki_window_max(void)
{
#ifdef ZCL_TESTING
    if (s_test_wiki_window_max > 0)
        return s_test_wiki_window_max;
#endif
    return FLEET_BOARD_WIKI_QUOTA_WINDOW_MAX;
}

static int64_t board_wiki_stored_max(void)
{
#ifdef ZCL_TESTING
    if (s_test_wiki_stored_max > 0)
        return s_test_wiki_stored_max;
#endif
    return FLEET_BOARD_WIKI_QUOTA_STORED_MAX;
}

/* One stored wiki revision of one key, as much as the eviction rule reads. */
struct board_wiki_row {
    bool review;
    uint8_t id[32];
    char slug[FLEET_BOARD_SLUG_MAX + 1];
    int64_t created_at;
};
enum { BOARD_WIKI_SCAN_MAX = FLEET_BOARD_PUBLIC_QUOTA_STORED_MAX };


/* This key's wiki rows in this scope, oldest first. Returns the count, or -1
 * when the scan failed or the key holds more rows than the buffer, in which
 * case nobody can name a safe victim. Caller holds the board write lock. */
static int board_wiki_rows(struct node_db *ndb,
                           const struct fleet_board_post *post,
                           struct board_wiki_row *rows)
{
    struct qb q;
    fleet_board_select_row(&q);
    qb_where_blob(&q, QB_C_fleet_board_posts_host_pubkey, QB_EQ,
                  post->host_pubkey, 32);
    qb_where_int(&q, QB_C_fleet_board_posts_scope, QB_EQ, post->scope);
    qb_where_int(&q, QB_C_fleet_board_posts_kind, QB_EQ, FLEET_BOARD_KIND_WIKI);
    qb_order_by(&q, QB_C_fleet_board_posts_created_at, QB_ASC);
    qb_order_by(&q, QB_C_fleet_board_posts_id, QB_ASC);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s)) return -1;
    int n = 0;
    bool healthy = true;
    while (AR_STEP_ROW(s)) {
        struct db_fleet_board_post row;
        if (n >= BOARD_WIKI_SCAN_MAX || !fleet_board_row_read(s, &row)) {
            healthy = false; break;
        }
        struct json_value review;
        enum fleet_wiki_review_status kind = fleet_wiki_review_parse(
            row.post.text, row.post.text_len, &review, NULL);
        json_free(&review);
        if (kind != FLEET_WIKI_NOT_REVIEW &&
            (kind != FLEET_WIKI_REVIEW_VALID || !fleet_board_review_shape(&row.post))) {
            healthy = false; break;
        }
        memcpy(rows[n].id, row.post.id, 32);
        (void)snprintf(rows[n].slug, sizeof(rows[n].slug), "%s", row.post.slug);
        rows[n].created_at = (int64_t)row.post.created_at;
        rows[n].review = kind == FLEET_WIKI_REVIEW_VALID;
        n++;
    }
    healthy = sqlite3_reset(s) == SQLITE_OK && healthy;
    sqlite3_finalize(s);
    return healthy ? n : -1;
}


/* True when `other` is a later revision than (created_at, id): the same
 * order db_fleet_board_wiki_read resolves a page by. */
static bool board_wiki_later(const struct board_wiki_row *other,
                             int64_t created_at, const uint8_t id[32])
{
    return other->created_at > created_at ||
           (other->created_at == created_at &&
            memcmp(other->id, id, 32) > 0);
}

static bool board_wiki_plain_superseded(const struct board_wiki_row *rows,
    int n, int i, const struct fleet_board_post *post, bool incoming_review)
{
    if (!incoming_review && !strcmp(rows[i].slug, post->slug)) return true;
    for (int j = 0; j < n; j++)
        if (!rows[j].review && !strcmp(rows[j].slug, rows[i].slug) &&
            board_wiki_later(&rows[j], rows[i].created_at, rows[i].id)) return true;
    return false;
}


static bool board_wiki_pick_victim(const struct board_wiki_row *rows, int n,
                                   const struct fleet_board_post *post,
                                   uint8_t victim[32])
{
    struct json_value review;
    enum fleet_wiki_review_status kind = fleet_wiki_review_parse(
        post->text, post->text_len, &review, NULL);
    json_free(&review);
    if (kind != FLEET_WIKI_NOT_REVIEW && kind != FLEET_WIKI_REVIEW_VALID)
        return false;
    bool incoming_review = kind == FLEET_WIKI_REVIEW_VALID;
    if (!incoming_review)
        for (int i = 0; i < n; i++)
            if (!rows[i].review && strcmp(rows[i].slug, post->slug) == 0 &&
                board_wiki_later(&rows[i], (int64_t)post->created_at, post->id))
                return false;
    for (int i = 0; i < n; i++) {
        /* Review ancestors are needed to establish complete lineage. Quota
         * pressure may refuse an append, never silently sever that evidence. */
        if (rows[i].review) continue;
        if (board_wiki_plain_superseded(rows, n, i, post, incoming_review)) { memcpy(victim, rows[i].id, 32); return true; }
    }
    return false;
}

/* The wiki stored leg, decided under the board write lock: room, or the id
 * of this key's own oldest superseded revision to replace, or the final
 * refusal. Only this key's rows in this scope are ever read, so an
 * incoming revision can never name another key's row. */
enum fleet_board_result fleet_board_wiki_room(
    struct node_db *ndb, const struct fleet_board_post *post, bool *evict,
    uint8_t victim[32])
{
    *evict = false;
    if (post->kind != FLEET_BOARD_KIND_WIKI ||
        post->scope == FLEET_BOARD_SCOPE_LEGACY_PUBLIC)
        return FLEET_BOARD_OK;
    int64_t resident = 0;
    if (!fleet_board_key_count(ndb, post->host_pubkey, post->scope, true, -1,
                               &resident)) {
        LOG_WARN("fleet.board", "wiki resident aggregate failed");
        return FLEET_BOARD_ERR_WIKI_QUOTA;
    }
    if (resident < board_wiki_stored_max())
        return FLEET_BOARD_OK;
    static struct board_wiki_row rows[BOARD_WIKI_SCAN_MAX];
    int n = board_wiki_rows(ndb, post, rows);
    if (n < 0 || !board_wiki_pick_victim(rows, n, post, victim))
        return FLEET_BOARD_ERR_WIKI_FULL;
    *evict = true;
    return FLEET_BOARD_OK;
}

/* Wiki rows are permanent, so together they may use at most half the
 * store's byte cap: they can never fill the store and block ordinary posts.
 * Caller holds the board write lock; a query error refuses. */
bool fleet_board_wiki_bytes_fit(struct node_db *ndb, int64_t body_bytes)
{
    struct qb q;
    int64_t bytes = 0;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_agg(&q, QB_SUM, QB_C_fleet_board_posts_body_bytes, true);
    qb_where_int(&q, QB_C_fleet_board_posts_kind, QB_EQ,
                 FLEET_BOARD_KIND_WIKI);
    if (!fleet_board_aggregate_checked(ndb, &q, &bytes)) {
        LOG_WARN("fleet.board", "wiki byte-sum aggregate failed");
        return false;
    }
    int64_t half = fleet_board_max_bytes() / 2;
    return body_bytes <= half && bytes <= half - body_bytes;
}


/* Times of the last replacements, node-wide. Guarded by the board write
 * lock. */
static int64_t s_evict_at[FLEET_BOARD_WIKI_EVICT_MAX];
static unsigned s_evict_used;
static unsigned s_evict_next;

bool fleet_board_wiki_evict_allowed(int64_t now)
{
    unsigned recent = 0;
    for (unsigned i = 0; i < s_evict_used; i++)
        if (s_evict_at[i] > now - FLEET_BOARD_WIKI_EVICT_SECONDS)
            recent++;
    return recent < FLEET_BOARD_WIKI_EVICT_MAX;
}

void fleet_board_wiki_evict_note(int64_t now)
{
    s_evict_at[s_evict_next] = now;
    s_evict_next = (s_evict_next + 1u) % FLEET_BOARD_WIKI_EVICT_MAX;
    if (s_evict_used < FLEET_BOARD_WIKI_EVICT_MAX)
        s_evict_used++;
}

#ifdef ZCL_TESTING
void db_fleet_board_test_reset_wiki_evictions(void)
{
    s_evict_used = 0;
    s_evict_next = 0;
}
#endif

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

static int board_wiki_next_slug(struct node_db *ndb, const char *after,
                                char slug[FLEET_BOARD_SLUG_MAX + 1])
{
    struct qb q;
    qb_select(&q, QB_T_fleet_board_posts);
    qb_select_columns(&q, k_board_slug_cols, BOARD_SLUG_NCOLS);
    qb_where_int(&q, QB_C_fleet_board_posts_kind, QB_EQ, FLEET_BOARD_KIND_WIKI);
    if (after[0])
        qb_where_text(&q, QB_C_fleet_board_posts_slug, QB_GT, after);
    qb_order_by(&q, QB_C_fleet_board_posts_slug, QB_ASC);
    qb_limit(&q, 1);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s)) {
        LOG_WARN("fleet.board", "wiki slug seek prepare failed: %s", qb_error(&q));
        return -1;
    }
    bool found = AR_STEP_ROW(s);
    if (found) {
        struct fleet_board_slug_ref row;
        board_read_slug_ref(&row, s);
        (void)snprintf(slug, FLEET_BOARD_SLUG_MAX + 1, "%s", row.slug);
    }
    bool healthy = found || sqlite3_reset(s) == SQLITE_OK;
    sqlite3_finalize(s);
    if (healthy) return found ? 1 : 0;
    LOG_WARN("fleet.board", "wiki slug seek failed: %s", sqlite3_errmsg(ndb->db));
    return -1;
}

/* Same newest-verifying rule as wiki_read, with an explicit bound on this
 * query's total cryptographic revision reads. Plain text is still a winner. */
static enum fleet_wiki_query_status board_wiki_query_latest(
    struct node_db *ndb, const char *slug, unsigned *verified,
    struct db_fleet_board_post *out, bool *found)
{
    *found = false;
    struct qb q;
    fleet_board_select_row(&q);
    qb_where_int(&q, QB_C_fleet_board_posts_kind, QB_EQ, FLEET_BOARD_KIND_WIKI);
    qb_where_text(&q, QB_C_fleet_board_posts_slug, QB_EQ, slug);
    qb_order_by(&q, QB_C_fleet_board_posts_created_at, QB_DESC);
    qb_order_by(&q, QB_C_fleet_board_posts_id, QB_DESC);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s)) {
        LOG_WARN("fleet.board", "wiki revision seek prepare failed slug=%s: %s", slug, qb_error(&q));
        return FLEET_WIKI_QUERY_STORAGE;
    }
    enum fleet_wiki_query_status status = FLEET_WIKI_QUERY_DONE;
    for (;;) {
        if (!AR_STEP_ROW(s)) {
            if (sqlite3_reset(s) != SQLITE_OK) {
                LOG_WARN("fleet.board", "wiki revision seek failed slug=%s: %s",
                    slug, sqlite3_errmsg(ndb->db));
                status = FLEET_WIKI_QUERY_STORAGE;
            }
            break;
        }
        if (*verified >= FLEET_BOARD_LIST_MAX) {
            status = FLEET_WIKI_QUERY_VERIFY_BUDGET;
            break;
        }
        (*verified)++;
        if (fleet_board_row_read(s, out)) {
            struct json_value review;
            enum fleet_wiki_review_status kind = fleet_wiki_review_parse(out->post.text, out->post.text_len, &review, NULL);
            json_free(&review);
            if (kind == FLEET_WIKI_REVIEW_ALLOC_FAILED) { status = FLEET_WIKI_QUERY_VISITOR_FAILED; break; }
            if (kind != FLEET_WIKI_NOT_REVIEW) continue;
            *found = true;
            break;
        }
    }
    sqlite3_finalize(s);
    return status;
}

static bool board_wiki_query_arguments(struct node_db *ndb, const char *after,
    fleet_wiki_visit_fn visit, struct fleet_wiki_query_progress *progress)
{
    if (!ndb || !ndb->open || !after || !visit || !progress)
        LOG_RETURN(false, "fleet.board", "wiki query requires an open DB, cursor, visitor and progress");
    if (after[0] && !fleet_board_slug_valid(after))
        LOG_RETURN(false, "fleet.board", "wiki query cursor is not a valid slug");
    return true;
}

static bool board_wiki_list_args_ok(struct node_db *ndb, const char *after,
    const struct db_fleet_board_post *out, size_t max)
{
    return ndb && ndb->open && after && out && max > 0 &&
        (!after[0] || fleet_board_slug_valid(after));
}

int db_fleet_board_wiki_list_after(struct node_db *ndb, const char *after,
    struct db_fleet_board_post *out, size_t max,
    char last_scanned[FLEET_BOARD_SLUG_MAX + 1], bool *more)
{
    char last_sink[FLEET_BOARD_SLUG_MAX + 1];
    bool more_sink;
    char *last = last_scanned ? last_scanned : last_sink;
    bool *has_more = more ? more : &more_sink;
    last[0] = '\0';
    *has_more = false;
    if (!board_wiki_list_args_ok(ndb, after, out, max))
        return 0;
    if (max > FLEET_BOARD_LIST_MAX)
        max = FLEET_BOARD_LIST_MAX;
    char slug[FLEET_BOARD_SLUG_MAX + 1];
    (void)snprintf(last, FLEET_BOARD_SLUG_MAX + 1, "%s", after);
    size_t scanned = 0;
    int written = 0;
    while (board_wiki_next_slug(ndb, last, slug) > 0) {
        if (scanned++ == max) {
            *has_more = true;
            break;
        }
        (void)snprintf(last, FLEET_BOARD_SLUG_MAX + 1, "%s", slug);
        if (db_fleet_board_wiki_read(ndb, slug, &out[written]))
            written++;
    }
    return written;
}

bool db_fleet_board_wiki_query(struct node_db *ndb, const char *after,
    fleet_wiki_visit_fn visit, void *context,
    struct fleet_wiki_query_progress *progress)
{
    if (!board_wiki_query_arguments(ndb, after, visit, progress)) return false;
    memset(progress, 0, sizeof(*progress));
    (void)snprintf(progress->after_slug, sizeof(progress->after_slug), "%s", after);
    while (progress->scanned < FLEET_BOARD_LIST_MAX) {
        char slug[FLEET_BOARD_SLUG_MAX + 1];
        int next = board_wiki_next_slug(ndb, progress->after_slug, slug);
        if (next < 0) { progress->status = FLEET_WIKI_QUERY_STORAGE; return false; }
        if (next == 0) return true;
        struct db_fleet_board_post row;
        bool found;
        progress->status = board_wiki_query_latest(ndb, slug,
            &progress->verified, &row, &found);
        if (progress->status != FLEET_WIKI_QUERY_DONE) {
            (void)snprintf(progress->blocked_slug, sizeof(progress->blocked_slug), "%s", slug);
            return progress->status != FLEET_WIKI_QUERY_STORAGE;
        }
        enum fleet_wiki_visit_result accepted = FLEET_WIKI_VISIT_CONTINUE;
        if (found) accepted = visit(context, &row);
        if (accepted == FLEET_WIKI_VISIT_FAILED) {
            progress->status = FLEET_WIKI_QUERY_VISITOR_FAILED;
            return false;
        }
        if (accepted == FLEET_WIKI_VISIT_PAGE) {
            progress->status = FLEET_WIKI_QUERY_PAGE;
            return true;
        }
        progress->scanned++;
        (void)snprintf(progress->after_slug, sizeof(progress->after_slug), "%s", slug);
    }
    progress->status = FLEET_WIKI_QUERY_PAGE;
    return true;
}

bool db_fleet_board_wiki_read_checked(struct node_db *ndb, const char *slug,
    struct db_fleet_board_post *out, bool *newer_unverified)
{
    /* raw-return-ok:absent-page-is-not-an-error — same contract as
     * db_fleet_board_wiki_read: an illegal or unknown slug has no page. */
    if (!ndb || !ndb->open || !out || !newer_unverified ||
        !fleet_board_slug_valid(slug))
        return false; // raw-return-ok:absent-page-is-not-an-error
    unsigned verified = 0;
    bool found = false;
    *newer_unverified = false;
    enum fleet_wiki_query_status status =
        board_wiki_query_latest(ndb, slug, &verified, out, &found);
    if (status != FLEET_WIKI_QUERY_DONE || !found)
        return false; // raw-return-ok:absent-page-is-not-an-error
    /* Every attempt before the winner was a newer revision that failed. */
    *newer_unverified = verified > 1;
    return true;
}

/* The signed review type is a payload format, not a second storage authority. */
bool fleet_board_review_shape(const struct fleet_board_post *post)
{
    if (!post || post->kind != FLEET_BOARD_KIND_WIKI) return post != NULL;
    struct json_value review;
    enum fleet_wiki_review_status kind = fleet_wiki_review_parse(
        post->text, post->text_len, &review, NULL);
    bool valid = kind == FLEET_WIKI_NOT_REVIEW;
    if (kind == FLEET_WIKI_REVIEW_VALID) {
        uint8_t target[32];
        valid = fleet_board_id_from_hex(json_get_str(json_get(&review, "target")), target) &&
            !memcmp(target, post->ref, 32);
    }
    json_free(&review);
    if (!valid) LOG_WARN("fleet.board", "signed wiki review shape or target binding refused");
    return valid;
}

static bool review_same_lineage(const struct fleet_board_post *a,
    const struct fleet_board_post *b)
{
    return a->kind == FLEET_BOARD_KIND_WIKI && b->kind == FLEET_BOARD_KIND_WIKI &&
        a->scope == b->scope && !strcmp(a->room, b->room) &&
        !memcmp(a->host_pubkey, b->host_pubkey, 32) && !memcmp(a->ref, b->ref, 32);
}

static bool review_is_typed(const struct fleet_board_post *post)
{
    struct json_value review;
    enum fleet_wiki_review_status kind = fleet_wiki_review_parse(
        post->text, post->text_len, &review, NULL);
    json_free(&review);
    return kind == FLEET_WIKI_REVIEW_VALID && fleet_board_review_shape(post);
}

static bool review_ancestry(struct node_db *, const struct fleet_board_post *);

enum fleet_board_result db_fleet_board_review_local_check(
    struct node_db *ndb, const struct fleet_board_post *post)
{
    struct json_value review;
    enum fleet_wiki_review_status kind = fleet_wiki_review_parse(post->text, post->text_len, &review, NULL);
    json_free(&review);
    if (kind == FLEET_WIKI_NOT_REVIEW) return FLEET_BOARD_OK;
    if (kind != FLEET_WIKI_REVIEW_VALID || !fleet_board_review_shape(post)) return FLEET_BOARD_ERR_TEXT;
    struct db_fleet_board_post target;
    if (!db_fleet_board_post_find(ndb, post->ref, &target) ||
        target.post.kind != FLEET_BOARD_KIND_WIKI ||
        target.post.scope != post->scope || strcmp(target.post.room, post->room)) {
        LOG_WARN("fleet.board", "local review requires a retained verified target in the same visibility scope and room");
        return FLEET_BOARD_ERR_SCOPE;
    }
    static const uint8_t zero[32];
    if (memcmp(post->supersedes, zero, 32)) {
        struct db_fleet_board_post parent;
        if (!db_fleet_board_post_find(ndb, post->supersedes, &parent) ||
            !review_is_typed(&parent.post) || !review_same_lineage(post, &parent.post) ||
            !review_ancestry(ndb, &parent.post)) {
            LOG_WARN("fleet.board", "local review predecessor is unavailable or belongs to another reviewer or target");
            return FLEET_BOARD_ERR_TEXT;
        }
    }
    return FLEET_BOARD_OK;
}

/* Stable id pagination is independent of mutable newest-by-slug selection.
 * Corrupt rows fail the entire page; no false exhaustion is reported. */
static bool review_row_classify(const struct fleet_board_post *post, bool *typed)
{
    struct json_value review;
    enum fleet_wiki_review_status kind =
        fleet_wiki_review_parse(post->text, post->text_len, &review, NULL);
    json_free(&review);
    *typed = kind == FLEET_WIKI_REVIEW_VALID;
    if (kind == FLEET_WIKI_NOT_REVIEW) return true;
    return kind == FLEET_WIKI_REVIEW_VALID && fleet_board_review_shape(post);
}

static bool review_page_arguments(struct node_db *ndb, const uint8_t *target,
    const uint8_t *after, struct db_fleet_board_post *out, size_t max,
    size_t *count, uint8_t *next, bool *more)
{
    if (!ndb || !ndb->open || !target || !after || !out || !count ||
        !next || !more || !max || max > FLEET_BOARD_LIST_MAX) {
        LOG_WARN("fleet.board", "review page requires open storage, ids and bounded output arguments");
        return false;
    }
    return true;
}


bool db_fleet_board_wiki_reviews(struct node_db *ndb, const uint8_t target[32],
    const uint8_t after[32], struct db_fleet_board_post *out, size_t max,
    size_t *count, uint8_t next[32], bool *more)
{
    if (!review_page_arguments(ndb, target, after, out, max, count, next, more)) return false;
    *count = 0; *more = false;
    memcpy(next, after, 32);
    struct qb q;
    fleet_board_select_row(&q);
    qb_where_int(&q, QB_C_fleet_board_posts_kind, QB_EQ, FLEET_BOARD_KIND_WIKI);
    qb_where_blob(&q, QB_C_fleet_board_posts_ref, QB_EQ, target, 32);
    qb_where_int(&q, QB_C_fleet_board_posts_scope, QB_EQ, FLEET_BOARD_SCOPE_PUBLIC);
    qb_where_text(&q, QB_C_fleet_board_posts_room, QB_EQ, FLEET_BOARD_ROOM_DEFAULT);
    qb_where_blob(&q, QB_C_fleet_board_posts_id, QB_GT, after, 32);
    qb_order_by(&q, QB_C_fleet_board_posts_id, QB_ASC);
    qb_limit(&q, FLEET_BOARD_LIST_MAX + 1);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s)) {
        LOG_WARN("fleet.board", "review page query prepare failed: %s", qb_error(&q));
        return false;
    }
    unsigned scanned = 0;
    bool healthy = true;
    while (AR_STEP_ROW(s)) {
        if (scanned++ == FLEET_BOARD_LIST_MAX || *count == max) { *more = true; break; }
        struct db_fleet_board_post row;
        if (!fleet_board_row_read(s, &row)) { healthy = false; break; }
        bool typed;
        if (!review_row_classify(&row.post, &typed)) { healthy = false; break; }
        memcpy(next, row.post.id, 32);
        if (typed) out[(*count)++] = row;
    }
    healthy = sqlite3_reset(s) == SQLITE_OK && healthy;
    sqlite3_finalize(s);
    if (!healthy) LOG_WARN("fleet.board", "review page could not verify every selected row");
    return healthy;
}

static bool review_ancestry(struct node_db *ndb, const struct fleet_board_post *post)
{
    static const uint8_t zero[32];
    struct fleet_board_post current = *post;
    for (unsigned i = 0; i < FLEET_BOARD_LIST_MAX; i++) {
        if (!memcmp(current.supersedes, zero, 32)) return true;
        struct db_fleet_board_post parent;
        if (!db_fleet_board_post_find(ndb, current.supersedes, &parent) ||
            !review_is_typed(&parent.post) || !review_same_lineage(post, &parent.post))
            return false;
        current = parent.post;
    }
    return false;
}


static bool review_graph_path(const int *parents, size_t n, size_t start)
{
    size_t at = start;
    for (size_t depth = 0; depth < n; depth++) {
        if (parents[at] == -1) return true;
        if (parents[at] < 0) return false;
        at = (size_t)parents[at];
    }
    return false; /* A cycle or traversal beyond this retained graph. */
}

static bool review_graph_load(struct node_db *ndb, const struct fleet_board_post *post,
    struct db_fleet_board_post *rows, size_t *count, unsigned *verified)
{
    struct qb q;
    fleet_board_select_row(&q);
    qb_where_int(&q, QB_C_fleet_board_posts_kind, QB_EQ, FLEET_BOARD_KIND_WIKI);
    qb_where_blob(&q, QB_C_fleet_board_posts_ref, QB_EQ, post->ref, 32);
    qb_where_blob(&q, QB_C_fleet_board_posts_host_pubkey, QB_EQ, post->host_pubkey, 32);
    qb_where_int(&q, QB_C_fleet_board_posts_scope, QB_EQ, post->scope);
    qb_where_text(&q, QB_C_fleet_board_posts_room, QB_EQ, post->room);
    qb_limit(&q, FLEET_BOARD_LIST_MAX + 1);
    sqlite3_stmt *s = NULL;
    *count = 0;
    if (!QB_PREPARE(ndb, &q, s)) return false;
    unsigned scanned = 0;
    bool healthy = true;
    while (AR_STEP_ROW(s)) {
        if (scanned++ == FLEET_BOARD_LIST_MAX) { healthy = false; break; }
        (*verified)++;
        if (!fleet_board_row_read(s, &rows[*count])) { healthy = false; break; }
        bool typed;
        if (!review_row_classify(&rows[*count].post, &typed)) { healthy = false; break; }
        if (typed) (*count)++;
    }
    healthy = sqlite3_reset(s) == SQLITE_OK && healthy;
    sqlite3_finalize(s);
    return healthy;
}

static size_t review_graph_bind(const struct db_fleet_board_post *rows, size_t n,
    const uint8_t id[32], int *parents)
{
    static const uint8_t zero[32];
    size_t own = n;
    for (size_t i = 0; i < n; i++) {
        parents[i] = !memcmp(rows[i].post.supersedes, zero, 32) ? -1 : -2;
        for (size_t j = 0; j < n; j++)
            if (!memcmp(rows[i].post.supersedes, rows[j].post.id, 32))
                parents[i] = (int)j;
        if (!memcmp(rows[i].post.id, id, 32)) own = i;
    }
    return own;
}

static void review_graph_assess(const struct db_fleet_board_post *rows, size_t n,
    const uint8_t id[32], bool healthy, struct fleet_wiki_review_state *state)
{
    int parents[FLEET_BOARD_LIST_MAX];
    size_t own = review_graph_bind(rows, n, id, parents);
    state->lineage_valid = healthy && own < n && review_graph_path(parents, n, own);
    if (healthy) for (size_t i = 0; i < n; i++)
        if (!review_graph_path(parents, n, i)) healthy = false;
    state->complete = healthy;
    if (!healthy) return;
    unsigned leaves = 0;
    for (size_t i = 0; i < n; i++) {
        bool child = false;
        for (size_t j = 0; j < n; j++) if (parents[j] == (int)i) child = true;
        if (child) continue;
        leaves++;
        if (i == own) state->current = true;
    }
    state->fork = leaves > 1;
}

/* At most LIST_MAX graph signatures plus one target signature. Ancestry is
 * then walked in already verified memory, never re-verified per descendant. */
bool db_fleet_board_review_state(struct node_db *ndb,
    const struct fleet_board_post *post, struct fleet_wiki_review_state *state)
{
    if (!state || !post || !review_is_typed(post)) return false;
    memset(state, 0, sizeof(*state));
    struct db_fleet_board_post target;
    state->resolved = db_fleet_board_post_find(ndb, post->ref, &target) &&
        target.post.kind == FLEET_BOARD_KIND_WIKI &&
        target.post.scope == post->scope && !strcmp(target.post.room, post->room);
    struct db_fleet_board_post *rows = zcl_calloc(FLEET_BOARD_LIST_MAX,
        sizeof(*rows), "fleet.board.review_graph");
    if (!rows) return false;
    size_t count;
    bool healthy = review_graph_load(ndb, post, rows, &count, &state->graph_verified);
    review_graph_assess(rows, count, post->id, healthy, state);
    free(rows);
    return true;
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
    fleet_board_select_row(&q);
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
    while (!found && AR_STEP_ROW(s)) {
        if (!fleet_board_row_read(s, out)) continue;
        struct json_value review;
        enum fleet_wiki_review_status kind = fleet_wiki_review_parse(out->post.text, out->post.text_len, &review, NULL);
        json_free(&review);
        if (kind == FLEET_WIKI_REVIEW_ALLOC_FAILED) break;
        found = kind == FLEET_WIKI_NOT_REVIEW;
    }
    sqlite3_finalize(s);
    return found;
}
