/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Fleet wiki mutation: receiver-local compare/append and retained replay.
 * Signing/admission belong to composition; storage uses the existing AR
 * writer and board lock. No parallel request ledger or storage migration.
 * ar-validate-skip:delegated-board-save — signed input is verified here;
 * fleet_board_append_record owns the canonical validators and AR lifecycle. */
#include "models/fleet_board_post.h"
#include "models/fleet_board_post_internal.h"
#include "models/db_txn.h"
#include "models/query_builder.h"
#include "session/fleet_wiki_entry.h"
#include "util/log_macros.h"

#include <string.h>

static enum fleet_board_wiki_write_status wiki_write_row(
    struct node_db *ndb, struct qb *q, struct db_fleet_board_post *out,
    bool unique, bool *found)
{
    sqlite3_stmt *s = NULL;
    *found = false;
    if (!QB_PREPARE(ndb, q, s)) {
        LOG_WARN("fleet.board", "wiki mutation select prepare failed: %s", qb_error(q));
        return FLEET_WIKI_WRITE_STORAGE;
    }
    bool row = AR_STEP_ROW(s);
    bool valid = !row || fleet_board_row_read(s, out);
    bool duplicate = row && unique && AR_STEP_ROW(s);
    int rc = sqlite3_reset(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_OK) {
        LOG_WARN("fleet.board", "wiki mutation select failed: %d", rc);
        return FLEET_WIKI_WRITE_STORAGE;
    }
    if (!valid || duplicate) {
        LOG_WARN("fleet.board", "wiki mutation held row corrupt or request ambiguous");
        return FLEET_WIKI_WRITE_CORRUPT;
    }
    *found = row;
    return FLEET_WIKI_WRITE_OK;
}

static bool wiki_write_payload_same(const struct fleet_board_post *a,
    const struct fleet_board_post *b)
{
    return a->scope == b->scope && a->ttl == b->ttl &&
        a->text_len == b->text_len && !strcmp(a->room, b->room) &&
        !strcmp(a->agent, b->agent) && !strcmp(a->slug, b->slug) &&
        !strcmp(a->title, b->title) && !memcmp(a->text, b->text, a->text_len) &&
        !memcmp(a->ref, b->ref, 32) && !memcmp(a->supersedes, b->supersedes, 32);
}

static enum fleet_board_wiki_write_status wiki_write_replay(
    struct node_db *ndb, const struct fleet_board_post *post,
    struct db_fleet_board_post *out)
{
    struct qb q;
    fleet_board_select_row(&q);
    qb_where_int(&q, QB_C_fleet_board_posts_kind, QB_EQ, FLEET_BOARD_KIND_WIKI);
    qb_where_text(&q, QB_C_fleet_board_posts_receipt, QB_EQ, post->receipt);
    qb_where_blob(&q, QB_C_fleet_board_posts_host_pubkey, QB_EQ, post->host_pubkey, 32);
    qb_limit(&q, 2);
    bool found;
    enum fleet_board_wiki_write_status status = wiki_write_row(ndb, &q, out, true, &found);
    if (status != FLEET_WIKI_WRITE_OK || !found) return status;
    if (!wiki_write_payload_same(post, &out->post)) {
        LOG_WARN("fleet.board", "wiki mutation request marker reused with different payload");
        return FLEET_WIKI_WRITE_COLLISION;
    }
    return FLEET_WIKI_WRITE_REPLAY;
}

static enum fleet_board_wiki_write_status wiki_write_plain_head(
    struct node_db *ndb, struct qb *q, struct db_fleet_board_post *out, bool *found)
{
    *found = false;
    qb_limit(q, FLEET_BOARD_LIST_MAX + 1);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, q, s)) return FLEET_WIKI_WRITE_STORAGE;
    enum fleet_board_wiki_write_status status = FLEET_WIKI_WRITE_OK;
    unsigned scanned = 0;
    while (AR_STEP_ROW(s)) {
        if (++scanned > FLEET_BOARD_LIST_MAX) { status = FLEET_WIKI_WRITE_STORAGE; break; }
        if (!fleet_board_row_read(s, out)) { status = FLEET_WIKI_WRITE_CORRUPT; break; }
        struct json_value review;
        enum fleet_wiki_review_status kind = fleet_wiki_review_parse(
            out->post.text, out->post.text_len, &review, NULL);
        json_free(&review);
        if (kind == FLEET_WIKI_REVIEW_ALLOC_FAILED) { status = FLEET_WIKI_WRITE_STORAGE; break; }
        if (kind != FLEET_WIKI_NOT_REVIEW) continue;
        *found = true; break;
    }
    if (sqlite3_reset(s) != SQLITE_OK) status = FLEET_WIKI_WRITE_STORAGE;
    sqlite3_finalize(s);
    return status;
}


static enum fleet_board_wiki_write_status wiki_write_review_head(
    struct node_db *ndb, const struct fleet_board_post *post, const uint8_t *expected)
{
    struct qb q;
    fleet_board_select_row(&q);
    qb_where_int(&q, QB_C_fleet_board_posts_kind, QB_EQ, FLEET_BOARD_KIND_WIKI);
    qb_where_blob(&q, QB_C_fleet_board_posts_ref, QB_EQ, post->ref, 32);
    qb_where_blob(&q, QB_C_fleet_board_posts_host_pubkey, QB_EQ, post->host_pubkey, 32);
    qb_where_int(&q, QB_C_fleet_board_posts_scope, QB_EQ, post->scope);
    qb_where_text(&q, QB_C_fleet_board_posts_room, QB_EQ, post->room);
    if (expected) qb_where_blob(&q, QB_C_fleet_board_posts_supersedes, QB_EQ, expected, 32);
    qb_limit(&q, FLEET_BOARD_LIST_MAX + 1);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s)) return FLEET_WIKI_WRITE_STORAGE;
    enum fleet_board_wiki_write_status status = FLEET_WIKI_WRITE_OK;
    unsigned scanned = 0;
    while (AR_STEP_ROW(s)) {
        struct db_fleet_board_post row;
        if (++scanned > FLEET_BOARD_LIST_MAX) { status = FLEET_WIKI_WRITE_STORAGE; break; }
        if (!fleet_board_row_read(s, &row)) { status = FLEET_WIKI_WRITE_CORRUPT; break; }
        struct json_value review;
        enum fleet_wiki_review_status kind = fleet_wiki_review_parse(
            row.post.text, row.post.text_len, &review, NULL);
        json_free(&review);
        if (kind == FLEET_WIKI_REVIEW_ALLOC_FAILED) { status = FLEET_WIKI_WRITE_STORAGE; break; }
        if (kind == FLEET_WIKI_NOT_REVIEW) continue;
        if (kind != FLEET_WIKI_REVIEW_VALID || !fleet_board_review_shape(&row.post)) {
            status = FLEET_WIKI_WRITE_CORRUPT; break;
        }
        /* Absent means no prior opinion; an expected id names one explicit
         * graph leaf. An earlier-dated child still supersedes that leaf. */
        status = FLEET_WIKI_WRITE_CONFLICT; break;
    }
    if (sqlite3_reset(s) != SQLITE_OK) status = FLEET_WIKI_WRITE_STORAGE;
    sqlite3_finalize(s);
    if (status != FLEET_WIKI_WRITE_OK || !expected) return status;
    struct db_fleet_board_post parent;
    if (!db_fleet_board_post_find(ndb, expected, &parent)) return FLEET_WIKI_WRITE_CORRUPT;
    return post->created_at > parent.post.created_at ? FLEET_WIKI_WRITE_OK : FLEET_WIKI_WRITE_CLOCK;
}


static enum fleet_board_wiki_write_status wiki_write_head(
    struct node_db *ndb, const struct fleet_board_post *post,
    const uint8_t *expected)
{
    struct qb q;
    fleet_board_select_row(&q);
    qb_where_int(&q, QB_C_fleet_board_posts_kind, QB_EQ, FLEET_BOARD_KIND_WIKI);
    struct json_value review;
    enum fleet_wiki_review_status kind = fleet_wiki_review_parse(post->text, post->text_len, &review, NULL);
    json_free(&review);
    if (kind == FLEET_WIKI_REVIEW_ALLOC_FAILED || kind == FLEET_WIKI_REVIEW_INVALID)
        return FLEET_WIKI_WRITE_STORAGE;
    if (kind == FLEET_WIKI_REVIEW_VALID) return wiki_write_review_head(ndb, post, expected);
    qb_where_text(&q, QB_C_fleet_board_posts_slug, QB_EQ, post->slug);
    qb_order_by(&q, QB_C_fleet_board_posts_created_at, QB_DESC);
    qb_order_by(&q, QB_C_fleet_board_posts_id, QB_DESC);
    struct db_fleet_board_post head;
    bool found;
    enum fleet_board_wiki_write_status status = wiki_write_plain_head(ndb, &q, &head, &found);
    if (status != FLEET_WIKI_WRITE_OK) return status;
    if (found != (expected != NULL) || (found && memcmp(head.post.id, expected, 32))) {
        LOG_WARN("fleet.board", "wiki mutation receiver-local head differs from expected");
        return FLEET_WIKI_WRITE_CONFLICT;
    }
    if (found && post->created_at <= head.post.created_at) {
        LOG_WARN("fleet.board", "wiki mutation requires a strictly later real timestamp");
        return FLEET_WIKI_WRITE_CLOCK;
    }
    return FLEET_WIKI_WRITE_OK;
}

static enum fleet_board_result wiki_write_append(struct node_db *ndb,
    const struct fleet_board_post *post, int64_t now, bool *evicted)
{
    size_t bytes = 0;
    bool known = false;
    enum fleet_board_result r = fleet_board_ingest_prepare(ndb, post, now, &bytes, &known);
    if (r != FLEET_BOARD_OK) return r;
    if (known) return FLEET_BOARD_ERR_STORAGE;
    uint8_t victim[32];
    r = fleet_board_wiki_room(ndb, post, now, evicted, victim);
    if (r != FLEET_BOARD_OK) return r;
    if (*evicted) {
        if (!fleet_board_wiki_evict_allowed(now)) return FLEET_BOARD_ERR_WIKI_QUOTA;
        if (!fleet_board_remove_and_relink(ndb, post, victim)) return FLEET_BOARD_ERR_STORAGE;
    }
    return fleet_board_append_record(ndb, post, now, bytes);
}

static enum fleet_board_wiki_write_status wiki_write_transaction(
    struct node_db *ndb, const struct fleet_board_post *post,
    const uint8_t *expected, int64_t now, struct db_fleet_board_post *out,
    enum fleet_board_result *refusal)
{
    DB_TXN_SCOPE(txn, ndb, "fleet_board.wiki_compare_append");
    if (!txn) return FLEET_WIKI_WRITE_BUSY;
    enum fleet_board_wiki_write_status status = wiki_write_replay(ndb, post, out);
    if (status == FLEET_WIKI_WRITE_REPLAY)
        return db_txn_commit(txn) ? status : FLEET_WIKI_WRITE_STORAGE;
    if (status != FLEET_WIKI_WRITE_OK) return status;
    *refusal = db_fleet_board_review_local_check(ndb, post);
    if (*refusal != FLEET_BOARD_OK) return FLEET_WIKI_WRITE_REFUSED;
    status = wiki_write_head(ndb, post, expected);
    if (status != FLEET_WIKI_WRITE_OK) return status;
    bool evicted = false;
    *refusal = wiki_write_append(ndb, post, now, &evicted);
    if (*refusal == FLEET_BOARD_ERR_STORAGE) return FLEET_WIKI_WRITE_STORAGE;
    if (*refusal != FLEET_BOARD_OK) return FLEET_WIKI_WRITE_REFUSED;
    /* Read back the exact canonical row before committing; this also catches
     * an insertion/readback error without publishing partial success. */
    struct qb q;
    fleet_board_select_row(&q);
    qb_where_blob(&q, QB_C_fleet_board_posts_id, QB_EQ, post->id, 32);
    bool found;
    status = wiki_write_row(ndb, &q, out, true, &found);
    if (status != FLEET_WIKI_WRITE_OK || !found) return FLEET_WIKI_WRITE_STORAGE;
    if (!db_txn_commit(txn)) return FLEET_WIKI_WRITE_STORAGE;
    if (evicted) fleet_board_wiki_evict_note(now);
    return FLEET_WIKI_WRITE_OK;
}

enum fleet_board_wiki_write_status db_fleet_board_wiki_write(
    struct node_db *ndb, const struct fleet_board_post *post,
    const uint8_t *expected, int64_t now, struct db_fleet_board_post *out,
    enum fleet_board_result *refusal)
{
    static const uint8_t absent[32];
    if (!ndb || !ndb->open || !post || !out || !refusal) return FLEET_WIKI_WRITE_ARGS;
    memset(out, 0, sizeof(*out));
    *refusal = FLEET_BOARD_OK;
    if (post->kind != FLEET_BOARD_KIND_WIKI || !post->receipt[0] ||
        memcmp(post->supersedes, expected ? expected : absent, 32)) return FLEET_WIKI_WRITE_ARGS;
    *refusal = fleet_board_post_verify(post);
    if (*refusal != FLEET_BOARD_OK) return FLEET_WIKI_WRITE_REFUSED;
    struct node_db_status db_status;
    node_db_get_status(ndb, &db_status);
    if (db_status.tx_open) return FLEET_WIKI_WRITE_BUSY;
    fleet_board_write_lock();
    int64_t high = fleet_board_arrival_checkpoint();
    enum fleet_board_wiki_write_status status = wiki_write_transaction(ndb, post, expected, now, out, refusal);
    if (status != FLEET_WIKI_WRITE_OK && status != FLEET_WIKI_WRITE_REPLAY)
        fleet_board_arrival_restore(high);
    fleet_board_write_unlock();
    return status;
}
