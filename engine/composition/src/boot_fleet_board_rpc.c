/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `fleet_board` RPC method — the node-side half of every board
 * and wiki command.
 *
 * The CLI half runs in a separate one-shot process from a checkout and holds
 * no node state, so every leaf asks the running node over this one method and
 * fails closed when there is none. That is deliberate: a board a checkout
 * could write privately would be a private notebook, not a fleet board, and
 * two agents would silently diverge.
 *
 * One method, one `op` field, because the whole surface is small and a reader
 * comparing the CLI against the node should be able to see both halves at
 * once. Every op is bounded; no op takes a path, a command, or a key. */

#include "config/boot_fleet_board.h"

#include "config/runtime.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "models/fleet_board_post.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const struct json_value *fb_input(const struct json_value *params)
{
    const struct json_value *first =
        params && json_size(params) ? json_at(params, 0) : NULL;
    return first && first->type == JSON_OBJ ? first : NULL;
}

static void fb_error(struct json_value *result, const char *code,
                     const char *message)
{
    json_set_object(result);
    json_push_kv_bool(result, "ok", false);
    json_push_kv_str(result, "code", code);
    json_push_kv_str(result, "message", message);
}

static void fb_refuse(struct json_value *result, enum fleet_board_result r)
{
    fb_error(result, "BOARD_REFUSED", fleet_board_result_string(r));
}

static const char *fb_str(const struct json_value *in, const char *key,
                          const char *fallback)
{
    const char *v = json_get_str(json_get(in, key));
    return v ? v : fallback;
}

static int64_t fb_int(const struct json_value *in, const char *key,
                      int64_t fallback)
{
    const struct json_value *v = json_get(in, key);
    return v && v->type == JSON_INT ? json_get_int(v) : fallback;
}

static bool fb_bool(const struct json_value *in, const char *key)
{
    const struct json_value *v = json_get(in, key);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

/* One post as a JSON object. Public projection: the host is rendered as its
 * full public key hex, because a board reader must be able to check a
 * signature themselves rather than trust this node's rendering of it. */
static void fb_render_post(struct json_value *into,
                           const struct db_fleet_board_post *row)
{
    char hex[65];
    fleet_board_id_to_hex(row->post.id, hex);
    (void)json_push_kv_str(into, "id", hex);
    (void)json_push_kv_str(into, "kind", fleet_board_kind_name(row->post.kind));
    (void)json_push_kv_int(into, "created_at", (int64_t)row->post.created_at);
    (void)json_push_kv_int(into, "ttl", (int64_t)row->post.ttl);
    (void)json_push_kv_int(into, "expires_at", row->expires_at);
    fleet_board_id_to_hex(row->post.ref, hex);
    (void)json_push_kv_str(into, "ref", hex);
    fleet_board_id_to_hex(row->post.host_pubkey, hex);
    (void)json_push_kv_str(into, "host", hex);
    char signature_hex[FLEET_BOARD_SIG_BYTES * 2 + 1];
    zcl_hex_encode(row->post.signature, FLEET_BOARD_SIG_BYTES, signature_hex);
    (void)json_push_kv_str(into, "signature", signature_hex);
    (void)json_push_kv_str(into, "agent", row->post.agent);
    (void)json_push_kv_str(into, "text", row->post.text);
    (void)json_push_kv_int(into, "text_len", row->post.text_len);
    if (row->post.slug[0]) {
        (void)json_push_kv_str(into, "slug", row->post.slug);
        (void)json_push_kv_str(into, "title", row->post.title);
        fleet_board_id_to_hex(row->post.supersedes, hex);
        (void)json_push_kv_str(into, "supersedes", hex);
    }
    if (row->post.receipt[0])
        (void)json_push_kv_str(into, "receipt", row->post.receipt);
    (void)json_push_kv_int(into, "seq", row->seq);
    (void)json_push_kv_int(into, "received_at", row->received_at);
}

static void fb_render_list(struct json_value *result,
                           const struct db_fleet_board_post *rows, int n)
{
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (int i = 0; i < n; i++) {
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        fb_render_post(&item, &rows[i]);
        (void)json_push_back(&arr, &item);
        json_free(&item);
    }
    (void)json_push_kv(result, "posts", &arr);
    json_free(&arr);
    json_push_kv_int(result, "returned", n);
}

/* Build an unsigned post from the request. Signing, storing, and announcing
 * belong to boot_fleet_board_publish; this only reads caller input. */
static bool fb_compose(const struct json_value *in, struct json_value *result,
                       int64_t now, struct fleet_board_post *post)
{
    memset(post, 0, sizeof(*post));
    const char *kind_name = fb_str(in, "kind", "note");
    if (!fleet_board_kind_from_name(kind_name, &post->kind)) {
        fb_error(result, "BAD_KIND",
                 "kind must be one of problem, need, offer, claim, result, "
                 "note, wiki");
        return false;
    }
    const char *text = fb_str(in, "text", NULL);
    if (!text || !text[0]) {
        fb_error(result, "MISSING_TEXT", "text is required");
        return false;
    }
    size_t text_len = strlen(text);
    if (text_len > fleet_board_text_max(post->kind)) {
        fb_error(result, "TEXT_TOO_LONG",
                 "text is over this kind's signed byte limit");
        return false;
    }
    memcpy(post->text, text, text_len);
    post->text[text_len] = '\0';
    post->text_len = (uint32_t)text_len;

    (void)snprintf(post->agent, sizeof(post->agent), "%s",
                   fb_str(in, "agent", ""));
    (void)snprintf(post->receipt, sizeof(post->receipt), "%s",
                   fb_str(in, "receipt", ""));
    const char *ref = fb_str(in, "ref", NULL);
    if (ref && ref[0] && !fleet_board_id_from_hex(ref, post->ref)) {
        fb_error(result, "BAD_REF", "ref must be a 64-character post id");
        return false;
    }
    if (post->kind == FLEET_BOARD_KIND_WIKI) {
        (void)snprintf(post->slug, sizeof(post->slug), "%s",
                       fb_str(in, "slug", ""));
        (void)snprintf(post->title, sizeof(post->title), "%s",
                       fb_str(in, "title", ""));
        const char *sup = fb_str(in, "supersedes", NULL);
        if (sup && sup[0] &&
            !fleet_board_id_from_hex(sup, post->supersedes)) {
            fb_error(result, "BAD_SUPERSEDES",
                     "supersedes must be a 64-character post id");
            return false;
        }
    }
    int64_t ttl = fb_int(in, "ttl", FLEET_BOARD_TTL_DEFAULT);
    if (ttl <= 0 || ttl > FLEET_BOARD_TTL_MAX) {
        fb_error(result, "BAD_TTL", "ttl must be 1..2592000 seconds");
        return false;
    }
    post->ttl = (uint32_t)ttl;
    post->created_at = (uint64_t)now;

    enum fleet_board_result r = fleet_board_post_validate(post);
    if (r != FLEET_BOARD_OK) {
        fb_refuse(result, r);
        return false;
    }
    return true;
}

static void fb_op_post(const struct json_value *in, struct json_value *result,
                       int64_t now)
{
    struct fleet_board_post post;
    if (!fb_compose(in, result, now, &post))
        return;
    enum fleet_board_result r = boot_fleet_board_publish(&post, now);
    if (r != FLEET_BOARD_OK) {
        fb_refuse(result, r);
        return;
    }
    char hex[65];
    fleet_board_id_to_hex(post.id, hex);
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "id", hex);
    json_push_kv_str(result, "kind", fleet_board_kind_name(post.kind));
    json_push_kv_int(result, "created_at", (int64_t)post.created_at);
}

static void fb_op_list(struct node_db *ndb, const struct json_value *in,
                       struct json_value *result, int64_t now)
{
    struct fleet_board_filter filter;
    memset(&filter, 0, sizeof(filter));
    const char *kind = fb_str(in, "kind", NULL);
    if (kind && kind[0] && !fleet_board_kind_from_name(kind, &filter.kind)) {
        fb_error(result, "BAD_KIND", "unknown post kind");
        return;
    }
    const char *host = fb_str(in, "host", NULL);
    if (host && host[0]) {
        if (!fleet_board_id_from_hex(host, filter.host_pubkey)) {
            fb_error(result, "BAD_HOST",
                     "host must be a 64-character public key hex");
            return;
        }
        filter.host_set = true;
    }
    filter.since = fb_int(in, "since", 0);
    filter.open_only = fb_bool(in, "open");
    (void)snprintf(filter.slug, sizeof(filter.slug), "%s",
                   fb_str(in, "slug", ""));

    int64_t limit = fb_int(in, "limit", 50);
    if (limit <= 0 || limit > FLEET_BOARD_LIST_MAX)
        limit = FLEET_BOARD_LIST_MAX;

    struct db_fleet_board_post *rows =
        zcl_calloc((size_t)limit, sizeof(*rows), "fleet_board.rpc.list");
    if (!rows) {
        fb_error(result, "BOARD_ALLOC_FAILED",
                 "the bounded board result snapshot could not be allocated");
        return;
    }
    int n = db_fleet_board_list(ndb, &filter, now, rows, (size_t)limit);
    fb_render_list(result, rows, n);
    free(rows);
}

static void fb_op_show(struct node_db *ndb, const struct json_value *in,
                       struct json_value *result)
{
    uint8_t id[32];
    const char *hex = fb_str(in, "id", NULL);
    if (!hex || !fleet_board_id_from_hex(hex, id)) {
        fb_error(result, "BAD_ID", "id must be a 64-character post id");
        return;
    }
    struct db_fleet_board_post row;
    if (!db_fleet_board_post_find(ndb, id, &row)) {
        fb_error(result, "NOT_FOUND", "no post with that id is held here");
        return;
    }
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    fb_render_post(result, &row);
}

static void fb_op_status(struct node_db *ndb, struct json_value *result,
                         int64_t now)
{
    struct fleet_board_status status;
    if (!db_fleet_board_status(ndb, now, &status)) {
        fb_error(result, "STATUS_UNAVAILABLE", "the board store did not answer");
        return;
    }
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_int(result, "posts", status.posts);
    json_push_kv_int(result, "bytes", status.bytes);
    json_push_kv_int(result, "max_posts", FLEET_BOARD_STORE_MAX_POSTS);
    json_push_kv_int(result, "max_bytes", FLEET_BOARD_STORE_MAX_BYTES);
    json_push_kv_int(result, "oldest_created_at", status.oldest_created_at);
    json_push_kv_int(result, "newest_created_at", status.newest_created_at);
    json_push_kv_int(result, "open_questions", status.open_questions);
    json_push_kv_int(result, "wiki_pages", status.wiki_pages);
    if (status.head_chain_set) {
        char hex[65];
        fleet_board_id_to_hex(status.head_chain, hex);
        json_push_kv_str(result, "head_chain", hex);
    }
    int64_t checked = 0;
    json_push_kv_bool(result, "chain_intact",
                      db_fleet_board_chain_verify(ndb, &checked));
    json_push_kv_int(result, "chain_checked", checked);
    /* Status is read-only: inspecting the board must never create a signing
     * identity or copy private key material into the RPC path. */
    uint8_t pubkey[32];
    if (boot_fleet_board_public_identity(pubkey)) {
        char hex[65];
        fleet_board_id_to_hex(pubkey, hex);
        json_push_kv_str(result, "host", hex);
    } else {
        json_push_kv_str(result, "host_unavailable", "identity_not_loaded");
    }
}

static void fb_op_wiki_read(struct node_db *ndb, const struct json_value *in,
                            struct json_value *result)
{
    const char *slug = fb_str(in, "slug", NULL);
    struct db_fleet_board_post row;
    if (!slug || !db_fleet_board_wiki_read(ndb, slug, &row)) {
        fb_error(result, "NO_PAGE", "no wiki page with that slug is held here");
        return;
    }
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    fb_render_post(result, &row);
}

static void fb_op_wiki_list(struct node_db *ndb, struct json_value *result)
{
    struct db_fleet_board_post *rows = zcl_calloc(
        FLEET_BOARD_LIST_MAX, sizeof(*rows), "fleet_board.rpc.wiki_list");
    if (!rows) {
        fb_error(result, "BOARD_ALLOC_FAILED",
                 "the bounded wiki result snapshot could not be allocated");
        return;
    }
    int n = db_fleet_board_wiki_list(ndb, rows, FLEET_BOARD_LIST_MAX);
    fb_render_list(result, rows, n);
    free(rows);
}

static void fb_op_wiki_history(struct node_db *ndb,
                               const struct json_value *in,
                               struct json_value *result)
{
    const char *slug = fb_str(in, "slug", NULL);
    if (!slug || !slug[0]) {
        fb_error(result, "MISSING_SLUG", "slug is required");
        return;
    }
    struct db_fleet_board_post *rows = zcl_calloc(
        FLEET_BOARD_LIST_MAX, sizeof(*rows), "fleet_board.rpc.wiki_history");
    if (!rows) {
        fb_error(result, "BOARD_ALLOC_FAILED",
                 "the bounded wiki result snapshot could not be allocated");
        return;
    }
    int n = db_fleet_board_wiki_history(ndb, slug, rows,
                                        FLEET_BOARD_LIST_MAX);
    fb_render_list(result, rows, n);
    free(rows);
}

static bool rpc_fleet_board(const struct json_value *params, bool help,
                            struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "fleet_board — the signed, gossiped AI message board and "
                     "wiki every full node carries. ops: post, "
                     "list, show, status, wiki_read, wiki_list, wiki_history. "
                     "It carries requests, offers, and pointers to evidence; "
                     "it is never an authority");
        return true;
    }
    const struct json_value *in = fb_input(params);
    const char *op = in ? fb_str(in, "op", NULL) : NULL;
    if (!op || !op[0]) {
        fb_error(result, "MISSING_OP", "op is required");
        return true;
    }
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !ndb->open) {
        fb_error(result, "NODE_DB_UNAVAILABLE",
                 "the node database is not open; the board lives in it");
        return true;
    }
    int64_t now = (int64_t)platform_time_wall_time_t();

    if (strcmp(op, "post") == 0)            fb_op_post(in, result, now);
    else if (strcmp(op, "list") == 0)       fb_op_list(ndb, in, result, now);
    else if (strcmp(op, "show") == 0)       fb_op_show(ndb, in, result);
    else if (strcmp(op, "status") == 0)     fb_op_status(ndb, result, now);
    else if (strcmp(op, "wiki_read") == 0)  fb_op_wiki_read(ndb, in, result);
    else if (strcmp(op, "wiki_list") == 0)  fb_op_wiki_list(ndb, result);
    else if (strcmp(op, "wiki_history") == 0)
        fb_op_wiki_history(ndb, in, result);
    else
        fb_error(result, "UNKNOWN_OP", "no such board operation");
    return true;
}

void boot_fleet_board_register_rpc(struct rpc_table *table)
{
    const struct rpc_command commands[] = {
        {"fleet", "fleet_board", rpc_fleet_board, true},
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
        rpc_table_must_append(table, &commands[i]);
}
