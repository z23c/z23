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
#include "crypto/random_secret.h"
#include "json/json.h"
#include "models/fleet_board_post.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "session/fleet_wiki_entry.h"
#include "sha3/sha3.h"
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
    fb_error(result, r == FLEET_BOARD_ERR_BUSY ? "BOARD_BUSY" : "BOARD_REFUSED",
             fleet_board_result_string(r));
}

static void fb_refuse_write(struct json_value *result, enum fleet_board_result r)
{
    char message[640];
    fb_error(result, r == FLEET_BOARD_ERR_BUSY ? "BOARD_BUSY" : "BOARD_REFUSED",
             boot_fleet_board_write_message(r, message, sizeof(message)));
}

static const char *fb_str(const struct json_value *in, const char *key,
                          const char *fallback)
{
    /* json_get_str renders a missing key as "", never NULL: without the
     * emptiness check the fallback would never fire. */
    const char *v = json_get_str(json_get(in, key));
    return v[0] ? v : fallback;
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
static bool fb_render_post_fields(struct json_value *into,
                           const struct db_fleet_board_post *row, bool include_text)
{
    bool ok = true;
    char hex[65];
    fleet_board_id_to_hex(row->post.id, hex);
    ok &= json_push_kv_str(into, "id", hex);
    ok &= json_push_kv_str(into, "kind", fleet_board_kind_name(row->post.kind));
    ok &= json_push_kv_int(into, "created_at", (int64_t)row->post.created_at);
    ok &= json_push_kv_int(into, "ttl", (int64_t)row->post.ttl);
    ok &= json_push_kv_int(into, "expires_at", row->expires_at);
    fleet_board_id_to_hex(row->post.ref, hex);
    ok &= json_push_kv_str(into, "ref", hex);
    fleet_board_id_to_hex(row->post.host_pubkey, hex);
    ok &= json_push_kv_str(into, "host", hex);
    char signature_hex[FLEET_BOARD_SIG_BYTES * 2 + 1];
    zcl_hex_encode(row->post.signature, FLEET_BOARD_SIG_BYTES, signature_hex);
    ok &= json_push_kv_str(into, "signature", signature_hex);
    ok &= json_push_kv_str(into, "agent", row->post.agent);
    ok &= json_push_kv_str(into, "scope",
                           fleet_board_scope_name(row->post.scope));
    if (row->post.scope != FLEET_BOARD_SCOPE_FLEET)
        ok &= json_push_kv_str(into, "room",
                               fleet_board_room_name(&row->post));
    if (include_text)
        ok &= json_push_kv_str(into, "text", row->post.text);
    ok &= json_push_kv_int(into, "text_len", row->post.text_len);
    if (row->post.slug[0]) {
        ok &= json_push_kv_str(into, "slug", row->post.slug);
        ok &= json_push_kv_str(into, "title", row->post.title);
        fleet_board_id_to_hex(row->post.supersedes, hex);
        ok &= json_push_kv_str(into, "supersedes", hex);
    }
    if (row->post.receipt[0])
        ok &= json_push_kv_str(into, "receipt", row->post.receipt);
    ok &= json_push_kv_int(into, "seq", row->seq);
    ok &= json_push_kv_int(into, "received_at", row->received_at);
    return ok;
}

static void fb_render_post(struct json_value *into,
                           const struct db_fleet_board_post *row)
{
    fb_render_post_fields(into, row, true);
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

/* The two signed times: ttl, and created_at. created_at defaults to this
 * node's clock. A caller retrying the same content passes back the
 * created_at it used the first time: every signed byte is then the same,
 * Ed25519 is deterministic, so the retry derives the same post id and the
 * store keeps one post, not two. It is bounded on both sides — never more
 * than the skew a peer would accept ahead of now, and never so old that the
 * post would already be expired when it is signed. */
static bool fb_compose_time(const struct json_value *in,
                            struct json_value *result, int64_t now,
                            struct fleet_board_post *post)
{
    int64_t ttl = fb_int(in, "ttl", FLEET_BOARD_TTL_DEFAULT);
    if (ttl <= 0 || ttl > FLEET_BOARD_TTL_MAX) {
        fb_error(result, "BAD_TTL", "ttl must be 1..2592000 seconds");
        return false;
    }
    post->ttl = (uint32_t)ttl;
    const struct json_value *given = json_get(in, "created_at");
    if (!given || given->type == JSON_NULL) {
        post->created_at = (uint64_t)now;
        return true;
    }
    int64_t created_at = given->type == JSON_INT ? json_get_int(given) : 0;
    if (created_at <= 0 || created_at > now + FLEET_BOARD_FUTURE_SKEW_MAX) {
        fb_error(result, "BAD_CREATED_AT",
                 "created_at must be Unix seconds, at most 300 seconds "
                 "ahead of this node's clock");
        return false;
    }
    if (created_at + ttl <= now) {
        fb_error(result, "CREATED_AT_EXPIRED",
                 "created_at is older than the post's ttl: the post would "
                 "already be expired");
        return false;
    }
    post->created_at = (uint64_t)created_at;
    return true;
}

static bool fb_compose_scope(const struct json_value *in,
                             struct json_value *result,
                             struct fleet_board_post *post)
{
    /* Everything signed today is scoped. The default is the public default
     * room, which is where the pre-scope board already lives; "fleet" marks
     * the post fleet-private, and a fleet post names no room. */
    const char *scope_name = fb_str(in, "scope", "public");
    if (!fleet_board_scope_from_name(scope_name, &post->scope)) {
        fb_error(result, "BAD_SCOPE", "scope must be public or fleet");
        return false;
    }
    const char *room = fb_str(in, "room",
        post->scope == FLEET_BOARD_SCOPE_PUBLIC ? FLEET_BOARD_ROOM_DEFAULT
                                                : "");
    (void)snprintf(post->room, sizeof(post->room), "%s", room);
    if (post->scope == FLEET_BOARD_SCOPE_FLEET && post->room[0]) {
        fb_error(result, "BAD_ROOM", "a fleet-scoped post names no room");
        return false;
    }
    if (post->scope == FLEET_BOARD_SCOPE_PUBLIC &&
        !fleet_board_room_valid(room)) {
        fb_error(result, "BAD_ROOM",
                 "room must be 1..32 bytes of [a-z0-9-]");
        return false;
    }
    return true;
}

/* `format: "entry"` on a wiki write asks for the body to be a valid
 * zcl.fleet_wiki_entry.v1 object; any other format value is refused and an
 * absent one leaves the page plain text. */
static bool fb_check_entry_format(const struct json_value *in,
                                  struct json_value *result,
                                  const struct fleet_board_post *post)
{
    const char *format = fb_str(in, "format", NULL);
    if (!format)
        return true;
    if (!strcmp(format, "review")) {
        struct json_value review;
        const char *why = NULL;
        enum fleet_wiki_review_status status = fleet_wiki_review_parse(post->text, post->text_len, &review, &why);
        json_free(&review);
        if (status == FLEET_WIKI_REVIEW_VALID) return true;
        fb_error(result, "BAD_REVIEW", why ? why : "format review requires zcl.fleet_wiki_review.v1");
        return false;
    }
    if (strcmp(format, "entry") != 0) {
        fb_error(result, "BAD_FORMAT", "format must be entry or review when given");
        return false;
    }
    struct json_value entry;
    const char *why = NULL;
    if (!fleet_wiki_entry_parse(post->text, post->text_len, &entry, &why)) {
        fb_error(result, "BAD_ENTRY", why);
        return false;
    }
    json_free(&entry);
    return true;
}

/* The wiki-only fields of a post: slug, title, supersedes, and the optional
 * entry-format check of the body. */
static bool fb_compose_wiki(const struct json_value *in,
                            struct json_value *result,
                            struct fleet_board_post *post)
{
    (void)snprintf(post->slug, sizeof(post->slug), "%s",
                   fb_str(in, "slug", ""));
    (void)snprintf(post->title, sizeof(post->title), "%s",
                   fb_str(in, "title", ""));
    const char *sup = fb_str(in, "supersedes", NULL);
    if (sup && sup[0] && !fleet_board_id_from_hex(sup, post->supersedes)) {
        fb_error(result, "BAD_SUPERSEDES",
                 "supersedes must be a 64-character post id");
        return false;
    }
    return fb_check_entry_format(in, result, post);
}

/* `format` belongs to wiki writes; any other kind that carries it is
 * refused rather than silently ignored. */
static bool fb_compose_kind_fields(const struct json_value *in,
                                   struct json_value *result,
                                   struct fleet_board_post *post)
{
    if (post->kind == FLEET_BOARD_KIND_WIKI)
        return fb_compose_wiki(in, result, post);
    if (fb_str(in, "format", NULL)) {
        fb_error(result, "FORMAT_NOT_WIKI",
                 "format applies to wiki writes only");
        return false;
    }
    return true;
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
                 "note, wiki, agents");
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
    if (!fb_compose_scope(in, result, post))
        return false;
    const char *ref = fb_str(in, "ref", NULL);
    if (ref && ref[0] && !fleet_board_id_from_hex(ref, post->ref)) {
        fb_error(result, "BAD_REF", "ref must be a 64-character post id");
        return false;
    }
    if (!fb_compose_kind_fields(in, result, post))
        return false;
    if (!fb_compose_time(in, result, now, post))
        return false;

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
        fb_refuse_write(result, r);
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

static bool fb_wiki_write_ids(const char *parent, const char *binding,
    const char *marker, uint8_t expected[32], bool *absent)
{
    uint8_t decoded[32];
    *absent = !strcmp(parent, "absent");
    return (*absent || zcl_hex_decode_lower(parent, expected, 32)) &&
        zcl_hex_decode_lower(marker, decoded, 32) && strlen(binding) == 32 &&
        zcl_hex_decode_lower(binding, decoded, 16);
}

static bool fb_wiki_write_sizes(const char *text, const char *slug, const char *title)
{
    return text[0] && strlen(text) <= FLEET_BOARD_WIKI_TEXT_MAX &&
        strlen(slug) <= FLEET_BOARD_SLUG_MAX && strlen(title) <= FLEET_BOARD_TITLE_MAX;
}

static bool fb_wiki_write_compose(const struct json_value *in,
    struct json_value *result, int64_t now, struct fleet_board_post *post,
    uint8_t expected[32], bool *absent)
{
    const char *parent = fb_str(in, "expected", NULL);
    const char *text = fb_str(in, "text", NULL);
    const char *slug = fb_str(in, "slug", NULL);
    const char *title = fb_str(in, "title", NULL);
    const char *binding = fb_str(in, "binding", NULL);
    const char *marker = fb_str(in, "marker", NULL);
    if (!parent || !text || !slug || !title || !binding || !marker) {
        fb_error(result, "WIKI_INPUT", "expected, inline text, slug, title, binding and marker are required");
        return false;
    }
    if (!fb_wiki_write_ids(parent, binding, marker, expected, absent)) {
        fb_error(result, "WIKI_INPUT", "expected must be absent or exact id; binding and marker must be canonical hex");
        return false;
    }
    if (!fb_wiki_write_sizes(text, slug, title)) {
        fb_error(result, "WIKI_INPUT", "inline text, slug or title exceeds its signed byte bound");
        return false;
    }
    memset(post, 0, sizeof(*post));
    post->kind = FLEET_BOARD_KIND_WIKI;
    post->scope = FLEET_BOARD_SCOPE_PUBLIC;
    post->created_at = (uint64_t)now;
    post->ttl = 86400;
    (void)snprintf(post->room, sizeof(post->room), "%s", FLEET_BOARD_ROOM_DEFAULT);
    (void)snprintf(post->agent, sizeof(post->agent), "%s", binding);
    (void)snprintf(post->receipt, sizeof(post->receipt), "wiki-write-v1:%s", marker);
    (void)snprintf(post->slug, sizeof(post->slug), "%s", slug);
    (void)snprintf(post->title, sizeof(post->title), "%s", title);
    post->text_len = (uint32_t)strlen(text);
    memcpy(post->text, text, post->text_len + 1);
    if (!*absent) memcpy(post->supersedes, expected, 32);
    enum fleet_board_result valid = fleet_board_post_validate(post);
    if (valid != FLEET_BOARD_OK) { fb_refuse(result, valid); return false; }
    return true;
}

static bool fb_wiki_write_receipt(struct json_value *result,
    const struct db_fleet_board_post *row, bool replay)
{
    uint8_t digest[32];
    char hex[65];
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    sha3_256_write(&hash, (const unsigned char *)row->post.text, row->post.text_len);
    sha3_256_finalize(&hash, digest);
    fleet_board_id_to_hex(digest, hex);
    json_set_object(result);
    bool ok = fb_render_post_fields(result, row, false);
    ok &= json_push_kv_bool(result, "ok", true);
    ok &= json_push_kv_bool(result, "replayed", replay);
    ok &= json_push_kv_bool(result, "partial", true);
    ok &= json_push_kv_str(result, "verification", "receiver-verified-full-object; partial receipt requires full reconstruction for independent verification");
    ok &= json_push_kv_int(result, "signed_scope", row->post.scope);
    ok &= json_push_kv_str(result, "signed_room", row->post.room);
    ok &= json_push_kv_str(result, "representation", "zcl.fleet_wiki_write_receipt.v1");
    ok &= json_push_kv_str(result, "body_sha3_256", hex);
    return ok;
}

static void fb_op_wiki_write(const struct json_value *in,
    struct json_value *result, int64_t now)
{
    struct fleet_board_post post;
    uint8_t expected[32];
    bool absent;
    if (!fb_wiki_write_compose(in, result, now, &post, expected, &absent)) return;
    struct db_fleet_board_post out;
    enum fleet_board_result refusal;
    enum fleet_board_wiki_write_status status = boot_fleet_board_wiki_write(
        &post, absent ? NULL : expected, now, &out, &refusal);
    if (status != FLEET_WIKI_WRITE_OK && status != FLEET_WIKI_WRITE_REPLAY) {
        static const char *const codes[] = {"OK", "REPLAY", "WIKI_INPUT", "WIKI_CONFLICT",
            "WIKI_CORRUPT", "WIKI_REQUEST_COLLISION", "WIKI_CLOCK", "WIKI_BUSY",
            "WIKI_STORAGE", "WIKI_REFUSED"};
        char message[640];
        bool refused = status == FLEET_WIKI_WRITE_REFUSED && refusal != FLEET_BOARD_OK;
        fb_error(result, codes[status], refused ? boot_fleet_board_write_message(refusal, message, sizeof(message))
            : "receiver-local atomic wiki mutation was refused; reconcile retained request before retry");
        return;
    }
    if (!fb_wiki_write_receipt(result, &out, status == FLEET_WIKI_WRITE_REPLAY))
        fb_error(result, "WIKI_OUTCOME_UNKNOWN", "mutation committed but receipt projection failed; reconcile the same request key");
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
    const char *scope = fb_str(in, "scope", NULL);
    if (scope && scope[0]) {
        /* "legacy" selects the pre-scope rows explicitly; the name "public"
         * means the signed public scope, while a bare list sees both. */
        if (strcmp(scope, "legacy") == 0) {
            filter.scope_set = true;
            filter.scope = FLEET_BOARD_SCOPE_LEGACY_PUBLIC;
        } else if (fleet_board_scope_from_name(scope, &filter.scope)) {
            filter.scope_set = true;
        } else {
            fb_error(result, "BAD_SCOPE",
                     "scope must be public, fleet, or legacy");
            return;
        }
    }
    (void)snprintf(filter.room, sizeof(filter.room), "%s",
                   fb_str(in, "room", ""));

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

/* ── fleet_page: FLEET-scope posts in this store's arrival order ─────────
 *
 * The local reader's twin of the paired pull: the same arrival-ordered page
 * (db_fleet_board_fleet_after) a paired box pulls, for a process on THIS
 * box that consumes fleet posts, such as the agent-mail receiver. A
 * created_at cursor would skip a post that arrives late with an older
 * signed time; the arrival number never does. Every answer names this node
 * process by a random epoch, because a restart may reuse the arrival number
 * of a reclaimed row: a reader that sees a new epoch starts again from 0,
 * which dedupe by post id makes free of effect. */

#define FB_PAGE_DEFAULT 16

static uint8_t g_fb_page_epoch[16];
static bool g_fb_page_epoch_ready;

static bool fb_page_epoch_hex(char out[33])
{
    if (!g_fb_page_epoch_ready)
        g_fb_page_epoch_ready = zcl_random_secret_bytes(
            g_fb_page_epoch, sizeof(g_fb_page_epoch), "fleet_board_page_epoch");
    if (!g_fb_page_epoch_ready)
        return false;
    zcl_hex_encode(g_fb_page_epoch, sizeof(g_fb_page_epoch), out);
    return true;
}

static bool fb_page_visit(const struct db_fleet_board_post *row, void *ctx)
{
    struct json_value *arr = ctx;
    struct json_value item;
    json_init(&item);
    json_set_object(&item);
    fb_render_post(&item, row);
    (void)json_push_kv_int(&item, "arrival", row->arrival);
    bool pushed = json_push_back(arr, &item);
    json_free(&item);
    return pushed;
}

static void fb_op_fleet_page(struct node_db *ndb, const struct json_value *in,
                             struct json_value *result, int64_t now)
{
    int64_t after = fb_int(in, "after", 0);
    int64_t limit = fb_int(in, "limit", FB_PAGE_DEFAULT);
    char epoch[33];
    if (after < 0) {
        fb_error(result, "BAD_AFTER", "after is a non-negative arrival number");
        return;
    }
    if (limit <= 0 || limit > (int64_t)FLEET_BOARD_FLEET_ANSWER_POSTS_MAX)
        limit = FLEET_BOARD_FLEET_ANSWER_POSTS_MAX;
    if (!fb_page_epoch_hex(epoch)) {
        fb_error(result, "PAGE_UNAVAILABLE",
                 "the CSPRNG did not yield this process's page epoch");
        return;
    }
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    int64_t scanned = after;
    int n = db_fleet_board_fleet_after(ndb, now, after, (unsigned)limit,
                                       fb_page_visit, &arr, &scanned);
    if (n < 0) {
        json_free(&arr);
        fb_error(result, "PAGE_UNAVAILABLE",
                 "the fleet page could not be read from the board store");
        return;
    }
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    (void)json_push_kv(result, "posts", &arr);
    json_free(&arr);
    json_push_kv_int(result, "returned", n);
    json_push_kv_int(result, "scanned", scanned);
    json_push_kv_str(result, "epoch", epoch);
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
    /* Verified posts this node refused because their author holds no role
     * here. Invisible in the counts above, because they were never stored. */
    json_push_kv_int(result, "role_refused",
                     (int64_t)boot_fleet_board_role_refused_count());
    /* And keys the role bootstrap never reached because the host-scan
     * bound stopped it: a refusal above may be that, not a decision. */
    json_push_kv_int(result, "grandfather_truncated",
                     (int64_t)boot_fleet_board_grandfather_truncated_count());
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

/* The body is hex so byte offsets may split UTF-8 without losing bytes.
 * A chunk is a partial projection, never independently verified evidence. */
static void fb_wiki_chunk_render(const struct db_fleet_board_post *row,
                                 int64_t start, size_t count, size_t cap,
                                 struct json_value *result)
{
    json_set_object(result);
    bool ok = json_push_kv_bool(result, "ok", true);
    ok &= fb_render_post_fields(result, row, false);
    ok &= json_push_kv_int(result, "signed_scope", row->post.scope);
    ok &= json_push_kv_str(result, "signed_room", row->post.room);
    ok &= json_push_kv_str(result, "representation", "zcl.fleet_wiki_body_chunk.v1");
    ok &= json_push_kv_str(result, "verification", "reconstruct full signed post and verify id/signature; chunk alone is not verified evidence");
    ok &= json_push_kv_int(result, "offset", start);
    if (!ok) {
        fb_error(result, "CHUNK_PROJECTION_FAILED", "cannot faithfully construct signed chunk metadata");
        return;
    }
    size_t base = json_write(result, NULL, 0);
    /* Native bridge's envelope allowance plus chunk keys and integer digits.
     * Refuse rather than omit fields needed for signed reconstruction. */
    if (base + 896 >= cap) {
        fb_error(result, "CHUNK_BUDGET", "signed metadata does not fit the response budget");
        return;
    }
    size_t n = row->post.text_len - (size_t)start;
    if (n > count) n = count;
    size_t room = (cap - base - 896) / 2;
    if (n > room) n = room;
    char data[2049];
    zcl_hex_encode((const uint8_t *)row->post.text + start, n, data);
    ok = json_push_kv_str(result, "data_hex", data);
    ok &= json_push_kv_int(result, "next_offset", start + (int64_t)n);
    ok &= json_push_kv_bool(result, "complete", start + (int64_t)n == row->post.text_len);
    if (!ok) fb_error(result, "CHUNK_PROJECTION_FAILED", "cannot faithfully construct signed body chunk");
}

static void fb_op_wiki_chunk(struct node_db *ndb, const struct json_value *in,
                             struct json_value *result)
{
    uint8_t id[32];
    const char *hex = fb_str(in, "id", NULL);
    if (!hex || !fleet_board_id_from_hex(hex, id)) {
        fb_error(result, "BAD_ID", "id must be a 64-character revision id");
        return;
    }
    int64_t start = fb_int(in, "offset", -1);
    int64_t count = fb_int(in, "bytes", -1);
    int64_t cap = fb_int(in, "response_budget", 4096);
    const struct json_value *budget = json_get(in, "response_budget");
    if (json_get(in, "slug") || (budget && budget->type != JSON_INT)) {
        fb_error(result, "BAD_CHUNK", "exact id cannot be combined with slug; response budget must be an integer");
        return;
    }
    if (start < 0 || count < 1 || count > 1024 || cap < 2048 || cap > 8192) {
        fb_error(result, "BAD_CHUNK", "offset must be nonnegative, bytes 1..1024 and response budget 2048..8192");
        return;
    }
    struct db_fleet_board_post row;
    if (!db_fleet_board_post_find(ndb, id, &row)) {
        fb_error(result, "NOT_FOUND", "no verifying retained revision with that id is held here");
        return;
    }
    if (row.post.kind != FLEET_BOARD_KIND_WIKI) {
        fb_error(result, "NOT_WIKI", "the exact revision is not a wiki page");
        return;
    }
    if ((uint64_t)start > row.post.text_len) {
        fb_error(result, "BAD_OFFSET", "offset exceeds the revision body length");
        return;
    }
    fb_wiki_chunk_render(&row, start, (size_t)count, (size_t)cap, result);
}

/* Legacy/direct callers cannot observe the native registry envelope. Keep
 * their conservative allowance; registry callers supply measured limits. */
#define FB_WIKI_READ_MARGIN 1536

struct fb_wiki_read_limits { size_t full, partial; bool unbounded; };

static bool fb_wiki_read_limits(const struct json_value *in,
                                 struct fb_wiki_read_limits *out)
{
    int64_t cap = fb_int(in, "response_budget", 0);
    const struct json_value *data = json_get(in, "data_budget");
    if (!data) {
        out->unbounded = cap <= 0;
        out->full = cap > FB_WIKI_READ_MARGIN ? (size_t)cap - FB_WIKI_READ_MARGIN : 0;
        out->partial = out->full;
        return true;
    }
    const struct json_value *hint = json_get(in, "continuation_bytes");
    if (data->type != JSON_INT || !hint || hint->type != JSON_INT)
        return false;
    int64_t room = json_get_int(data), extra = json_get_int(hint);
    if (cap <= 0 || cap > 8192 || room < 0 || room > cap || extra < 0 || extra > room)
        return false;
    out->unbounded = false;
    /* The RPC's ok field is retained in these sizing observations but omitted
     * by the native bridge. This deliberately leaves small unused headroom. */
    out->full = (size_t)room;
    out->partial = (size_t)(room - extra);
    return true;
}

/* Every temporary owns its copy; allocation failure is never a size result. */
static bool fb_wiki_read_trial(const struct json_value *base, const char *text,
                               const struct json_value *entry, bool partial,
                               size_t offset, struct json_value *trial)
{
    json_init(trial);
    bool ok = json_copy_checked(trial, base) &&
        json_push_kv_str(trial, "text", text);
    if (ok && entry)
        ok = json_push_kv(trial, "entry", entry);
    if (ok && partial)
        ok = json_push_kv_bool(trial, "truncated", true) &&
            json_push_kv_int(trial, "next_offset", (int64_t)offset);
    return ok;
}

/* Search byte limits, rounding each candidate down to a UTF-8 boundary.
 * Include escaped text and continuation fields in every sizing observation. */
static bool fb_wiki_read_prefix(const struct db_fleet_board_post *row,
                                size_t room, struct json_value *result)
{
    char *copy = zcl_malloc(row->post.text_len + 1,
                            "fleet_board.rpc.wiki_prefix");
    if (!copy) return false;
    memcpy(copy, row->post.text, row->post.text_len);
    copy[row->post.text_len] = 0;
    /* A partial body must leave at least one byte for continuation. */
    size_t low = 1, high = row->post.text_len ? row->post.text_len - 1 : 0, best = 0;
    bool ok = true;
    while (low <= high) {
        size_t mid = low + (high - low) / 2, n = mid;
        while (n > 0 && ((uint8_t)row->post.text[n] & 0xC0) == 0x80) n--;
        char saved = copy[n];
        copy[n] = 0;
        struct json_value trial;
        ok = fb_wiki_read_trial(result, copy, NULL, true, n, &trial);
        copy[n] = saved;
        bool fits = ok && json_write(&trial, NULL, 0) <= room;
        json_free(&trial);
        if (!ok) break;
        if (fits) {
            best = n;
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }
    if (ok && best > 0) {
        copy[best] = 0;
        struct json_value trial;
        ok = fb_wiki_read_trial(result, copy, NULL, true, best, &trial);
        if (ok) {
            json_free(result);
            *result = trial;
        } else {
            json_free(&trial);
        }
    } else if (ok) {
        fb_error(result, "READ_BUDGET",
                 "page metadata and a whole body character do not fit the response budget");
    }
    free(copy);
    return ok;
}

/* Preserve the established full text plus parsed-entry representation when
 * it fits. Larger bodies use an explicitly partial raw-text projection. */
static void fb_wiki_read_body(const struct db_fleet_board_post *row,
                              const struct fb_wiki_read_limits *limits,
                              struct json_value *result)
{
    struct json_value entry;
    json_init(&entry);
    enum fleet_wiki_parse_status parsed = fleet_wiki_entry_parse_checked(
        row->post.text, row->post.text_len, &entry, NULL);
    if (parsed == FLEET_WIKI_PARSE_ALLOC_FAILED) {
        json_free(&entry);
        fb_error(result, "READ_PROJECTION_FAILED", "cannot allocate the parsed page entry");
        return;
    }
    struct json_value trial;
    bool ok = fb_wiki_read_trial(result, row->post.text,
        parsed == FLEET_WIKI_PARSE_ENTRY ? &entry : NULL, false, 0, &trial);
    if (ok && (limits->unbounded || json_write(&trial, NULL, 0) <= limits->full)) {
        json_free(result);
        *result = trial;
    } else {
        json_free(&trial);
        /* The parsed entry is the first thing to give way: the raw body, whole,
         * still reads back in one reply. */
        ok = ok && fb_wiki_read_trial(result, row->post.text, NULL, false, 0, &trial);
        if (ok && json_write(&trial, NULL, 0) <= limits->full) {
            json_free(result);
            *result = trial;
        } else {
            json_free(&trial);
            if (ok) ok = fb_wiki_read_prefix(row, limits->partial, result);
        }
    }
    json_free(&entry);
    if (!ok)
        fb_error(result, "READ_PROJECTION_FAILED",
                 "cannot faithfully construct the bounded page projection");
}

static void fb_op_wiki_read(struct node_db *ndb, const struct json_value *in,
                            struct json_value *result)
{
    if (json_get(in, "id")) {
        fb_op_wiki_chunk(ndb, in, result);
        return;
    }
    if (json_get(in, "offset") || json_get(in, "bytes")) {
        fb_error(result, "MISSING_ID", "byte chunks require an exact revision id");
        return;
    }
    const char *slug = fb_str(in, "slug", NULL);
    struct db_fleet_board_post row;
    if (!slug || !db_fleet_board_wiki_read(ndb, slug, &row)) {
        fb_error(result, "NO_PAGE", "no wiki page with that slug is held here");
        return;
    }
    json_set_object(result);
    if (!json_push_kv_bool(result, "ok", true) ||
        !fb_render_post_fields(result, &row, false)) {
        fb_error(result, "READ_PROJECTION_FAILED", "cannot faithfully construct page metadata");
        return;
    }
    struct fb_wiki_read_limits limits;
    if (!fb_wiki_read_limits(in, &limits)) {
        fb_error(result, "READ_BUDGET", "invalid response data or continuation allowance");
        return;
    }
    fb_wiki_read_body(&row, &limits, result);
}

static bool fb_index_item(struct json_value *item,
                          const struct db_fleet_board_post *row)
{
    struct json_value entry;
    char plain[FLEET_WIKI_SUMMARY_MAX + 1];
    enum fleet_wiki_parse_status parsed = fleet_wiki_entry_parse_checked(
        row->post.text, row->post.text_len, &entry, NULL);
    if (parsed == FLEET_WIKI_PARSE_ALLOC_FAILED) return false;
    bool is_entry = parsed == FLEET_WIKI_PARSE_ENTRY;
    if (!is_entry) fleet_wiki_plain_summary(row->post.text, row->post.text_len, plain);
    char id[65], host[65];
    fleet_board_id_to_hex(row->post.id, id);
    fleet_board_id_to_hex(row->post.host_pubkey, host);
    json_set_object(item);
    bool ok = json_push_kv_str(item, "kind", "wiki") &&
        json_push_kv_str(item, "slug", row->post.slug) &&
        json_push_kv_str(item, "title", row->post.title) &&
        (!is_entry || json_push_kv(item, "topic", json_get(&entry, "topic"))) &&
        json_push_kv_str(item, "summary",
            is_entry ? json_get_str(json_get(&entry, "summary")) : plain) &&
        json_push_kv_str(item, "host", host) &&
        json_push_kv_str(item, "agent", row->post.agent) &&
        json_push_kv_int(item, "created_at", (int64_t)row->post.created_at) &&
        json_push_kv_str(item, "id", id);
    if (is_entry) json_free(&entry);
    return ok;
}

static bool fb_render_wiki_index(struct json_value *result,
                                 const struct db_fleet_board_post *rows, int n)
{
    json_set_object(result);
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    bool ok = json_push_kv_bool(result, "ok", true);
    for (int i = 0; ok && i < n; i++) {
        struct json_value item;
        json_init(&item);
        ok = fb_index_item(&item, &rows[i]) && json_push_back(&arr, &item);
        json_free(&item);
    }
    ok = ok && json_push_kv(result, "posts", &arr) &&
        json_push_kv_int(result, "returned", n);
    json_free(&arr);
    return ok;
}

static void fb_op_wiki_list(struct node_db *ndb, const struct json_value *in,
                            struct json_value *result)
{
    const char *after = fb_str(in, "after_slug", "");
    if (after[0] && !fleet_board_slug_valid(after)) {
        fb_error(result, "BAD_AFTER", "after_slug must be a page slug");
        return;
    }
    struct db_fleet_board_post *rows = zcl_calloc(
        FLEET_BOARD_LIST_MAX, sizeof(*rows), "fleet_board.rpc.wiki_list");
    if (!rows) {
        fb_error(result, "BOARD_ALLOC_FAILED",
                 "the bounded wiki result snapshot could not be allocated");
        return;
    }
    char last[FLEET_BOARD_SLUG_MAX + 1];
    bool more;
    int n = db_fleet_board_wiki_list_after(ndb, after, rows, FLEET_BOARD_LIST_MAX,
                                           last, &more);
    if (n < 0) {
        free(rows);
        fb_error(result, "BOARD_STORAGE", "the wiki index could not be read from the board store");
        return;
    }
    if (!fb_render_wiki_index(result, rows, n) ||
        !json_push_kv_bool(result, "more", more) ||
        !json_push_kv_str(result, "after_slug", last)) {
        json_free(result);
        json_init(result);
        fb_error(result, "READ_PROJECTION_FAILED",
                 "cannot faithfully construct the wiki index");
    }
    free(rows);
}

/* Exact-target retrieval includes every signer and preserves forks. Private
 * or cross-room peer statements are not projected by this public wiki view. */
static bool fb_review_allowance(const struct json_value *in, size_t *allowance)
{
    const struct json_value *cap_value = json_get(in, "response_budget");
    const struct json_value *data = json_get(in, "data_budget");
    int64_t cap = fb_int(in, "response_budget", 8192);
    if ((cap_value && cap_value->type != JSON_INT) || cap < 2048 || cap > 8192)
        return false;
    if (data) {
        if (data->type != JSON_INT || data->val.i < 0 || data->val.i > cap)
            return false;
        *allowance = (size_t)data->val.i;
    } else {
        /* Direct RPC/handler calls lack a measured registry envelope. */
        *allowance = (size_t)cap - FB_WIKI_READ_MARGIN;
    }
    return true;
}


static const char *fb_review_resolution(const struct fleet_wiki_review_state *state)
{
    if (!state->resolved) return "unresolved-target";
    if (!state->lineage_valid) return "unresolved-lineage";
    if (!state->complete) return "graph-unavailable";
    if (state->fork) return "fork";
    return state->current ? "current-held-opinion" : "superseded";
}

static bool fb_review_render_row(struct node_db *ndb,
    const struct db_fleet_board_post *row, struct json_value *item)
{
    const struct fleet_board_post *post = &row->post;
    struct fleet_wiki_review_state state;
    struct json_value review;
    enum fleet_wiki_review_status kind =
        fleet_wiki_review_parse(post->text, post->text_len, &review, NULL);
    if (kind != FLEET_WIKI_REVIEW_VALID ||
        !db_fleet_board_review_state(ndb, post, &state)) {
        json_free(&review);
        return false;
    }
    bool ok = fb_render_post_fields(item, row, true);
    ok &= json_push_kv(item, "review", &review);
    ok &= json_push_kv_bool(item, "target_resolved", state.resolved);
    ok &= json_push_kv_bool(item, "lineage_valid", state.lineage_valid);
    ok &= json_push_kv_bool(item, "graph_complete", state.complete);
    ok &= json_push_kv_int(item, "graph_verified", state.graph_verified);
    ok &= json_push_kv_int(item, "graph_verify_limit", FLEET_BOARD_LIST_MAX);
    ok &= json_push_kv_bool(item, "current", state.current);
    ok &= json_push_kv_bool(item, "fork", state.fork);
    ok &= json_push_kv_str(item, "resolution", fb_review_resolution(&state));
    ok &= json_push_kv_str(item, "reviewer", json_get_str(json_get(item, "host")));
    json_free(&review);
    return ok;
}

static bool fb_review_result(struct json_value *result, const struct json_value *posts,
    const char *target, const uint8_t next[32], bool more)
{
    json_set_object(result);
    char hex[65]; fleet_board_id_to_hex(next, hex);
    bool ok = json_push_kv_bool(result, "ok", true);
    ok &= json_push_kv(result, "posts", posts);
    ok &= json_push_kv_str(result, "target", target);
    ok &= json_push_kv_str(result, "after_id", hex);
    ok &= json_push_kv_bool(result, "has_more", more);
    ok &= json_push_kv_str(result, "selection",
        "receiver-held individual statements; no global score or reviewer privilege");
    return ok;
}

static void fb_op_wiki_reviews(struct node_db *ndb, const struct json_value *in,
    struct json_value *result)
{
    size_t allowance;
    if (!fb_review_allowance(in, &allowance)) {
        fb_error(result, "REVIEW_BUDGET",
            "response_budget must be 2048..8192 and measured data_budget must fit it");
        return;
    }
    uint8_t target[32], after[32] = {0}, next[32];
    const char *text = fb_str(in, "target", "");
    const char *cursor = fb_str(in, "after_id", "");
    if (!fleet_board_id_from_hex(text, target) ||
        (cursor[0] && !fleet_board_id_from_hex(cursor, after))) {
        fb_error(result, "BAD_REVIEW_QUERY", "target and after_id must be exact revision ids");
        return;
    }
    struct db_fleet_board_post rows[1];
    size_t count;
    bool more;
    if (!db_fleet_board_wiki_reviews(ndb, target, after, rows, 1, &count, next, &more)) {
        fb_error(result, "REVIEW_QUERY_FAILED", "review page unavailable; no exhaustion is claimed");
        return;
    }
    struct json_value posts;
    json_init(&posts); json_set_array(&posts);
    bool ok = true;
    for (size_t i = 0; i < count; i++) {
        const struct fleet_board_post *post = &rows[i].post;
        if (post->scope != FLEET_BOARD_SCOPE_PUBLIC ||
            strcmp(post->room, FLEET_BOARD_ROOM_DEFAULT)) continue;
        struct json_value item;
        json_init(&item); json_set_object(&item);
        ok = fb_review_render_row(ndb, &rows[i], &item);
        if (ok) ok = json_push_back(&posts, &item);
        json_free(&item);
        if (!ok) break;
    }
    if (ok) ok = fb_review_result(result, &posts, text, next, more);
    json_free(&posts);
    if (!ok) {
        fb_error(result, "REVIEW_PROJECTION_FAILED", "cannot faithfully project review evidence");
        return;
    }
    size_t encoded = json_write(result, NULL, 0);
    if (!encoded) fb_error(result, "REVIEW_PROJECTION_FAILED", "cannot measure complete review evidence");
    else if (encoded > allowance)
        fb_error(result, "REVIEW_BUDGET",
            "complete signed review page does not fit; retry the same target and input cursor with a larger budget");
}


static void fb_op_wiki_history(struct node_db *ndb,
                               const struct json_value *in,
                               struct json_value *result)
{
    if (json_get(in, "target")) { fb_op_wiki_reviews(ndb, in, result); return; }
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

enum { FB_FIND_MAX_ENTRIES = 8, FB_FIND_Q_MAX = 128 };
struct fb_find_query {
    struct fleet_wiki_entry_query filters;
    const char *after;
    size_t budget;
};
struct fb_find_context {
    struct fb_find_query query;
    struct json_value entries;
    size_t used;
    unsigned returned;
};

static bool fb_find_string(const struct json_value *in, const char *key,
                            size_t max, bool empty, const char **out)
{
    const struct json_value *v = json_get(in, key);
    *out = v ? json_get_str(v) : "";
    if (!v) return true;
    if (v->type != JSON_STR || strlen(*out) > max) return false;
    if (!empty && !(*out)[0]) return false;
    if (empty) return true;
    for (size_t i = 0; (*out)[i]; i++) {
        unsigned char c = (unsigned char)(*out)[i];
        if (c < 0x20 || c == 0x7f) return false;
    }
    return true;
}

static bool fb_find_query_read(const struct json_value *in,
                               struct fb_find_query *q)
{
    const struct json_value *cap = json_get(in, "response_budget");
    int64_t budget = fb_int(in, "response_budget", 4096);
    if (cap && cap->type != JSON_INT) return false;
    if (budget < 2048 || budget > 8192) return false;
    q->budget = (size_t)budget;
    if (!fb_find_string(in, "q", 128, true, &q->filters.q) ||
        !fb_find_string(in, "topic", 64, false, &q->filters.topic) ||
        !fb_find_string(in, "applies_to", 64, false, &q->filters.applies_to) ||
        !fb_find_string(in, "after_slug", 64, true, &q->after)) return false;
    if (q->filters.topic[0] && !fleet_board_slug_valid(q->filters.topic)) return false;
    return !q->after[0] || fleet_board_slug_valid(q->after);
}

static bool fb_find_item_identity(const struct db_fleet_board_post *row,
                                  const struct json_value *entry,
                                  struct json_value *item)
{
    json_set_object(item);
    char id[65], host[65];
    fleet_board_id_to_hex(row->post.id, id);
    fleet_board_id_to_hex(row->post.host_pubkey, host);
    return json_push_kv_str(item, "kind", "entry") &&
        json_push_kv(item, "topic", json_get(entry, "topic")) &&
        json_push_kv_str(item, "slug", row->post.slug) &&
        json_push_kv_str(item, "id", id) &&
        json_push_kv_str(item, "host", host) &&
        json_push_kv_int(item, "created_at", (int64_t)row->post.created_at) &&
        json_push_kv_int(item, "expires_at", row->expires_at) &&
        json_push_kv(item, "updated", json_get(entry, "updated"));
}

static bool fb_find_item_rules(const struct json_value *entry,
                               struct json_value *item)
{
    struct json_value rules;
    json_init(&rules); json_set_array(&rules);
    const struct json_value *lessons = json_get(entry, "lessons");
    bool ok = true;
    for (size_t i = 0; ok && i < json_size(lessons); i++)
        ok = json_push_back(&rules, json_get(json_at(lessons, i), "rule"));
    if (ok) ok = json_push_kv(item, "rules", &rules);
    json_free(&rules);
    return ok;
}

static bool fb_find_item_project(const struct db_fleet_board_post *row,
    const struct json_value *entry, unsigned mode, struct json_value *item)
{
    if (!fb_find_item_identity(row, entry, item)) return false;
    if (mode < 2 && !json_push_kv(item, "summary", json_get(entry, "summary"))) return false;
    if (mode == 0 && !fb_find_item_rules(entry, item)) return false;
    return json_push_kv_bool(item, "rules_omitted", mode != 0) &&
        json_push_kv_bool(item, "summary_omitted", mode == 2);
}

static bool fb_find_push_matched(struct json_value *item,
    const char *const *fields, size_t n)
{
    struct json_value matched;
    json_init(&matched); json_set_array(&matched);
    bool ok = true;
    for (size_t i = 0; ok && i < n; i++) {
        struct json_value name;
        json_init(&name); json_set_str(&name, fields[i]);
        ok = json_push_back(&matched, &name);
        json_free(&name);
    }
    if (ok) ok = json_push_kv(item, "matched", &matched);
    json_free(&matched);
    return ok;
}

static bool fb_find_item_matched(const struct fb_find_context *c,
    const struct db_fleet_board_post *row, const struct json_value *entry,
    struct json_value *item)
{
    const char *fields[FLEET_WIKI_MATCH_FIELDS];
    size_t n = fleet_wiki_entry_matched_fields(entry, row->post.slug,
        c->query.filters.q, fields);
    return fb_find_push_matched(item, fields, n);
}


static enum fleet_wiki_visit_result fb_find_append(struct fb_find_context *c,
    struct json_value *item, bool *fits)
{
    size_t bytes = json_write(item, NULL, 0) + 1;
    *fits = c->used + bytes <= c->query.budget - 768;
    if (!*fits) return FLEET_WIKI_VISIT_CONTINUE;
    if (!json_push_back(&c->entries, item)) return FLEET_WIKI_VISIT_FAILED;
    c->used += bytes;
    c->returned++;
    return FLEET_WIKI_VISIT_CONTINUE;
}

static enum fleet_wiki_visit_result fb_find_emit(struct fb_find_context *c,
    const struct db_fleet_board_post *row, const struct json_value *entry)
{
    for (unsigned mode = 0; mode < 3; mode++) {
        struct json_value item;
        bool fits = false;
        json_init(&item);
        if (!fb_find_item_project(row, entry, mode, &item) ||
            !fb_find_item_matched(c, row, entry, &item)) {
            json_free(&item);
            return FLEET_WIKI_VISIT_FAILED;
        }
        enum fleet_wiki_visit_result status = fb_find_append(c, &item, &fits);
        json_free(&item);
        if (status == FLEET_WIKI_VISIT_FAILED || fits) return status;
    }
    return FLEET_WIKI_VISIT_PAGE;
}

static bool fb_find_page_item(const struct db_fleet_board_post *row,
    const char *summary, const char *const *fields, size_t n,
    struct json_value *item)
{
    char id[65], host[65];
    fleet_board_id_to_hex(row->post.id, id);
    fleet_board_id_to_hex(row->post.host_pubkey, host);
    json_set_object(item);
    return json_push_kv_str(item, "kind", "page") &&
        json_push_kv_str(item, "slug", row->post.slug) &&
        json_push_kv_str(item, "title", row->post.title) &&
        json_push_kv_str(item, "id", id) &&
        json_push_kv_str(item, "host", host) &&
        json_push_kv_int(item, "created_at", (int64_t)row->post.created_at) &&
        json_push_kv_int(item, "expires_at", row->expires_at) &&
        json_push_kv_str(item, "summary", summary) &&
        fb_find_push_matched(item, fields, n);
}

/* A plain-text newest revision is found by slug, title or first line. Bodies
 * that open with a JSON object but fail the entry rules stay hidden, and an
 * exact topic or applies_to filter excludes pages, which have neither. */
static enum fleet_wiki_visit_result fb_find_visit_page(struct fb_find_context *c,
    const struct db_fleet_board_post *row)
{
    const struct fleet_wiki_entry_query *f = &c->query.filters;
    char summary[FLEET_WIKI_SUMMARY_MAX + 1];
    const char *fields[3];
    struct json_value item;
    bool fits = false;
    if (row->post.text_len == 0 || row->post.text[0] == '{' ||
        f->topic[0] || f->applies_to[0]) return FLEET_WIKI_VISIT_CONTINUE;
    fleet_wiki_plain_summary(row->post.text, row->post.text_len, summary);
    size_t n = fleet_wiki_page_matched_fields(row->post.slug, row->post.title,
                                              summary, f->q, fields);
    if (f->q[0] && n == 0) return FLEET_WIKI_VISIT_CONTINUE;
    json_init(&item);
    if (!fb_find_page_item(row, summary, fields, n, &item)) {
        json_free(&item);
        return FLEET_WIKI_VISIT_FAILED;
    }
    enum fleet_wiki_visit_result status = fb_find_append(c, &item, &fits);
    json_free(&item);
    return status != FLEET_WIKI_VISIT_CONTINUE || fits ? status : FLEET_WIKI_VISIT_PAGE;
}

static enum fleet_wiki_visit_result fb_find_visit(void *context,
    const struct db_fleet_board_post *row)
{
    struct fb_find_context *c = context;
    if (c->returned >= FB_FIND_MAX_ENTRIES) return FLEET_WIKI_VISIT_PAGE;
    struct json_value entry;
    enum fleet_wiki_parse_status parsed = fleet_wiki_entry_parse_checked(
        row->post.text, row->post.text_len, &entry, NULL);
    if (parsed == FLEET_WIKI_PARSE_ALLOC_FAILED) return FLEET_WIKI_VISIT_FAILED;
    if (parsed != FLEET_WIKI_PARSE_ENTRY) return fb_find_visit_page(c, row);
    enum fleet_wiki_visit_result status = FLEET_WIKI_VISIT_CONTINUE;
    struct fleet_wiki_entry_query filters = c->query.filters;
    filters.slug = row->post.slug;
    if (fleet_wiki_entry_query_matches(&entry, &filters))
        status = fb_find_emit(c, row, &entry);
    json_free(&entry);
    return status;
}

static bool fb_find_result_progress(struct json_value *result,
    const struct fleet_wiki_query_progress *p)
{
    bool incomplete = p->status != FLEET_WIKI_QUERY_DONE;
    return json_push_kv_int(result, "scanned", p->scanned) &&
        json_push_kv_int(result, "verified", p->verified) &&
        json_push_kv_bool(result, "truncated", incomplete) &&
        json_push_kv_bool(result, "incomplete", incomplete) &&
        json_push_kv_str(result, "after_slug", p->after_slug) &&
        json_push_kv_str(result, "blocked_slug", p->blocked_slug) &&
        json_push_kv_str(result, "reason", p->status == FLEET_WIKI_QUERY_VERIFY_BUDGET
            ? "verification_budget; unresolved slug not skipped; use separate exact slug read"
            : incomplete ? "page; resume after_slug with unchanged filters; no snapshot" : "exhausted");
}

static bool fb_find_result(struct json_value *result,
    const struct fb_find_context *c, const struct fleet_wiki_query_progress *p)
{
    json_set_object(result);
    return json_push_kv_bool(result, "ok", true) &&
        json_push_kv_str(result, "identity_schema", FLEET_WIKI_DISCOVERY_IDENTITY_SCHEMA) &&
        json_push_kv_str(result, "query_schema", "zcl.fleet_wiki_query.v1") &&
        json_push_kv(result, "entries", &c->entries) &&
        json_push_kv_int(result, "returned", c->returned) &&
        fb_find_result_progress(result, p);
}

static void fb_op_wiki_find(struct node_db *ndb, const struct json_value *in,
                            struct json_value *result)
{
    if (strlen(fb_str(in, "q", "")) > FB_FIND_Q_MAX) {
        fb_error(result, "Q_TOO_LONG", "q is over 128 bytes");
        return;
    }
    struct fb_find_context c = {.used = 512};
    if (!fb_find_query_read(in, &c.query)) {
        fb_error(result, "BAD_QUERY", "q is at most 128 bytes; topic/applies_to at most 64 nonempty bytes; after_slug is a slug; response budget 2048..8192");
        return;
    }
    json_init(&c.entries); json_set_array(&c.entries);
    struct fleet_wiki_query_progress progress = {.status = FLEET_WIKI_QUERY_STORAGE};
    bool ok = db_fleet_board_wiki_query(ndb, c.query.after, fb_find_visit, &c, &progress);
    if (!ok) {
        LOG_WARN("fleet.board", "wiki query failed status=%d", (int)progress.status);
        fb_error(result, "QUERY_FAILED", "wiki query storage or projection failed; no exhaustion claimed");
    }
    else if (!fb_find_result(result, &c, &progress))
        fb_error(result, "QUERY_ALLOC_FAILED", "wiki query response could not be allocated");
    json_free(&c.entries);
}

/* The wiki ops. Returns false when `op` is not one of them. */
static bool fb_dispatch_wiki(struct node_db *ndb, const char *op,
                             const struct json_value *in,
                             struct json_value *result)
{
    if (strcmp(op, "wiki_read") == 0)
        fb_op_wiki_read(ndb, in, result);
    else if (strcmp(op, "wiki_list") == 0)
        fb_op_wiki_list(ndb, in, result);
    else if (strcmp(op, "wiki_find") == 0)
        fb_op_wiki_find(ndb, in, result);
    else if (strcmp(op, "wiki_history") == 0)
        fb_op_wiki_history(ndb, in, result);
    else
        return false;
    return true;
}

static bool rpc_fleet_board(const struct json_value *params, bool help,
                            struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "fleet_board — the signed, gossiped AI message board and "
                     "wiki every full node carries. ops: post, "
                     "list, show, fleet_page, status, wiki_read, wiki_list, "
                     "wiki_find, wiki_history. "
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
    else if (strcmp(op, "wiki_write") == 0) fb_op_wiki_write(in, result, now);
    else if (strcmp(op, "list") == 0)       fb_op_list(ndb, in, result, now);
    else if (strcmp(op, "show") == 0)       fb_op_show(ndb, in, result);
    else if (strcmp(op, "fleet_page") == 0)
        fb_op_fleet_page(ndb, in, result, now);
    else if (strcmp(op, "status") == 0)     fb_op_status(ndb, result, now);
    else if (!fb_dispatch_wiki(ndb, op, in, result))
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
