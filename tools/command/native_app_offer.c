/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the zcl.app_offer.v1 catalog entry and the catalog read (see
 * command/native_app_offer.h). Every post is untrusted: its board
 * signature is checked here again, and its text is parsed strictly. */

#include "command/native_app_offer.h"

#include "command/native_app_compose.h"
#include "command/native_fleet_bundle.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "controllers/rpc_client.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "session/fleet_board_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZAO_PARAMS 256u
#define ZAO_ONION_STATUS_MAX (64u * 1024u)

bool zcl_app_offer_local_endpoint(char host[static 63],
                                  char endpoint[static ZCL_APP_OFFER_ONION_MAX + 1u],
                                  bool *status_read)
{
    struct json_value in; struct zcl_command_reply inner;
    host[0] = endpoint[0] = '\0'; json_init(&in); json_set_object(&in);
    bool ok = zcl_app_offer_call("core.network.onion.status", &in, &inner);
    json_free(&in); if (status_read) *status_read = ok;
    bool ready = ok && vcs_app_offer_endpoint(&inner.data, host, endpoint);
    zcl_command_reply_free(&inner); return ready;
}

/* ── one post, re-verified here ──────────────────────────────────────── */

static const char *zao_str(const struct json_value *post, const char *key)
{
    const struct json_value *v = json_get(post, key);
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

static bool zao_int(const struct json_value *post, const char *key,
                    int64_t lo, int64_t hi, int64_t *out)
{
    const struct json_value *v = json_get(post, key);
    if (!v || v->type != JSON_INT || json_get_int(v) < lo ||
        json_get_int(v) > hi)
        return false;
    *out = json_get_int(v);
    return true;
}

static bool zao_text_field(char *dst, size_t cap, const char *s)
{
    if (!s)
        s = "";
    if (strlen(s) >= cap)
        return false;
    (void)snprintf(dst, cap, "%s", s);
    return true;
}

static bool zao_post_text(const struct json_value *post,
                          struct fleet_board_post *p, const char *room,
                          const char *text)
{
    return zao_text_field(p->room, sizeof(p->room), room) &&
           zao_text_field(p->agent, sizeof(p->agent), zao_str(post, "agent")) &&
           zao_text_field(p->receipt, sizeof(p->receipt), zao_str(post, "receipt")) &&
           zao_text_field(p->text, sizeof(p->text), text);
}

/* The signed fields of a public offer post, from the node's rendering. */
static bool zao_post_fields(const struct json_value *post,
                            struct fleet_board_post *p, const char *expected_kind)
{
    int64_t created = 0, ttl = 0, text_len = 0;
    const char *text = zao_str(post, "text");
    const char *kind = zao_str(post, "kind");
    const char *scope = zao_str(post, "scope");
    const char *room = zao_str(post, "room");
    bool ok = kind && strcmp(kind, expected_kind) == 0 && scope &&
              strcmp(scope, "public") == 0 && room &&
              strcmp(room, ZCL_APP_OFFER_ROOM) == 0 && text &&
              !zao_str(post, "slug") &&
              fleet_board_kind_from_name(kind, &p->kind) &&
              fleet_board_scope_from_name(scope, &p->scope) &&
              zao_int(post, "created_at", 1, INT64_MAX, &created) &&
              zao_int(post, "ttl", 1, FLEET_BOARD_TTL_MAX, &ttl) &&
              zao_int(post, "text_len", 1, ZCL_APP_OFFER_TEXT_MAX,
                      &text_len) &&
              (size_t)text_len == strlen(text);
    ok = ok && zao_post_text(post, p, room, text);
    p->created_at = (uint64_t)created;
    p->ttl = (uint32_t)ttl;
    p->text_len = (uint32_t)text_len;
    return ok;
}

static bool zao_post_keys(const struct json_value *post,
                          struct fleet_board_post *p)
{
    const char *sig = zao_str(post, "signature");
    const char *ref = zao_str(post, "ref");
    return fleet_board_id_from_hex(zao_str(post, "id"), p->id) &&
           fleet_board_id_from_hex(zao_str(post, "host"), p->host_pubkey) &&
           (!ref || fleet_board_id_from_hex(ref, p->ref)) && sig &&
           strlen(sig) == 2u * FLEET_BOARD_SIG_BYTES &&
           zcl_hex_decode_lower(sig, p->signature, FLEET_BOARD_SIG_BYTES);
}

bool zcl_app_offer_from_post(const struct json_value *post,
                             struct zcl_app_offer_row *row)
{
    if (!post || post->type != JSON_OBJ || !row)
        return false;
    memset(row, 0, sizeof(*row));
    struct fleet_board_post *p =
        zcl_calloc(1, sizeof(*p), "app.offer.post");
    if (!p)
        return false;
    bool ok = zao_post_fields(post, p, ZCL_APP_OFFER_KIND) && zao_post_keys(post, p) &&
              fleet_board_post_validate(p) == FLEET_BOARD_OK &&
              fleet_board_post_verify(p) == FLEET_BOARD_OK &&
              fleet_board_post_check_time(p, platform_time_wall_unix()) ==
                  FLEET_BOARD_OK &&
              zcl_app_offer_parse(p->text, p->text_len, &row->offer);
    if (ok) {
        fleet_board_id_to_hex(p->id, row->post_id);
        fleet_board_id_to_hex(p->host_pubkey, row->host);
        row->created_at = (int64_t)p->created_at;
    } else {
        memset(row, 0, sizeof(*row));
    }
    free(p);
    return ok;
}

/* ── the catalog ─────────────────────────────────────────────────────── */

/* Coalesce repeats only when the signed host and advertised bytes agree. */
static bool zao_add_row(struct zcl_app_offer_row *rows, size_t cap,
                        size_t *count, const struct zcl_app_offer_row *row)
{
    for (size_t i = 0; i < *count; i++) {
        const struct zcl_app_offer *a = &rows[i].offer, *b = &row->offer;
        if (strcmp(rows[i].host, row->host) || strcmp(a->name, b->name) ||
            strcmp(a->root, b->root) || strcmp(a->publisher, b->publisher) ||
            strcmp(a->carrier, b->carrier) || strcmp(a->sha256, b->sha256) ||
            strcmp(a->onion, b->onion) || a->size != b->size)
            continue;
        if (row->created_at > rows[i].created_at)
            rows[i] = *row;
        return true;
    }
    if (*count >= cap)
        return false;
    rows[(*count)++] = *row;
    return true;
}

static int zao_newest_first(const void *a, const void *b)
{
    const struct zcl_app_offer_row *x = a, *y = b;
    if (x->created_at != y->created_at)
        return x->created_at < y->created_at ? 1 : -1;
    int cmp = strcmp(x->offer.root, y->offer.root);
    if (!cmp) cmp = strcmp(x->host, y->host);
    return cmp ? cmp : strcmp(x->post_id, y->post_id);
}

bool zcl_app_offer_catalog(struct zcl_app_offer_row *rows, size_t cap,
                           size_t *count, struct zcl_command_reply *why)
{
    struct json_value in;
    struct zcl_app_offer_row row;
    *count = 0;
    const char *kv[] = {"room", ZCL_APP_OFFER_ROOM, "scope", "public",
                        "kind", ZCL_APP_OFFER_KIND};
    bool built = zcl_app_input(&in, kv, 6) &&
                 json_push_kv_int(&in, "limit", ZCL_APP_OFFER_ROWS_MAX);
    bool ok = built && zcl_app_offer_call(ZCL_APP_OFFER_BOARD_LIST, &in, why);
    json_free(&in);
    if (!built) {
        zcl_command_reply_init(why, "zcl.app_offer.inner.v1");
        zcl_command_reply_fail(why, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC", "prepare",
                               false, false, "board list input",
                               ZCL_APP_OFFER_BOARD_LIST);
    }
    if (!ok)
        return false;
    const struct json_value *posts = json_get(&why->data, "posts");
    if (!posts || posts->type != JSON_ARR ||
        json_size(posts) >= ZCL_APP_OFFER_ROWS_MAX) {
        zcl_command_reply_fail(why, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_TRANSIENT, "CATALOG_INCOMPLETE", "execute",
            true, false, "board response is malformed or reaches the catalog limit",
            ZCL_APP_OFFER_BOARD_LIST);
        return false;
    }
    for (size_t i = 0; i < json_size(posts); i++) {
        if (zcl_app_offer_from_post(json_at(posts, i), &row) &&
            !zao_add_row(rows, cap, count, &row)) {
            *count = 0;
            zcl_command_reply_fail(why, ZCL_COMMAND_STATUS_FAILED,
                ZCL_COMMAND_EXIT_TRANSIENT, "CATALOG_INCOMPLETE", "execute",
                true, false, "catalog exceeds the caller's capacity",
                ZCL_APP_OFFER_BOARD_LIST);
            return false;
        }
    }
    if (*count > 1)
        qsort(rows, *count, sizeof(rows[0]), zao_newest_first);
    return true;
}

static bool zar_target(const char *s)
{
    if (!s || !*s || strlen(s) >= sizeof(((struct zcl_app_rebuild *)0)->target)) return false;
    for (; *s; ++s)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= '0' && *s <= '9') || *s == '-' || *s == '_')) return false;
    return true;
}

static bool zar_valid(const struct zcl_app_rebuild *r)
{
    return r && vcs_app_offer_hex_valid(r->publisher, 33) && vcs_app_offer_hex_valid(r->release_root, 32) &&
        vcs_app_offer_hex_valid(r->package_root, 32) && vcs_app_offer_hex_valid(r->version, 32) &&
        vcs_app_offer_hex_valid(r->image, 32) && vcs_app_offer_hex_valid(r->closure, 32) &&
        vcs_app_offer_hex_valid(r->environment, 32) && vcs_app_offer_hex_valid(r->dependency, 32) &&
        vcs_app_offer_hex_valid(r->record, 32) && zar_target(r->target);
}

bool zcl_app_rebuild_format(const struct zcl_app_rebuild *r, char *out, size_t cap)
{
    if (!out || !cap || !zar_valid(r)) return false;
    int n = snprintf(out, cap, "{\"schema\":\"zcl.app_rebuild.v1\",\"publisher\":\"%s\","
        "\"release_root\":\"%s\",\"package_root\":\"%s\",\"version\":\"%s\","
        "\"image\":\"%s\",\"closure\":\"%s\",\"environment\":\"%s\","
        "\"dependency\":\"%s\",\"record\":\"%s\",\"target\":\"%s\"}",
        r->publisher, r->release_root, r->package_root, r->version, r->image,
        r->closure, r->environment, r->dependency, r->record, r->target);
    return n > 0 && (size_t)n < cap && (size_t)n <= ZCL_APP_OFFER_TEXT_MAX;
}

static bool zar_parse(const char *text, struct zcl_app_rebuild *r)
{
    struct json_value doc; json_init(&doc);
    bool ok = text && json_read(&doc, text, strlen(text)) && doc.type == JSON_OBJ && doc.num_children == 11;
    const char *keys[] = {"publisher", "release_root", "package_root", "version", "image", "closure", "environment", "dependency", "record", "target"};
    char *dst[] = {r->publisher, r->release_root, r->package_root, r->version, r->image, r->closure, r->environment, r->dependency, r->record, r->target};
    const size_t caps[] = {sizeof(r->publisher), sizeof(r->release_root), sizeof(r->package_root), sizeof(r->version), sizeof(r->image), sizeof(r->closure), sizeof(r->environment), sizeof(r->dependency), sizeof(r->record), sizeof(r->target)};
    if (ok) { const char *schema = zao_str(&doc, "schema"); ok = schema && !strcmp(schema, "zcl.app_rebuild.v1"); }
    for (size_t i = 0; ok && i < 10; ++i) {
        const char *s = zao_str(&doc, keys[i]);
        if (!s || strlen(s) >= caps[i]) ok = false;
        else memcpy(dst[i], s, strlen(s) + 1);
    }
    if (ok) {
        char canonical[ZCL_APP_OFFER_TEXT_MAX + 1u];
        ok = zar_valid(r) && zcl_app_rebuild_format(r, canonical, sizeof(canonical)) && !strcmp(canonical, text);
    }
    json_free(&doc); return ok;
}

static int zar_post(const struct json_value *post, struct zcl_app_rebuild *r, char host[65])
{
    struct fleet_board_post *p = zcl_calloc(1, sizeof(*p), "app.rebuild.post");
    if (!p) return -1;
    bool ok = zao_post_fields(post, p, "result") && zao_post_keys(post, p) &&
        fleet_board_post_validate(p) == FLEET_BOARD_OK && fleet_board_post_verify(p) == FLEET_BOARD_OK &&
        fleet_board_post_check_time(p, platform_time_wall_unix()) == FLEET_BOARD_OK && zar_parse(p->text, r);
    if (ok) fleet_board_id_to_hex(p->host_pubkey, host);
    free(p); return ok ? 1 : 0;
}

/* Match the observed release, image and environment. Build/version details
 * remain signed in each observation but are not claimed to identify people. */
static bool zar_matches(const struct zcl_app_rebuild *a, const struct zcl_app_rebuild *b)
{
    return !strcmp(a->publisher, b->publisher) && !strcmp(a->release_root, b->release_root) &&
        !strcmp(a->image, b->image) && !strcmp(a->target, b->target) && !strcmp(a->environment, b->environment);
}

bool zcl_app_rebuild_count(const struct zcl_app_rebuild *local, size_t *count, struct zcl_command_reply *why)
{
    struct json_value in; *count = 0;
    const char *kv[] = {"room", "apps", "scope", "public", "kind", "result"};
    bool built = zcl_app_input(&in, kv, 6) && json_push_kv_int(&in, "limit", ZCL_APP_OFFER_ROWS_MAX);
    bool ok = built && zcl_app_offer_call(ZCL_APP_OFFER_BOARD_LIST, &in, why);
    json_free(&in);
    if (!built) { zcl_command_reply_init(why, "zcl.app_rebuild.list.v1"); return false; }
    if (!ok) return false;
    const struct json_value *posts = json_get(&why->data, "posts");
    if (!posts || posts->type != JSON_ARR || json_size(posts) >= ZCL_APP_OFFER_ROWS_MAX) return false;
    char hosts[ZCL_APP_OFFER_ROWS_MAX][65];
    for (size_t i = 0; i < json_size(posts); ++i) {
        struct zcl_app_rebuild r = {0}; char host[65];
        int valid = zar_post(json_at(posts, i), &r, host);
        if (valid < 0) { *count = 0; return false; }
        if (!valid || !zar_matches(&r, local)) continue;
        size_t j = 0; while (j < *count && strcmp(hosts[j], host)) ++j;
        if (j == *count) { memcpy(hosts[*count], host, sizeof(host)); ++*count; }
    }
    return true;
}

void zcl_app_offer_age(int64_t created_at, int64_t now, char *out,
                       size_t cap)
{
    int64_t s = now > created_at ? now - created_at : 0;
    if (s < 60)
        (void)snprintf(out, cap, "%llds", (long long)s);
    else if (s < 3600)
        (void)snprintf(out, cap, "%lldm", (long long)(s / 60));
    else if (s < 86400)
        (void)snprintf(out, cap, "%lldh", (long long)(s / 3600));
    else
        (void)snprintf(out, cap, "%lldd", (long long)(s / 86400));
}

/* ── the transport seam ──────────────────────────────────────────────── */

/* The node's whole board list for these filters, unpaged: the leaf's
 * reply budget would cut it to a few posts. */
static bool zao_board_list(const struct json_value *input,
                           struct zcl_command_reply *out)
{
    char params[ZAO_PARAMS];
    struct json_value fwd, body;
    json_init(&fwd);
    json_copy(&fwd, input);
    bool ok = json_push_kv_str(&fwd, "op", "list");
    size_t n = ok ? json_write(&fwd, params + 1, sizeof(params) - 2u) : 0;
    json_free(&fwd);
    ok = ok && n > 0 && n < sizeof(params) - 2u;
    char *raw = NULL;
    if (ok) {
        params[0] = '[';
        params[1 + n] = ']';
        params[2 + n] = '\0';
        zcl_native_bridge_ensure_rpc();
        raw = node_rpc_call("fleet_board", params);
    }
    json_init(&body);
    ok = raw && json_read(&body, raw, strlen(raw)) && body.type == JSON_OBJ &&
         json_get_bool_or(&body, "ok", false) &&
         json_get(&body, "posts") &&
         json_get(&body, "posts")->type == JSON_ARR;
    free(raw);
    if (ok)
        ok = json_push_kv(&out->data, "posts", json_get(&body, "posts"));
    json_free(&body);
    if (!ok)
        zcl_command_reply_fail(out, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_TRANSIENT, "BOARD_UNREADABLE",
                               "execute", true, false,
                               "the node's board did not answer; start the "
                               "node (z23) and try again",
                               "fleet_board list room=apps");
    return ok;
}

static bool zao_onion_shape(const struct json_value *body)
{
    const char *schema = zao_str(body, "schema");
    const struct json_value *tor = json_get(body, "tor_ready"), *service = json_get(body, "onion_service_ready");
    return body && body->type == JSON_OBJ && schema && !strcmp(schema, "zcl.onion_status.v1") &&
        zao_str(body, "bootstrap_state") && zao_str(body, "onion_address") &&
        tor && tor->type == JSON_BOOL && service && service->type == JSON_BOOL;
}

/* The normal command view can page the port map after a busy dial ledger.
 * Read the node's bounded RPC body so readiness and its port are one snapshot. */
static bool zao_onion_status(struct zcl_command_reply *out)
{
    zcl_command_reply_init(out, "zcl.onion_status.v1");
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call("onionstatus", "[]");
    struct json_value body; json_init(&body);
    size_t n = raw ? strnlen(raw, ZAO_ONION_STATUS_MAX + 1u) : 0;
    bool ok = n && n <= ZAO_ONION_STATUS_MAX && json_read(&body, raw, n) &&
        zao_onion_shape(&body) && json_copy_checked(&out->data, &body);
    free(raw); json_free(&body);
    if (!ok) zcl_command_reply_fail(out, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_TRANSIENT,
        "ONION_STATUS_UNREADABLE", "execute", true, false, "node onion status was unavailable or malformed", "onionstatus");
    return ok;
}

static bool zao_default_call(const char *path, const struct json_value *input,
                             struct zcl_command_reply *out)
{
    if (strcmp(path, ZCL_APP_OFFER_BOARD_LIST) == 0) {
        zcl_command_reply_init(out, "zcl.app_offer.board_list.v1");
        return zao_board_list(input, out);
    }
    if (strcmp(path, "core.network.onion.status") == 0)
        return zao_onion_status(out);
    if (strcmp(path, ZCL_APP_HOST_ENABLE) == 0) {
        struct json_value in, body;
        json_init(&in); json_init(&body);
        zcl_command_reply_init(out, "zcl.app_host_enable.v1");
        bool built = json_copy_checked(&in, input) && json_push_kv_str(&in, "op", "app_host_enable");
        bool called = built && zcl_native_fleet_board_call(&in, &body, out);
        bool ok = called && json_copy_checked(&out->data, &body);
        if (!built || (called && !ok))
            zcl_command_reply_fail(out, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                "ALLOC", "execute", false, called, "cannot prepare or copy hosting request", "app.host.enable");
        else if (!called) out->error.mutated = true;
        json_free(&in); json_free(&body);
        return ok;
    }
    return zcl_app_inner_call(path, input, out, NULL);
}

static zcl_app_offer_call_fn g_zao_call;

void zcl_app_offer_set_call(zcl_app_offer_call_fn fn)
{
    g_zao_call = fn;
}

bool zcl_app_offer_call(const char *path, const struct json_value *input,
                        struct zcl_command_reply *out)
{
    return (g_zao_call ? g_zao_call : zao_default_call)(path, input, out);
}
