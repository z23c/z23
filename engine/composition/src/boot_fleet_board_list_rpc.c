/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded resident fleet board list RPC and page rendering. */
#include "boot_fleet_board_rpc_internal.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "models/fleet_board_post.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
bool fb_render_list(struct json_value *result,
                           const struct db_fleet_board_post *rows, int n)
{
    json_set_object(result);
    bool ok = json_push_kv_bool(result, "ok", true);
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (int i = 0; ok && i < n; i++) {
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        ok = fb_render_post_fields(&item, &rows[i], true) &&
             json_push_kv_int(&item, "arrival", rows[i].arrival) &&
             json_push_back(&arr, &item);
        json_free(&item);
    }
    ok = ok && json_push_kv(result, "posts", &arr);
    json_free(&arr);
    return ok && json_push_kv_int(result, "returned", n);
}

static bool fb_list_bad_cursor(struct json_value *result, const char *why)
{
    fb_error(result, "BAD_CURSOR", why);
    return false;
}

static bool fb_list_cursor(const struct json_value *in, struct json_value *result,
                           struct fleet_board_filter *filter)
{
    const struct json_value *before_time = json_get(in, "before_created_at");
    const struct json_value *before_id = json_get(in, "before_id");
    if ((before_time != NULL) != (before_id != NULL) ||
        (before_time && (before_time->type != JSON_INT ||
         json_get_int(before_time) <= 0 || before_id->type != JSON_STR ||
         !zcl_hex_decode_lower(json_get_str(before_id), filter->before_id, 32))))
        return fb_list_bad_cursor(result, "before_created_at and before_id must be a positive timestamp and 64-character post id together");
    if (before_time) {
        filter->before_set = true;
        filter->before_created_at = json_get_int(before_time);
    }
    return true;
}

/* `before=<post id>`: the page that follows that post, newest first. The id
 * is resolved to the (created_at, id) keyset the pair above names, so it is
 * the same cursor in a shorter spelling. */
static bool fb_list_before_post(struct node_db *ndb, const struct json_value *in,
                                struct json_value *result, int64_t now,
                                struct fleet_board_filter *filter)
{
    const char *hex = fb_str(in, "before", NULL);
    if (!hex)
        return true;
    struct fleet_board_filter by_id = {0};
    struct db_fleet_board_post row;
    bool complete = false;
    if (filter->before_set || !fleet_board_id_from_hex(hex, by_id.id))
        return fb_list_bad_cursor(result, "before is one 64-character post id and cannot be combined with before_created_at");
    by_id.id_set = true;
    if (db_fleet_board_list_checked(ndb, &by_id, now, &row, 1, &complete) != 1)
        return fb_list_bad_cursor(result, complete
            ? "before names a post this node does not hold (it may have expired); pass before_created_at and before_id instead"
            : "the board could not be read to resolve before; try again");
    filter->before_set = true;
    filter->before_created_at = (int64_t)row.post.created_at;
    memcpy(filter->before_id, row.post.id, 32);
    return true;
}

static bool fb_list_after(const struct json_value *in, struct json_value *result,
                          struct fleet_board_filter *filter)
{
    const struct json_value *after = json_get(in, "after");
    if (!after)
        return true;
    if (after->type != JSON_INT || json_get_int(after) < 0)
        return fb_list_bad_cursor(result, "after is a non-negative arrival number (a post's arrival, or head_arrival)");
    if (filter->before_set)
        return fb_list_bad_cursor(result, "after reads forward and before reads backward; pass one");
    filter->after_set = true;
    filter->after_arrival = json_get_int(after);
    return true;
}

static bool fb_list_room(const struct json_value *in, struct json_value *result,
                         struct fleet_board_filter *filter)
{
    const struct json_value *room = json_get(in, "room");
    const char *name = room && room->type == JSON_STR ? json_get_str(room) : "";
    if (room && (room->type != JSON_STR || !name || (name[0] && !fleet_board_room_valid(name)))) {
        fb_error(result, "BAD_ROOM", "Use 1..32 lowercase letters or digits, with internal hyphens allowed, or omit the room filter.");
        json_push_kv_str(result, "next_action", "use_valid_exact_room_or_omit_filter");
        return false;
    }
    (void)snprintf(filter->room, sizeof(filter->room), "%s", name);
    return true;
}

/* Rooms left out unless asked for. A bare listing drops the vitals room (one
 * post per machine per minute); naming any room, or `exclude_room=none`, keeps
 * the caller in charge. */
static bool fb_list_exclude_room(const struct json_value *in, struct json_value *result,
                                 struct fleet_board_filter *filter)
{
    const char *name = fb_str(in, "exclude_room", NULL);
    if (name && !strcmp(name, "none"))
        return true;
    if (!name && !filter->room[0])
        name = FLEET_BOARD_ROOM_VITALS;
    if (name && (!fleet_board_room_valid(name) || !strcmp(name, filter->room))) {
        fb_error(result, "BAD_ROOM", "exclude_room is one valid room name other than room, or none to exclude nothing");
        return false;
    }
    if (name)
        (void)snprintf(filter->exclude_room, sizeof(filter->exclude_room), "%s", name);
    return true;
}

static bool fb_list_ref(const struct json_value *in, struct json_value *result,
                        struct fleet_board_filter *filter)
{
    const char *hex = fb_str(in, "ref", NULL);
    if (!hex)
        return true;
    if (!fleet_board_id_from_hex(hex, filter->ref)) {
        fb_error(result, "BAD_REF", "ref must be a 64-character post id hex");
        return false;
    }
    filter->ref_set = true;
    return true;
}

static bool fb_list_kind_name(const struct json_value *in, const char *key,
                              struct json_value *result, uint8_t *out)
{
    const char *kind = fb_str(in, key, NULL);
    if (kind && kind[0] && !fleet_board_kind_from_name(kind, out)) {
        fb_error(result, "BAD_KIND", "unknown post kind");
        return false;
    }
    return true;
}

static bool fb_list_agent(const struct json_value *in, const char *key,
                          struct json_value *result, char *out)
{
    const char *agent = fb_str(in, key, "");
    if (strlen(agent) > FLEET_BOARD_AGENT_MAX) {
        fb_error(result, "BAD_AGENT", "agent names are at most 32 bytes");
        return false;
    }
    (void)snprintf(out, FLEET_BOARD_AGENT_MAX + 1, "%s", agent);
    return true;
}

/* scope: public, fleet, legacy, or all (the default: every scope, no filter).
 * "legacy" selects the pre-scope rows explicitly; "public" means the signed
 * public scope only, while a bare list sees both. */
static bool fb_list_scope(const struct json_value *in, struct json_value *result,
                          struct fleet_board_filter *filter)
{
    const char *scope = fb_str(in, "scope", NULL);
    if (!scope || !scope[0] || !strcmp(scope, "all"))
        return true;
    filter->scope_set = true;
    if (strcmp(scope, "legacy") == 0) {
        filter->scope = FLEET_BOARD_SCOPE_LEGACY_PUBLIC;
        return true;
    }
    if (fleet_board_scope_from_name(scope, &filter->scope))
        return true;
    fb_error(result, "BAD_SCOPE", "scope must be public, fleet, legacy, or all");
    return false;
}

static bool fb_list_filter_selectors(const struct json_value *in,
                                     struct json_value *result,
                                     struct fleet_board_filter *filter)
{
    const char *host = fb_str(in, "host", NULL);
    if (host && host[0]) {
        if (!fleet_board_id_from_hex(host, filter->host_pubkey)) {
            fb_error(result, "BAD_HOST",
                     "host must be a 64-character public key hex");
            return false;
        }
        filter->host_set = true;
    }
    return fb_list_kind_name(in, "kind", result, &filter->kind) &&
           fb_list_kind_name(in, "exclude_kind", result, &filter->exclude_kind) &&
           fb_list_agent(in, "agent", result, filter->agent) &&
           fb_list_agent(in, "exclude_agent", result, filter->exclude_agent) &&
           fb_list_ref(in, result, filter);
}

static bool fb_list_filter(struct node_db *ndb, const struct json_value *in,
                           struct json_value *result, int64_t now,
                           struct fleet_board_filter *out)
{
    struct fleet_board_filter filter = {0};
    if (!fb_list_cursor(in, result, &filter) ||
        !fb_list_before_post(ndb, in, result, now, &filter) ||
        !fb_list_after(in, result, &filter) ||
        !fb_list_filter_selectors(in, result, &filter))
        return false;
    filter.since = fb_int(in, "since", 0);
    filter.open_only = fb_bool(in, "open");
    (void)snprintf(filter.slug, sizeof(filter.slug), "%s",
                   fb_str(in, "slug", ""));
    if (!fb_list_scope(in, result, &filter) ||
        !fb_list_room(in, result, &filter) ||
        !fb_list_exclude_room(in, result, &filter))
        return false;
    *out = filter;
    return true;
}

/* How the page ended, so a short page is never mistaken for the end of the
 * board: `end` (nothing older/newer matches) or `limit` (the row limit was
 * reached). The command layer reports `byte_budget` when its reply budget cuts
 * the page short. */
static bool fb_list_describe(struct json_value *result, int64_t asked,
                             int64_t applied, int64_t head,
                             const struct fleet_board_filter *filter, bool has_more)
{
    bool ok = json_push_kv_int(result, "limit", asked) &&
              json_push_kv_int(result, "limit_applied", applied) &&
              json_push_kv_int(result, "limit_max", FLEET_BOARD_LIST_MAX) &&
              json_push_kv_int(result, "head_arrival", head) &&
              json_push_kv_str(result, "order",
                               filter->after_set ? "oldest_first" : "newest_first") &&
              json_push_kv_str(result, "stopped_by", has_more ? "limit" : "end");
    if (filter->exclude_room[0])
        ok = ok && json_push_kv_str(result, "excluded_room", filter->exclude_room);
    return ok;
}

static bool fb_list_cursors(struct json_value *result,
                            const struct fleet_board_filter *filter,
                            const struct db_fleet_board_post *rows, int n,
                            bool has_more)
{
    char id[65];
    if (filter->after_set) {
        int64_t last = n > 0 ? rows[n - 1].arrival : filter->after_arrival;
        return json_push_kv_int(result, "next_after", last);
    }
    if (!has_more || n <= 0)
        return true;
    fleet_board_id_to_hex(rows[n - 1].post.id, id);
    return json_push_kv_int(result, "next_created_at", rows[n - 1].post.created_at) &&
           json_push_kv_str(result, "next_id", id) &&
           json_push_kv_str(result, "next_before", id);
}

static bool fb_list_render(struct json_value *result,
                           const struct fleet_board_filter *filter,
                           const struct db_fleet_board_post *rows, int n,
                           bool has_more, int64_t asked, int64_t applied,
                           int64_t head)
{
    return fb_render_list(result, rows, n) &&
           json_push_kv_bool(result, "has_more", has_more) &&
           fb_list_describe(result, asked, applied, head, filter, has_more) &&
           fb_list_cursors(result, filter, rows, n, has_more);
}

void fb_op_list(struct node_db *ndb, const struct json_value *in,
                       struct json_value *result, int64_t now)
{
    struct fleet_board_filter filter;
    if (!fb_list_filter(ndb, in, result, now, &filter)) return;

    int64_t asked = fb_int(in, "limit", 50);
    int64_t limit = asked;
    if (limit <= 0 || limit > FLEET_BOARD_LIST_MAX)
        limit = FLEET_BOARD_LIST_MAX;
    /* Snapshot ceiling, read before the page: a post that arrives meanwhile
     * is left for the next `after=head_arrival` read instead of landing in
     * both. */
    int64_t head = 0;
    if (!db_fleet_board_head_arrival(ndb, &head)) {
        fb_error(result, "BOARD_READ_FAILED",
                 "the board list could not be read completely; try again");
        return;
    }
    filter.max_arrival = head;

    struct db_fleet_board_post *rows =
        zcl_calloc((size_t)limit, sizeof(*rows), "fleet_board.rpc.list");
    if (!rows) {
        fb_error(result, "BOARD_ALLOC_FAILED",
                 "the bounded board result snapshot could not be allocated");
        return;
    }
    bool complete = false;
    bool has_more = false;
    int n = db_fleet_board_list_page(ndb, &filter, now, rows, (size_t)limit,
                                     &complete, &has_more);
    if (!complete)
        fb_error(result, "BOARD_READ_FAILED",
                 "the board list could not be read completely; try again");
    else if (!fb_list_render(result, &filter, rows, n, has_more, asked, limit, head))
        fb_error(result, "BOARD_ALLOC_FAILED", "the board page continuation could not be allocated");
    free(rows);
}
