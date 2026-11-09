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
        ok = fb_render_post_fields(&item, &rows[i], true) && json_push_back(&arr, &item);
        json_free(&item);
    }
    ok = ok && json_push_kv(result, "posts", &arr);
    json_free(&arr);
    return ok && json_push_kv_int(result, "returned", n);
}

static bool fb_list_cursor(const struct json_value *in, struct json_value *result,
                           struct fleet_board_filter *filter)
{
    const struct json_value *before_time = json_get(in, "before_created_at");
    const struct json_value *before_id = json_get(in, "before_id");
    if ((before_time != NULL) != (before_id != NULL) ||
        (before_time && (before_time->type != JSON_INT ||
         json_get_int(before_time) <= 0 || before_id->type != JSON_STR ||
         !zcl_hex_decode_lower(json_get_str(before_id), filter->before_id, 32)))) {
        fb_error(result, "BAD_CURSOR", "before_created_at and before_id must be a positive timestamp and 64-character post id together");
        return false;
    }
    if (before_time) {
        filter->before_set = true;
        filter->before_created_at = json_get_int(before_time);
    }
    return true;
}

static bool fb_list_filter(const struct json_value *in, struct json_value *result,
                           struct fleet_board_filter *out)
{
    struct fleet_board_filter filter = {0};
    if (!fb_list_cursor(in, result, &filter)) return false;
    const char *kind = fb_str(in, "kind", NULL);
    if (kind && kind[0] && !fleet_board_kind_from_name(kind, &filter.kind)) {
        fb_error(result, "BAD_KIND", "unknown post kind");
        return false;
    }
    const char *host = fb_str(in, "host", NULL);
    if (host && host[0]) {
        if (!fleet_board_id_from_hex(host, filter.host_pubkey)) {
            fb_error(result, "BAD_HOST",
                     "host must be a 64-character public key hex");
            return false;
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
            return false;
        }
    }
    (void)snprintf(filter.room, sizeof(filter.room), "%s",
                   fb_str(in, "room", ""));
    *out = filter;
    return true;
}

void fb_op_list(struct node_db *ndb, const struct json_value *in,
                       struct json_value *result, int64_t now)
{
    struct fleet_board_filter filter;
    if (!fb_list_filter(in, result, &filter)) return;

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
    bool complete = false;
    bool has_more = false;
    int n = db_fleet_board_list_page(ndb, &filter, now, rows, (size_t)limit,
                                     &complete, &has_more);
    if (complete) {
        bool rendered = fb_render_list(result, rows, n) &&
                        json_push_kv_bool(result, "has_more", has_more);
        if (has_more && n > 0) {
            char id[65];
            fleet_board_id_to_hex(rows[n - 1].post.id, id);
            rendered = rendered && json_push_kv_int(result, "next_created_at", rows[n - 1].post.created_at) &&
                       json_push_kv_str(result, "next_id", id);
        }
        if (!rendered)
            fb_error(result, "BOARD_ALLOC_FAILED", "the board page continuation could not be allocated");
    } else
        fb_error(result, "BOARD_READ_FAILED",
                 "the board list could not be read completely; try again");
    free(rows);
}
