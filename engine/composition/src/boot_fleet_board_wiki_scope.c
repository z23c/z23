/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The scope option of the fleet wiki leaves: the view a read takes
 * and the same-scope rule for a review or a revision. Visibility follows the
 * signed scope of each revision; the signing authority stays this node's. */

#include "boot_fleet_board_wiki_scope_internal.h"

#include "session/fleet_board_proto.h"
#include "session/fleet_wiki_entry.h"

#include <stdio.h>
#include <string.h>

bool boot_fleet_wiki_view_parse(const struct json_value *in,
                                enum fleet_wiki_view *view, const char **why)
{
    const char *name = json_get_str(json_get(in, "scope"));
    *view = FLEET_WIKI_VIEW_PUBLIC;
    if (!name[0] || !strcmp(name, "public"))
        return true;
    if (!strcmp(name, "fleet")) {
        *view = FLEET_WIKI_VIEW_FLEET;
        return true;
    }
    *why = "scope must be public or fleet";
    return false;
}

static enum fleet_wiki_view view_of(uint8_t scope)
{
    return scope == FLEET_BOARD_SCOPE_FLEET ? FLEET_WIKI_VIEW_FLEET
                                            : FLEET_WIKI_VIEW_PUBLIC;
}

/* The id of the page a typed review answers; false for any other body. */
static bool review_target(const struct fleet_board_post *post, uint8_t id[32])
{
    struct json_value review;
    bool typed = fleet_wiki_review_parse(post->text, post->text_len, &review,
                                         NULL) == FLEET_WIKI_REVIEW_VALID &&
        fleet_board_id_from_hex(json_get_str(json_get(&review, "target")), id);
    json_free(&review);
    return typed;
}

static bool crosses(struct node_db *ndb, const struct fleet_board_post *post,
                    const uint8_t id[32], uint8_t *held_scope)
{
    struct db_fleet_board_post held;
    if (!db_fleet_board_post_find(ndb, id, &held) ||
        held.post.kind != FLEET_BOARD_KIND_WIKI)
        return false;
    *held_scope = held.post.scope;
    return !fleet_wiki_view_has(view_of(post->scope), held.post.scope);
}

static const char *refuse(const char *what, uint8_t own, uint8_t held,
                          char *buf, size_t cap)
{
    (void)snprintf(buf, cap,
        "a %s in the %s scope cannot answer a page signed in the %s scope; "
        "write it with scope=%s, the scope of the page it answers",
        what, own == FLEET_BOARD_SCOPE_FLEET ? "fleet" : "public",
        held == FLEET_BOARD_SCOPE_FLEET ? "fleet" : "public",
        held == FLEET_BOARD_SCOPE_FLEET ? "fleet" : "public");
    return buf;
}

const char *boot_fleet_wiki_scope_refusal(struct node_db *ndb,
    const struct fleet_board_post *post, const char **code, char *buf,
    size_t cap)
{
    static const uint8_t zero[32];
    uint8_t id[32], held;
    if (post->kind != FLEET_BOARD_KIND_WIKI)
        return NULL;
    if (review_target(post, id) && crosses(ndb, post, id, &held)) {
        *code = "CROSS_SCOPE_REVIEW";
        return refuse("review", post->scope, held, buf, cap);
    }
    if (memcmp(post->supersedes, zero, 32) &&
        crosses(ndb, post, post->supersedes, &held)) {
        *code = "CROSS_SCOPE_REVISION";
        return refuse("revision", post->scope, held, buf, cap);
    }
    return NULL;
}

bool boot_fleet_wiki_review_in_view(enum fleet_wiki_view view,
                                    const struct fleet_board_post *post)
{
    if (post->scope != fleet_wiki_view_scope(view))
        return false;
    return view == FLEET_WIKI_VIEW_FLEET ||
           !strcmp(post->room, FLEET_BOARD_ROOM_DEFAULT);
}

bool boot_fleet_wiki_scope_reject(struct node_db *ndb,
    const struct fleet_board_post *post, struct json_value *result)
{
    const char *code = NULL;
    char why[320];
    const char *refusal = boot_fleet_wiki_scope_refusal(ndb, post, &code, why,
                                                         sizeof(why));
    if (!refusal)
        return false;
    json_set_object(result);
    json_push_kv_bool(result, "ok", false);
    json_push_kv_str(result, "code", code);
    json_push_kv_str(result, "message", refusal);
    return true;
}
