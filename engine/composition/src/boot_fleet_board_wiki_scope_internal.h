/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_fleet_board_wiki_scope_internal — the scope option of the wiki leaves:
 * which view a read takes, and whether a review or revision stays in the
 * scope of the page it answers. */

#ifndef ZCL_CONFIG_BOOT_FLEET_BOARD_WIKI_SCOPE_INTERNAL_H
#define ZCL_CONFIG_BOOT_FLEET_BOARD_WIKI_SCOPE_INTERNAL_H

#include "json/json.h"
#include "models/fleet_board_post.h"

/* The `scope` field of a wiki read, find, list or history request: absent or
 * "public" is the public view (the behaviour before the option existed),
 * "fleet" the fleet-private view. False, with *why naming the accepted
 * values, for anything else. */
bool boot_fleet_wiki_view_parse(const struct json_value *in,
                                enum fleet_wiki_view *view, const char **why);

/* A wiki post (a revision or a typed review) may answer only a page signed
 * under its own scope: a public review of a fleet page would announce the
 * fleet page's id to the public board, and a fleet revision of a public page
 * would fork a page across two audiences. Returns NULL when the post is fine,
 * else a sentence for the writer, with *code naming the refusal. A target
 * this node does not hold is not decided here. */
const char *boot_fleet_wiki_scope_refusal(struct node_db *ndb,
    const struct fleet_board_post *post, const char **code, char *buf,
    size_t cap);

#endif
