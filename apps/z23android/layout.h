/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_LAYOUT_H
#define ZAPP_LAYOUT_H
#include "json/json.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZAPP_LAYOUT_MAX_BYTES 65536u
#define ZAPP_LAYOUT_MAX_DEPTH 8
#define ZAPP_LAYOUT_MAX_NODES 256u
#define ZAPP_LAYOUT_MAX_SCREENS 16u
#define ZAPP_NAME_CAP 48

/* The closed set of primitives of a zcl.layout_recipe.v1 document: containers, arrangements, leaves. */
enum zapp_node_kind {
    ZAPP_NODE_PAGER_VERTICAL, ZAPP_NODE_LIST, ZAPP_NODE_GRID,
    ZAPP_NODE_ROW, ZAPP_NODE_COLUMN, ZAPP_NODE_STACK,
    ZAPP_NODE_VIDEO, ZAPP_NODE_IMAGE, ZAPP_NODE_TEXT, ZAPP_NODE_COUNTER, ZAPP_NODE_ACTION, ZAPP_NODE_AVATAR
};
enum zapp_text_style { ZAPP_STYLE_BODY, ZAPP_STYLE_TITLE, ZAPP_STYLE_CAPTION };

/* A node renders card fields by name and names an action by id; it holds no URL and no method. A
 * container with a card kind renders its children once per card of that kind. */
struct zapp_node {
    enum zapp_node_kind kind;
    enum zapp_text_style style;
    char card[ZAPP_NAME_CAP];  /* Card kind a container repeats its children for, or empty. */
    char field[ZAPP_NAME_CAP]; /* Dotted path into the current card, or empty. */
    char id[ZAPP_NAME_CAP];    /* Action id of an action node. */
    int max_lines;             /* 0 for no limit. */
    int columns;               /* Grid columns. */
    struct zapp_node *children;
    size_t child_count;
};
/* Colors as 0xAARRGGBB with full alpha. */
struct zapp_theme { uint32_t background, text, muted, accent; };
struct zapp_screen { char name[ZAPP_NAME_CAP]; struct zapp_node root; };
struct zapp_layout {
    uint64_t generation; /* Unique per parsed layout, so a renderer can tell one from another. */
    char id[ZAPP_NAME_CAP];
    struct zapp_theme theme;
    struct zapp_screen screens[ZAPP_LAYOUT_MAX_SCREENS];
    size_t screen_count;
    size_t node_count;
};

/* Parses a layout document. The whole layout is refused, with a sentence in reason, for a document over
 * 64 KiB, an unknown primitive, a color that is not "#rrggbb", more than 8 levels or 256 nodes. Unknown
 * fields are ignored. The result is released with zapp_layout_free. */
struct zapp_layout *zapp_layout_parse(const char *json, size_t len, char *reason, size_t reason_cap);
void zapp_layout_free(struct zapp_layout *layout);
/* The root node of the named screen, or NULL. */
const struct zapp_node *zapp_layout_screen(const struct zapp_layout *layout, const char *name);
/* Copies the scalar at a dotted path of a card ("counts.comments") as text, cut on a character
 * boundary to fit cap. A missing or non-scalar field gives an empty string and false. */
bool zapp_card_field(const struct json_value *card, const char *path, char *out, size_t cap);
/* True when the card's schema is zcl.<kind>_card.v1. */
bool zapp_card_is(const struct json_value *card, const char *kind);
#endif
