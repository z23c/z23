/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "layout.h"
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const struct { const char *name; enum zapp_node_kind kind; bool container; } kinds[] = {
    {"pager_vertical", ZAPP_NODE_PAGER_VERTICAL, true}, {"list", ZAPP_NODE_LIST, true},
    {"grid", ZAPP_NODE_GRID, true}, {"row", ZAPP_NODE_ROW, true}, {"column", ZAPP_NODE_COLUMN, true},
    {"stack", ZAPP_NODE_STACK, true}, {"video", ZAPP_NODE_VIDEO, false}, {"image", ZAPP_NODE_IMAGE, false},
    {"text", ZAPP_NODE_TEXT, false}, {"counter", ZAPP_NODE_COUNTER, false},
    {"action", ZAPP_NODE_ACTION, false}, {"avatar", ZAPP_NODE_AVATAR, false},
};
static uint64_t generations;

struct parser { struct zapp_layout *layout; char *reason; size_t cap; };

static bool refuse(struct parser *p, const char *format, ...) __attribute__((format(printf, 2, 3)));
static bool refuse(struct parser *p, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (p->reason && p->cap) vsnprintf(p->reason, p->cap, format, args);
    va_end(args);
    return false;
}
static bool parse_color(const char *text, uint32_t *out)
{
    if (!text || strlen(text) != 7 || text[0] != '#') return false;
    uint32_t value = 0;
    for (size_t i = 1; i < 7; ++i) {
        char c = text[i];
        uint32_t digit = c >= '0' && c <= '9' ? (uint32_t)(c - '0') : c >= 'a' && c <= 'f' ? (uint32_t)(c - 'a' + 10) :
            c >= 'A' && c <= 'F' ? (uint32_t)(c - 'A' + 10) : 16u;
        if (digit == 16u) return false;
        value = value << 4 | digit;
    }
    *out = 0xff000000u | value;
    return true;
}
static bool parse_theme(struct parser *p, const struct json_value *theme)
{
    if (theme->type != JSON_OBJ) return refuse(p, "theme must be an object");
    uint32_t *slots[] = {&p->layout->theme.background, &p->layout->theme.text, &p->layout->theme.muted, &p->layout->theme.accent};
    static const char *const names[] = {"background", "text", "muted", "accent"};
    for (size_t i = 0; i < 4; ++i) {
        const struct json_value *color = json_get(theme, names[i]);
        if (!color) continue;
        if (color->type != JSON_STR || !parse_color(color->val.s, slots[i]))
            return refuse(p, "theme color %s must be #rrggbb", names[i]);
    }
    return true;
}
static bool name_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
}
/* Copies an optional name made of letters, digits and "_.-"; anything else refuses the layout. */
static bool copy_name(struct parser *p, const struct json_value *obj, const char *key, char *out)
{
    const struct json_value *value = json_get(obj, key);
    if (!value) return true;
    const char *s = value->type == JSON_STR ? value->val.s : NULL;
    size_t length = s ? strlen(s) : 0;
    if (!s || length >= ZAPP_NAME_CAP) return refuse(p, "%s must be a short name", key);
    for (size_t i = 0; i < length; ++i)
        if (!name_char(s[i])) return refuse(p, "%s holds a character that is not allowed", key);
    memcpy(out, s, length + 1);
    return true;
}
static int clamped(const struct json_value *obj, const char *key, int low, int high, int fallback)
{
    const struct json_value *value = json_get(obj, key);
    if (!value || value->type != JSON_INT) return fallback;
    return value->val.i < low ? low : value->val.i > high ? (int)high : (int)value->val.i;
}
static enum zapp_text_style parse_style(const struct json_value *obj)
{
    const struct json_value *style = json_get(obj, "style");
    const char *name = style && style->type == JSON_STR ? style->val.s : "";
    return !strcmp(name, "title") ? ZAPP_STYLE_TITLE : !strcmp(name, "caption") ? ZAPP_STYLE_CAPTION : ZAPP_STYLE_BODY;
}
static bool parse_kind(struct parser *p, const struct json_value *obj, size_t *index)
{
    const struct json_value *type = json_get(obj, "type");
    if (!type) type = json_get(obj, "container");
    if (!type || type->type != JSON_STR) return refuse(p, "a node needs a type");
    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); ++i)
        if (!strcmp(kinds[i].name, type->val.s)) { *index = i; return true; }
    return refuse(p, "unknown primitive \"%.32s\"", type->val.s);
}
static bool parse_node(struct parser *p, const struct json_value *obj, struct zapp_node *node, int depth);
static bool parse_children(struct parser *p, const struct json_value *list, struct zapp_node *node, int depth)
{
    if (!list) return true;
    if (list->type != JSON_ARR) return refuse(p, "children must be an array");
    if (list->num_children > ZAPP_LAYOUT_MAX_NODES - p->layout->node_count)
        return refuse(p, "more than %u nodes", ZAPP_LAYOUT_MAX_NODES);
    if (!list->num_children) return true;
    node->children = calloc(list->num_children, sizeof(*node->children));
    if (!node->children) return refuse(p, "out of memory");
    node->child_count = list->num_children;
    for (size_t i = 0; i < node->child_count; ++i)
        if (!parse_node(p, &list->children[i], &node->children[i], depth + 1)) return false;
    return true;
}
static bool parse_node(struct parser *p, const struct json_value *obj, struct zapp_node *node, int depth)
{
    size_t index = 0;
    if (depth > ZAPP_LAYOUT_MAX_DEPTH) return refuse(p, "nested deeper than %d levels", ZAPP_LAYOUT_MAX_DEPTH);
    if (obj->type != JSON_OBJ) return refuse(p, "a node must be an object");
    if (++p->layout->node_count > ZAPP_LAYOUT_MAX_NODES) return refuse(p, "more than %u nodes", ZAPP_LAYOUT_MAX_NODES);
    if (!parse_kind(p, obj, &index)) return false;
    node->kind = kinds[index].kind;
    node->style = parse_style(obj);
    node->max_lines = clamped(obj, "max_lines", 0, 20, 0);
    node->columns = clamped(obj, "columns", 1, 6, 2);
    if (!copy_name(p, obj, "card", node->card) || !copy_name(p, obj, "id", node->id)) return false;
    if (!copy_name(p, obj, "field", node->field)) return false;
    return !kinds[index].container || parse_children(p, json_get(obj, "children"), node, depth);
}
static bool parse_screens(struct parser *p, const struct json_value *screens)
{
    if (!screens || screens->type != JSON_OBJ || !screens->num_children) return refuse(p, "screens must name at least one screen");
    if (screens->num_children > ZAPP_LAYOUT_MAX_SCREENS) return refuse(p, "more than %u screens", ZAPP_LAYOUT_MAX_SCREENS);
    for (size_t i = 0; i < screens->num_children; ++i) {
        struct zapp_screen *screen = &p->layout->screens[p->layout->screen_count++];
        if (strlen(screens->keys[i]) >= sizeof(screen->name)) return refuse(p, "a screen name is too long");
        memcpy(screen->name, screens->keys[i], strlen(screens->keys[i]) + 1);
        if (!parse_node(p, &screens->children[i], &screen->root, 1)) return false;
    }
    return true;
}
static bool parse_document(struct parser *p, const struct json_value *doc)
{
    const struct json_value *schema = json_get(doc, "schema");
    if (doc->type != JSON_OBJ || !schema || schema->type != JSON_STR || strcmp(schema->val.s, "zcl.layout_recipe.v1"))
        return refuse(p, "not a zcl.layout_recipe.v1 document");
    const struct json_value *theme = json_get(doc, "theme");
    return copy_name(p, doc, "id", p->layout->id) && (!theme || parse_theme(p, theme)) &&
        parse_screens(p, json_get(doc, "screens"));
}
static void free_node(struct zapp_node *node)
{
    for (size_t i = 0; i < node->child_count; ++i) free_node(&node->children[i]);
    free(node->children);
}
void zapp_layout_free(struct zapp_layout *layout)
{
    if (!layout) return;
    for (size_t i = 0; i < layout->screen_count; ++i) free_node(&layout->screens[i].root);
    free(layout);
}
struct zapp_layout *zapp_layout_parse(const char *json, size_t len, char *reason, size_t reason_cap)
{
    struct parser p = {.layout = calloc(1, sizeof(struct zapp_layout)), .reason = reason, .cap = reason_cap};
    struct json_value doc;
    json_init(&doc);
    if (reason && reason_cap) reason[0] = 0;
    bool ok = p.layout && len <= ZAPP_LAYOUT_MAX_BYTES;
    if (p.layout && !ok) refuse(&p, "larger than 64 KiB");
    if (ok && !(ok = json_read(&doc, json, len))) refuse(&p, "not valid JSON");
    if (ok) {
        p.layout->theme = (struct zapp_theme){0xff000000u, 0xffffffffu, 0xff9a9a9au, 0xff3ddc97u};
        p.layout->generation = ++generations;
        ok = parse_document(&p, &doc);
    } else if (!p.layout) refuse(&p, "out of memory");
    json_free(&doc);
    if (!ok) { zapp_layout_free(p.layout); return NULL; }
    return p.layout;
}
const struct zapp_node *zapp_layout_screen(const struct zapp_layout *layout, const char *name)
{
    if (!layout || !name) return NULL;
    for (size_t i = 0; i < layout->screen_count; ++i)
        if (!strcmp(layout->screens[i].name, name)) return &layout->screens[i].root;
    return NULL;
}
static const struct json_value *card_path(const struct json_value *card, const char *path)
{
    const struct json_value *value = card;
    char segment[ZAPP_NAME_CAP];
    while (value && *path) {
        size_t length = strcspn(path, ".");
        if (!length || length >= sizeof(segment)) return NULL;
        memcpy(segment, path, length); segment[length] = 0;
        value = json_get(value, segment);
        path += length + (path[length] == '.');
    }
    return value;
}
static void copy_cut(const char *text, char *out, size_t cap)
{
    size_t length = strlen(text);
    if (length >= cap) {
        length = cap - 1;
        while (length && ((unsigned char)text[length] & 0xc0u) == 0x80u) --length;
    }
    memcpy(out, text, length);
    out[length] = 0;
}
bool zapp_card_field(const struct json_value *card, const char *path, char *out, size_t cap)
{
    if (!out || !cap) return false;
    out[0] = 0;
    const struct json_value *value = card && path && *path ? card_path(card, path) : NULL;
    char number[32];
    if (!value) return false;
    switch (value->type) {
    case JSON_STR: copy_cut(value->val.s ? value->val.s : "", out, cap); break;
    case JSON_INT: snprintf(number, sizeof(number), "%" PRId64, value->val.i); copy_cut(number, out, cap); break;
    case JSON_REAL: snprintf(number, sizeof(number), "%.15g", value->val.d); copy_cut(number, out, cap); break;
    case JSON_BOOL: copy_cut(value->val.b ? "true" : "false", out, cap); break;
    default: return false;
    }
    return true;
}
bool zapp_card_is(const struct json_value *card, const char *kind)
{
    char schema[ZAPP_NAME_CAP];
    if (!zapp_card_field(card, "schema", schema, sizeof(schema))) return false;
    char expected[ZAPP_NAME_CAP];
    snprintf(expected, sizeof(expected), "zcl.%s_card.v1", kind);
    return !strcmp(schema, expected);
}
