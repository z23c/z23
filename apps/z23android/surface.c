/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "surface.h"
#include "jni_util.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VIEW_MAX 1024u
#define TEXT_CAP 160
#define MATCH (-1)
#define WRAP (-2)
#define FIXED_DP 320.0f /* Height of a video or image in a parent that scrolls. */
#define GRAVITY_CENTER 17
#define GRAVITY_START_CENTER 8388627

/* Where a view sits: in a vertical or horizontal LinearLayout, a FrameLayout or a grid row. */
enum placement { IN_COLUMN, IN_ROW, IN_STACK, IN_CELL };

struct bind {
    jobject view;
    const struct zapp_node *node;
    size_t card;
    bool applied;
    char last[TEXT_CAP];
};
static struct {
    jobject activity, host;
    struct bind *binds;
    size_t bind_count;
    bool built;
    uint64_t generation, signature;
    char screen[ZAPP_NAME_CAP];
} state;

struct build {
    JNIEnv *env;
    const struct zapp_layout *layout;
    const struct json_value *const *cards;
    size_t count, views;
    zapp_surface_labels labels;
    bool failed;
};
struct rows { jobject row; int filled; };

static jint mix(uint32_t a, uint32_t b, unsigned percent)
{
    uint32_t out = 0xff000000u;
    for (unsigned shift = 0; shift < 24; shift += 8) {
        uint32_t x = a >> shift & 255u, y = b >> shift & 255u;
        out |= ((x * (100u - percent) + y * percent) / 100u & 255u) << shift;
    }
    return (jint)out;
}
static jint tile_color(const struct build *b) { return mix(b->layout->theme.background, b->layout->theme.text, 14); }

/* The text a leaf shows now: a card field, the first letter of one, or the label of an action. */
static void leaf_text(const struct build *b, const struct zapp_node *node, size_t card, char *out)
{
    out[0] = 0;
    if (card != ZAPP_NO_CARD && node->field[0]) (void)zapp_card_field(b->cards[card], node->field, out, TEXT_CAP);
    else if (node->kind == ZAPP_NODE_ACTION && b->labels) {
        const char *label = b->labels(node->id);
        if (label) snprintf(out, TEXT_CAP, "%s", label);
    }
    if (node->kind != ZAPP_NODE_AVATAR) return;
    size_t length = out[0] ? 1 : 0;
    while (out[length] && ((unsigned char)out[length] & 0xc0u) == 0x80u) ++length;
    if (length == 1 && out[0] >= 'a' && out[0] <= 'z') out[0] = (char)(out[0] - 'a' + 'A');
    out[length] = 0;
}
static void apply_text(JNIEnv *env, struct bind *bind, const char *text)
{
    if (bind->applied && !strcmp(bind->last, text)) return;
    bind->applied = true;
    snprintf(bind->last, sizeof(bind->last), "%s", text);
    (void)zj_text(env, bind->view, text);
    if (bind->node->kind != ZAPP_NODE_ACTION) (void)zj_visible(env, bind->view, text[0] != 0);
}
static void release_binds(JNIEnv *env)
{
    for (size_t i = 0; i < state.bind_count; ++i) (*env)->DeleteGlobalRef(env, state.binds[i].view);
    state.bind_count = 0; state.built = false;
}
static bool bind_view(struct build *b, jobject view, const struct zapp_node *node, size_t card)
{
    char text[TEXT_CAP];
    if (state.bind_count == VIEW_MAX) return false;
    struct bind *bind = &state.binds[state.bind_count];
    memset(bind, 0, sizeof(*bind));
    if (!zj_keep(b->env, &bind->view, view)) return false;
    bind->node = node; bind->card = card;
    leaf_text(b, node, card, text);
    apply_text(b->env, bind, text);
    ++state.bind_count;
    return true;
}
static float text_size(const struct zapp_node *node)
{
    return node->style == ZAPP_STYLE_TITLE ? 28.0f : node->style == ZAPP_STYLE_CAPTION ? 14.0f : 17.0f;
}
static bool style_tile(struct build *b, jobject view, bool cell)
{
    const struct zapp_theme *theme = &b->layout->theme;
    return zj_typography(b->env, view, cell ? 18.0f : 16.0f, (jint)theme->text) &&
        zj_bool_property(b->env, view, "setAllCaps", false) && zj_pill(b->env, view, tile_color(b), cell ? 24.0f : 12.0f) &&
        zj_flatten(b->env, view) && (cell || (zj_int_property(b->env, view, "setGravity", GRAVITY_START_CENTER) &&
        zj_padding(b->env, view, 16, 8)));
}
static jobject make_view(struct build *b, const char *type)
{
    return zj_widget(b->env, type, state.activity);
}
static jobject make_text(struct build *b, const struct zapp_node *node)
{
    const struct zapp_theme *theme = &b->layout->theme;
    bool counter = node->kind == ZAPP_NODE_COUNTER;
    jobject view = make_view(b, "android/widget/TextView");
    jint color = counter ? (jint)theme->accent : (jint)(node->style == ZAPP_STYLE_CAPTION ? theme->muted : theme->text);
    bool ok = view && zj_typography(b->env, view, counter ? 16.0f : text_size(node), color) && zj_padding(b->env, view, 0, 4) &&
        (node->max_lines <= 0 || zj_int_property(b->env, view, "setMaxLines", node->max_lines));
    return ok ? view : NULL;
}
static jobject make_avatar(struct build *b)
{
    const struct zapp_theme *theme = &b->layout->theme;
    jobject view = make_view(b, "android/widget/TextView");
    bool ok = view && zj_typography(b->env, view, 18.0f, (jint)theme->background) &&
        zj_int_property(b->env, view, "setGravity", GRAVITY_CENTER) && zj_pill(b->env, view, (jint)theme->accent, 24.0f);
    return ok ? view : NULL;
}
static jobject make_image(struct build *b)
{
    jobject view = make_view(b, "android/widget/ImageView");
    return view && zj_pill(b->env, view, tile_color(b), 12.0f) ? view : NULL;
}
static jobject make_action(struct build *b, bool cell)
{
    jobject view = make_view(b, "android/widget/Button");
    return view && style_tile(b, view, cell) ? view : NULL;
}
static bool fills(const struct zapp_node *node)
{
    return node->kind == ZAPP_NODE_GRID || node->kind == ZAPP_NODE_VIDEO || node->kind == ZAPP_NODE_IMAGE;
}
/* Size and spacing from the parent: fill kinds share the space left, or take a fixed height when the
 * parent scrolls; cells of a grid row share its width. */
static bool set_params(struct build *b, jobject view, const struct zapp_node *node, enum placement where, bool scrolls)
{
    bool fill = fills(node), fixed = fill && scrolls && node->kind != ZAPP_NODE_GRID;
    int margin = node->kind == ZAPP_NODE_ACTION ? 6 : 0;
    switch (where) {
    case IN_COLUMN:
        if (fill && !scrolls) return zj_margins(b->env, view, MATCH, 0, 1.0f, 0, 0, 0, 0);
        return zj_margins(b->env, view, MATCH, fixed ? zj_dp(FIXED_DP) : WRAP, 0.0f, margin, margin, margin, margin);
    case IN_ROW: return zj_margins(b->env, view, 0, fill ? MATCH : WRAP, 1.0f, margin, margin, margin, margin);
    case IN_CELL: return zj_margins(b->env, view, 0, MATCH, 1.0f, 6, 6, 6, 6);
    case IN_STACK: return zj_margins(b->env, view, MATCH, fill || node->kind <= ZAPP_NODE_STACK ? MATCH : WRAP, 0.0f, 0, 0, 0, 0);
    }
    return false;
}
static jobject make_node(struct build *b, const struct zapp_node *node, size_t card, enum placement where, bool scrolls);
/* Adds one child to a group; a grid fills rows of its column count. A node with nothing to draw is skipped. */
static bool add_child(struct build *b, const struct zapp_node *parent, const struct zapp_node *child, size_t card,
                      jobject group, struct rows *rows, bool scrolls)
{
    JNIEnv *env = b->env;
    bool grid = parent->kind == ZAPP_NODE_GRID;
    enum placement where = grid ? IN_CELL : parent->kind == ZAPP_NODE_ROW ? IN_ROW :
        parent->kind == ZAPP_NODE_STACK ? IN_STACK : IN_COLUMN;
    if (b->views >= VIEW_MAX) return true;
    jobject view = make_node(b, child, card, where, scrolls);
    if (b->failed) return false;
    if (!view) return true;
    if (grid && (rows->filled == parent->columns || !rows->row)) {
        if (rows->row && !(zj_append(env, group, rows->row))) b->failed = true;
        if (rows->row) (*env)->DeleteLocalRef(env, rows->row);
        rows->row = zj_widget(env, "android/widget/LinearLayout", state.activity);
        rows->filled = 0;
        if (!rows->row || !zj_int_property(env, rows->row, "setOrientation", 0) ||
            !zj_margins(env, rows->row, MATCH, scrolls ? zj_dp(110.0f) : 0, scrolls ? 0.0f : 1.0f, 0, 0, 0, 0)) b->failed = true;
    }
    if (!b->failed && !zj_append(env, grid ? rows->row : group, view)) b->failed = true;
    rows->filled += grid;
    (*env)->DeleteLocalRef(env, view);
    return !b->failed;
}
/* Children are drawn once, or once per card of the container's card kind. */
static bool add_children(struct build *b, const struct zapp_node *node, size_t card, jobject group, bool scrolls)
{
    struct rows rows = {NULL, 0};
    size_t passes = node->card[0] ? b->count : 1;
    for (size_t pass = 0; pass < passes && !b->failed; ++pass) {
        size_t current = card;
        if (node->card[0]) {
            if (!zapp_card_is(b->cards[pass], node->card)) continue;
            current = pass;
        }
        for (size_t i = 0; i < node->child_count && add_child(b, node, &node->children[i], current, group, &rows, scrolls); ++i) {}
    }
    if (node->kind == ZAPP_NODE_GRID && rows.row) {
        for (; rows.filled < node->columns && !b->failed; ++rows.filled) {
            jobject gap = zj_widget(b->env, "android/view/View", state.activity);
            if (!gap || !zj_margins(b->env, gap, 0, MATCH, 1.0f, 6, 6, 6, 6) || !zj_append(b->env, rows.row, gap)) b->failed = true;
            if (gap) (*b->env)->DeleteLocalRef(b->env, gap);
        }
        if (!b->failed && !zj_append(b->env, group, rows.row)) b->failed = true;
    }
    if (rows.row) (*b->env)->DeleteLocalRef(b->env, rows.row);
    return !b->failed;
}
static const char *group_type(const struct zapp_node *node)
{
    return node->kind == ZAPP_NODE_STACK ? "android/widget/FrameLayout" : "android/widget/LinearLayout";
}
static jobject make_container(struct build *b, const struct zapp_node *node, size_t card, enum placement where, bool scrolls)
{
    bool scroll_here = !scrolls && (node->kind == ZAPP_NODE_LIST || node->kind == ZAPP_NODE_PAGER_VERTICAL);
    jobject group = make_view(b, group_type(node)), outer = group;
    bool ok = group && (node->kind == ZAPP_NODE_STACK || zj_int_property(b->env, group, "setOrientation", node->kind == ZAPP_NODE_ROW ? 0 : 1));
    if (ok && scroll_here) {
        outer = make_view(b, "android/widget/ScrollView");
        ok = outer && zj_append(b->env, outer, group);
    }
    ok = ok && add_children(b, node, card, group, scrolls || scroll_here) && set_params(b, outer, node, where, scrolls);
    return ok ? outer : NULL;
}
static jobject make_leaf(struct build *b, const struct zapp_node *node, size_t card, enum placement where)
{
    jobject view = NULL;
    switch (node->kind) {
    case ZAPP_NODE_TEXT: case ZAPP_NODE_COUNTER: view = make_text(b, node); break;
    case ZAPP_NODE_AVATAR: view = make_avatar(b); break;
    case ZAPP_NODE_IMAGE: view = make_image(b); break;
    case ZAPP_NODE_VIDEO: view = make_view(b, "android/view/SurfaceView"); break;
    case ZAPP_NODE_ACTION: view = make_action(b, where == IN_CELL); break;
    default: break;
    }
    bool bound = node->kind == ZAPP_NODE_TEXT || node->kind == ZAPP_NODE_COUNTER || node->kind == ZAPP_NODE_AVATAR ||
        node->kind == ZAPP_NODE_ACTION;
    if (view && bound && !bind_view(b, view, node, card)) { (*b->env)->DeleteLocalRef(b->env, view); return NULL; }
    return view;
}
/* A container that repeats a card kind has nothing to draw when no card of that kind exists. */
static bool has_cards(const struct build *b, const struct zapp_node *node)
{
    for (size_t i = 0; node->card[0] && i < b->count; ++i)
        if (zapp_card_is(b->cards[i], node->card)) return true;
    return !node->card[0];
}
static jobject make_node(struct build *b, const struct zapp_node *node, size_t card, enum placement where, bool scrolls)
{
    JNIEnv *env = b->env;
    bool container = node->kind <= ZAPP_NODE_STACK;
    char label[TEXT_CAP];
    if (container && !has_cards(b, node)) return NULL;
    if (node->kind == ZAPP_NODE_ACTION) {
        leaf_text(b, node, card, label);
        if (!label[0]) return NULL;
    }
    if ((*env)->PushLocalFrame(env, 16) != JNI_OK) { (void)zj_clean(env); b->failed = true; return NULL; }
    ++b->views;
    jobject view = container ? make_container(b, node, card, where, scrolls) : make_leaf(b, node, card, where);
    bool ok = view && (container || set_params(b, view, node, where, scrolls));
    if (!ok) b->failed = true;
    return (*env)->PopLocalFrame(env, ok ? view : NULL);
}
bool zapp_surface_create(JNIEnv *env, jobject activity, jobject host)
{
    state.binds = calloc(VIEW_MAX, sizeof(*state.binds));
    if (!state.binds) return false;
    state.activity = (*env)->NewGlobalRef(env, activity);
    state.host = (*env)->NewGlobalRef(env, host);
    if (zj_clean(env) && state.activity && state.host) return true;
    zapp_surface_destroy(env);
    return false;
}
void zapp_surface_destroy(JNIEnv *env)
{
    release_binds(env);
    free(state.binds);
    if (state.activity) (*env)->DeleteGlobalRef(env, state.activity);
    if (state.host) (*env)->DeleteGlobalRef(env, state.host);
    memset(&state, 0, sizeof(state));
}
static uint64_t signature(const struct json_value *const *cards, size_t count)
{
    uint64_t hash = 1469598103934665603ull + count;
    char schema[ZAPP_NAME_CAP];
    for (size_t i = 0; i < count; ++i) {
        (void)zapp_card_field(cards[i], "schema", schema, sizeof(schema));
        for (const char *p = schema; *p; ++p) hash = (hash ^ (unsigned char)*p) * 1099511628211ull;
        hash = (hash ^ 0xffu) * 1099511628211ull;
    }
    return hash;
}
static void update_text(struct build *b)
{
    char text[TEXT_CAP];
    for (size_t i = 0; i < state.bind_count; ++i) {
        leaf_text(b, state.binds[i].node, state.binds[i].card, text);
        apply_text(b->env, &state.binds[i], text);
    }
}
static bool rebuild(struct build *b, const struct zapp_node *root, const char *screen, uint64_t signature_now)
{
    JNIEnv *env = b->env;
    release_binds(env);
    jmethodID clear = zj_method(env, state.host, "removeAllViews", "()V");
    if (clear) (*env)->CallVoidMethod(env, state.host, clear);
    bool ok = clear && zj_clean(env) && zj_int_property(env, state.host, "setBackgroundColor", (jint)b->layout->theme.background);
    jobject view = ok ? make_node(b, root, ZAPP_NO_CARD, IN_STACK, false) : NULL;
    ok = view && zj_append(env, state.host, view);
    if (view) (*env)->DeleteLocalRef(env, view);
    if (!ok) { release_binds(env); return false; }
    state.built = true; state.generation = b->layout->generation; state.signature = signature_now;
    snprintf(state.screen, sizeof(state.screen), "%s", screen);
    return true;
}
bool zapp_surface_show(JNIEnv *env, const struct zapp_layout *layout, const char *screen,
                       const struct json_value *const *cards, size_t count, zapp_surface_labels labels)
{
    const struct zapp_node *root = zapp_layout_screen(layout, screen);
    struct build b = {.env = env, .layout = layout, .cards = cards, .count = count, .labels = labels};
    if (!root || !state.host) return false;
    uint64_t now = signature(cards, count);
    if (state.built && state.generation == layout->generation && now == state.signature && !strcmp(state.screen, screen)) {
        update_text(&b);
        return true;
    }
    return rebuild(&b, root, screen, now);
}
bool zapp_surface_hit(JNIEnv *env, float x, float y, char id[ZAPP_NAME_CAP], size_t *card)
{
    for (size_t i = 0; i < state.bind_count; ++i) {
        const struct bind *bind = &state.binds[i];
        if (bind->node->kind != ZAPP_NODE_ACTION || !zj_hit(env, bind->view, x, y)) continue;
        memcpy(id, bind->node->id, ZAPP_NAME_CAP);
        *card = bind->card;
        return true;
    }
    return false;
}
