/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: ui lifecycle, dirty rectangles, hit testing, focus order, dialogs
 * and event dispatch that turns key and mouse events into named actions. */
#include <stdio.h>
#include <string.h>

#include "base/cleanse.h"
#include "base/safe_alloc.h"
#include "gui/ui.h"

struct gui_ui *gui_ui_new(struct gui_tree *tree)
{
    struct gui_ui *ui = zcl_calloc(1, sizeof(*ui), "gui_ui");
    if (!ui) return NULL;
    ui->data.pool = zcl_calloc(GUI_DATA_BYTES, 1, "gui_data_pool");
    if (!ui->data.pool) {
        free(ui);
        return NULL;
    }
    ui->tree = tree;
    ui->scale = 1.0f;
    ui->win_focused = true;
    ui->layout_dirty = true;
    return ui;
}

void gui_ui_free(struct gui_ui *ui)
{
    if (!ui) return;
    for (size_t i = 0; i < 8; i++)
        if (ui->inputs[i].buf) {
            memory_cleanse(ui->inputs[i].buf, ui->inputs[i].cap + 1);
            free(ui->inputs[i].buf);
        }
    free(ui->data.pool);
    free(ui);
}

void gui_ui_set_window(struct gui_ui *ui, struct gui_window *w) { ui->win = w; }

void gui_ui_set_scale(struct gui_ui *ui, float scale)
{
    if (scale > 0.0f && scale != ui->scale) {
        ui->scale = scale;
        ui->layout_dirty = true;
    }
}

void gui_ui_rebind(struct gui_ui *ui)
{
    ui->layout_dirty = true;
    if (gui_tree_find(ui->tree, ui->focus) < 0) ui->focus[0] = 0;
    if (gui_tree_find(ui->tree, ui->hover) < 0) ui->hover[0] = 0;
    if (gui_tree_find(ui->tree, ui->pressed) < 0) ui->pressed[0] = 0;
}

void gui_ui_mark_rect(struct gui_ui *ui, struct gui_rect r)
{
    int32_t m = gui_px(ui, 3);
    r = (struct gui_rect){ r.x - m, r.y - m, r.w + 2 * m, r.h + 2 * m };
    if (ui->ndirty < 8) {
        ui->dirty[ui->ndirty++] = r;
        return;
    }
    struct gui_rect u = r;
    for (size_t i = 0; i < ui->ndirty; i++) u = gui_rect_union(u, ui->dirty[i]);
    ui->dirty[0] = u;
    ui->ndirty = 1;
}

void gui_ui_mark_node(struct gui_ui *ui, const char *id)
{
    int at = gui_tree_find(ui->tree, id);
    if (at >= 0) gui_ui_mark_rect(ui, ui->tree->nodes[at].frame);
}

size_t gui_ui_take_dirty(struct gui_ui *ui, struct gui_rect *out, size_t cap)
{
    size_t n = ui->ndirty < cap ? ui->ndirty : cap;
    memcpy(out, ui->dirty, n * sizeof(*out));
    ui->ndirty = 0;
    return n;
}

void gui_ui_toast(struct gui_ui *ui, const char *utf8, uint32_t ms)
{
    snprintf(ui->toast, sizeof(ui->toast), "%s", utf8);
    ui->toast_until_ns = gui_now_ns() + (uint64_t)ms * 1000000ull;
    gui_ui_mark_rect(ui, (struct gui_rect){ ui->w / 3, ui->h - gui_px(ui, 110), ui->w - ui->w / 3,
                                            gui_px(ui, 110) });
}

bool gui_ui_tick(struct gui_ui *ui)
{
    if (!ui->toast[0] || gui_now_ns() < ui->toast_until_ns) return false;
    ui->toast[0] = 0;
    gui_ui_mark_rect(ui, (struct gui_rect){ ui->w / 3, ui->h - gui_px(ui, 110), ui->w - ui->w / 3,
                                            gui_px(ui, 110) });
    return true;
}

void gui_ui_blink(struct gui_ui *ui)
{
    ui->caret_on = !ui->caret_on;
    gui_ui_mark_node(ui, ui->focus);
}

bool gui_ui_wants_blink(const struct gui_ui *ui)
{
    int at = gui_tree_find(ui->tree, ui->focus);
    return at >= 0 && ui->tree->nodes[at].kind == GUI_INPUT && ui->win_focused;
}

/* ---- scope, visibility, hit testing ---------------------------------- */

static bool node_visible(const struct gui_tree *t, uint16_t i)
{
    for (; i != GUI_NONE; i = t->nodes[i].parent)
        if (t->nodes[i].flags & GUI_F_HIDDEN) return false;
    return true;
}

static int open_dialog(const struct gui_tree *t)
{
    int found = -1;
    for (uint16_t i = 0; i < t->count; i++)
        if (t->nodes[i].kind == GUI_DIALOG && node_visible(t, i)) found = i;
    return found;
}

static bool in_scope(const struct gui_tree *t, uint16_t i, int dialog)
{
    if (dialog < 0) return true;
    for (; i != GUI_NONE; i = t->nodes[i].parent)
        if (i == (uint16_t)dialog) return true;
    return false;
}

static bool interactive(const struct gui_node *n)
{
    return (n->flags & GUI_F_FOCUSABLE) && !(n->flags & GUI_F_DISABLED);
}

static int hit_test(const struct gui_ui *ui, int32_t x, int32_t y)
{
    const struct gui_tree *t = ui->tree;
    int dialog = open_dialog(t), found = -1;
    for (uint16_t i = 0; i < t->count; i++) {
        const struct gui_node *n = &t->nodes[i];
        if (!interactive(n) || !gui_rect_contains(n->frame, x, y)) continue;
        if (!node_visible(t, i) || !in_scope(t, i, dialog)) continue;
        found = i;
    }
    return found;
}

static void set_focus(struct gui_ui *ui, const char *id, bool kbd)
{
    if (strcmp(ui->focus, id)) {
        gui_ui_mark_node(ui, ui->focus);
        snprintf(ui->focus, sizeof(ui->focus), "%s", id);
        gui_ui_mark_node(ui, id);
    }
    ui->kbd_focus = kbd;
    ui->caret_on = true;
}

void gui_ui_focus(struct gui_ui *ui, const char *id) { set_focus(ui, id, true); }

static void focus_step(struct gui_ui *ui, bool back)
{
    const struct gui_tree *t = ui->tree;
    int dialog = open_dialog(t), cur = gui_tree_find(t, ui->focus), pick = -1;
    int count = (int)t->count;
    for (int k = 1; k <= count; k++) {
        int i = back ? (cur < 0 ? count - k : ((cur - k) % count + count) % count)
                     : (cur < 0 ? k - 1 : (cur + k) % count);
        if (interactive(&t->nodes[i]) && node_visible(t, (uint16_t)i) &&
            in_scope(t, (uint16_t)i, dialog)) {
            pick = i;
            break;
        }
    }
    if (pick >= 0) set_focus(ui, t->nodes[pick].id, true);
}

static bool fire(const struct gui_node *n, struct gui_action *out)
{
    if (!n->action[0]) return false;
    snprintf(out->name, sizeof(out->name), "%s", n->action);
    snprintf(out->node_id, sizeof(out->node_id), "%s", n->id);
    out->row = -1;
    return true;
}

static bool fire_default(struct gui_ui *ui, struct gui_action *out)
{
    const struct gui_tree *t = ui->tree;
    int dialog = open_dialog(t);
    for (uint16_t i = 0; i < t->count; i++)
        if (t->nodes[i].kind == GUI_BUTTON && (t->nodes[i].flags & GUI_F_DEFAULT) &&
            interactive(&t->nodes[i]) && node_visible(t, i) && in_scope(t, i, dialog))
            return fire(&t->nodes[i], out);
    return false;
}

static bool key_on_focus(struct gui_ui *ui, const struct gui_event *ev, struct gui_node *n,
                         struct gui_action *out)
{
    enum gui_key k = ev->key.key;
    switch (n->kind) {
    case GUI_BUTTON:
        return (k == GUI_KEY_ENTER || k == GUI_KEY_SPACE) && fire(n, out);
    case GUI_INPUT:
        if (gui_ui_text_key(ui, ev, n)) return false;
        return k == GUI_KEY_ENTER && fire_default(ui, out);
    case GUI_TABLE:
        return gui_ui_table_key(ui, n, ev, out);
    case GUI_TEXT:
        if (k == GUI_KEY_C && (ev->mods & GUI_MOD_CTRL) && ui->win) {
            const char *s = n->bind[0] ? gui_ui_get(ui, n->bind) : gui_tree_text(ui->tree, n);
            gui_clipboard_set_text(ui->win, s, strlen(s));
        }
        return false;
    default: return false;
    }
}

static bool on_key(struct gui_ui *ui, const struct gui_event *ev, struct gui_action *out)
{
    if (!ev->key.down) return false;
    enum gui_key k = ev->key.key;
    if (k == GUI_KEY_TAB) {
        focus_step(ui, (ev->mods & GUI_MOD_SHIFT) != 0);
        return false;
    }
    int dialog = open_dialog(ui->tree);
    if (k == GUI_KEY_ESCAPE && dialog >= 0) return fire(&ui->tree->nodes[dialog], out);
    int f = gui_tree_find(ui->tree, ui->focus);
    if (f >= 0 && in_scope(ui->tree, (uint16_t)f, dialog)) {
        ui->kbd_focus = true;
        if (key_on_focus(ui, ev, &ui->tree->nodes[f], out)) return true;
        if (ui->tree->nodes[f].kind != GUI_BUTTON || k != GUI_KEY_ENTER) return false;
    }
    return k == GUI_KEY_ENTER && fire_default(ui, out);
}

static void on_move(struct gui_ui *ui, int32_t x, int32_t y)
{
    ui->last_mx = x;
    ui->last_my = y;
    int h = hit_test(ui, x, y);
    const char *id = h >= 0 ? ui->tree->nodes[h].id : "";
    if (strcmp(id, ui->hover)) {
        gui_ui_mark_node(ui, ui->hover);
        snprintf(ui->hover, sizeof(ui->hover), "%s", id);
        gui_ui_mark_node(ui, id);
    }
    int p = gui_tree_find(ui->tree, ui->pressed);
    if (p >= 0 && ui->tree->nodes[p].kind == GUI_INPUT)
        gui_ui_input_click(ui, &ui->tree->nodes[p], x, true);
}

static bool on_button(struct gui_ui *ui, const struct gui_event *ev, struct gui_action *out)
{
    if (ev->button.button != 1) return false;
    int h = hit_test(ui, ev->button.x, ev->button.y);
    if (ev->button.down) {
        if (h < 0) {
            if (open_dialog(ui->tree) < 0) set_focus(ui, "", false);
            return false;
        }
        struct gui_node *n = &ui->tree->nodes[h];
        set_focus(ui, n->id, false);
        snprintf(ui->pressed, sizeof(ui->pressed), "%s", n->id);
        gui_ui_mark_rect(ui, n->frame);
        if (n->kind == GUI_INPUT) {
            gui_ui_input_click(ui, n, ev->button.x, (ev->mods & GUI_MOD_SHIFT) != 0);
            if (ev->button.clicks >= 2) {
                struct gui_event all = { .type = GUI_EV_KEY, .mods = GUI_MOD_CTRL,
                                         .key = { GUI_KEY_A, 0, true, false } };
                (void)gui_ui_text_key(ui, &all, n);
            }
        }
        if (n->kind == GUI_TABLE) return gui_ui_table_click(ui, n, ev->button.x, ev->button.y, out);
        return false;
    }
    int p = gui_tree_find(ui->tree, ui->pressed);
    ui->pressed[0] = 0;
    if (p < 0) return false;
    gui_ui_mark_rect(ui, ui->tree->nodes[p].frame);
    return h == p && ui->tree->nodes[p].kind == GUI_BUTTON && fire(&ui->tree->nodes[p], out);
}

bool gui_ui_event(struct gui_ui *ui, const struct gui_event *ev, struct gui_action *out)
{
    memset(out, 0, sizeof(*out));
    out->row = -1;
    switch (ev->type) {
    case GUI_EV_KEY: return on_key(ui, ev, out);
    case GUI_EV_TEXT: {
        int f = gui_tree_find(ui->tree, ui->focus);
        if (f >= 0 && ui->tree->nodes[f].kind == GUI_INPUT &&
            !(ev->mods & GUI_MOD_CTRL))
            (void)gui_ui_text_insert(ui, &ui->tree->nodes[f], ev->text.codepoint);
        return false;
    }
    case GUI_EV_MOUSE_MOVE: on_move(ui, ev->move.x, ev->move.y); return false;
    case GUI_EV_MOUSE_BUTTON: return on_button(ui, ev, out);
    case GUI_EV_MOUSE_WHEEL: {
        int h = hit_test(ui, ev->wheel.x, ev->wheel.y);
        if (h >= 0 && ui->tree->nodes[h].kind == GUI_TABLE)
            gui_ui_table_wheel(ui, &ui->tree->nodes[h], ev->wheel.dy);
        return false;
    }
    case GUI_EV_FOCUS:
        ui->win_focused = ev->focus.gained;
        gui_ui_mark_node(ui, ui->focus);
        return false;
    default: return false;
    }
}

enum gui_cursor gui_ui_cursor(const struct gui_ui *ui)
{
    int h = hit_test(ui, ui->last_mx, ui->last_my);
    if (h < 0) return GUI_CURSOR_ARROW;
    switch (ui->tree->nodes[h].kind) {
    case GUI_INPUT: return GUI_CURSOR_IBEAM;
    case GUI_BUTTON: return GUI_CURSOR_HAND;
    default: return GUI_CURSOR_ARROW;
    }
}
