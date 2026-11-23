/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the text field: a bounded UTF-8 buffer with caret and selection on
 * codepoint boundaries, per-kind input filters, secret mode (bullets, no
 * copy/cut, cleansed buffer), clipboard paste and painting. */
#include <stdio.h>
#include <string.h>

#include "base/cleanse.h"
#include "base/safe_alloc.h"
#include "gui/ui.h"

#define SEL_COLOR gui_rgb(0x2f, 0x4f, 0x8f)
#define ACCENT gui_rgb(0x7a, 0xb8, 0xff)

struct gui_input_state *gui_ui_input_find(struct gui_ui *ui, const char *id,
                                          bool create, size_t cap)
{
    struct gui_input_state *free_slot = NULL;
    for (size_t i = 0; i < 8; i++) {
        struct gui_input_state *s = &ui->inputs[i];
        if (s->buf && !strcmp(s->id, id)) return s;
        if (!s->buf && !free_slot) free_slot = s;
    }
    if (!create || !free_slot) return NULL;
    free_slot->buf = zcl_calloc(cap + 1, 1, "gui_input_buf");
    if (!free_slot->buf) return NULL;
    snprintf(free_slot->id, sizeof(free_slot->id), "%s", id);
    free_slot->cap = cap;
    free_slot->len = free_slot->caret = free_slot->anchor = 0;
    free_slot->scroll_x = 0;
    return free_slot;
}

static struct gui_input_state *state_of(struct gui_ui *ui, const struct gui_node *n)
{
    return gui_ui_input_find(ui, n->id, true, n->max_bytes);
}

static void changed(struct gui_ui *ui, struct gui_node *n, struct gui_input_state *s)
{
    if (n->bind[0] && n->ikind != GUI_IN_SECRET) gui_ui_set(ui, n->bind, s->buf);
    gui_ui_mark_rect(ui, n->frame);
    ui->caret_on = true;
}

static bool sel_active(const struct gui_input_state *s) { return s->caret != s->anchor; }

static void sel_range(const struct gui_input_state *s, size_t *a, size_t *b)
{
    *a = s->caret < s->anchor ? s->caret : s->anchor;
    *b = s->caret < s->anchor ? s->anchor : s->caret;
}

static void delete_range(struct gui_input_state *s, size_t a, size_t b)
{
    memmove(s->buf + a, s->buf + b, s->len - b + 1);
    s->len -= b - a;
    s->caret = s->anchor = a;
}

static bool is_alnum(uint32_t cp)
{
    return (cp >= '0' && cp <= '9') || (cp >= 'a' && cp <= 'z') || (cp >= 'A' && cp <= 'Z');
}

/* AMOUNT: digits and one dot, at most 8 decimals. */
static bool amount_allows(const struct gui_input_state *s, uint32_t cp)
{
    const char *dot = strchr(s->buf, '.');
    if (cp == '.') return !dot;
    if (cp < '0' || cp > '9') return false;
    if (!dot || (size_t)(dot - s->buf) >= s->caret) return true;
    return strlen(dot + 1) < 8;
}

static bool allowed(const struct gui_input_state *s, enum gui_input_kind k, uint32_t cp)
{
    if (cp < 0x20u && !(cp == '\n' && k == GUI_IN_MEMO)) return false;
    if (cp == 0x7Fu) return false;
    if (k == GUI_IN_AMOUNT) return amount_allows(s, cp);
    if (k == GUI_IN_ADDRESS) return is_alnum(cp);
    return true;
}

bool gui_ui_text_insert(struct gui_ui *ui, struct gui_node *n, uint32_t cp)
{
    struct gui_input_state *s = state_of(ui, n);
    if (!s || !allowed(s, n->ikind, cp)) return false;
    char enc[4];
    size_t el = gui_utf8_encode(cp, enc);
    size_t a, b;
    sel_range(s, &a, &b);
    if (s->len - (b - a) + el > s->cap) return false;
    if (sel_active(s)) delete_range(s, a, b);
    memmove(s->buf + s->caret + el, s->buf + s->caret, s->len - s->caret + 1);
    memcpy(s->buf + s->caret, enc, el);
    s->len += el;
    s->caret += el;
    s->anchor = s->caret;
    changed(ui, n, s);
    return true;
}

static bool is_space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

/* Trim surrounding whitespace in place; returns the new length. */
static size_t trim_clip(char *clip, size_t cl)
{
    size_t a = 0;
    while (a < cl && is_space(clip[a])) a++;
    while (cl > a && is_space(clip[cl - 1])) cl--;
    memmove(clip, clip + a, cl - a);
    return cl - a;
}

static void do_paste(struct gui_ui *ui, struct gui_node *n, struct gui_input_state *s)
{
    char clip[1024], saved[1025];
    size_t cl = ui->win ? gui_clipboard_get_text(ui->win, clip, sizeof(clip)) : 0;
    if (n->ikind == GUI_IN_ADDRESS || n->ikind == GUI_IN_AMOUNT) cl = trim_clip(clip, cl);
    size_t a, b;
    sel_range(s, &a, &b);
    if (s->len - (b - a) + cl > s->cap || s->len > 1024) {
        gui_ui_toast(ui, "That text is too long for this field", 3000);
        return;
    }
    /* A refused paste changes nothing: keep a copy of the state to restore. */
    size_t sl = s->len, sc = s->caret, sa = s->anchor;
    memcpy(saved, s->buf, sl + 1);
    size_t i = 0;
    while (i < cl) {
        if (gui_ui_text_insert(ui, n, gui_utf8_next(clip, cl, &i))) continue;
        memcpy(s->buf, saved, sl + 1);
        s->len = sl;
        s->caret = sc;
        s->anchor = sa;
        gui_ui_toast(ui, "That text can't be pasted here", 3000);
        changed(ui, n, s);
        return;
    }
}

static size_t word_step(const struct gui_input_state *s, size_t at, bool right)
{
    if (right) {
        while (at < s->len && s->buf[at] == ' ') at++;
        while (at < s->len && s->buf[at] != ' ') at++;
        return at;
    }
    while (at > 0 && s->buf[at - 1] == ' ') at--;
    while (at > 0 && s->buf[at - 1] != ' ') at--;
    return at;
}

static void move_caret(struct gui_input_state *s, size_t to, bool extend)
{
    s->caret = to;
    if (!extend) s->anchor = to;
}

static bool nav_key(struct gui_input_state *s, const struct gui_event *ev)
{
    bool shift = (ev->mods & GUI_MOD_SHIFT) != 0, ctrl = (ev->mods & GUI_MOD_CTRL) != 0;
    size_t a, b;
    sel_range(s, &a, &b);
    switch (ev->key.key) {
    case GUI_KEY_LEFT:
        if (sel_active(s) && !shift) move_caret(s, a, false);
        else move_caret(s, ctrl ? word_step(s, s->caret, false) : gui_utf8_prev(s->buf, s->len, s->caret), shift);
        return true;
    case GUI_KEY_RIGHT:
        if (sel_active(s) && !shift) move_caret(s, b, false);
        else if (s->caret < s->len) {
            size_t i = s->caret;
            (void)gui_utf8_next(s->buf, s->len, &i);
            move_caret(s, ctrl ? word_step(s, s->caret, true) : i, shift);
        }
        return true;
    case GUI_KEY_HOME: move_caret(s, 0, shift); return true;
    case GUI_KEY_END: move_caret(s, s->len, shift); return true;
    default: return false;
    }
}

static bool edit_key(struct gui_ui *ui, struct gui_node *n, struct gui_input_state *s,
                     const struct gui_event *ev)
{
    size_t a, b;
    sel_range(s, &a, &b);
    switch (ev->key.key) {
    case GUI_KEY_BACKSPACE:
        if (sel_active(s)) delete_range(s, a, b);
        else if (s->caret > 0) delete_range(s, gui_utf8_prev(s->buf, s->len, s->caret), s->caret);
        else return true;
        changed(ui, n, s);
        return true;
    case GUI_KEY_DELETE:
        if (sel_active(s)) delete_range(s, a, b);
        else if (s->caret < s->len) {
            size_t i = s->caret;
            (void)gui_utf8_next(s->buf, s->len, &i);
            delete_range(s, s->caret, i);
        } else return true;
        changed(ui, n, s);
        return true;
    case GUI_KEY_ENTER:
        if (n->ikind == GUI_IN_MEMO) (void)gui_ui_text_insert(ui, n, '\n');
        return n->ikind == GUI_IN_MEMO;
    default: return false;
    }
}

static bool ctrl_key(struct gui_ui *ui, struct gui_node *n, struct gui_input_state *s,
                     const struct gui_event *ev)
{
    size_t a, b;
    sel_range(s, &a, &b);
    bool secret = n->ikind == GUI_IN_SECRET;
    switch (ev->key.key) {
    case GUI_KEY_A: s->anchor = 0; s->caret = s->len; return true;
    case GUI_KEY_C:
        if (!secret && sel_active(s) && ui->win) gui_clipboard_set_text(ui->win, s->buf + a, b - a);
        return true;
    case GUI_KEY_X:
        if (!secret && sel_active(s) && ui->win) {
            gui_clipboard_set_text(ui->win, s->buf + a, b - a);
            delete_range(s, a, b);
            changed(ui, n, s);
        }
        return true;
    case GUI_KEY_V: do_paste(ui, n, s); return true;
    default: return false;
    }
}

bool gui_ui_text_key(struct gui_ui *ui, const struct gui_event *ev, struct gui_node *n)
{
    struct gui_input_state *s = state_of(ui, n);
    if (!s || !ev->key.down) return false;
    size_t c0 = s->caret, a0 = s->anchor;
    bool used = (ev->mods & GUI_MOD_CTRL) && ctrl_key(ui, n, s, ev);
    if (!used) used = nav_key(s, ev);
    if (!used) used = edit_key(ui, n, s, ev);
    if (used && (c0 != s->caret || a0 != s->anchor)) {
        gui_ui_mark_rect(ui, n->frame);
        ui->caret_on = true;
    }
    return used;
}

void gui_ui_input_click(struct gui_ui *ui, struct gui_node *n, int32_t x, bool extend)
{
    struct gui_input_state *s = state_of(ui, n);
    if (!s) return;
    const struct gui_theme_entry *th = gui_theme(GS_INPUT);
    int32_t px = gui_ui_text_px(ui, GS_INPUT);
    int32_t rel = x - (n->frame.x + gui_px(ui, 10)) + s->scroll_x;
    size_t at = n->ikind == GUI_IN_SECRET
        ? (size_t)0 : gui_text_index_at_x(th->font, px, s->buf, s->len, rel);
    if (n->ikind == GUI_IN_SECRET) {
        int32_t step = px / 2 + 2;
        size_t chars = 0, i = 0;
        while (i < s->len) { (void)gui_utf8_next(s->buf, s->len, &i); chars++; }
        size_t k = rel <= 0 ? 0 : (size_t)(rel / step);
        if (k > chars) k = chars;
        at = 0;
        for (size_t c = 0; c < k; c++) (void)gui_utf8_next(s->buf, s->len, &at);
    }
    move_caret(s, at, extend);
    gui_ui_mark_rect(ui, n->frame);
    ui->caret_on = true;
}

bool gui_ui_input_text(const struct gui_ui *ui, const char *id, char *buf, size_t cap)
{
    for (size_t i = 0; i < 8; i++)
        if (ui->inputs[i].buf && !strcmp(ui->inputs[i].id, id)) {
            if (ui->inputs[i].len + 1 > cap) return false;
            memcpy(buf, ui->inputs[i].buf, ui->inputs[i].len + 1);
            return true;
        }
    if (cap) buf[0] = 0;
    return cap != 0;
}

void gui_ui_input_clear(struct gui_ui *ui, const char *id)
{
    struct gui_input_state *s = gui_ui_input_find(ui, id, false, 0);
    if (!s) return;
    memory_cleanse(s->buf, s->cap + 1);
    s->len = s->caret = s->anchor = 0;
    gui_ui_mark_node(ui, id);
}

void gui_ui_input_set(struct gui_ui *ui, const char *id, const char *utf8)
{
    int at = gui_tree_find(ui->tree, id);
    if (at < 0) return;
    struct gui_node *n = &ui->tree->nodes[at];
    struct gui_input_state *s = state_of(ui, n);
    if (!s) return;
    size_t l = strlen(utf8);
    if (l > s->cap) l = s->cap;
    memcpy(s->buf, utf8, l);
    s->buf[l] = 0;
    s->len = s->caret = s->anchor = l;
    changed(ui, n, s);
}

struct ictx {
    const struct gui_theme_entry *th;
    struct gui_input_state *st;
    const char *txt;
    size_t len;
    int32_t px, asc, desc, lh, step, sx, caret_x;
    struct gui_rect inner;
    bool secret;
};

static void ictx_init(struct ictx *c, struct gui_ui *ui, const struct gui_node *n)
{
    c->th = gui_theme(GS_INPUT);
    c->st = gui_ui_input_find(ui, n->id, false, 0);
    c->txt = c->st ? c->st->buf : "";
    c->len = c->st ? c->st->len : 0;
    c->px = gui_ui_text_px(ui, GS_INPUT);
    gui_font_metrics(c->th->font, c->px, &c->asc, &c->desc, &c->lh);
    int32_t padx = gui_px(ui, 10), pady = gui_px(ui, 8);
    c->inner = (struct gui_rect){ n->frame.x + padx, n->frame.y + pady, n->frame.w - 2 * padx,
                                  n->frame.h - 2 * pady };
    c->secret = n->ikind == GUI_IN_SECRET;
    c->step = c->px / 2 + 2;
    c->sx = 0;
    c->caret_x = 0;
}

/* x offset of a byte index: bullets are fixed-width, text is measured. */
static int32_t index_x(const struct ictx *c, size_t at)
{
    if (!c->secret) return gui_text_width(c->th->font, c->px, c->txt, at);
    size_t chars = 0, i = 0;
    while (i < at) {
        (void)gui_utf8_next(c->txt, c->len, &i);
        chars++;
    }
    return (int32_t)chars * c->step;
}

/* Keep the caret inside the visible window by scrolling. */
static void ictx_scroll(struct ictx *c)
{
    if (!c->st) return;
    c->caret_x = index_x(c, c->st->caret);
    if (c->caret_x - c->st->scroll_x > c->inner.w - 2) c->st->scroll_x = c->caret_x - c->inner.w + 2;
    if (c->caret_x - c->st->scroll_x < 0) c->st->scroll_x = c->caret_x;
    c->sx = c->st->scroll_x;
}

static void paint_selection(struct gui_surface *s, const struct ictx *c)
{
    if (!c->st || !sel_active(c->st) || c->secret) return;
    size_t a, b;
    sel_range(c->st, &a, &b);
    int32_t xa = index_x(c, a), xb = index_x(c, b);
    gui_fill_rect(s, (struct gui_rect){ c->inner.x + xa - c->sx, c->inner.y, xb - xa, c->lh }, SEL_COLOR);
}

static void paint_memo_lines(struct gui_surface *s, const struct ictx *c)
{
    size_t at = 0;
    int32_t y = c->inner.y;
    while (at <= c->len) {
        size_t e = at;
        while (e < c->len && c->txt[e] != '\n') e++;
        gui_text_draw(s, c->th->font, c->px, c->inner.x - c->sx, y + c->asc, c->txt + at, e - at, c->th->fg);
        y += c->lh;
        at = e + 1;
    }
}

static void paint_body(struct gui_surface *s, const struct ictx *c, const struct gui_node *n)
{
    if (c->secret) {
        size_t i = 0;
        int32_t x = c->inner.x - c->sx;
        while (i < c->len) {
            (void)gui_utf8_next(c->txt, c->len, &i);
            gui_fill_circle(s, x + c->step / 2, c->inner.y + c->lh / 2, c->px / 6 + 1, c->th->fg);
            x += c->step;
        }
    } else if (n->ikind == GUI_IN_MEMO) {
        paint_memo_lines(s, c);
    } else {
        gui_text_draw(s, c->th->font, c->px, c->inner.x - c->sx, c->inner.y + c->asc, c->txt, c->len,
                      c->th->fg);
    }
}

static void paint_counter(struct gui_ui *ui, struct gui_surface *s, const struct gui_node *n,
                          const struct ictx *c)
{
    if (n->ikind != GUI_IN_MEMO || !c->st) return;
    char cnt[24];
    snprintf(cnt, sizeof(cnt), "%zu/%u", c->st->len, n->max_bytes);
    int32_t cw = gui_text_width(GUI_FONT_TEXT, c->px, cnt, strlen(cnt));
    gui_text_draw(s, GUI_FONT_TEXT, c->px, n->frame.x + n->frame.w - cw - gui_px(ui, 10),
                  n->frame.y + n->frame.h - gui_px(ui, 6) - c->desc, cnt, strlen(cnt),
                  c->st->len > n->max_bytes ? gui_rgb(0xff, 0x6b, 0x5e) : gui_rgb(0x9a, 0xa3, 0xb2));
}

void gui_ui_input_paint(struct gui_ui *ui, struct gui_surface *s, struct gui_node *n)
{
    struct ictx c;
    ictx_init(&c, ui, n);
    bool focused = ui->focus[0] && !strcmp(ui->focus, n->id);
    int32_t rad = gui_px(ui, c.th->radius);
    gui_fill_round_rect(s, n->frame, rad, focused ? ACCENT : c.th->border);
    gui_fill_round_rect(s, (struct gui_rect){ n->frame.x + 1, n->frame.y + 1, n->frame.w - 2,
                        n->frame.h - 2 }, rad > 0 ? rad - 1 : 0, c.th->bg);
    gui_clip_push(s, c.inner);
    if (!c.len)
        gui_text_draw(s, c.th->font, c.px, c.inner.x, c.inner.y + c.asc, gui_tree_text(ui->tree, n),
                      n->text_len, gui_rgb(0x8a, 0x92, 0xa0));
    ictx_scroll(&c);
    paint_selection(s, &c);
    paint_body(s, &c, n);
    if (focused && ui->caret_on && ui->win_focused)
        gui_fill_rect(s, (struct gui_rect){ c.inner.x + c.caret_x - c.sx, c.inner.y, gui_px(ui, 1) + 1, c.lh },
                      c.th->fg);
    gui_clip_pop(s);
    paint_counter(ui, s, n, &c);
}
