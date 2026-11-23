/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: paint the widget tree from theme tokens, clipped to dirty rects. */
#include <stdlib.h>
#include <string.h>

#include "gui/ui.h"

#define FOCUS_RING RGB(0x7a, 0xb8, 0xff)
#define RGB(r, g, b) (((uint32_t)(r) << 16) | ((uint32_t)(g) << 8) | (uint32_t)(b))

static bool is_id(const char *a, const struct gui_node *n)
{
    return a[0] && !strcmp(a, n->id);
}

static uint32_t shade(uint32_t c, int delta)
{
    int r = (int)((c >> 16) & 255u) + delta, g = (int)((c >> 8) & 255u) + delta,
        b = (int)(c & 255u) + delta;
    r = r < 0 ? 0 : r > 255 ? 255 : r;
    g = g < 0 ? 0 : g > 255 ? 255 : g;
    b = b < 0 ? 0 : b > 255 ? 255 : b;
    return gui_rgb((uint8_t)r, (uint8_t)g, (uint8_t)b);
}

static void panel(struct gui_ui *ui, struct gui_surface *s, struct gui_rect fr,
                  const struct gui_theme_entry *th)
{
    int32_t rad = gui_px(ui, th->radius);
    if (th->border) {
        gui_fill_round_rect(s, fr, rad, th->border);
        struct gui_rect in = { fr.x + 1, fr.y + 1, fr.w - 2, fr.h - 2 };
        gui_fill_round_rect(s, in, rad > 0 ? rad - 1 : 0, th->bg);
    } else {
        gui_fill_round_rect(s, fr, rad, th->bg);
    }
}

static void focus_ring(struct gui_ui *ui, struct gui_surface *s, struct gui_rect fr)
{
    int32_t t = gui_px(ui, 2);
    struct gui_rect o = { fr.x - t, fr.y - t, fr.w + 2 * t, fr.h + 2 * t };
    gui_stroke_rect(s, o, t, FOCUS_RING);
}

struct tline { const struct gui_theme_entry *th; int32_t px, asc, lh, x, y; struct gui_rect fr; };

static void paint_wrapped(struct gui_surface *s, const struct tline *l, const char *str, size_t len)
{
    size_t at = 0;
    int32_t ly = l->y;
    while (at < len) {
        size_t k = gui_wrap_line(l->th->font, l->px, str + at, len - at, l->fr.w);
        size_t shown = k;
        while (shown > 0 && (str[at + shown - 1] == ' ' || str[at + shown - 1] == '\n')) shown--;
        gui_text_draw(s, l->th->font, l->px, l->x, ly + l->asc, str + at, shown, l->th->fg);
        ly += l->lh;
        at += k ? k : len;
    }
}

static void paint_single(struct gui_surface *s, const struct tline *l, const struct gui_node *n,
                         const char *str, size_t len)
{
    const struct gui_theme_entry *th = l->th;
    int32_t tw = gui_text_width(th->font, l->px, str, len), x = l->x;
    if ((n->flags & GUI_F_ELLIPSIS) && tw > l->fr.w && l->fr.w > 0) {
        int32_t dots = gui_text_width(th->font, l->px, "...", 3);
        size_t fit = gui_text_fit(th->font, l->px, str, len, l->fr.w - dots);
        gui_text_draw(s, th->font, l->px, x, l->y + l->asc, str, fit, th->fg);
        gui_text_draw(s, th->font, l->px, x + gui_text_width(th->font, l->px, str, fit),
                      l->y + l->asc, "...", 3, th->fg);
        return;
    }
    if (n->flags & GUI_F_RIGHT) x = l->fr.x + l->fr.w - tw;
    gui_text_draw(s, th->font, l->px, x, l->y + l->asc, str, len, th->fg);
}

static void paint_text(struct gui_ui *ui, struct gui_surface *s, struct gui_node *n)
{
    struct tline l = { .th = gui_theme(n->style), .fr = n->frame };
    int32_t desc;
    l.px = gui_ui_text_px(ui, n->style);
    gui_font_metrics(l.th->font, l.px, &l.asc, &desc, &l.lh);
    const char *str = n->bind[0] ? gui_ui_get(ui, n->bind) : gui_tree_text(ui->tree, n);
    size_t len = strlen(str);
    l.x = l.fr.x;
    l.y = l.fr.y;
    if (n->style >= GS_BADGE_PRIVATE && n->style <= GS_BADGE_DANGER) {
        gui_fill_round_rect(s, l.fr, gui_px(ui, l.th->radius), l.th->bg);
        l.x += gui_px(ui, 9);
        l.y += gui_px(ui, 3);
    }
    if ((n->flags & GUI_F_WRAP) && l.fr.w > 0) paint_wrapped(s, &l, str, len);
    else paint_single(s, &l, n, str, len);
    if ((n->flags & GUI_F_SELECTABLE) && is_id(ui->focus, n) && ui->kbd_focus)
        focus_ring(ui, s, l.fr);
}

static void paint_button(struct gui_ui *ui, struct gui_surface *s, struct gui_node *n)
{
    struct gui_theme_entry th = *gui_theme(n->style);
    bool disabled = (n->flags & GUI_F_DISABLED) != 0;
    bool nav = n->style == GS_NAV || n->style == GS_NAV_ACTIVE;
    if (disabled) {
        th.bg = RGB(0x23, 0x26, 0x2e);
        th.fg = RGB(0x8a, 0x92, 0xa0);
        th.border = 0;
    } else if (is_id(ui->pressed, n)) {
        th.bg = shade(th.bg, -14);
    } else if (is_id(ui->hover, n)) {
        th.bg = shade(th.bg, 14);
    }
    if (nav) th.border = 0;
    panel(ui, s, n->frame, &th);
    int32_t px = gui_ui_text_px(ui, n->style), asc, desc, lh;
    gui_font_metrics(th.font, px, &asc, &desc, &lh);
    const char *lbl = gui_tree_text(ui->tree, n);
    int32_t tw = gui_text_width(th.font, px, lbl, n->text_len);
    int32_t x = nav ? n->frame.x + gui_px(ui, 14) : n->frame.x + (n->frame.w - tw) / 2;
    gui_text_draw(s, th.font, px, x, n->frame.y + (n->frame.h - lh) / 2 + asc, lbl,
                  n->text_len, th.fg);
    if (is_id(ui->focus, n) && ui->kbd_focus) focus_ring(ui, s, n->frame);
}

static void paint_progress(struct gui_ui *ui, struct gui_surface *s, struct gui_node *n)
{
    int32_t rad = n->frame.h / 2;
    gui_fill_round_rect(s, n->frame, rad, RGB(0x2a, 0x2f, 0x3a));
    const char *v = gui_ui_get(ui, n->bind);
    int32_t permille = v[0] ? (int32_t)strtol(v, NULL, 10) : -1;
    struct gui_rect bar = n->frame;
    if (permille >= 0) {
        if (permille > 1000) permille = 1000;
        bar.w = (int32_t)((int64_t)n->frame.w * permille / 1000);
    } else {
        bar.x += n->frame.w / 3;
        bar.w = n->frame.w / 3;
    }
    if (bar.w > 0) gui_fill_round_rect(s, bar, rad, RGB(0x2f, 0x6f, 0xed));
}

static void paint_node(struct gui_ui *ui, struct gui_surface *s, uint16_t i);

static bool box_has_panel(enum gui_style st)
{
    return st == GS_SCREEN || st == GS_CARD || st == GS_CARD_WARN || st == GS_NAV || st == GS_STATUS ||
           st == GS_TOAST;
}

static void paint_box(struct gui_ui *ui, struct gui_surface *s, struct gui_node *n)
{
    if (box_has_panel(n->style)) {
        struct gui_theme_entry flat = *gui_theme(n->style);
        if (n->style == GS_NAV || n->style == GS_STATUS) flat.radius = 0;
        panel(ui, s, n->frame, &flat);
    }
    for (uint16_t c = n->first; c != GUI_NONE; c = ui->tree->nodes[c].next) paint_node(ui, s, c);
}

static void paint_node(struct gui_ui *ui, struct gui_surface *s, uint16_t i)
{
    struct gui_node *n = &ui->tree->nodes[i];
    if ((n->flags & GUI_F_HIDDEN) || n->kind == GUI_DIALOG) return;
    if (!gui_rect_intersect(n->frame, s->clip, NULL)) return;
    switch (n->kind) {
    case GUI_BOX: paint_box(ui, s, n); break;
    case GUI_TEXT: paint_text(ui, s, n); break;
    case GUI_BUTTON: paint_button(ui, s, n); break;
    case GUI_INPUT: gui_ui_input_paint(ui, s, n); break;
    case GUI_TABLE: gui_ui_table_paint(ui, s, n); break;
    case GUI_PROGRESS: paint_progress(ui, s, n); break;
    default: break;
    }
}

static void paint_dialog(struct gui_ui *ui, struct gui_surface *s, uint16_t i)
{
    struct gui_node *n = &ui->tree->nodes[i];
    const struct gui_theme_entry *th = gui_theme(GS_DIALOG);
    gui_fill_rect_blend(s, (struct gui_rect){ 0, 0, ui->w, ui->h }, 0, 150);
    panel(ui, s, n->frame, th);
    int32_t px = gui_ui_text_px(ui, GS_TITLE), asc, desc, lh;
    const struct gui_theme_entry *tt = gui_theme(GS_TITLE);
    gui_font_metrics(tt->font, px, &asc, &desc, &lh);
    int32_t pad = gui_px(ui, n->pad);
    gui_text_draw(s, tt->font, px, n->frame.x + pad, n->frame.y + pad + asc,
                  gui_tree_text(ui->tree, n), n->text_len, tt->fg);
    for (uint16_t c = n->first; c != GUI_NONE; c = ui->tree->nodes[c].next)
        paint_node(ui, s, c);
}

static void paint_toast(struct gui_ui *ui, struct gui_surface *s)
{
    if (!ui->toast[0]) return;
    const struct gui_theme_entry *th = gui_theme(GS_TOAST);
    int32_t px = gui_ui_text_px(ui, GS_TOAST), asc, desc, lh;
    gui_font_metrics(th->font, px, &asc, &desc, &lh);
    int32_t tw = gui_text_width(th->font, px, ui->toast, strlen(ui->toast));
    int32_t padx = gui_px(ui, 12), pady = gui_px(ui, 6);
    struct gui_rect r = { ui->w - tw - 2 * padx - gui_px(ui, 12),
                          ui->h - lh - 2 * pady - gui_px(ui, 40), tw + 2 * padx, lh + 2 * pady };
    panel(ui, s, r, th);
    gui_text_draw(s, th->font, px, r.x + padx, r.y + pady + asc, ui->toast,
                  strlen(ui->toast), th->fg);
}

static void paint_all(struct gui_ui *ui, struct gui_surface *s)
{
    const struct gui_tree *t = ui->tree;
    if (t->root == GUI_NONE) return;
    paint_node(ui, s, t->root);
    for (uint16_t i = 0; i < t->count; i++)
        if (t->nodes[i].kind == GUI_DIALOG && !(t->nodes[i].flags & GUI_F_HIDDEN))
            paint_dialog(ui, s, i);
    paint_toast(ui, s);
}

void gui_ui_paint(struct gui_ui *ui, struct gui_surface *s,
                  const struct gui_rect *dirty, size_t n)
{
    if (n == 0) {
        gui_clip_push(s, (struct gui_rect){ 0, 0, s->w, s->h });
        paint_all(ui, s);
        gui_clip_pop(s);
        return;
    }
    for (size_t i = 0; i < n; i++) {
        if (!gui_clip_push(s, dirty[i])) continue;
        paint_all(ui, s);
        gui_clip_pop(s);
    }
}
