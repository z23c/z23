/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: paint the widget tree from theme tokens, clipped to dirty rects:
 * panels, the beta13 group box (title knocked into the border), accent
 * cards, the nav rail, pills, status icons, buttons and drop-down popups. */
#include <stdlib.h>
#include <string.h>

#include "gui/ui.h"

#define RGB(r, g, b) (((uint32_t)(r) << 16) | ((uint32_t)(g) << 8) | (uint32_t)(b))
#define FOCUS_RING RGB(0x34, 0xc7, 0x59)
#define C_HERO RGB(0x34, 0xc7, 0x59)
#define C_GREEN RGB(0x1f, 0x7a, 0x1f)
#define C_AMBER RGB(0xd9, 0x82, 0x2b)
#define C_WHITE RGB(0xff, 0xff, 0xff)

size_t gui_ui_glyph_map(const char *in, size_t len, char *out, size_t cap);
int32_t gui_ui_run_width(enum gui_font f, int32_t px, const char *s, size_t len);
int32_t gui_ui_fit_px(const struct gui_ui *ui, const struct gui_node *n, const char *s, size_t len,
                      int32_t avail);
bool gui_ui_is_pill(enum gui_style st);
int32_t gui_ui_pill_h(const struct gui_ui *ui, enum gui_style st);
bool gui_ui_is_popup(const struct gui_node *n);
void gui_ui_run_draw(struct gui_surface *s, enum gui_font f, int32_t px, int32_t x, int32_t baseline,
                     const char *str, size_t len, uint32_t color, uint32_t dot_color);
void gui_ui_pill_draw(struct gui_ui *ui, struct gui_surface *s, struct gui_rect r, enum gui_style st,
                      const char *label, size_t len);

static bool is_id(const char *a, const struct gui_node *n)
{
    return a[0] && !strcmp(a, n->id);
}

/* Text with the interim glyph map's dot (1) and circle (2) drawn as shapes. */
void gui_ui_run_draw(struct gui_surface *s, enum gui_font f, int32_t px, int32_t x, int32_t baseline,
                     const char *str, size_t len, uint32_t color, uint32_t dot_color)
{
    size_t start = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i < len && str[i] != 1 && str[i] != 2) continue;
        gui_text_draw(s, f, px, x, baseline, str + start, i - start, color);
        x += gui_text_width(f, px, str + start, i - start);
        if (i < len) {
            int32_t w = gui_text_width(f, px, str[i] == 1 ? " " : "o", 1);
            int32_t r = str[i] == 1 ? (px + 8) / 10 : px * 3 / 10;
            gui_fill_circle(s, x + w / 2, baseline - px * 7 / 20, r < 1 ? 1 : r, str[i] == 1 ? color : dot_color);
            x += w;
        }
        start = i + 1;
    }
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

/* A left border of width w that follows the rounded corners. */
static void accent_left(struct gui_ui *ui, struct gui_surface *s, struct gui_rect fr, int32_t radius,
                        uint32_t color, int32_t w)
{
    if (!gui_clip_push(s, (struct gui_rect){ fr.x, fr.y, gui_px(ui, w), fr.h })) return;
    gui_fill_round_rect(s, fr, gui_px(ui, radius), color);
    gui_clip_pop(s);
}

static void focus_ring(struct gui_ui *ui, struct gui_surface *s, struct gui_rect fr)
{
    int32_t t = gui_px(ui, 2), o = t + gui_px(ui, 2);
    struct gui_rect r = { fr.x - o, fr.y - o, fr.w + 2 * o, fr.h + 2 * o };
    gui_stroke_rect(s, r, t, FOCUS_RING);
}

/* Pill: badge colour at alpha 38 over the cell, 1 px border, label in the
 * token's text colour (AA-safe), radius = height / 2. */
void gui_ui_pill_draw(struct gui_ui *ui, struct gui_surface *s, struct gui_rect r, enum gui_style st,
                      const char *label, size_t len)
{
    const struct gui_theme_entry *th = gui_theme(st);
    int32_t px = gui_ui_text_px(ui, st), asc, desc, lh;
    gui_font_metrics(th->font, px, &asc, &desc, &lh);
    gui_fill_round_rect(s, r, r.h / 2, th->border);
    gui_fill_round_rect(s, (struct gui_rect){ r.x + 1, r.y + 1, r.w - 2, r.h - 2 }, r.h / 2 - 1, th->bg);
    int32_t tw = gui_ui_run_width(th->font, px, label, len);
    gui_ui_run_draw(s, th->font, px, r.x + (r.w - tw) / 2, r.y + (r.h - lh) / 2 + asc, label, len, th->fg,
                    th->fg);
}

struct tline { const struct gui_theme_entry *th; int32_t px, asc, lh, x, y; struct gui_rect fr; uint32_t dot; };

static void paint_wrapped(struct gui_surface *s, const struct tline *l, const char *str, size_t len)
{
    size_t at = 0;
    int32_t ly = l->y;
    while (at < len) {
        size_t k = gui_wrap_line(l->th->font, l->px, str + at, len - at, l->fr.w);
        size_t shown = k;
        while (shown > 0 && (str[at + shown - 1] == ' ' || str[at + shown - 1] == '\n')) shown--;
        gui_ui_run_draw(s, l->th->font, l->px, l->x, ly + l->asc, str + at, shown, l->th->fg, l->dot);
        ly += l->lh;
        at += k ? k : len;
    }
}

static void paint_single(struct gui_surface *s, const struct tline *l, const struct gui_node *n,
                         const char *str, size_t len)
{
    const struct gui_theme_entry *th = l->th;
    int32_t tw = gui_ui_run_width(th->font, l->px, str, len), x = l->x;
    if ((n->flags & GUI_F_ELLIPSIS) && tw > l->fr.w && l->fr.w > 0) {
        int32_t dots = gui_text_width(th->font, l->px, "...", 3);
        size_t fit = gui_text_fit(th->font, l->px, str, len, l->fr.w - dots);
        gui_ui_run_draw(s, th->font, l->px, x, l->y + l->asc, str, fit, th->fg, l->dot);
        gui_text_draw(s, th->font, l->px, x + gui_ui_run_width(th->font, l->px, str, fit),
                      l->y + l->asc, "...", 3, th->fg);
        return;
    }
    if (n->flags & GUI_F_RIGHT) x = l->fr.x + l->fr.w - tw;
    gui_ui_run_draw(s, th->font, l->px, x, l->y + l->asc, str, len, th->fg, l->dot);
}

static void paint_text(struct gui_ui *ui, struct gui_surface *s, struct gui_node *n)
{
    struct tline l = { .th = gui_theme(n->style), .fr = n->frame };
    int32_t desc;
    char str[4200];
    const char *raw = n->bind[0] ? gui_ui_get(ui, n->bind) : gui_tree_text(ui->tree, n);
    size_t len = gui_ui_glyph_map(raw, strlen(raw), str, sizeof(str));
    if (gui_ui_is_pill(n->style)) {
        gui_ui_pill_draw(ui, s, n->frame, n->style, str, len);
        return;
    }
    l.px = gui_ui_fit_px(ui, n, str, len, l.fr.w);
    l.dot = n->style == GS_SYNC_PILL ? C_HERO : l.th->fg;
    gui_font_metrics(l.th->font, l.px, &l.asc, &desc, &l.lh);
    l.x = l.fr.x + (n->style == GS_GROUP_TITLE ? gui_px(ui, 14) : 0);
    l.y = l.fr.y;
    if ((n->flags & GUI_F_WRAP) && l.fr.w > 0) paint_wrapped(s, &l, str, len);
    else paint_single(s, &l, n, str, len);
    if ((n->flags & GUI_F_SELECTABLE) && is_id(ui->focus, n) && ui->kbd_focus)
        focus_ring(ui, s, l.fr);
}

/* ---- buttons ---- */

static bool is_nav(enum gui_style st)
{
    return st == GS_NAV || st == GS_NAV_ACTIVE || (st >= GS_NAV_ITEM && st <= GS_NAV_ADV_ACTIVE);
}

static bool nav_active(enum gui_style st)
{
    return st == GS_NAV_ACTIVE || st == GS_NAV_ITEM_ACTIVE || st == GS_NAV_ADV_ACTIVE;
}

/* Hover and pressed colours from dark.qss, per button family. */
static void button_disabled(const struct gui_node *n, struct gui_theme_entry *th)
{
    bool flat = is_nav(n->style) || n->style == GS_MENU_ITEM;
    if (!flat && n->style != GS_MENUBAR_ITEM) th->bg = RGB(0x1d, 0x20, 0x27);
    th->fg = RGB(0x6b, 0x71, 0x77);
    th->border = flat ? 0 : RGB(0x23, 0x27, 0x2f);
}

static void button_hot(enum gui_style st, bool pressed, struct gui_theme_entry *th)
{
    switch (st) {
    case GS_BUTTON_PRIMARY: th->bg = th->border = pressed ? RGB(0x1a, 0x6b, 0x1a) : RGB(0x2a, 0x9d, 0x2a); break;
    case GS_BUTTON_AMBER: th->bg = th->border = pressed ? RGB(0xc2, 0x73, 0x1f) : RGB(0xe0, 0x94, 0x44); break;
    case GS_MENU_ITEM:
    case GS_MENUBAR_ITEM: th->bg = RGB(0x2a, 0x2e, 0x37); break;
    default:
        if (is_nav(st) && !nav_active(st)) {
            th->bg = RGB(0x1a, 0x1d, 0x23);
            th->fg = RGB(0xe6, 0xe6, 0xe6);
        } else if (!is_nav(st)) {
            th->bg = pressed ? RGB(0x2a, 0x2e, 0x37) : RGB(0x33, 0x39, 0x45);
        }
        break;
    }
}

static void button_state(struct gui_ui *ui, const struct gui_node *n, struct gui_theme_entry *th)
{
    bool pressed = is_id(ui->pressed, n), hover = is_id(ui->hover, n);
    if (n->flags & GUI_F_DISABLED) button_disabled(n, th);
    else if (pressed || hover) button_hot(n->style, pressed, th);
}

static void gear(struct gui_ui *ui, struct gui_surface *s, int32_t cx, int32_t cy, uint32_t color, uint32_t bg)
{
    for (int k = 0; k < 8; k++) { /* eight teeth */
        static const int8_t dx[8] = { 0, 4, 6, 4, 0, -4, -6, -4 }, dy[8] = { -6, -4, 0, 4, 6, 4, 0, -4 };
        gui_fill_circle(s, cx + gui_px(ui, dx[k]), cy + gui_px(ui, dy[k]), gui_px(ui, 1) + 1, color);
    }
    gui_fill_circle(s, cx, cy, gui_px(ui, 5), color);
    gui_fill_circle(s, cx, cy, gui_px(ui, 2), bg);
}

static void paint_nav(struct gui_ui *ui, struct gui_surface *s, struct gui_node *n, struct gui_theme_entry *th)
{
    int32_t rad = gui_px(ui, th->radius);
    gui_fill_round_rect(s, n->frame, rad, th->bg);
    if (nav_active(n->style)) accent_left(ui, s, n->frame, th->radius, C_GREEN, 3);
    else if (is_id(ui->hover, n)) accent_left(ui, s, n->frame, th->radius, RGB(0x15, 0x3c, 0x18), 3);
    if (n->style == GS_NAV_ADV || n->style == GS_NAV_ADV_ACTIVE)
        gear(ui, s, n->frame.x + gui_px(ui, 22), n->frame.y + n->frame.h / 2, th->fg, th->bg);
}

static void paint_button(struct gui_ui *ui, struct gui_surface *s, struct gui_node *n)
{
    struct gui_theme_entry th = *gui_theme(n->style);
    button_state(ui, n, &th);
    bool nav = is_nav(n->style), left = nav || n->style == GS_MENU_ITEM;
    if (nav) paint_nav(ui, s, n, &th);
    else panel(ui, s, n->frame, &th);
    int32_t px = gui_ui_text_px(ui, n->style), asc, desc, lh;
    gui_font_metrics(th.font, px, &asc, &desc, &lh);
    char buf[256];
    size_t len = gui_ui_glyph_map(gui_tree_text(ui->tree, n), n->text_len, buf, sizeof(buf));
    const char *lbl = buf;
    int32_t tw = gui_ui_run_width(th.font, px, lbl, len);
    int32_t x = left ? n->frame.x + gui_px(ui, nav ? 16 : 22) : n->frame.x + (n->frame.w - tw) / 2;
    if (n->style == GS_NAV_ADV || n->style == GS_NAV_ADV_ACTIVE) { /* the gear stands in for U+2699 */
        while (len && *lbl == ' ') { lbl++; len--; }
        x += gui_px(ui, 22);
    }
    gui_ui_run_draw(s, th.font, px, x, n->frame.y + (n->frame.h - lh) / 2 + asc, lbl, len, th.fg, th.fg);
    if (is_id(ui->focus, n) && ui->kbd_focus) focus_ring(ui, s, n->frame);
}

static void paint_progress(struct gui_ui *ui, struct gui_surface *s, struct gui_node *n)
{
    int32_t rad = n->frame.h / 2;
    gui_fill_round_rect(s, n->frame, rad, RGB(0x1d, 0x20, 0x27));
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
    if (bar.w > 0) gui_fill_round_rect(s, bar, rad, C_GREEN);
}

/* ---- boxes ---- */

static void paint_icon(struct gui_ui *ui, struct gui_surface *s, const struct gui_node *n)
{
    struct gui_rect f = n->frame;
    uint32_t c = gui_theme(n->style)->border;
    int32_t cx = f.x + f.w / 2, cy = f.y + f.h / 2, r = (f.w < f.h ? f.w : f.h) / 2;
    if (n->style == GS_ICON_WARN) { /* triangle with "!" */
        for (int32_t y = 0; y < f.h; y++) {
            int32_t half = (int32_t)((int64_t)f.w * (y + 1) / (2 * f.h));
            gui_fill_rect(s, (struct gui_rect){ cx - half, f.y + y, 2 * half, 1 }, c);
        }
        int32_t t = gui_px(ui, 2);
        gui_fill_rect(s, (struct gui_rect){ cx - t / 2, f.y + f.h * 3 / 8, t, f.h * 3 / 8 }, RGB(0x15, 0x17, 0x1c));
        gui_fill_rect(s, (struct gui_rect){ cx - t / 2, f.y + f.h * 13 / 16, t, t }, RGB(0x15, 0x17, 0x1c));
        return;
    }
    gui_fill_circle(s, cx, cy, r, c);
    int32_t u = (r + 3) / 4;
    for (int32_t k = 0; k < (u > 1 ? 2 : 1); k++) {
        if (n->style == GS_ICON_OK) { /* tick */
            gui_line(s, cx - 2 * u, cy + k, cx - u / 2, cy + 3 * u / 2 + k, C_WHITE);
            gui_line(s, cx - u / 2, cy + 3 * u / 2 + k, cx + 2 * u, cy - 3 * u / 2 + k, C_WHITE);
        } else { /* cross */
            gui_line(s, cx - u * 3 / 2 + k, cy - u * 3 / 2, cx + u * 3 / 2 + k, cy + u * 3 / 2, C_WHITE);
            gui_line(s, cx + u * 3 / 2 + k, cy - u * 3 / 2, cx - u * 3 / 2 + k, cy + u * 3 / 2, C_WHITE);
        }
    }
}

/* Group box: the border starts at the title's middle; the title is knocked out. */
static void paint_group(struct gui_ui *ui, struct gui_surface *s, const struct gui_node *n)
{
    const struct gui_theme_entry *th = gui_theme(n->style);
    const struct gui_node *title = n->first != GUI_NONE ? &ui->tree->nodes[n->first] : NULL;
    bool has_title = title && title->kind == GUI_TEXT && title->style == GS_GROUP_TITLE;
    int32_t top = has_title ? title->frame.y + title->frame.h / 2 : n->frame.y;
    struct gui_rect b = { n->frame.x, top, n->frame.w, n->frame.y + n->frame.h - top };
    panel(ui, s, b, th);
    if (!has_title) return;
    char str[256];
    const char *raw = gui_tree_text(ui->tree, title);
    size_t len = gui_ui_glyph_map(raw, strlen(raw), str, sizeof(str));
    int32_t tw = gui_ui_run_width(gui_theme(GS_GROUP_TITLE)->font, gui_ui_text_px(ui, GS_GROUP_TITLE), str, len);
    gui_fill_rect(s, (struct gui_rect){ title->frame.x + gui_px(ui, 10), title->frame.y, tw + gui_px(ui, 8),
                                        title->frame.h }, th->bg);
}

enum box_paint { BP_NONE, BP_FLAT, BP_RAIL, BP_STATUSBAR, BP_GROUP, BP_ACCENT, BP_PANEL, BP_ICON };

static enum box_paint box_paint_of(enum gui_style st)
{
    static const uint8_t k[GS_COUNT] = {
        [GS_SCREEN] = BP_FLAT, [GS_PAGE] = BP_FLAT, [GS_MENUBAR] = BP_FLAT, [GS_NAV] = BP_FLAT,
        [GS_STATUS] = BP_FLAT, [GS_RAIL] = BP_RAIL, [GS_STATUSBAR] = BP_STATUSBAR, [GS_GROUP] = BP_GROUP,
        [GS_HERO_CARD] = BP_ACCENT, [GS_CARD_AMBER] = BP_ACCENT, [GS_CARD] = BP_PANEL,
        [GS_CARD_WARN] = BP_PANEL, [GS_TOAST] = BP_PANEL, [GS_MENU_POPUP] = BP_PANEL,
        [GS_BANNER_CONNECTING] = BP_PANEL, [GS_BANNER_SYNCING] = BP_PANEL, [GS_BANNER_INFO] = BP_PANEL,
        [GS_ICON_OK] = BP_ICON, [GS_ICON_WARN] = BP_ICON, [GS_ICON_CRIT] = BP_ICON,
    };
    return st < GS_COUNT ? (enum box_paint)k[st] : BP_NONE;
}

static void paint_box_panel(struct gui_ui *ui, struct gui_surface *s, const struct gui_node *n)
{
    struct gui_theme_entry th = *gui_theme(n->style);
    struct gui_rect f = n->frame;
    enum box_paint bp = box_paint_of(n->style);
    if (bp == BP_FLAT || bp == BP_RAIL || bp == BP_STATUSBAR) gui_fill_rect(s, f, th.bg);
    switch (bp) {
    case BP_RAIL: gui_fill_rect(s, (struct gui_rect){ f.x + f.w - 1, f.y, 1, f.h }, th.border); break;
    case BP_STATUSBAR: gui_fill_rect(s, (struct gui_rect){ f.x, f.y, f.w, 1 }, th.border); break;
    case BP_GROUP: paint_group(ui, s, n); break;
    case BP_ACCENT:
        panel(ui, s, f, &th);
        accent_left(ui, s, f, th.radius, n->style == GS_HERO_CARD ? C_HERO : C_AMBER, 3);
        break;
    case BP_PANEL: panel(ui, s, f, &th); break;
    case BP_ICON: paint_icon(ui, s, n); break;
    default: break;
    }
}

static void paint_node(struct gui_ui *ui, struct gui_surface *s, uint16_t i);

static void paint_box(struct gui_ui *ui, struct gui_surface *s, struct gui_node *n)
{
    paint_box_panel(ui, s, n);
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
    if (gui_ui_is_popup(n)) {
        panel(ui, s, n->frame, gui_theme(GS_MENU_POPUP));
    } else {
        const struct gui_theme_entry *th = gui_theme(GS_DIALOG);
        gui_fill_rect_blend(s, (struct gui_rect){ 0, 0, ui->w, ui->h }, 0, 150);
        panel(ui, s, n->frame, th);
        int32_t px = gui_ui_text_px(ui, GS_TITLE), asc, desc, lh;
        const struct gui_theme_entry *tt = gui_theme(GS_TITLE);
        gui_font_metrics(tt->font, px, &asc, &desc, &lh);
        int32_t pad = gui_px(ui, n->pad);
        char str[256];
        size_t len = gui_ui_glyph_map(gui_tree_text(ui->tree, n), n->text_len, str, sizeof(str));
        gui_ui_run_draw(s, tt->font, px, n->frame.x + pad, n->frame.y + pad + asc, str, len, tt->fg, tt->fg);
    }
    for (uint16_t c = n->first; c != GUI_NONE; c = ui->tree->nodes[c].next)
        paint_node(ui, s, c);
}

static void paint_toast(struct gui_ui *ui, struct gui_surface *s)
{
    if (!ui->toast[0]) return;
    const struct gui_theme_entry *th = gui_theme(GS_TOAST);
    int32_t px = gui_ui_text_px(ui, GS_TOAST), asc, desc, lh;
    gui_font_metrics(th->font, px, &asc, &desc, &lh);
    char str[128];
    size_t len = gui_ui_glyph_map(ui->toast, strlen(ui->toast), str, sizeof(str));
    int32_t tw = gui_ui_run_width(th->font, px, str, len);
    int32_t padx = gui_px(ui, 12), pady = gui_px(ui, 6);
    struct gui_rect r = { ui->w - tw - 2 * padx - gui_px(ui, 12),
                          ui->h - lh - 2 * pady - gui_px(ui, 40), tw + 2 * padx, lh + 2 * pady };
    panel(ui, s, r, th);
    gui_ui_run_draw(s, th->font, px, r.x + padx, r.y + pady + asc, str, len, th->fg, th->fg);
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
